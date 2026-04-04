const std = @import("std");

const PortInfo = struct {
    port: u16,
    protocol: []const u8,
    process_name: []const u8,
    pid: u32,
    user: []const u8,

    fn deinit(self: PortInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.protocol);
        allocator.free(self.process_name);
        allocator.free(self.user);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("memory leak detected");
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var filter_port: ?u16 = null;
    if (args.len > 1) {
        filter_port = std.fmt.parseInt(u16, args[1], 10) catch {
            std.debug.print("Error: '{s}' is not a valid port number\n", .{args[1]});
            std.process.exit(1);
        };
    }

    var ports = try getListeningPorts(allocator);
    defer {
        for (ports.items) |port| port.deinit(allocator);
        ports.deinit(allocator);
    }

    var buf: [4096]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    const stdout = &w.interface;

    if (filter_port) |target| {
        var found = false;
        for (ports.items) |port| {
            if (port.port == target) {
                try printPortDetail(stdout, port);
                found = true;
            }
        }
        if (!found) {
            try stdout.print("No process found using port {d}\n", .{target});
        }
    } else {
        if (ports.items.len == 0) {
            try stdout.print("No listening ports found\n", .{});
        } else {
            try stdout.print("{s:>6} {s:<12} {s:<10} {s}\n", .{ "PORT", "PROTOCOL", "PID", "PROCESS" });
            for (ports.items) |port| {
                try stdout.print("{d:>6} {s:<12} {d:<10} {s}\n", .{
                    port.port,
                    port.protocol,
                    port.pid,
                    port.process_name,
                });
            }
        }
    }
    try stdout.flush();
}

fn printPortDetail(stdout: *std.Io.Writer, port: PortInfo) !void {
    try stdout.print("Port:       {d}\n", .{port.port});
    try stdout.print("Protocol:   {s}\n", .{port.protocol});
    try stdout.print("Process:    {s}\n", .{port.process_name});
    try stdout.print("PID:        {d}\n", .{port.pid});
    try stdout.print("User:       {s}\n", .{port.user});
}

fn getListeningPorts(allocator: std.mem.Allocator) !std.ArrayList(PortInfo) {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-FcnuPp" },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const exit_code = switch (result.term) {
        .Exited => |code| code,
        else => return error.LsofFailed,
    };
    if (exit_code != 0) return error.LsofFailed;

    // Cache UID -> username to avoid forking `id` per port line.
    var uid_cache: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer {
        var it = uid_cache.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        uid_cache.deinit(allocator);
    }

    var ports: std.ArrayList(PortInfo) = .empty;
    errdefer {
        for (ports.items) |port| port.deinit(allocator);
        ports.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');

    var current_pid: u32 = 0;
    var current_cmd: []const u8 = "";
    var current_uid: []const u8 = "";
    var current_type: []const u8 = "unknown";

    while (lines.next()) |line| {
        if (line.len == 0) continue;

        const field_type = line[0];
        const field_data = if (line.len > 1) line[1..] else "";

        switch (field_type) {
            'p' => {
                current_cmd = "";
                current_uid = "";
                current_type = "unknown";
                current_pid = std.fmt.parseInt(u32, field_data, 10) catch blk: {
                    std.debug.print("warning: skipping entry with unparseable PID '{s}'\n", .{field_data});
                    break :blk 0;
                };
            },
            'c' => current_cmd = field_data,
            'u' => current_uid = field_data,
            'P' => current_type = field_data,
            'n' => {
                if (current_pid == 0 or current_cmd.len == 0) continue;
                if (std.mem.eql(u8, field_data, "*:*")) continue;

                const username = resolveUsername(allocator, current_uid, &uid_cache);

                if (parseNetworkLine(allocator, field_data, current_type, current_pid, current_cmd, username)) |port| {
                    if (isDuplicate(ports.items, port)) {
                        port.deinit(allocator);
                        continue;
                    }
                    ports.append(allocator, port) catch |err| {
                        port.deinit(allocator);
                        return err;
                    };
                } else |err| {
                    std.debug.print("warning: skipping malformed address '{s}': {}\n", .{ field_data, err });
                }
            },
            else => {},
        }
    }

    return ports;
}

fn resolveUsername(
    allocator: std.mem.Allocator,
    uid: []const u8,
    cache: *std.StringHashMapUnmanaged([]const u8),
) []const u8 {
    if (uid.len == 0) return "unknown";
    if (cache.get(uid)) |cached| return cached;

    const name = lookupUsername(allocator, uid) catch return uid;
    const key = allocator.dupe(u8, uid) catch {
        allocator.free(name);
        return uid;
    };
    cache.put(allocator, key, name) catch {
        allocator.free(key);
        allocator.free(name);
        return uid;
    };
    return name;
}

fn lookupUsername(allocator: std.mem.Allocator, uid: []const u8) ![]const u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "id", "-nu", uid },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const code = switch (result.term) {
        .Exited => |code| code,
        else => return error.IdFailed,
    };
    if (code != 0) return error.IdFailed;

    const trimmed = std.mem.trim(u8, result.stdout, " \n\r\t");
    return try allocator.dupe(u8, trimmed);
}

fn isDuplicate(existing: []const PortInfo, new: PortInfo) bool {
    for (existing) |e| {
        if (e.port == new.port and e.pid == new.pid and std.mem.eql(u8, e.protocol, new.protocol)) return true;
    }
    return false;
}

fn parseNetworkLine(
    allocator: std.mem.Allocator,
    addr_str: []const u8,
    protocol: []const u8,
    pid: u32,
    command: []const u8,
    user: []const u8,
) !PortInfo {
    //  *:59865  |  127.0.0.1:5432  |  [::1]:5432
    const colon_idx = std.mem.lastIndexOfScalar(u8, addr_str, ':') orelse return error.InvalidFormat;
    if (colon_idx == 0) return error.InvalidFormat;

    const port_str = addr_str[colon_idx + 1 ..];
    const port = try std.fmt.parseInt(u16, port_str, 10);

    const proto = try allocator.dupe(u8, protocol);
    errdefer allocator.free(proto);

    const name = try allocator.dupe(u8, command);
    errdefer allocator.free(name);

    const owned_user = try allocator.dupe(u8, user);

    return PortInfo{
        .port = port,
        .protocol = proto,
        .process_name = name,
        .pid = pid,
        .user = owned_user,
    };
}
