const std = @import("std");
const builtin = @import("builtin");

const platform = switch (builtin.os.tag) {
    .macos => @import("darwin.zig"),
    .linux => @import("linux.zig"),
    else => @compileError("unsupported platform"),
};

const SortField = enum { port, pid, proc };

const Options = struct {
    filter_port: ?u16 = null,
    sort_by: SortField = .port,
};

pub const PortInfo = struct {
    port: u16,
    protocol: []const u8,
    process_name: []const u8,
    pid: u32,
    user: []const u8,

    pub fn deinit(self: PortInfo, allocator: std.mem.Allocator) void {
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

    const opts = parseArgs(args) catch {
        std.process.exit(1);
    };

    var ports = try platform.getListeningPorts(allocator);
    defer {
        for (ports.items) |port| port.deinit(allocator);
        ports.deinit(allocator);
    }

    var buf: [4096]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    const stdout = &w.interface;

    std.mem.sortUnstable(PortInfo, ports.items, opts.sort_by, sortPorts);

    if (opts.filter_port) |target| {
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

fn parseArgs(args: []const []const u8) !Options {
    var opts: Options = .{};
    var i: usize = 1; // skip argv[0]
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.startsWith(u8, arg, "--sort=")) {
            opts.sort_by = parseSortField(arg["--sort=".len..]) orelse {
                printBadSortField(arg["--sort=".len..]);
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--sort")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: {s} requires a value (port, pid, proc)\n", .{arg});
                return error.InvalidArgs;
            }
            opts.sort_by = parseSortField(args[i]) orelse {
                printBadSortField(args[i]);
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp();
            std.process.exit(0);
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("Error: unknown option '{s}'\n", .{arg});
            return error.InvalidArgs;
        } else {
            opts.filter_port = std.fmt.parseInt(u16, arg, 10) catch {
                std.debug.print("Error: '{s}' is not a valid port number\n", .{arg});
                return error.InvalidArgs;
            };
        }
    }
    return opts;
}

fn parseSortField(value: []const u8) ?SortField {
    const fields = .{
        .{ "port", SortField.port },
        .{ "pid", SortField.pid },
        .{ "proc", SortField.proc },
        .{ "process", SortField.proc },
        .{ "name", SortField.proc },
    };
    inline for (fields) |f| {
        if (std.mem.eql(u8, value, f[0])) return f[1];
    }
    return null;
}

fn printHelp() void {
    std.debug.print(
        \\Usage: ports [options] [port]
        \\
        \\Show listening TCP and UDP ports.
        \\
        \\Arguments:
        \\  port                   Show details for a specific port number
        \\
        \\Options:
        \\  -s, --sort <field>     Sort output by: port (default), pid, proc
        \\  -h, --help             Show this help
        \\
    , .{});
}

fn printBadSortField(value: []const u8) void {
    std.debug.print("Error: '{s}' is not a valid sort field (port, pid, proc)\n", .{value});
}

fn sortPorts(sort_by: SortField, a: PortInfo, b: PortInfo) bool {
    return switch (sort_by) {
        .port => a.port < b.port,
        .pid => a.pid < b.pid,
        .proc => std.mem.order(u8, a.process_name, b.process_name) == .lt,
    };
}

