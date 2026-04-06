const std = @import("std");
const PortInfo = @import("main.zig").PortInfo;

const SocketEntry = struct {
    inode: u64,
    port: u16,
    protocol: []const u8, // static string, not owned
    uid: u32,
};

const PidInfo = struct {
    pid: u32,
    comm: []const u8, // heap-allocated
};

pub fn getListeningPorts(allocator: std.mem.Allocator) !std.ArrayList(PortInfo) {
    // Phase 1: Parse /proc/net/{tcp,tcp6,udp,udp6}
    var sockets: std.ArrayList(SocketEntry) = .empty;
    defer sockets.deinit(allocator);

    const paths = [_][]const u8{ "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6" };
    const states = [_][]const u8{ "0A", "0A", "07", "07" };
    const protos = [_][]const u8{ "TCP", "TCP", "UDP", "UDP" };

    for (paths, states, protos) |path, state, proto| {
        collectSockets(allocator, &sockets, path, state, proto) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
    }

    // Phase 2: Build inode -> (pid, process_name) map by scanning /proc/[pid]/fd/
    //          Without sudo, only the current user's processes are visible.
    var inode_map: std.AutoHashMapUnmanaged(u64, PidInfo) = .empty;
    defer {
        var it = inode_map.iterator();
        while (it.next()) |entry| allocator.free(entry.value_ptr.comm);
        inode_map.deinit(allocator);
    }
    buildInodeMap(allocator, &inode_map) catch |err| {
        std.debug.print("warning: could not scan /proc for process info: {}\n", .{err});
    };

    // Phase 3: UID -> username cache
    var uid_cache: std.AutoHashMapUnmanaged(u32, []const u8) = .empty;
    defer {
        var it = uid_cache.iterator();
        while (it.next()) |entry| allocator.free(entry.value_ptr.*);
        uid_cache.deinit(allocator);
    }

    // Phase 4: Merge into PortInfo list
    var ports: std.ArrayList(PortInfo) = .empty;
    errdefer {
        for (ports.items) |p| p.deinit(allocator);
        ports.deinit(allocator);
    }

    for (sockets.items) |socket| {
        const pid_info = inode_map.get(socket.inode);
        const pid: u32 = if (pid_info) |pi| pi.pid else 0;
        const comm: []const u8 = if (pid_info) |pi| pi.comm else "-";
        const username = resolveUsername(allocator, socket.uid, &uid_cache);

        const proto = try allocator.dupe(u8, socket.protocol);
        errdefer allocator.free(proto);
        const name = try allocator.dupe(u8, comm);
        errdefer allocator.free(name);
        const user = try allocator.dupe(u8, username);

        const port_info = PortInfo{
            .port = socket.port,
            .protocol = proto,
            .process_name = name,
            .pid = pid,
            .user = user,
        };

        if (isDuplicate(ports.items, port_info)) {
            port_info.deinit(allocator);
            continue;
        }

        ports.append(allocator, port_info) catch |err| {
            port_info.deinit(allocator);
            return err;
        };
    }

    return ports;
}

// ── /proc/net/* parsing ──────────────────────────────────────────────

fn collectSockets(
    allocator: std.mem.Allocator,
    sockets: *std.ArrayList(SocketEntry),
    path: []const u8,
    target_state: []const u8,
    protocol: []const u8,
) !void {
    const content = try readProcFile(allocator, path);
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next(); // skip header

    while (lines.next()) |line| {
        if (parseLine(line, target_state, protocol)) |entry| {
            try sockets.append(allocator, entry);
        }
    }
}

fn readProcFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        try list.appendSlice(allocator, buf[0..n]);
    }
    return try list.toOwnedSlice(allocator);
}

//   /proc/net/tcp line format (whitespace-separated fields):
//
//     [0]  sl:             slot number
//     [1]  local_address   hex_ip:hex_port  (e.g. 0100007F:0035)
//     [2]  rem_address     hex_ip:hex_port
//     [3]  st              hex state  (0A = TCP LISTEN, 07 = UDP bound)
//     [4]  tx_queue:rx_queue
//     [5]  tr:tm->when
//     [6]  retrnsmt
//     [7]  uid             numeric UID of socket owner
//     [8]  timeout
//     [9]  inode           socket inode number
fn parseLine(line: []const u8, target_state: []const u8, protocol: []const u8) ?SocketEntry {
    var fields = std.mem.tokenizeAny(u8, line, " \t");
    _ = fields.next() orelse return null; // [0] sl:
    const local_addr = fields.next() orelse return null; // [1]
    _ = fields.next() orelse return null; // [2]
    const state = fields.next() orelse return null; // [3]
    _ = fields.next() orelse return null; // [4]
    _ = fields.next() orelse return null; // [5]
    _ = fields.next() orelse return null; // [6]
    const uid_str = fields.next() orelse return null; // [7]
    _ = fields.next() orelse return null; // [8]
    const inode_str = fields.next() orelse return null; // [9]

    if (!std.mem.eql(u8, state, target_state)) return null;

    const port = parseHexPort(local_addr) catch return null;
    const uid = std.fmt.parseInt(u32, uid_str, 10) catch return null;
    const inode = std.fmt.parseInt(u64, inode_str, 10) catch return null;
    if (inode == 0) return null;

    return .{ .inode = inode, .port = port, .protocol = protocol, .uid = uid };
}

fn parseHexPort(addr: []const u8) !u16 {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.InvalidFormat;
    return std.fmt.parseInt(u16, addr[colon + 1 ..], 16);
}

// ── /proc/[pid]/fd/ scanning ─────────────────────────────────────────
//
//    Reads symlinks in /proc/[pid]/fd/ looking for "socket:[inode]".
//    Without sudo, openDir on another user's /proc/[pid]/fd/ fails
//    with EACCES — we skip silently and those ports show pid=0, name="-".

fn buildInodeMap(allocator: std.mem.Allocator, map: *std.AutoHashMapUnmanaged(u64, PidInfo)) !void {
    var proc_dir = try std.fs.openDirAbsolute("/proc", .{ .iterate = true });
    defer proc_dir.close();

    var proc_iter = proc_dir.iterate();
    while (try proc_iter.next()) |entry| {
        _ = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        scanPidFds(allocator, map, proc_dir, entry.name) catch continue;
    }
}

fn scanPidFds(
    allocator: std.mem.Allocator,
    map: *std.AutoHashMapUnmanaged(u64, PidInfo),
    proc_dir: std.fs.Dir,
    pid_name: []const u8,
) !void {
    var pid_dir = proc_dir.openDir(pid_name, .{}) catch return;
    defer pid_dir.close();

    const pid = std.fmt.parseInt(u32, pid_name, 10) catch return;

    var fd_dir = pid_dir.openDir("fd", .{ .iterate = true }) catch return;
    defer fd_dir.close();

    var comm: ?[]const u8 = null;
    defer if (comm) |c| allocator.free(c);

    var fd_iter = fd_dir.iterate();
    while (fd_iter.next() catch null) |fd_entry| {
        var buf: [256]u8 = undefined;
        const link = fd_dir.readLink(fd_entry.name, &buf) catch continue;

        const inode = parseSocketInode(link) orelse continue;
        if (map.get(inode) != null) continue; // already mapped (e.g. forked socket)

        if (comm == null) {
            comm = readComm(allocator, pid_dir) catch (allocator.dupe(u8, "?") catch continue);
        }

        const comm_copy = allocator.dupe(u8, comm.?) catch continue;
        map.put(allocator, inode, .{ .pid = pid, .comm = comm_copy }) catch {
            allocator.free(comm_copy);
            continue;
        };
    }
}

fn parseSocketInode(link: []const u8) ?u64 {
    const prefix = "socket:[";
    if (!std.mem.startsWith(u8, link, prefix)) return null;
    if (!std.mem.endsWith(u8, link, "]")) return null;
    return std.fmt.parseInt(u64, link[prefix.len .. link.len - 1], 10) catch null;
}

fn readComm(allocator: std.mem.Allocator, pid_dir: std.fs.Dir) ![]const u8 {
    const file = try pid_dir.openFile("comm", .{});
    defer file.close();
    var buf: [256]u8 = undefined;
    const n = try file.readAll(&buf);
    return try allocator.dupe(u8, std.mem.trim(u8, buf[0..n], "\n"));
}

// ── UID -> username resolution (same approach as darwin.zig) ─────────

fn resolveUsername(
    allocator: std.mem.Allocator,
    uid: u32,
    cache: *std.AutoHashMapUnmanaged(u32, []const u8),
) []const u8 {
    if (cache.get(uid)) |cached| return cached;

    const name = lookupUsername(allocator, uid) catch return "?";
    cache.put(allocator, uid, name) catch {
        allocator.free(name);
        return "?";
    };
    return name;
}

fn lookupUsername(allocator: std.mem.Allocator, uid: u32) ![]const u8 {
    var uid_buf: [16]u8 = undefined;
    const uid_str = std.fmt.bufPrint(&uid_buf, "{d}", .{uid}) catch unreachable;

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "id", "-nu", uid_str },
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

// ── deduplication ────────────────────────────────────────────────────

fn isDuplicate(existing: []const PortInfo, new: PortInfo) bool {
    for (existing) |e| {
        if (e.port == new.port and e.pid == new.pid and std.mem.eql(u8, e.protocol, new.protocol)) return true;
    }
    return false;
}

// ── tests ────────────────────────────────────────────────────────────

test "parseHexPort IPv4" {
    try std.testing.expectEqual(@as(u16, 53), try parseHexPort("0100007F:0035"));
    try std.testing.expectEqual(@as(u16, 631), try parseHexPort("00000000:0277"));
    try std.testing.expectEqual(@as(u16, 5355), try parseHexPort("00000000:14EB"));
    try std.testing.expectEqual(@as(u16, 22), try parseHexPort("00000000:0016"));
}

test "parseHexPort IPv6" {
    try std.testing.expectEqual(@as(u16, 631), try parseHexPort("00000000000000000000000001000000:0277"));
    try std.testing.expectEqual(@as(u16, 5355), try parseHexPort("00000000000000000000000000000000:14EB"));
}

test "parseSocketInode" {
    try std.testing.expectEqual(@as(?u64, 12345), parseSocketInode("socket:[12345]"));
    try std.testing.expectEqual(@as(?u64, null), parseSocketInode("pipe:[12345]"));
    try std.testing.expectEqual(@as(?u64, null), parseSocketInode("anon_inode:[eventfd]"));
    try std.testing.expectEqual(@as(?u64, null), parseSocketInode(""));
}

test "parseLine TCP LISTEN" {
    const line = "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   974        0 12509 1 00000000dac3e7ad 100 0 0 10 5";
    const entry = parseLine(line, "0A", "TCP") orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(@as(u16, 53), entry.port);
    try std.testing.expectEqual(@as(u32, 974), entry.uid);
    try std.testing.expectEqual(@as(u64, 12509), entry.inode);
    try std.testing.expectEqualStrings("TCP", entry.protocol);
}

test "parseLine skips non-LISTEN" {
    const line = "   0: 0100007F:0035 0100007F:D4A2 01 00000000:00000000 00:00000000 00000000  1000        0 56789 1 0000000000000000 100 0 0 10 0";
    try std.testing.expect(parseLine(line, "0A", "TCP") == null);
}

test "parseLine UDP" {
    const line = " 3554: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   969        0 7607 2 00000000e66fda4e 0";
    const entry = parseLine(line, "07", "UDP") orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(@as(u16, 5353), entry.port);
    try std.testing.expectEqual(@as(u32, 969), entry.uid);
    try std.testing.expectEqual(@as(u64, 7607), entry.inode);
    try std.testing.expectEqualStrings("UDP", entry.protocol);
}

test "parseLine skips inode 0" {
    const line = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0";
    try std.testing.expect(parseLine(line, "0A", "TCP") == null);
}

test "parseLine IPv6 TCP" {
    const line = "   0: 00000000000000000000000000000000:14EB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   974        0 12504 1 00000000e8ac4dcc 100 0 0 10 5";
    const entry = parseLine(line, "0A", "TCP") orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(@as(u16, 5355), entry.port);
    try std.testing.expectEqual(@as(u64, 12504), entry.inode);
}
