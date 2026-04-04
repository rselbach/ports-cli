const std = @import("std");
const PortInfo = @import("main.zig").PortInfo;

pub fn getListeningPorts(allocator: std.mem.Allocator) !std.ArrayList(PortInfo) {
    _ = allocator;
    @compileError("Linux support not yet implemented");
}
