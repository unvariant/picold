const std = @import("std");
const common = @import("target/common.zig");
const link = @import("link.zig");
const heap = std.heap;
const process = std.process;

var GeneralPurposeAllocator = heap.GeneralPurposeAllocator(.{}){};
const ArenaAllocator = heap.ArenaAllocator;

const debug = std.debug;
const print = debug.print;

var arena = ArenaAllocator.init(GeneralPurposeAllocator.allocator());
var allocator = arena.allocator();

pub fn main () !void {
    var args = try process.argsWithAllocator(allocator);
    _ = args.next();

    if (args.next()) |path| {
        try link.withOptions(path, allocator, .{});
    }

    arena.deinit();
}