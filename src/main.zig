const std = @import("std");
const common = @import("target/common.zig");

const debug = std.debug;

const print = debug.print;

pub fn main () !void {
    const flags = @import("target/x86-64.zig").SectionType.Unwind;
    print("{X}\n", .{ @enumToInt(flags), });
}