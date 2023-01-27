const std = @import("std");
const debug = std.debug;
const io = std.io;
const testing = std.testing;
const GeneralPurposeAlloctor = std.heap.GeneralPurposeAlloctor(.{});

const clap = @import("clap");

pub fn main() !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\-I  --input            Input file to link
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
    }) catch |err| {
        // Report useful error and exit
        diag.report(io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.input) |input| {
        std.debug.print("{}\n", .{input});
    }
}