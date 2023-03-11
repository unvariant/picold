const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const meta = std.meta;

const Target = std.Target;
const ChildProcess = std.ChildProcess;
const Allocator = mem.Allocator;
const Arch = Target.Cpu.Arch;
const Tuple = meta.Tuple;

pub const DetectError = error {
    Failure,
    Unrecognized,
};

pub usingnamespace switch (builtin.os.tag) {
    .windows => struct {
        pub fn getArch (allocator: Allocator) !Arch {
            _ = allocator;
            if (std.zig.system.NativeTargetInfo.detectNativeCpuAndFeatures()) |cpu| {
                return cpu.arch;
            }
            return DetectError.Failure;
        }
    },
    .linux, .macos => struct {
        pub fn getArch (allocator: Allocator) !Arch {
            const output = try ChildProcess.exec(.{
                .allocator = allocator,
                .argv = &[_][]const u8 {
                    "uname", "-m"
                },
            });

            const newline = mem.indexOf(u8, output.stdout, "\n") orelse output.stdout.len;
            const archname = output.stdout[0 .. newline];

            const targets = &[_]Tuple(&.{[]const []const u8, Arch}) {
                .{
                    &[_][]const u8 {
                        "arm64",
                    },
                    .aarch64,
                },
            };

            for (targets) |target| {
                for (target[0]) |name| {
                    if (mem.eql(u8, archname, name)) {
                        return target[1];
                    }
                }
            }
            return DetectError.Unrecognized;
        }
    },
    else => @compileError("unsupported platform"),
};