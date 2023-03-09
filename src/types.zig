const builtin = @import("builtin");

pub usingnamespace switch (builtin.cpu.arch) {
    .i386 => struct {
        pub const Addr = u32;
        pub const Offset = u32;
        pub const Half = u16;
        pub const Word = u32;
        pub const Sword = i32;
    },
    .x86_64 => struct {
        pub const Addr = u64;
    }
}