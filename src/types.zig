const std = @import("std");
const builtin = @import("builtin");

const elf = std.elf;

pub usingnamespace switch (builtin.cpu.arch) {
    .i386, .arm => struct {
        pub const Ehdr = elf.Elf32_Ehdr;
        pub const Phdr = elf.Elf32_Phdr;
        pub const Shdr = elf.Elf64_Shdr;


    },
    .x86_64, .aarch64 => struct {
        pub const Ehdr = elf.Elf64_Ehdr;
        pub const Phdr = elf.Elf64_Phdr;
        pub const Shdr = elf.Elf64_Phdr;
    }
};