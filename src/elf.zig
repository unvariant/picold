const std = @import("std");
const builtin = @import("builtin");

const elf = std.elf;

const Arch = std.Target.Cpu.Arch;

pub fn fromArch (arch: Arch) type {
    return switch (arch) {
        .i386, .arm => struct {
            pub const Header = elf.Header;
            pub const Ehdr = elf.Elf32_Ehdr;
            pub const Phdr = elf.Elf32_Phdr;
            pub const Shdr = elf.Elf64_Shdr;
        },
        .x86_64, .aarch64 => struct {
            pub const Header = elf.Header;
            pub const Ehdr = elf.Elf64_Ehdr;
            pub const Phdr = elf.Elf64_Phdr;
            pub const Shdr = elf.Elf64_Phdr;
        },
        else => @compileError("architechture not supported"),
    };
}