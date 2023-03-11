const std = @import("std");
const elfGeneric = @import("elf.zig");
const detect = @import("detect.zig");

const fs = std.fs;
const elf = std.elf;
const mem = std.mem;
const debug = std.debug;

const Allocator = mem.Allocator;
const Target = std.Target;
const Arch = Target.Cpu.Arch;
const ArrayList = std.ArrayList;

fn Clone (comptime Self: type) type {
    return struct {
        pub fn clone (self: Self, allocator: Allocator) !*Self {
            var new = try allocator.create(Self);
            inline for (@typeInfo(Self).Struct.fields) |field| {
                @field(new, field.name) = @field(self, field.name);
            }
            return new;
        }
    };
}

pub fn withOptions (path: []const u8, allocator: Allocator, options: struct {

}) !void {
    var config = options;

    const SectionType = enum(u32) {
        Null,
        Progbits,
        Symtab,
        Strtab,
        Rela,
        Hash,
        Dynamic,
        Note,
        Nobits,
        Rel,
        Shlib,
        Dynsym,
        InitArray,
        FiniArray,
        PreinitArray,
        Group,
        SymtabIndex,
        Unwind = 0x70000001,
    };

    const SectionFlags = packed struct {
        write: bool = false,
        alloc: bool = false,
        exec: bool = false,
        merge: bool = false,
        strings: bool = false,
        info_link: bool = false,
        os_nonfonforming: bool = false,
        group: bool = false,
        tls: bool = false,
        reserved0: u55,
    };

    const Name = union {
        resolved: []const u8,
        unresolved: u64,
    };

    const Section = struct {
        name: Name,
        shtype: u32,
        flags: u64,
        addr: u64,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        alignment: u64,
        entsize: u64,

        const Self = @This();

        pub fn from (section: elf.Elf64_Shdr) Self {
            return .{
                .name = .{ .unresolved = section.sh_name, },
                .shtype = section.sh_type,
                .flags = section.sh_flags,
                .addr = section.sh_addr,
                .offset = section.sh_offset,
                .size = section.sh_size,
                .link = section.sh_link,
                .info = section.sh_info,
                .alignment = section.sh_addralign,
                .entsize = section.sh_entsize,
            };
        }

        pub usingnamespace Clone(Self);
    };

    const SectionList = ArrayList(Section);

    var input = try fs.cwd().openFile(path, .{});
    defer input.close();

    const input_size = (try input.metadata()).size();

    const header = try elf.Header.read(&input);
    var section_iterator = header.section_header_iterator(&input);
    var sections = SectionList.init(allocator);
    while (try section_iterator.next()) |section| {
        try sections.append(Section.from(section));
    }

    for (sections.items) |section| {
        debug.print("{any}\n", .{ section.name.unresolved, });
    }

    // 

    _ = config;
    _ = SectionType;
    _ = SectionFlags;
    _ = input_size;
}