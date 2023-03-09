const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const io = std.io;
const fs = std.fs;
const debug = std.debug;
const ArrayList = std.ArrayList;
const Allocator = mem.Allocator;
const HashMaps = std.hash_map;
const HashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const ArrayHashMap = std.ArrayHashMap;

const Buffer = @import("main.zig").Buffer;

pub const RelocType = enum(u32) {
    R_X86_64_NONE,
    R_X86_64_64,
    R_X86_64_PC32,
    R_X86_64_GOT32,
    R_X86_64_PLT32,
    R_X86_64_COPY,
    R_X86_64_GLOB_DAT,
    R_X86_64_JUMP_SLOT,
    R_X86_64_RELATIVE,
    R_X86_64_GOTPCREL,
    R_X86_64_32,
    R_X86_64_32S,
    R_X86_64_16,
    R_X86_64_PC16,
    R_X86_64_8,
    R_X86_64_PC8,
    R_X86_64_DPTMOD64,
    R_X86_64_DTPOFF64,
    R_X86_64_TPOFF64,
    R_X86_64_TLSGD,
    R_X86_64_TLSLD,
    R_X86_64_DTPOFF32,
    R_X86_64_GOTTPOFF,
    R_X86_64_TPOFF32,
    R_X86_64_PC64,
    R_X86_64_GOTOFF64,
    R_X86_64_GOTPC32,
};

pub const SymbolType = enum(u4) {
    STT_NOTYPE = 0,
    STT_OBJECT = 1,
    STT_FUNC = 2,
    STT_SECTION = 3,
    STT_FILE = 4,
    STT_LOPROC = 13,
    STT_HIPROC = 15,
};

pub const SymbolBind = enum(u4) {
    STB_LOCAL = 0,
    STB_GLOBAL = 1,
    STB_WEAK = 2,
    STB_LOOS = 10,
    STB_HIOS = 12,
    STB_LOPROC = 13,
    STB_HIPROC = 15,
};

pub const SymbolVisibility = enum(u8) {
    STV_DEFAULT = 0,
    STV_INTERNAL = 1,
    STV_HIDDEN = 2,
    STV_PROTECTED = 3,
};

pub const Symbol = struct {
    name: elf.Elf64_Word,
    symbol_type: SymbolType,
    symbol_binding: SymbolBind,
    visibility: SymbolVisibility,
    section_index: elf.Elf64_Section,
    value: elf.Elf64_Addr,
    size: elf.Elf64_Xword,

    const Self = @This();

    pub fn new (symbol: elf.Elf64_Sym) Self {
        return Self {
            .name = symbol.st_name,
            .symbol_type = @intToEnum(SymbolType, @truncate(u4, symbol.st_info)),
            .symbol_binding = @intToEnum(SymbolBind, @truncate(u4, symbol.st_info >> 4)),
            .visibility = @intToEnum(SymbolVisibility, symbol.st_other),
            .section_index = symbol.st_shndx,
            .value = symbol.st_value,
            .size = symbol.st_size,
        };
    }
};

pub const Section = struct {
    name_offset: elf.Elf64_Word,
    kind: SectionKind,
    flags: SectionFlags,
    addr: ?elf.Elf64_Addr,
    offset: elf.Elf64_Off,
    size: elf.Elf64_Xword,
    link: elf.Elf64_Word,
    info: elf.Elf64_Word,
    addralign: ?elf.Elf64_Xword,
    entry_size: ?elf.Elf64_Xword,
    raw_header: elf.Elf64_Shdr,
    contents: ?Buffer,

    const Self = @This();

    pub fn new (section: elf.Elf64_Shdr) Self {
        return Self {
            .name_offset = section.sh_name,
            .kind = @intToEnum(SectionKind, section.sh_type),
            .flags = @bitCast(SectionFlags, section.sh_flags),
            .addr = toNull(@TypeOf(section.sh_addr), section.sh_addr),
            .offset = section.sh_offset,
            .size = section.sh_size,
            .link = section.sh_link,
            .info = section.sh_info,
            .addralign = toNull(@TypeOf(section.sh_addralign), section.sh_addralign),
            .entry_size = toNull(@TypeOf(section.sh_entsize), section.sh_entsize),
            .raw_header = section,
            .contents = null,
        };
    }

    pub fn filesize (self: Self) usize {
        return switch (self.kind) {
            .SHT_NOBITS => 0,
            else => self.size,
        };
    }
    
    pub fn raw (self: Self) elf.Elf64_Shdr {
        return .{
            .sh_name = self.name_offset,
            .sh_type = @enumToInt(self.kind),
            .sh_flags = @bitCast(elf.Elf64_Xword, self.flags),
            .sh_addr = self.addr orelse 0,
            .sh_offset = self.offset,
            .sh_size = self.size,
            .sh_link = self.link,
            .sh_info = self.info,
            .sh_addralign = self.addralign orelse @panic("address alignment must be set"),
            .sh_entsize = self.entry_size orelse 0,
        };
    }

    pub fn getContents (self: *Self, stream: anytype, allocator: anytype) *Buffer {
        if (self.contents) |*contents| {
            return contents;
        } else {
            self.contents = Buffer.new(readSection(self.raw_header, stream, allocator) catch @panic("unable to read section"));
            return &self.contents.?;
        }
    }

    pub fn seekableStream (self: *Self, stream: anytype, allocator: anytype) Buffer.SeekableStream {
        return self.getContents(stream, allocator).seekableStream();
    }

    pub fn reader (self: *Self, stream: anytype, allocator: anytype) Buffer.Reader {
        return self.getContents(stream, allocator).reader();
    }

    pub fn writer (self: *Self, stream: anytype, allocator: anytype) Buffer.Writer {
        return self.getContents(stream, allocator).writer();
    }

    pub fn drop (self: *Self, allocator: anytype) void {
        if (self.contents) |contents| {
            allocator.free(contents.buffer);
        }
        allocator.destroy(self);
    }

    fn toNull (comptime T: type, val: T) ?T {
        if (val == 0) {
            return null;
        } else {
            return val;
        }
    }
};

pub const SectionKind = enum(u32) {
    SHT_NULL = 0,
    SHT_PROGBITS = 1,
    SHT_SYMTAB = 2,
    SHT_STRTAB = 3,
    SHT_RELA = 4,
    SHT_HASH = 5,
    SHT_DYNAMIC = 6,
    SHT_NOTE = 7,
    SHT_NOBITS = 8,
    SHT_REL = 9,
    SHT_SHLIB = 10,
    SHT_DYNSYM = 11,
    SHT_INIT_ARRAY = 14,
    SHT_FINI_ARRAY = 15,
    SHT_PREINIT_ARRAY = 16,
    SHT_GROUP = 17,
    SHT_SYMTAB_SHNDX = 18,
    SHT_LOOS = 0x60000000,
    SHT_HIOS = 0x6fffffff,
    SHT_LOPROC = 0x70000000,
    SHT_HIPROC = 0x7fffffff,
    SHT_LOUSER = 0x80000000,
    SHT_HIUSER = 0xffffffff,
};

const SectionFlags = packed struct {
    write: bool,
    alloc: bool,
    exec: bool,
    merge: bool,
    strings: bool,
    info_link: bool,
    link_order: bool,
    os_specific: bool,
    group: bool,
    tls: bool,
    reversed: u54,
};

fn isNull (comptime T: type, val: ?T) bool {
    if (val) |_| {
        return true;
    } else {
        return false;
    }
}

fn readSection (section: elf.Elf64_Shdr, stream: anytype, allocator: anytype) ![]align(8) u8 {
    const size = switch (@intToEnum(SectionKind, section.sh_type)) {
        .SHT_NOBITS => 0,
        else => section.sh_size,
    };
    var buffer = try allocator.alignedAlloc(u8, 8, size);
    try stream.seekableStream().seekTo(section.sh_offset);
    _ = try stream.reader().read(buffer);
    return buffer;
}

pub const SymbolList = struct {
    symbols: []const Symbol,
    allocator: Allocator,

    const Self = @This();

    pub fn new (section: elf.Elf64_Shdr, stream: anytype, allocator: anytype) !Self {
        const buffer = try readSection(section, stream, allocator);
        defer allocator.free(buffer);
        const len = buffer.len / @sizeOf(elf.Elf64_Sym);
        const raw = @ptrCast([*]const elf.Elf64_Sym, buffer.ptr)[0 .. len];
        const symbols = try allocator.alloc(Symbol, len);

        for (symbols) |_, idx| {
            symbols[idx] = Symbol.new(raw[idx]);
        }

        return Self {
            .symbols = symbols,
            .allocator = allocator,
        };
    }

    pub fn items (self: *Self) []const Symbol {
        return self.symbols;
    }

    pub fn deinit (self: *Self) void {
        self.allocator.free(self.symbols);
    }
};

pub fn getSymbolTable (header: elf.Header, sections: []elf.Elf64_Shdr, stream: anytype, allocator: anytype) !SymbolList {
    _ = header;
    for (sections) |section| {
        if (section.sh_type == elf.SHT_SYMTAB) {
            return SymbolList.new(section, stream, allocator);
        }
    }
    @panic("unable to find symbol table");
}

pub fn getSectionNames (header: elf.Header, sections: []elf.Elf64_Shdr, stream: anytype, allocator: anytype) !StringList {
    const section_names = sections[header.shstrndx];
    return try StringList.new(section_names, stream, allocator);
}

pub fn getSymbolNames (header: elf.Header, sections: []elf.Elf64_Shdr, stream: anytype, allocator: anytype) !StringList {
    for (sections) |section, idx| {
        if (section.sh_type == elf.SHT_STRTAB and idx != header.shstrndx) {
            return try StringList.new(section, stream, allocator);
        }
    }
    @panic("unable to find symbol names");
}

const StringList = struct {
    buffer: []const u8,
    allocator: mem.Allocator,

    const Self = @This();

    pub fn new (section: elf.Elf64_Shdr, stream: anytype, allocator: anytype) !Self {
        var buffer = try readSection(section, stream, allocator);

        return Self {
            .buffer = buffer,
            .allocator = allocator,
        };
    }

    pub fn get (self: *Self, offset: usize) [:0]const u8 {
        return mem.span(@ptrCast([*:0]const u8, self.buffer.ptr) + offset);
    }

    pub fn deinit (self: *Self) void {
        _ = self.allocator.free(self.buffer);
    }
};

fn StringArrayHashMap (comptime T: type) type {
    return ArrayHashMap([]const u8, T, std.array_hash_map.StringContext, true);
}

pub const SectionMap = StringArrayHashMap(*Section);

pub const SymbolMap = StringArrayHashMap(Symbol);

pub const RelocSection = struct {
    raw: []const elf.Elf64_Rela,
    target_section_index: usize,
    allocator: Allocator,

    const Self = @This();

    pub fn new (header: elf.Header, section: elf.Elf64_Shdr, stream: anytype, allocator: anytype) !Self {
        _ = header;

        debug.assert(section.sh_type == @enumToInt(SectionKind.SHT_RELA));
        
        var buffer = try readSection(section, stream, allocator);
        var relocs = buffer.len / @sizeOf(elf.Elf64_Rela);
        var raw = @ptrCast([*]const elf.Elf64_Rela, buffer.ptr)[0 .. relocs];
        return Self {
            .raw = raw,
            .target_section_index = section.sh_info,
            .allocator = allocator,
        };
    }

    pub fn items (self: Self) []const elf.Elf64_Rela {
        return self.raw;
    }

    pub fn deinit (self: *Self) void {
        self.allocator.free(self.raw);
    }
};

pub const RelocSections = struct {
    sections: []RelocSection,
    allocator: mem.Allocator,

    const Self = @This();

    pub fn new (header: elf.Header, sections: []const elf.Elf64_Shdr, stream: anytype, allocator: anytype) !Self {
        var relocs: usize = 0;
        for (sections) |section| {
            if (section.sh_type == @enumToInt(SectionKind.SHT_RELA)) {
                relocs += 1;
            }
        }

        var index: usize = 0;
        var relocations = try allocator.alloc(RelocSection, relocs);
        for (sections) |section| {
            if (section.sh_type == @enumToInt(SectionKind.SHT_RELA)) {
                relocations[index] = try RelocSection.new(header, section, stream, allocator);
                index += 1;
            }
        }

        return Self {
            .sections = relocations,
            .allocator = allocator,
        };
    }

    pub fn items (self: Self) []const RelocSection {
        return self.sections;
    }

    pub fn deinit (self: *Self) void {
        for (self.sections) |*section| {
            section.deinit();
        }
        self.allocator.free(self.sections);
    }
};

pub const PageSize: usize = 0x1000;
pub const SegmentAlignment: usize = 0x200000;

pub fn isAligned (address: usize, comptime alignment: usize) bool {
    return switch (@popCount(alignment)) {
        0 => @compileError("alignment cannot be zero"),
        1 => (address & alignment - 1) == 0,
        else => (address % alignment) == 0,
    };
}

pub fn resolveSectionVirtualAddresses (base_address: usize, section_map: SectionMap, symbol_map: SymbolMap) usize {
    debug.assert(isAligned(base_address, SegmentAlignment));
    var address = base_address;
    var it = section_map.iterator();
    while (it.next()) |entry| {
        var section_name = entry.key_ptr.*;
        var section = entry.value_ptr.*;
        if (isNull(@TypeOf(section.addr), section.addr)) {
            section.addr = address;
            debug.print("section_name: {s}\n", .{section_name});
            debug.print("section_kind: {any}\n", .{section.kind});
            debug.print("section_flag: {any}\n", .{section.flags});
            if (symbol_map.getPtr(section_name)) |symbol| {
                symbol.value = address;
            }
            address += mem.alignForward(section.size, SegmentAlignment);
        } else {
            unreachable;
        }
    }
    return address;
}

pub const SegmentKind = enum(elf.Elf64_Word) {
    PT_NULL = 0,
    PT_LOAD = 1,
    PT_DYNAMIC = 2,
    PT_INTERP = 3,
    PT_NOTE = 4,
    PT_SHLIB = 5,
    PT_PHDR = 6,
    PT_TLS = 7,
    PT_LOOS = 0x60000000,
    PT_HIOS = 0x6fffffff,
    PT_LOPROC = 0x70000000,
    PT_HIPROC = 0x7fffffff,
};

pub const SegmentFlags = packed struct {
    PF_X: bool,
    PF_W: bool,
    PF_R: bool,
    reserved: u29,
};

pub const Segment = struct {
    kind: SegmentKind,
    flags: SegmentFlags,
    offset: ?elf.Elf64_Off,
    vaddr: ?elf.Elf64_Addr,
    filesz: elf.Elf64_Xword,
    memsz: elf.Elf64_Xword,
    alignment: elf.Elf64_Xword,

    const Self = @This();

    pub fn raw (self: Self) elf.Elf64_Phdr {
        return .{
            .p_type = @enumToInt(self.kind),
            .p_flags = @bitCast(elf.Elf64_Word, self.flags),
            .p_offset = self.offset orelse @panic("offset field of segment is null"),
            .p_vaddr = self.vaddr orelse 0,
            .p_paddr = self.vaddr orelse 0,
            .p_filesz = self.filesz,
            .p_memsz = self.memsz,
            .p_align = self.alignment,
        };
    }
};

pub const Class = enum(u8) {
    None = 0,
    Bits32 = 1,
    Bits64 = 2,
};

pub const Encoding = enum(u8) {
    None,
    LittleEndian,
    BigEndian,
};

pub const OsAbi = enum(u8) {
    SystemV,
    Hpux,
    Netbsd,
    Linux,
    GNUhurd,
    Solaris,
    Aix,
    Irix,
    Freebsd,
    Tru64,
    Modesto,
    Openbsd,
    Openvms,
    Nsk,
    Aros,
    FenixOS,
    Nuxi,
    Openvos,
};

pub const Identifier = extern struct {
    magic: [4]u8,
    class: u8,
    encoding: u8,
    version: u8,
    os_abi: u8,
    abi_version: u8,

    const Self = @This();

    pub fn raw (self: Self) [elf.EI_NIDENT]u8 {
        var dst = [_]u8{0} ** elf.EI_NIDENT;
        mem.copy(u8, dst[0 .. @sizeOf(Self)], @ptrCast([*]const u8, &self)[0 .. @sizeOf(Self)]);
        return dst;
    }
};

pub const SegmentList = ArrayList(Segment);

pub const Builder = struct {
    sections: SectionMap,
    segments: SegmentList,
    allocator: Allocator,
    vaddr_base: usize,

    const Self = @This();

    const Error = error {

    };

    pub fn new (
        sections: SectionMap,
        allocator: anytype,
        vaddr_base: usize,
    ) Self {
        return Self {
            .sections = sections,
            .segments = SegmentList.init(allocator) catch @panic("failed to allocate segments array"),
            .allocator = allocator,
            .vaddr_base = vaddr_base,
        };
    }

    pub fn build (self: *Self) !void {
        var stream = try fs.cwd().createFile("tmp.elf", .{
            .read = true,
            .truncate = true,
        });
        defer stream.close();

        var segments = ArrayList(u8).init(self.allocator);
        defer segments.deinit();

        // for (self.sections.keys()) |section| {

        // }

        const phdr_offset = @sizeOf(elf.Elf64_Ehdr);
        const phdr_filesz = @sizeOf(elf.Elf64_Phdr) * segments.items.len;
        const shdr_offset = phdr_offset + phdr_filesz;
        // const shdr_filesz = @sizeOf(elf.Elf64_Shdr) * self.sections.items.len;

        var header = elf.Elf64_Ehdr {
            .e_ident = [_]u8{0x7F, 'E', 'L', 'F'} ++ [_]u8{ elf.ELFCLASS64, elf.ELFDATA2LSB, 1, 0, 0 } ++ [_]u8{0} ** 7,
            .e_type = elf.ET.EXEC,
            .e_machine = elf.EM.X86_64,
            .e_version = 0,
            .e_entry = 0x100000,
            .e_phoff = phdr_offset,
            .e_shoff = shdr_offset,
            .e_flags = 0,
            .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
            .e_phentsize = @sizeOf(elf.Elf64_Phdr),
            .e_phnum = @truncate(u16, self.segments.items.len),
            .e_shentsize = @sizeOf(elf.Elf64_Shdr),
            .e_shnum = @truncate(u16, self.sections.values().len),
            .e_shstrndx = 0,
        };

        debug.print("{any} {any}\n", .{stream, header});
    }

    fn resolve (self: *Self) !void {
        _ = self;
    }
};