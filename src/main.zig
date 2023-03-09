const std = @import("std");
const debug = std.debug;
const heap = std.heap;
const io = std.io;
const fs = std.fs;
const mem = std.mem;
const elf = std.elf;
const math = std.math;
const ArrayList = std.ArrayList;
const process = std.process;
const testing = std.testing;
const elf64 = @import("elf64.zig");
const StringHashMap = std.StringHashMap;

pub fn main () !void {
    var GeneralPurposeAllocator = heap.GeneralPurposeAllocator(.{}){};
    var allocator = GeneralPurposeAllocator.allocator();
    defer _ = GeneralPurposeAllocator.deinit();
    var args = try process.ArgIterator.initWithAllocator(allocator);

    _ = args.next();
    if (args.next()) |path| {
        try link(allocator, path);
    }
}

pub fn link (allocator: mem.Allocator, relative_path: []const u8) !void {
    var input = try fs.cwd().openFile(relative_path, .{});
    defer input.close();

    const size = (try input.metadata()).size();

    const contents = try input.reader().readAllAlloc(allocator, size);
    defer allocator.free(contents);

    var stream = Buffer.new(contents);
    const header = try elf.Header.read(&stream);

    var section_iterator = header.section_header_iterator(stream);
    var sections = try allocator.alloc(elf.Elf64_Shdr, header.shnum);
    defer _ = allocator.free(sections);
    for (sections) |_, idx| {
        sections[idx] = (try section_iterator.next()).?;
    }

    var section_names = try elf64.getSectionNames(header, sections, &stream, allocator);
    defer section_names.deinit();
    var symbol_names = try elf64.getSymbolNames(header, sections, &stream, allocator);
    defer symbol_names.deinit();
    var symbols = try elf64.getSymbolTable(header, sections, &stream, allocator);
    defer symbols.deinit();

    var section_map = elf64.SectionMap.init(allocator);
    defer section_map.deinit();
    var symbol_map = elf64.SymbolMap.init(allocator);
    defer symbol_map.deinit();

    for (sections) |section| {
        const name = section_names.get(section.sh_name);
        var sh = elf64.Section.new(section);
        var new = try allocator.create(elf64.Section);
        inline for (@typeInfo(elf64.Section).Struct.fields) |field| {
            @field(new, field.name) = @field(sh, field.name);
        } 
        try section_map.put(name, new);
    }

    for (symbols.items()) |symbol| {
        const name = switch (symbol.symbol_type) {
            .STT_SECTION => section_map.keys()[symbol.section_index],
            else => symbol_names.get(symbol.name),
        };
        symbol_map.put(name, symbol) catch {};
    }

    var rsections = try elf64.RelocSections.new(header, sections, &stream, allocator);
    defer rsections.deinit();

    const base_address = 0x400000;
    const end_address = elf64.resolveSectionVirtualAddresses(base_address, section_map, symbol_map);

    for (rsections.items()) |rsection| {
        for (rsection.items()) |relocation| {
            const symbol = symbol_map.values()[relocation.r_sym()];
            var target = section_map.values()[rsection.target_section_index];
            const rtype = @intToEnum(elf64.RelocType, relocation.r_type());
            try target.seekableStream(&stream, allocator).seekTo(relocation.r_offset);
            switch (rtype) {
                .R_X86_64_64 => {
                    _ = try target.writer(&stream, allocator).writeIntLittle(i64, @bitCast(i64, symbol.value) + relocation.r_addend);
                },
                else => unreachable,
            }
        }
    }

    var segments = ArrayList(elf64.Segment).init(allocator);
    defer segments.deinit();
    var sects = elf64.SectionMap.init(allocator);
    defer sects.deinit();

    var it = section_map.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const section = entry.value_ptr.*;
        var flags = @bitCast(elf64.SegmentFlags, @as(u32, 0));
        if (section.flags.alloc) {
            flags.PF_R = true;
        }
        if (section.flags.write) {
            flags.PF_W = true;
        }
        if (section.flags.exec) {
            flags.PF_X = true;
        }
        if (@bitCast(u32, flags) != 0) {
            flags.PF_W = true;
            flags.PF_R = true;
            flags.PF_X = true;
            try segments.append(.{
                .kind = .PT_LOAD,
                .flags = flags,
                .offset = null,
                .vaddr = section.addr,
                .filesz = section.getContents(&stream, allocator).seekableStream().getEndPos() catch 0,
                .memsz = section.size,
                .alignment = elf64.SegmentAlignment,
            });
            try sects.put(name, section);
        }
    }

    var strtab_header = elf64.Section.new(.{
        .sh_name = 0,
        .sh_type = @enumToInt(elf64.SectionKind.SHT_STRTAB),
        .sh_flags = 0,
        .sh_addr = 0,
        .sh_offset = 0,
        .sh_size = 0,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = 1,
        .sh_entsize = 0,
    });
    try sects.put(".shstrtab", &strtab_header);

    var shstrtab = Buffer.new(try allocator.dupe(u8, &[_]u8{ 0, }));
    for (sects.keys()) |name| {
        var section = sects.get(name).?;
        section.name_offset = @truncate(u32, try shstrtab.seekableStream().getEndPos());
        try shstrtab.extend(name, allocator);
        try shstrtab.extend(&[_]u8{ 0, }, allocator);
    }
    try shstrtab.extend(&[_]u8{ 0, }, allocator);
    sects.get(".shstrtab").?.contents = shstrtab;
    sects.get(".shstrtab").?.size = try shstrtab.seekableStream().getEndPos();

    var new = try fs.cwd().createFile("tmp.elf", .{
        .read = true,
        .truncate = true,
    });
    defer new.close();

    const phdr_offset = @sizeOf(elf.Elf64_Ehdr);
    const phdr_filesz = @sizeOf(elf.Elf64_Phdr) * segments.items.len;
    const shdr_offset = phdr_offset + phdr_filesz;

    const ident = elf64.Identifier {
        .magic = [4]u8{ 0x7F, 'E', 'L', 'F', },
        .class = @enumToInt(elf64.Class.Bits64),
        .encoding = @enumToInt(elf64.Encoding.LittleEndian),
        .version = 1,
        .os_abi = @enumToInt(elf64.OsAbi.SystemV),
        .abi_version = 0,
    };

    var hdr = elf.Elf64_Ehdr {
        .e_ident = ident.raw(),
        .e_type = elf.ET.EXEC,
        .e_machine = elf.EM.X86_64,
        .e_version = 1,
        .e_entry = 0x400000,
        .e_phoff = phdr_offset,
        .e_shoff = shdr_offset,
        .e_flags = 0,
        .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
        .e_phentsize = @sizeOf(elf.Elf64_Phdr),
        .e_phnum = @truncate(u16, segments.items.len),
        .e_shentsize = @sizeOf(elf.Elf64_Shdr),
        .e_shnum = @truncate(u16, sects.count()) + 1,
        .e_shstrndx = @truncate(u16, sects.count()),
    };

    if (segments.items.len > 0) {
        var fileoff: usize = hdr.e_shoff + hdr.e_shnum * hdr.e_shentsize;
        var iter = sects.iterator();
        while (iter.next()) |entry| {
            var section = entry.value_ptr.*;
            fileoff = mem.alignForward(fileoff, section.addralign.?);
            section.offset = fileoff;
            if (section.addr) |*addr| {
                addr.* += fileoff;
            }
            if (mem.eql(u8, entry.key_ptr.*, ".text")) {
                hdr.e_entry = section.addr.?;
            }
            fileoff += section.filesize();
        }
        
        var index: usize = 0;
        while (index < segments.items.len) : (index += 1) {
            segments.items[index].offset = sects.values()[index].offset;
            segments.items[index].vaddr.? += sects.values()[index].offset;
        }
    }

    _ = try new.writer().write(@ptrCast([*]u8, &hdr)[0 .. @sizeOf(elf.Elf64_Ehdr)]);

    for (segments.items) |item| {
        _ = try new.writer().writeStruct(item.raw());
    }

    _ = try new.writer().writeStruct(elf.Elf64_Shdr {
        .sh_name = 0,
        .sh_type = 0,
        .sh_flags = 0,
        .sh_addr = 0,
        .sh_offset = 0,
        .sh_size = 0,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = 0,
        .sh_entsize = 0,
    });

    for (sects.values()) |item| {
        _ = try new.writer().writeStruct(item.raw());
    }

    for (sects.values()) |item| {
        const end = try new.seekableStream().getEndPos();
        _ = try new.writer().writeByteNTimes(0, mem.alignForward(end, item.addralign.?) - end);
        _ = try new.writer().write(item.getContents(&stream, allocator).buffer);
    }

    _ = end_address;

    for (section_map.values()) |section| {
        section.drop(allocator);
    }
}

pub const Buffer = struct {
    buffer: []u8,
    offset: usize,

    const Self = @This();

    pub fn new (buffer: []u8) Self {
        return Self {
            .buffer = buffer,
            .offset = 0,
        };
    }

    pub fn extend (self: *Self, other: []const u8, allocator: anytype) !void {
        const end = self.buffer.len;
        self.buffer = try allocator.realloc(self.buffer, self.buffer.len + other.len);
        mem.copy(u8, self.buffer[end .. ], other);
    }

    pub const SeekableStream = io.SeekableStream(
        *Self,
        SeekError,
        error{},
        seekTo,
        seekBy,
        getPos,
        getEndPos,
    );

    pub const SeekError = error {
        OutOfBounds,
    };

    pub fn seekableStream (self: *Self) SeekableStream {
        return .{ .context = self };
    }

    fn seekTo (self: *Self, pos: u64) SeekError!void {
        if (pos < 0 or pos >= self.buffer.len) {
            return error.OutOfBounds;
        }
        self.offset = pos;
    }

    fn seekBy (self: *Self, pos: i64) SeekError!void {
        const new_offset = @intCast(i64, self.offset) + pos;
        if (new_offset < 0 or new_offset >= self.buffer.len) {
            return error.OutOfBounds;
        }
        self.offset = @intCast(usize, new_offset);
    }

    fn getPos (self: *Self) error{}!u64 {
        return self.offset;
    }

    fn getEndPos (self: *Self) error{}!u64 {
        return self.buffer.len;
    }

    const Reader = io.Reader(
        *Self,
        ReadError,
        read,
    );

    const ReadError = error{};

    pub fn reader (self: *Self) Reader {
        return .{ .context = self };
    }

    fn read (self: *Self, buffer: []u8) ReadError!usize {
        const copy = math.min(buffer.len, self.buffer.len - self.offset);
        if (copy > 0) {
            mem.copy(u8, buffer, self.buffer[self.offset .. self.offset + copy]);
            self.offset += copy;
        }
        return copy;
    }

    pub const Writer = io.Writer(
        *Self,
        WriteError,
        write,
    );

    const WriteError = error{};

    pub fn writer (self: *Self) Writer {
        return .{ .context = self };
    }

    fn write (self: *Self, buffer: []const u8) WriteError!usize {
        mem.copy(u8, self.buffer[self.offset .. self.offset + buffer.len], buffer);
        self.offset += buffer.len;
        return buffer.len;
    }
};