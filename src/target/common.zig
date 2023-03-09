const std = @import("std");
const builtin = @import("builtin");

const meta = std.meta;
const elf = std.elf;
const mem = std.mem;

const Type = std.builtin.Type;
const Tuple = meta.Tuple;
const Array = std.BoundedArray;
const EnumField = Type.EnumField;
const StructField = Type.StructField;

pub fn mergeEnums (comptime T: type, comptime new: []const EnumField) type {
    switch (@typeInfo(T)) {
        .Enum => |old| {
            const fields = old.fields ++ new;
            const is_exhaustive = fields.len >= @truncate(old.tag_type, 0xFFFFFFFFFFFFFFFF);
            const newtype = .{
                .Enum = .{
                    .layout = .Auto,
                    .tag_type = old.tag_type,
                    .fields = fields,
                    .decls = old.decls,
                    .is_exhaustive = is_exhaustive,
                },
            };
            return @Type(newtype);
        },
        else => @compileError(@typeName(T) ++ " is not an Enum"),
    }
}

fn tryEnum (comptime T: type, comptime n: comptime_int) ?type {
    switch (@typeInfo(T)) {
        .Enum => |info| {
            inline for (info.fields) |field| {
                if (field.value == n) {
                    return @intToEnum(T, n);
                }
            }
            return null;
        },
        else => @compileError(@typeName(T) ++ " is not an Enum"),
    }
}

pub fn SectionType (comptime Tag: type) type {
    const Generic = enum {
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
    };

    const info = @typeInfo(Generic).Enum;

    return @Type(.{
        .Enum = .{
            .layout = .Auto,
            .tag_type = Tag,
            .fields = info.fields,
            .decls = info.decls,
            .is_exhaustive = info.is_exhaustive,
        },
    });
}

pub fn SectionFlags (comptime Tag: type, comptime new: []Tuple(&.{ []const u8, usize, })) type {
    // TODO: create comptime packed struct with fields at specified offsets
    _ = new;
    const Flags = packed struct {
        write: bool = false,
        alloc: bool = false,
        exec: bool = false,
        merge: bool = false,
        strings: bool = false,
        info_link: bool = false,
        os_nonfonforming: bool = false,
        group: bool = false,
        tls: bool = false,
    };

    if (@bitSizeOf(Flags) > @bitSizeOf(Tag)) {
        @compileError("@bitSizeOf(" ++ @typeName(Flags) ++ ") is larger than @bitSizeOf(" ++ @typeName(Tag) ++ ")");
    }

    const info = @typeInfo(Flags).Struct;
    const fields = info.fields ++ &[_]StructField{
        .{
            .name = "reserved",
            .field_type = @Type(.{
                .Int = .{
                    .signedness = .unsigned,
                    .bits = @bitSizeOf(Tag) - @bitSizeOf(Flags),
                },
            }),
            .default_value = &0,
            .is_comptime = true,
            .alignment = 0,
        },
    };

    return @Type(.{
        .Struct = .{
            .layout = .Packed,
            .backing_integer = Tag,
            .fields = fields,
            .decls = info.decls,
            .is_tuple = false,
        },
    });
}