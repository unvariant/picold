const std = @import("std");
const common = @import("common.zig");

const EnumField = common.EnumField;

pub const SectionType = common.mergeEnums(common.SectionType(u64), &[_]EnumField{
    .{ .name = "Unwind", .value = 0x70000001, },
});