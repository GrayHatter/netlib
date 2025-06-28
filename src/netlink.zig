pub const MsgType = std.os.linux.NetlinkMessageType;

pub fn MsgHdr(T: anytype) type {
    return extern struct {
        len: u32,
        type: T,
        flags: u16,
        /// Sequence number
        seq: u32,
        /// Sending process port ID
        pid: u32,
    };
}

pub const route = struct {
    pub const GenMsg = extern struct {
        family: u8,

        pub const packet: GenMsg = .{ .family = AF.PACKET };
    };
};

pub const generic = struct {
    pub const MsgHdr = extern struct {
        cmd: u8,
        version: u8 = 2,
        reserved: u16 = 0,
    };

    pub const GENL = enum(u8) {
        ID_CTRL = std.os.linux.NetlinkMessageType.MIN_TYPE,
        ID_VFS_DQUOT,
        ID_PMCRAID,
        START_ALLOC,
    };
};

const std = @import("std");
const AF = std.posix.AF;
