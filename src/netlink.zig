pub const MsgType = std.os.linux.NetlinkMessageType;
pub const nl80211 = @import("nl80211.zig");

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
        cmd: Ctrl.Cmd,
        version: u8 = 2,
        reserved: u16 = 0,
    };

    pub const Ctrl = struct {
        pub const Attr = enum(u16) {
            UNSPEC,
            FAMILY_ID,
            FAMILY_NAME,
            VERSION,
            HDRSIZE,
            MAXATTR,
            OPS,
            MCAST_GROUPS,
            POLICY,
            OP_POLICY,
            OP,
            __CTRL_ATTR_MAX,
        };

        pub const Cmd = enum(u8) {
            UNSPEC,
            NEWFAMILY,
            DELFAMILY,
            GETFAMILY,
            NEWOPS,
            DELOPS,
            GETOPS,
            NEWMCAST_GRP,
            DELMCAST_GRP,
            GETMCAST_GRP,
            GETPOLICY,
            __MAX,
        };
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
