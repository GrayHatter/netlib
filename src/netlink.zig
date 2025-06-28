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

const std = @import("std");

pub const Route = struct {};

pub const Generic = struct {};
