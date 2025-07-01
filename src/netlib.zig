//! NetLib
//!

pub const netlink = @import("netlink.zig");

pub const socket = @import("socket.zig");

test {
    _ = &netlink;
    _ = &socket;
}
