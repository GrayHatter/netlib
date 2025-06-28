pub const Socket = struct {
    fd: std.os.linux.fd_t,

    pub fn read(s: Socket, b: []u8) !usize {
        return try posix.read(s.fd, b);
    }

    pub fn write(s: Socket, b: []const u8) !usize {
        return try posix.write(s.fd, b);
    }
};

pub const Flavor = enum {
    datagram,
    stream,
    netlink_generic,
    netlink_route,
};

pub fn socket(F: Flavor) !Socket {
    const domain: u32, const sock_type: u32, const proto: u32 = switch (F) {
        .datagram => .{ AF.INET, SOCK.DGRAM, 0 },
        .stream => .{ AF.INET, SOCK.STREAM, 0 },
        .netlink_generic => .{ AF.NETLINK, SOCK.RAW, os.linux.NETLINK.GENERIC },
        .netlink_route => .{ AF.NETLINK, SOCK.RAW, os.linux.NETLINK.ROUTE },
    };

    return .{
        .fd = try std.posix.socket(domain, sock_type, proto),
    };
}

const std = @import("std");
const os = std.os;
const posix = std.posix;
const AF = posix.AF;
const SOCK = posix.SOCK;
