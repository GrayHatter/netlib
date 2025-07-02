pub const Domain = enum(i32) {
    unspec = 0,
    local = 1,
    inet = 2,
    ax25 = 3,
    ipx = 4,
    appletalk = 5,
    netrom = 6,
    bridge = 7,
    atmpvc = 8,
    x25 = 9,
    inet6 = 10,
    rose = 11,
    decNET = 12,
    netbeui = 13,
    security = 14,
    key = 15,
    netlink = 16,
    packet = 17,
    ash = 18,
    econet = 19,
    atmsvc = 20,
    rds = 21,
    sna = 22,
    irda = 23,
    pppox = 24,
    wanpipe = 25,
    llc = 26,
    ib = 27,
    mpls = 28,
    can = 29,
    tipc = 30,
    bluetooth = 31,
    iucv = 32,
    rxrpc = 33,
    isdn = 34,
    phonet = 35,
    ieee802154 = 36,
    caif = 37,
    alg = 38,
    nfc = 39,
    vsock = 40,
    kcm = 41,
    qipcrtr = 42,
    smc = 43,
    xdp = 44,
    max = 45,

    pub const unix: Domain = .local;
    pub const file: Domain = .local;
    pub const route: Domain = .netlink;
};

pub fn Socket(d: Domain) type {
    return switch (d) {
        .netlink => struct {
            fd: std.os.linux.fd_t,

            pub const Self = @This();
            pub const Domain = d;
            pub const Protocol = enum(i32) {
                route,
                generic,
            };

            pub fn init(p: Protocol) !Self {
                return .{
                    .fd = try posix.socket(
                        @intFromEnum(Self.Domain),
                        SOCK.RAW,
                        switch (p) {
                            .route => os.linux.NETLINK.ROUTE,
                            .generic => os.linux.NETLINK.GENERIC,
                        },
                    ),
                };
            }

            pub fn read(s: Self, b: []u8) !usize {
                return try posix.read(s.fd, b);
            }

            pub fn write(s: Self, b: []const u8) !usize {
                return try posix.write(s.fd, b);
            }

            pub fn close(s: Self) void {
                posix.close(s.fd);
            }
        },
        else => struct {
            fd: std.os.linux.fd_t,

            pub const Self = @This();
            pub const Domain = d;
            pub const Type = enum(i32) { _ };
            pub const Protocol = enum(i32) { _ };

            pub fn init(t: Type, p: Protocol) !Self {
                return .{
                    .fd = try posix.socket(
                        @intFromEnum(Self.Domain),
                        @intFromEnum(t),
                        @intFromEnum(p),
                    ),
                };
            }

            pub fn read(s: Self, b: []u8) !usize {
                return try posix.read(s.fd, b);
            }

            pub fn write(s: Self, b: []const u8) !usize {
                return try posix.write(s.fd, b);
            }

            pub fn close(s: Self) void {
                posix.close(s.fd);
            }
        },
    };
}

pub const Flavor = enum {
    datagram,
    stream,
    netlink_generic,
    netlink_route,
};

//pub fn socket(F: Flavor) !Socket(.netlink {
//    const domain: u32, const sock_type: u32, const proto: u32 = switch (F) {
//        .datagram => .{ AF.INET, SOCK.DGRAM, 0 },
//        .stream => .{ AF.INET, SOCK.STREAM, 0 },
//        .netlink_generic => .{ AF.NETLINK, SOCK.RAW, os.linux.NETLINK.GENERIC },
//        .netlink_route => .{ AF.NETLINK, SOCK.RAW, os.linux.NETLINK.ROUTE },
//    };
//
//    return .{
//        .fd = try std.posix.socket(domain, sock_type, proto),
//    };
//}

const std = @import("std");
const os = std.os;
const posix = std.posix;
const AF = posix.AF;
const SOCK = posix.SOCK;
