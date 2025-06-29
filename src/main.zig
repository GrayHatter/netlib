fn usage(arg0: []const u8) noreturn {
    //
    std.debug.print(
        \\error: you're holding it wrong
        \\
        \\Usage: {s}
        \\
    , .{arg0});
    std.posix.exit(1);
}

var debug: bool = false;

pub const nlmsghdr = netlink.MsgHdr(netlink.MsgType, netlink.HeaderFlags.Get);

pub const IfLink = struct {
    index: u32,
    name: [:0]const u8 = "ERROR: NO IFNAME",
    altname: ?[:0]const u8 = null,
    grp_id: u32 = 0,

    mac: ?[6]u8 = null,
    mac_brd: ?[6]u8 = null,

    stats: ?stats64 = null,

    qdisc: ?[:0]const u8 = null,
    txqueue: u32 = 0,

    carrier: bool = false,

    mtu: u32 = 0,
    mtu_min: u32 = 0,
    mtu_max: u32 = 0,

    addresses: struct {
        buffer: [20]u8 = @splat(0),
    } = .{},

    pub const stats64 = std.os.linux.rtnl_link_stats64;

    pub fn init(nlmsg: []align(4) const u8) !IfLink {
        var offset: usize = 0;
        offset += @sizeOf(nlmsghdr);
        const infomsg: *const ifinfomsg = @ptrCast(@alignCast(nlmsg[offset..]));
        offset += @sizeOf(ifinfomsg);

        var link: IfLink = .{ .index = @intCast(infomsg.index) };
        try link.scanAttr(@alignCast(nlmsg[offset..]));

        return link;
    }

    fn scanAttr(link: *IfLink, nlmsg: []align(4) const u8) !void {
        var offset: usize = 0;
        while (offset < nlmsg.len) {
            const attr: Attr(netlink.IFLA) = try .init(@alignCast(nlmsg[offset..]));
            switch (attr.type.type) {
                .QDISC => link.qdisc = attr.data[0 .. attr.data.len - 1 :0],
                .IFNAME => link.name = attr.data[0 .. attr.data.len - 1 :0],
                .AF_SPEC => {
                    if (debug) {
                        std.debug.print("attr {}\n", .{attr.type.type});
                        std.debug.print("attr.len {}\n", .{attr.len});
                        std.debug.print("attr.data {any}\n", .{attr.data});
                    }
                },
                .STATS => {},
                .STATS64 => {
                    var stats: stats64 = undefined;
                    const sbytes = std.mem.asBytes(&stats);
                    if (attr.len < sbytes.len) return error.MalformedAttr;
                    link.stats = @as(*align(4) const stats64, @ptrCast(attr.data[0..sbytes.len])).*;
                },
                .ADDRESS => switch (attr.data.len) {
                    6 => link.mac = attr.data[0..6].*,
                    else => return error.InvalidAddress,
                },
                .BROADCAST => switch (attr.data.len) {
                    6 => link.mac_brd = attr.data[0..6].*,
                    else => return error.InvalidAddress,
                },
                .MAP => {
                    const link_ifmap = std.os.linux.rtnl_link_ifmap;
                    const ifmap: *align(4) const link_ifmap = @alignCast(@ptrCast(attr.data.ptr));
                    if (debug) std.debug.print("ifmap {} \n", .{ifmap.*});
                },
                .WIRELESS => std.debug.print("WIRELESS attr.data {any} \n", .{attr.data}),
                .CARRIER => link.carrier = attr.data[0] == 1,
                .MTU => link.mtu = @bitCast(attr.data[0..4].*),
                .MIN_MTU => link.mtu_min = @bitCast(attr.data[0..4].*),
                .MAX_MTU => link.mtu_max = @bitCast(attr.data[0..4].*),
                .TXQLEN => link.txqueue = @bitCast(attr.data[0..4].*),
                .GROUP => link.grp_id = @bitCast(attr.data[0..4].*),
                // Probably nested
                .PROP_LIST => {
                    const pattr: Attr(netlink.IFLA) = try .init(@alignCast(attr.data));
                    switch (pattr.type.type) {
                        .ALT_IFNAME => link.altname = pattr.data[0 .. pattr.data.len - 1 :0],
                        else => std.debug.print("{}\n", .{pattr}),
                    }
                },

                else => {
                    const int: u16 = @intFromEnum(attr.type.type);
                    if (debug) {
                        std.debug.print(
                            "attr {} (nested {}) (nbo {}) {} {b} [len: {}]\n",
                            .{
                                attr.type.type,
                                attr.type.nested,
                                attr.type.byte_order,
                                int,
                                int,
                                attr.len - 4,
                            },
                        );
                        std.debug.print("    data {any} \n", .{attr.data});
                    }
                },
            }
            offset += attr.len_aligned;
        }
    }

    pub fn format(l: IfLink, comptime _: []const u8, _: std.fmt.FormatOptions, out: anytype) anyerror!void {
        var mac_buf: [17]u8 = undefined;
        var brd_buf: [17]u8 = undefined;
        try out.print(
            \\{}: {s}: <{s}> mtu[{}] qdisc[{s}] state[--] mode[--] group[{}] qlen[{}]
            \\    link/[something] {s} {s}{s}{s}
        ,
            .{
                l.index,                                     l.name,   if (l.carrier) "UP" else "DOWN", l.mtu,
                l.qdisc orelse "ukn",                        l.grp_id, l.txqueue,
                if (l.mac) |m| std.fmt.bufPrint(
                    &mac_buf,
                    "{x}:{x}:{x}:{x}:{x}:{x}",
                    .{ m[0], m[1], m[2], m[3], m[4], m[5] },
                ) catch unreachable else "mac not found",
                if (l.mac_brd) |b| std.fmt.bufPrint(
                    &brd_buf,
                    "{x}:{x}:{x}:{x}:{x}:{x}",
                    .{ b[0], b[1], b[2], b[3], b[4], b[5] },
                ) catch unreachable else "mac not found",
                if (l.altname) |_| "\n    altname " else "",
                l.altname orelse "",
            },
        );
    }
};

pub fn main() !void {
    var args = std.process.args();
    const arg0 = args.next() orelse usage("wat?!");

    while (args.next()) |arg| {
        if (startsWith(u8, arg, "--")) {
            usage(arg0);
        } else if (eql(u8, arg, "nl80211")) {
            return try nl80211.sendMsg();
        } else {
            return try route();
        }
    }
    return usage(arg0);
}

pub fn route() !void {
    const stdout = std.io.getStdOut().writer();

    const s = try socket(.netlink_route);

    const full_size = @sizeOf(nlmsghdr) + @sizeOf(netlink.route.GenMsg);

    var w_buffer: [full_size]u8 align(4) = undefined;
    var w_list: std.ArrayListUnmanaged(u8) = .initBuffer(&w_buffer);
    var w = w_list.fixedWriter();

    var hdr: netlink.MsgHdr(netlink.MsgType, netlink.HeaderFlags.Get) = .{
        .len = @sizeOf(nlmsghdr) + @sizeOf(netlink.route.GenMsg),
        .type = .RTM_GETLINK,
        .flags = .{
            .REQUEST = true,
            .ACK = true,
            .ROOT = true,
            .MATCH = true,
        },
        .seq = 1,
        .pid = 0,
    };
    try w.writeStruct(hdr);
    const rtgen: netlink.route.GenMsg = .{
        .family = AF.PACKET,
    };
    try w.writeStruct(rtgen);

    _ = try s.write(w_list.items);

    // Netlink expects that the user buffer will be at least 8kB or a page size
    // of the CPU architecture, whichever is bigger. Particular Netlink families
    // may, however, require a larger buffer. 32kB buffer is recommended for
    // most efficient handling of dumps (larger buffer fits more dumped objects
    // and therefore fewer recvmsg() calls are needed).
    // https://docs.kernel.org/userspace-api/netlink/intro.html
    var rbuffer: [0x8000]u8 align(4) = undefined;

    var nl_more: bool = true;

    // reliable transmissions from kernel to user are impossible in any case.
    // The kernel can't send a netlink message if the socket buffer is full: the
    // message will be dropped and the kernel and the user-space process will no
    // longer have the same view of kernel state.  It is up to the application
    // to detect when this happens (via the ENOBUFS error returned by
    // recvmsg()) and resynchronize.
    while (nl_more) {
        var size = try s.read(&rbuffer);
        var start: usize = 0;
        while (size > 0) {
            if (size < @sizeOf(nlmsghdr)) {
                try stdout.print("response too small {}\n", .{size});
                @panic("");
            }

            const lhdr: *nlmsghdr = @ptrCast(@alignCast(rbuffer[start..]));
            const aligned: usize = lhdr.len + 3 & ~@as(usize, 3);

            switch (lhdr.type) {
                .RTM_NEWLINK => {
                    const link: IfLink = try .init(@alignCast(rbuffer[start..][0..aligned]));
                    try stdout.print("{}\n", .{link});
                },
                .DONE => nl_more = false,
                else => |t| try stdout.print("unimplemented tag {}\n", .{t}),
            }

            size -|= aligned;
            start += aligned;
        }
    }

    hdr.type = .RTM_GETADDR;
    hdr.seq += 1;
    w_list.items.len = 0;
    try w.writeStruct(hdr);
    try w.writeStruct(rtgen);

    _ = try s.write(w_list.items);
    nl_more = true;

    while (nl_more) {
        var size = try s.read(&rbuffer);
        var start: usize = 0;
        while (size > 0) {
            if (size < @sizeOf(nlmsghdr)) {
                try stdout.print("response too small {}\n", .{size});
                @panic("");
            }

            try stdout.print("\n\n\n", .{});
            const lhdr: *nlmsghdr = @ptrCast(@alignCast(rbuffer[start..]));
            const aligned: usize = lhdr.len + 3 & ~@as(usize, 3);

            switch (lhdr.type) {
                .RTM_NEWADDR => try dumpAddr(stdout, rbuffer[start..][0..aligned]),
                .DONE => nl_more = false,
                else => |t| try stdout.print("unimplemented tag {}\n", .{t}),
            }

            size -|= aligned;
            start += aligned;
        }
    }

    try stdout.print("done\n", .{});
}

const Family = enum(u8) {
    IPv4 = 2,
    IPv6 = 10,
    _,
};

const ifaddrmsg = extern struct {
    family: Family,
    prefixlen: u8,
    flags: Flags,
    scope: u8,
    index: u32,

    pub const Flags = packed struct(u8) {
        SECONDARY: bool,
        //TEMPORARY              IFA_F_SECONDARY
        NODAD: bool,
        OPTIMISTIC: bool,
        DADFAILED: bool,
        HOMEADDRESS: bool,
        DEPRECATED: bool,
        TENTATIVE: bool,
        PERMANENT: bool,
        //MANAGETEMPADDR: bool,
        //NOPREFIXROUTE: bool,
        //MCAUTOJOIN: bool,
        //STABLE_PRIVACY: bool,
    };
};

pub const IFA_FLAGS = packed struct(u32) {
    SECONDARY: bool,
    NODAD: bool,
    OPTIMISTIC: bool,
    DADFAILED: bool,
    HOMEADDRESS: bool,
    DEPRECATED: bool,
    TENTATIVE: bool,
    PERMANENT: bool,
    MANAGETEMPADDR: bool,
    NOPREFIXROUTE: bool,
    MCAUTOJOIN: bool,
    STABLE_PRIVACY: bool,
    __unused: u20,
};

pub const ifinfomsg = extern struct {
    family: u8,
    __pad1: u8 = 0,

    /// ARPHRD_*
    type: c_ushort,

    /// Link index
    index: c_int,

    /// IFF_* flags
    flags: net_device_flags,

    /// IFF_* change mask
    change: c_uint,
};

const net_device_flags = packed struct(c_uint) {
    up: bool,
    broadcast: bool,
    debug: bool,
    loopback: bool,
    pointopoint: bool,
    notrailers: bool,
    running: bool,
    noarp: bool,
    promisc: bool,
    allmulti: bool,
    master: bool,
    slave: bool,
    multicast: bool,
    portsel: bool,
    automedia: bool,
    dynamic: bool,
    lower_up: bool,
    dormant: bool,
    echo: bool,
    __padding: u13,
};

pub const ifa_cacheinfo = extern struct {
    prefered: u32,
    valid: u32,
    created: u32,
    updated: u32,
};

pub const ifa_proto = enum(u8) {
    UNSPEC,
    KERNEL_LO,
    KERNEL_RA,
    KERNEL_LL,
};

fn dumpRtAttrAddr(stdout: anytype, data: []const u8) !void {
    var offset: usize = 0;
    //const rtattr = std.os.linux.rtattr;
    while (offset < data.len) {
        const attr: Attr(netlink.IFA) = try .init(@alignCast(data[offset..]));
        switch (attr.type.type) {
            .LABEL => {
                const name: [:0]const u8 = attr.data[0 .. attr.data.len - 1 :0];
                try stdout.print(
                    "name ({}) '{s}' {any} \n",
                    .{ name.len, name, name },
                );
            },
            .ADDRESS,
            .BROADCAST,
            .LOCAL,
            => |t| {
                try stdout.writeAll(switch (t) {
                    .ADDRESS => "addr  ",
                    .BROADCAST => "bcast ",
                    .LOCAL => "local ",
                    else => unreachable,
                });
                const int: u16 = @intFromEnum(attr.type.type);
                switch (attr.data.len) {
                    4 => {
                        try stdout.print("{}.{}.{}.{}\n", .{
                            attr.data[0],
                            attr.data[1],
                            attr.data[2],
                            attr.data[3],
                        });
                    },
                    16 => {
                        try stdout.print("{}:{}:{}:{}:{}:{}:{}:{}\n", .{
                            std.fmt.fmtSliceHexLower(attr.data[0..][0..2]),
                            std.fmt.fmtSliceHexLower(attr.data[2..][0..2]),
                            std.fmt.fmtSliceHexLower(attr.data[4..][0..2]),
                            std.fmt.fmtSliceHexLower(attr.data[6..][0..2]),
                            std.fmt.fmtSliceHexLower(attr.data[8..][0..2]),
                            std.fmt.fmtSliceHexLower(attr.data[10..][0..2]),
                            std.fmt.fmtSliceHexLower(attr.data[12..][0..2]),
                            std.fmt.fmtSliceHexLower(attr.data[14..][0..2]),
                        });
                    },
                    else => {
                        try stdout.print("attr {}    {}    {b}\n", .{ attr.type.type, int, int });
                        try stdout.print("len {} \n", .{attr.data.len});
                    },
                }
            },
            .CACHEINFO => {
                const cinfo: *align(4) const ifa_cacheinfo = @alignCast(@ptrCast(attr.data.ptr));
                try stdout.print("cacheinfo {} \n", .{cinfo.*});
            },
            .FLAGS => {
                const flags: *align(4) const IFA_FLAGS = @alignCast(@ptrCast(attr.data.ptr));
                try stdout.print("flags {} \n", .{flags.*});
            },
            .PROTO => {
                const prot: *align(4) const ifa_proto = @alignCast(@ptrCast(attr.data.ptr));
                try stdout.print("prot {} \n", .{prot.*});
            },
            .RT_PRIORITY => {
                const pri: *align(4) const u32 = @alignCast(@ptrCast(attr.data.ptr));
                try stdout.print("rt pri {} \n", .{pri.*});
            },

            else => {
                const int: u16 = @intFromEnum(attr.type.type);
                try stdout.print("\n\n\n\nattr {}\n    {}    {b}\n", .{ attr.type.type, int, int });
                try stdout.print("attr.len {}\n", .{attr.len});
                try stdout.print("attr.data {any} \n\n\n", .{attr.data});
            },
        }
        offset += attr.len_aligned;
    }
}

fn dumpAddr(stdout: anytype, data: []const u8) !void {
    try stdout.print("NEWADDR\n", .{});
    //try stdout.print("blob {any}\n", .{data});
    var offset: usize = @sizeOf(nlmsghdr);
    const addr: *const ifaddrmsg = @ptrCast(@alignCast(data[offset..]));
    try stdout.print("addr {any}\n", .{addr});
    offset += @sizeOf(ifaddrmsg);
    //try stdout.print("blob {any}\n", .{data[offset..]});
    try dumpRtAttrAddr(stdout, data[offset..]);
}

pub const netlink = @import("netlink.zig");
pub const nl80211 = @import("nl80211.zig");
pub const socket = @import("socket.zig").socket;
const Attr = netlink.Attr;

//const socket = std.posix.socket;
const write = std.posix.write;
const read = std.posix.read;
const connect = std.posix.connect;
const close = std.posix.close;
const AF = std.posix.AF;
const SOCK = std.posix.SOCK;
const posix = std.posix;

const std = @import("std");
const Allocator = std.mem.Allocator;
const indexOf = std.mem.indexOf;
const indexOfAny = std.mem.indexOfAny;
const indexOfScalar = std.mem.indexOfScalar;
const indexOfScalarPos = std.mem.indexOfScalarPos;
const parseInt = std.fmt.parseInt;
const startsWith = std.mem.startsWith;
const eql = std.mem.eql;
const bufPrint = std.fmt.bufPrint;
