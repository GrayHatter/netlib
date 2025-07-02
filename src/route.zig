const debug = false;

pub const IfLink = struct {
    index: u32,
    name: [:0]const u8 = "ERROR: NO IFNAME",
    altname: ?[:0]const u8 = null,
    grp_id: u32 = 0,

    mac: [6]u8 = @splat(0),
    mac_brd: [6]u8 = @splat(0xff),

    stats: ?stats64 = null,

    qdisc: ?[:0]const u8 = null,
    txqueue: u32 = 0,

    carrier: bool = false,

    mtu: u32 = 0,
    mtu_min: u32 = 0,
    mtu_max: u32 = 0,

    addresses: std.BoundedArray(Address, 64) = .{},

    pub const Address = struct {
        addr: ?Addr,
        broadcast: ?Addr,
        local: ?Addr = null,
        prefix: u8 = 0,

        pub const Addr = union(enum) {
            inet: u32,
            inet6: u128,
            pub fn format(
                a: Addr,
                comptime fs: []const u8,
                _: std.fmt.FormatOptions,
                out: anytype,
            ) anyerror!void {
                if (comptime eql(u8, fs, "inet")) {
                    switch (a) {
                        .inet => try out.writeAll("inet  "),
                        .inet6 => try out.writeAll("inet6 "),
                    }
                }

                switch (a) {
                    .inet => |in| {
                        const bytes = std.mem.asBytes(&in);
                        try out.print(
                            "{}.{}.{}.{}",
                            .{ bytes[0], bytes[1], bytes[2], bytes[3] },
                        );
                    },
                    .inet6 => |in6| {
                        var buffer: [140]u8 = @splat(0);
                        var high: u8 = 0;
                        var len: usize = 0;
                        var breaks: u8 = 0;

                        for (std.mem.asBytes(&in6), 0..) |b, i| {
                            if (i > 0 and i % 2 == 0 and breaks < 2) {
                                _ = try std.fmt.bufPrint(buffer[len..], ":", .{});
                                len += 1;
                                breaks += 1;
                            }
                            if (i % 2 == 0) {
                                high = b;
                                if (b == 0) continue;
                                _ = try std.fmt.bufPrint(buffer[len..], "{x}", .{b});
                                len += 2;
                                breaks = 0;
                            } else {
                                if (high > 0) {
                                    const B = try std.fmt.bufPrint(buffer[len..], "{x:02}", .{b});
                                    len += B.len;
                                } else if (b > 0) {
                                    const B = try std.fmt.bufPrint(buffer[len..], "{x}", .{b});
                                    len += B.len;
                                }
                            }
                        }
                        try out.print("{s}", .{buffer[0..len]});
                    },
                }
            }
        };

        pub fn format(
            a: Address,
            comptime fs: []const u8,
            fo: std.fmt.FormatOptions,
            out: anytype,
        ) anyerror!void {
            if (a.addr) |addr| {
                try addr.format(fs, fo, out);
                try out.print("/{}", .{a.prefix});
            }
        }
    };

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
                .qdisc => link.qdisc = attr.data[0 .. attr.data.len - 1 :0],
                .ifname => link.name = attr.data[0 .. attr.data.len - 1 :0],
                .af_spec => {
                    if (debug) {
                        std.debug.print("attr {}\n", .{attr.type.type});
                        std.debug.print("attr.len {}\n", .{attr.len});
                        std.debug.print("attr.data {any}\n", .{attr.data});
                    }
                },
                .stats => {},
                .stats64 => {
                    var stats: stats64 = undefined;
                    const sbytes = std.mem.asBytes(&stats);
                    if (attr.len < sbytes.len) return error.MalformedAttr;
                    link.stats = @as(*align(4) const stats64, @ptrCast(attr.data[0..sbytes.len])).*;
                },
                .address => switch (attr.data.len) {
                    6 => link.mac = attr.data[0..6].*,
                    else => return error.InvalidAddress,
                },
                .broadcast => switch (attr.data.len) {
                    6 => link.mac_brd = attr.data[0..6].*,
                    else => return error.InvalidAddress,
                },
                .map => {
                    const link_ifmap = std.os.linux.rtnl_link_ifmap;
                    const ifmap: *align(4) const link_ifmap = @alignCast(@ptrCast(attr.data.ptr));
                    if (debug) std.debug.print("ifmap {} \n", .{ifmap.*});
                },
                .wireless => std.debug.print("WIRELESS attr.data {any} \n", .{attr.data}),
                .carrier => link.carrier = attr.data[0] == 1,
                .mtu => link.mtu = @bitCast(attr.data[0..4].*),
                .min_mtu => link.mtu_min = @bitCast(attr.data[0..4].*),
                .max_mtu => link.mtu_max = @bitCast(attr.data[0..4].*),
                .txqlen => link.txqueue = @bitCast(attr.data[0..4].*),
                .group => link.grp_id = @bitCast(attr.data[0..4].*),
                // Probably nested
                .prop_list => {
                    const pattr: Attr(netlink.IFLA) = try .init(@alignCast(attr.data));
                    switch (pattr.type.type) {
                        .alt_ifname => link.altname = pattr.data[0 .. pattr.data.len - 1 :0],
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
                std.fmt.bufPrint(
                    &mac_buf,
                    "{x}:{x}:{x}:{x}:{x}:{x}",
                    .{ l.mac[0], l.mac[1], l.mac[2], l.mac[3], l.mac[4], l.mac[5] },
                ) catch unreachable,
                std.fmt.bufPrint(
                    &brd_buf,
                    "{x}:{x}:{x}:{x}:{x}:{x}",
                    .{ l.mac_brd[0], l.mac_brd[1], l.mac_brd[2], l.mac_brd[3], l.mac_brd[4], l.mac_brd[5] },
                ) catch unreachable,
                if (l.altname) |_| "\n    altname " else "",
                l.altname orelse "",
            },
        );
        for (l.addresses.constSlice()) |addr| {
            if (addr.addr) |_| try out.print("\n    {inet}", .{addr});
        }
    }
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

pub const ifa_proto = enum(u8) {
    unspec,
    kernel_lo,
    kernel_ra,
    kernel_ll,
};

const Family = enum(u8) {
    ipv4 = 2,
    ipv6 = 10,
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

pub const ifa_cacheinfo = extern struct {
    prefered: u32,
    valid: u32,
    created: u32,
    updated: u32,
};

pub fn route() !void {
    const stdout = std.io.getStdOut().writer();

    const s: socket = try .init(.route);
    defer s.close();

    const full_size = @sizeOf(nlmsghdr) + @sizeOf(netlink.route.GenMsg);

    var w_buffer: [full_size]u8 align(4) = undefined;
    var w_list: std.ArrayListUnmanaged(u8) = .initBuffer(&w_buffer);
    var w = w_list.fixedWriter();

    var hdr: netlink.MsgHdr(netlink.MsgType, netlink.HeaderFlags.Get) = .{
        .len = @sizeOf(nlmsghdr) + @sizeOf(netlink.route.GenMsg),
        .type = .rtm_getlink,
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

    var iflist_buffer: [64]IfLink = undefined;
    var iflist: std.ArrayListUnmanaged(IfLink) = .initBuffer(&iflist_buffer);

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
                .rtm_newlink => {
                    iflist.appendAssumeCapacity(try .init(@alignCast(rbuffer[start..][0..aligned])));
                    //try stdout.print("{}\n", .{link});
                },
                .DONE => nl_more = false,
                else => |t| try stdout.print("unimplemented tag {}\n", .{t}),
            }

            size -|= aligned;
            start += aligned;
        }
    }

    hdr.type = .rtm_getaddr;
    hdr.seq += 1;
    w_list.items.len = 0;
    try w.writeStruct(hdr);
    try w.writeStruct(rtgen);

    _ = try s.write(w_list.items);
    nl_more = true;

    var rbuffer_a: [0x8000]u8 align(4) = undefined;
    while (nl_more) {
        var size = try s.read(&rbuffer_a);
        var start: usize = 0;
        while (size > 0) {
            if (size < @sizeOf(nlmsghdr)) {
                try stdout.print("response too small {}\n", .{size});
                @panic("");
            }

            const lhdr: *nlmsghdr = @ptrCast(@alignCast(rbuffer_a[start..]));
            const aligned: usize = lhdr.len + 3 & ~@as(usize, 3);

            switch (lhdr.type) {
                .rtm_newaddr => try dumpAddr(stdout, rbuffer_a[start..][0..aligned], &iflist),
                .DONE => nl_more = false,
                else => |t| try stdout.print("unimplemented tag {}\n", .{t}),
            }

            size -|= aligned;
            start += aligned;
        }
    }

    for (iflist.items) |ifl| {
        try stdout.print("{}\n", .{ifl});
    }

    if (debug) try stdout.print("done\n", .{});
}

fn dumpRtAttrAddr(stdout: anytype, data: []const u8) !IfLink.Address {
    var offset: usize = 0;
    var addr: IfLink.Address = .{ .addr = null, .broadcast = null, .local = null };
    while (offset < data.len) {
        const attr: Attr(netlink.IFA) = try .init(@alignCast(data[offset..]));
        switch (attr.type.type) {
            .label => {
                const name: [:0]const u8 = attr.data[0 .. attr.data.len - 1 :0];
                if (debug) try stdout.print("name ({}) '{s}' {any} \n", .{ name.len, name, name });
            },
            .address,
            .broadcast,
            .local,
            => |t| {
                const addr_data: IfLink.Address.Addr = switch (attr.data.len) {
                    4 => .{ .inet = @as(*const u32, @ptrCast(attr.data)).* },
                    16 => .{ .inet6 = @as(*align(4) const u128, @ptrCast(attr.data)).* },
                    else => return error.InvalidAddressSize,
                };

                switch (t) {
                    .address => addr.addr = addr_data,
                    .broadcast => addr.broadcast = addr_data,
                    .local => addr.local = addr_data,
                    else => unreachable,
                }

                if (debug) try stdout.writeAll(switch (t) {
                    .address => "    addr  ",
                    .broadcast => "    bcast ",
                    .local => "    local ",
                    else => unreachable,
                });

                const int: u16 = @intFromEnum(attr.type.type);
                switch (attr.data.len) {
                    4 => {
                        if (debug) try stdout.print("{}.{}.{}.{}\n", .{
                            attr.data[0],
                            attr.data[1],
                            attr.data[2],
                            attr.data[3],
                        });
                    },
                    16 => {
                        if (debug) try stdout.print("{}:{}:{}:{}:{}:{}:{}:{}\n", .{
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
                        if (debug) try stdout.print("    attr {}    {}    {b}\n", .{ attr.type.type, int, int });
                        if (debug) try stdout.print("    len {} \n", .{attr.data.len});
                    },
                }
            },
            .cacheinfo => {
                const cinfo: *align(4) const ifa_cacheinfo = @alignCast(@ptrCast(attr.data.ptr));
                if (debug) try stdout.print("    cacheinfo {} \n", .{cinfo.*});
            },
            .flags => {
                const flags: *align(4) const IFA_FLAGS = @alignCast(@ptrCast(attr.data.ptr));
                if (debug) try stdout.print("    flags {} \n", .{flags.*});
            },
            .proto => {
                const prot: *align(4) const ifa_proto = @alignCast(@ptrCast(attr.data.ptr));
                if (debug) try stdout.print("    prot {} \n", .{prot.*});
            },
            .rt_priority => {
                const pri: *align(4) const u32 = @alignCast(@ptrCast(attr.data.ptr));
                if (debug) try stdout.print("    rt pri {} \n", .{pri.*});
            },

            else => {
                const int: u16 = @intFromEnum(attr.type.type);
                try stdout.print("    attr {}\n    {}    {b}\n", .{ attr.type.type, int, int });
                try stdout.print("    attr.len {}\n", .{attr.len});
                try stdout.print("    attr.data {any} \n\n\n", .{attr.data});
            },
        }
        offset += attr.len_aligned;
    }
    return addr;
}

fn dumpAddr(stdout: anytype, data: []const u8, list: *std.ArrayListUnmanaged(IfLink)) !void {
    //try stdout.print("blob {any}\n", .{data});
    var offset: usize = @sizeOf(nlmsghdr);
    const addrmsg: *const ifaddrmsg = @ptrCast(@alignCast(data[offset..]));
    offset += @sizeOf(ifaddrmsg);
    if (debug) try stdout.print("addr {any}\n", .{addrmsg});
    const index = addrmsg.index - 1;
    if (index >= list.items.len) return error.UnexpectedAddressIndex;
    const iface = &list.items[index];
    //iface.prefix = addrmsg.prefixlen;

    var addr = try dumpRtAttrAddr(stdout, data[offset..]);
    addr.prefix = addrmsg.prefixlen;
    try iface.addresses.append(addr);
}

pub const socket = @import("socket.zig").Socket(.netlink);
pub const netlink = @import("netlink.zig");
pub const nlmsghdr = netlink.MsgHdr(netlink.MsgType, netlink.HeaderFlags.Get);
const std = @import("std");
const eql = std.mem.eql;
const Attr = netlink.Attr;
const AF = std.posix.AF;
