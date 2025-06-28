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

pub const netlink = @import("netlink.zig");

pub const nlmsghdr = netlink.MsgHdr(netlink.MsgType);

pub fn Attr(T: enum { rtlink, rtaddr, genl }) type {
    return struct {
        len: u16,
        type: AttrType,
        data: []align(4) const u8,
        /// The payload size reflects struct + data, but the whole message must
        /// be 4 aligned. len_aligned is provided for convenience.
        len_aligned: u16,

        pub const Header = packed struct {
            len: u16,
            type: AttrType,
        };

        pub const AttrType = switch (T) {
            .rtaddr => IFA,
            .rtlink => IFLA,
            .genl => netlink.generic.Ctrl.Attr,
        };

        pub const Self = @This();

        pub fn init(data: []align(4) const u8) !Self {
            const len: *const u16 = @ptrCast(data[0..2]);
            if (len.* > data.len or len.* < 4) return error.MalformedAttr;
            const type_: *const AttrType = @ptrCast(data[2..4]);
            return .{
                .len = len.*,
                .type = type_.*,
                .data = data[4..][0 .. len.* - 4],
                .len_aligned = len.* + 3 & ~@as(u16, 3),
            };
        }
    };
}

pub fn main() !void {
    var args = std.process.args();
    const arg0 = args.next() orelse usage("wat?!");

    while (args.next()) |arg| {
        if (startsWith(u8, arg, "--")) {
            usage(arg0);
        } else if (eql(u8, arg, "nl80211")) {
            return try nl80211SendMsg();
        } else {
            return try route();
        }
    }
    return usage(arg0);
}

pub const nlmsgerr = extern struct {
    err: i32,
    msg: nlmsghdr,
};

pub fn nl80211SendMsg() !void {
    const stdout = std.io.getStdOut().writer();

    const s = try socket(AF.NETLINK, SOCK.RAW, std.os.linux.NETLINK.GENERIC);

    const full_size = (@sizeOf(nlmsghdr) + @sizeOf(netlink.generic.MsgHdr) + @sizeOf(Attr(.genl).Header) + 8 + 3) & ~@as(usize, 3);

    var w_buffer: [full_size]u8 align(4) = undefined;
    var w_list: std.ArrayListUnmanaged(u8) = .initBuffer(&w_buffer);
    var w = w_list.fixedWriter();

    const req_hdr: netlink.MsgHdr(netlink.generic.GENL) = .{
        .len = full_size,
        .type = .ID_CTRL,
        .flags = std.os.linux.NLM_F_REQUEST | std.os.linux.NLM_F_ACK,
        .seq = 1,
        .pid = 0,
    };
    try w.writeStruct(req_hdr);

    const r_genmsg: netlink.generic.MsgHdr = .{
        .cmd = .GETFAMILY,
    };
    try w.writeStruct(r_genmsg);

    const attr: Attr(.genl).Header = .{
        .len = 12,
        .type = .FAMILY_NAME,
    };
    try w.writeStruct(attr);
    try w.writeAll("nl80211");
    try w.writeByte(0);

    _ = try write(s, w_list.items);

    try stdout.print("{any}\n", .{w_list.items});

    var rbuffer: [0x8000]u8 align(4) = undefined;

    var nl_more: bool = true;

    while (nl_more) {
        var size = try read(s, &rbuffer);
        try stdout.print("\n\n\n", .{});
        try stdout.print("{} {any} \n", .{ size, rbuffer[0..size] });
        var start: usize = 0;
        while (size > 0) {
            if (size < @sizeOf(nlmsghdr)) {
                try stdout.print("response too small {}\n", .{size});
                @panic("");
            }

            try stdout.print("\n\n\n", .{});
            const hdr: *nlmsghdr = @ptrCast(@alignCast(rbuffer[start..]));
            const aligned: usize = hdr.len + 3 & ~@as(usize, 3);

            switch (hdr.type) {
                .ERROR => {
                    try stdout.print("error {} \n", .{hdr});
                    try stdout.print("flags {} {b} {x}\n", .{ hdr.flags, hdr.flags, hdr.flags });
                    if (hdr.len > @sizeOf(nlmsghdr)) {
                        const emsg: *align(4) nlmsgerr = @alignCast(@ptrCast(rbuffer[start + @sizeOf(nlmsghdr) ..]));
                        try stdout.print("error msg {} \n", .{emsg});
                    }
                    nl_more = false;
                },

                .DONE => {
                    nl_more = false;
                },
                else => try dumpNl80211(stdout, @alignCast(rbuffer[start + @sizeOf(nlmsghdr) .. aligned])),
            }

            size -|= aligned;
            start += aligned;
        }
    }
    try stdout.print("done\n", .{});
}

pub fn dumpNl80211(stdout: anytype, data: []align(4) const u8) !void {
    var offset: usize = 0;
    //const rtattr = std.os.linux.rtattr;
    const genlmsg: *align(4) const netlink.generic.MsgHdr = @ptrCast(@alignCast(data[offset..]));
    try stdout.print("genl {any}\n", .{genlmsg});
    offset += @sizeOf(netlink.generic.MsgHdr);

    while (offset < data.len) {
        const attr: Attr(.genl) = try .init(@alignCast(data[offset..]));
        switch (attr.type) {
            else => {
                try stdout.print("\n\n\n\nattr {}\n    {}    {b}\n", .{ attr.type, @intFromEnum(attr.type), @intFromEnum(attr.type) });
                try stdout.print("attr.len {}\n", .{attr.len});
                try stdout.print("attr.data {any} \n\n\n", .{attr.data});
            },
        }
        offset += attr.len_aligned;
    }
}

pub fn route() !void {
    const stdout = std.io.getStdOut().writer();

    const s = try socket(AF.NETLINK, SOCK.RAW, std.os.linux.NETLINK.ROUTE);

    const full_size = @sizeOf(nlmsghdr) + @sizeOf(netlink.route.GenMsg);

    var w_buffer: [full_size]u8 align(4) = undefined;
    var w_list: std.ArrayListUnmanaged(u8) = .initBuffer(&w_buffer);
    var w = w_list.fixedWriter();

    var hdr: netlink.MsgHdr(netlink.MsgType) = .{
        .len = @sizeOf(nlmsghdr) + @sizeOf(netlink.route.GenMsg),
        .type = .RTM_GETLINK,
        .flags = std.os.linux.NLM_F_REQUEST | std.os.linux.NLM_F_ACK | std.os.linux.NLM_F_DUMP,
        .seq = 1,
        .pid = 0,
    };
    try w.writeStruct(hdr);
    const rtgen: netlink.route.GenMsg = .{
        .family = AF.PACKET,
    };
    try w.writeStruct(rtgen);

    _ = try write(s, w_list.items);

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
        var size = try read(s, &rbuffer);
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
                .RTM_NEWLINK => try dumpLink(stdout, rbuffer[start..][0..aligned]),
                .RTM_NEWADDR => try dumpAddr(stdout, rbuffer[start..][0..aligned]),
                .DONE => {
                    nl_more = false;
                    try stdout.print("LIST DONE\n", .{});
                },
                else => |t| {
                    try stdout.print("unimplemented tag {}\n", .{t});
                },
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

    _ = try write(s, w_list.items);
    nl_more = true;

    while (nl_more) {
        var size = try read(s, &rbuffer);
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
                .RTM_NEWLINK => try dumpLink(stdout, rbuffer[start..][0..aligned]),
                .RTM_NEWADDR => try dumpAddr(stdout, rbuffer[start..][0..aligned]),
                .DONE => {
                    nl_more = false;
                    try stdout.print("LIST DONE\n", .{});
                },
                else => |t| {
                    try stdout.print("unimplemented tag {}\n", .{t});
                },
            }

            size -|= aligned;
            start += aligned;
        }
    }

    try stdout.print("done\n", .{});
}

pub const IFA = packed struct(u16) {
    type: Type,
    byte_order: bool,
    nested: bool,

    const Type = enum(u14) {
        UNSPEC,
        ADDRESS,
        LOCAL,
        LABEL,
        BROADCAST,
        ANYCAST,
        CACHEINFO,
        MULTICAST,
        FLAGS,
        RT_PRIORITY,
        TARGET_NETNSID,
        PROTO,

        _,
    };
};

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

pub const IFLA = packed struct(u16) {
    type: Type,
    byte_order: bool,
    nested: bool,

    pub const Type = enum(u14) {
        UNSPEC,
        ADDRESS,
        BROADCAST,
        IFNAME,
        MTU,
        LINK,
        QDISC,
        STATS,
        COST,
        PRIORITY,
        MASTER,

        /// Wireless Extension event
        WIRELESS,

        /// Protocol specific information for a link
        PROTINFO,

        TXQLEN,
        MAP,
        WEIGHT,
        OPERSTATE,
        LINKMODE,
        LINKINFO,
        NET_NS_PID,
        IFALIAS,

        /// Number of VFs if device is SR-IOV PF
        NUM_VF,

        VFINFO_LIST,
        STATS64,
        VF_PORTS,
        PORT_SELF,
        AF_SPEC,

        /// Group the device belongs to
        GROUP,

        NET_NS_FD,

        /// Extended info mask, VFs, etc
        EXT_MASK,

        /// Promiscuity count: > 0 means acts PROMISC
        PROMISCUITY,

        NUM_TX_QUEUES,
        NUM_RX_QUEUES,
        CARRIER,
        PHYS_PORT_ID,
        CARRIER_CHANGES,
        PHYS_SWITCH_ID,
        LINK_NETNSID,
        PHYS_PORT_NAME,
        PROTO_DOWN,
        GSO_MAX_SEGS,
        GSO_MAX_SIZE,
        PAD,
        XDP,
        EVENT,

        NEW_NETNSID,
        IF_NETNSID,

        CARRIER_UP_COUNT,
        CARRIER_DOWN_COUNT,
        NEW_IFINDEX,
        MIN_MTU,
        MAX_MTU,

        PROP_LIST,
        ALT_IFNAME, // Alternative ifname
        PERM_ADDRESS,
        PROTO_DOWN_REASON,

        // device (sysfs) name as parent, used instead
        // of IFLA_LINK where there's no parent netdev
        PARENT_DEV_NAME,
        PARENT_DEV_BUS_NAME,
        GRO_MAX_SIZE,
        TSO_MAX_SIZE,
        TSO_MAX_SEGS,
        ALLMULTI, // Allmulti count: > 0 means acts ALLMULTI

        DEVLINK_PORT,

        GSO_IPV4_MAX_SIZE,
        GRO_IPV4_MAX_SIZE,
        DPLL_PIN,
        MAX_PACING_OFFLOAD_HORIZON,
        NETNS_IMMUTABLE,
        __MAX,
        _,
    };

    pub const TARGET_NETNSID: IFLA = .IF_NETNSID;
};

fn dumpRtAttrAddr(stdout: anytype, data: []const u8) !void {
    var offset: usize = 0;
    //const rtattr = std.os.linux.rtattr;
    while (offset < data.len) {
        const attr: Attr(.rtaddr) = try .init(@alignCast(data[offset..]));
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

fn dumpRtAttrLink(stdout: anytype, data: []align(4) const u8) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        const attr: Attr(.rtlink) = try .init(@alignCast(data[offset..]));
        switch (attr.type.type) {
            .QDISC => {
                const name: [:0]const u8 = attr.data[0 .. attr.data.len - 1 :0];
                try stdout.print(
                    "QDISC ({}) '{s}' {any} \n",
                    .{ name.len, name, name },
                );
            },
            .IFNAME => {
                const name: [:0]const u8 = attr.data[0 .. attr.data.len - 1 :0];
                try stdout.print(
                    "name ({}) '{s}' {any} \n",
                    .{ name.len, name, name },
                );
            },
            .AF_SPEC => {
                try stdout.print("attr {}\n", .{attr.type.type});
                try stdout.print("attr.len {}\n", .{attr.len});
            },
            .STATS => {},
            .STATS64 => {
                const stats64 = std.os.linux.rtnl_link_stats64;
                var stats: stats64 = undefined;
                const sbytes = std.mem.asBytes(&stats);
                std.debug.print("{} vs {}\n", .{ sbytes.len, attr.data.len });
                if (data.len < sbytes.len) return error.MalformedAttr;
                @memcpy(sbytes, attr.data[0..sbytes.len]);
                try stdout.print("stats {} \n", .{stats});
            },
            .BROADCAST, .ADDRESS => {
                const int: u16 = @intFromEnum(attr.type.type);
                try stdout.print("attr {}    {}    {b}\n", .{ attr.type.type, int, int });
                switch (attr.data.len) {
                    6 => {
                        try stdout.print("    {x}:{x}:{x}:{x}:{x}:{x}\n", .{
                            attr.data[0], attr.data[1], attr.data[2],
                            attr.data[3], attr.data[4], attr.data[5],
                        });
                    },
                    else => {
                        try stdout.print("    len {} \n", .{attr.data.len});
                    },
                }
            },
            .MAP => {
                const link_ifmap = std.os.linux.rtnl_link_ifmap;
                const ifmap: *align(4) const link_ifmap = @alignCast(@ptrCast(attr.data.ptr));
                try stdout.print("ifmap {} \n", .{ifmap.*});
            },
            .WIRELESS => {
                const int: u16 = @intFromEnum(attr.type.type);
                try stdout.print("attr {}\n    {}    {b}\n", .{ attr.type.type, int, int });
                try stdout.print("attr.len {}\n", .{attr.len});
                try stdout.print(
                    "state offset {} len {} total {} remain {} \n",
                    .{ offset, attr.len, attr.data.len, attr.data.len },
                );
                try stdout.print("attr.data {any} \n", .{attr.data});
            },
            else => {
                const int: u16 = @intFromEnum(attr.type.type);
                try stdout.print(
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
                try stdout.print("    data {any} \n", .{attr.data});
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

fn dumpLink(stdout: anytype, data: []const u8) !void {
    var offset: usize = 0;
    try stdout.print("NEWLINK\n", .{});
    offset += @sizeOf(nlmsghdr);
    const link: *const ifinfomsg = @ptrCast(@alignCast(data[offset..]));
    try stdout.print("link {}\n", .{link});
    offset += @sizeOf(ifinfomsg);
    try dumpRtAttrLink(stdout, @alignCast(data[offset..]));
}

const socket = std.posix.socket;
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
