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

const rtgenmsg = extern struct {
    family: u8,
};

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    //var debug_a: std.heap.DebugAllocator(.{}) = .{};
    //const a = debug_a.allocator();

    var args = std.process.args();
    const arg0 = args.next() orelse usage("wat?!");

    while (args.next()) |arg| {
        if (startsWith(u8, arg, "--")) {
            usage(arg0);
        }
    }

    var buffer: std.ArrayListUnmanaged(u8) = .{};
    _ = &buffer;

    const s = try socket(AF.NETLINK, SOCK.RAW, std.os.linux.NETLINK.ROUTE);

    const both_size = @sizeOf(nlmsghdr) + @sizeOf(rtgenmsg);

    var wbuffer: [both_size]u8 align(4) = undefined;
    const r_hdr: *nlmsghdr = @ptrCast(wbuffer[0..]);
    r_hdr.* = .{
        .len = both_size,
        .type = .RTM_GETLINK,
        .flags = std.os.linux.NLM_F_REQUEST | std.os.linux.NLM_F_ACK | std.os.linux.NLM_F_DUMP,
        .seq = 10,
        .pid = 0,
    };
    const r_rtgen: *rtgenmsg = @ptrCast(wbuffer[@sizeOf(nlmsghdr)..]);
    r_rtgen.* = .{
        .family = AF.PACKET,
    };

    _ = try write(s, wbuffer[0..both_size]);

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

            try stdout.print("\n\n", .{});
            const hdr: *nlmsghdr = @ptrCast(@alignCast(rbuffer[start..]));
            try stdout.print("hdr {}\n", .{hdr});
            const aligned: usize = hdr.len + 3 & ~@as(usize, 3);
            try stdout.print("hdr.size {} aligned {} rem {}\n", .{ hdr.len, aligned, size });

            switch (hdr.type) {
                .RTM_NEWLINK => try dumpLink(stdout, rbuffer[start..][0..aligned]),
                .RTM_NEWADDR => try dumpAddr(stdout, rbuffer[start..][0..aligned]),
                .DONE => nl_more = false,
                else => |t| {
                    try stdout.print("unimplemented tag {}\n", .{t});
                },
            }

            size -|= aligned;
            start += aligned;
        }
    }

    r_hdr.type = .RTM_GETADDR;
    r_hdr.seq += 1;
    _ = try write(s, wbuffer[0..both_size]);
    nl_more = true;

    while (nl_more) {
        var size = try read(s, &rbuffer);
        var start: usize = 0;
        while (size > 0) {
            if (size < @sizeOf(nlmsghdr)) {
                try stdout.print("response too small {}\n", .{size});
                @panic("");
            }

            try stdout.print("\n\n", .{});
            const hdr: *nlmsghdr = @ptrCast(@alignCast(rbuffer[start..]));
            try stdout.print("hdr {}\n", .{hdr});
            const aligned: usize = hdr.len + 3 & ~@as(usize, 3);
            try stdout.print("hdr.size {} aligned {} rem {}\n", .{ hdr.len, aligned, size });

            switch (hdr.type) {
                .RTM_NEWLINK => try dumpLink(stdout, rbuffer[start..][0..aligned]),
                .RTM_NEWADDR => try dumpAddr(stdout, rbuffer[start..][0..aligned]),
                .DONE => nl_more = false,
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

pub const rtattr = extern struct {
    /// Length of option
    len: c_ushort,

    /// Type of option
    type: packed union {
        /// IFLA_* from linux/if_link.h
        link: IFLA,
        /// IFA_* from linux/if_addr.h
        addr: IFA,
    },

    pub const ALIGNTO = 4;
};

pub const IFA = packed struct(u16) {
    type: enum(u14) {
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
    },
    byte_order: bool,
    nested: bool,
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
    type: enum(u14) {
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
    },
    byte_order: bool,
    nested: bool,

    pub const TARGET_NETNSID: IFLA = .IF_NETNSID;
};

fn dumpRtAttrAddr(stdout: anytype, data: []const u8) !void {
    var offset: usize = 0;
    //const rtattr = std.os.linux.rtattr;
    while (offset < data.len) {
        const attr: *const rtattr = @ptrCast(@alignCast(data[offset..]));
        offset += @sizeOf(rtattr);
        switch (attr.type.addr.type) {
            .LABEL => {
                const name_len = attr.len - @sizeOf(rtattr);
                const nameptr: [*]const u8 = @ptrCast(@alignCast(data[offset..]));
                const name: [:0]const u8 = nameptr[0 .. name_len - 1 :0];
                try stdout.print(
                    "name ({}) '{s}' {any} \n",
                    .{ name_len, name, name },
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
                const int: u16 = @intFromEnum(attr.type.addr.type);
                const len = attr.len - @sizeOf(rtattr);
                const attr_data: [*]const u8 = @ptrCast(@alignCast(data[offset..]));
                switch (len) {
                    4 => {
                        try stdout.print("{}.{}.{}.{}\n", .{
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        });
                    },
                    16 => {
                        try stdout.print("{}:{}:{}:{}:{}:{}:{}:{}\n", .{
                            std.fmt.fmtSliceHexLower(attr_data[0..][0..2]),
                            std.fmt.fmtSliceHexLower(attr_data[2..][0..2]),
                            std.fmt.fmtSliceHexLower(attr_data[4..][0..2]),
                            std.fmt.fmtSliceHexLower(attr_data[6..][0..2]),
                            std.fmt.fmtSliceHexLower(attr_data[8..][0..2]),
                            std.fmt.fmtSliceHexLower(attr_data[10..][0..2]),
                            std.fmt.fmtSliceHexLower(attr_data[12..][0..2]),
                            std.fmt.fmtSliceHexLower(attr_data[14..][0..2]),
                        });
                    },
                    else => {
                        try stdout.print("attr {}    {}    {b}\n", .{ attr.type.addr.type, int, int });
                        try stdout.print("len {} \n", .{len});
                    },
                }
            },
            .CACHEINFO => {
                const cinfo: *align(4) const ifa_cacheinfo = @alignCast(@ptrCast(data[offset..].ptr));
                try stdout.print("cacheinfo {} \n", .{cinfo.*});
            },
            .FLAGS => {
                const flags: *align(4) const IFA_FLAGS = @alignCast(@ptrCast(data[offset..].ptr));
                try stdout.print("flags {} \n", .{flags.*});
            },
            .PROTO => {
                const prot: *align(4) const ifa_proto = @alignCast(@ptrCast(data[offset..].ptr));
                try stdout.print("prot {} \n", .{prot.*});
            },
            else => {
                const int: u16 = @intFromEnum(attr.type.addr.type);
                try stdout.print("\n\n\n\nattr {}\n    {}    {b}\n", .{ attr.type.addr.type, int, int });
                try stdout.print("attr.len {}\n", .{attr.len});
                const len = attr.len - @sizeOf(rtattr);
                const attr_data: [*]const u8 = @ptrCast(@alignCast(data[offset..]));
                try stdout.print("attr.data {any} \n\n\n", .{attr_data[0..len]});
            },
        }
        offset += (attr.len + 3 & ~@as(usize, 3)) - @sizeOf(rtattr);
    }
}

fn dumpRtAttrLink(stdout: anytype, data: []const u8) !void {
    var offset: usize = 0;
    //const rtattr = std.os.linux.rtattr;
    while (offset < data.len) {
        const attr: *const rtattr = @ptrCast(@alignCast(data[offset..]));
        offset += @sizeOf(rtattr);
        switch (attr.type.link.type) {
            .IFNAME => {
                const name_len = attr.len - @sizeOf(rtattr);
                const nameptr: [*]const u8 = @ptrCast(@alignCast(data[offset..]));
                const name: [:0]const u8 = nameptr[0 .. name_len - 1 :0];
                try stdout.print(
                    "name ({}) '{s}' {any} \n",
                    .{ name_len, name, name },
                );
            },
            .AF_SPEC => {
                try stdout.print("attr {}\n", .{attr.type.link.type});
                try stdout.print("attr.len {}\n", .{attr.len});
            },
            .STATS => {},
            .STATS64 => {
                const stats64 = std.os.linux.rtnl_link_stats64;
                var stats: stats64 = undefined;
                const sbytes = std.mem.asBytes(&stats);
                const len = @min(attr.len - @sizeOf(rtattr), sbytes.len);
                @memcpy(sbytes[0..len], data[offset..][0..len]);
                try stdout.print("stats {} \n", .{stats});
            },
            .BROADCAST, .ADDRESS => {
                const int: u16 = @intFromEnum(attr.type.link.type);
                try stdout.print("attr {}    {}    {b}\n", .{ attr.type.link.type, int, int });
                const len = attr.len - @sizeOf(rtattr);
                const attr_data: [*]const u8 = @ptrCast(@alignCast(data[offset..]));
                switch (len) {
                    6 => {
                        try stdout.print("addr {}:{}:{}:{}:{}\n", .{
                            std.fmt.fmtSliceHexLower(attr_data[0..][0..1]),
                            std.fmt.fmtSliceHexLower(attr_data[2..][0..1]),
                            std.fmt.fmtSliceHexLower(attr_data[4..][0..1]),
                            std.fmt.fmtSliceHexLower(attr_data[6..][0..1]),
                            std.fmt.fmtSliceHexLower(attr_data[8..][0..1]),
                        });
                    },
                    else => {
                        try stdout.print("len {} \n", .{len});
                    },
                }
            },
            .MAP => {
                const link_ifmap = std.os.linux.rtnl_link_ifmap;
                const ifmap: *align(4) const link_ifmap = @alignCast(@ptrCast(data[offset..].ptr));
                try stdout.print("ifmap {} \n", .{ifmap.*});
            },
            .WIRELESS => {
                const int: u16 = @intFromEnum(attr.type.link.type);
                try stdout.print("attr {}\n    {}    {b}\n", .{ attr.type.link.type, int, int });
                try stdout.print("attr.len {}\n", .{attr.len});
                const len = attr.len - @sizeOf(rtattr);
                const attr_data: [*]const u8 = @ptrCast(@alignCast(data[offset..]));
                try stdout.print("state offset {} len {} total {} remain {} \n", .{ offset, len, data.len, data[offset..].len });
                try stdout.print("attr.data {any} \n", .{attr_data[0..len]});
            },
            else => {
                const int: u16 = @intFromEnum(attr.type.link.type);
                try stdout.print("attr {}\n    {}    {b}\n", .{ attr.type.link.type, int, int });
                try stdout.print("attr.len {}\n", .{attr.len});
                const len = attr.len - @sizeOf(rtattr);
                const attr_data: [*]const u8 = @ptrCast(@alignCast(data[offset..]));
                try stdout.print("attr.data {any} \n", .{attr_data[0..len]});
            },
        }
        offset += (attr.len + 3 & ~@as(usize, 3)) - @sizeOf(rtattr);
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
    try dumpRtAttrLink(stdout, data[offset..]);
}

//      RTM_NEWLINK
//       RTM_DELLINK
//       RTM_GETLINK
//              Create, remove, or get information about a specific network
//              interface.  These messages contain an ifinfomsg structure
//              followed by a series of rtattr structures.
//
//
//              ifi_flags contains the device flags, see netdevice(7);
//              ifi_index is the unique interface index (since Linux 3.7,
//              it is possible to feed a nonzero value with the RTM_NEWLINK
//              message, thus creating a link with the given ifindex);
//              ifi_change is reserved for future use and should be always
//              set to 0xFFFFFFFF.
//                                  Routing attributes
//              rta_type            Value type         Description
//              ────────────────────────────────────────────────────────────
//              IFLA_UNSPEC         -                  unspecified
//              IFLA_ADDRESS        hardware address   interface L2 address
//              IFLA_BROADCAST      hardware address   L2 broadcast address
//              IFLA_IFNAME         asciiz string      Device name
//              IFLA_MTU            unsigned int       MTU of the device
//              IFLA_LINK           int                Link type
//              IFLA_QDISC          asciiz string      Queueing discipline
//              IFLA_STATS          see below          Interface Statistics
//              IFLA_PERM_ADDRESS   hardware address   hardware address
//                                                     provided by device
//                                                     (since Linux 5.5)
//
//              The value type for IFLA_STATS is struct rtnl_link_stats
//              (struct net_device_stats in Linux 2.4 and earlier).

const RTMGRP_LINK = 1;
const RTMGRP_NOTIFY = 2;
const RTMGRP_NEIGH = 4;
const RTMGRP_TC = 8;
const RTMGRP_IPV4_IFADDR = 0x10;
const RTMGRP_IPV4_MROUTE = 0x20;
const RTMGRP_IPV4_ROUTE = 0x40;
const RTMGRP_IPV4_RULE = 0x80;
const RTMGRP_IPV6_IFADDR = 0x100;
const RTMGRP_IPV6_MROUTE = 0x200;
const RTMGRP_IPV6_ROUTE = 0x400;
const RTMGRP_IPV6_IFINFO = 0x800;
const RTMGRP_DECnet_IFADDR = 0x1000;
const RTMGRP_DECnet_ROUTE = 0x4000;
const RTMGRP_IPV6_PREFIX = 0x20000;

const rtnetlink_groups = enum { RTNLGRP_NONE, RTNLGRP_LINK, RTNLGRP_NOTIFY, RTNLGRP_NEIGH, RTNLGRP_TC, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_MROUTE, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_MROUTE, RTNLGRP_IPV6_ROUTE, RTNLGRP_IPV6_IFINFO, RTNLGRP_DECnet_IFADDR, RTNLGRP_NOP2, RTNLGRP_DECnet_ROUTE, RTNLGRP_DECnet_RULE, RTNLGRP_NOP4, RTNLGRP_IPV6_PREFIX, RTNLGRP_IPV6_RULE, RTNLGRP_ND_USEROPT, RTNLGRP_PHONET_IFADDR, RTNLGRP_PHONET_ROUTE, RTNLGRP_DCB, RTNLGRP_IPV4_NETCONF, RTNLGRP_IPV6_NETCONF, RTNLGRP_MDB, RTNLGRP_MPLS_ROUTE, RTNLGRP_NSID, RTNLGRP_MPLS_NETCONF, RTNLGRP_IPV4_MROUTE_R, RTNLGRP_IPV6_MROUTE_R, RTNLGRP_NEXTHOP, RTNLGRP_BRVLAN, RTNLGRP_MCTP_IFADDR, RTNLGRP_TUNNEL, RTNLGRP_STATS, RTNLGRP_IPV4_MCADDR, RTNLGRP_IPV6_MCADDR, RTNLGRP_IPV6_ACADDR, __RTNLGRP_MAX };

const nlmsghdr = std.os.linux.nlmsghdr;

const genlmsghdr = extern struct {
    cmd: u8,
    version: u8 = 1,
    reserved: u16 = 0,
};

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
