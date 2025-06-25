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

fn dumpRtAttr(stdout: anytype, data: []const u8) !void {
    var offset: usize = 0;
    const rtattr = std.os.linux.rtattr;
    while (offset < data.len) {
        const attr: *const rtattr = @ptrCast(@alignCast(data[offset..]));
        offset += @sizeOf(rtattr);
        switch (attr.type.link) {
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
                try stdout.print("attr {}\n", .{attr.type.link});
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
            else => {
                const int: u16 = @intFromEnum(attr.type.link);
                try stdout.print("attr {}\n    {}    {b}\n", .{ attr.type.link, int, int });
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
    try dumpRtAttr(stdout, data[offset..]);
}

fn dumpLink(stdout: anytype, data: []const u8) !void {
    var offset: usize = 0;
    try stdout.print("NEWLINK\n", .{});
    offset += @sizeOf(nlmsghdr);
    const link: *const ifinfomsg = @ptrCast(@alignCast(data[offset..]));
    try stdout.print("link {}\n", .{link});
    offset += @sizeOf(ifinfomsg);
    try dumpRtAttr(stdout, data[offset..]);
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
