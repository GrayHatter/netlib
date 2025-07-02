pub const nl80211 = @import("nl80211.zig");

pub fn MsgHdr(T: type, Flags: type) type {
    return extern struct {
        len: u32,
        type: T,
        flags: Flags,
        /// Sequence number (set and used by userspace to ident request source)
        seq: u32 = 0,
        /// Destination process port ID
        pid: u32 = 0,
    };
}

pub const HdrFlags = enum { get, new, delete, ack };

pub const HeaderFlags = struct {
    pub const Get = packed struct(u16) {
        REQUEST: bool = false, // 0x01 /* It is request message.  */
        MULTI: bool = false, // 0x02 /* Multipart message, terminated by NLMSG_DONE */
        ACK: bool = false, // 0x04 /* Reply with ack, with zero or error code */
        ECHO: bool = false, // 0x08 /* Receive resulting notifications */
        DUMP_INTR: bool = false, // 0x10 /* Dump was inconsistent due to sequence change */
        DUMP_FILTERED: bool = false, // 0x20 /* Dump was filtered as requested */
        __padding: u2 = 0,

        ROOT: bool = false, // 0x100 /* specify tree root */
        MATCH: bool = false, // 0x200 /* return all matching */
        ATOMIC: bool = false, // 0x400 /* atomic GET  */
        ___padding: u5 = 0,

        pub fn format(g: Get, comptime _: []const u8, _: std.fmt.FormatOptions, out: anytype) anyerror!void {
            try out.writeAll("(");
            inline for (@typeInfo(Get).@"struct".fields) |f| {
                if (f.type != bool) continue;
                if (@field(g, f.name)) try out.writeAll(f.name ++ ",");
            }
            try out.writeAll(")");
        }

        pub const DUMP: Get = .{ .REQUEST = true, .ACK = true, .ROOT = true, .MATCH = true };
        pub const ReqAck: Get = .{ .REQUEST = true, .ACK = true };
    };

    pub const New = packed struct(u16) {
        REQUEST: bool = false, // 0x01 /* It is request message.  */
        MULTI: bool = false, // 0x02 /* Multipart message, terminated by NLMSG_DONE */
        ACK: bool = false, // 0x04 /* Reply with ack, with zero or error code */
        ECHO: bool = false, // 0x08 /* Receive resulting notifications */
        DUMP_INTR: bool = false, // 0x10 /* Dump was inconsistent due to sequence change */
        DUMP_FILTERED: bool = false, // 0x20 /* Dump was filtered as requested */
        __padding: u2 = 0,

        REPLACE: bool = false, // 0x100 /* Override existing  */
        EXCL: bool = false, // 0x200 /* Do not touch, if it exists */
        CREATE: bool = false, // 0x400 /* Create, if it does not exist */
        APPEND: bool = false, // 0x800 /* Add to end of list  */
        ___padding: u4 = 0,
    };
    pub const Delete = packed struct(u16) {
        REQUEST: bool = false, // 0x01 /* It is request message.  */
        MULTI: bool = false, // 0x02 /* Multipart message, terminated by NLMSG_DONE */
        ACK: bool = false, // 0x04 /* Reply with ack, with zero or error code */
        ECHO: bool = false, // 0x08 /* Receive resulting notifications */
        DUMP_INTR: bool = false, // 0x10 /* Dump was inconsistent due to sequence change */
        DUMP_FILTERED: bool = false, // 0x20 /* Dump was filtered as requested */
        __padding: u2 = 0,

        NONREC: bool = false, // 0x100 /* Do not delete recursively */
        BULK: bool = false, // 0x200 /* Delete multiple objects */
        ___padding: u6 = 0,
    };
    pub const Ack = packed struct(u16) {
        REQUEST: bool = false, // 0x01 /* It is request message.  */
        MULTI: bool = false, // 0x02 /* Multipart message, terminated by NLMSG_DONE */
        ACK: bool = false, // 0x04 /* Reply with ack, with zero or error code */
        ECHO: bool = false, // 0x08 /* Receive resulting notifications */
        DUMP_INTR: bool = false, // 0x10 /* Dump was inconsistent due to sequence change */
        DUMP_FILTERED: bool = false, // 0x20 /* Dump was filtered as requested */
        __padding: u2 = 0,

        CAPPED: bool = false, // 0x100 /* request was capped */
        ACK_TLVS: bool = false, // 0x200 /* extended ACK TVLs were included */
        ___padding: u6 = 0,

        pub const ReqAck: Ack = .{ .REQUEST = true, .ACK = true };
    };
};

pub const MsgType = enum(u16) {
    /// Nothing.
    NOOP = 0x1,

    /// eRROR
    ERROR = 0x2,

    /// eND OF A DUMP
    DONE = 0x3,

    /// dATA LOST
    OVERRUN = 0x4,

    // RTLINK TYPES

    rtm_newlink = 16,
    rtm_dellink,
    rtm_getlink,
    rtm_setlink,

    rtm_newaddr = 20,
    rtm_deladdr,
    rtm_getaddr,

    rtm_newroute = 24,
    rtm_delroute,
    rtm_getroute,

    rtm_newneigh = 28,
    rtm_delneigh,
    rtm_getneigh,

    rtm_newrule = 32,
    rtm_delrule,
    rtm_getrule,

    rtm_newqdisc = 36,
    rtm_delqdisc,
    rtm_getqdisc,

    rtm_newtclass = 40,
    rtm_deltclass,
    rtm_gettclass,

    rtm_newtfilter = 44,
    rtm_deltfilter,
    rtm_gettfilter,

    rtm_newaction = 48,
    rtm_delaction,
    rtm_getaction,

    rtm_newprefix = 52,

    rtm_getmulticast = 58,

    rtm_getanycast = 62,

    rtm_newneightbl = 64,
    rtm_getneightbl = 66,
    rtm_setneightbl,

    rtm_newnduseropt = 68,

    rtm_newaddrlabel = 72,
    rtm_deladdrlabel,
    rtm_getaddrlabel,

    rtm_getdcb = 78,
    rtm_setdcb,

    rtm_newnetconf = 80,
    rtm_delnetconf,
    rtm_getnetconf = 82,

    rtm_newmdb = 84,
    rtm_delmdb = 85,
    rtm_getmdb = 86,

    rtm_newnsid = 88,
    rtm_delnsid = 89,
    rtm_getnsid = 90,

    rtm_newstats = 92,
    rtm_getstats = 94,

    rtm_newcachereport = 96,

    rtm_newchain = 100,
    rtm_delchain,
    rtm_getchain,

    rtm_newnexthop = 104,
    rtm_delnexthop,
    rtm_getnexthop,

    _,
    /// < 0x10: reserved control messages
    pub const MIN_TYPE = 0x10;
};

pub fn Attr(T: type) type {
    return struct {
        len: u16,
        type: AttrType,
        data: []align(4) const u8,
        /// The payload size reflects struct + data, but the whole message must
        /// be 4 aligned. len_aligned is provided for convenience.
        len_aligned: u16,

        // Common Header is provided for convenience
        pub const Header = packed struct {
            len: u16,
            type: AttrType,
        };

        pub const AttrType = T;

        pub const Self = @This();

        pub fn initNew(t: AttrType, data: []align(4) const u8) Self {
            const aligned: u16 = @intCast((@sizeOf(Header) + data.len + 3) & ~@as(u16, 3));
            return .{
                .len = @intCast(@sizeOf(Header) + data.len),
                .type = t,
                .data = data,
                .len_aligned = aligned,
            };
        }

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

pub const IFLA = packed struct(u16) {
    type: Type,
    byte_order: bool,
    nested: bool,

    pub const Type = enum(u14) {
        unspec,
        address,
        broadcast,
        ifname,
        mtu,
        link,
        qdisc,
        stats,
        cost,
        priority,
        master,
        /// Wireless Extension event
        wireless,
        /// Protocol specific information for a link
        protinfo,
        txqlen,
        map,
        weight,
        operstate,
        linkmode,
        linkinfo,
        net_ns_pid,
        ifalias,
        /// Number of VFs if device is SR-IOV PF
        num_vf,
        vfinfo_list,
        stats64,
        vf_ports,
        port_self,
        af_spec,
        /// Group the device belongs to
        group,
        net_ns_fd,
        /// Extended info mask, VFs, etc
        ext_mask,
        /// Promiscuity count: > 0 means acts PROMISC
        promiscuity,
        num_tx_queues,
        num_rx_queues,
        carrier,
        phys_port_id,
        carrier_changes,
        phys_switch_id,
        link_netnsid,
        phys_port_name,
        proto_down,
        gso_max_segs,
        gso_max_size,
        pad,
        xdp,
        event,
        new_netnsid,
        if_netnsid,
        carrier_up_count,
        carrier_down_count,
        new_ifindex,
        min_mtu,
        max_mtu,
        prop_list,
        // Alternative ifname
        alt_ifname,
        perm_address,
        proto_down_reason,
        // device (sysfs) name as parent, used instead
        // of IFLA_LINK where there's no parent netdev
        parent_dev_name,
        parent_dev_bus_name,
        gro_max_size,
        tso_max_size,
        tso_max_segs,
        // Allmulti count: > 0 means acts ALLMULTI
        allmulti,
        devlink_port,
        gso_ipv4_max_size,
        gro_ipv4_max_size,
        dpll_pin,
        max_pacing_offload_horizon,
        netns_immutable,
        __max,
        _,
    };

    pub const TARGET_NETNSID: IFLA = .IF_NETNSID;
};

pub const IFA = packed struct(u16) {
    type: Type,
    byte_order: bool,
    nested: bool,

    const Type = enum(u14) {
        unspec,
        address,
        local,
        label,
        broadcast,
        anycast,
        cacheinfo,
        multicast,
        flags,
        rt_priority,
        target_netnsid,
        proto,
        _,
    };
};

pub const route = struct {
    pub const GenMsg = extern struct {
        family: u8,

        pub const packet: GenMsg = .{ .family = AF.PACKET };
    };
};

pub const generic = struct {
    /// Experimental API
    pub fn newSocket() !socket.Socket(.netlink) {
        return try socket.socket(.netlink_generic);
    }

    pub fn MsgHdr(T: type) type {
        comptime std.debug.assert(@sizeOf(T) == 1);
        return extern struct {
            cmd: T,
            version: u8 = 1,
            reserved: u16 = 0,
        };
    }

    pub const Ctrl = struct {
        pub const Attr = enum(u16) {
            unspec,
            family_id,
            family_name,
            version,
            hdrsize,
            maxattr,
            ops,
            mcast_groups,
            policy,
            op_policy,
            op,
            __max,
        };

        pub const AttrOps = enum(u16) {
            unspec,
            id,
            flags,
            __max,
        };

        pub const Cmd = enum(u8) {
            unspec,
            newfamily,
            delfamily,
            getfamily,
            newops,
            delops,
            getops,
            newmcast_grp,
            delmcast_grp,
            getmcast_grp,
            getpolicy,
            __max,
        };
    };

    pub const GENL = enum(u8) {
        id_ctrl = std.os.linux.NetlinkMessageType.MIN_TYPE,
        id_vfs_dquot,
        id_pmcraid,
        start_alloc,
    };
    pub const CAP = packed struct(u32) {
        ADMIN_PERM: bool,
        DO: bool,
        DUMP: bool,
        HAS_POLICY: bool,
        UNS_ADMIN_PERM: bool,
        __padding: u27,
    };
};

pub fn NewMessage(MHT: type, MHF: type, BT: type, PAYLOAD_SIZE: usize) type {
    return struct {
        header: Hdr,
        base: BT,
        data: [data_size]u8 align(4) = undefined,

        len: usize = @sizeOf(Hdr) + @sizeOf(BT),

        extra: usize = 0,

        pub const Self = @This();
        pub const Hdr = MsgHdr(MHT, MHF);
        pub const header_size = @sizeOf(Hdr) + @sizeOf(BT);
        pub const data_size = header_size + PAYLOAD_SIZE;
        pub const Socket = socket.Socket(.netlink);

        pub fn init(h: Hdr, b: BT) Self {
            return .{
                .header = h,
                .base = b,
            };
        }

        pub fn initRecv(sock: Socket) !Self {
            var s: Self = .{
                .header = undefined,
                .base = undefined,
                .data = @splat(0),
            };

            const size = try sock.read(&s.data);
            if (size < @sizeOf(Hdr) + @sizeOf(BT)) return error.InvalidRead;

            s.header = @as(*Hdr, @ptrCast(s.data[0..])).*;
            if (size < s.header.len) return error.InvalidMsgHeader;
            s.base = @as(*BT, @ptrCast(s.data[@sizeOf(Hdr)..])).*;
            s.len = s.header.len;
            s.extra = size - s.len;
            return s;
        }

        pub fn initFromExtra(extra: *Self) !Self {
            if (extra.extra < header_size) return error.InvalidData;
            const blob: []align(4) u8 = @alignCast(extra.data[extra.len..][0..extra.extra]);

            var s: Self = .{
                .header = @as(*Hdr, @ptrCast(blob)).*,
                .base = @as(*BT, @ptrCast(blob[@sizeOf(Hdr)..])).*,
                .data = undefined,
            };
            if (s.header.len > blob.len) return error.InvalidHeader;
            s.len = s.header.len;
            s.extra = blob.len - s.len;
            @memcpy(s.data[0..blob.len], blob[0..]);

            return s;
        }

        pub fn payload(s: *const Self, offset: usize) []align(4) const u8 {
            const os = offset + 3 & ~@as(usize, 3);
            return @alignCast(s.data[header_size + os .. s.len]);
        }

        pub fn packAttr(s: *Self, AT: type, attr: AT) !void {
            if (attr.len_aligned + s.len > data_size) return error.OutOfSpace;
            @memcpy(s.data[s.len..][0..2], asBytes(&attr.len));
            @memcpy(s.data[s.len..][2..4], asBytes(&attr.type));
            @memcpy(s.data[s.len..][4..][0..attr.data.len], attr.data);
            const padding = attr.len_aligned - attr.len;
            if (padding > 0) {
                @memset(s.data[s.len + 4 + attr.data.len ..][0..padding], 0);
            }
            s.len += attr.len_aligned;
        }

        pub fn send(s: *Self, sock: Socket) !void {
            var h: Hdr = s.header;
            h.len = @intCast(s.len);

            s.data[0..@sizeOf(Hdr)].* = asBytes(&h).*;
            s.data[@sizeOf(Hdr)..][0..@sizeOf(BT)].* = asBytes(&s.base).*;
            _ = try sock.write(s.data[0..s.len]);
        }
    };
}

const socket = @import("socket.zig");
const std = @import("std");
const AF = std.posix.AF;
const asBytes = std.mem.asBytes;
