pub const MsgType = std.os.linux.NetlinkMessageType;
pub const nl80211 = @import("nl80211.zig");

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
            .genl => generic.Ctrl.Attr,
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

pub const route = struct {
    pub const GenMsg = extern struct {
        family: u8,

        pub const packet: GenMsg = .{ .family = AF.PACKET };
    };
};

pub const generic = struct {
    pub const MsgHdr = extern struct {
        cmd: Ctrl.Cmd,
        version: u8 = 2,
        reserved: u16 = 0,
    };

    pub const Ctrl = struct {
        pub const Attr = enum(u16) {
            UNSPEC,
            FAMILY_ID,
            FAMILY_NAME,
            VERSION,
            HDRSIZE,
            MAXATTR,
            OPS,
            MCAST_GROUPS,
            POLICY,
            OP_POLICY,
            OP,
            __CTRL_ATTR_MAX,
        };

        pub const Cmd = enum(u8) {
            UNSPEC,
            NEWFAMILY,
            DELFAMILY,
            GETFAMILY,
            NEWOPS,
            DELOPS,
            GETOPS,
            NEWMCAST_GRP,
            DELMCAST_GRP,
            GETMCAST_GRP,
            GETPOLICY,
            __MAX,
        };
    };

    pub const GENL = enum(u8) {
        ID_CTRL = std.os.linux.NetlinkMessageType.MIN_TYPE,
        ID_VFS_DQUOT,
        ID_PMCRAID,
        START_ALLOC,
    };
};

const std = @import("std");
const AF = std.posix.AF;
