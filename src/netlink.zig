pub const MsgType = std.os.linux.NetlinkMessageType;
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
    /// Experimental API
    pub fn newSocket() !socket.Socket {
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
            __MAX,
        };

        pub const AttrOps = enum(u16) {
            UNSPEC,
            ID,
            FLAGS,
            __MAX,
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

        pub fn init(h: Hdr, b: BT) Self {
            return .{
                .header = h,
                .base = b,
            };
        }

        pub fn initRecv(sock: socket.Socket) !Self {
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

        pub fn send(s: *Self, sock: socket.Socket) !void {
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
