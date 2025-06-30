pub const Cmd = enum(u8) {
    UNSPEC,
    GET_WIPHY,
    SET_WIPHY,
    NEW_WIPHY,
    DEL_WIPHY,
    GET_INTERFACE,
    SET_INTERFACE,
    NEW_INTERFACE,
    DEL_INTERFACE,
    GET_KEY,
    SET_KEY,
    NEW_KEY,
    DEL_KEY,
    GET_BEACON,
    SET_BEACON,
    START_AP,
    STOP_AP,
    GET_STATION,
    SET_STATION,
    NEW_STATION,
    DEL_STATION,
    GET_MPATH,
    SET_MPATH,
    NEW_MPATH,
    DEL_MPATH,
    SET_BSS,
    SET_REG,
    REQ_SET_REG,
    GET_MESH_CONFIG,
    SET_MESH_CONFIG,
    SET_MGMT_EXTRA_IE,
    GET_REG,
    GET_SCAN,
    TRIGGER_SCAN,
    NEW_SCAN_RESULTS,
    SCAN_ABORTED,
    REG_CHANGE,
    AUTHENTICATE,
    ASSOCIATE,
    DEAUTHENTICATE,
    DISASSOCIATE,
    MICHAEL_MIC_FAILURE,
    REG_BEACON_HINT,
    JOIN_IBSS,
    LEAVE_IBSS,
    TESTMODE,
    CONNECT,
    ROAM,
    DISCONNECT,
    SET_WIPHY_NETNS,
    GET_SURVEY,
    NEW_SURVEY_RESULTS,
    SET_PMKSA,
    DEL_PMKSA,
    FLUSH_PMKSA,
    REMAIN_ON_CHANNEL,
    CANCEL_REMAIN_ON_CHANNEL,
    SET_TX_BITRATE_MASK,
    REGISTER_FRAME,
    FRAME,
    FRAME_TX_STATUS,
    SET_POWER_SAVE,
    GET_POWER_SAVE,
    SET_CQM,
    NOTIFY_CQM,
    SET_CHANNEL,
    SET_WDS_PEER,
    FRAME_WAIT_CANCEL,
    JOIN_MESH,
    LEAVE_MESH,
    UNPROT_DEAUTHENTICATE,
    UNPROT_DISASSOCIATE,
    NEW_PEER_CANDIDATE,
    GET_WOWLAN,
    SET_WOWLAN,
    START_SCHED_SCAN,
    STOP_SCHED_SCAN,
    SCHED_SCAN_RESULTS,
    SCHED_SCAN_STOPPED,
    SET_REKEY_OFFLOAD,
    PMKSA_CANDIDATE,
    TDLS_OPER,
    TDLS_MGMT,
    UNEXPECTED_FRAME,
    PROBE_CLIENT,
    REGISTER_BEACONS,
    UNEXPECTED_4ADDR_FRAME,
    SET_NOACK_MAP,
    CH_SWITCH_NOTIFY,
    START_P2P_DEVICE,
    STOP_P2P_DEVICE,
    CONN_FAILED,
    SET_MCAST_RATE,
    SET_MAC_ACL,
    RADAR_DETECT,
    GET_PROTOCOL_FEATURES,
    UPDATE_FT_IES,
    FT_EVENT,
    CRIT_PROTOCOL_START,
    CRIT_PROTOCOL_STOP,
    GET_COALESCE,
    SET_COALESCE,
    CHANNEL_SWITCH,
    VENDOR,
    SET_QOS_MAP,
    ADD_TX_TS,
    DEL_TX_TS,
    GET_MPP,
    JOIN_OCB,
    LEAVE_OCB,
    CH_SWITCH_STARTED_NOTIFY,
    TDLS_CHANNEL_SWITCH,
    TDLS_CANCEL_CHANNEL_SWITCH,
    WIPHY_REG_CHANGE,
    ABORT_SCAN,
    START_NAN,
    STOP_NAN,
    ADD_NAN_FUNCTION,
    DEL_NAN_FUNCTION,
    CHANGE_NAN_CONFIG,
    NAN_MATCH,
    SET_MULTICAST_TO_UNICAST,
    UPDATE_CONNECT_PARAMS,
    SET_PMK,
    DEL_PMK,
    PORT_AUTHORIZED,
    RELOAD_REGDB,
    EXTERNAL_AUTH,
    STA_OPMODE_CHANGED,
    CONTROL_PORT_FRAME,
    GET_FTM_RESPONDER_STATS,
    PEER_MEASUREMENT_START,
    PEER_MEASUREMENT_RESULT,
    PEER_MEASUREMENT_COMPLETE,
    NOTIFY_RADAR,
    UPDATE_OWE_INFO,
    PROBE_MESH_LINK,
    SET_TID_CONFIG,
    UNPROT_BEACON,
    CONTROL_PORT_FRAME_TX_STATUS,
    SET_SAR_SPECS,
    OBSS_COLOR_COLLISION,
    COLOR_CHANGE_REQUEST,
    COLOR_CHANGE_STARTED,
    COLOR_CHANGE_ABORTED,
    COLOR_CHANGE_COMPLETED,
    SET_FILS_AAD,
    ASSOC_COMEBACK,
    ADD_LINK,
    REMOVE_LINK,
    ADD_LINK_STA,
    MODIFY_LINK_STA,
    REMOVE_LINK_STA,
    SET_HW_TIMESTAMP,
    LINKS_REMOVED,
    SET_TID_TO_LINK_MAPPING,
    ASSOC_MLO_RECONF,
    EPCS_CFG,
    __AFTER_LAST,

    pub const NEW_BEACON: Cmd = .START_AP;
    pub const DEL_BEACON: Cmd = .STOP_AP;
    pub const ACTION: Cmd = .FRAME;
    pub const ACTION_TX_STATUS: Cmd = .FRAME_TX_STATUS;
    pub const REGISTER_ACTION: Cmd = .REGISTER_FRAME;
};

pub fn sendMsg() !void {
    const stdout = std.io.getStdOut().writer();

    const s = try socket(.netlink_generic);

    const NlMsgHdr = netlink.MsgHdr(netlink.MsgType, netlink.HeaderFlags.Get);
    const GenlMsgHdr = netlink.MsgHdr(netlink.generic.GENL, netlink.HeaderFlags.Ack);
    const CtrlMsgHdr = netlink.generic.MsgHdr(netlink.generic.Ctrl.Cmd);
    const AttrCtrlHdr = Attr(netlink.generic.Ctrl.Attr).Header;

    const full_size = (@sizeOf(NlMsgHdr) + @sizeOf(CtrlMsgHdr) + @sizeOf(AttrCtrlHdr) + 8 + 3) & ~@as(usize, 3);

    var w_buffer: [full_size]u8 align(4) = undefined;
    var w_list: std.ArrayListUnmanaged(u8) = .initBuffer(&w_buffer);
    var w = w_list.fixedWriter();

    const req_hdr: GenlMsgHdr = .{ .len = full_size, .type = .ID_CTRL, .flags = .ReqAck, .seq = 1 };
    try w.writeStruct(req_hdr);

    const r_genmsg: CtrlMsgHdr = .{ .cmd = .GETFAMILY };
    try w.writeStruct(r_genmsg);

    const attr: AttrCtrlHdr = .{ .len = 12, .type = .FAMILY_NAME };
    try w.writeStruct(attr);
    try w.writeAll("nl80211");
    try w.writeByte(0);

    _ = try s.write(w_list.items);

    try stdout.print("request {any}\n", .{w_list.items});

    var rbuffer: [0x8000]u8 align(4) = undefined;

    var nl_more: bool = true;

    var fid: u16 = 0;

    while (nl_more) {
        var size = try s.read(&rbuffer);
        var start: usize = 0;
        while (size > 0) {
            if (size < @sizeOf(NlMsgHdr)) {
                try stdout.print("response too small {}\n", .{size});
                @panic("");
            }

            try stdout.print("\n\n\n", .{});
            const hdr: *NlMsgHdr = @ptrCast(@alignCast(rbuffer[start..]));
            const aligned: usize = hdr.len + 3 & ~@as(usize, 3);

            try stdout.print("flags {} {b} \n", .{ hdr.flags, @as(u16, @bitCast(hdr.flags)) });
            switch (hdr.type) {
                .ERROR => {
                    try stdout.print("error {} \n", .{hdr});
                    if (hdr.len > @sizeOf(NlMsgHdr)) {
                        const emsg: *align(4) nlmsgerr = @alignCast(@ptrCast(rbuffer[start + @sizeOf(NlMsgHdr) ..]));
                        try stdout.print("error msg {} \n", .{emsg});
                    }
                    nl_more = false;
                },

                .DONE => nl_more = false,
                else => fid = try dump(stdout, @alignCast(rbuffer[start + @sizeOf(NlMsgHdr) .. aligned])),
            }

            size -|= aligned;
            start += aligned;
        }
    }

    if (fid != 0) {
        try msgFamily(stdout, fid);
    }

    try stdout.print("done\n", .{});
}

fn msgFamily(stdout: anytype, fid: u16) !void {
    const s = try socket(.netlink_generic);

    {
        try stdout.print("\n\n\ndump prot features \n\n\n", .{});

        const NlMsgHdr = netlink.MsgHdr(netlink.MsgType, netlink.HeaderFlags.Get);
        const GenlMsgHdr = netlink.MsgHdr(u16, netlink.HeaderFlags.Get);
        const CtrlMsgHdr = netlink.generic.MsgHdr(Cmd);

        const full_size = (@sizeOf(GenlMsgHdr) + @sizeOf(CtrlMsgHdr) + 3) & ~@as(usize, 3);

        var w_buffer: [full_size]u8 align(4) = undefined;
        var w_list: std.ArrayListUnmanaged(u8) = .initBuffer(&w_buffer);
        var w = w_list.fixedWriter();

        const req_hdr: GenlMsgHdr = .{ .len = full_size, .type = fid, .flags = .ReqAck, .seq = 13 };
        try w.writeStruct(req_hdr);
        try stdout.print("req_hdr {any}\n\n\n", .{req_hdr});

        try w.writeStruct(CtrlMsgHdr{ .cmd = .GET_PROTOCOL_FEATURES });

        _ = try s.write(w_list.items);

        try stdout.print("request {any}\n", .{w_list.items});

        var rbuffer: [0x8000]u8 align(4) = undefined;

        var nl_more: bool = true;

        while (nl_more) {
            var size = try s.read(&rbuffer);
            var start: usize = 0;
            while (size > 0) {
                if (size < @sizeOf(NlMsgHdr)) {
                    try stdout.print("response too small {}\n", .{size});
                    @panic("");
                }
                try stdout.print("\n\n\n", .{});
                try stdout.print("data\n{any}\n\n\n", .{rbuffer[0..size]});
                const hdr: *NlMsgHdr = @ptrCast(@alignCast(rbuffer[start..]));
                const aligned: usize = hdr.len + 3 & ~@as(usize, 3);

                switch (hdr.type) {
                    .ERROR => {
                        try stdout.print("error {} \n", .{hdr});
                        if (hdr.len > @sizeOf(NlMsgHdr)) {
                            const emsg: *align(4) nlmsgerr = @alignCast(@ptrCast(rbuffer[start + @sizeOf(NlMsgHdr) ..]));
                            try stdout.print("error msg {} \n", .{emsg});
                        }
                        nl_more = false;
                    },

                    .DONE => nl_more = false,
                    else => {
                        try stdout.print("hdr {any}\n", .{hdr});
                    },
                }
                size -|= aligned;
                start += aligned;
            }
        }
    }
    {
        try stdout.print("\n\n\ndump wiphy \n\n\n", .{});

        const NlMsgHdr = netlink.MsgHdr(netlink.MsgType, netlink.HeaderFlags.Get);
        const CtrlMsgHdr = netlink.generic.MsgHdr(Cmd);

        const full_size = (@sizeOf(NlMsgHdr) + @sizeOf(CtrlMsgHdr) + 3) & ~@as(usize, 3);

        var w_buffer: [full_size]u8 align(4) = undefined;
        var w_list: std.ArrayListUnmanaged(u8) = .initBuffer(&w_buffer);
        var w = w_list.fixedWriter();

        const req_hdr: NlMsgHdr = .{
            .len = full_size,
            .type = @enumFromInt(fid),
            .flags = .DUMP,
            .seq = 17,
        };
        try w.writeStruct(req_hdr);
        //try stdout.print("req_hdr {any}\n\n\n", .{req_hdr});
        try w.writeStruct(CtrlMsgHdr{ .cmd = .GET_WIPHY });
        //try stdout.print("request {any}\n", .{w_list.items});
        _ = try s.write(w_list.items);

        var rbuffer: [0x8000]u8 align(4) = undefined;

        var nl_more: bool = true;

        while (nl_more) {
            var size = try s.read(&rbuffer);
            var start: usize = 0;
            while (size > 0) {
                if (size < @sizeOf(NlMsgHdr)) {
                    try stdout.print("response too small {}\n", .{size});
                    @panic("");
                }
                try stdout.print("\n\n\n", .{});
                //try stdout.print("data\n{any}\n\n\n", .{rbuffer[0..size]});
                const hdr: *NlMsgHdr = @ptrCast(@alignCast(rbuffer[start..]));
                try stdout.print("hdr {any}\n", .{hdr});

                const aligned: usize = hdr.len + 3 & ~@as(usize, 3);

                const cmsghdr: *CtrlMsgHdr = @ptrCast(@alignCast(rbuffer[start + @sizeOf(NlMsgHdr) ..]));
                try stdout.print("cmsghdr {any}\n\n", .{cmsghdr.*});

                switch (hdr.type) {
                    .ERROR => {
                        try stdout.print("error {} \n", .{hdr});
                        if (hdr.len > @sizeOf(NlMsgHdr)) {
                            const emsg: *align(4) nlmsgerr = @alignCast(@ptrCast(rbuffer[start + @sizeOf(NlMsgHdr) + @sizeOf(CtrlMsgHdr) ..]));
                            try stdout.print("error msg {} \n", .{emsg});
                        }
                        nl_more = false;
                    },

                    .DONE => nl_more = false,
                    else => {
                        var a_offset: usize = start + @sizeOf(NlMsgHdr) + @sizeOf(CtrlMsgHdr);
                        while (a_offset < hdr.len + start) {
                            const attr: Attr(Attrs) = try .init(@alignCast(rbuffer[a_offset..]));
                            switch (attr.type) {
                                .WIPHY_NAME => try stdout.print("    name: {s}\n", .{attr.data[0 .. attr.data.len - 1 :0]}),
                                else => {
                                    try stdout.print(
                                        "    attr.type {} [{}] {any}\n",
                                        .{ attr.type, attr.len, if (attr.len <= 40) attr.data else "" },
                                    );
                                },
                            }
                            a_offset += attr.len_aligned;
                        }
                    },
                }

                size -|= aligned;
                start += aligned;
            }
        }
    }
}

pub fn dump(stdout: anytype, data: []align(4) const u8) !u16 {
    var offset: usize = 0;
    //const rtattr = std.os.linux.rtattr;
    const genlmsg: *align(4) const netlink.generic.MsgHdr(netlink.generic.Ctrl.Cmd) = @ptrCast(@alignCast(data[offset..]));
    try stdout.print("genl {any}\n", .{genlmsg});
    offset += @sizeOf(netlink.generic.MsgHdr(netlink.generic.Ctrl.Cmd));

    var family_id: u16 = 0;

    while (offset < data.len) {
        const attr: Attr(netlink.generic.Ctrl.Attr) = try .init(@alignCast(data[offset..]));
        switch (attr.type) {
            .FAMILY_NAME => try stdout.print("name: {s}\n", .{attr.data[0 .. attr.data.len - 1 :0]}),
            .FAMILY_ID => family_id = @as(*const u16, @ptrCast(attr.data)).*,
            .VERSION => try stdout.print("version: {}\n", .{@as(*const u32, @ptrCast(attr.data)).*}),
            .HDRSIZE => try stdout.print("hdrsize: {}\n", .{@as(*const u32, @ptrCast(attr.data)).*}),
            .MAXATTR => try stdout.print("maxattr: {}\n", .{@as(*const u32, @ptrCast(attr.data)).*}),
            .MCAST_GROUPS => try stdout.print("mcastgrp: {any}\n", .{attr.data}),
            .OPS => {
                try stdout.print(
                    "attr {}\n    {}    {b}\n",
                    .{ attr.type, @intFromEnum(attr.type), @intFromEnum(attr.type) },
                );
                var noffset: usize = 0;
                while (noffset < attr.data.len) {
                    const nattr: Attr(u16) = try .init(@alignCast(attr.data[noffset..]));
                    noffset += nattr.len;

                    const nattr_0: Attr(netlink.generic.Ctrl.AttrOps) = try .init(nattr.data[0..8]);
                    const nattr_1: Attr(netlink.generic.Ctrl.AttrOps) = try .init(nattr.data[8..16]);

                    // I couldn't find documentation, so I'm just expermenting
                    // with the way iproute2/genl works
                    const op_id: *const u32 = @ptrCast(nattr_0.data[0..4]);
                    try stdout.print("    {}\n", .{@as(Cmd, @enumFromInt(op_id.*))});
                    try stdout.print("        op id {} (0x{x}) ", .{ op_id.*, op_id.* });
                    const cap: *const netlink.generic.CAP = @ptrCast(nattr_1.data);
                    if (cap.ADMIN_PERM) try stdout.print(" admin required,", .{});
                    if (cap.DO) try stdout.print(" can do,", .{});
                    if (cap.HAS_POLICY) try stdout.print(" has policy,", .{});
                    if (cap.__padding != 0) try stdout.print(" padding non-zero {}", .{cap.__padding});
                    try stdout.print("\n", .{});
                }
            },
            else => {
                try stdout.print("\n\n\n\nattr {}\n    {}    {b} ", .{ attr.type, @intFromEnum(attr.type), @intFromEnum(attr.type) });
                try stdout.print("attr.len {}\n", .{attr.len});
                try stdout.print("attr.data {any} \n\n\n", .{attr.data});
            },
        }
        offset += attr.len_aligned;
    }
    if (family_id != 0) try stdout.print("ID: {}\n", .{family_id});
    return family_id;
}

pub const nlmsgerr = extern struct {
    err: i32,
    msg: nlmsghdr,

    const nlmsghdr = netlink.MsgHdr(netlink.MsgType, netlink.HeaderFlags.Get);
};

const Attrs = @import("nl80211/attr.zig").Attrs;

const netlink = @import("netlink.zig");
const socket = @import("socket.zig").socket;

const Attr = netlink.Attr;

const std = @import("std");
