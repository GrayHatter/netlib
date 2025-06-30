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

const kapi = @import("nl80211/kapi.zig");
const Attrs = kapi.Attrs;
const Cmd = kapi.Cmd;

const netlink = @import("netlink.zig");
const socket = @import("socket.zig").socket;

const Attr = netlink.Attr;

const std = @import("std");
