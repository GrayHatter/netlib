pub fn sendMsg() !void {
    const stdout = std.io.getStdOut().writer();

    const s = try socket(.netlink_generic);
    defer s.close();

    const CtrlMsgHdr = nl.generic.MsgHdr(nl.generic.Ctrl.Cmd);
    const AttrCtrlHdr = Attr(nl.generic.Ctrl.Attr);

    var msg: nl.NewMessage(nl.generic.GENL, NlHdrFlags.Ack, CtrlMsgHdr, 12) = .init(
        .{ .len = 0, .type = .ID_CTRL, .flags = .ReqAck, .seq = 1 },
        .{ .cmd = .GETFAMILY },
    );
    try msg.packAttr(AttrCtrlHdr, .initNew(.FAMILY_NAME, @alignCast("nl80211\x00")));
    try msg.send(s);

    var fid: u16 = 0;
    var nl_more: bool = true;
    while (nl_more) {
        var family: nl.NewMessage(NlMsgType, NlHdrFlags.Get, CtrlMsgHdr, 0x8000) = try .initRecv(s);
        std.debug.assert(family.extra == 0);

        try stdout.print("flags {} {b} \n", .{ family.header.flags, @as(u16, @bitCast(family.header.flags)) });
        switch (family.header.type) {
            .DONE => nl_more = false,
            .ERROR => {
                if (family.header.len > @sizeOf(@TypeOf(family.header))) {
                    const emsg: *align(4) nlmsgerr = @alignCast(@ptrCast(&family.base));
                    if (emsg.err != 0) {
                        try stdout.print("error {} \n", .{family.header});
                        try stdout.print("error msg {} \n", .{emsg});
                    }
                }
                nl_more = false;
            },
            else => fid = try dumpAttrs(stdout, @alignCast(family.payload(0))),
        }
    }

    if (fid != 0) {
        try dumpProtocol(stdout, fid);
        try dumpWiphy(stdout, fid);
    }

    try stdout.print("done\n", .{});
}

fn dumpProtocol(stdout: anytype, fid: u16) !void {
    {
        const s = try socket(.netlink_generic);
        defer s.close();
        try stdout.print("\n\n\ndump prot features\n", .{});

        const CtrlMsgHdr = nl.generic.MsgHdr(Cmd);
        var msg: nl.NewMessage(u16, NlHdrFlags.Get, CtrlMsgHdr, 0) = .init(
            .{ .len = 0, .type = fid, .flags = .ReqAck, .seq = 6 },
            .{ .cmd = .GET_PROTOCOL_FEATURES },
        );
        try msg.send(s);

        var rbuffer: [0x8000]u8 align(4) = undefined;
        var nl_more: bool = true;
        while (nl_more) {
            var size = try s.read(&rbuffer);
            var start: usize = 0;
            const NlMsgHdr = nl.MsgHdr(NlMsgType, NlHdrFlags.Get);
            while (size > 0) {
                if (size < @sizeOf(NlMsgHdr)) {
                    try stdout.print("response too small {}\n", .{size});
                    @panic("");
                }
                try stdout.print("    data{any}\n", .{rbuffer[0..size]});
                const hdr: *NlMsgHdr = @ptrCast(@alignCast(rbuffer[start..]));
                const aligned: usize = hdr.len + 3 & ~@as(usize, 3);

                switch (hdr.type) {
                    .DONE => nl_more = false,
                    .ERROR => {
                        if (hdr.len > @sizeOf(NlMsgHdr)) {
                            const emsg: *align(4) nlmsgerr = @alignCast(@ptrCast(rbuffer[start + @sizeOf(NlMsgHdr) ..]));
                            if (emsg.err != 0) {
                                try stdout.print("error {} \n", .{hdr});
                                try stdout.print("error msg {} \n", .{emsg});
                            }
                        }
                        nl_more = false;
                    },
                    else => try stdout.print("    hdr {any}\n", .{hdr}),
                }
                size -|= aligned;
                start += aligned;
            }
        }
    }
}

fn dumpWiphy(stdout: anytype, fid: u16) !void {
    {
        const s = try socket(.netlink_generic);
        defer s.close();

        try stdout.print("\n\n\ndump wiphy\n", .{});

        const NlMsgHdr = nl.MsgHdr(NlMsgType, NlHdrFlags.Get);
        const CtrlMsgHdr = nl.generic.MsgHdr(Cmd);

        var msg: nl.NewMessage(u16, NlHdrFlags.Get, CtrlMsgHdr, 0) = .init(
            .{ .len = 0, .type = fid, .flags = .DUMP, .seq = 17 },
            .{ .cmd = .GET_WIPHY },
        );
        try msg.send(s);

        var nl_more: bool = true;
        while (nl_more) {
            var wiphy: nl.NewMessage(NlMsgType, NlHdrFlags.Get, CtrlMsgHdr, 0x8000) = try .initRecv(s);
            std.debug.assert(wiphy.extra == 0);
            //try stdout.print("\n\n\nhdr {any}\n", .{wiphy.header});
            var offset: usize = 0;
            var blob = wiphy.payload(offset);
            switch (wiphy.header.type) {
                .DONE => nl_more = false,
                .ERROR => {
                    try stdout.print("error {} \n", .{wiphy.header});
                    if (wiphy.header.len > @sizeOf(NlMsgHdr)) {
                        const emsg: *align(4) const nlmsgerr = @ptrCast(blob);
                        try stdout.print("error msg {} \n", .{emsg});
                    }
                    nl_more = false;
                },
                else => {
                    while (blob.len > 0) {
                        const attr: Attr(Attrs) = try .init(blob);
                        switch (attr.type) {
                            .WIPHY_NAME => try stdout.print("    name: {s}\n", .{attr.data[0 .. attr.data.len - 1 :0]}),
                            else => {
                                try stdout.print(
                                    "    attr.type {} [{}] {any}\n",
                                    .{ attr.type, attr.len, if (attr.len <= 40) attr.data else "" },
                                );
                            },
                        }
                        offset += attr.len_aligned;
                        blob = wiphy.payload(offset);
                    }
                },
            }
        }
    }
}

pub fn dumpAttrs(stdout: anytype, data: []align(4) const u8) !u16 {
    var offset: usize = 0;
    var family_id: u16 = 0;
    while (offset < data.len) {
        const attr: Attr(nl.generic.Ctrl.Attr) = try .init(@alignCast(data[offset..]));
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

                    const nattr_0: Attr(nl.generic.Ctrl.AttrOps) = try .init(nattr.data[0..8]);
                    const nattr_1: Attr(nl.generic.Ctrl.AttrOps) = try .init(nattr.data[8..16]);

                    // I couldn't find documentation, so I'm just expermenting
                    // with the way iproute2/genl works
                    const op_id: *const u32 = @ptrCast(nattr_0.data[0..4]);
                    try stdout.print("    {}\n", .{@as(Cmd, @enumFromInt(op_id.*))});
                    try stdout.print("        op id {} (0x{x}) ", .{ op_id.*, op_id.* });
                    const cap: *const nl.generic.CAP = @ptrCast(nattr_1.data);
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

    const nlmsghdr = nl.MsgHdr(NlMsgType, NlHdrFlags.Get);
};

const NlHdrFlags = nl.HeaderFlags;
const NlMsgType = nl.MsgType;

const kapi = @import("nl80211/kapi.zig");
const Attrs = kapi.Attrs;
const Cmd = kapi.Cmd;

const nl = @import("netlink.zig");
const socket = @import("socket.zig").socket;

const Attr = nl.Attr;

const std = @import("std");
