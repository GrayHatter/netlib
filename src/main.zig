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

var debug: bool = false;

pub fn main() !void {
    var args = std.process.args();
    const arg0 = args.next() orelse usage("wat?!");

    while (args.next()) |arg| {
        if (startsWith(u8, arg, "--")) {
            usage(arg0);
        } else if (eql(u8, arg, "nl80211")) {
            return try nl80211.sendMsg();
        } else {
            return try route.route();
        }
    }
    return usage(arg0);
}

const route = @import("route.zig");
pub const nl80211 = @import("nl80211.zig");
const std = @import("std");
const startsWith = std.mem.startsWith;
const eql = std.mem.eql;
