const std = @import("std");

pub fn main() !void {
    const Sha1 = std.crypto.hash.Sha1;
    const msg = "test";
    var out: [20]u8 = undefined;
    Sha1.hash(msg, &out, .{});
    
    std.debug.print("SHA1 Hash: ", .{});
    for (out) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
}
