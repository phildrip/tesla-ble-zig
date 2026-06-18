const std = @import("std");
const crypto = @import("crypto.zig");

pub fn main() !void {
    const api_encryption_key = "Cg/+mx6ZdH2QBdrmrKtg/zmG0TK/IDHBBr3DUJDXKpo=";
    var decoded_priv_key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&decoded_priv_key, api_encryption_key);

    const kp = try crypto.KeyPair.fromBytes(decoded_priv_key);
    
    std.debug.print("Our Public Key: ", .{});
    for (kp.public_key) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});

    const key_id = kp.getPublicKeyId();
    std.debug.print("Our Key ID (first 4 bytes of SHA1): ", .{});
    for (key_id) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});

    var full_sha1: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(&kp.public_key, &full_sha1, .{});
    std.debug.print("Our Full SHA1: ", .{});
    for (full_sha1) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
}
