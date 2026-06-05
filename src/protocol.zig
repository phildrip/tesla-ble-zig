const std = @import("std");

/// UniversalMessage_Domain defines the message domains for the Tesla BLE protocol.
pub const Domain = enum(u8) {
    broadcast = 0,
    vehicle_security = 2,
    infotainment = 3,
};

/// Signatures_Tag defines TLV (Tag-Length-Value) tags used to assemble the
/// Authenticated Data (AD) metadata hash for signing commands.
pub const Tag = enum(u8) {
    signature_type = 0,
    domain = 1,
    personalization = 2,
    epoch = 3,
    expires_at = 4,
    counter = 5,
    challenge = 6,
    flags = 7,
    request_hash = 8,
    fault = 9,
    end = 255,
};

/// Signatures_SignatureType defines the type of authentication signature.
pub const SignatureType = enum(u8) {
    aes_gcm = 0,
    aes_gcm_personalized = 5,
    hmac = 6,
    hmac_personalized = 8,
    aes_gcm_response = 9,
};

test "protocol type alignments" {
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(Domain.vehicle_security));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(Domain.infotainment));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(Tag.counter));
    try std.testing.expectEqual(@as(u8, 255), @intFromEnum(Tag.end));
    try std.testing.expectEqual(@as(u8, 9), @intFromEnum(SignatureType.aes_gcm_response));
}
