const std = @import("std");
const P256 = std.crypto.ecc.P256;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const KeyPair = struct {
    private_key: [32]u8,
    public_key: [65]u8,

    /// Generate a new, secure P256 KeyPair using the provided system standard I/O engine.
    pub fn generate(io: std.Io) !KeyPair {
        // Generate a random scalar directly from standard secure Io
        const scalar = P256.scalar.random(io, .big);
        
        // Multiply the basePoint by the scalar to get the public point
        const public_point = try P256.basePoint.mul(scalar, .big);
        const public_key_sec1 = public_point.toUncompressedSec1();

        return KeyPair{
            .private_key = scalar,
            .public_key = public_key_sec1,
        };
    }

    /// Load a KeyPair from raw 32-byte private key bytes.
    pub fn fromBytes(private_key_bytes: [32]u8) !KeyPair {
        // Multiply basePoint to get the corresponding public key
        const public_point = try P256.basePoint.mul(private_key_bytes, .big);
        const public_key_sec1 = public_point.toUncompressedSec1();

        return KeyPair{
            .private_key = private_key_bytes,
            .public_key = public_key_sec1,
        };
    }

    /// Computes the unique 4-byte Key ID from the public key.
    /// In the Tesla BLE protocol, this is the first 4 bytes of the SHA1 hash of the public key.
    pub fn getPublicKeyId(self: KeyPair) [4]u8 {
        var hash_out: [20]u8 = undefined;
        Sha1.hash(&self.public_key, &hash_out, .{});
        var key_id: [4]u8 = undefined;
        @memcpy(&key_id, hash_out[0..4]);
        return key_id;
    }
};

/// Computes the 16-byte shared secret SHA1 hash from our private key and the vehicle's public key point.
/// Returns the first 16 bytes of the SHA1 hash as our symmetric AES-GCM-128 session key.
pub fn computeSharedSecret(private_key: [32]u8, vehicle_public_key: [65]u8) ! [16]u8 {
    // Deserialize the vehicle's uncompressed SEC1 public key point
    const vehicle_point = try P256.fromSec1(&vehicle_public_key);
    
    // Multiply the vehicle's point by our private key scalar to perform ECDH
    const shared_point = try vehicle_point.mul(private_key, .big);
    const shared_sec1 = shared_point.toUncompressedSec1();

    // Hash only the X coordinate of the shared point with SHA1
    var hash_out: [20]u8 = undefined;
    Sha1.hash(shared_sec1[1..33], &hash_out, .{});

    // The session key is the first 16 bytes of the SHA1 hash
    var session_key: [16]u8 = undefined;
    @memcpy(&session_key, hash_out[0..16]);
    return session_key;
}

/// Computes the SHA256 hash of the Authenticated Data (AD) buffer to create the AAD.
pub fn computeAdHash(ad_buffer: []const u8) [32]u8 {
    var hash_out: [32]u8 = undefined;
    Sha256.hash(ad_buffer, &hash_out, .{});
    return hash_out;
}

/// AES-GCM-128 Encryption with AAD metadata hash.
pub fn aesGcmEncrypt(
    key: [16]u8,
    nonce: [12]u8,
    ad_hash: [32]u8,
    plaintext: []const u8,
    ciphertext_out: []u8,
    tag_out: *[16]u8,
) void {
    Aes128Gcm.encrypt(ciphertext_out, tag_out, plaintext, &ad_hash, nonce, key);
}

/// AES-GCM-128 Decryption with AAD metadata hash.
pub fn aesGcmDecrypt(
    key: [16]u8,
    nonce: [12]u8,
    ad_hash: [32]u8,
    ciphertext: []const u8,
    tag: [16]u8,
    plaintext_out: []u8,
) !void {
    try Aes128Gcm.decrypt(plaintext_out, ciphertext, tag, &ad_hash, nonce, key);
}

test "comprehensive crypto library test" {
    // We can simulate an ECDH handshake between two KeyPairs
    // Setup standard mock/PRNG for test predictability or generate two keys
    const kp_ours = try KeyPair.fromBytes([_]u8{1} ** 32);
    const kp_theirs = try KeyPair.fromBytes([_]u8{2} ** 32);

    // Compute shared secrets from both sides
    const secret_ours = try computeSharedSecret(kp_ours.private_key, kp_theirs.public_key);
    const secret_theirs = try computeSharedSecret(kp_theirs.private_key, kp_ours.public_key);

    // Verify ECDH agreement
    try std.testing.expectEqualSlices(u8, &secret_ours, &secret_theirs);

    // Test Key ID generation
    const key_id = kp_ours.getPublicKeyId();
    try std.testing.expect(key_id.len == 4);

    // Test AES-GCM Encryption & Decryption
    const key = secret_ours;
    const nonce = [_]u8{42} ** 12;
    const ad_buffer = "Tesla_AD_Metadata_Header_Sample_Payload";
    const ad_hash = computeAdHash(ad_buffer);
    const msg = "Super_Secret_Unlock_Vehicle_Command_Payload";

    var ciphertext: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    aesGcmEncrypt(key, nonce, ad_hash, msg, &ciphertext, &tag);

    var decrypted: [msg.len]u8 = undefined;
    try aesGcmDecrypt(key, nonce, ad_hash, &ciphertext, tag, &decrypted);

    try std.testing.expectEqualSlices(u8, msg, &decrypted);
}

test "crypto edge cases and error handling" {
    // Passing an invalid vehicle public key to computeSharedSecret should fail cleanly
    const private_key = [_]u8{1} ** 32;
    const invalid_public_key = [_]u8{0} ** 65;
    const res = computeSharedSecret(private_key, invalid_public_key);
    try std.testing.expectError(error.InvalidEncoding, res);
}

