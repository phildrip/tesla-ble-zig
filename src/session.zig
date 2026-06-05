const std = @import("std");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");

/// SeenCounterCache provides a fixed-size, bare-metal friendly, non-allocating cache
/// of seen response counters to prevent replay attacks. It tracks up to 16 of the
/// most recent request ID and counter pairings in a ring buffer.
pub const SeenCounterCache = struct {
    const Slot = struct {
        request_id: u32,
        counter: u32,
    };
    slots: [16]Slot,
    head: usize,
    count: usize,

    pub fn init() SeenCounterCache {
        return .{
            .slots = [_]Slot{.{ .request_id = 0, .counter = 0 }} ** 16,
            .head = 0,
            .count = 0,
        };
    }

    /// Verifies if a response counter has been previously received for a given request ID.
    /// If it has been used, returns false. Otherwise, caches the counter and returns true.
    pub fn validateAndAdd(self: *SeenCounterCache, request_id: u32, counter: u32) bool {
        const limit = @min(self.count, 16);
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            const idx = (self.head + 16 - i) % 16;
            if (self.slots[idx].request_id == request_id and self.slots[idx].counter == counter) {
                return false;
            }
        }

        self.head = (self.head + 1) % 16;
        self.slots[self.head] = .{ .request_id = request_id, .counter = counter };
        if (self.count < 16) {
            self.count += 1;
        }
        return true;
    }
};

/// Session represents a Tesla BLE secure session, managing sequence counters,
/// epoch info, shared session keys, and providing high-level safe methods for
/// AD construction, command encryption, and response decryption.
pub const Session = struct {
    domain: protocol.Domain,
    vin: [32]u8,
    vin_len: u8,
    epoch: [16]u8,
    counter: u32,
    time_zero: u32,
    shared_secret: [16]u8,
    is_valid: bool,
    seen_counters: SeenCounterCache,

    /// Create a new session tracking structure for a specified message domain and VIN.
    pub fn init(domain: protocol.Domain, vin: []const u8) !Session {
        if (vin.len > 32) return error.VinTooLong;
        var self = Session{
            .domain = domain,
            .vin = [_]u8{0} ** 32,
            .vin_len = @intCast(vin.len),
            .epoch = [_]u8{0} ** 16,
            .counter = 0,
            .time_zero = 0,
            .shared_secret = [_]u8{0} ** 16,
            .is_valid = false,
            .seen_counters = SeenCounterCache.init(),
        };
        @memcpy(self.vin[0..vin.len], vin);
        return self;
    }

    /// Return the stored VIN string as a read-only slice.
    pub fn getVin(self: Session) []const u8 {
        return self.vin[0..self.vin_len];
    }

    /// Increments the session's counter (with wrapping overflow protection).
    pub fn incrementCounter(self: *Session) void {
        self.counter = self.counter +% 1;
    }

    /// Update the session state with a vehicle-provided SessionInfo payload.
    /// This triggers the ECDH key exchange to compute the shared secret session key.
    pub fn updateSession(
        self: *Session,
        epoch: [16]u8,
        counter: u32,
        clock_time: u32,
        generated_at: u32,
        vehicle_pub_key: [65]u8,
        our_private_key: [32]u8,
    ) !void {
        self.epoch = epoch;
        self.counter = counter;
        self.time_zero = generated_at -% clock_time;
        self.shared_secret = try crypto.computeSharedSecret(our_private_key, vehicle_pub_key);
        self.is_valid = true;
    }

    /// Generate an epoch-relative command expiration timestamp.
    pub fn generateExpiresAt(self: Session, current_time: u32, seconds: u32) u32 {
        return (current_time + seconds) -% self.time_zero;
    }

    /// Helper to assemble a TLV representation of Authenticated Data (AD) for signing/encryption.
    pub fn constructAdBuffer(
        self: Session,
        signature_type: protocol.SignatureType,
        expires_at: u32,
        flags: u32,
        request_hash: ?[]const u8,
        fault: u32,
        output: []u8,
    ) !usize {
        var index: usize = 0;

        // Signature type
        if (index + 3 > output.len) return error.BufferTooSmall;
        output[index] = @intFromEnum(protocol.Tag.signature_type);
        output[index + 1] = 0x01;
        output[index + 2] = @intFromEnum(signature_type);
        index += 3;

        // Domain
        if (index + 3 > output.len) return error.BufferTooSmall;
        output[index] = @intFromEnum(protocol.Tag.domain);
        output[index + 1] = 0x01;
        output[index + 2] = @intFromEnum(self.domain);
        index += 3;

        // Personalization (VIN)
        const vin_slice = self.getVin();
        if (index + 2 + vin_slice.len > output.len) return error.BufferTooSmall;
        output[index] = @intFromEnum(protocol.Tag.personalization);
        output[index + 1] = @intCast(vin_slice.len);
        @memcpy(output[index + 2 .. index + 2 + vin_slice.len], vin_slice);
        index += 2 + vin_slice.len;

        // Epoch
        if (index + 18 > output.len) return error.BufferTooSmall;
        output[index] = @intFromEnum(protocol.Tag.epoch);
        output[index + 1] = 16;
        @memcpy(output[index + 2 .. index + 18], &self.epoch);
        index += 18;

        // Expires at
        if (index + 6 > output.len) return error.BufferTooSmall;
        output[index] = @intFromEnum(protocol.Tag.expires_at);
        output[index + 1] = 4;
        std.mem.writeInt(u32, output[index + 2 .. index + 6][0..4], expires_at, .big);
        index += 6;

        // Counter
        if (index + 6 > output.len) return error.BufferTooSmall;
        output[index] = @intFromEnum(protocol.Tag.counter);
        output[index + 1] = 4;
        std.mem.writeInt(u32, output[index + 2 .. index + 6][0..4], self.counter, .big);
        index += 6;

        if (flags > 0 or signature_type == .aes_gcm_response) {
            if (index + 6 > output.len) return error.BufferTooSmall;
            output[index] = @intFromEnum(protocol.Tag.flags);
            output[index + 1] = 4;
            std.mem.writeInt(u32, output[index + 2 .. index + 6][0..4], flags, .big);
            index += 6;
        }

        if (signature_type == .aes_gcm_response) {
            if (request_hash) |hash| {
                if (index + 2 + hash.len > output.len) return error.BufferTooSmall;
                output[index] = @intFromEnum(protocol.Tag.request_hash);
                output[index + 1] = @intCast(hash.len);
                @memcpy(output[index + 2 .. index + 2 + hash.len], hash);
                index += 2 + hash.len;
            }

            if (index + 6 > output.len) return error.BufferTooSmall;
            output[index] = @intFromEnum(protocol.Tag.fault);
            output[index + 1] = 4;
            std.mem.writeInt(u32, output[index + 2 .. index + 6][0..4], fault, .big);
            index += 6;
        }

        // Terminal byte
        if (index + 1 > output.len) return error.BufferTooSmall;
        output[index] = @intFromEnum(protocol.Tag.end);
        index += 1;

        return index;
    }

    /// Construct a Request Hash buffer by prefixing the signature/auth type byte and copying the auth tag.
    pub fn constructRequestHash(
        auth_type: protocol.SignatureType,
        auth_tag: []const u8,
        domain: protocol.Domain,
        request_hash_out: []u8,
    ) !usize {
        if (request_hash_out.len < auth_tag.len + 1) {
            return error.BufferTooSmall;
        }
        request_hash_out[0] = @intFromEnum(auth_type);

        // For Vehicle Security domain, truncate HMAC-SHA256 to 16 bytes (mimicking C++ Peer::ConstructRequestHash)
        const tag_length = if (auth_type == .hmac_personalized and domain == .vehicle_security)
            @min(@as(usize, 16), auth_tag.len)
        else
            auth_tag.len;

        @memcpy(request_hash_out[1 .. 1 + tag_length], auth_tag[0..tag_length]);
        return tag_length + 1;
    }

    /// High-level method to encrypt an outgoing command payload.
    /// Returns the length of the ciphertext.
    pub fn encryptCommand(
        self: *Session,
        random: std.Random,
        plaintext: []const u8,
        expires_at: u32,
        flags: u32,
        ciphertext_out: []u8,
        tag_out: *[16]u8,
        nonce_out: *[12]u8,
    ) !usize {
        if (!self.is_valid) return error.SessionNotInitialized;
        if (ciphertext_out.len < plaintext.len) return error.BufferTooSmall;

        // 1. Generate random nonce
        random.bytes(nonce_out);

        // 2. Construct AD buffer
        var ad_buffer: [256]u8 = undefined;
        const ad_len = try self.constructAdBuffer(
            .aes_gcm_personalized,
            expires_at,
            flags,
            null,
            0,
            &ad_buffer,
        );

        // 3. Compute AD hash (SHA256)
        const ad_hash = crypto.computeAdHash(ad_buffer[0..ad_len]);

        // 4. Encrypt with AES-128-GCM using the 16-byte shared secret
        crypto.aesGcmEncrypt(
            self.shared_secret,
            nonce_out.*,
            ad_hash,
            plaintext,
            ciphertext_out,
            tag_out,
        );

        return plaintext.len;
    }

    /// High-level method to decrypt an incoming vehicle response payload.
    /// Returns the length of the plaintext.
    pub fn decryptResponse(
        self: *Session,
        ciphertext: []const u8,
        tag: [16]u8,
        nonce: [12]u8,
        request_hash: []const u8,
        flags: u32,
        fault: u32,
        plaintext_out: []u8,
    ) !usize {
        if (!self.is_valid) return error.SessionNotInitialized;
        if (plaintext_out.len < ciphertext.len) return error.BufferTooSmall;

        // 1. Construct AD buffer for response
        var ad_buffer: [256]u8 = undefined;
        const ad_len = try self.constructAdBuffer(
            .aes_gcm_response,
            0, // expires_at is not used for responses
            flags,
            request_hash,
            fault,
            &ad_buffer,
        );

        // 2. Compute AD hash (SHA256)
        const ad_hash = crypto.computeAdHash(ad_buffer[0..ad_len]);

        // 3. Decrypt with AES-128-GCM using the 16-byte shared secret
        try crypto.aesGcmDecrypt(
            self.shared_secret,
            nonce,
            ad_hash,
            ciphertext,
            tag,
            plaintext_out[0..ciphertext.len],
        );

        return ciphertext.len;
    }

    /// Validate the response counter for anti-replay tracking.
    pub fn validateResponseCounter(self: *Session, counter: u32, request_id: u32) bool {
        return self.seen_counters.validateAndAdd(request_id, counter);
    }
};

test "SeenCounterCache behavior" {
    var cache = SeenCounterCache.init();
    try std.testing.expect(cache.validateAndAdd(12345, 1));
    try std.testing.expect(!cache.validateAndAdd(12345, 1)); // Duplicate
    try std.testing.expect(cache.validateAndAdd(12345, 2)); // Diff counter
    try std.testing.expect(cache.validateAndAdd(54321, 1)); // Diff request

    // Fill up cache to trigger evictions
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        _ = cache.validateAndAdd(999, i);
    }
    // Now counter 1 for 12345 should have been evicted and can be re-entered
    try std.testing.expect(cache.validateAndAdd(12345, 1));
}

test "Session AD and Cryptographic pipeline" {
    // Generate a mock handshake
    const kp_ours = try crypto.KeyPair.fromBytes([_]u8{5} ** 32);
    const kp_theirs = try crypto.KeyPair.fromBytes([_]u8{10} ** 32);

    const vin = "5YJ3E1EBXLF000000";
    var sess = try Session.init(.vehicle_security, vin);

    try std.testing.expectEqualSlices(u8, vin, sess.getVin());

    // Update with mock handshake (epoch, counter, clock_time, generated_at)
    const mock_epoch = [_]u8{42} ** 16;
    try sess.updateSession(
        mock_epoch,
        1,
        1000,
        2000,
        kp_theirs.public_key,
        kp_ours.private_key,
    );

    try std.testing.expect(sess.is_valid);
    try std.testing.expectEqualSlices(u8, &mock_epoch, &sess.epoch);
    try std.testing.expectEqual(sess.counter, 1);

    // Test expires_at generator
    const exp = sess.generateExpiresAt(2005, 5); // 2005 + 5 - (2000 - 1000) = 1010
    try std.testing.expectEqual(@as(u32, 1010), exp);

    // Test encryption and decryption loop
    const plaintext = "Unlocking the model 3 via Zig bare metal!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    var nonce: [12]u8 = undefined;

    // Standard fast PRNG for tests
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    const random = prng.random();

    const cipher_len = try sess.encryptCommand(
        random,
        plaintext,
        exp,
        0,
        &ciphertext,
        &tag,
        &nonce,
    );
    try std.testing.expectEqual(plaintext.len, cipher_len);

    // 1. Decrypt command (representing vehicle side decrypting client command)
    {
        var cmd_decrypted: [plaintext.len]u8 = undefined;
        var cmd_ad_buffer: [256]u8 = undefined;
        const cmd_ad_len = try sess.constructAdBuffer(
            .aes_gcm_personalized,
            exp,
            0,
            null,
            0,
            &cmd_ad_buffer,
        );
        const cmd_ad_hash = crypto.computeAdHash(cmd_ad_buffer[0..cmd_ad_len]);
        try crypto.aesGcmDecrypt(
            sess.shared_secret,
            nonce,
            cmd_ad_hash,
            &ciphertext,
            tag,
            &cmd_decrypted,
        );
        try std.testing.expectEqualSlices(u8, plaintext, &cmd_decrypted);
    }

    // 2. Encrypt and decrypt a Response (representing vehicle sending a response and client decrypting it)
    {
        const response_plaintext = "Vehicle unlocked successfully!";
        var resp_ciphertext: [response_plaintext.len]u8 = undefined;
        var resp_tag: [16]u8 = undefined;
        var resp_nonce: [12]u8 = undefined;

        // Generate response nonce
        random.bytes(&resp_nonce);

        // Construct request hash from the request command tag
        var req_hash: [32]u8 = undefined;
        const req_hash_len = try Session.constructRequestHash(
            .aes_gcm_personalized,
            &tag,
            sess.domain,
            &req_hash,
        );

        // Build AD buffer for response (on vehicle side)
        var resp_ad_buffer: [256]u8 = undefined;
        const resp_ad_len = try sess.constructAdBuffer(
            .aes_gcm_response,
            0, // expires_at not used for responses
            0, // flags
            req_hash[0..req_hash_len],
            0, // fault
            &resp_ad_buffer,
        );
        const resp_ad_hash = crypto.computeAdHash(resp_ad_buffer[0..resp_ad_len]);

        // Encrypt the response on the vehicle side
        crypto.aesGcmEncrypt(
            sess.shared_secret,
            resp_nonce,
            resp_ad_hash,
            response_plaintext,
            &resp_ciphertext,
            &resp_tag,
        );

        // Client side decrypts the response
        var resp_decrypted: [response_plaintext.len]u8 = undefined;
        const resp_dec_len = try sess.decryptResponse(
            &resp_ciphertext,
            resp_tag,
            resp_nonce,
            req_hash[0..req_hash_len],
            0,
            0,
            &resp_decrypted,
        );

        try std.testing.expectEqual(response_plaintext.len, resp_dec_len);
        try std.testing.expectEqualSlices(u8, response_plaintext, &resp_decrypted);
    }
}
