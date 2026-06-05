//! Statically-allocated, memory-safe Zig Client implementation for Tesla BLE control.
const std = @import("std");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");
const session = @import("session.zig");
const protobuf = @import("protobuf.zig");

pub const Client = struct {
    key_pair: crypto.KeyPair,
    connection_id: [16]u8,
    session_vcsec: session.Session,
    session_infotainment: session.Session,
    last_request_hash: [17]u8,
    last_request_hash_len: usize,

    /// Create a new Tesla BLE Client with a specified VIN and connection ID.
    /// If private_key_bytes is provided, loads the existing identity.
    /// Otherwise, initializes a default test/placeholder identity.
    pub fn init(vin: []const u8, private_key_bytes: ?[32]u8, connection_id: [16]u8) !Client {
        const key_pair = if (private_key_bytes) |bytes|
            try crypto.KeyPair.fromBytes(bytes)
        else
            try crypto.KeyPair.fromBytes([_]u8{1} ** 32); // Fallback standard identity

        return Client{
            .key_pair = key_pair,
            .connection_id = connection_id,
            .session_vcsec = try session.Session.init(.vehicle_security, vin),
            .session_infotainment = try session.Session.init(.infotainment, vin),
            .last_request_hash = [_]u8{0} ** 17,
            .last_request_hash_len = 0,
        };
    }

    /// Retrieve the correct Session Peer based on the target message domain.
    pub fn getPeer(self: *Client, domain: protocol.Domain) ?*session.Session {
        return switch (domain) {
            .vehicle_security => &self.session_vcsec,
            .infotainment => &self.session_infotainment,
            else => null,
        };
    }

    /// Update VIN identifier across both secure domains.
    pub fn setVin(self: *Client, vin: []const u8) !void {
        self.session_vcsec = try session.Session.init(.vehicle_security, vin);
        self.session_infotainment = try session.Session.init(.infotainment, vin);
    }

    /// Helper to prefix the 2-byte big-endian length prefix onto the BLE packet.
    pub fn insertLength(payload_len: usize, buffer: []u8) !usize {
        if (buffer.len < payload_len + 2) return error.BufferTooSmall;
        buffer[0] = @intCast((payload_len >> 8) & 0xFF);
        buffer[1] = @intCast(payload_len & 0xFF);
        return payload_len + 2;
    }

    /// Build a Session Info Request (handshake request) packet ready for BLE transmission.
    pub fn buildSessionInfoRequestMessage(
        self: *Client,
        random: std.Random,
        domain: protocol.Domain,
        output: []u8,
    ) !usize {
        if (output.len < 10) return error.BufferTooSmall;

        var writer = protobuf.Writer.init(output[2..]);

        // 1. to_destination (field 6)
        try protobuf.Destination.encodeDomain(domain, 6, &writer);

        // 2. from_destination (field 7)
        try protobuf.Destination.encodeRoutingAddress(&self.connection_id, 7, &writer);

        // 3. session_info_request (field 14)
        try protobuf.SessionInfoRequest.encode(&self.key_pair.public_key, 14, &writer);

        // 4. uuid (field 51)
        var uuid: [16]u8 = undefined;
        random.bytes(&uuid);
        try writer.writeLengthDelimited(51, &uuid);

        // 5. flags (field 52) - requests encrypted response (1 << FLAG_ENCRYPT_RESPONSE) = 2
        try writer.writeUint32(52, 2);

        const payload_len = writer.pos;
        return try insertLength(payload_len, output);
    }

    /// Build a signed and encrypted vehicle security action payload (such as Lock, Unlock, or Wake).
    pub fn buildRkeActionMessage(
        self: *Client,
        random: std.Random,
        current_timestamp: u32,
        action: u32,
        output: []u8,
    ) !usize {
        var payload_buf: [32]u8 = undefined;
        var writer = protobuf.Writer.init(&payload_buf);
        try protobuf.UnsignedMessage.encodeRkeAction(action, &writer);
        const payload_slice = payload_buf[0..writer.pos];

        return try self.buildUniversalMessageWithPayload(
            random,
            current_timestamp,
            payload_slice,
            .vehicle_security,
            true,
            output,
        );
    }

    /// Build a signed and encrypted closure move request payload (such as trunk or frunk).
    pub fn buildClosureMoveRequestMessage(
        self: *Client,
        random: std.Random,
        current_timestamp: u32,
        rear_trunk_action: u32,
        front_trunk_action: u32,
        output: []u8,
    ) !usize {
        var payload_buf: [64]u8 = undefined;
        var writer = protobuf.Writer.init(&payload_buf);
        try protobuf.UnsignedMessage.encodeClosureMoveRequest(rear_trunk_action, front_trunk_action, &writer);
        const payload_slice = payload_buf[0..writer.pos];

        return try self.buildUniversalMessageWithPayload(
            random,
            current_timestamp,
            payload_slice,
            .vehicle_security,
            true,
            output,
        );
    }

    /// Build a completely framed, signed, and encrypted/unsigned universal command payload.
    pub fn buildUniversalMessageWithPayload(
        self: *Client,
        random: std.Random,
        current_timestamp: u32,
        payload: []const u8,
        domain: protocol.Domain,
        encrypt_payload: bool,
        output: []u8,
    ) !usize {
        if (output.len < payload.len + 32) return error.BufferTooSmall;

        var writer = protobuf.Writer.init(output[2..]);

        // 1. to_destination (field 6)
        try protobuf.Destination.encodeDomain(domain, 6, &writer);

        // 2. from_destination (field 7)
        try protobuf.Destination.encodeRoutingAddress(&self.connection_id, 7, &writer);

        // 3. flags (field 52)
        const flags: u32 = 2; // FLAG_ENCRYPT_RESPONSE
        try writer.writeUint32(52, flags);

        // 4. uuid (field 51)
        var uuid: [16]u8 = undefined;
        random.bytes(&uuid);
        try writer.writeLengthDelimited(51, &uuid);

        const active_sess = self.getPeer(domain) orelse return error.InvalidDomain;

        if (encrypt_payload) {
            if (!active_sess.is_valid) return error.SessionNotInitialized;

            // Secure session increment
            active_sess.incrementCounter();

            // Handshake expiration bounds
            const expires_at = active_sess.generateExpiresAt(current_timestamp, 5);

            var ciphertext_buf: [256]u8 = undefined;
            if (payload.len > ciphertext_buf.len) return error.PayloadTooLarge;

            var tag: [16]u8 = undefined;
            var nonce: [12]u8 = undefined;

            const ciphertext_len = try active_sess.encryptCommand(
                random,
                payload,
                expires_at,
                flags,
                ciphertext_buf[0..payload.len],
                &tag,
                &nonce,
            );

            // Write ciphertext (field 10)
            try writer.writeLengthDelimited(10, ciphertext_buf[0..ciphertext_len]);

            // Write cryptographic signature data (field 13)
            try protobuf.SignatureData.encodeAesGcmPersonalized(
                &self.key_pair.public_key,
                &active_sess.epoch,
                nonce,
                active_sess.counter,
                expires_at,
                tag,
                13,
                &writer,
            );

            // Construct and cache request hash context
            var req_hash_buf: [17]u8 = undefined;
            const req_hash_len = try session.Session.constructRequestHash(
                .aes_gcm_personalized,
                &tag,
                domain,
                &req_hash_buf,
            );
            @memcpy(self.last_request_hash[0..req_hash_len], req_hash_buf[0..req_hash_len]);
            self.last_request_hash_len = req_hash_len;
        } else {
            // Write plaintext payload (field 10)
            try writer.writeLengthDelimited(10, payload);
        }

        const payload_len = writer.pos;
        return try insertLength(payload_len, output);
    }

    /// Process received handshake payload and update local session secret vectors.
    pub fn handleSessionInfoResponse(
        self: *Client,
        domain: protocol.Domain,
        current_timestamp: u32,
        session_info_bytes: []const u8,
    ) !void {
        const active_sess = self.getPeer(domain) orelse return error.InvalidDomain;
        const info = try protobuf.SessionInfo.decode(session_info_bytes);

        if (info.status != 0) return error.KeyNotOnWhitelist;

        try active_sess.updateSession(
            info.epoch,
            info.counter,
            info.clock_time,
            current_timestamp,
            info.public_key,
            self.key_pair.private_key,
        );
    }

    /// Decrypt an incoming vehicle response BLE payload using current cached session states.
    pub fn decryptResponse(
        self: *Client,
        domain: protocol.Domain,
        decoded_msg: protobuf.DecodedRoutableMessage,
        plaintext_out: []u8,
    ) !usize {
        const active_sess = self.getPeer(domain) orelse return error.InvalidDomain;

        const sig = decoded_msg.aes_gcm_response_sig orelse return error.MissingSignatureData;
        const ciphertext = decoded_msg.protobuf_message_as_bytes orelse return error.MissingPayload;

        // Extract a 32-bit request identifier out of the message's UUID to validate connection sequence
        const request_id = std.mem.readInt(u32, decoded_msg.uuid[0..4], .big);
        if (!active_sess.validateResponseCounter(sig.counter, request_id)) {
            return error.ReplayDetected;
        }

        return try active_sess.decryptResponse(
            ciphertext,
            sig.tag,
            sig.nonce,
            self.last_request_hash[0..self.last_request_hash_len],
            decoded_msg.flags,
            decoded_msg.signed_message_fault,
            plaintext_out,
        );
    }
};

test "Complete Client Handshake and Encrypted Communication Loop" {
    const vin = "5YJ3E1EBXLF000000";
    const conn_id = [_]u8{0x77} ** 16;
    var client = try Client.init(vin, [_]u8{3} ** 32, conn_id);

    var prng = std.Random.DefaultPrng.init(0xbadface);
    const random = prng.random();

    var buffer: [512]u8 = undefined;

    // 1. Build a session info request message
    const req_len = try client.buildSessionInfoRequestMessage(random, .vehicle_security, &buffer);
    try std.testing.expect(req_len > 2);
    try std.testing.expectEqual(buffer[0], @as(u8, @intCast((req_len - 2) >> 8)));
    try std.testing.expectEqual(buffer[1], @as(u8, @intCast((req_len - 2) & 0xFF)));

    // Decode the request as an verification of format
    const req_decoded = try protobuf.DecodedRoutableMessage.decode(buffer[2..req_len]);
    try std.testing.expectEqual(protocol.Domain.vehicle_security, req_decoded.to_destination_domain.?);
    try std.testing.expectEqualSlices(u8, &conn_id, req_decoded.from_destination_routing_address[0..16]);

    // 2. Simulate vehicle side: generate response handshake payload (SessionInfo)
    var vehicle_sess_info_buf: [128]u8 = undefined;
    var si_writer = protobuf.Writer.init(&vehicle_sess_info_buf);
    // counter = 1
    try si_writer.writeUint32(1, 1);
    // publicKey = vehicle public key (65 bytes)
    const kp_vehicle = try crypto.KeyPair.fromBytes([_]u8{4} ** 32);
    try si_writer.writeLengthDelimited(2, &kp_vehicle.public_key);
    // epoch = mock epoch (16 bytes)
    const mock_epoch = [_]u8{0xde} ** 16;
    try si_writer.writeLengthDelimited(3, &mock_epoch);
    // clock_time = 1000
    try si_writer.writeFixed32(4, 1000);
    // status = 0 (OK)
    try si_writer.writeUint32(5, 0);

    // Update client session with the handshake payload
    try client.handleSessionInfoResponse(.vehicle_security, 2000, vehicle_sess_info_buf[0..si_writer.pos]);
    try std.testing.expect(client.session_vcsec.is_valid);
    try std.testing.expectEqual(client.session_vcsec.counter, 1);

    // 3. Build an encrypted command payload
    const cmd_msg = "Honk lights and blink horn!";
    const cmd_len = try client.buildUniversalMessageWithPayload(
        random,
        2005,
        cmd_msg,
        .vehicle_security,
        true,
        &buffer,
    );
    try std.testing.expect(cmd_len > 2);

    // 4. Simulate response from the car
    const response_text = "Action successful!";
    var resp_buf: [256]u8 = undefined;
    var resp_len: usize = 0;
    {
        var resp_writer = protobuf.Writer.init(&resp_buf);
        
        // 1. to_destination
        try protobuf.Destination.encodeRoutingAddress(&conn_id, 6, &resp_writer);

        // 2. uuid (matching request's high 4 bytes)
        const mock_resp_uuid = [_]u8{0} ** 16;
        try resp_writer.writeLengthDelimited(51, &mock_resp_uuid);

        // 3. flags
        try resp_writer.writeUint32(52, 2);

        // 4. Encrypt response on the vehicle side
        var ciphertext_buf: [128]u8 = undefined;
        const mock_resp_nonce = [_]u8{0x99} ** 12;
        var resp_tag: [16]u8 = undefined;

        // AD compilation on vehicle side
        var ad_buffer: [128]u8 = undefined;
        const ad_len = try client.session_vcsec.constructAdBuffer(
            .aes_gcm_response,
            0,
            2,
            client.last_request_hash[0..client.last_request_hash_len],
            0,
            &ad_buffer,
        );
        const ad_hash = crypto.computeAdHash(ad_buffer[0..ad_len]);

        crypto.aesGcmEncrypt(
            client.session_vcsec.shared_secret,
            mock_resp_nonce,
            ad_hash,
            response_text,
            ciphertext_buf[0..response_text.len],
            &resp_tag,
        );

        // Write ciphertext
        try resp_writer.writeLengthDelimited(10, ciphertext_buf[0..response_text.len]);

        // Write AES_GCM_Response_data signature (field 13)
        var sig_buf: [128]u8 = undefined;
        var sig_writer = protobuf.Writer.init(&sig_buf);
        try sig_writer.writeLengthDelimited(1, &mock_resp_nonce);
        try sig_writer.writeUint32(2, 5); // counter = 5
        try sig_writer.writeLengthDelimited(3, &resp_tag);

        var inner_sig_buf: [160]u8 = undefined;
        var inner_sig_writer = protobuf.Writer.init(&inner_sig_buf);
        try inner_sig_writer.writeLengthDelimited(9, sig_buf[0..sig_writer.pos]);

        try resp_writer.writeLengthDelimited(13, inner_sig_buf[0..inner_sig_writer.pos]);
        resp_len = resp_writer.pos;
    }

    // Decrypt the response on the client side
    const decoded_resp = try protobuf.DecodedRoutableMessage.decode(resp_buf[0..resp_len]);
    var decrypted_plaintext: [128]u8 = undefined;
    const decrypted_len = try client.decryptResponse(
        .vehicle_security,
        decoded_resp,
        &decrypted_plaintext,
    );

    try std.testing.expectEqualSlices(u8, response_text, decrypted_plaintext[0..decrypted_len]);
}
