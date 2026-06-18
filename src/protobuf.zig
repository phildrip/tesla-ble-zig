//! Bare-metal safe, non-allocating, zero-dependency Protobuf serialization library for Tesla BLE.
const std = @import("std");
const protocol = @import("protocol.zig");

pub const Writer = struct {
    buffer: []u8,
    pos: usize,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer, .pos = 0 };
    }

    pub fn writeByte(self: *Writer, b: u8) !void {
        if (self.pos >= self.buffer.len) return error.BufferTooSmall;
        self.buffer[self.pos] = b;
        self.pos += 1;
    }

    pub fn writeBytes(self: *Writer, bytes: []const u8) !void {
        if (self.pos + bytes.len > self.buffer.len) return error.BufferTooSmall;
        @memcpy(self.buffer[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn writeVarint(self: *Writer, value: u64) !void {
        var val = value;
        while (val >= 0x80) {
            try self.writeByte(@intCast((val & 0x7F) | 0x80));
            val >>= 7;
        }
        try self.writeByte(@intCast(val));
    }

    pub fn writeTag(self: *Writer, field_number: u32, wire_type: u32) !void {
        try self.writeVarint((field_number << 3) | wire_type);
    }

    pub fn writeLengthDelimited(self: *Writer, field_number: u32, data: []const u8) !void {
        try self.writeTag(field_number, 2);
        try self.writeVarint(data.len);
        try self.writeBytes(data);
    }

    pub fn writeUint32(self: *Writer, field_number: u32, value: u32) !void {
        try self.writeTag(field_number, 0);
        try self.writeVarint(value);
    }

    pub fn writeFixed32(self: *Writer, field_number: u32, value: u32) !void {
        try self.writeTag(field_number, 5);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }
};

pub const Reader = struct {
    buffer: []const u8,
    pos: usize,

    pub fn init(buffer: []const u8) Reader {
        return .{ .buffer = buffer, .pos = 0 };
    }

    pub fn hasMore(self: Reader) bool {
        return self.pos < self.buffer.len;
    }

    pub fn readByte(self: *Reader) !u8 {
        if (self.pos >= self.buffer.len) return error.EndOfStream;
        const b = self.buffer[self.pos];
        self.pos += 1;
        return b;
    }

    pub fn readBytes(self: *Reader, len_u64: u64) ![]const u8 {
        const len = std.math.cast(usize, len_u64) orelse return error.EndOfStream;
        if (self.pos + len > self.buffer.len) return error.EndOfStream;
        const slice = self.buffer[self.pos .. self.pos + len];
        self.pos += len;
        return slice;
    }

    pub fn readVarint(self: *Reader) !u64 {
        var value: u64 = 0;
        var shift: u8 = 0;
        while (true) {
            const b = try self.readByte();
            value |= @as(u64, b & 0x7F) << @intCast(shift);
            if (b & 0x80 == 0) break;
            shift += 7;
            if (shift >= 64) return error.MalformedVarint;
        }
        return value;
    }

    pub fn readTag(self: *Reader) !struct { field_number: u32, wire_type: u32 } {
        const tag = try self.readVarint();
        return .{
            .field_number = @intCast(tag >> 3),
            .wire_type = @intCast(tag & 0x07),
        };
    }

    pub fn skipValue(self: *Reader, wire_type: u32) !void {
        switch (wire_type) {
            0 => {
                _ = try self.readVarint();
            },
            1 => {
                _ = try self.readBytes(8);
            },
            2 => {
                const len = try self.readVarint();
                _ = try self.readBytes(len);
            },
            5 => {
                _ = try self.readBytes(4);
            },
            else => return error.UnsupportedWireType,
        }
    }
};

pub const Destination = struct {
    pub fn encodeDomain(domain: protocol.Domain, field_number: u32, outer: *Writer) !void {
        var temp_buf: [32]u8 = undefined;
        var inner = Writer.init(&temp_buf);
        // Domain domain = 1;
        try inner.writeUint32(1, @intFromEnum(domain));
        try outer.writeLengthDelimited(field_number, inner.buffer[0..inner.pos]);
    }

    pub fn encodeRoutingAddress(address: []const u8, field_number: u32, outer: *Writer) !void {
        var temp_buf: [32]u8 = undefined;
        var inner = Writer.init(&temp_buf);
        // bytes routing_address = 2;
        try inner.writeLengthDelimited(2, address);
        try outer.writeLengthDelimited(field_number, inner.buffer[0..inner.pos]);
    }
};

pub const SessionInfoRequest = struct {
    pub fn encode(public_key: []const u8, field_number: u32, outer: *Writer) !void {
        var temp_buf: [128]u8 = undefined;
        var inner = Writer.init(&temp_buf);
        // bytes public_key = 1;
        try inner.writeLengthDelimited(1, public_key);
        try outer.writeLengthDelimited(field_number, inner.buffer[0..inner.pos]);
    }
};

pub const SignatureData = struct {
    pub fn encodeAesGcmPersonalized(
        public_key: []const u8,
        epoch: []const u8,
        nonce: [12]u8,
        counter: u32,
        expires_at: u32,
        tag: [16]u8,
        field_number: u32,
        outer: *Writer,
    ) !void {
        var temp_buf: [256]u8 = undefined;
        var inner = Writer.init(&temp_buf);

        // 1. Signer Identity (field 1)
        {
            var identity_buf: [128]u8 = undefined;
            var identity_inner = Writer.init(&identity_buf);
            // bytes public_key = 1;
            try identity_inner.writeLengthDelimited(1, public_key);
            try inner.writeLengthDelimited(1, identity_inner.buffer[0..identity_inner.pos]);
        }

        // 2. AES_GCM_Personalized_data (field 5)
        {
            var aes_buf: [128]u8 = undefined;
            var aes_inner = Writer.init(&aes_buf);
            // bytes epoch = 1;
            try aes_inner.writeLengthDelimited(1, epoch);
            // bytes nonce = 2;
            try aes_inner.writeLengthDelimited(2, &nonce);
            // uint32 counter = 3;
            try aes_inner.writeUint32(3, counter);
            // fixed32 expires_at = 4;
            try aes_inner.writeFixed32(4, expires_at);
            // bytes tag = 5;
            try aes_inner.writeLengthDelimited(5, &tag);

            try inner.writeLengthDelimited(5, aes_inner.buffer[0..aes_inner.pos]);
        }

        try outer.writeLengthDelimited(field_number, inner.buffer[0..inner.pos]);
    }
};

pub const SessionInfo = struct {
    counter: u32 = 0,
    public_key: [65]u8 = [_]u8{0} ** 65,
    public_key_len: usize = 0,
    epoch: [16]u8 = [_]u8{0} ** 16,
    epoch_len: usize = 0,
    clock_time: u32 = 0,
    status: u32 = 0,
    handle: u32 = 0,

    pub fn decode(buffer: []const u8) !SessionInfo {
        var reader = Reader.init(buffer);
        var self = SessionInfo{};

        while (reader.hasMore()) {
            const tag = try reader.readTag();
            switch (tag.field_number) {
                1 => {
                    self.counter = @intCast(try reader.readVarint());
                },
                2 => {
                    const len = try reader.readVarint();
                    const bytes = try reader.readBytes(len);
                    if (bytes.len > 65) return error.PublicKeyTooLong;
                    @memcpy(self.public_key[0..bytes.len], bytes);
                    self.public_key_len = bytes.len;
                },
                3 => {
                    if (tag.wire_type == 2) {
                        const len = try reader.readVarint();
                        const bytes = try reader.readBytes(len);
                        if (bytes.len > 16) return error.EpochTooLong;
                        @memcpy(self.epoch[0..bytes.len], bytes);
                        self.epoch_len = bytes.len;
                    } else if (tag.wire_type == 0) {
                        const val = try reader.readVarint();
                        var temp: [10]u8 = undefined;
                        var idx: usize = 0;
                        var temp_val = val;
                        while (temp_val >= 0x80) {
                            temp[idx] = @intCast((temp_val & 0x7F) | 0x80);
                            temp_val >>= 7;
                            idx += 1;
                        }
                        temp[idx] = @intCast(temp_val);
                        idx += 1;
                        const bytes = temp[0..idx];
                        if (bytes.len > 16) return error.EpochTooLong;
                        @memcpy(self.epoch[0..bytes.len], bytes);
                        self.epoch_len = bytes.len;
                    } else {
                        try reader.skipValue(tag.wire_type);
                    }
                },
                4 => {
                    if (tag.wire_type == 5) {
                        const bytes = try reader.readBytes(4);
                        self.clock_time = std.mem.readInt(u32, bytes[0..4], .little);
                    } else if (tag.wire_type == 0) {
                        self.clock_time = @intCast(try reader.readVarint());
                    } else if (tag.wire_type == 2) {
                        const len = try reader.readVarint();
                        const bytes = try reader.readBytes(len);
                        var val: u32 = 0;
                        if (bytes.len > 0) {
                            if (bytes.len == 4) {
                                val = std.mem.readInt(u32, bytes[0..4], .little);
                            } else {
                                var shift: u5 = 0;
                                for (bytes) |b| {
                                    val |= @as(u32, b) << shift;
                                    shift +%= 8;
                                }
                            }
                        }
                        self.clock_time = val;
                    } else {
                        try reader.skipValue(tag.wire_type);
                    }
                },
                5 => {
                    self.status = @intCast(try reader.readVarint());
                },
                6 => {
                    self.handle = @intCast(try reader.readVarint());
                },
                else => {
                    try reader.skipValue(tag.wire_type);
                },
            }
        }
        return self;
    }
};

pub const AesGcmResponseSignatureData = struct {
    nonce: [12]u8 = [_]u8{0} ** 12,
    counter: u32 = 0,
    tag: [16]u8 = [_]u8{0} ** 16,

    pub fn decode(buffer: []const u8) !AesGcmResponseSignatureData {
        var reader = Reader.init(buffer);
        var self = AesGcmResponseSignatureData{};

        while (reader.hasMore()) {
            const tag = try reader.readTag();
            switch (tag.field_number) {
                1 => {
                    const len = try reader.readVarint();
                    const bytes = try reader.readBytes(len);
                    if (bytes.len != 12) return error.InvalidNonceLength;
                    @memcpy(&self.nonce, bytes);
                },
                2 => {
                    self.counter = @intCast(try reader.readVarint());
                },
                3 => {
                    const len = try reader.readVarint();
                    const bytes = try reader.readBytes(len);
                    if (bytes.len != 16) return error.InvalidTagLength;
                    @memcpy(&self.tag, bytes);
                },
                else => {
                    try reader.skipValue(tag.wire_type);
                },
            }
        }
        return self;
    }
};

pub const DecodedRoutableMessage = struct {
    to_destination_domain: ?protocol.Domain = null,
    from_destination_routing_address: [16]u8 = [_]u8{0} ** 16,
    from_destination_routing_address_len: usize = 0,
    protobuf_message_as_bytes: ?[]const u8 = null,
    session_info: ?[]const u8 = null,
    signed_message_fault: u32 = 0,
    flags: u32 = 0,
    uuid: [16]u8 = [_]u8{0} ** 16,
    uuid_len: usize = 0,
    aes_gcm_response_sig: ?AesGcmResponseSignatureData = null,

    pub fn decode(buffer: []const u8) !DecodedRoutableMessage {
        var reader = Reader.init(buffer);
        var self = DecodedRoutableMessage{};

        while (reader.hasMore()) {
            const tag = try reader.readTag();
            switch (tag.field_number) {
                6 => { // to_destination (Destination)
                    const len = try reader.readVarint();
                    const bytes = try reader.readBytes(len);
                    var inner = Reader.init(bytes);
                    if (inner.hasMore()) {
                        const inner_tag = try inner.readTag();
                        if (inner_tag.field_number == 1) { // domain enum
                            self.to_destination_domain = @enumFromInt(try inner.readVarint());
                        }
                    }
                },
                7 => { // from_destination (Destination)
                    const len = try reader.readVarint();
                    const bytes = try reader.readBytes(len);
                    var inner = Reader.init(bytes);
                    if (inner.hasMore()) {
                        const inner_tag = try inner.readTag();
                        if (inner_tag.field_number == 2) { // routing_address bytes
                            const addr_len = try inner.readVarint();
                            const addr_bytes = try inner.readBytes(addr_len);
                            if (addr_bytes.len > 16) return error.RoutingAddressTooLong;
                            @memcpy(self.from_destination_routing_address[0..addr_bytes.len], addr_bytes);
                            self.from_destination_routing_address_len = addr_bytes.len;
                        }
                    }
                },
                10 => { // protobuf_message_as_bytes (payload bytes)
                    const len = try reader.readVarint();
                    self.protobuf_message_as_bytes = try reader.readBytes(len);
                },
                3, 15 => { // session_info (payload bytes in some vehicle protocol versions)
                    const len = try reader.readVarint();
                    self.session_info = try reader.readBytes(len);
                },
                12 => { // signedMessageStatus (MessageStatus)
                    const len = try reader.readVarint();
                    const bytes = try reader.readBytes(len);
                    var inner = Reader.init(bytes);
                    while (inner.hasMore()) {
                        const inner_tag = try inner.readTag();
                        if (inner_tag.field_number == 2) { // signed_message_fault (MessageFault_E)
                            self.signed_message_fault = @intCast(try inner.readVarint());
                        } else {
                            try inner.skipValue(inner_tag.wire_type);
                        }
                    }
                },
                13 => { // signature_data (SignatureData)
                    const len = try reader.readVarint();
                    const bytes = try reader.readBytes(len);
                    var inner = Reader.init(bytes);
                    while (inner.hasMore()) {
                        const inner_tag = try inner.readTag();
                        if (inner_tag.field_number == 9) { // AES_GCM_Response_data
                            const sig_len = try inner.readVarint();
                            const sig_bytes = try inner.readBytes(sig_len);
                            self.aes_gcm_response_sig = try AesGcmResponseSignatureData.decode(sig_bytes);
                        } else {
                            try inner.skipValue(inner_tag.wire_type);
                        }
                    }
                },
                51 => { // uuid (bytes)
                    const len = try reader.readVarint();
                    const bytes = try reader.readBytes(len);
                    if (bytes.len > 16) return error.UuidTooLong;
                    @memcpy(self.uuid[0..bytes.len], bytes);
                    self.uuid_len = bytes.len;
                },
                52 => { // flags
                    self.flags = @intCast(try reader.readVarint());
                },
                else => {
                    try reader.skipValue(tag.wire_type);
                },
            }
        }
        return self;
    }
};

pub const UnsignedMessage = struct {
    pub fn encodeRkeAction(action: u32, outer: *Writer) !void {
        // Message is UnsignedMessage, field 2 is RKEAction (enum)
        try outer.writeUint32(2, action);
    }

    pub fn encodeClosureMoveRequest(rear_trunk_action: u32, front_trunk_action: u32, outer: *Writer) !void {
        var temp_buf: [64]u8 = undefined;
        var inner = Writer.init(&temp_buf);
        if (rear_trunk_action != 0) {
            try inner.writeUint32(5, rear_trunk_action);
        }
        if (front_trunk_action != 0) {
            try inner.writeUint32(6, front_trunk_action);
        }
        // UnsignedMessage field 4 is closureMoveRequest
        try outer.writeLengthDelimited(4, inner.buffer[0..inner.pos]);
    }
};

test "Protobuf writing and reading pipeline" {
    var buffer: [512]u8 = undefined;
    var writer = Writer.init(&buffer);

    // Write a mock SessionInfoRequest inside RoutableMessage
    // 1. to_destination
    try Destination.encodeDomain(.infotainment, 6, &writer);

    // 2. from_destination
    const mock_conn_id = [_]u8{0xaa} ** 16;
    try Destination.encodeRoutingAddress(&mock_conn_id, 7, &writer);

    // 3. session_info_request (field 14)
    const mock_pub_key = [_]u8{0x04} ++ ([_]u8{0xee} ** 64);
    try SessionInfoRequest.encode(&mock_pub_key, 14, &writer);

    // 4. uuid (field 51)
    const mock_uuid = [_]u8{7} ** 16;
    try writer.writeLengthDelimited(51, &mock_uuid);

    // 5. flags (field 52)
    try writer.writeUint32(52, 2);

    const serialized_len = writer.pos;
    try std.testing.expect(serialized_len > 0);

    // Let's decode and verify using DecodedRoutableMessage
    const decoded = try DecodedRoutableMessage.decode(buffer[0..serialized_len]);
    try std.testing.expectEqual(protocol.Domain.infotainment, decoded.to_destination_domain.?);
    try std.testing.expectEqual(mock_conn_id.len, decoded.from_destination_routing_address_len);
    try std.testing.expectEqualSlices(u8, &mock_conn_id, decoded.from_destination_routing_address[0..decoded.from_destination_routing_address_len]);
    try std.testing.expectEqualSlices(u8, &mock_uuid, decoded.uuid[0..decoded.uuid_len]);
    try std.testing.expectEqual(@as(u32, 2), decoded.flags);
}

test "UnsignedMessage Serialization" {
    var buffer: [128]u8 = undefined;

    // Test RKE Action Lock serialization
    {
        var writer = Writer.init(&buffer);
        try UnsignedMessage.encodeRkeAction(1, &writer);
        const written = buffer[0..writer.pos];
        // Expect tag 2 (field_number=2, wire_type=0) -> (2<<3)|0 = 16 (0x10)
        // Expect value 1 -> 1
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x10, 0x01 }, written);
    }

    // Test Closure Move Request (rear trunk = 1, front trunk = 1)
    {
        var writer = Writer.init(&buffer);
        try UnsignedMessage.encodeClosureMoveRequest(1, 1, &writer);
        const written = buffer[0..writer.pos];
        // Expect tag 4 (field_number=4, wire_type=2) -> (4<<3)|2 = 34 (0x22)
        // Inside length-delimited sub-message:
        // rearTrunk (field 5, wire_type 0) -> (5<<3)|0 = 40 (0x28) with value 1
        // frontTrunk (field 6, wire_type 0) -> (6<<3)|0 = 48 (0x30) with value 1
        // Length of sub-message = 4 bytes: [0x28, 0x01, 0x30, 0x01]
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x22, 0x04, 0x28, 0x01, 0x30, 0x01 }, written);
    }
}

test "Vehicle SessionInfo Response decoding" {
    // 31-byte payload: 1a 1d 12 16 0a 14 d6 4c a5 77 03 55 b2 a2 34 8c 58 8f 19 69 d3 62 38 bc 02 5f 18 02 22 01 01
    const raw_payload = [_]u8{
        0x1a, 0x1d, 0x12, 0x16, 0x0a, 0x14, 0xd6, 0x4c, 0xa5, 0x77,
        0x03, 0x55, 0xb2, 0xa2, 0x34, 0x8c, 0x58, 0x8f, 0x19, 0x69,
        0xd3, 0x62, 0x38, 0xbc, 0x02, 0x5f, 0x18, 0x02, 0x22, 0x01,
        0x01,
    };

    // First, let's decode it as DecodedRoutableMessage.
    // It should contain session_info on Field 3.
    const decoded = try DecodedRoutableMessage.decode(&raw_payload);
    try std.testing.expect(decoded.session_info != null);

    const si_bytes = decoded.session_info.?;
    try std.testing.expectEqual(@as(usize, 29), si_bytes.len);

    // Let's decode the inner SessionInfo
    const info = try SessionInfo.decode(si_bytes);
    
    // Let's print the decoded fields for debugging
    std.debug.print("Decoded SessionInfo status: {d}\n", .{info.status});
    std.debug.print("Decoded SessionInfo public_key_len: {d}\n", .{info.public_key_len});
    std.debug.print("Decoded SessionInfo counter: {d}\n", .{info.counter});
}

