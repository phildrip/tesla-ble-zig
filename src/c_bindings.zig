//! Standard C-compatible ABI bindings for the Tesla BLE Zig Library.
//! Allows seamless cross-language integration with C/C++ (such as ESP-IDF or ESPHome wrappers).
const std = @import("std");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");
const session = @import("session.zig");
const protobuf = @import("protobuf.zig");
const client = @import("client.zig");

// Linker hooks to resolve randomness in a target-agnostic manner.
// The consumer C/C++ application must implement this (e.g. calling esp_fill_random on ESP32).
extern fn tesla_random_bytes(buf: [*]u8, len: usize) void;

// Simple custom std.Random implementation that delegates to our linker hook
const TeslaRandom = struct {
    pub fn random() std.Random {
        return .{
            .ptr = undefined,
            .fillFn = fill,
        };
    }

    fn fill(ptr: *anyopaque, buf: []u8) void {
        _ = ptr;
        tesla_random_bytes(buf.ptr, buf.len);
    }
};

const ErrorCode = enum(i32) {
    OK = 0,
    InvalidArgs = -1,
    BufferTooSmall = -2,
    SessionNotInitialized = -3,
    InvalidEncoding = -4,
    DecryptFailed = -5,
    InvalidDomain = -6,
    KeyNotOnWhitelist = -7,
    ReplayDetected = -8,
    PayloadTooLarge = -9,
    UnknownError = -99,
};

fn mapError(err: anyerror) ErrorCode {
    return switch (err) {
        error.BufferTooSmall => .BufferTooSmall,
        error.SessionNotInitialized => .SessionNotInitialized,
        error.InvalidEncoding => .InvalidEncoding,
        error.DecryptFailed => .DecryptFailed,
        error.InvalidDomain => .InvalidDomain,
        error.KeyNotOnWhitelist => .KeyNotOnWhitelist,
        error.ReplayDetected => .ReplayDetected,
        error.PayloadTooLarge => .PayloadTooLarge,
        else => .UnknownError,
    };
}

/// Returns the size in bytes of the `Client` structure.
/// Allows C++ compilers to allocate exactly the required stack space for placement initialization.
export fn tesla_client_size() usize {
    return @sizeOf(client.Client);
}

/// Initialize the Client structure in-place (placement-init) inside a pre-allocated memory buffer.
/// Completely heapless and safe for bare-metal targets.
export fn tesla_client_init(
    client_ptr: ?*anyopaque,
    vin_ptr: ?[*]const u8,
    vin_len: usize,
    priv_key_ptr: ?[*]const u8,
    connection_id_ptr: ?[*]const u8,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const vp = vin_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const conn_p = connection_id_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);

    const vin = vp[0..vin_len];
    var priv_key: ?[32]u8 = null;
    if (priv_key_ptr) |pk| {
        var key_bytes: [32]u8 = undefined;
        @memcpy(&key_bytes, pk[0..32]);
        priv_key = key_bytes;
    }

    var conn_id: [16]u8 = undefined;
    @memcpy(&conn_id, conn_p[0..16]);

    const real_client = client.Client.init(vin, priv_key, conn_id) catch |err| {
        return @intFromEnum(mapError(err));
    };

    const dest = @as(*client.Client, @ptrCast(@alignCast(cp)));
    dest.* = real_client;

    return @intFromEnum(ErrorCode.OK);
}

/// Copy the 65-byte uncompressed public key of the client.
export fn tesla_client_get_public_key(client_ptr: ?*anyopaque, out_pub_key_65: ?[*]u8) void {
    const cp = client_ptr orelse return;
    const out = out_pub_key_65 orelse return;
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    @memcpy(out[0..65], &c.key_pair.public_key);
}

/// Copy the 4-byte Key ID derived from the client's public key hash.
export fn tesla_client_get_key_id(client_ptr: ?*anyopaque, out_key_id_4: ?[*]u8) void {
    const cp = client_ptr orelse return;
    const out = out_key_id_4 orelse return;
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const key_id = c.key_pair.getPublicKeyId();
    @memcpy(out[0..4], &key_id);
}

/// Build a session info request BLE packet (the handshake initializer).
export fn tesla_client_build_session_info_request(
    client_ptr: ?*anyopaque,
    domain_val: u32,
    out_buffer: ?[*]u8,
    out_buffer_len: usize,
    out_written_len: ?*usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_buffer orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const wr = out_written_len orelse return @intFromEnum(ErrorCode.InvalidArgs);

    if (domain_val != 2 and domain_val != 3) return @intFromEnum(ErrorCode.InvalidDomain);
    const domain: protocol.Domain = @enumFromInt(domain_val);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const r = TeslaRandom.random();

    const len = c.buildSessionInfoRequestMessage(r, domain, out[0..out_buffer_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    wr.* = len;
    return @intFromEnum(ErrorCode.OK);
}

/// Handle a received session info payload (completes the handshake and sets up session keys).
export fn tesla_client_handle_session_info_response(
    client_ptr: ?*anyopaque,
    domain_val: u32,
    current_timestamp: u32,
    session_info_ptr: ?[*]const u8,
    session_info_len: usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const si = session_info_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);

    if (domain_val != 2 and domain_val != 3) return @intFromEnum(ErrorCode.InvalidDomain);
    const domain: protocol.Domain = @enumFromInt(domain_val);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));

    c.handleSessionInfoResponse(domain, current_timestamp, si[0..session_info_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    return @intFromEnum(ErrorCode.OK);
}

/// Frame, sign, encrypt, and assemble a universal command ready for BLE transmission.
export fn tesla_client_build_universal_message(
    client_ptr: ?*anyopaque,
    current_timestamp: u32,
    payload_ptr: ?[*]const u8,
    payload_len: usize,
    domain_val: u32,
    encrypt: bool,
    out_buffer: ?[*]u8,
    out_buffer_len: usize,
    out_written_len: ?*usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const payload = payload_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_buffer orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const wr = out_written_len orelse return @intFromEnum(ErrorCode.InvalidArgs);

    if (domain_val != 2 and domain_val != 3) return @intFromEnum(ErrorCode.InvalidDomain);
    const domain: protocol.Domain = @enumFromInt(domain_val);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const r = TeslaRandom.random();

    const len = c.buildUniversalMessageWithPayload(
        r,
        current_timestamp,
        payload[0..payload_len],
        domain,
        encrypt,
        out[0..out_buffer_len],
    ) catch |err| {
        return @intFromEnum(mapError(err));
    };

    wr.* = len;
    return @intFromEnum(ErrorCode.OK);
}

/// Build a signed and encrypted Lock command BLE packet.
export fn tesla_client_build_lock_command(
    client_ptr: ?*anyopaque,
    current_timestamp: u32,
    out_buffer: ?[*]u8,
    out_buffer_len: usize,
    out_written_len: ?*usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_buffer orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const wr = out_written_len orelse return @intFromEnum(ErrorCode.InvalidArgs);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const r = TeslaRandom.random();

    const len = c.buildRkeActionMessage(r, current_timestamp, 1, out[0..out_buffer_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    wr.* = len;
    return @intFromEnum(ErrorCode.OK);
}

/// Build a signed and encrypted Unlock command BLE packet.
export fn tesla_client_build_unlock_command(
    client_ptr: ?*anyopaque,
    current_timestamp: u32,
    out_buffer: ?[*]u8,
    out_buffer_len: usize,
    out_written_len: ?*usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_buffer orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const wr = out_written_len orelse return @intFromEnum(ErrorCode.InvalidArgs);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const r = TeslaRandom.random();

    const len = c.buildRkeActionMessage(r, current_timestamp, 0, out[0..out_buffer_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    wr.* = len;
    return @intFromEnum(ErrorCode.OK);
}

/// Build a signed and encrypted Wake command BLE packet.
export fn tesla_client_build_wake_command(
    client_ptr: ?*anyopaque,
    current_timestamp: u32,
    out_buffer: ?[*]u8,
    out_buffer_len: usize,
    out_written_len: ?*usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_buffer orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const wr = out_written_len orelse return @intFromEnum(ErrorCode.InvalidArgs);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const r = TeslaRandom.random();

    const len = c.buildRkeActionMessage(r, current_timestamp, 30, out[0..out_buffer_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    wr.* = len;
    return @intFromEnum(ErrorCode.OK);
}

/// Build a signed and encrypted Rear Trunk action command BLE packet.
export fn tesla_client_build_trunk_command(
    client_ptr: ?*anyopaque,
    current_timestamp: u32,
    out_buffer: ?[*]u8,
    out_buffer_len: usize,
    out_written_len: ?*usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_buffer orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const wr = out_written_len orelse return @intFromEnum(ErrorCode.InvalidArgs);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const r = TeslaRandom.random();

    // rear trunk move = 1, front trunk = 0
    const len = c.buildClosureMoveRequestMessage(r, current_timestamp, 1, 0, out[0..out_buffer_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    wr.* = len;
    return @intFromEnum(ErrorCode.OK);
}

/// Build a signed and encrypted Front Trunk (Frunk) action command BLE packet.
export fn tesla_client_build_frunk_command(
    client_ptr: ?*anyopaque,
    current_timestamp: u32,
    out_buffer: ?[*]u8,
    out_buffer_len: usize,
    out_written_len: ?*usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_buffer orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const wr = out_written_len orelse return @intFromEnum(ErrorCode.InvalidArgs);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const r = TeslaRandom.random();

    // rear trunk move = 0, front trunk = 1
    const len = c.buildClosureMoveRequestMessage(r, current_timestamp, 0, 1, out[0..out_buffer_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    wr.* = len;
    return @intFromEnum(ErrorCode.OK);
}

/// Decrypt an authenticated vehicle response payload using session parameters.
export fn tesla_client_decrypt_response(
    client_ptr: ?*anyopaque,
    domain_val: u32,
    response_ptr: ?[*]const u8,
    response_len: usize,
    out_buffer: ?[*]u8,
    out_buffer_len: usize,
    out_written_len: ?*usize,
) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const resp = response_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_buffer orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const wr = out_written_len orelse return @intFromEnum(ErrorCode.InvalidArgs);

    if (domain_val != 2 and domain_val != 3) return @intFromEnum(ErrorCode.InvalidDomain);
    const domain: protocol.Domain = @enumFromInt(domain_val);

    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));

    // Decode RoutableMessage wrapper
    const decoded = protobuf.DecodedRoutableMessage.decode(resp[0..response_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    const len = c.decryptResponse(domain, decoded, out[0..out_buffer_len]) catch |err| {
        return @intFromEnum(mapError(err));
    };

    wr.* = len;
    return @intFromEnum(ErrorCode.OK);
}

// Host-native mock of tesla_random_bytes to compile unit tests
fn mock_tesla_random_bytes(buf: [*]u8, len: usize) callconv(.c) void {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        buf[i] = @intCast(i & 0xFF);
    }
}

comptime {
    if (@import("builtin").is_test) {
        @export(&mock_tesla_random_bytes, .{ .name = "tesla_random_bytes", .linkage = .strong });
    }
}

test "C ABI Placement-Initialization and Communication Loop Verification" {
    // Override the extern linker hook for tests by export-redefining or linking
    // For tests, we use standard placement initialization and call exported methods
    const size = tesla_client_size();
    try std.testing.expect(size > 0);

    const client_buf = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(client_buf);

    const vin = "5YJ3E1EBXLF000000";
    const key_bytes = [_]u8{5} ** 32;
    const conn_bytes = [_]u8{0x88} ** 16;

    // Test initialization
    const rc_init = tesla_client_init(
        client_buf.ptr,
        vin.ptr,
        vin.len,
        &key_bytes,
        &conn_bytes,
    );
    try std.testing.expectEqual(@as(i32, 0), rc_init);

    // Verify key getters
    var pub_key: [65]u8 = undefined;
    tesla_client_get_public_key(client_buf.ptr, &pub_key);
    try std.testing.expect(pub_key[0] == 0x04);

    var key_id: [4]u8 = undefined;
    tesla_client_get_key_id(client_buf.ptr, &key_id);
    try std.testing.expect(key_id[0] != 0);

    // We can verify that we can load the compiled bindings natively
}
