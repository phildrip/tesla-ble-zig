//! Standard C-compatible ABI bindings for the Tesla BLE Zig Library.
//! Allows seamless cross-language integration with C/C++ (such as ESP-IDF or ESPHome wrappers).
const std = @import("std");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");
const session = @import("session.zig");
const protobuf = @import("protobuf.zig");
const client = @import("client.zig");
const scheduler = @import("scheduler.zig");
const queue = @import("queue.zig");

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

/// Get the current Connection State Machine state.
export fn tesla_client_get_csm_state(client_ptr: ?*anyopaque) u8 {
    const cp = client_ptr orelse return 0; // default to disconnected (0)
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    return @intFromEnum(c.csm.state);
}

/// Handle a Connection State Machine event from the C environment.
export fn tesla_client_handle_csm_event(client_ptr: ?*anyopaque, event_val: u8, current_timestamp: u32) void {
    const cp = client_ptr orelse return;
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    
    const Event = @import("csm.zig").Event;
    var valid = false;
    inline for (std.meta.fields(Event)) |f| {
        if (event_val == f.value) valid = true;
    }
    if (!valid) return;
    
    const event: Event = @enumFromInt(event_val);
    switch (event) {
        .ble_disconnected => c.handleBleDisconnected(current_timestamp),
        .ble_connected => c.handleBleConnected(current_timestamp),
        .connect_requested => c.handleConnectRequested(current_timestamp),
        else => c.csm.handleEvent(event, current_timestamp),
    }
}

/// Get the number of VCSEC handshake attempts.
export fn tesla_client_get_csm_vcsec_attempts(client_ptr: ?*anyopaque) u8 {
    const cp = client_ptr orelse return 0;
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    return c.csm.vcsec_handshake_attempts;
}

/// Get the number of Infotainment handshake attempts.
export fn tesla_client_get_csm_infotainment_attempts(client_ptr: ?*anyopaque) u8 {
    const cp = client_ptr orelse return 0;
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    return c.csm.infotainment_handshake_attempts;
}

/// Get the session key (shared secret) derived by the Zig Client for a given domain.
export fn tesla_client_get_shared_secret(client_ptr: ?*anyopaque, domain_val: u32, out_secret_16: ?[*]u8) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_secret_16 orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const domain = @as(protocol.Domain, @enumFromInt(domain_val));
    const peer = c.getPeer(domain) orelse return @intFromEnum(ErrorCode.InvalidDomain);
    @memcpy(out[0..16], &peer.shared_secret);
    return @intFromEnum(ErrorCode.OK);
}

/// Get the session sequence counter tracked by the Zig Client for a given domain.
export fn tesla_client_get_session_counter(client_ptr: ?*anyopaque, domain_val: u32) u32 {
    const cp = client_ptr orelse return 0;
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const domain = @as(protocol.Domain, @enumFromInt(domain_val));
    const peer = c.getPeer(domain) orelse return 0;
    return peer.counter;
}

/// Get the session epoch bytes tracked by the Zig Client for a given domain.
export fn tesla_client_get_session_epoch(client_ptr: ?*anyopaque, domain_val: u32, out_epoch_16: ?[*]u8) i32 {
    const cp = client_ptr orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const out = out_epoch_16 orelse return @intFromEnum(ErrorCode.InvalidArgs);
    const c = @as(*client.Client, @ptrCast(@alignCast(cp)));
    const domain = @as(protocol.Domain, @enumFromInt(domain_val));
    const peer = c.getPeer(domain) orelse return @intFromEnum(ErrorCode.InvalidDomain);
    @memcpy(out[0..16], &peer.epoch);
    return @intFromEnum(ErrorCode.OK);
}

/// Returns the size in bytes of the `Scheduler` structure.
export fn tesla_scheduler_size() usize {
    return @sizeOf(scheduler.Scheduler);
}

/// Initialize the Scheduler structure in-place inside a pre-allocated memory buffer.
export fn tesla_scheduler_init(
    scheduler_ptr: ?*anyopaque,
    post_wake_poll_time_ms: u32,
    poll_data_period_ms: u32,
    poll_asleep_period_ms: u32,
    poll_charging_period_ms: u32,
    fast_poll_if_unlocked: bool,
    wake_on_boot: bool,
) void {
    const sp = scheduler_ptr orelse return;
    const config = scheduler.SchedulerConfig{
        .post_wake_poll_time_ms = post_wake_poll_time_ms,
        .poll_data_period_ms = poll_data_period_ms,
        .poll_asleep_period_ms = poll_asleep_period_ms,
        .poll_charging_period_ms = poll_charging_period_ms,
        .fast_poll_if_unlocked = fast_poll_if_unlocked,
        .wake_on_boot = wake_on_boot,
    };
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    s.* = scheduler.Scheduler.init(config);
}

/// Update the timing configuration of the scheduler dynamically.
export fn tesla_scheduler_update_config(
    scheduler_ptr: ?*anyopaque,
    post_wake_poll_time_ms: u32,
    poll_data_period_ms: u32,
    poll_asleep_period_ms: u32,
    poll_charging_period_ms: u32,
) void {
    const sp = scheduler_ptr orelse return;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    s.config.post_wake_poll_time_ms = post_wake_poll_time_ms;
    s.config.poll_data_period_ms = poll_data_period_ms;
    s.config.poll_asleep_period_ms = poll_asleep_period_ms;
    s.config.poll_charging_period_ms = poll_charging_period_ms;
}


/// Perform a scheduler tick, returning decision outputs.
export fn tesla_scheduler_tick(
    scheduler_ptr: ?*anyopaque,
    current_time_ms: u32,
    is_asleep: bool,
    is_unlocked: bool,
    is_user_present: bool,
    one_off_update: bool,
    out_should_poll_vcsec: ?*bool,
    out_should_poll_infotainment: ?*bool,
    out_should_wake_vehicle: ?*bool,
    out_clear_one_off_update: ?*bool,
) void {
    const sp = scheduler_ptr orelse return;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    const dec = s.tick(current_time_ms, is_asleep, is_unlocked, is_user_present, one_off_update);
    if (out_should_poll_vcsec) |p| p.* = dec.should_poll_vcsec;
    if (out_should_poll_infotainment) |p| p.* = dec.should_poll_infotainment;
    if (out_should_wake_vehicle) |p| p.* = dec.should_wake_vehicle;
    if (out_clear_one_off_update) |p| p.* = dec.clear_one_off_update;
}

/// Get the current internal charging state tracking of the scheduler.
export fn tesla_scheduler_get_charging_state(scheduler_ptr: ?*anyopaque) u8 {
    const sp = scheduler_ptr orelse return 0;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    return @intFromEnum(s.car_is_charging);
}

/// Set the internal charging state tracking of the scheduler.
export fn tesla_scheduler_set_charging_state(scheduler_ptr: ?*anyopaque, charging_state: u8) void {
    const sp = scheduler_ptr orelse return;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    const state: scheduler.ChargingState = @enumFromInt(charging_state);
    s.car_is_charging = state;
}

/// Reset the VCSEC poll timestamp to 0.
export fn tesla_scheduler_reset_vcsec_poll_time(scheduler_ptr: ?*anyopaque) void {
    const sp = scheduler_ptr orelse return;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    s.last_vcsec_poll_time = 0;
}

/// Get the total number of Infotainment updates triggered since connection.
export fn tesla_scheduler_get_number_updates_since_connection(scheduler_ptr: ?*anyopaque) u32 {
    const sp = scheduler_ptr orelse return 0;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    return s.number_updates_since_connection;
}

/// Set the total number of Infotainment updates triggered since connection.
export fn tesla_scheduler_set_number_updates_since_connection(scheduler_ptr: ?*anyopaque, count: u32) void {
    const sp = scheduler_ptr orelse return;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    s.number_updates_since_connection = count;
}

/// Get the car's just woken state.
export fn tesla_scheduler_get_car_just_woken(scheduler_ptr: ?*anyopaque) u8 {
    const sp = scheduler_ptr orelse return 0;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    return @intFromEnum(s.car_just_woken);
}

/// Set the car's just woken state.
export fn tesla_scheduler_set_car_just_woken(scheduler_ptr: ?*anyopaque, state: u8) void {
    const sp = scheduler_ptr orelse return;
    const s = @as(*scheduler.Scheduler, @ptrCast(@alignCast(sp)));
    const woken: scheduler.CarWakeState = @enumFromInt(state);
    s.car_just_woken = woken;
}

/// Returns the size in bytes of the `CommandQueue` structure.
/// Allows C/C++ compilers to allocate exactly the required stack space for placement initialization.
export fn tesla_queue_size() usize {
    return @sizeOf(queue.CommandQueue);
}

/// Initialize the CommandQueue structure in-place inside a pre-allocated memory buffer.
export fn tesla_queue_init(queue_ptr: ?*anyopaque) void {
    const qp = queue_ptr orelse return;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    q.* = queue.CommandQueue.init();
}

/// Check if the command queue is empty.
export fn tesla_queue_empty(queue_ptr: ?*anyopaque) bool {
    const qp = queue_ptr orelse return true;
    const q = @as(*const queue.CommandQueue, @ptrCast(@alignCast(qp)));
    return q.empty();
}

/// Get the current number of commands in the queue.
export fn tesla_queue_count(queue_ptr: ?*anyopaque) usize {
    const qp = queue_ptr orelse return 0;
    const q = @as(*const queue.CommandQueue, @ptrCast(@alignCast(qp)));
    return q.size();
}

/// Append a new command to the back of the queue. Returns the generated unique ID (or 0 on error).
export fn tesla_queue_push_back(queue_ptr: ?*anyopaque, domain: u32, action: u32, current_time: u32) u32 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    return q.pushBack(domain, action, current_time) catch 0;
}

/// Prioritized insertion: inserts a command at the front (or second position if front is already active).
/// Returns the generated unique ID (or 0 on error).
export fn tesla_queue_place_at_front(queue_ptr: ?*anyopaque, domain: u32, action: u32, current_time: u32) u32 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    return q.placeAtFront(domain, action, current_time) catch 0;
}

/// Remove the front-most command from the queue.
export fn tesla_queue_pop_front(queue_ptr: ?*anyopaque) void {
    const qp = queue_ptr orelse return;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    q.popFront();
}

/// Get the unique ID of the front-most command (returns 0 if empty).
export fn tesla_queue_get_front_id(queue_ptr: ?*anyopaque) u32 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    return cmd.id;
}

/// Get the domain of the front-most command (returns 0 if empty).
export fn tesla_queue_get_front_domain(queue_ptr: ?*anyopaque) u32 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    return cmd.domain;
}

/// Get the action of the front-most command (returns 0 if empty).
export fn tesla_queue_get_front_action(queue_ptr: ?*anyopaque) u32 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    return cmd.action;
}

/// Get the state of the front-most command (returns 0/idle if empty).
export fn tesla_queue_get_front_state(queue_ptr: ?*anyopaque) u8 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    return @intFromEnum(cmd.state);
}

/// Set the state of the front-most command.
export fn tesla_queue_set_front_state(queue_ptr: ?*anyopaque, state_val: u8) void {
    const qp = queue_ptr orelse return;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return;
    const state: queue.CommandState = @enumFromInt(state_val);
    cmd.state = state;
}

/// Get the started_at timestamp of the front-most command (returns 0 if empty).
export fn tesla_queue_get_front_started_at(queue_ptr: ?*anyopaque) u32 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    return cmd.started_at;
}

/// Set the started_at timestamp of the front-most command.
export fn tesla_queue_set_front_started_at(queue_ptr: ?*anyopaque, timestamp: u32) void {
    const qp = queue_ptr orelse return;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return;
    cmd.started_at = timestamp;
}

/// Get the last_tx_at timestamp of the front-most command (returns 0 if empty).
export fn tesla_queue_get_front_last_tx_at(queue_ptr: ?*anyopaque) u32 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    return cmd.last_tx_at;
}

/// Set the last_tx_at timestamp of the front-most command.
export fn tesla_queue_set_front_last_tx_at(queue_ptr: ?*anyopaque, timestamp: u32) void {
    const qp = queue_ptr orelse return;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return;
    cmd.last_tx_at = timestamp;
}

/// Get the retry count of the front-most command (returns 0 if empty).
export fn tesla_queue_get_front_retry_count(queue_ptr: ?*anyopaque) u8 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    return cmd.retry_count;
}

/// Increment the retry count of the front-most command and return the new value.
export fn tesla_queue_increment_front_retry_count(queue_ptr: ?*anyopaque) u8 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    if (cmd.retry_count < 255) {
        cmd.retry_count += 1;
    }
    return cmd.retry_count;
}

/// Set the retry count of the front-most command.
export fn tesla_queue_set_front_retry_count(queue_ptr: ?*anyopaque, count: u8) void {
    const qp = queue_ptr orelse return;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return;
    cmd.retry_count = count;
}

/// Get the done_times of the front-most command (returns 0 if empty).
export fn tesla_queue_get_front_done_times(queue_ptr: ?*anyopaque) u16 {
    const qp = queue_ptr orelse return 0;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return 0;
    return cmd.done_times;
}

/// Set the done_times of the front-most command.
export fn tesla_queue_set_front_done_times(queue_ptr: ?*anyopaque, done_times: u16) void {
    const qp = queue_ptr orelse return;
    const q = @as(*queue.CommandQueue, @ptrCast(@alignCast(qp)));
    const cmd = q.getFront() orelse return;
    cmd.done_times = done_times;
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

    // Verify CSM bindings
    try std.testing.expectEqual(@as(u8, 0), tesla_client_get_csm_state(client_buf.ptr));

    tesla_client_handle_csm_event(client_buf.ptr, 0, 100); // connect_requested
    try std.testing.expectEqual(@as(u8, 1), tesla_client_get_csm_state(client_buf.ptr)); // connecting

    tesla_client_handle_csm_event(client_buf.ptr, 1, 105); // ble_connected
    try std.testing.expectEqual(@as(u8, 2), tesla_client_get_csm_state(client_buf.ptr)); // handshaking_vcsec

    tesla_client_handle_csm_event(client_buf.ptr, 7, 110); // handshake_failed
    try std.testing.expectEqual(@as(u8, 1), tesla_client_get_csm_state(client_buf.ptr)); // connecting
    try std.testing.expectEqual(@as(u8, 1), tesla_client_get_csm_vcsec_attempts(client_buf.ptr));
}

test "C ABI Scheduler Integration and State Updates" {
    const size = tesla_scheduler_size();
    try std.testing.expect(size > 0);

    const sched_buf = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(sched_buf);

    tesla_scheduler_init(
        sched_buf.ptr,
        10000, // post_wake_poll_time_ms
        5000,  // poll_data_period_ms
        30000, // poll_asleep_period_ms
        15000, // poll_charging_period_ms
        true,  // fast_poll_if_unlocked
        true,  // wake_on_boot
    );

    // Initial state check
    try std.testing.expectEqual(@as(u8, 0), tesla_scheduler_get_charging_state(sched_buf.ptr));
    try std.testing.expectEqual(@as(u32, 0), tesla_scheduler_get_number_updates_since_connection(sched_buf.ptr));
    try std.testing.expectEqual(@as(u8, 0), tesla_scheduler_get_car_just_woken(sched_buf.ptr));

    // Tick at boot cycle 0
    var should_poll_vcsec = false;
    var should_poll_infotainment = false;
    var should_wake_vehicle = false;
    var clear_one_off_update = false;

    tesla_scheduler_tick(
        sched_buf.ptr,
        100, // current_time_ms
        true, // is_asleep
        false, // is_unlocked
        false, // is_user_present
        false, // one_off_update
        &should_poll_vcsec,
        &should_poll_infotainment,
        &should_wake_vehicle,
        &clear_one_off_update,
    );

    try std.testing.expectEqual(true, should_poll_vcsec);
    try std.testing.expectEqual(false, should_poll_infotainment);
    try std.testing.expectEqual(false, should_wake_vehicle);

    // Boot cycle 1
    tesla_scheduler_tick(sched_buf.ptr, 200, true, false, false, false, &should_poll_vcsec, &should_poll_infotainment, &should_wake_vehicle, &clear_one_off_update);
    try std.testing.expectEqual(false, should_wake_vehicle);

    // Boot cycle 2 -> should wake vehicle
    tesla_scheduler_tick(sched_buf.ptr, 300, true, false, false, false, &should_poll_vcsec, &should_poll_infotainment, &should_wake_vehicle, &clear_one_off_update);
    try std.testing.expectEqual(true, should_wake_vehicle);

    // Test charging state and getters/setters
    tesla_scheduler_set_charging_state(sched_buf.ptr, 2); // charging_ongoing
    try std.testing.expectEqual(@as(u8, 2), tesla_scheduler_get_charging_state(sched_buf.ptr));

    // Test car_just_woken getters/setters
    tesla_scheduler_set_car_just_woken(sched_buf.ptr, 1); // yes_initial
    try std.testing.expectEqual(@as(u8, 1), tesla_scheduler_get_car_just_woken(sched_buf.ptr));

    // Test updates since connection getters/setters
    tesla_scheduler_set_number_updates_since_connection(sched_buf.ptr, 42);
    try std.testing.expectEqual(@as(u32, 42), tesla_scheduler_get_number_updates_since_connection(sched_buf.ptr));
}
