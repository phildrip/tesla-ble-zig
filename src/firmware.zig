//! @file firmware.zig
//! @brief Standalone, pure-Zig firmware entry point, Wi-Fi coordinator, and HA MQTT discovery engine.

const std = @import("std");
const builtin = @import("builtin");
const nimble_layer = @import("nimble.zig");
const client_module = @import("client.zig");
const queue_module = @import("queue.zig");

// Extern functions to invoke ESP-IDF C wrappers (defined in main.c)
extern fn tesla_c_wifi_init(ssid: [*:0]const u8, password: [*:0]const u8) void;
extern fn tesla_c_mqtt_init(broker_url: [*:0]const u8) void;
extern fn tesla_c_mqtt_publish(topic: [*:0]const u8, payload: [*]const u8, len: usize, qos: i32, retain: i32) void;
extern fn tesla_c_mqtt_subscribe(topic: [*:0]const u8, qos: i32) void;
extern fn esp_timer_get_time() callconv(.c) i64;

// Global configuration loaded at startup passed from C app_main
var wifi_ssid: [*:0]const u8 = undefined;
var wifi_pass: [*:0]const u8 = undefined;
var mqtt_broker_url: [*:0]const u8 = undefined;
var mqtt_broker_user: [*:0]const u8 = undefined;
var mqtt_broker_pass: [*:0]const u8 = undefined;
var vehicle_vin: [*:0]const u8 = undefined;
var ble_mac_address: [*:0]const u8 = undefined;
var api_encryption_key: [*:0]const u8 = undefined;
var vehicle_public_key_str: [*:0]const u8 = undefined;

// Active global Client and CommandQueue structures
pub var client_inst: client_module.Client = undefined;
pub var queue_inst: queue_module.CommandQueue = undefined;
pub var is_initialized: bool = false;
var pending_pair_request: bool = false;

fn parseHexKey(hex: []const u8, out: []u8) !void {
    if (hex.len != out.len * 2) return error.InvalidLength;
    for (out, 0..) |*b, i| {
        b.* = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    }
}

/// Get system millisecond timestamp in a platform-agnostic manner.
pub fn getMillis() u32 {
    if (builtin.os.tag == .freestanding) {
        return @intCast(@divTrunc(esp_timer_get_time(), 1000));
    } else {
        var ts: std.posix.timespec = undefined;
        _ = std.posix.system.clock_gettime(.REALTIME, &ts);
        const ms = @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
        return @truncate(ms);
    }
}

/// Get system seconds for Tesla protocol timestamp deltas.
fn getSeconds() u32 {
    if (builtin.os.tag == .freestanding) {
        return @intCast(@divTrunc(esp_timer_get_time(), 1_000_000));
    } else {
        var ts: std.posix.timespec = undefined;
        _ = std.posix.system.clock_gettime(.REALTIME, &ts);
        return @truncate(@as(u64, @intCast(ts.sec)));
    }
}

// Pure-Zig global entry-point callable from ESP-IDF bootloader.
pub export fn tesla_zig_app_main(
    ssid: [*:0]const u8,
    password: [*:0]const u8,
    broker_url: [*:0]const u8,
    broker_user: [*:0]const u8,
    broker_pass: [*:0]const u8,
    vin: [*:0]const u8,
    ble_mac: [*:0]const u8,
    api_key: [*:0]const u8,
    vehicle_pub_key: [*:0]const u8,
    saved_vcsec_session: [*]const u8,
    saved_vcsec_session_len: usize,
    saved_infotainment_session: [*]const u8,
    saved_infotainment_session_len: usize,
) callconv(.c) void {
    std.log.info("🚗 Starting Pure-Zig Standalone Tesla BLE Firmware...", .{});

    wifi_ssid = ssid;
    wifi_pass = password;
    mqtt_broker_url = broker_url;
    mqtt_broker_user = broker_user;
    mqtt_broker_pass = broker_pass;
    vehicle_vin = vin;
    ble_mac_address = ble_mac;
    api_encryption_key = api_key;
    vehicle_public_key_str = vehicle_pub_key;

    std.log.info("[System] Initialized config SSID: {s}, Broker: {s}, User: {s}, VIN: {s}, MAC: {s}", .{
        wifi_ssid,
        mqtt_broker_url,
        mqtt_broker_user,
        vehicle_vin,
        ble_mac_address,
    });

    // Parse the Base64 API encryption key (which is our private key)
    var decoded_priv_key: [32]u8 = undefined;
    const key_len = std.mem.span(api_encryption_key);
    var decoded = true;
    std.base64.standard.Decoder.decode(&decoded_priv_key, key_len) catch |err| {
        std.log.err("Failed to decode base64 api_key: {any}. Using fallback.", .{err});
        @memcpy(&decoded_priv_key, &[_]u8{5} ** 32);
        decoded = false;
    };

    const dummy_conn_id = [_]u8{0x88} ** 16;
    const vin_slice = std.mem.span(vehicle_vin);
    client_inst = client_module.Client.init(vin_slice, decoded_priv_key, dummy_conn_id) catch |err| {
        std.log.err("Failed to initialize Client: {any}", .{err});
        return;
    };

    // Load static vehicle public key if configured
    const v_pub_key_span = std.mem.span(vehicle_public_key_str);
    if (v_pub_key_span.len > 0 and !std.mem.eql(u8, v_pub_key_span, "your_vehicle_public_key_hex")) {
        var vehicle_public_key_raw = [_]u8{0} ** 65;
        parseHexKey(v_pub_key_span, &vehicle_public_key_raw) catch |err| {
            std.log.err("Failed to parse vehicle_pub_key hex string: {any}", .{err});
        };
        if (vehicle_public_key_raw[0] == 0x04) {
            client_inst.setVehiclePublicKey(vehicle_public_key_raw);
            std.log.info("[System] Successfully parsed and set static vehicle public key.", .{});
        } else {
            std.log.err("[System] Parsed vehicle public key is invalid (must start with 0x04 uncompressed SEC1 prefix)", .{});
        }
    }

    loadSavedSessionInfo(.vehicle_security, saved_vcsec_session, saved_vcsec_session_len);
    loadSavedSessionInfo(.infotainment, saved_infotainment_session, saved_infotainment_session_len);

    queue_inst = queue_module.CommandQueue.init();
    is_initialized = true;

    std.log.info("Client and CommandQueue initialized successfully. PrivKey Decoded={any}.", .{decoded});

    if (builtin.os.tag == .freestanding) {
        // 1. Connect to Wi-Fi
        tesla_c_wifi_init(wifi_ssid, wifi_pass);

        // 2. Connect to MQTT Broker
        tesla_c_mqtt_init(mqtt_broker_url);

        // 3. Initialize NimBLE Controller and Start scanning
        nimble_layer.initNimble();
    } else {
        std.log.info("[Mock] Running in native test mode. Wi-Fi, MQTT, and BLE simulated.", .{});
    }
}

fn loadSavedSessionInfo(domain: @import("protocol.zig").Domain, session_ptr: [*]const u8, session_len: usize) void {
    if (session_len == 0) {
        std.log.warn("[System] No saved {any} SessionInfo provided from NVS.", .{domain});
        return;
    }

    std.log.info("[System] Loading saved {any} SessionInfo from NVS ({d} bytes).", .{ domain, session_len });

    const session_bytes = session_ptr[0..session_len];
    const info = @import("protobuf.zig").SessionInfo.decode(session_bytes) catch |err| {
        std.log.err("[System] Failed to decode saved {any} SessionInfo from NVS: {any}", .{ domain, err });
        return;
    };

    if (domain == .vehicle_security and info.public_key_len == 65 and info.public_key[0] == 0x04) {
        client_inst.setVehiclePublicKey(info.public_key);
        std.log.info("[System] Restored full vehicle public key from saved {any} SessionInfo.", .{domain});
    } else if (info.public_key_len != 65 or info.public_key[0] != 0x04) {
        std.log.warn("[System] Saved {any} SessionInfo did not contain a full vehicle public key (len={d}).", .{ domain, info.public_key_len });
    }

    client_inst.handleSessionInfoResponse(domain, getSeconds(), session_bytes) catch |err| {
        std.log.err("[System] Failed to restore saved {any} SessionInfo into Zig client: {any}", .{ domain, err });
        return;
    };

    std.log.info("[System] Restored saved {any} secure session from NVS.", .{domain});
}

// -------------------------------------------------------------
// Callbacks from C-Glue Layer into Zig
// -------------------------------------------------------------

pub export fn tesla_zig_wifi_on_connected() callconv(.c) void {
    std.log.info("[Wi-Fi callback] Wi-Fi connected!", .{});
}

pub export fn tesla_zig_mqtt_on_connected() callconv(.c) void {
    std.log.info("[MQTT callback] Connected to broker. Subscribing to control topics and registering Auto-Discovery...", .{});
    subscribeToControlTopics();
    publishHomeAssistantDiscovery();
}

pub export fn tesla_zig_mqtt_on_message(
    topic_ptr: [*]const u8,
    topic_len: usize,
    data_ptr: [*]const u8,
    data_len: usize,
) callconv(.c) void {
    const topic = topic_ptr[0..topic_len];
    const payload = data_ptr[0..data_len];
    std.log.info("[MQTT callback] Received message on topic: {s} | payload: {s}", .{ topic, payload });
    handleIncomingCommand(topic, payload);
}

// Subscribe to Home Assistant Command topics for control entities.
fn subscribeToControlTopics() void {
    var buf: [256]u8 = undefined;
    const topic = std.fmt.bufPrintZ(&buf, "tesla_ble/{s}/command/#", .{vehicle_vin}) catch return;
    tesla_c_mqtt_subscribe(topic, 1);
}

// Publish Home Assistant MQTT Auto-Discovery Config payloads.
fn publishHomeAssistantDiscovery() void {
    var topic_buf: [256]u8 = undefined;
    var payload_buf: [1024]u8 = undefined;

    // 1. Lock Switch entity discovery
    const lock_discovery_topic = std.fmt.bufPrintZ(&topic_buf, "homeassistant/switch/tesla_ble_{s}_lock/config", .{vehicle_vin}) catch return;
    const lock_discovery_payload = std.fmt.bufPrint(&payload_buf,
        \\{{
        \\"name":"Tesla Lock",
        \\"unique_id":"tesla_ble_{s}_lock",
        \\"state_topic":"tesla_ble/{s}/state/lock",
        \\"command_topic":"tesla_ble/{s}/command/lock",
        \\"payload_on":"LOCK",
        \\"payload_off":"UNLOCK",
        \\"state_on":"LOCKED",
        \\"state_off":"UNLOCKED",
        \\"device":{{
        \\"identifiers":["tesla_ble_{s}"],
        \\"name":"Tesla Model C6",
        \\"model":"Tesla BLE Zig Controller",
        \\"manufacturer":"Antigravity"
        \\}}
        \\}}
    , .{ vehicle_vin, vehicle_vin, vehicle_vin, vehicle_vin }) catch return;

    tesla_c_mqtt_publish(lock_discovery_topic, lock_discovery_payload.ptr, lock_discovery_payload.len, 1, 1);

    // 2. Frunk binary control entity discovery
    const frunk_discovery_topic = std.fmt.bufPrintZ(&topic_buf, "homeassistant/button/tesla_ble_{s}_frunk/config", .{vehicle_vin}) catch return;
    const frunk_discovery_payload = std.fmt.bufPrint(&payload_buf,
        \\{{
        \\"name":"Tesla Open Frunk",
        \\"unique_id":"tesla_ble_{s}_frunk",
        \\"command_topic":"tesla_ble/{s}/command/frunk",
        \\"payload_press":"OPEN",
        \\"device":{{
        \\"identifiers":["tesla_ble_{s}"],
        \\"name":"Tesla Model C6"
        \\}}
        \\}}
    , .{ vehicle_vin, vehicle_vin, vehicle_vin }) catch return;

    tesla_c_mqtt_publish(frunk_discovery_topic, frunk_discovery_payload.ptr, frunk_discovery_payload.len, 1, 1);

    // 3. Flash lights button discovery
    const flash_discovery_topic = std.fmt.bufPrintZ(&topic_buf, "homeassistant/button/tesla_ble_{s}_flash_lights/config", .{vehicle_vin}) catch return;
    const flash_discovery_payload = std.fmt.bufPrint(&payload_buf,
        \\{{
        \\"name":"Tesla Flash Lights",
        \\"unique_id":"tesla_ble_{s}_flash_lights",
        \\"command_topic":"tesla_ble/{s}/command/flash_lights",
        \\"payload_press":"FLASH",
        \\"device":{{
        \\"identifiers":["tesla_ble_{s}"],
        \\"name":"Tesla Model C6"
        \\}}
        \\}}
    , .{ vehicle_vin, vehicle_vin, vehicle_vin }) catch return;

    tesla_c_mqtt_publish(flash_discovery_topic, flash_discovery_payload.ptr, flash_discovery_payload.len, 1, 1);

    // 4. Charger State binary sensor discovery
    const charger_discovery_topic = std.fmt.bufPrintZ(&topic_buf, "homeassistant/binary_sensor/tesla_ble_{s}_charging/config", .{vehicle_vin}) catch return;
    const charger_discovery_payload = std.fmt.bufPrint(&payload_buf,
        \\{{
        \\"name":"Tesla Charging Status",
        \\"unique_id":"tesla_ble_{s}_charging",
        \\"state_topic":"tesla_ble/{s}/state/charging",
        \\"payload_on":"CHARGING",
        \\"payload_off":"NOT_CHARGING",
        \\"device":{{
        \\"identifiers":["tesla_ble_{s}"],
        \\"name":"Tesla Model C6"
        \\}}
        \\}}
    , .{ vehicle_vin, vehicle_vin, vehicle_vin }) catch return;

    tesla_c_mqtt_publish(charger_discovery_topic, charger_discovery_payload.ptr, charger_discovery_payload.len, 1, 1);

    std.log.info("[HA Discovery] Successfully registered lock, frunk, flash lights, and charging entities", .{});
}

// Handle inbound control messages from Home Assistant.
fn handleIncomingCommand(topic: []const u8, payload: []const u8) void {
    if (!is_initialized) return;

    if (std.mem.endsWith(u8, topic, "command/lock")) {
        if (std.mem.eql(u8, payload, "LOCK")) {
            std.log.info("[Command] Enqueueing lock command", .{});
            _ = queue_inst.pushBack(2, 1, getMillis()) catch |err| {
                std.log.err("Queue full: {any}", .{err});
            };
        } else if (std.mem.eql(u8, payload, "UNLOCK")) {
            std.log.info("[Command] Enqueueing unlock command", .{});
            _ = queue_inst.pushBack(2, 0, getMillis()) catch |err| {
                std.log.err("Queue full: {any}", .{err});
            };
        }
    } else if (std.mem.endsWith(u8, topic, "command/frunk")) {
        if (std.mem.eql(u8, payload, "OPEN")) {
            std.log.info("[Command] Enqueueing frunk release command", .{});
            _ = queue_inst.pushBack(2, 31, getMillis()) catch |err| {
                std.log.err("Queue full: {any}", .{err});
            };
        }
    } else if (std.mem.endsWith(u8, topic, "command/flash_lights")) {
        if (std.mem.eql(u8, payload, "FLASH")) {
            std.log.info("[Command] Enqueueing flash lights command", .{});
            _ = queue_inst.pushBack(3, 26, getMillis()) catch |err| {
                std.log.err("Queue full: {any}", .{err});
            };
        }
    } else if (std.mem.endsWith(u8, topic, "command/pair")) {
        if (std.mem.eql(u8, payload, "PAIR")) {
            std.log.info("[Command] Pairing requested; preparing whitelist message", .{});
            pending_pair_request = true;
            if (client_inst.csm.state == .disconnected) {
                std.log.info("CSM disconnected. Initiating BLE scanning for pairing...", .{});
                nimble_layer.startScanning();
            } else {
                sendPairingRequest();
            }
        }
    }

    // Process the queue!
    processQueue();
}

pub fn sendHandshakeRequest(domain: @import("protocol.zig").Domain) void {
    if (!is_initialized) return;

    var buffer: [256]u8 = undefined;
    const r = @import("c_bindings.zig").TeslaRandom.random();

    const len = client_inst.buildSessionInfoRequestMessage(r, domain, &buffer) catch |err| {
        std.log.err("Failed to build SessionInfoRequest for domain {any}: {any}", .{ domain, err });
        return;
    };

    std.log.info("Sending SessionInfoRequest ({d} bytes) for domain {any}...", .{ len, domain });
    nimble_layer.writeTxCharacteristic(buffer[0..len]);
}

pub fn handleBleChannelReady() void {
    if (!is_initialized) return;

    if (pending_pair_request) {
        sendPairingRequest();
    } else if (client_inst.session_vcsec.is_valid) {
        std.log.info("[System] Using restored VCSEC session; skipping SessionInfoRequest.", .{});
        client_inst.csm.handleEvent(.handshake_success_vcsec, getMillis());
        processQueue();
    } else {
        sendHandshakeRequest(.vehicle_security);
    }
}

pub fn sendPairingRequest() void {
    if (!is_initialized) return;

    var buffer: [256]u8 = undefined;
    const len = client_inst.buildWhiteListMessage(.driver, .cloud_key, &buffer) catch |err| {
        std.log.err("Failed to build whitelist pairing message: {any}", .{err});
        return;
    };

    pending_pair_request = false;
    std.log.info("Sending VCSEC whitelist pairing message ({d} bytes)...", .{len});
    nimble_layer.writeTxCharacteristic(buffer[0..len]);
    std.log.info("Please tap your Tesla key card on the reader now.", .{});
}

var rx_reassembly_buf: [512]u8 = undefined;
var rx_reassembly_len: usize = 0;
var rx_expected_len: usize = 0;
var tx_command_buf: [512]u8 = undefined;
var processing_queue = false;

pub fn handleRxNotification(payload: []const u8) void {
    if (!is_initialized) return;

    std.log.info("[Firmware] Received packet fragment ({d} bytes)...", .{payload.len});

    // If starting a new packet assembly
    if (rx_reassembly_len == 0) {
        if (payload.len < 2) {
            std.log.err("Packet too short to read length prefix: {d} bytes", .{payload.len});
            return;
        }
        const msg_len = (@as(usize, payload[0]) << 8) | payload[1];
        rx_expected_len = msg_len + 2;
    }

    // Safety guard to avoid buffer overflow
    if (rx_reassembly_len + payload.len > rx_reassembly_buf.len) {
        std.log.err("Reassembly buffer overflow! Resetting state.", .{});
        rx_reassembly_len = 0;
        rx_expected_len = 0;
        return;
    }

    // Copy fragment into assembly buffer
    @memcpy(rx_reassembly_buf[rx_reassembly_len .. rx_reassembly_len + payload.len], payload);
    rx_reassembly_len += payload.len;

    std.log.info("[Firmware] Reassembly progress: {d}/{d} bytes", .{ rx_reassembly_len, rx_expected_len });

    // Check if we have gathered the entire packet
    if (rx_reassembly_len >= rx_expected_len) {
        const full_message = rx_reassembly_buf[0..rx_reassembly_len];
        std.log.info("[Firmware] Full packet reassembled ({d} bytes). Processing...", .{rx_reassembly_len});

        // Reset reassembly trackers first to prepare for any synchronous follow-up packets
        const current_len = rx_reassembly_len;
        rx_reassembly_len = 0;
        rx_expected_len = 0;

        processFullRxMessage(full_message[0..current_len]);
    }
}

fn processFullRxMessage(payload: []const u8) void {
    if (payload.len < 2) return;
    const msg_len = (@as(usize, payload[0]) << 8) | payload[1];
    if (payload.len < msg_len + 2) return;

    const msg_bytes = payload[2 .. msg_len + 2];

    const decoded = @import("protobuf.zig").DecodedRoutableMessage.decode(msg_bytes) catch |err| {
        std.log.err("Failed to decode RoutableMessage: {any}", .{err});
        return;
    };

    if (decoded.session_info) |si_bytes| {
        std.log.info("Received SessionInfo response!", .{});
        if (decoded.signed_message_fault != 0) {
            std.log.warn("SessionInfo response included signed message fault={d}", .{decoded.signed_message_fault});
        }
        const domain = decoded.from_destination_domain orelse decoded.to_destination_domain orelse .vehicle_security;
        if (client_inst.getPeer(domain)) |active_sess| {
            if (active_sess.is_valid and processing_queue) {
                std.log.info("Ignoring duplicate SessionInfo for already-valid domain {any}.", .{domain});
                processQueue();
                return;
            }
        }

        client_inst.handleSessionInfoResponse(domain, getSeconds(), si_bytes) catch |err| {
            std.log.err("Failed to handle SessionInfoResponse: {any}", .{err});
            return;
        };

        std.log.info("Session for domain {any} initialized successfully! CSM State: {any}", .{ domain, client_inst.csm.state });

        // Publish lock state to Home Assistant on successful handshake (default to UNLOCKED)
        publishStateUpdate("state/lock", "UNLOCKED");

        processQueue();
    } else {
        if (decoded.protobuf_message_as_bytes) |vcsec_bytes| {
            if (decoded.aes_gcm_response_sig == null) {
                const vcsec_msg = @import("protobuf.zig").DecodedVcsecMessage.decode(vcsec_bytes) catch |err| {
                    std.log.err("Failed to decode plaintext VCSEC response: {any}", .{err});
                    return;
                };

                if (vcsec_msg.command_status) |status| {
                    std.log.info("Received VCSEC command status: operation_status={d}", .{status.operation_status});
                    if (status.whitelist_operation_status) |whitelist_status| {
                        std.log.info(
                            "Whitelist status: operation_status={d}, information={d}",
                            .{ whitelist_status.operation_status, whitelist_status.information },
                        );
                    }
                    return;
                }

                if (vcsec_msg.has_whitelist_info) {
                    std.log.info("Received VCSEC whitelist info response.", .{});
                    return;
                }
                if (vcsec_msg.has_whitelist_entry_info) {
                    std.log.info("Received VCSEC whitelist entry info response.", .{});
                    return;
                }
            }
        }

        var plaintext_buf: [512]u8 = undefined;
        const domain = decoded.from_destination_domain orelse decoded.to_destination_domain orelse .vehicle_security;
        const decrypted_len = client_inst.decryptResponse(
            domain,
            decoded,
            &plaintext_buf,
        ) catch |err| {
            std.log.err("Failed to decrypt {any} vehicle response: {any}", .{ domain, err });
            return;
        };

        std.log.info("Successfully decrypted {any} response ({d} bytes)", .{ domain, decrypted_len });
    }
}

pub fn processQueue() void {
    if (!is_initialized) return;
    if (processing_queue) {
        return;
    }
    processing_queue = true;
    defer processing_queue = false;

    if (queue_inst.empty()) {
        return;
    }

    // Check if we are connected and secure
    if (client_inst.csm.state != .secure_vcsec and client_inst.csm.state != .fully_secure) {
        std.log.warn("Cannot process queue: CSM state is not secure ({any})", .{client_inst.csm.state});
        // Start scanning if we are disconnected!
        if (client_inst.csm.state == .disconnected) {
            std.log.info("CSM disconnected. Initiating BLE scanning...", .{});
            nimble_layer.startScanning();
        }
        return;
    }

    const cmd = queue_inst.getFront().?;
    std.log.info("Processing command ID {d}: domain={d}, action={d}", .{ cmd.id, cmd.domain, cmd.action });

    if (cmd.domain == 3 and !client_inst.session_infotainment.is_valid) {
        std.log.info("Infotainment session not ready; requesting SessionInfo before command", .{});
        sendHandshakeRequest(.infotainment);
        return;
    }

    const r = @import("c_bindings.zig").TeslaRandom.random();
    var len: usize = 0;

    if (cmd.action == 1) {
        len = client_inst.buildRkeActionMessage(r, getSeconds(), 1, &tx_command_buf) catch |err| {
            std.log.err("Failed to build Lock message: {any}", .{err});
            return;
        };
    } else if (cmd.action == 0) {
        len = client_inst.buildRkeActionMessage(r, getSeconds(), 0, &tx_command_buf) catch |err| {
            std.log.err("Failed to build Unlock message: {any}", .{err});
            return;
        };
    } else if (cmd.action == 30) {
        len = client_inst.buildRkeActionMessage(r, getSeconds(), 30, &tx_command_buf) catch |err| {
            std.log.err("Failed to build Wake message: {any}", .{err});
            return;
        };
    } else if (cmd.action == 31) {
        len = client_inst.buildClosureMoveRequestMessage(r, getSeconds(), 0, 1, &tx_command_buf) catch |err| {
            std.log.err("Failed to build Frunk message: {any}", .{err});
            return;
        };
    } else if (cmd.domain == 3 and cmd.action == 26) {
        std.log.info("Building Flash Lights infotainment message...", .{});
        len = client_inst.buildFlashLightsMessage(r, getSeconds(), &tx_command_buf) catch |err| {
            std.log.err("Failed to build Flash Lights message: {any}", .{err});
            return;
        };
        std.log.info("Built Flash Lights message ({d} bytes).", .{len});
    } else {
        std.log.err("Unknown action {d}", .{cmd.action});
        queue_inst.popFront();
        return;
    }

    std.log.info("Sending secure command BLE packet ({d} bytes)...", .{len});
    nimble_layer.writeTxCharacteristic(tx_command_buf[0..len]);

    cmd.state = .waiting_for_response;
    queue_inst.popFront();

    if (cmd.action == 1) {
        publishStateUpdate("state/lock", "LOCKED");
    } else if (cmd.action == 0) {
        publishStateUpdate("state/lock", "UNLOCKED");
    }
}

fn publishStateUpdate(subtopic: []const u8, payload: []const u8) void {
    var topic_buf: [256]u8 = undefined;
    const topic = std.fmt.bufPrintZ(&topic_buf, "tesla_ble/{s}/{s}", .{ vehicle_vin, subtopic }) catch return;
    tesla_c_mqtt_publish(topic, payload.ptr, payload.len, 1, 1);
}
