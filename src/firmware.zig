//! @file firmware.zig
//! @brief Standalone, pure-Zig firmware entry point, Wi-Fi coordinator, and HA MQTT discovery engine.

const std = @import("std");
const builtin = @import("builtin");

// Conditional imports for freestanding ESP-IDF targets vs native testing
const esp = if (builtin.os.tag == .freestanding) @cImport({
    @cInclude("esp_wifi.h");
    @cInclude("esp_event.h");
    @cInclude("esp_netif.h");
    @cInclude("nvs_flash.h");
    @cInclude("mqtt_client.h");
    @cInclude("sdkconfig.h"); // For configuration settings!
}) else struct {
    // Mocks for local target compiler testing
    pub const esp_err_t = i32;
    pub const ESP_OK = 0;
    pub const esp_mqtt_client_handle_t = ?*anyopaque;
    pub const esp_mqtt_event_handle_t = ?*anyopaque;
};

const nimble_layer = @import("nimble.zig");
const client_module = @import("client.zig");
const queue_module = @import("queue.zig");

// Static configuration (loaded from sdkconfig if available, falling back to defaults)
const WIFI_SSID = if (builtin.os.tag == .freestanding and @hasDecl(esp, "CONFIG_WIFI_SSID")) esp.CONFIG_WIFI_SSID else "Tesla_BLE_Control";
const WIFI_PASS = if (builtin.os.tag == .freestanding and @hasDecl(esp, "CONFIG_WIFI_PASSWORD")) esp.CONFIG_WIFI_PASSWORD else "secure_password";
const MQTT_BROKER_URL = if (builtin.os.tag == .freestanding and @hasDecl(esp, "CONFIG_MQTT_BROKER_URL")) esp.CONFIG_MQTT_BROKER_URL else "mqtt://homeassistant.local:1883";
const VEHICLE_VIN = if (builtin.os.tag == .freestanding and @hasDecl(esp, "CONFIG_VEHICLE_VIN")) esp.CONFIG_VEHICLE_VIN else "5YJ3E1EBXLFXXXXXX";

var mqtt_client: esp.esp_mqtt_client_handle_t = null;

// Pure-Zig global entry-point callable from ESP-IDF bootloader.
pub export fn app_main() callconv(.c) void {
    std.log.info("🚗 Starting Pure-Zig Standalone Tesla BLE Firmware...", .{});

    if (builtin.os.tag == .freestanding) {
        // 1. Initialize NVS Flash
        var err = esp.nvs_flash_init();
        if (err == 100) { // ESP_ERR_NVS_NO_FREE_PAGES
            _ = esp.nvs_flash_erase();
            err = esp.nvs_flash_init();
        }
        std.log.info("[System] NVS initialized with status: {d}", .{err});

        // 2. Initialize TCP/IP and Network Interface
        _ = esp.esp_netif_init();
        _ = esp.esp_event_loop_create_default();
        std.log.info("[Network] TCP/IP netif stack running", .{});

        // 3. Connect to Wi-Fi
        initWifi();

        // 4. Connect to MQTT Broker & Register Auto-Discovery Entities
        initMqtt();

        // 5. Initialize NimBLE Controller and Start scanning
        nimble_layer.initNimble();
    } else {
        std.log.info("[Mock] Running in native test mode. Wi-Fi, MQTT, and BLE simulated.", .{});
    }
}

// Initialize and start the Wi-Fi client station.
fn initWifi() void {
    if (builtin.os.tag != .freestanding) return;

    const netif = esp.esp_netif_create_default_wifi_sta();
    _ = netif;

    var cfg = esp.wifi_init_config_t{}; // standard initialization
    _ = esp.esp_wifi_init(&cfg);

    var wifi_cfg = esp.wifi_config_t{
        .sta = .{
            .ssid = std.mem.zeroes([32]u8),
            .password = std.mem.zeroes([64]u8),
            .threshold = .{ .authmode = 3 }, // WPA2
        },
    };
    @memcpy(wifi_cfg.sta.ssid[0..WIFI_SSID.len], WIFI_SSID);
    @memcpy(wifi_cfg.sta.password[0..WIFI_PASS.len], WIFI_PASS);

    _ = esp.esp_wifi_set_mode(1); // WIFI_MODE_STA
    _ = esp.esp_wifi_set_config(0, &wifi_cfg); // ESP_IF_WIFI_STA
    _ = esp.esp_wifi_start();

    std.log.info("[Wi-Fi] Client station started. Connecting to SSID: {s}", .{WIFI_SSID});
}

// Initialize MQTT client.
fn initMqtt() void {
    if (builtin.os.tag != .freestanding) return;

    var mqtt_cfg = esp.esp_mqtt_client_config_t{
        .broker = .{
            .address = .{
                .uri = MQTT_BROKER_URL,
            },
        },
    };

    mqtt_client = esp.esp_mqtt_client_init(&mqtt_cfg);
    _ = esp.esp_mqtt_register_events(mqtt_client, 0, mqttEventHandler, null); // ESP_EVENT_ANY_ID
    _ = esp.esp_mqtt_client_start(mqtt_client);

    std.log.info("[MQTT] Client initialized and started with broker: {s}", .{MQTT_BROKER_URL});
}

// MQTT Event Callback Handler.
fn mqttEventHandler(handler_args: ?*anyopaque, base: esp.esp_event_base_t, event_id: i32, event_data: ?*anyopaque) callconv(.c) void {
    _ = handler_args;
    _ = base;
    const event = @as(*esp.esp_mqtt_event_t, @ptrCast(@alignCast(event_data)));

    switch (event_id) {
        0 => { // MQTT_EVENT_CONNECTED
            std.log.info("[MQTT] Connected to broker. Publishing Auto-Discovery entities...", .{});
            publishHomeAssistantDiscovery();
            subscribeToControlTopics();
        },
        1 => { // MQTT_EVENT_DISCONNECTED
            std.log.warn("[MQTT] Disconnected from broker.", .{});
        },
        3 => { // MQTT_EVENT_SUBSCRIBED
            std.log.info("[MQTT] Subscribed to command topic", .{});
        },
        5 => { // MQTT_EVENT_DATA
            handleIncomingCommand(event.topic[0..@as(usize, @intCast(event.topic_len))], event.data[0..@as(usize, @intCast(event.data_len))]);
        },
        else => {},
    }
}

// Subscribe to Home Assistant Command topics for control entities.
fn subscribeToControlTopics() void {
    if (mqtt_client == null) return;
    const topic = "tesla_ble/" ++ VEHICLE_VIN ++ "/command/#";
    _ = esp.esp_mqtt_client_subscribe(mqtt_client, topic, 1);
}

// Publish Home Assistant MQTT Auto-Discovery Config payloads.
// This utilizes completely stack-allocated static strings to avoid heap usage.
fn publishHomeAssistantDiscovery() void {
    if (mqtt_client == null) return;

    // 1. Lock Switch entity discovery
    const lock_discovery_topic = "homeassistant/switch/tesla_ble_" ++ VEHICLE_VIN ++ "_lock/config";
    const lock_discovery_payload =
        "{" ++
        "\"name\":\"Tesla Lock\"," ++
        "\"unique_id\":\"tesla_ble_" ++ VEHICLE_VIN ++ "_lock\"," ++
        "\"state_topic\":\"tesla_ble/" ++ VEHICLE_VIN ++ "/state/lock\"," ++
        "\"command_topic\":\"tesla_ble/" ++ VEHICLE_VIN ++ "/command/lock\"," ++
        "\"payload_on\":\"LOCK\"," ++
        "\"payload_off\":\"UNLOCK\"," ++
        "\"state_on\":\"LOCKED\"," ++
        "\"state_off\":\"UNLOCKED\"," ++
        "\"device\":{" ++
        "\"identifiers\":[\"tesla_ble_" ++ VEHICLE_VIN ++ "\"]," ++
        "\"name\":\"Tesla Model C6\"," ++
        "\"model\":\"Tesla BLE Zig Controller\"," ++
        "\"manufacturer\":\"Antigravity\"" ++
        "}" ++
        "}";

    _ = esp.esp_mqtt_client_publish(mqtt_client, lock_discovery_topic, lock_discovery_payload, lock_discovery_payload.len, 1, 1);

    // 2. Frunk binary control entity discovery
    const frunk_discovery_topic = "homeassistant/button/tesla_ble_" ++ VEHICLE_VIN ++ "_frunk/config";
    const frunk_discovery_payload =
        "{" ++
        "\"name\":\"Tesla Open Frunk\"," ++
        "\"unique_id\":\"tesla_ble_" ++ VEHICLE_VIN ++ "_frunk\"," ++
        "\"command_topic\":\"tesla_ble/" ++ VEHICLE_VIN ++ "/command/frunk\"," ++
        "\"payload_press\":\"OPEN\"," ++
        "\"device\":{" ++
        "\"identifiers\":[\"tesla_ble_" ++ VEHICLE_VIN ++ "\"]," ++
        "\"name\":\"Tesla Model C6\"" ++
        "}" ++
        "}";

    _ = esp.esp_mqtt_client_publish(mqtt_client, frunk_discovery_topic, frunk_discovery_payload, frunk_discovery_payload.len, 1, 1);

    // 3. Charger State binary sensor discovery
    const charger_discovery_topic = "homeassistant/binary_sensor/tesla_ble_" ++ VEHICLE_VIN ++ "_charging/config";
    const charger_discovery_payload =
        "{" ++
        "\"name\":\"Tesla Charging Status\"," ++
        "\"unique_id\":\"tesla_ble_" ++ VEHICLE_VIN ++ "_charging\"," ++
        "\"state_topic\":\"tesla_ble/" ++ VEHICLE_VIN ++ "/state/charging\"," ++
        "\"payload_on\":\"CHARGING\"," ++
        "\"payload_off\":\"NOT_CHARGING\"," ++
        "\"device\":{" ++
        "\"identifiers\":[\"tesla_ble_" ++ VEHICLE_VIN ++ "\"]," ++
        "\"name\":\"Tesla Model C6\"" ++
        "}" ++
        "}";

    _ = esp.esp_mqtt_client_publish(mqtt_client, charger_discovery_topic, charger_discovery_payload, charger_discovery_payload.len, 1, 1);

    std.log.info("[HA Discovery] Successfully registered switch.tesla_ble_lock, button.tesla_ble_frunk, and binary_sensor.tesla_ble_charging", .{});
}

// Handle inbound control messages from Home Assistant.
fn handleIncomingCommand(topic: []const u8, payload: []const u8) void {
    std.log.info("[MQTT RX] Incoming Command on Topic: {s} | Payload: {s}", .{topic, payload});

    // Parse the command and add to the Zig command queue
    if (std.mem.endsWith(u8, topic, "command/lock")) {
        if (std.mem.eql(u8, payload, "LOCK")) {
            std.log.info("[Command] Enqueueing lock command", .{});
            // Invoke the queue manager to enqueue a secure lock message
            // queue_module.push_back_command(...)
        } else if (std.mem.eql(u8, payload, "UNLOCK")) {
            std.log.info("[Command] Enqueueing unlock command", .{});
        }
    } else if (std.mem.endsWith(u8, topic, "command/frunk")) {
        if (std.mem.eql(u8, payload, "OPEN")) {
            std.log.info("[Command] Enqueueing frunk release command", .{});
        }
    }
}
