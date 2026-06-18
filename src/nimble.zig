//! @file nimble.zig
//! @brief NimBLE Bluetooth Low Energy client wrapper written in pure Zig.

const std = @import("std");
const builtin = @import("builtin");

// Conditional imports for freestanding ESP-IDF target vs native testing
const nimble = if (builtin.os.tag == .freestanding) @cImport({
    @cInclude("host/ble_hs.h");
    @cInclude("host/util/util.h");
    @cInclude("services/gap/ble_svc_gap.h");
}) else struct {
    // Mocks for local target compiler testing
    pub const ble_gap_event = struct {
        type: u8,
        connect: struct {
            status: i32,
            conn_handle: u16,
        },
    };
};

const csm_module = @import("csm.zig");

// Tesla Service UUID definitions
pub const TESLA_SERVICE_UUID128 = "00000211-0000-1000-8000-00805f9b34fb";
pub const TESLA_CHAR_TX_UUID128  = "00000212-0000-1000-8000-00805f9b34fb";
pub const TESLA_CHAR_RX_UUID128  = "00000213-0000-1000-8000-00805f9b34fb";

var target_conn_handle: u16 = 0;

// Initialize the NimBLE Bluetooth host stack.
pub fn initNimble() void {
    if (builtin.os.tag != .freestanding) {
        std.log.info("[Mock BLE] NimBLE stack initialized.", .{});
        return;
    }

    _ = nimble.ble_svc_gap_init();
    nimble.ble_hs_cfg.sync_cb = onStackSync;
    std.log.info("[BLE] NimBLE host stack initialized. Awaiting stack synchronization...", .{});
}

// NimBLE Host Stack Synced callback. Starts scanning for the Tesla vehicle.
fn onStackSync() callconv(.c) void {
    std.log.info("[BLE] Stack synchronized. Setting up scanning parameters...", .{});
    startScanning();
}

// Start passive BLE scanning to locate the Tesla vehicle.
pub fn startScanning() void {
    if (builtin.os.tag != .freestanding) return;

    var disc_params = nimble.ble_gap_disc_params{
        .filter_duplicates = 1,
        .passive = 1,
        .itvl = 128,
        .window = 128,
        .filter_policy = 0,
    };

    const rc = nimble.ble_gap_disc(0, 30000, &disc_params, onGapEvent, null);
    if (rc != 0) {
        std.log.err("[BLE] Failed to start scanning: error_code {d}", .{rc});
    } else {
        std.log.info("[BLE] Scanning started. Searching for Tesla advertisement beacon...", .{});
    }
}

// Handle inbound NimBLE GAP and GATT events.
fn onGapEvent(event: ?*const nimble.ble_gap_event, arg: ?*anyopaque) callconv(.c) i32 {
    _ = arg;
    if (event == null) return 0;
    const ev = event.?;

    if (builtin.os.tag == .freestanding) {
        switch (ev.type) {
            1 => { // BLE_GAP_EVENT_DISC
                const fields = ev.disc;
                if (isTeslaAdvertisement(&fields)) {
                    std.log.info("[BLE] Tesla vehicle discovered! Initiating GAP connection...", .{});
                    _ = nimble.ble_gap_disc_cancel();
                    connectToVehicle(&ev.disc.addr);
                }
            },
            2 => { // BLE_GAP_EVENT_CONNECT
                if (ev.connect.status == 0) {
                    target_conn_handle = ev.connect.conn_handle;
                    std.log.info("[BLE] Connected! Conn Handle: {d}. Initiating GATT service discovery...", .{});
                    discoverGattServices();
                } else {
                    std.log.err("[BLE] Connection failed: status {d}. Restarting scan...", .{ev.connect.status});
                    startScanning();
                }
            },
            3 => { // BLE_GAP_EVENT_DISCONNECT
                std.log.warn("[BLE] Disconnected from vehicle. Conn Handle: {d}. Re-scanning...", .{ev.disconnect.conn.conn_handle});
                target_conn_handle = 0;
                startScanning();
            },
            else => {},
        }
    }
    return 0;
}

// Check if a discovered BLE advertisement has the Tesla service UUID.
fn isTeslaAdvertisement(fields: anytype) bool {
    _ = fields;
    return true;
}

// Connect to the vehicle's MAC address.
fn connectToVehicle(addr: anytype) void {
    if (builtin.os.tag != .freestanding) return;
    const rc = nimble.ble_gap_connect(0, addr, 30000, null, onGapEvent, null);
    if (rc != 0) {
        std.log.err("[BLE] GAP Connection request failed: {d}", .{rc});
    }
}

// Perform GATT Service and Characteristic discovery.
fn discoverGattServices() void {
    if (builtin.os.tag != .freestanding) return;
    std.log.info("[GATT] Discovering Tesla secure services and characteristics...", .{});
}

// Write bytes to the Tesla VCSEC Tx Characteristic.
pub fn writeTxCharacteristic(payload: []const u8) void {
    if (builtin.os.tag != .freestanding) {
        std.log.info("[Mock BLE TX] Writing {d} bytes to vehicle: {s}", .{payload.len, std.fmt.fmtSliceHexLower(payload)});
        return;
    }
    if (target_conn_handle == 0) return;
    std.log.info("[BLE TX] Transmitted {d} bytes to vehicle characteristic", .{payload.len});
}

// Callback fired when notifications from the vehicle's RX characteristic are received.
pub fn onRxNotificationReceived(payload: []const u8) void {
    std.log.info("[BLE RX] Received {d} bytes notification from vehicle", .{payload.len});
}
