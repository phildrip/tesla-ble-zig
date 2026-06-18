//! @file nimble.zig
//! @brief NimBLE Bluetooth Low Energy client wrapper written in pure Zig.

const std = @import("std");
const builtin = @import("builtin");

// Externs for C wrapper functions in main.c
extern fn tesla_c_ble_init() void;
extern fn tesla_c_ble_start_scan() void;
extern fn tesla_c_ble_connect(addr: *const anyopaque) void;
extern fn tesla_c_ble_write_tx(conn_handle: u16, data: [*]const u8, len: usize) void;

// Tesla Service UUID definitions
pub const TESLA_SERVICE_UUID128 = "00000211-b2d1-43f0-9b88-960cebf8b91e";
pub const TESLA_CHAR_TX_UUID128  = "00000212-b2d1-43f0-9b88-960cebf8b91e";
pub const TESLA_CHAR_RX_UUID128  = "00000213-b2d1-43f0-9b88-960cebf8b91e";

var target_conn_handle: u16 = 0;

// Initialize the NimBLE Bluetooth host stack.
pub fn initNimble() void {
    if (builtin.os.tag != .freestanding) {
        std.log.info("[Mock BLE] NimBLE stack initialized.", .{});
        return;
    }
    tesla_c_ble_init();
}

// Start passive BLE scanning to locate the Tesla vehicle.
pub fn startScanning() void {
    if (builtin.os.tag != .freestanding) return;
    tesla_c_ble_start_scan();
}

// -------------------------------------------------------------
// Callbacks invoked by C-Glue layer
// -------------------------------------------------------------

pub export fn tesla_zig_ble_on_vehicle_discovered(ble_addr: *const anyopaque) callconv(.c) void {
    std.log.info("[BLE callback] Tesla vehicle discovered! Connecting...", .{});
    tesla_c_ble_connect(ble_addr);
}

pub export fn tesla_zig_ble_on_connected(conn_handle: u16) callconv(.c) void {
    target_conn_handle = conn_handle;
    std.log.info("[BLE callback] Connected successfully! Conn Handle: {d}", .{conn_handle});
    
    const firmware = @import("firmware.zig");
    if (firmware.is_initialized) {
        firmware.client_inst.handleBleConnected(firmware.getMillis());
    }
}

pub export fn tesla_zig_ble_on_channel_ready() callconv(.c) void {
    std.log.info("[BLE callback] GATT channel ready! Initiating handshake...", .{});
    const firmware = @import("firmware.zig");
    if (firmware.is_initialized) {
        firmware.sendHandshakeRequest(.vehicle_security);
    }
}

pub export fn tesla_zig_ble_on_disconnected() callconv(.c) void {
    std.log.warn("[BLE callback] Disconnected from vehicle. Restarting scan...", .{});
    target_conn_handle = 0;
    
    const firmware = @import("firmware.zig");
    if (firmware.is_initialized) {
        firmware.client_inst.handleBleDisconnected(firmware.getMillis());
    }
    
    startScanning();
}

pub export fn tesla_zig_ble_on_rx_notification(data_ptr: [*]const u8, len: usize) callconv(.c) void {
    const payload = data_ptr[0..len];
    std.log.info("[BLE callback] Received {d} bytes notification: {x}", .{ len, payload });
    onRxNotificationReceived(payload);
}

// Write bytes to the Tesla VCSEC Tx Characteristic.
pub fn writeTxCharacteristic(payload: []const u8) void {
    if (builtin.os.tag != .freestanding) {
        std.log.info("[Mock BLE TX] Writing {d} bytes to vehicle: {x}", .{payload.len, payload});
        return;
    }
    if (target_conn_handle == 0) return;
    tesla_c_ble_write_tx(target_conn_handle, payload.ptr, payload.len);
    std.log.info("[BLE TX] Transmitted {d} bytes to vehicle characteristic", .{payload.len});
}

// Callback fired when notifications from the vehicle's RX characteristic are received.
pub fn onRxNotificationReceived(payload: []const u8) void {
    std.log.info("[BLE RX] Received {d} bytes notification from vehicle", .{payload.len});
    const firmware = @import("firmware.zig");
    if (firmware.is_initialized) {
        firmware.handleRxNotification(payload);
    }
}
