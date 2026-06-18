//! Bare-metal safe Zig implementation of the Tesla BLE key-fob control protocol.
const std = @import("std");
const builtin = @import("builtin");

pub const protocol = @import("protocol.zig");
pub const crypto = @import("crypto.zig");
pub const session = @import("session.zig");
pub const protobuf = @import("protobuf.zig");
pub const client = @import("client.zig");
pub const c_bindings = @import("c_bindings.zig");
pub const csm = @import("csm.zig");
pub const scheduler = @import("scheduler.zig");
pub const queue = @import("queue.zig");
pub const firmware = @import("firmware.zig");
pub const nimble = @import("nimble.zig");
pub const jni = @import("jni_bindings.zig");

test {
    // Reference tests to ensure they are built and executed by the build runner
    std.testing.refAllDecls(@This());
}

// Mock C-bindings when compiling native tests to satisfy the linker
// without needing ESP-IDF.
pub const mocks = if (builtin.is_test) struct {
    export fn tesla_c_wifi_init(ssid: [*:0]const u8, password: [*:0]const u8) void {
        _ = ssid; _ = password;
    }
    export fn tesla_c_mqtt_init(broker_url: [*:0]const u8) void {
        _ = broker_url;
    }
    export fn tesla_c_mqtt_publish(topic: [*:0]const u8, payload: [*]const u8, len: usize, qos: i32, retain: i32) void {
        _ = topic; _ = payload; _ = len; _ = qos; _ = retain;
    }
    export fn tesla_c_mqtt_subscribe(topic: [*:0]const u8, qos: i32) void {
        _ = topic; _ = qos;
    }
    export fn esp_timer_get_time() callconv(.c) i64 {
        return 0;
    }
    export fn tesla_c_ble_init() void {}
    export fn tesla_c_ble_start_scan() void {}
    export fn tesla_c_ble_connect(addr: *const anyopaque) void {
        _ = addr;
    }
    export fn tesla_c_ble_write_tx(conn_handle: u16, data: [*]const u8, len: usize) void {
        _ = conn_handle; _ = data; _ = len;
    }
} else struct {};
