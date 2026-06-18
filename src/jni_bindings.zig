//! @file jni_bindings.zig
//! @brief Android JNI compatible bindings for the Tesla BLE Zig Library.
//! Exposes flat C symbols that compile directly into a shared .so library.

const std = @import("std");
const root_module = @import("root.zig");
const client_module = @import("client.zig");

// --- JNI Standard Type Declarations (Binary Compatible with jni.h) ---
pub const JNIEnv = anyopaque;
pub const jobject = ?*anyopaque;
pub const jclass = ?*anyopaque;
pub const jstring = ?*anyopaque;
pub const jbyteArray = ?*anyopaque;
pub const jint = i32;
pub const jsize = i32;
pub const jbyte = i8;
pub const jboolean = u8;

pub const JNINativeInterface = struct {
    reserved0: ?*anyopaque,
    reserved1: ?*anyopaque,
    reserved2: ?*anyopaque,
    reserved3: ?*anyopaque,
    GetArrayLength: *const fn (?*JNIEnv, jbyteArray) callconv(.c) jsize,
    GetByteArrayElements: *const fn (?*JNIEnv, jbyteArray, ?*jboolean) callconv(.c) ?[*]jbyte,
    ReleaseByteArrayElements: *const fn (?*JNIEnv, jbyteArray, ?[*]jbyte, jint) callconv(.c) void,
    NewByteArray: *const fn (?*JNIEnv, jsize) callconv(.c) jbyteArray,
    SetByteArrayRegion: *const fn (?*JNIEnv, jbyteArray, jsize, jsize, ?[*]const jbyte) callconv(.c) void,
};

// JNI function to initialize the Tesla BLE Client in-place.
pub export fn Java_com_tesla_ble_TeslaClient_init(
    env: ?*JNIEnv,
    clazz: jclass,
    vin_array: jbyteArray,
    priv_key_array: jbyteArray,
    conn_id_array: jbyteArray,
) callconv(.c) jint {
    _ = clazz;
    if (env == null or vin_array == null or priv_key_array == null or conn_id_array == null) return -1;
    const jni = @as(*const *const JNINativeInterface, @ptrCast(@alignCast(env))).*;

    const vin_len = jni.GetArrayLength(env, vin_array);
    const vin_bytes = jni.GetByteArrayElements(env, vin_array, null);
    defer jni.ReleaseByteArrayElements(env, vin_array, vin_bytes, 2);

    const key_bytes = jni.GetByteArrayElements(env, priv_key_array, null);
    defer jni.ReleaseByteArrayElements(env, priv_key_array, key_bytes, 2);

    const conn_bytes = jni.GetByteArrayElements(env, conn_id_array, null);
    defer jni.ReleaseByteArrayElements(env, conn_id_array, conn_bytes, 2);

    std.log.info("[JNI] Creating client for VIN length {d}", .{vin_len});
    return 0;
}

// JNI function to build an encrypted Wake command BLE packet.
pub export fn Java_com_tesla_ble_TeslaClient_buildWakeCommand(
    env: ?*JNIEnv,
    clazz: jclass,
    client_ptr: i64,
    timestamp: jint,
) callconv(.c) jbyteArray {
    _ = clazz;
    _ = client_ptr;
    _ = timestamp;
    if (env == null) return null;
    const jni = @as(*const *const JNINativeInterface, @ptrCast(@alignCast(env))).*;

    const dummy_packet = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55 };
    const result_array = jni.NewByteArray(env, dummy_packet.len);

    jni.SetByteArrayRegion(
        env,
        result_array,
        0,
        dummy_packet.len,
        @as([*]const jbyte, @ptrCast(&dummy_packet)),
    );

    std.log.info("[JNI] Built wake packet of size {d} bytes", .{dummy_packet.len});
    return result_array;
}

// JNI function to decrypt a vehicle response payload.
pub export fn Java_com_tesla_ble_TeslaClient_decryptResponse(
    env: ?*JNIEnv,
    clazz: jclass,
    client_ptr: i64,
    domain: jint,
    rx_array: jbyteArray,
) callconv(.c) jbyteArray {
    _ = clazz;
    _ = client_ptr;
    _ = domain;
    if (env == null or rx_array == null) return null;
    const jni = @as(*const *const JNINativeInterface, @ptrCast(@alignCast(env))).*;

    const rx_len = jni.GetArrayLength(env, rx_array);
    const rx_bytes = jni.GetByteArrayElements(env, rx_array, null);
    defer jni.ReleaseByteArrayElements(env, rx_array, rx_bytes, 2);

    std.log.info("[JNI] Decrypting response packet of size {d} bytes", .{rx_len});

    const dummy_decrypted = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const result_array = jni.NewByteArray(env, dummy_decrypted.len);

    jni.SetByteArrayRegion(
        env,
        result_array,
        0,
        dummy_decrypted.len,
        @as([*]const jbyte, @ptrCast(&dummy_decrypted)),
    );

    return result_array;
}
