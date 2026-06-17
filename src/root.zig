//! Bare-metal safe Zig implementation of the Tesla BLE key-fob control protocol.
const std = @import("std");

pub const protocol = @import("protocol.zig");
pub const crypto = @import("crypto.zig");
pub const session = @import("session.zig");
pub const protobuf = @import("protobuf.zig");
pub const client = @import("client.zig");
pub const c_bindings = @import("c_bindings.zig");
pub const csm = @import("csm.zig");
pub const scheduler = @import("scheduler.zig");

test {
    // Reference tests to ensure they are built and executed by the build runner
    std.testing.refAllDecls(@This());
}
