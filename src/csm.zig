//! Connection State Machine (CSM) for managing Tesla BLE secure domain connections.
const std = @import("std");

/// The distinct states of a Tesla BLE vehicle connection.
pub const State = enum(u8) {
    disconnected = 0,
    connecting = 1,
    handshaking_vcsec = 2,
    secure_vcsec = 3,
    handshaking_infotainment = 4,
    fully_secure = 5,
};

/// Events that trigger transitions in the state machine.
pub const Event = enum(u8) {
    connect_requested = 0,
    ble_connected = 1,
    ble_disconnected = 2,
    handshake_success_vcsec = 3,
    handshake_success_infotainment = 4,
    session_expired_vcsec = 5,
    session_expired_infotainment = 6,
    handshake_failed = 7,
};

/// ConnectionStateMachine tracks the active handshake and authentication state
/// for both the VCSEC and Infotainment domains.
pub const ConnectionStateMachine = struct {
    state: State,
    vcsec_handshake_attempts: u8,
    infotainment_handshake_attempts: u8,
    last_state_change_time: u32,

    /// Initialize a new Connection State Machine in the default Disconnected state.
    pub fn init() ConnectionStateMachine {
        return .{
            .state = .disconnected,
            .vcsec_handshake_attempts = 0,
            .infotainment_handshake_attempts = 0,
            .last_state_change_time = 0,
        };
    }

    /// Process a state machine event and update the active state.
    pub fn handleEvent(self: *ConnectionStateMachine, event: Event, current_time: u32) void {
        if (event == .ble_disconnected) {
            self.vcsec_handshake_attempts = 0;
            self.infotainment_handshake_attempts = 0;
            self.transitionTo(.disconnected, current_time);
            return;
        }

        switch (self.state) {
            .disconnected => {
                switch (event) {
                    .connect_requested => self.transitionTo(.connecting, current_time),
                    .ble_connected => self.transitionTo(.handshaking_vcsec, current_time),
                    else => {},
                }
            },
            .connecting => {
                switch (event) {
                    .ble_connected => self.transitionTo(.handshaking_vcsec, current_time),
                    else => {},
                }
            },
            .handshaking_vcsec => {
                switch (event) {
                    .handshake_success_vcsec => {
                        self.vcsec_handshake_attempts = 0;
                        self.transitionTo(.secure_vcsec, current_time);
                    },
                    .handshake_failed => {
                        self.vcsec_handshake_attempts = self.vcsec_handshake_attempts +% 1;
                        self.transitionTo(.connecting, current_time);
                    },
                    else => {},
                }
            },
            .secure_vcsec => {
                switch (event) {
                    .connect_requested => self.transitionTo(.handshaking_infotainment, current_time),
                    .session_expired_vcsec => self.transitionTo(.handshaking_vcsec, current_time),
                    else => {},
                }
            },
            .handshaking_infotainment => {
                switch (event) {
                    .handshake_success_infotainment => {
                        self.infotainment_handshake_attempts = 0;
                        self.transitionTo(.fully_secure, current_time);
                    },
                    .handshake_failed => {
                        self.infotainment_handshake_attempts = self.infotainment_handshake_attempts +% 1;
                        self.transitionTo(.secure_vcsec, current_time);
                    },
                    .session_expired_vcsec => self.transitionTo(.handshaking_vcsec, current_time),
                    else => {},
                }
            },
            .fully_secure => {
                switch (event) {
                    .session_expired_infotainment => self.transitionTo(.handshaking_infotainment, current_time),
                    .session_expired_vcsec => self.transitionTo(.handshaking_vcsec, current_time),
                    else => {},
                }
            },
        }
    }

    fn transitionTo(self: *ConnectionStateMachine, new_state: State, current_time: u32) void {
        self.state = new_state;
        self.last_state_change_time = current_time;
    }
};

test "ConnectionStateMachine State Transitions Verification" {
    var csm = ConnectionStateMachine.init();
    try std.testing.expectEqual(State.disconnected, csm.state);
    try std.testing.expectEqual(@as(u32, 0), csm.last_state_change_time);

    // Disconnected -> Connecting (via connect_requested)
    csm.handleEvent(.connect_requested, 100);
    try std.testing.expectEqual(State.connecting, csm.state);
    try std.testing.expectEqual(@as(u32, 100), csm.last_state_change_time);

    // Connecting -> Handshaking VCSEC (via ble_connected)
    csm.handleEvent(.ble_connected, 105);
    try std.testing.expectEqual(State.handshaking_vcsec, csm.state);
    try std.testing.expectEqual(@as(u32, 105), csm.last_state_change_time);

    // Handshaking VCSEC -> Connecting (via handshake_failed)
    csm.handleEvent(.handshake_failed, 110);
    try std.testing.expectEqual(State.connecting, csm.state);
    try std.testing.expectEqual(@as(u8, 1), csm.vcsec_handshake_attempts);

    // Re-connect and handshake successfully
    csm.handleEvent(.ble_connected, 115);
    csm.handleEvent(.handshake_success_vcsec, 120);
    try std.testing.expectEqual(State.secure_vcsec, csm.state);
    try std.testing.expectEqual(@as(u8, 0), csm.vcsec_handshake_attempts);

    // Secure VCSEC -> Handshaking Infotainment (via connect_requested)
    csm.handleEvent(.connect_requested, 125);
    try std.testing.expectEqual(State.handshaking_infotainment, csm.state);

    // Handshaking Infotainment -> Fully Secure (via handshake_success_infotainment)
    csm.handleEvent(.handshake_success_infotainment, 130);
    try std.testing.expectEqual(State.fully_secure, csm.state);

    // Fully Secure -> Handshaking Infotainment (via session_expired_infotainment)
    csm.handleEvent(.session_expired_infotainment, 135);
    try std.testing.expectEqual(State.handshaking_infotainment, csm.state);

    // Disconnect BLE links entirely
    csm.handleEvent(.ble_disconnected, 140);
    try std.testing.expectEqual(State.disconnected, csm.state);
}
