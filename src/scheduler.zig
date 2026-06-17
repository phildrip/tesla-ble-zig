const std = @import("std");

pub const ChargingState = enum(u8) {
    not_charging = 0,
    charging_just_started = 1,
    charging_ongoing = 2,
};

pub const CarWakeState = enum(u8) {
    no = 0,
    yes_initial = 1,
    yes_polling = 2,
};

pub const SchedulerConfig = struct {
    post_wake_poll_time_ms: u32,
    poll_data_period_ms: u32,
    poll_asleep_period_ms: u32,
    poll_charging_period_ms: u32,
    fast_poll_if_unlocked: bool,
    wake_on_boot: bool,
};

pub const Decisions = struct {
    should_poll_vcsec: bool,
    should_poll_infotainment: bool,
    should_wake_vehicle: bool,
    clear_one_off_update: bool,
};

pub const Scheduler = struct {
    config: SchedulerConfig,

    // Timestamps
    last_vcsec_poll_time: u32 = 0,
    last_infotainment_poll_time: u32 = 0,
    car_wake_time: u32 = 0,

    // State
    car_just_woken: CarWakeState = .no,
    previous_asleep_state: bool = false,
    car_is_charging: ChargingState = .not_charging,
    esp32_just_started: u8 = 0,
    number_updates_since_connection: u32 = 0,

    pub fn init(config: SchedulerConfig) Scheduler {
        return Scheduler{
            .config = config,
        };
    }

    pub fn tick(
        self: *Scheduler,
        current_time_ms: u32,
        is_asleep: bool,
        is_unlocked: bool,
        is_user_present: bool,
        one_off_update: bool,
    ) Decisions {
        // --- 1. VCSEC Polling Logic ---
        var should_poll_vcsec = false;
        if (!is_asleep) {
            should_poll_vcsec = true;
        } else if (self.config.poll_asleep_period_ms != 0) {
            if (self.last_vcsec_poll_time == 0 or (current_time_ms - self.last_vcsec_poll_time) > self.config.poll_asleep_period_ms) {
                should_poll_vcsec = true;
            }
        } else if (self.last_vcsec_poll_time == 0) {
            should_poll_vcsec = true;
        }

        if (should_poll_vcsec) {
            self.last_vcsec_poll_time = current_time_ms;
        }

        // --- 2. ESP32 Boot Wake Logic ---
        var should_wake_vehicle = false;
        switch (self.esp32_just_started) {
            0, 1 => {
                self.esp32_just_started += 1;
            },
            2 => {
                if (self.config.wake_on_boot) {
                    should_wake_vehicle = true;
                }
                self.esp32_just_started += 1;
            },
            else => {},
        }

        // --- 3. Wake / Sleep Transition logic ---
        if (!is_asleep and self.previous_asleep_state) {
            self.car_just_woken = .yes_initial;
            self.car_wake_time = current_time_ms;
        }
        if (is_asleep and !self.previous_asleep_state) {
            self.car_is_charging = .not_charging;
        }
        self.previous_asleep_state = is_asleep;

        // --- 4. Infotainment Polling Logic ---
        var do_poll = false;
        if (one_off_update or (is_unlocked and self.config.fast_poll_if_unlocked) or is_user_present) {
            do_poll = true;
        } else if (self.car_is_charging != .not_charging) {
            if (self.car_is_charging == .charging_just_started) {
                do_poll = true;
                self.car_is_charging = .charging_ongoing;
            } else if ((current_time_ms - self.last_infotainment_poll_time) > self.config.poll_charging_period_ms) {
                do_poll = true;
            }
        } else if (self.car_just_woken != .no) {
            if (self.car_just_woken == .yes_initial) {
                do_poll = true;
                self.car_just_woken = .yes_polling;
            } else if ((current_time_ms - self.last_infotainment_poll_time) > self.config.poll_data_period_ms) {
                do_poll = true;
            }
        } else if (self.config.poll_asleep_period_ms != 0) {
            if ((current_time_ms - self.last_infotainment_poll_time) > self.config.poll_asleep_period_ms) {
                do_poll = true;
            }
        }

        var should_poll_infotainment = false;
        var clear_one_off_update = false;

        if (do_poll) {
            self.last_infotainment_poll_time = current_time_ms;
            should_poll_infotainment = true;

            if (self.car_just_woken != .no) {
                if ((current_time_ms - self.car_wake_time) > self.config.post_wake_poll_time_ms) {
                    self.car_just_woken = .no;
                }
            }
            clear_one_off_update = true;
            self.number_updates_since_connection += 1;
        }

        return Decisions{
            .should_poll_vcsec = should_poll_vcsec,
            .should_poll_infotainment = should_poll_infotainment,
            .should_wake_vehicle = should_wake_vehicle,
            .clear_one_off_update = clear_one_off_update,
        };
    }
};

test "Scheduler - Basic Boot and VCSEC Polling" {
    const config = SchedulerConfig{
        .post_wake_poll_time_ms = 10000,
        .poll_data_period_ms = 5000,
        .poll_asleep_period_ms = 30000,
        .poll_charging_period_ms = 15000,
        .fast_poll_if_unlocked = true,
        .wake_on_boot = true,
    };
    var scheduler = Scheduler.init(config);

    // Initial state: Boot cycle 0
    var dec = scheduler.tick(100, true, false, false, false);
    try std.testing.expectEqual(true, dec.should_poll_vcsec);
    try std.testing.expectEqual(false, dec.should_poll_infotainment);
    try std.testing.expectEqual(false, dec.should_wake_vehicle);

    // Boot cycle 1
    dec = scheduler.tick(200, true, false, false, false);
    try std.testing.expectEqual(false, dec.should_wake_vehicle);

    // Boot cycle 2 -> should wake vehicle
    dec = scheduler.tick(300, true, false, false, false);
    try std.testing.expectEqual(true, dec.should_wake_vehicle);

    // Subsequent cycles -> no wake
    dec = scheduler.tick(400, true, false, false, false);
    try std.testing.expectEqual(false, dec.should_wake_vehicle);
}

test "Scheduler - Infotainment Polling on Wake transition" {
    const config = SchedulerConfig{
        .post_wake_poll_time_ms = 10000,
        .poll_data_period_ms = 5000,
        .poll_asleep_period_ms = 30000,
        .poll_charging_period_ms = 15000,
        .fast_poll_if_unlocked = true,
        .wake_on_boot = true,
    };
    var scheduler = Scheduler.init(config);
    scheduler.previous_asleep_state = true;

    // Transition from asleep to awake
    var dec = scheduler.tick(1000, false, false, false, false);
    try std.testing.expectEqual(true, dec.should_poll_infotainment); // Immediately poll on wake
    try std.testing.expectEqual(.yes_polling, scheduler.car_just_woken);

    // Try ticking again before poll_data_period_ms has elapsed -> should not poll
    dec = scheduler.tick(2000, false, false, false, false);
    try std.testing.expectEqual(false, dec.should_poll_infotainment);

    // Tick after poll_data_period_ms (5000ms) has elapsed -> should poll again
    dec = scheduler.tick(7000, false, false, false, false);
    try std.testing.expectEqual(true, dec.should_poll_infotainment);

    // Try ticking after post_wake_poll_time_ms has expired (10000ms from 1000ms) and another poll cycle is triggered (at 13000ms) -> should set car_just_woken back to .no
    _ = scheduler.tick(13000, false, false, false, false);
    try std.testing.expectEqual(.no, scheduler.car_just_woken);
}

