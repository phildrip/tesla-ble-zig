//! Command Queue module for tracking and prioritizing secure BLE commands in a zero-allocation ring buffer.
const std = @import("std");

/// Lifecycle states of a queued BLE command.
pub const CommandState = enum(u8) {
    idle = 0,
    waiting_for_vcsec_auth = 1,
    waiting_for_vcsec_auth_response = 2,
    waiting_for_infotainment_auth = 3,
    waiting_for_infotainment_auth_response = 4,
    waiting_for_wake = 5,
    waiting_for_wake_response = 6,
    waiting_for_lock_response = 7,
    ready = 8,
    waiting_for_response = 9,
    waiting_for_get_post_set = 10,
};

/// Structure representing a queued secure command.
pub const Command = struct {
    domain: u32,
    action: u32,
    id: u32,
    state: CommandState,
    started_at: u32,
    last_tx_at: u32,
    retry_count: u8,
    done_times: u16,
};

/// Zero-allocation, static circular buffer for command queuing.
pub const CommandQueue = struct {
    commands: [32]Command,
    head: usize,
    count: usize,
    next_id: u32,

    /// Initialize a new empty command queue.
    pub fn init() CommandQueue {
        return .{
            .commands = undefined,
            .head = 0,
            .count = 0,
            .next_id = 1,
        };
    }

    /// Return current number of elements in the queue.
    pub fn size(self: *const CommandQueue) usize {
        return self.count;
    }

    /// Check if the queue is empty.
    pub fn empty(self: *const CommandQueue) bool {
        return self.count == 0;
    }

    /// Get a mutable pointer to the front-most command in the queue.
    pub fn getFront(self: *CommandQueue) ?*Command {
        if (self.count == 0) return null;
        return &self.commands[self.head];
    }

    /// Retrieve a command pointer by its unique identifier.
    pub fn getById(self: *CommandQueue, id: u32) ?*Command {
        if (self.count == 0) return null;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + i) % self.commands.len;
            if (self.commands[idx].id == id) {
                return &self.commands[idx];
            }
        }
        return null;
    }

    /// Retrieve a command pointer by its array position (0-indexed from head).
    pub fn getAt(self: *CommandQueue, index: usize) ?*Command {
        if (index >= self.count) return null;
        const idx = (self.head + index) % self.commands.len;
        return &self.commands[idx];
    }

    /// Append a new command to the back of the queue.
    pub fn pushBack(self: *CommandQueue, domain: u32, action: u32, current_time: u32) !u32 {
        if (self.count >= self.commands.len) return error.QueueFull;
        const id = self.next_id;
        self.next_id = if (self.next_id == 0xffffffff) 1 else self.next_id + 1;

        const tail = (self.head + self.count) % self.commands.len;
        self.commands[tail] = .{
            .domain = domain,
            .action = action,
            .id = id,
            .state = .idle,
            .started_at = current_time,
            .last_tx_at = 0,
            .retry_count = 0,
            .done_times = 0,
        };
        self.count += 1;
        return id;
    }

    /// Remove the front-most command from the queue.
    pub fn popFront(self: *CommandQueue) void {
        if (self.count == 0) return;
        self.head = (self.head + 1) % self.commands.len;
        self.count -= 1;
    }

    /// Prioritized placement: inserts command at front (index 0) if the current front is inactive (idle),
    /// or second (index 1) if the current front command is already active and in progress.
    pub fn placeAtFront(self: *CommandQueue, domain: u32, action: u32, current_time: u32) !u32 {
        if (self.count >= self.commands.len) return error.QueueFull;
        const id = self.next_id;
        self.next_id = if (self.next_id == 0xffffffff) 1 else self.next_id + 1;

        if (self.count == 0) {
            const idx = self.head;
            self.commands[idx] = .{
                .domain = domain,
                .action = action,
                .id = id,
                .state = .idle,
                .started_at = current_time,
                .last_tx_at = 0,
                .retry_count = 0,
                .done_times = 0,
            };
            self.count = 1;
            return id;
        }

        const front = self.getFront().?;
        if (front.state == .idle) {
            // Slide everything to the right by 1 element to insert at self.head
            var i: usize = self.count;
            while (i > 0) : (i -= 1) {
                const src = (self.head + i - 1) % self.commands.len;
                const dst = (self.head + i) % self.commands.len;
                self.commands[dst] = self.commands[src];
            }
            self.commands[self.head] = .{
                .domain = domain,
                .action = action,
                .id = id,
                .state = .idle,
                .started_at = current_time,
                .last_tx_at = 0,
                .retry_count = 0,
                .done_times = 0,
            };
            self.count += 1;
        } else {
            // Front in-progress, insert at second position (index 1 from head)
            var i: usize = self.count;
            while (i > 1) : (i -= 1) {
                const src = (self.head + i - 1) % self.commands.len;
                const dst = (self.head + i) % self.commands.len;
                self.commands[dst] = self.commands[src];
            }
            const second_idx = (self.head + 1) % self.commands.len;
            self.commands[second_idx] = .{
                .domain = domain,
                .action = action,
                .id = id,
                .state = .idle,
                .started_at = current_time,
                .last_tx_at = 0,
                .retry_count = 0,
                .done_times = 0,
            };
            self.count += 1;
        }
        return id;
    }
};

test "CommandQueue - Basic Push/Pop & IDs" {
    var q = CommandQueue.init();
    try std.testing.expectEqual(@as(usize, 0), q.size());
    try std.testing.expect(q.empty());

    const id1 = try q.pushBack(2, 42, 1000);
    try std.testing.expectEqual(@as(u32, 1), id1);
    try std.testing.expectEqual(@as(usize, 1), q.size());

    const id2 = try q.pushBack(3, 84, 1100);
    try std.testing.expectEqual(@as(u32, 2), id2);
    try std.testing.expectEqual(@as(usize, 2), q.size());

    const front = q.getFront().?;
    try std.testing.expectEqual(@as(u32, 1), front.id);
    try std.testing.expectEqual(@as(u32, 2), front.domain);
    try std.testing.expectEqual(@as(u32, 42), front.action);
    try std.testing.expectEqual(CommandState.idle, front.state);

    q.popFront();
    try std.testing.expectEqual(@as(usize, 1), q.size());

    const front2 = q.getFront().?;
    try std.testing.expectEqual(@as(u32, 2), front2.id);
}

test "CommandQueue - Priorities (placeAtFront)" {
    var q = CommandQueue.init();

    // 1. Priority insertion on empty queue should put it at front (index 0)
    const p1 = try q.placeAtFront(2, 1, 100);
    try std.testing.expectEqual(@as(u32, 1), p1);
    try std.testing.expectEqual(@as(usize, 1), q.size());
    try std.testing.expectEqual(@as(u32, 1), q.getAt(0).?.action);

    // 2. Priority insertion with idle front should put new command at front, moving p1 to index 1
    const p2 = try q.placeAtFront(2, 2, 105);
    try std.testing.expectEqual(@as(u32, 2), p2);
    try std.testing.expectEqual(@as(usize, 2), q.size());
    try std.testing.expectEqual(@as(u32, 2), q.getAt(0).?.action);
    try std.testing.expectEqual(@as(u32, 1), q.getAt(1).?.action);

    // 3. Mark front command as active
    q.getAt(0).?.state = .waiting_for_vcsec_auth;

    // 4. Priority insertion with active front command should insert new command at index 1, pushing index 1 (action 1) to index 2
    const p3 = try q.placeAtFront(2, 3, 110);
    try std.testing.expectEqual(@as(u32, 3), p3);
    try std.testing.expectEqual(@as(usize, 3), q.size());
    
    try std.testing.expectEqual(@as(u32, 2), q.getAt(0).?.action); // Still front and in progress
    try std.testing.expectEqual(@as(u32, 3), q.getAt(1).?.action); // Priority insertion placed second
    try std.testing.expectEqual(@as(u32, 1), q.getAt(2).?.action); // Old idle command pushed third
}
