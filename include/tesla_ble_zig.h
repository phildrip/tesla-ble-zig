/**
 * @file tesla_ble_zig.h
 * @brief Standard C-compatible ABI bindings for the Tesla BLE Zig Library.
 * 
 * This header maps the exported Zig functions to C/C++, designed for zero-allocation
 * bare-metal environments (like ESP-IDF/ESPHome on ESP32-C6).
 */

#ifndef TESLA_BLE_ZIG_H
#define TESLA_BLE_ZIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes returned by all library functions.
 * Matches the Zig ErrorCode enum exactly.
 */
typedef enum {
    TESLA_OK = 0,
    TESLA_ERROR_INVALID_ARGS = -1,
    TESLA_ERROR_BUFFER_TOO_SMALL = -2,
    TESLA_ERROR_SESSION_NOT_INITIALIZED = -3,
    TESLA_ERROR_INVALID_ENCODING = -4,
    TESLA_ERROR_DECRYPT_FAILED = -5,
    TESLA_ERROR_INVALID_DOMAIN = -6,
    TESLA_ERROR_KEY_NOT_ON_WHITELIST = -7,
    TESLA_ERROR_REPLAY_DETECTED = -8,
    TESLA_ERROR_PAYLOAD_TOO_LARGE = -9,
    TESLA_ERROR_UNKNOWN = -99
} tesla_error_t;

/**
 * @brief Domain values for Tesla BLE communication.
 * Domain 2 is VEHICLE_SECURITY (VCSEC), Domain 3 is INFOTAINMENT (CarServer).
 */
typedef enum {
    TESLA_DOMAIN_VEHICLE_SECURITY = 2,
    TESLA_DOMAIN_INFOTAINMENT = 3
} tesla_domain_t;

/**
 * @brief Distinct states of the Tesla Connection State Machine (CSM).
 */
typedef enum {
    TESLA_CSM_STATE_DISCONNECTED = 0,
    TESLA_CSM_STATE_CONNECTING = 1,
    TESLA_CSM_STATE_HANDSHAKING_VCSEC = 2,
    TESLA_CSM_STATE_SECURE_VCSEC = 3,
    TESLA_CSM_STATE_HANDSHAKING_INFOTAINMENT = 4,
    TESLA_CSM_STATE_FULLY_SECURE = 5
} tesla_csm_state_t;

/**
 * @brief Events that trigger transitions in the Connection State Machine (CSM).
 */
typedef enum {
    TESLA_CSM_EVENT_CONNECT_REQUESTED = 0,
    TESLA_CSM_EVENT_BLE_CONNECTED = 1,
    TESLA_CSM_EVENT_BLE_DISCONNECTED = 2,
    TESLA_CSM_EVENT_HANDSHAKE_SUCCESS_VCSEC = 3,
    TESLA_CSM_EVENT_HANDSHAKE_SUCCESS_INFOTAINMENT = 4,
    TESLA_CSM_EVENT_SESSION_EXPIRED_VCSEC = 5,
    TESLA_CSM_EVENT_SESSION_EXPIRED_INFOTAINMENT = 6,
    TESLA_CSM_EVENT_HANDSHAKE_FAILED = 7
} tesla_csm_event_t;

/**
 * @brief External random number generation hook.
 * 
 * @important The consumer C/C++ application MUST implement this function!
 * For example, on ESP32, this can be implemented by calling esp_fill_random.
 * 
 * @param buf Pointer to the destination buffer.
 * @param len Number of bytes of randomness to generate.
 */
extern void tesla_random_bytes(uint8_t *buf, size_t len);

/**
 * @brief Returns the size in bytes of the Client structure.
 * 
 * Use this to pre-allocate an aligned buffer on the stack or statically
 * before invoking `tesla_client_init`.
 * 
 * @return Size of the Client structure in bytes.
 */
size_t tesla_client_size(void);

/**
 * @brief Initialize the Client structure in-place (placement-init) inside a pre-allocated memory buffer.
 * 
 * Completely heapless and safe for bare-metal targets.
 * 
 * @param client_ptr Pointer to pre-allocated memory buffer of at least `tesla_client_size()` bytes.
 * @param vin_ptr Pointer to the VIN string.
 * @param vin_len Length of the VIN string.
 * @param priv_key_ptr Pointer to the 32-byte private key. If NULL, a random one will be generated.
 * @param connection_id_ptr Pointer to a 16-byte Connection ID. Must not be NULL.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_init(
    void *client_ptr,
    const uint8_t *vin_ptr,
    size_t vin_len,
    const uint8_t *priv_key_ptr,
    const uint8_t *connection_id_ptr
);

/**
 * @brief Copy the 65-byte uncompressed public key of the client.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param out_pub_key_65 Pointer to the 65-byte destination buffer.
 */
void tesla_client_get_public_key(void *client_ptr, uint8_t *out_pub_key_65);

/**
 * @brief Copy the 4-byte Key ID derived from the client's public key hash.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param out_key_id_4 Pointer to the 4-byte destination buffer.
 */
void tesla_client_get_key_id(void *client_ptr, uint8_t *out_key_id_4);

/**
 * @brief Build a session info request BLE packet (the handshake initializer).
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param domain_val Domain to request session keys for (VEHICLE_SECURITY or INFOTAINMENT).
 * @param out_buffer Pointer to the output buffer to write the BLE packet to.
 * @param out_buffer_len Capacity of the output buffer.
 * @param out_written_len Pointer to receive the actual written size.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_build_session_info_request(
    void *client_ptr,
    uint32_t domain_val,
    uint8_t *out_buffer,
    size_t out_buffer_len,
    size_t *out_written_len
);

/**
 * @brief Handle a received session info payload (completes the handshake and sets up session keys).
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param domain_val Domain of the session (VEHICLE_SECURITY or INFOTAINMENT).
 * @param current_timestamp Epoch timestamp or synchronized counter representing the current time.
 * @param session_info_ptr Pointer to the received SessionInfo protobuf payload.
 * @param session_info_len Length of the session info payload.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_handle_session_info_response(
    void *client_ptr,
    uint32_t domain_val,
    uint32_t current_timestamp,
    const uint8_t *session_info_ptr,
    size_t session_info_len
);

/**
 * @brief Frame, sign, encrypt, and assemble a universal command ready for BLE transmission.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param current_timestamp Epoch timestamp or synchronized counter representing the current time.
 * @param payload_ptr Pointer to the command payload (e.g. serialized VCSEC or CarServer protobuf).
 * @param payload_len Length of the command payload.
 * @param domain_val Domain of the target (VEHICLE_SECURITY or INFOTAINMENT).
 * @param encrypt Whether to encrypt the payload. True is highly recommended for security.
 * @param out_buffer Pointer to the output buffer to write the ready-to-transmit BLE packet to.
 * @param out_buffer_len Capacity of the output buffer.
 * @param out_written_len Pointer to receive the actual written size.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_build_universal_message(
    void *client_ptr,
    uint32_t current_timestamp,
    const uint8_t *payload_ptr,
    size_t payload_len,
    uint32_t domain_val,
    bool encrypt,
    uint8_t *out_buffer,
    size_t out_buffer_len,
    size_t *out_written_len
);

/**
 * @brief Build a signed and encrypted Lock command BLE packet.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param current_timestamp Current epoch timestamp or synchronized counter.
 * @param out_buffer Output buffer to write the ready-to-transmit BLE packet to.
 * @param out_buffer_len Capacity of the output buffer.
 * @param out_written_len Pointer to receive the actual written size.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_build_lock_command(
    void *client_ptr,
    uint32_t current_timestamp,
    uint8_t *out_buffer,
    size_t out_buffer_len,
    size_t *out_written_len
);

/**
 * @brief Build a signed and encrypted Unlock command BLE packet.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param current_timestamp Current epoch timestamp or synchronized counter.
 * @param out_buffer Output buffer to write the ready-to-transmit BLE packet to.
 * @param out_buffer_len Capacity of the output buffer.
 * @param out_written_len Pointer to receive the actual written size.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_build_unlock_command(
    void *client_ptr,
    uint32_t current_timestamp,
    uint8_t *out_buffer,
    size_t out_buffer_len,
    size_t *out_written_len
);

/**
 * @brief Build a signed and encrypted Wake command BLE packet.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param current_timestamp Current epoch timestamp or synchronized counter.
 * @param out_buffer Output buffer to write the ready-to-transmit BLE packet to.
 * @param out_buffer_len Capacity of the output buffer.
 * @param out_written_len Pointer to receive the actual written size.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_build_wake_command(
    void *client_ptr,
    uint32_t current_timestamp,
    uint8_t *out_buffer,
    size_t out_buffer_len,
    size_t *out_written_len
);

/**
 * @brief Build a signed and encrypted Rear Trunk action command BLE packet.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param current_timestamp Current epoch timestamp or synchronized counter.
 * @param out_buffer Output buffer to write the ready-to-transmit BLE packet to.
 * @param out_buffer_len Capacity of the output buffer.
 * @param out_written_len Pointer to receive the actual written size.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_build_trunk_command(
    void *client_ptr,
    uint32_t current_timestamp,
    uint8_t *out_buffer,
    size_t out_buffer_len,
    size_t *out_written_len
);

/**
 * @brief Build a signed and encrypted Front Trunk (Frunk) action command BLE packet.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param current_timestamp Current epoch timestamp or synchronized counter.
 * @param out_buffer Output buffer to write the ready-to-transmit BLE packet to.
 * @param out_buffer_len Capacity of the output buffer.
 * @param out_written_len Pointer to receive the actual written size.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_build_frunk_command(
    void *client_ptr,
    uint32_t current_timestamp,
    uint8_t *out_buffer,
    size_t out_buffer_len,
    size_t *out_written_len
);

/**
 * @brief Decrypt an authenticated vehicle response payload using session parameters.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param domain_val Domain of the response (VEHICLE_SECURITY or INFOTAINMENT).
 * @param response_ptr Pointer to the received BLE packet (RoutableMessage protobuf).
 * @param response_len Length of the received BLE packet.
 * @param out_buffer Pointer to the output buffer to write the decrypted/unwrapped payload to.
 * @param out_buffer_len Capacity of the output buffer.
 * @param out_written_len Pointer to receive the actual written size of the decrypted payload.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_decrypt_response(
    void *client_ptr,
    uint32_t domain_val,
    const uint8_t *response_ptr,
    size_t response_len,
    uint8_t *out_buffer,
    size_t out_buffer_len,
    size_t *out_written_len
);

/**
 * @brief Get the current Connection State Machine state.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @return State value matching tesla_csm_state_t.
 */
uint8_t tesla_client_get_csm_state(void *client_ptr);

/**
 * @brief Handle a Connection State Machine event from the C environment.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param event_val Event value matching tesla_csm_event_t.
 * @param current_timestamp Current epoch timestamp or synchronized counter.
 */
void tesla_client_handle_csm_event(void *client_ptr, uint8_t event_val, uint32_t current_timestamp);

/**
 * @brief Get the number of VCSEC handshake attempts since last success.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @return Number of attempts.
 */
uint8_t tesla_client_get_csm_vcsec_attempts(void *client_ptr);

/**
 * @brief Get the number of Infotainment handshake attempts since last success.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @return Number of attempts.
 */
uint8_t tesla_client_get_csm_infotainment_attempts(void *client_ptr);

/**
 * @brief Get the session key (shared secret) derived by the Zig Client for a given domain.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param domain_val Domain of the session.
 * @param out_secret_16 Pointer to the 16-byte destination buffer.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_get_shared_secret(void *client_ptr, uint32_t domain_val, uint8_t *out_secret_16);

/**
 * @brief Get the session sequence counter tracked by the Zig Client for a given domain.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param domain_val Domain of the session.
 * @return The sequence counter value.
 */
uint32_t tesla_client_get_session_counter(void *client_ptr, uint32_t domain_val);

/**
 * @brief Get the session epoch bytes tracked by the Zig Client for a given domain.
 * 
 * @param client_ptr Pointer to the initialized Client.
 * @param domain_val Domain of the session.
 * @param out_epoch_16 Pointer to the 16-byte destination buffer.
 * @return TESLA_OK on success, or an error code on failure.
 */
int32_t tesla_client_get_session_epoch(void *client_ptr, uint32_t domain_val, uint8_t *out_epoch_16);

/**
 * @brief Get the size in bytes of the Scheduler structure.
 * 
 * @return Size in bytes.
 */
size_t tesla_scheduler_size(void);

/**
 * @brief Initialize the Scheduler in-place.
 * 
 * @param scheduler_ptr Pointer to a pre-allocated block of memory of at least `tesla_scheduler_size()` bytes.
 * @param post_wake_poll_time_ms Milliseconds to poll after the car wakes up.
 * @param poll_data_period_ms Interval to poll data when awake.
 * @param poll_asleep_period_ms Interval to poll when asleep.
 * @param poll_charging_period_ms Interval to poll when charging.
 * @param fast_poll_if_unlocked Whether fast polling is enabled when unlocked.
 * @param wake_on_boot Whether to wake the car on boot.
 */
void tesla_scheduler_init(
    void *scheduler_ptr,
    uint32_t post_wake_poll_time_ms,
    uint32_t poll_data_period_ms,
    uint32_t poll_asleep_period_ms,
    uint32_t poll_charging_period_ms,
    bool fast_poll_if_unlocked,
    bool wake_on_boot
);

/**
 * @brief Update the timing configuration of the scheduler dynamically.
 * 
 * @param scheduler_ptr Pointer to the Scheduler.
 * @param post_wake_poll_time_ms Milliseconds to poll after the car wakes up.
 * @param poll_data_period_ms Interval to poll data when awake.
 * @param poll_asleep_period_ms Interval to poll when asleep.
 * @param poll_charging_period_ms Interval to poll when charging.
 */
void tesla_scheduler_update_config(
    void *scheduler_ptr,
    uint32_t post_wake_poll_time_ms,
    uint32_t poll_data_period_ms,
    uint32_t poll_asleep_period_ms,
    uint32_t poll_charging_period_ms
);


/**
 * @brief Perform a scheduler tick, returning decision outputs.
 * 
 * @param scheduler_ptr Pointer to the initialized Scheduler.
 * @param current_time_ms Current timestamp in milliseconds.
 * @param is_asleep Whether the car is currently asleep.
 * @param is_unlocked Whether the car is currently unlocked.
 * @param is_user_present Whether a user is currently present in the car.
 * @param one_off_update Whether a one-off poll has been requested.
 * @param out_should_poll_vcsec Pointer to write the VCSEC polling decision.
 * @param out_should_poll_infotainment Pointer to write the Infotainment polling decision.
 * @param out_should_wake_vehicle Pointer to write the wake vehicle decision.
 * @param out_clear_one_off_update Pointer to write whether to clear the one-off update request.
 */
void tesla_scheduler_tick(
    void *scheduler_ptr,
    uint32_t current_time_ms,
    bool is_asleep,
    bool is_unlocked,
    bool is_user_present,
    bool one_off_update,
    bool *out_should_poll_vcsec,
    bool *out_should_poll_infotainment,
    bool *out_should_wake_vehicle,
    bool *out_clear_one_off_update
);

/**
 * @brief Get the current internal charging state tracking of the scheduler.
 * 
 * @param scheduler_ptr Pointer to the Scheduler.
 * @return Internal charging state (0 = NotCharging, 1 = ChargingJustStarted, 2 = ChargingOngoing).
 */
uint8_t tesla_scheduler_get_charging_state(void *scheduler_ptr);

/**
 * @brief Set the internal charging state tracking of the scheduler.
 * 
 * @param scheduler_ptr Pointer to the Scheduler.
 * @param charging_state State value (0 = NotCharging, 1 = ChargingJustStarted, 2 = ChargingOngoing).
 */
void tesla_scheduler_set_charging_state(void *scheduler_ptr, uint8_t charging_state);

/**
 * @brief Reset the VCSEC poll timestamp to 0.
 * 
 * @param scheduler_ptr Pointer to the Scheduler.
 */
void tesla_scheduler_reset_vcsec_poll_time(void *scheduler_ptr);

/**
 * @brief Get the total number of Infotainment updates triggered since connection.
 * 
 * @param scheduler_ptr Pointer to the Scheduler.
 * @return Number of updates.
 */
uint32_t tesla_scheduler_get_number_updates_since_connection(void *scheduler_ptr);

/**
 * @brief Set the total number of Infotainment updates triggered since connection.
 * 
 * @param scheduler_ptr Pointer to the Scheduler.
 * @param count Value to set.
 */
void tesla_scheduler_set_number_updates_since_connection(void *scheduler_ptr, uint32_t count);

/**
 * @brief Get the car's just woken state.
 * 
 * @param scheduler_ptr Pointer to the Scheduler.
 * @return Just woken state (0 = no, 1 = yes_initial, 2 = yes_polling).
 */
uint8_t tesla_scheduler_get_car_just_woken(void *scheduler_ptr);

/**
 * @brief Set the car's just woken state.
 * 
 * @param scheduler_ptr Pointer to the Scheduler.
 * @param state Just woken state.
 */
void tesla_scheduler_set_car_just_woken(void *scheduler_ptr, uint8_t state);

#ifdef __cplusplus
}
#endif

#endif /* TESLA_BLE_ZIG_H */
