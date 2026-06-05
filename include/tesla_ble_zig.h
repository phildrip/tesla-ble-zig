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

#ifdef __cplusplus
}
#endif

#endif /* TESLA_BLE_ZIG_H */
