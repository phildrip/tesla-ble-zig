#include <iostream>
#include <vector>
#include <cassert>
#include <cstring>
#include "../include/tesla_ble_zig.h"

// Implement the external linker hook expected by our Zig library
extern "C" void tesla_random_bytes(uint8_t *buf, size_t len) {
    // Standard deterministic mock randomness for test predictability
    for (size_t i = 0; i < len; ++i) {
        buf[i] = static_cast<uint8_t>((i + 42) & 0xFF);
    }
}

int main() {
    std::cout << "[Integration Test] Starting C++ integration test compiled with Zig C++..." << std::endl;

    // 1. Verify client size
    size_t client_sz = tesla_client_size();
    std::cout << "[Integration Test] Zig Client struct size: " << client_sz << " bytes" << std::endl;
    assert(client_sz > 0);

    // 2. Allocate the memory buffer for placement-initialization on the stack
    std::vector<uint8_t> client_buffer(client_sz);

    // 3. Initialize parameters
    const char *vin = "5YJ3E1EBXLF000000";
    uint8_t dummy_priv_key[32];
    std::memset(dummy_priv_key, 0x05, 32); // All 0x05 for deterministic key derivation

    uint8_t connection_id[16];
    std::memset(connection_id, 0x88, 16);

    // 4. Initialize client
    int32_t rc = tesla_client_init(
        client_buffer.data(),
        reinterpret_cast<const uint8_t*>(vin),
        std::strlen(vin),
        dummy_priv_key,
        connection_id
    );
    std::cout << "[Integration Test] tesla_client_init returned: " << rc << std::endl;
    assert(rc == TESLA_OK);

    // 5. Verify public key extraction
    uint8_t pub_key[65];
    std::memset(pub_key, 0, 65);
    tesla_client_get_public_key(client_buffer.data(), pub_key);
    std::cout << "[Integration Test] Extracted public key prefix (SEC1 format): 0x" 
              << std::hex << static_cast<int>(pub_key[0]) << std::dec << std::endl;
    assert(pub_key[0] == 0x04); // SEC1 uncompressed point prefix

    // 6. Verify key ID extraction
    uint8_t key_id[4];
    std::memset(key_id, 0, 4);
    tesla_client_get_key_id(client_buffer.data(), key_id);
    std::cout << "[Integration Test] Extracted key ID: 0x" 
              << std::hex 
              << static_cast<int>(key_id[0]) << static_cast<int>(key_id[1])
              << static_cast<int>(key_id[2]) << static_cast<int>(key_id[3])
              << std::dec << std::endl;
    assert((key_id[0] | key_id[1] | key_id[2] | key_id[3]) != 0);

    // 7. Verify session request packet building
    uint8_t out_buf[256];
    size_t out_written = 0;
    rc = tesla_client_build_session_info_request(
        client_buffer.data(),
        TESLA_DOMAIN_VEHICLE_SECURITY,
        out_buf,
        sizeof(out_buf),
        &out_written
    );
    std::cout << "[Integration Test] tesla_client_build_session_info_request returned: " << rc << std::endl;
    assert(rc == TESLA_OK);
    std::cout << "[Integration Test] Written BLE handshake packet size: " << out_written << " bytes" << std::endl;
    assert(out_written > 0);

    // 8. Verify command building fails before session is initialized
    rc = tesla_client_build_lock_command(
        client_buffer.data(),
        1000,
        out_buf,
        sizeof(out_buf),
        &out_written
    );
    std::cout << "[Integration Test] tesla_client_build_lock_command before handshake returned: " << rc << std::endl;
    assert(rc == TESLA_ERROR_SESSION_NOT_INITIALIZED);

    // 9. Initialize the session by feeding a mock SessionInfo Response
    // We serialize a basic SessionInfo payload using manual protobuf encoding:
    // field 1 (counter) = 1 (tag 1<<3 | 0 = 0x08, value = 0x01)
    // field 2 (publicKey) = 65 bytes (tag 2<<3 | 2 = 0x12, length = 65, followed by 65 bytes of public key)
    // field 3 (epoch) = 16 bytes (tag 3<<3 | 2 = 0x1a, length = 16, followed by 16 bytes of epoch)
    // field 4 (clock_time) = 1000 (tag 4<<3 | 5 = 0x25, value = 1000 in little-endian fixed32 -> 0xe8 0x03 0x00 0x00)
    // field 5 (status) = 0 (tag 5<<3 | 0 = 0x28, value = 0x00)
    std::vector<uint8_t> mock_session_info;
    
    mock_session_info.push_back(0x08);
    mock_session_info.push_back(0x01);

    mock_session_info.push_back(0x12);
    mock_session_info.push_back(65);
    for (int i = 0; i < 65; ++i) {
        mock_session_info.push_back(pub_key[i]);
    }

    mock_session_info.push_back(0x1a);
    mock_session_info.push_back(16);
    for (int i = 0; i < 16; ++i) {
        mock_session_info.push_back(0xde);
    }

    mock_session_info.push_back(0x25);
    mock_session_info.push_back(0xe8);
    mock_session_info.push_back(0x03);
    mock_session_info.push_back(0x00);
    mock_session_info.push_back(0x00);

    mock_session_info.push_back(0x28);
    mock_session_info.push_back(0x00);

    rc = tesla_client_handle_session_info_response(
        client_buffer.data(),
        TESLA_DOMAIN_VEHICLE_SECURITY,
        1000, // current_timestamp
        mock_session_info.data(),
        mock_session_info.size()
    );
    std::cout << "[Integration Test] tesla_client_handle_session_info_response returned: " << rc << std::endl;
    assert(rc == TESLA_OK);

    // 10. Verify command building works after session is initialized
    rc = tesla_client_build_lock_command(
        client_buffer.data(),
        1005, // current_timestamp
        out_buf,
        sizeof(out_buf),
        &out_written
    );
    std::cout << "[Integration Test] tesla_client_build_lock_command returned: " << rc << std::endl;
    assert(rc == TESLA_OK);
    assert(out_written > 0);

    rc = tesla_client_build_unlock_command(
        client_buffer.data(),
        1006,
        out_buf,
        sizeof(out_buf),
        &out_written
    );
    std::cout << "[Integration Test] tesla_client_build_unlock_command returned: " << rc << std::endl;
    assert(rc == TESLA_OK);
    assert(out_written > 0);

    rc = tesla_client_build_wake_command(
        client_buffer.data(),
        1007,
        out_buf,
        sizeof(out_buf),
        &out_written
    );
    std::cout << "[Integration Test] tesla_client_build_wake_command returned: " << rc << std::endl;
    assert(rc == TESLA_OK);
    assert(out_written > 0);

    rc = tesla_client_build_trunk_command(
        client_buffer.data(),
        1008,
        out_buf,
        sizeof(out_buf),
        &out_written
    );
    std::cout << "[Integration Test] tesla_client_build_trunk_command returned: " << rc << std::endl;
    assert(rc == TESLA_OK);
    assert(out_written > 0);

    rc = tesla_client_build_frunk_command(
        client_buffer.data(),
        1009,
        out_buf,
        sizeof(out_buf),
        &out_written
    );
    std::cout << "[Integration Test] tesla_client_build_frunk_command returned: " << rc << std::endl;
    assert(rc == TESLA_OK);
    assert(out_written > 0);

    std::cout << "[Integration Test] SUCCESS! Zig static library successfully integrated, linked, and executed from C++!" << std::endl;
    return 0;
}
