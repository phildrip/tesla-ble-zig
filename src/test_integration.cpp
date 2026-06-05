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

    std::cout << "[Integration Test] SUCCESS! Zig static library successfully integrated, linked, and executed from C++!" << std::endl;
    return 0;
}
