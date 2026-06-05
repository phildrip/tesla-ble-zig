#pragma once
#include <esp_system.h>
#include "tesla_ble_zig.h"

extern "C" {
    void tesla_random_bytes(uint8_t *buf, size_t len) {
        esp_fill_random(buf, len);
    }
}

inline void test_zig_library() {
    size_t sz = tesla_client_size();
    ESP_LOGI("tesla_zig", "Hello from Zig! Client memory structure size: %d bytes", (int)sz);
}
