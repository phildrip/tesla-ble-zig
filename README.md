# 🚗 Tesla BLE Zig Monorepo

[![Zig Version](https://img.shields.io/badge/Zig-0.16.0-f7a41d?logo=zig&logoColor=white)](https://ziglang.org/)
[![ESPHome](https://img.shields.io/badge/ESPHome-Integrated-4caf50?logo=homeassistant&logoColor=white)](https://esphome.io/)
[![Target](https://img.shields.io/badge/Target-ESP32--C6%20(RISC--V)-000000?logo=espressif&logoColor=white)](https://www.espressif.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A high-performance, freestanding, heapless **Zig** port of the `tesla-ble` cryptographic client, unified with an **ESPHome** firmware configuration for the **ESP32-C6 (RISC-V)**.

This repository enables secure, local, and direct Bluetooth Low Energy (BLE) control of your Tesla vehicle from Home Assistant with high memory efficiency and robust type-safety.

---

## ✨ Features

* **Zero Memory Allocations**: Completely heapless structure. Designed with static lifetime/placement-init, perfect for real-time bare-metal microcontrollers.
* **Extremely Lightweight**: 
  * The core client struct spans only **560 bytes** on a 32-bit RISC-V target (vs **592 bytes** on 64-bit x86_64).
  * Compiled binary optimizations fit effortlessly within strict ESP32-C6 SRAM boundaries.
* **Type-Safe Cryptography**: Built in Zig, offering native bounds-checking, strict error-handling, and clean compile-time optimizations.
* **Standard C-Compatible ABI**: Easily links into any C++ project (PlatformIO, ESP-IDF, ESPHome) using a clean, well-documented C API.
* **Integrated ESPHome Firmware**: Pre-configured ESPHome project files for M5Stack NanoC6 or other generic ESP32-C6 dev kits.

---

## 📂 Monorepo Architecture

The repository is structured as a clean monorepo:

```bash
tesla-ble-zig/
├── src/                    # Core Zig library source code
│   ├── root.zig            # Core cryptographic client logic
│   ├── c_bindings.zig      # Exported C-compatible ABI symbols
│   └── main.zig            # Optional native entry point / CLI testing tool
├── include/                # Public API Header
│   └── tesla_ble_zig.h     # Standard C/C++ ABI definitions
├── esphome/                # ESPHome Config & Deployment Assets
│   ├── secrets.yaml.example# Generic credentials configuration template
│   ├── tesla-ble-nanoc6.yml# ESPHome custom component node configuration
│   └── tesla_zig_glue.h    # ESPHome C++ hook mapping random bytes & testing boot
├── Makefile                # Multi-target build and deployment orchestrator
├── build.zig               # Zig build configuration script
└── build.zig.zon           # Zig package manifest
```

---

## 🛠️ Prerequisites

* **Zig Compiler**: Version `0.16.0`.
* **ESPHome Environment**: ESPHome installed locally or running on a target compiler machine (such as a Home Assistant server).
* **Hardware**: An ESP32-C6 board (e.g., M5Stack NanoC6, ESP32-C6-DevKitM-1).

---

## ⚙️ Building the Zig Static Library

### 1. Run Unit Tests (Local Target)
Verify cryptography and framing logic pass all unit test suites on your native developer architecture:
```bash
make test
# OR
zig build test
```

### 2. Native Static Build (x86_64 / macOS / Linux)
To build a static library for native desktop/server tools:
```bash
make build-x86_64
# OR
zig build -Dtarget=x86_64-linux -Doptimize=ReleaseSmall
```

### 3. ESP32-C6 Cross-Compilation (RISC-V 32-bit Soft-Float)
Cross-compile the Zig static library into a RISC-V object format that perfectly matches ESP-IDF's toolchain ABI:
```bash
make build-riscv
```

> [!IMPORTANT]
> **Why we specify the CPU baseline separately:**
> By default, Zig's freestanding RISC-V target (`riscv32-freestanding-none`) assumes a double-precision hardware floating-point ABI (`double-float`). However, the ESP32-C6 uses a soft-float architecture (`rv32imac` in ESP-IDF context). 
> 
> To generate relocatable binaries with a soft-float ABI, we separate the CPU parameters and pass:
> `zig build -Dtarget=riscv32-freestanding-none -Dcpu=baseline_rv32-f-d -Doptimize=ReleaseSmall`
> This produces a static binary (`libtesla_ble_zig.a`) that links seamlessly into ESPHome/PlatformIO.

---

## 🚀 Deploying & Flashing via ESPHome

For most users, you will compile and flash your ESP32-C6 on the same local development machine it is plugged into via USB.

### Step 1: Set Up Credentials
Under `esphome/`, copy the secrets template:
```bash
cp esphome/secrets.yaml.example esphome/secrets.yaml
```
Edit `esphome/secrets.yaml` to specify your:
* Wi-Fi SSID and Password.
* Vehicle VIN and vehicle Bluetooth MAC address.
* ESPHome API Encryption key.

> [!WARNING]
> `esphome/secrets.yaml` is hard-ignored in `.gitignore`. Never commit or publish your actual secrets, VIN, or private tokens to GitHub.

### Step 2: Copy Build Outputs locally
First, compile the static library for your ESP32-C6:
```bash
make build-riscv
```
Then, copy the compiled library and relevant headers into your local `/tmp` folder (which matches the include path defined in `tesla-ble-nanoc6.yml`):
```bash
cp zig-out/lib/libtesla_ble_zig.a /tmp/libtesla_ble_zig_riscv32.a
cp esphome/tesla_zig_glue.h /tmp/tesla_zig_glue.h
cp include/tesla_ble_zig.h /tmp/tesla_ble_zig.h
```

### Step 3: Compile and Flash Locally
Connect your ESP32-C6 via USB to your local machine, then run ESPHome to compile and upload the firmware:
```bash
# Compile and flash to the connected ESP32-C6
esphome run esphome/tesla-ble-nanoc6.yml
```

---

### 🌐 Advanced: Remote Build & Deploy Server (Optional)
If your ESP32-C6 is physically plugged into a separate machine (such as a Home Assistant server, Raspberry Pi, or a remote compiler host), the provided `Makefile` automates compiling locally, copying assets over the network, and triggering builds/flashing remotely:

1. **Configure Target Host** at the top of the `Makefile`:
   ```makefile
   REMOTE_HOST = 192.168.1.211            # Remote compiler machine IP/hostname
   REMOTE_DIR = /tmp/esphome-tesla-ble   # Project directory on remote host
   REMOTE_VENV = /tmp/esphome-venv/bin/esphome # Path to ESPHome executable
   REMOTE_PORT = /dev/ttyACM0             # ESP32-C6 USB device path
   ```

2. **Deploy Built Library over SSH**:
   ```bash
   make deploy-lib
   ```
   *Compiles the RISC-V library and copies headers to `/tmp` on the target remote host.*

3. **Compile remotely**:
   ```bash
   make compile-esphome
   ```

4. **Flash remote device over USB**:
   ```bash
   make flash-esphome
   ```

5. **Stream logs over SSH**:
   ```bash
   make logs-esphome
   ```

---

## 🧑‍💻 Heapless C/C++ API Overview

Integrating this custom library into your own bare-metal applications is incredibly straightforward.

### Placement-Init Allocation
Because the library is completely heapless, the C caller queries the required memory size, allocates the memory block (on the stack, in global static storage, or dynamically), and passes the buffer pointer to the initializer:

```cpp
#include "tesla_ble_zig.h"

// 1. Get exact memory block size needed (560 bytes on 32-bit RISC-V)
size_t client_sz = tesla_client_size();

// 2. Allocate the buffer statically (highly recommended for microcontrollers)
static uint8_t client_memory[560]; 

// 3. Initialize client in-place
int32_t status = tesla_client_init(
    client_memory, 
    (const uint8_t*)"5YJ3E1EBXLFXXXXXX", 17, // Vehicle VIN
    private_key_32_bytes, 
    connection_id_16_bytes
);

if (status == TESLA_OK) {
    // Client initialized successfully in client_memory!
}
```

### Cryptographic Hooks
The Zig library relies on hardware-level random generation for session handshakes and keys. The C-consumer must expose a `tesla_random_bytes` function:

```cpp
extern "C" {
    void tesla_random_bytes(uint8_t *buf, size_t len) {
        // ESP32 hardware random number generator
        esp_fill_random(buf, len);
    }
}
```

---

## ⚖️ License & Attribution

This library is released under the **MIT License**.
* Core Protocol Messages and structures are derived from [Tesla's Vehicle Command Protocol](https://github.com/teslamotors/vehicle-command).
* Custom Zig port and ESPHome integrations are built specifically for optimized ESP32-C6 deployments.
