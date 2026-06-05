# 🛠️ Tesla BLE Zig Integration Makefile

# Configuration variables
REMOTE_HOST = 192.168.1.211
REMOTE_DIR = /tmp/esphome-tesla-ble
REMOTE_VENV = /tmp/esphome-venv/bin/esphome
REMOTE_PORT = /dev/ttyACM0

.PHONY: all help build-riscv build-x86_64 test deploy-lib compile-esphome flash-esphome logs-esphome clean

all: help

help:
	@echo "Available commands:"
	@echo "  make build-riscv      - Build soft-float RISC-V static library for ESP32-C6"
	@echo "  make build-x86_64     - Build native x86_64 baseline static library"
	@echo "  make test             - Run Zig library unit tests"
	@echo "  make deploy-lib       - Copy RISC-V library and C header to remote host"
	@echo "  make compile-esphome  - Compile ESPHome firmware on remote host"
	@echo "  make flash-esphome    - Flash firmware to physical ESP32-C6 over USB"
	@echo "  make logs-esphome     - Stream serial console logs from ESP32-C6"
	@echo "  make clean            - Remove build caches and artifacts"

build-riscv:
	@echo "Building RISC-V 32-bit soft-float static library..."
	zig build -Dtarget=riscv32-freestanding-none -Dcpu=baseline_rv32-f-d -Doptimize=ReleaseSmall

build-x86_64:
	@echo "Building native x86_64 static library..."
	zig build -Dtarget=x86_64-linux -Doptimize=ReleaseSmall

test:
	@echo "Running unit tests..."
	zig build test

deploy-lib: build-riscv
	@echo "Deploying RISC-V static library and glue layer to remote host $(REMOTE_HOST)..."
	scp zig-out/lib/libtesla_ble_zig.a $(REMOTE_HOST):/tmp/libtesla_ble_zig_riscv32.a
	scp esphome/tesla_zig_glue.h $(REMOTE_HOST):/tmp/tesla_zig_glue.h
	scp include/tesla_ble_zig.h $(REMOTE_HOST):/tmp/tesla_ble_zig.h

compile-esphome: deploy-lib
	@echo "Compiling ESPHome project remotely..."
	ssh -o BatchMode=yes $(REMOTE_HOST) "$(REMOTE_VENV) compile $(REMOTE_DIR)/tesla-ble-nanoc6.yml"

flash-esphome:
	@echo "Flashing firmware to physical ESP32-C6 on $(REMOTE_PORT) via $(REMOTE_HOST)..."
	ssh -o BatchMode=yes $(REMOTE_HOST) "sudo $(REMOTE_VENV) upload $(REMOTE_DIR)/tesla-ble-nanoc6.yml --device $(REMOTE_PORT)"

logs-esphome:
	@echo "Streaming serial logs from physical ESP32-C6 on $(REMOTE_HOST)..."
	ssh -o BatchMode=yes $(REMOTE_HOST) "sudo $(REMOTE_VENV) logs $(REMOTE_DIR)/tesla-ble-nanoc6.yml --device $(REMOTE_PORT)"

clean:
	@echo "Cleaning local build artifacts..."
	rm -rf .zig-cache zig-out
