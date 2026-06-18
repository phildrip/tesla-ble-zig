# 🛠️ Tesla BLE Zig Integration Makefile

# Configuration variables
REMOTE_HOST = 192.168.1.211
REMOTE_DIR = /tmp/esphome-tesla-ble
REMOTE_VENV = /tmp/esphome-venv/bin/esphome
REMOTE_PORT = /dev/ttyACM0

# Standalone configuration variables
REMOTE_STANDALONE_DIR = /tmp/tesla-ble-standalone
LOCAL_PORT = /dev/ttyACM0

.PHONY: all help build-riscv build-x86_64 test deploy-lib compile-esphome flash-esphome logs-esphome build-standalone flash-standalone monitor-standalone deploy-standalone compile-remote-standalone flash-remote-standalone monitor-remote-standalone clean

all: help

help:
	@echo "Available commands:"
	@echo "  ESPHome Integration targets (remote compile & flash):"
	@echo "    make deploy-lib               - Copy RISC-V library and C header to remote host"
	@echo "    make compile-esphome          - Compile ESPHome firmware on remote host"
	@echo "    make flash-esphome            - Flash ESPHome firmware to physical ESP32-C6 over USB"
	@echo "    make logs-esphome             - Stream serial console logs from ESPHome firmware"
	@echo ""
	@echo "  Pure-Zig Standalone targets (local ESP-IDF):"
	@echo "    make build-standalone         - Build pure-Zig standalone firmware locally using idf.py"
	@echo "    make flash-standalone         - Flash pure-Zig standalone firmware locally"
	@echo "    make monitor-standalone       - Open serial log monitor for standalone firmware locally"
	@echo ""
	@echo "  Pure-Zig Standalone targets (remote ESP-IDF over SSH):"
	@echo "    make deploy-standalone        - Deploy entire workspace to remote host"
	@echo "    make compile-remote-standalone - Compile standalone firmware on remote host using idf.py"
	@echo "    make flash-remote-standalone  - Flash standalone firmware on remote host over USB"
	@echo "    make monitor-remote-standalone - Open serial log monitor for standalone remotely"
	@echo ""
	@echo "  Core Utility targets:"
	@echo "    make build-riscv              - Build soft-float RISC-V static library for ESP32-C6"
	@echo "    make build-x86_64             - Build native x86_64 baseline static library"
	@echo "    make test                     - Run Zig library unit tests"
	@echo "    make clean                    - Remove build caches and artifacts"

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
	@echo "Deploying RISC-V static library, glue layer and config to remote host $(REMOTE_HOST)..."
	scp zig-out/lib/libtesla_ble_zig.a $(REMOTE_HOST):/tmp/libtesla_ble_zig_riscv32.a
	scp esphome/tesla_zig_glue.h $(REMOTE_HOST):/tmp/tesla_zig_glue.h
	scp include/tesla_ble_zig.h $(REMOTE_HOST):/tmp/tesla_ble_zig.h
	scp -r esphome-tesla-ble-local/components/* $(REMOTE_HOST):$(REMOTE_DIR)/components/
	scp esphome/tesla-ble-nanoc6.yml $(REMOTE_HOST):$(REMOTE_DIR)/tesla-ble-nanoc6.yml
	scp esphome/secrets.yaml $(REMOTE_HOST):$(REMOTE_DIR)/secrets.yaml

compile-esphome: deploy-lib
	@echo "Compiling ESPHome project remotely..."
	ssh -o BatchMode=yes $(REMOTE_HOST) "$(REMOTE_VENV) compile $(REMOTE_DIR)/tesla-ble-nanoc6.yml"

flash-esphome:
	@echo "Flashing firmware to physical ESP32-C6 on $(REMOTE_PORT) via $(REMOTE_HOST)..."
	ssh -o BatchMode=yes $(REMOTE_HOST) "sudo $(REMOTE_VENV) upload $(REMOTE_DIR)/tesla-ble-nanoc6.yml --device $(REMOTE_PORT)"

logs-esphome:
	@echo "Streaming serial logs from physical ESP32-C6 on $(REMOTE_HOST)..."
	ssh -o BatchMode=yes $(REMOTE_HOST) "sudo $(REMOTE_VENV) logs $(REMOTE_DIR)/tesla-ble-nanoc6.yml --device $(REMOTE_PORT)"

# --- Pure-Zig Standalone Local Targets ---
build-standalone:
	@echo "Building pure-Zig standalone firmware locally..."
	idf.py -C standalone build

flash-standalone:
	@echo "Flashing pure-Zig standalone firmware locally to $(LOCAL_PORT)..."
	idf.py -C standalone -p $(LOCAL_PORT) flash

monitor-standalone:
	@echo "Opening serial monitor locally for $(LOCAL_PORT)..."
	idf.py -C standalone -p $(LOCAL_PORT) monitor

# --- Pure-Zig Standalone Remote Targets ---
deploy-standalone:
	@echo "Deploying complete workspace to remote host $(REMOTE_HOST)..."
	ssh -o BatchMode=yes $(REMOTE_HOST) "mkdir -p $(REMOTE_STANDALONE_DIR)"
	scp -r build.zig build.zig.zon Makefile src include standalone $(REMOTE_HOST):$(REMOTE_STANDALONE_DIR)/

compile-remote-standalone: deploy-standalone
	@echo "Compiling standalone firmware on remote host $(REMOTE_HOST)..."
	ssh -o BatchMode=yes $(REMOTE_HOST) 'bash -c "source ~/git/esp-idf/export.sh && cd $(REMOTE_STANDALONE_DIR)/standalone && idf.py build"'

flash-remote-standalone:
	@echo "Flashing standalone firmware on remote host $(REMOTE_HOST) to $(REMOTE_PORT)..."
	ssh -o BatchMode=yes $(REMOTE_HOST) 'bash -c "source ~/git/esp-idf/export.sh && cd $(REMOTE_STANDALONE_DIR)/standalone && idf.py -p $(REMOTE_PORT) flash"'

monitor-remote-standalone:
	@echo "Monitoring standalone logs on remote host $(REMOTE_HOST) on $(REMOTE_PORT)..."
	ssh -o BatchMode=yes $(REMOTE_HOST) -t 'bash -c "source ~/git/esp-idf/export.sh && cd $(REMOTE_STANDALONE_DIR)/standalone && idf.py -p $(REMOTE_PORT) monitor"'

clean:
	@echo "Cleaning local build artifacts..."
	rm -rf .zig-cache zig-out
	cd standalone && rm -rf build
