cmake_minimum_required(VERSION 3.16)

# Define configuration defaults list
set(SDKCONFIG_DEFAULTS "sdkconfig.defaults")

# Conditionally append local untracked configurations if they exist
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults.local")
    list(APPEND SDKCONFIG_DEFAULTS "sdkconfig.defaults.local")
endif()

# Include the ESP-IDF build system
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tesla-ble-zig-firmware)
