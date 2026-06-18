idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES esp_wifi nvs_flash mqtt bt)

# Define path to compile the Zig library
set(ZIG_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/zig_out")
set(ZIG_LIB_PATH "${ZIG_OUT_DIR}/lib/libtesla_ble_zig.a")

find_program(ZIG_EXECUTABLE zig)

if(ZIG_EXECUTABLE)
    message(STATUS "Found Zig compiler: ${ZIG_EXECUTABLE}. Rebuilding library.")
    add_custom_command(
        OUTPUT "${ZIG_LIB_PATH}"
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${ZIG_OUT_DIR}"
        COMMAND zig build -p "${ZIG_OUT_DIR}" -Dtarget=riscv32-freestanding-none -Dcpu=baseline_rv32-f-d -Doptimize=ReleaseSmall
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../.."
        DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/../../src/firmware.zig"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../src/nimble.zig"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../src/client.zig"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../src/queue.zig"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../src/csm.zig"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../src/protobuf.zig"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../src/jni_bindings.zig"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../build.zig"
        COMMENT "Compiling pure-Zig static library for ESP32-C6..."
    )
    add_custom_target(zig_lib_target DEPENDS "${ZIG_LIB_PATH}")
    add_dependencies(${COMPONENT_LIB} zig_lib_target)
else()
    message(STATUS "Zig compiler NOT found. Checking for precompiled static library...")
    set(PREBUILT_ZIG_LIB "${CMAKE_CURRENT_SOURCE_DIR}/liblibtesla_ble_zig.a")
    if(EXISTS "${PREBUILT_ZIG_LIB}")
        message(STATUS "Using precompiled Zig static library from: ${PREBUILT_ZIG_LIB}")
        add_custom_command(
            OUTPUT "${ZIG_LIB_PATH}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${ZIG_OUT_DIR}/lib"
            COMMAND ${CMAKE_COMMAND} -E copy "${PREBUILT_ZIG_LIB}" "${ZIG_LIB_PATH}"
            COMMENT "Copying precompiled Zig static library..."
        )
        add_custom_target(zig_lib_target DEPENDS "${ZIG_LIB_PATH}")
        add_dependencies(${COMPONENT_LIB} zig_lib_target)
    else()
        message(FATAL_ERROR "Zig compiler not found and no precompiled static library found at ${PREBUILT_ZIG_LIB}")
    endif()
endif()

# Link the Zig static library into our component
target_link_libraries(${COMPONENT_LIB} PRIVATE "${ZIG_LIB_PATH}")
