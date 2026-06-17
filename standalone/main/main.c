/**
 * @file main.c
 * @brief Simple ESP-IDF C stub calling the Zig-native app_main entry point.
 */

#include <stdio.h>

// Forward declaration of our Zig-native entry point
extern void app_main(void);

void app_main_c_stub(void) {
    // Forward directly to the Zig application
    app_main();
}
