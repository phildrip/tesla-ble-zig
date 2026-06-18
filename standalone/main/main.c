#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/pk_private.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "mqtt_client.h"
#include "sdkconfig.h"
#include "esp_random.h"

// Simple Base64 encoder for exactly 32 bytes to Base64
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode_32(const uint8_t *src, char *dst) {
    int i = 0;
    int j = 0;
    for (i = 0; i < 30; i += 3) {
        dst[j++] = base64_chars[(src[i] >> 2) & 0x3F];
        dst[j++] = base64_chars[((src[i] & 0x03) << 4) | ((src[i+1] >> 4) & 0x0F)];
        dst[j++] = base64_chars[((src[i+1] & 0x0F) << 2) | ((src[i+2] >> 6) & 0x03)];
        dst[j++] = base64_chars[src[i+2] & 0x3F];
    }
    dst[j++] = base64_chars[(src[30] >> 2) & 0x3F];
    dst[j++] = base64_chars[((src[30] & 0x03) << 4) | ((src[31] >> 4) & 0x0F)];
    dst[j++] = base64_chars[(src[31] & 0x0F) << 2];
    dst[j++] = '=';
    dst[j] = '\0';
}

// NimBLE BLE Headers
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

// -------------------------------------------------------------
#define LOG_TAG "TESLA_C_GLUE"

// Linker hook for high-quality hardware random numbers on ESP32-C6
void tesla_random_bytes(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);
}

// -------------------------------------------------------------
// Zig Forward Declarations (Callbacks into Zig from C)
// -------------------------------------------------------------
extern void tesla_zig_app_main(
    const char* ssid, 
    const char* password, 
    const char* broker_url, 
    const char* broker_user,
    const char* broker_pass,
    const char* vin,
    const char* ble_mac,
    const char* api_key,
    const char* vehicle_pub_key
);
extern void tesla_zig_wifi_on_connected(void);
extern void tesla_zig_mqtt_on_connected(void);
extern void tesla_zig_mqtt_on_message(const char* topic, int topic_len, const char* data, int data_len);
extern void tesla_zig_ble_on_vehicle_discovered(const void* ble_addr);
extern void tesla_zig_ble_on_connected(uint16_t conn_handle);
extern void tesla_zig_ble_on_disconnected(void);
extern void tesla_zig_ble_on_rx_notification(const uint8_t* data, int len);
extern void tesla_zig_ble_on_channel_ready(void);

// Global State
static esp_mqtt_client_handle_t mqtt_client = NULL;
static uint16_t active_conn_handle = 0;
static uint16_t gatt_tx_char_val_handle = 0;
static uint16_t gatt_rx_char_val_handle = 0;

// Tesla Secure UUID definitions
// Service: 00000211-b2d1-43f0-9b88-960cebf8b91e
// Tx Char:  00000212-b2d1-43f0-9b88-960cebf8b91e
// Rx Char:  00000213-b2d1-43f0-9b88-960cebf8b91e
static const ble_uuid128_t tesla_svc_uuid = BLE_UUID128_INIT(
    0x1e, 0xb9, 0xf8, 0xeb, 0x0c, 0x96, 0x88, 0x9b,
    0xf0, 0x43, 0xd1, 0xb2, 0x11, 0x02, 0x00, 0x00
);

static const ble_uuid128_t tesla_tx_char_uuid = BLE_UUID128_INIT(
    0x1e, 0xb9, 0xf8, 0xeb, 0x0c, 0x96, 0x88, 0x9b,
    0xf0, 0x43, 0xd1, 0xb2, 0x12, 0x02, 0x00, 0x00
);

static const ble_uuid128_t tesla_rx_char_uuid = BLE_UUID128_INIT(
    0x1e, 0xb9, 0xf8, 0xeb, 0x0c, 0x96, 0x88, 0x9b,
    0xf0, 0x43, 0xd1, 0xb2, 0x13, 0x02, 0x00, 0x00
);

// -------------------------------------------------------------
// Wi-Fi Implementation
// -------------------------------------------------------------
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        printf("[C Wi-Fi] Disconnected from Access Point. Retrying...\n");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        printf("[C Wi-Fi] Got IP Address: " IPSTR "\n", IP2STR(&event->ip_info.ip));
        tesla_zig_wifi_on_connected();
    }
}

void tesla_c_wifi_init(const char* ssid, const char* password) {
    printf("[C Wi-Fi] Initializing Wi-Fi station mode...\n");
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip);

    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    strncpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char*)wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
}

// -------------------------------------------------------------
// MQTT Implementation
// -------------------------------------------------------------
static void mqtt_event_handler(void *handler_args, esp_event_base_t base,
                               int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = event_data;
    switch (event_id) {
        case MQTT_EVENT_CONNECTED:
            printf("[C MQTT] Connected to MQTT broker\n");
            tesla_zig_mqtt_on_connected();
            break;
        case MQTT_EVENT_DISCONNECTED:
            printf("[C MQTT] Disconnected from MQTT broker\n");
            break;
        case MQTT_EVENT_DATA:
            tesla_zig_mqtt_on_message(event->topic, event->topic_len, event->data, event->data_len);
            break;
        default:
            break;
    }
}

void tesla_c_mqtt_init(const char* broker_url) {
    printf("[C MQTT] Initializing MQTT client for URL: %s...\n", broker_url);
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = broker_url,
    };
#if defined(CONFIG_MQTT_USERNAME)
    if (strlen(CONFIG_MQTT_USERNAME) > 0) {
        mqtt_cfg.credentials.username = CONFIG_MQTT_USERNAME;
        printf("[C MQTT] Using MQTT Username: %s\n", CONFIG_MQTT_USERNAME);
    }
#endif
#if defined(CONFIG_MQTT_PASSWORD)
    if (strlen(CONFIG_MQTT_PASSWORD) > 0) {
        mqtt_cfg.credentials.authentication.password = CONFIG_MQTT_PASSWORD;
        printf("[C MQTT] Using MQTT Password: [configured]\n");
    }
#endif
    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(mqtt_client);
}

void tesla_c_mqtt_publish(const char* topic, const char* payload, int len, int qos, int retain) {
    if (!mqtt_client) return;
    esp_mqtt_client_publish(mqtt_client, topic, payload, len, qos, retain);
}

void tesla_c_mqtt_subscribe(const char* topic, int qos) {
    if (!mqtt_client) return;
    esp_mqtt_client_subscribe(mqtt_client, topic, qos);
}

// -------------------------------------------------------------
// NimBLE BLE Host Implementation
// -------------------------------------------------------------
static int on_gap_event(struct ble_gap_event *event, void *arg);

void tesla_c_ble_start_scan(void) {
    printf("[C BLE] Starting BLE scan for Tesla beacons...\n");
    struct ble_gap_disc_params disc_params = {
        .filter_duplicates = 1,
        .passive = 1,
        .itvl = 128,
        .window = 128,
        .filter_policy = 0,
    };
    int rc = ble_gap_disc(0, BLE_HS_FOREVER, &disc_params, on_gap_event, NULL);
    if (rc != 0) {
        printf("[C BLE] Error starting passive scan: %d\n", rc);
    }
}

static int on_gatt_rx_notify(uint16_t conn_handle, uint16_t attr_handle,
                             struct os_mbuf **om, void *arg) {
    uint16_t len = OS_MBUF_PKTLEN(*om);
    uint8_t payload[256];
    if (len > sizeof(payload)) len = sizeof(payload);
    os_mbuf_copydata(*om, 0, len, payload);

    tesla_zig_ble_on_rx_notification(payload, len);
    return 0;
}

static int on_cccd_write(uint16_t conn_handle, const struct ble_gatt_error *error,
                         struct ble_gatt_attr *attr, void *arg) {
    if (error->status == 0) {
        printf("[C BLE] CCCD write completed successfully! Subscribed to notifications.\n");
        tesla_zig_ble_on_channel_ready();
    } else {
        printf("[C BLE] CCCD write failed: status %d\n", error->status);
    }
    return 0;
}

static int on_gatt_disc_desc_rx(uint16_t conn_handle, const struct ble_gatt_error *error,
                                uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg) {
    if (error->status == BLE_HS_EDONE) {
        printf("[C BLE] RX Characteristic subscription complete!\n");
        return 0;
    }
    if (error->status != 0) {
        printf("[C BLE] RX CCCD descriptor discovery failed: status %d\n", error->status);
        return 0;
    }

    if (ble_uuid_cmp(&dsc->uuid.u, BLE_UUID16_DECLARE(BLE_GATT_DSC_CLT_CFG_UUID16)) == 0) {
        // Found CCCD! Write 0x0001 to subscribe to notifications
        uint8_t val[2] = {1, 0};
        int rc = ble_gattc_write_flat(conn_handle, dsc->handle, val, sizeof(val), on_cccd_write, NULL);
        if (rc != 0) {
            printf("[C BLE] Failed to write CCCD descriptor: %d\n", rc);
        } else {
            printf("[C BLE] Successfully initiated CCCD write.\n");
        }
    }
    return 0;
}

static int on_gatt_disc_chars(uint16_t conn_handle, const struct ble_gatt_error *error,
                              const struct ble_gatt_chr *chr, void *arg) {
    if (error->status == BLE_HS_EDONE) {
        printf("[C BLE] Service characteristic discovery complete.\n");
        if (gatt_rx_char_val_handle != 0) {
            printf("[C BLE] Subscribing to notifications on RX Char handle: %d...\n", gatt_rx_char_val_handle);
            ble_gattc_disc_all_dscs(conn_handle, gatt_rx_char_val_handle, gatt_rx_char_val_handle + 5,
                                    on_gatt_disc_desc_rx, NULL);
        }
        return 0;
    }
    if (error->status != 0) {
        printf("[C BLE] GATT characteristic discovery failed: status %d\n", error->status);
        return 0;
    }

    if (ble_uuid_cmp(&chr->uuid.u, &tesla_tx_char_uuid.u) == 0) {
        gatt_tx_char_val_handle = chr->val_handle;
        printf("[C BLE] Discovered Tesla TX (Write) Characteristic on handle: %d\n", gatt_tx_char_val_handle);
    } else if (ble_uuid_cmp(&chr->uuid.u, &tesla_rx_char_uuid.u) == 0) {
        gatt_rx_char_val_handle = chr->val_handle;
        printf("[C BLE] Discovered Tesla RX (Notify) Characteristic on handle: %d\n", gatt_rx_char_val_handle);
    }
    return 0;
}

static int on_gatt_disc_svc(uint16_t conn_handle, const struct ble_gatt_error *error,
                            const struct ble_gatt_svc *svc, void *arg) {
    if (error->status == BLE_HS_EDONE) {
        return 0;
    }
    if (error->status != 0) {
        printf("[C BLE] GATT service discovery failed: status %d\n", error->status);
        return 0;
    }

    printf("[C BLE] Discovered Tesla Secure Service. Range: %d to %d\n", svc->start_handle, svc->end_handle);
    ble_gattc_disc_all_chrs(conn_handle, svc->start_handle, svc->end_handle, on_gatt_disc_chars, NULL);
    return 0;
}

static uint8_t target_ble_mac[6] = {0};
static bool has_target_ble_mac = false;

static bool parse_mac_address(const char* str, uint8_t* mac) {
    if (!str || strlen(str) < 17) return false;
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            mac[i] = (uint8_t)m[i];
        }
        return true;
    }
    return false;
}

static int on_gap_event(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
        case BLE_GAP_EVENT_DISC: {
            bool is_match = false;
            if (has_target_ble_mac) {
                bool match_forward = true;
                bool match_reverse = true;
                for (int i = 0; i < 6; i++) {
                    if (event->disc.addr.val[i] != target_ble_mac[i]) {
                        match_forward = false;
                    }
                    if (event->disc.addr.val[i] != target_ble_mac[5 - i]) {
                        match_reverse = false;
                    }
                }
                if (match_forward || match_reverse) {
                    is_match = true;
                }
            } else {
                struct ble_hs_adv_fields fields;
                int rc = ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data);
                if (rc == 0) {
                    bool found = false;
                    for (int i = 0; i < fields.num_uuids16; i++) {
                        if (fields.uuids16[i].value == 0x0211) {
                            found = true; break;
                        }
                    }
                    if (!found && fields.uuids128 != NULL) {
                        for (int i = 0; i < fields.num_uuids128; i++) {
                            const uint8_t *u = fields.uuids128[i].value;
                            if (u[12] == 0x11 && u[13] == 0x02) {
                                found = true; break;
                            }
                        }
                    }
                    if (!found && fields.name != NULL && fields.name_len > 1) {
                        if (fields.name[0] == 'S' && fields.name[fields.name_len - 1] == 'C') {
                            found = true;
                        }
                    }
                    if (found) {
                        is_match = true;
                    }
                }
            }

            if (is_match) {
                printf("[C BLE] Tesla vehicle discovered! Stopping scan and notifying Zig...\n");
                ble_gap_disc_cancel();
                tesla_zig_ble_on_vehicle_discovered(&event->disc.addr);
            }
            break;
        }
        case BLE_GAP_EVENT_CONNECT: {
            if (event->connect.status == 0) {
                printf("[C BLE] Connection established successfully! Conn Handle: %d\n", event->connect.conn_handle);
                active_conn_handle = event->connect.conn_handle;
                tesla_zig_ble_on_connected(event->connect.conn_handle);

                // Start GATT Service discovery to find secure TX/RX chars
                printf("[C BLE] Discovering GATT services...\n");
                ble_gattc_disc_svc_by_uuid(active_conn_handle, &tesla_svc_uuid.u, on_gatt_disc_svc, NULL);
            } else {
                printf("[C BLE] Connection failed: status %d. Restarting scan...\n", event->connect.status);
                tesla_c_ble_start_scan();
            }
            break;
        }
        case BLE_GAP_EVENT_DISCONNECT: {
            printf("[C BLE] Disconnected from vehicle: reason %d. Restarting scan...\n", event->disconnect.reason);
            active_conn_handle = 0;
            gatt_tx_char_val_handle = 0;
            gatt_rx_char_val_handle = 0;
            tesla_zig_ble_on_disconnected();
            break;
        }
        case BLE_GAP_EVENT_NOTIFY_RX: {
            if (event->notify_rx.attr_handle == gatt_rx_char_val_handle) {
                on_gatt_rx_notify(event->notify_rx.conn_handle,
                                  event->notify_rx.attr_handle,
                                  &event->notify_rx.om, NULL);
            }
            break;
        }
    }
    return 0;
}

void tesla_c_ble_connect(const void* ble_addr) {
    printf("[C BLE] Connecting to vehicle MAC Address...\n");
    int rc = ble_gap_connect(0, (const ble_addr_t*)ble_addr, 30000, NULL, on_gap_event, NULL);
    if (rc != 0) {
        printf("[C BLE] Connect request failed: %d\n", rc);
    }
}

void tesla_c_ble_write_tx(uint16_t conn_handle, const uint8_t* data, int len) {
    if (gatt_tx_char_val_handle == 0) {
        printf("[C BLE] Cannot write: TX character handle not discovered yet.\n");
        return;
    }
    int rc = ble_gattc_write_flat(conn_handle, gatt_tx_char_val_handle, data, len, NULL, NULL);
    if (rc != 0) {
        printf("[C BLE] Error writing to TX characteristic: %d\n", rc);
    }
}

static void on_stack_sync(void) {
    printf("[C BLE] NimBLE Bluetooth stack synced!\n");
    tesla_c_ble_start_scan();
}

static void nimble_host_task(void *param) {
    printf("[C BLE] NimBLE host task started!\n");
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void tesla_c_ble_init(void) {
    printf("[C BLE] Initializing NimBLE Bluetooth stack...\n");
    
#if defined(CONFIG_BLE_MAC_ADDRESS)
    has_target_ble_mac = parse_mac_address(CONFIG_BLE_MAC_ADDRESS, target_ble_mac);
    if (has_target_ble_mac) {
        printf("[C BLE] Configured target BLE MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               target_ble_mac[0], target_ble_mac[1], target_ble_mac[2],
               target_ble_mac[3], target_ble_mac[4], target_ble_mac[5]);
    } else {
        printf("[C BLE] No valid target BLE MAC configured, will scan for any Tesla vehicle.\n");
    }
#endif

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        printf("[C BLE] nimble_port_init failed: %d\n", err);
        return;
    }
    
    ble_svc_gap_init();
    ble_svc_gatt_init();
    
    ble_hs_cfg.sync_cb = on_stack_sync;
    
    nimble_port_freertos_init(nimble_host_task);
}

// -------------------------------------------------------------
// Application Entry Point
// -------------------------------------------------------------
void app_main(void) {
    printf("[C System] Initializing system and flash memory...\n");
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    printf("[C System] NVS partition initialized: %d\n", err);

    esp_netif_init();
    esp_event_loop_create_default();

    // Check for registered/whitelisted private key in NVS "storage" namespace
    char nvs_b64_key[45] = {0};
    const char *api_key_to_use = CONFIG_API_ENCRYPTION_KEY;
    
    nvs_handle_t my_handle;
    esp_err_t nvs_err = nvs_open("storage", NVS_READONLY, &my_handle);
    if (nvs_err == ESP_OK) {
        size_t required_private_key_size = 0;
        nvs_err = nvs_get_blob(my_handle, "private_key", NULL, &required_private_key_size);
        if (nvs_err == ESP_OK && required_private_key_size > 0) {
            printf("[C System] Found real whitelisted private key blob in NVS 'storage' (size=%d bytes).\n", (int)required_private_key_size);
            unsigned char *private_key_buffer = malloc(required_private_key_size + 1);
            if (private_key_buffer != NULL) {
                nvs_err = nvs_get_blob(my_handle, "private_key", private_key_buffer, &required_private_key_size);
                if (nvs_err == ESP_OK) {
                    private_key_buffer[required_private_key_size] = '\0'; // Null-terminate for PEM format
                    
                    mbedtls_pk_context pk_ctx;
                    mbedtls_pk_init(&pk_ctx);
                    int parse_rc = mbedtls_pk_parse_key(&pk_ctx, private_key_buffer, required_private_key_size + 1, NULL, 0);
                    if (parse_rc == 0) {
                        mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(pk_ctx);
                        if (ecp != NULL) {
                            uint8_t raw_key[32];
                            int mpi_rc = mbedtls_mpi_write_binary(&ecp->d, raw_key, 32);
                            if (mpi_rc == 0) {
                                printf("[C System] Successfully extracted raw 32-byte SEC1 private key from mbedtls ECP keypair!\n");
                                base64_encode_32(raw_key, nvs_b64_key);
                                printf("[C System] NVS Base64 Key: %s\n", nvs_b64_key);
                                api_key_to_use = nvs_b64_key;
                            } else {
                                printf("[C System] Failed to write binary from mbedtls MPI (rc=%d)\n", mpi_rc);
                            }
                        } else {
                            printf("[C System] Failed to get ECP keypair context from parsed PK context.\n");
                        }
                    } else {
                        printf("[C System] mbedtls_pk_parse_key failed with error -0x%04x. Trying raw 32-byte parse...\n", -parse_rc);
                        if (required_private_key_size == 32) {
                            printf("[C System] Fallback: parsed directly as raw 32-byte key.\n");
                            base64_encode_32(private_key_buffer, nvs_b64_key);
                            printf("[C System] NVS Base64 Key: %s\n", nvs_b64_key);
                            api_key_to_use = nvs_b64_key;
                        }
                    }
                    mbedtls_pk_free(&pk_ctx);
                } else {
                    printf("[C System] Failed to read private key blob bytes from NVS storage.\n");
                }
                free(private_key_buffer);
            }
        } else {
            printf("[C System] No private_key blob found in NVS 'storage' (err=%d, len=%d). Using default config key.\n", nvs_err, (int)required_private_key_size);
        }
        nvs_close(my_handle);
    } else {
        printf("[C System] Failed to open NVS namespace 'storage' (err=%d). Using default config key.\n", nvs_err);
    }

    // Launch the core Zig-native application thread
    printf("[C System] Handing over execution thread to Zig...\n");
    tesla_zig_app_main(
        CONFIG_WIFI_SSID,
        CONFIG_WIFI_PASSWORD,
        CONFIG_MQTT_BROKER_URL,
        CONFIG_MQTT_USERNAME,
        CONFIG_MQTT_PASSWORD,
        CONFIG_VEHICLE_VIN,
        CONFIG_BLE_MAC_ADDRESS,
        api_key_to_use,
        CONFIG_VEHICLE_PUBLIC_KEY
    );
}
