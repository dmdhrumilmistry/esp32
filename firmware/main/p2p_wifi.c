#include "p2p_wifi.h"

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "esp_bit_defs.h"

#include "p2p_crypto.h"

static const char *TAG = "wifi";
static EventGroupHandle_t s_events;
#define GOT_IP BIT0

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        // Don't block the default event loop; each connect attempt already takes seconds.
        xEventGroupClearBits(s_events, GOT_IP);
        ESP_LOGW(TAG, "disconnected (reason %d), reconnecting",
                 ((wifi_event_sta_disconnected_t *)data)->reason);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        ESP_LOGI(TAG, "got IP " IPSTR, IP2STR(&e->ip_info.ip));
        xEventGroupSetBits(s_events, GOT_IP);
    }
}

static esp_err_t common_init(void)
{
    s_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    return ESP_OK;
}

esp_err_t p2p_wifi_start_sta(const char *ssid, const char *pass)
{
    common_init();
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL));

    wifi_config_t cfg = {0};
    strlcpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid));
    strlcpy((char *)cfg.sta.password, pass, sizeof(cfg.sta.password));
    cfg.sta.threshold.authmode = pass[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    cfg.sta.pmf_cfg.capable = true;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE)); // lower latency for the tunnel
    return esp_wifi_start();
}

bool p2p_wifi_wait_ip(int timeout_ms)
{
    return xEventGroupWaitBits(s_events, GOT_IP, pdFALSE, pdTRUE, pdMS_TO_TICKS(timeout_ms)) & GOT_IP;
}

void p2p_wifi_gen_setup_password(char out[13])
{
    static const char alphabet[] = "abcdefghjkmnpqrstuvwxyz23456789"; // no look-alike chars
    uint8_t rnd[12];
    p2p_random(rnd, sizeof(rnd));
    for (int i = 0; i < 12; i++) {
        out[i] = alphabet[rnd[i] % (sizeof(alphabet) - 1)];
    }
    out[12] = '\0';
}

esp_err_t p2p_wifi_start_setup_ap(const char *pass)
{
    common_init();
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);

    wifi_config_t cfg = {0};
    int n = snprintf((char *)cfg.ap.ssid, sizeof(cfg.ap.ssid), "p2ptun-setup-%02x%02x", mac[4], mac[5]);
    cfg.ap.ssid_len = n;
    strlcpy((char *)cfg.ap.password, pass, sizeof(cfg.ap.password));
    cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
    cfg.ap.max_connection = 2;
    cfg.ap.channel = 6;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGW(TAG, "==================================================");
    ESP_LOGW(TAG, " SETUP MODE");
    ESP_LOGW(TAG, "  Wi-Fi:    %s", (char *)cfg.ap.ssid);
    ESP_LOGW(TAG, "  Password: %s", pass);
    ESP_LOGW(TAG, "  Open:     http://192.168.4.1/");
    ESP_LOGW(TAG, "==================================================");
    return ESP_OK;
}
