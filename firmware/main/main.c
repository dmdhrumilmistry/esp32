// p2ptun: a tiny serverless WireGuard "routing peer" for ESP32.
//
//   client  ──(encrypted knock via public Nostr relays)──►  ESP32
//   client  ◄──────────── WireGuard, direct P2P (UDP hole punch) ───────────►  ESP32 ──NAPT──► LAN
//
// See README.md and docs/PROTOCOL.md.
#include <string.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
#include "esp_netif_sntp.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "bootloader_random.h"

#include "p2p_config.h"
#include "p2p_crypto.h"
#include "p2p_events.h"
#include "p2p_portmap.h"
#include "p2p_signal.h"
#include "p2p_tunnel.h"
#include "p2p_web.h"
#include "p2p_wifi.h"
#include "mdns.h"

static const char *TAG = "p2ptun";

static int hw_rng(void *ctx, unsigned char *out, size_t len)
{
    esp_fill_random(out, len);
    return 0;
}

// Factory reset: hold the button (BOOT/GPIO0 by default) for 5 s while the firmware runs.
// (Holding GPIO0 *at power-up* would enter the ROM download mode instead.)
static void reset_button_task(void *arg)
{
    const gpio_num_t pin = (gpio_num_t)CONFIG_P2PTUN_RESET_GPIO;
    gpio_config_t io = {.pin_bit_mask = 1ULL << pin, .mode = GPIO_MODE_INPUT, .pull_up_en = GPIO_PULLUP_ENABLE};
    gpio_config(&io);
    int held = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(100));
        held = gpio_get_level(pin) == 0 ? held + 1 : 0;
        if (held == 10) {
            ESP_LOGW(TAG, "reset button held: keep holding 4 more seconds to wipe all settings and keys");
        }
        if (held >= 50) {
            ESP_LOGW(TAG, "factory reset: wiping settings and keys");
            p2p_config_factory_reset();
            esp_restart();
        }
    }
}

// Revokes time-limited peers once their expiry passes (checked every 15 s).
static void expiry_task(void *arg)
{
    static p2p_peer_t expired[P2P_MAX_PEERS];
    for (;; vTaskDelay(pdMS_TO_TICKS(15000))) {
        time_t now = time(NULL);
        if (now < 1700000000) {
            continue; // clock not synced yet (time-limited peers stay unloaded meanwhile, see p2p_tunnel.c)
        }
        int n = 0;
        p2p_config_t *cfg = p2p_config();
        p2p_config_lock();
        for (int i = 0; i < P2P_MAX_PEERS; i++) {
            p2p_peer_t *p = &cfg->peers[i];
            if (p->host && p->enabled && p->expires && now >= (time_t)p->expires) {
                p->enabled = 0;
                expired[n++] = *p;
            }
        }
        if (n) {
            p2p_config_save_peers();
        }
        p2p_config_unlock();
        if (n) {
            p2p_tunnel_sync_peers(); // cuts their live sessions
            for (int i = 0; i < n; i++) {
                p2p_event("access for '%s' expired: peer blocked", expired[i].name);
            }
        }
    }
}

void app_main(void)
{
    p2p_events_init();
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    p2p_crypto_set_rng(hw_rng, NULL);
    xTaskCreate(reset_button_task, "reset_btn", 2560, NULL, 2, NULL);

    // Before Wi-Fi is running the hardware RNG is only a true RNG with the bootloader
    // entropy source enabled. Generate long-term keys under it, then turn it off
    // (it must be off before Wi-Fi starts).
    char setup_pass[13];
    bootloader_random_enable();
    ESP_ERROR_CHECK(p2p_config_load());
    p2p_wifi_gen_setup_password(setup_pass);
    bootloader_random_disable();

    p2p_config_t *cfg = p2p_config();
    uint8_t pub[32];
    char pub_b64[48];
    p2p_wg_pubkey(cfg->wg_priv, pub);
    p2p_b64_encode(pub, 32, pub_b64, sizeof(pub_b64));
    ESP_LOGI(TAG, "device WireGuard public key: %s", pub_b64);

    if (cfg->ssid[0] == '\0' || !cfg->admin_set) {
        ESP_ERROR_CHECK(p2p_wifi_start_setup_ap(setup_pass));
        ESP_ERROR_CHECK(p2p_web_start(true));
        return;
    }

    ESP_ERROR_CHECK(p2p_wifi_start_sta(cfg->ssid, cfg->wifi_pass));
    while (!p2p_wifi_wait_ip(30000)) {
        ESP_LOGW(TAG, "waiting for Wi-Fi '%s' (hold BOOT 5 s to factory-reset and reconfigure)", cfg->ssid);
    }

    // Wall-clock time is needed for replay protection of signaling messages.
    esp_sntp_config_t sntp = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    esp_netif_sntp_init(&sntp);
    if (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(20000)) != ESP_OK) {
        ESP_LOGW(TAG, "time not synced yet; knocks are rejected until it is");
    }

    ESP_ERROR_CHECK(p2p_tunnel_start());
    ESP_ERROR_CHECK(p2p_portmap_start());
    xTaskCreate(expiry_task, "expiry", 3072, NULL, 3, NULL);
    ESP_ERROR_CHECK(p2p_signal_start());
    ESP_ERROR_CHECK(p2p_web_start(false));

    // Find the device on the LAN as http://p2ptun.local (best effort).
    if (CONFIG_P2PTUN_MDNS_HOSTNAME[0] && mdns_init() == ESP_OK) {
        mdns_hostname_set(CONFIG_P2PTUN_MDNS_HOSTNAME);
        mdns_instance_name_set("p2ptun admin UI");
        mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
        ESP_LOGI(TAG, "mDNS: http://%s.local/", CONFIG_P2PTUN_MDNS_HOSTNAME);
    }
    ESP_LOGI(TAG, "ready: manage peers at http://<device-ip>/ (LAN) or http://%s.1/ (tunnel)",
             CONFIG_P2PTUN_TUNNEL_PREFIX);
}
