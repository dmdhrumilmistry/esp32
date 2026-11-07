#include "p2p_config.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "p2p_crypto.h"

static const char *TAG = "config";
static const char *NS = "p2ptun";

static p2p_config_t s_cfg;
static SemaphoreHandle_t s_lock;

p2p_config_t *p2p_config(void) { return &s_cfg; }
void p2p_config_lock(void) { xSemaphoreTakeRecursive(s_lock, portMAX_DELAY); }
void p2p_config_unlock(void) { xSemaphoreGiveRecursive(s_lock); }

static esp_err_t get_blob(nvs_handle_t h, const char *key, void *out, size_t len)
{
    size_t n = len;
    esp_err_t err = nvs_get_blob(h, key, out, &n);
    if (err == ESP_OK && n != len) {
        return ESP_ERR_INVALID_SIZE;
    }
    return err;
}

static void get_str(nvs_handle_t h, const char *key, char *out, size_t len)
{
    size_t n = len;
    if (nvs_get_str(h, key, out, &n) != ESP_OK) {
        out[0] = '\0';
    }
}

esp_err_t p2p_config_load(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateRecursiveMutex();
    }
    memset(&s_cfg, 0, sizeof(s_cfg));

    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    get_str(h, "ssid", s_cfg.ssid, sizeof(s_cfg.ssid));
    get_str(h, "wifi_pass", s_cfg.wifi_pass, sizeof(s_cfg.wifi_pass));
    get_str(h, "relays", s_cfg.relays, sizeof(s_cfg.relays));
    if (s_cfg.relays[0] == '\0') {
        strlcpy(s_cfg.relays, CONFIG_P2PTUN_RELAYS, sizeof(s_cfg.relays));
    }
    s_cfg.admin_set = get_blob(h, "adm_salt", s_cfg.admin_salt, 16) == ESP_OK &&
                      get_blob(h, "adm_hash", s_cfg.admin_hash, 32) == ESP_OK;

    if (get_blob(h, "peers", s_cfg.peers, sizeof(s_cfg.peers)) != ESP_OK) {
        memset(s_cfg.peers, 0, sizeof(s_cfg.peers));
    }

    if (get_blob(h, "wg_priv", s_cfg.wg_priv, 32) != ESP_OK) {
        ESP_LOGI(TAG, "first boot: generating device WireGuard key");
        if (p2p_wg_genkey(s_cfg.wg_priv) != 0) {
            nvs_close(h);
            return ESP_FAIL;
        }
        err = nvs_set_blob(h, "wg_priv", s_cfg.wg_priv, 32);
        if (err == ESP_OK) {
            err = nvs_commit(h);
        }
    }
    nvs_close(h);
    return err;
}

static esp_err_t commit(const char *key, const void *blob, size_t len, const char *str)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = str ? nvs_set_str(h, key, str) : nvs_set_blob(h, key, blob, len);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t p2p_config_save_wifi(const char *ssid, const char *pass)
{
    strlcpy(s_cfg.ssid, ssid, sizeof(s_cfg.ssid));
    strlcpy(s_cfg.wifi_pass, pass, sizeof(s_cfg.wifi_pass));
    esp_err_t err = commit("ssid", NULL, 0, s_cfg.ssid);
    return err == ESP_OK ? commit("wifi_pass", NULL, 0, s_cfg.wifi_pass) : err;
}

esp_err_t p2p_config_save_admin(const uint8_t salt[16], const uint8_t hash[32])
{
    memcpy(s_cfg.admin_salt, salt, 16);
    memcpy(s_cfg.admin_hash, hash, 32);
    s_cfg.admin_set = true;
    esp_err_t err = commit("adm_salt", salt, 16, NULL);
    return err == ESP_OK ? commit("adm_hash", hash, 32, NULL) : err;
}

esp_err_t p2p_config_save_relays(const char *relays)
{
    strlcpy(s_cfg.relays, relays, sizeof(s_cfg.relays));
    return commit("relays", NULL, 0, s_cfg.relays);
}

esp_err_t p2p_config_save_peers(void)
{
    return commit("peers", s_cfg.peers, sizeof(s_cfg.peers), NULL);
}

esp_err_t p2p_config_factory_reset(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_erase_all(h);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

void p2p_config_peers_snapshot(p2p_peer_t out[P2P_MAX_PEERS])
{
    p2p_config_lock();
    memcpy(out, s_cfg.peers, sizeof(s_cfg.peers));
    p2p_config_unlock();
}
