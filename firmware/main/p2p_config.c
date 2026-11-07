#include "p2p_config.h"

#include <stdlib.h>
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

// Peer table layout before access rules / expiry were added (NVS key "peers").
typedef struct {
    char name[P2P_NAME_LEN];
    uint8_t pub[32];
    uint8_t host;
    uint8_t enabled;
} p2p_peer_v1_t;

static void migrate_v1_peers(nvs_handle_t h)
{
    p2p_peer_v1_t *old = calloc(P2P_MAX_PEERS, sizeof(*old));
    if (!old) {
        return;
    }
    if (get_blob(h, "peers", old, P2P_MAX_PEERS * sizeof(*old)) == ESP_OK) {
        for (int i = 0; i < P2P_MAX_PEERS; i++) {
            memcpy(s_cfg.peers[i].name, old[i].name, P2P_NAME_LEN);
            s_cfg.peers[i].name[P2P_NAME_LEN - 1] = '\0';
            memcpy(s_cfg.peers[i].pub, old[i].pub, 32);
            s_cfg.peers[i].host = old[i].host;
            s_cfg.peers[i].enabled = old[i].enabled;
        }
        if (nvs_set_blob(h, "peers2", s_cfg.peers, sizeof(s_cfg.peers)) == ESP_OK) {
            nvs_erase_key(h, "peers");
            nvs_commit(h);
            ESP_LOGI(TAG, "migrated peer table to v2 (access rules + expiry)");
        }
    }
    free(old);
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
    get_str(h, "ep_override", s_cfg.ep_override, sizeof(s_cfg.ep_override));
    get_str(h, "webclient", s_cfg.web_client, sizeof(s_cfg.web_client));
    uint8_t lock = 0;
    s_cfg.ui_tunnel_only = nvs_get_u8(h, "ui_lock", &lock) == ESP_OK && lock == 1;
    if (get_blob(h, "wol", s_cfg.wol, sizeof(s_cfg.wol)) != ESP_OK) {
        memset(s_cfg.wol, 0, sizeof(s_cfg.wol));
    }
    if (s_cfg.web_client[0] == '\0') {
        strlcpy(s_cfg.web_client, CONFIG_P2PTUN_WEB_CLIENT_URL, sizeof(s_cfg.web_client));
    }
    if (s_cfg.relays[0] == '\0') {
        strlcpy(s_cfg.relays, CONFIG_P2PTUN_RELAYS, sizeof(s_cfg.relays));
    }
    s_cfg.admin_set = get_blob(h, "adm_salt", s_cfg.admin_salt, 16) == ESP_OK &&
                      get_blob(h, "adm_hash", s_cfg.admin_hash, 32) == ESP_OK;

    if (get_blob(h, "peers2", s_cfg.peers, sizeof(s_cfg.peers)) != ESP_OK) {
        memset(s_cfg.peers, 0, sizeof(s_cfg.peers));
        migrate_v1_peers(h);
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

esp_err_t p2p_config_save_ep_override(const char *ep)
{
    char copy[sizeof(s_cfg.ep_override)];
    p2p_config_lock(); // read by the signal task (p2p_reach_endpoint)
    strlcpy(s_cfg.ep_override, ep, sizeof(s_cfg.ep_override));
    strlcpy(copy, s_cfg.ep_override, sizeof(copy));
    p2p_config_unlock();
    return commit("ep_override", NULL, 0, copy);
}

esp_err_t p2p_config_save_web_client(const char *url)
{
    char copy[sizeof(s_cfg.web_client)];
    p2p_config_lock();
    strlcpy(s_cfg.web_client, url, sizeof(s_cfg.web_client));
    strlcpy(copy, s_cfg.web_client, sizeof(copy));
    p2p_config_unlock();
    return commit("webclient", NULL, 0, copy);
}

esp_err_t p2p_config_save_ui_tunnel_only(bool on)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_u8(h, "ui_lock", on ? 1 : 0);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    if (err == ESP_OK) {
        s_cfg.ui_tunnel_only = on;
    }
    return err;
}

esp_err_t p2p_config_save_wol(void)
{
    return commit("wol", s_cfg.wol, sizeof(s_cfg.wol), NULL);
}

esp_err_t p2p_config_save_peers(void)
{
    return commit("peers2", s_cfg.peers, sizeof(s_cfg.peers), NULL);
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

int p2p_config_find_peer(const uint8_t pub[32])
{
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (s_cfg.peers[i].host && memcmp(s_cfg.peers[i].pub, pub, 32) == 0) {
            return i;
        }
    }
    return -1;
}

const char *p2p_config_add_peer(const char *name, const uint8_t pub[32], const char *acl, uint32_t expires,
                                p2p_peer_t *out)
{
    const char *err = NULL;
    p2p_config_lock();
    int slot = -1;
    bool used_host[256] = {false};
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (s_cfg.peers[i].host) {
            used_host[s_cfg.peers[i].host] = true;
        } else if (slot < 0) {
            slot = i;
        }
    }
    if (p2p_config_find_peer(pub) >= 0) {
        err = "this key is already a peer";
    } else if (slot < 0) {
        err = "peer table full";
    } else {
        uint8_t host = 2;
        while (used_host[host] && host < 254) host++;
        p2p_peer_t *p = &s_cfg.peers[slot];
        memset(p, 0, sizeof(*p));
        strlcpy(p->name, name, sizeof(p->name));
        memcpy(p->pub, pub, 32);
        p->host = host;
        p->enabled = 1;
        p->expires = expires;
        strlcpy(p->acl, acl ? acl : "", sizeof(p->acl));
        if (p2p_config_save_peers() != ESP_OK) {
            memset(p, 0, sizeof(*p));
            err = "saving failed";
        } else if (out) {
            *out = *p;
        }
    }
    p2p_config_unlock();
    return err;
}

void p2p_config_peers_snapshot(p2p_peer_t out[P2P_MAX_PEERS])
{
    p2p_config_lock();
    memcpy(out, s_cfg.peers, sizeof(s_cfg.peers));
    p2p_config_unlock();
}
