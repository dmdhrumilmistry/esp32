// Persistent device configuration (NVS) and the authorized-peer list.
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "sdkconfig.h"
#include "p2p_acl.h"

#define P2P_MAX_PEERS CONFIG_WIREGUARD_MAX_PEERS
#define P2P_NAME_LEN 24

typedef struct {
    char name[P2P_NAME_LEN];
    uint8_t pub[32];   // client's WireGuard public key
    uint8_t host;      // tunnel address = <prefix>.<host>; 0 = empty slot
    uint8_t enabled;   // 0 = blocked (not loaded into WireGuard)
    uint8_t reserved[2];
    uint32_t expires;  // unix seconds after which access is revoked automatically; 0 = never
    char acl[P2P_ACL_TEXT_LEN]; // access rules (see p2p_acl.h); "" = full access
} p2p_peer_t;

typedef struct {
    char ssid[33];
    char wifi_pass[65];
    bool admin_set;
    uint8_t admin_salt[16];
    uint8_t admin_hash[32];
    uint8_t wg_priv[32];
    char relays[256];
    char ep_override[72];   // "host:port" advertised instead of auto-detected endpoint ("" = auto)
    p2p_peer_t peers[P2P_MAX_PEERS];
} p2p_config_t;

esp_err_t p2p_config_load(void);           // also generates the device key on first boot
p2p_config_t *p2p_config(void);            // global config; hold p2p_config_lock() while touching peers
void p2p_config_lock(void);
void p2p_config_unlock(void);

esp_err_t p2p_config_save_wifi(const char *ssid, const char *pass);
esp_err_t p2p_config_save_admin(const uint8_t salt[16], const uint8_t hash[32]);
esp_err_t p2p_config_save_relays(const char *relays);
esp_err_t p2p_config_save_ep_override(const char *ep);
esp_err_t p2p_config_save_peers(void);     // caller holds the lock
esp_err_t p2p_config_factory_reset(void);

// Snapshot of the peer table (copy taken under the lock).
void p2p_config_peers_snapshot(p2p_peer_t out[P2P_MAX_PEERS]);
