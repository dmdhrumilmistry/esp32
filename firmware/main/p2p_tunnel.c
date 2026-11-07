#include "p2p_tunnel.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/ip.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "lwip/lwip_napt.h"

#include "wireguardif.h"
#include "wireguard-platform.h"

#include "p2p_config.h"
#include "p2p_crypto.h"
#include "p2p_stun.h"

#if !IP_NAPT || !IP_FORWARD
#error "p2ptun needs CONFIG_LWIP_IP_FORWARD=y and CONFIG_LWIP_IPV4_NAPT=y (see sdkconfig.defaults)"
#endif

static const char *TAG = "tunnel";

static struct netif s_wg_netif_struct;
static struct netif *s_wg;
static uint8_t s_prefix[3];

typedef struct {
    bool used;
    uint8_t pub[32];
    u8_t idx;
} loaded_peer_t;
static loaded_peer_t s_loaded[P2P_MAX_PEERS];

// STUN state (written from the TCPIP thread hook, read elsewhere)
static SemaphoreHandle_t s_stun_sem;
static volatile bool s_stun_pending;
static uint8_t s_stun_txid[12];
static uint8_t s_pub_ip[4];
static uint16_t s_pub_port;
static volatile int64_t s_pub_time_us; // 0 = unknown

// ---------------------------------------------------------------------------
static bool parse_prefix(const char *s, uint8_t out[3])
{
    unsigned a, b, c;
    char tail;
    if (sscanf(s, "%u.%u.%u%c", &a, &b, &c, &tail) != 3 || a > 255 || b > 255 || c > 255) {
        return false;
    }
    out[0] = a; out[1] = b; out[2] = c;
    return true;
}

void p2p_tunnel_peer_ip(uint8_t host, char *out, size_t len)
{
    snprintf(out, len, "%u.%u.%u.%u", s_prefix[0], s_prefix[1], s_prefix[2], host);
}

// ---- STUN hook: runs in the TCPIP thread for every datagram on the WG port ----
static bool raw_rx_hook(const uint8_t *data, size_t len, const ip_addr_t *addr, u16_t port)
{
    if (!p2p_stun_is_stun(data, len)) {
        return false;
    }
    uint8_t ip[4];
    uint16_t mport;
    if (s_stun_pending && p2p_stun_parse_response(data, len, s_stun_txid, ip, &mport)) {
        memcpy(s_pub_ip, ip, 4);
        s_pub_port = mport;
        s_pub_time_us = esp_timer_get_time();
        s_stun_pending = false;
        xSemaphoreGive(s_stun_sem);
    }
    return true; // never hand STUN to WireGuard
}

typedef struct {
    ip_addr_t ip;
    u16_t port;
    uint8_t pkt[P2P_STUN_REQ_LEN];
} stun_send_t;

static esp_err_t do_stun_send(void *ctx)
{
    stun_send_t *s = ctx;
    return wireguardif_send_raw(s_wg, &s->ip, s->port, s->pkt, sizeof(s->pkt)) == ERR_OK ? ESP_OK : ESP_FAIL;
}

static bool stun_once(const char *server)
{
    char host[64];
    const char *colon = strrchr(server, ':');
    if (!colon || (size_t)(colon - server) >= sizeof(host)) {
        return false;
    }
    memcpy(host, server, colon - server);
    host[colon - server] = '\0';

    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM};
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, colon + 1, &hints, &res) != 0 || !res) {
        return false;
    }
    stun_send_t s;
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    ip_addr_set_ip4_u32(&s.ip, sin->sin_addr.s_addr);
    s.port = ntohs(sin->sin_port);
    freeaddrinfo(res);

    for (int attempt = 0; attempt < 2; attempt++) {
        p2p_random(s_stun_txid, sizeof(s_stun_txid));
        p2p_stun_build_request(s_stun_txid, s.pkt);
        xSemaphoreTake(s_stun_sem, 0); // clear stale signal
        s_stun_pending = true;
        if (esp_netif_tcpip_exec(do_stun_send, &s) == ESP_OK &&
            xSemaphoreTake(s_stun_sem, pdMS_TO_TICKS(1500)) == pdTRUE) {
            return true;
        }
        s_stun_pending = false;
    }
    return false;
}

static void stun_task(void *arg)
{
    char servers[] = CONFIG_P2PTUN_STUN_SERVERS;
    for (;;) {
        bool ok = false;
        char list[sizeof(servers)];
        memcpy(list, servers, sizeof(servers));
        char *save = NULL;
        for (char *srv = strtok_r(list, ",", &save); srv && !ok; srv = strtok_r(NULL, ",", &save)) {
            while (*srv == ' ') srv++;
            ok = stun_once(srv);
        }
        if (ok) {
            ESP_LOGD(TAG, "public endpoint %u.%u.%u.%u:%u", s_pub_ip[0], s_pub_ip[1], s_pub_ip[2], s_pub_ip[3], s_pub_port);
        } else {
            ESP_LOGW(TAG, "STUN failed (UDP blocked?)");
        }
        // Refreshing every 20 s also keeps the NAT mapping of the WireGuard port alive.
        vTaskDelay(pdMS_TO_TICKS(ok ? 20000 : 5000));
    }
}

bool p2p_tunnel_public_endpoint(char *out, size_t len)
{
    int64_t t = s_pub_time_us;
    if (t == 0 || esp_timer_get_time() - t > 120LL * 1000000) {
        return false;
    }
    snprintf(out, len, "%u.%u.%u.%u:%u", s_pub_ip[0], s_pub_ip[1], s_pub_ip[2], s_pub_ip[3], s_pub_port);
    return true;
}

bool p2p_tunnel_public_ip(uint8_t ip[4])
{
    int64_t t = s_pub_time_us;
    if (t == 0 || esp_timer_get_time() - t > 120LL * 1000000) {
        return false;
    }
    memcpy(ip, s_pub_ip, 4);
    return true;
}

static bool sta_ip(esp_netif_ip_info_t *info)
{
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    return sta && esp_netif_get_ip_info(sta, info) == ESP_OK && info->ip.addr != 0;
}

bool p2p_tunnel_lan_endpoint(char *out, size_t len)
{
    esp_netif_ip_info_t info;
    if (!sta_ip(&info)) {
        return false;
    }
    snprintf(out, len, IPSTR ":%d", IP2STR(&info.ip), CONFIG_P2PTUN_WG_PORT);
    return true;
}

bool p2p_tunnel_lan_subnet(char *out, size_t len)
{
    esp_netif_ip_info_t info;
    if (!sta_ip(&info)) {
        return false;
    }
    esp_ip4_addr_t net = {.addr = info.ip.addr & info.netmask.addr};
    int bits = __builtin_popcount(info.netmask.addr);
    snprintf(out, len, IPSTR "/%d", IP2STR(&net), bits);
    return true;
}

// ---------------------------------------------------------------------------
typedef struct {
    struct wireguardif_init_data init;
    ip4_addr_t ip, mask, gw;
} create_ctx_t;

static esp_err_t do_create(void *arg)
{
    create_ctx_t *c = arg;
    s_wg = netif_add(&s_wg_netif_struct, &c->ip, &c->mask, &c->gw, &c->init, &wireguardif_init, &ip_input);
    if (!s_wg) {
        return ESP_FAIL;
    }
    netif_set_up(s_wg);
    // Source-NAT traffic arriving from the tunnel onto the LAN, so LAN hosts need no routes.
    if (!ip_napt_enable_netif(s_wg, 1)) {
        ESP_LOGE(TAG, "enabling NAPT failed");
        return ESP_FAIL;
    }
    wireguardif_set_raw_rx_hook(raw_rx_hook);
    return ESP_OK;
}

esp_err_t p2p_tunnel_start(void)
{
    if (s_wg) {
        return ESP_OK;
    }
    if (!parse_prefix(CONFIG_P2PTUN_TUNNEL_PREFIX, s_prefix)) {
        ESP_LOGE(TAG, "bad CONFIG_P2PTUN_TUNNEL_PREFIX");
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = wireguard_platform_init();
    if (err != ESP_OK) {
        return err;
    }
    s_stun_sem = xSemaphoreCreateBinary();

    static char priv_b64[48];
    p2p_b64_encode(p2p_config()->wg_priv, 32, priv_b64, sizeof(priv_b64));

    create_ctx_t c = {
        .init = {.private_key = priv_b64, .listen_port = CONFIG_P2PTUN_WG_PORT, .bind_netif = NULL},
    };
    IP4_ADDR(&c.ip, s_prefix[0], s_prefix[1], s_prefix[2], 1);
    IP4_ADDR(&c.mask, 255, 255, 255, 0);
    IP4_ADDR(&c.gw, 0, 0, 0, 0);
    err = esp_netif_tcpip_exec(do_create, &c);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "creating WireGuard interface failed");
        return err;
    }
    ESP_LOGI(TAG, "WireGuard up on %u.%u.%u.1/24, UDP %d", s_prefix[0], s_prefix[1], s_prefix[2], CONFIG_P2PTUN_WG_PORT);

    p2p_tunnel_sync_peers();
    xTaskCreate(stun_task, "stun", 4096, NULL, 4, NULL);
    return ESP_OK;
}

// ---------------------------------------------------------------------------
static esp_err_t do_sync(void *arg)
{
    const p2p_peer_t *peers = arg;

    // 1. remove peers that are gone or disabled
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (!s_loaded[i].used) {
            continue;
        }
        bool keep = false;
        for (int j = 0; j < P2P_MAX_PEERS; j++) {
            if (peers[j].host && peers[j].enabled && memcmp(peers[j].pub, s_loaded[i].pub, 32) == 0) {
                keep = true;
                break;
            }
        }
        if (!keep) {
            wireguardif_disconnect(s_wg, s_loaded[i].idx);
            wireguardif_remove_peer(s_wg, s_loaded[i].idx); // zeroes keys: session is gone
            ESP_LOGI(TAG, "peer removed from WireGuard (slot %u)", s_loaded[i].idx);
            memset(&s_loaded[i], 0, sizeof(s_loaded[i]));
        }
    }
    // 2. add newly enabled peers
    for (int j = 0; j < P2P_MAX_PEERS; j++) {
        if (!peers[j].host || !peers[j].enabled) {
            continue;
        }
        bool have = false;
        int free_slot = -1;
        for (int i = 0; i < P2P_MAX_PEERS; i++) {
            if (s_loaded[i].used && memcmp(s_loaded[i].pub, peers[j].pub, 32) == 0) {
                have = true;
                break;
            }
            if (!s_loaded[i].used && free_slot < 0) {
                free_slot = i;
            }
        }
        if (have || free_slot < 0) {
            continue;
        }
        char pub_b64[48];
        p2p_b64_encode(peers[j].pub, 32, pub_b64, sizeof(pub_b64));
        struct wireguardif_peer p;
        wireguardif_peer_init(&p);
        p.public_key = pub_b64;
        p.preshared_key = NULL;
        IP_ADDR4(&p.allowed_ip, s_prefix[0], s_prefix[1], s_prefix[2], peers[j].host);
        IP_ADDR4(&p.allowed_mask, 255, 255, 255, 255);
        p.keep_alive = CONFIG_P2PTUN_KEEPALIVE;
        u8_t idx = WIREGUARDIF_INVALID_INDEX;
        if (wireguardif_add_peer(s_wg, &p, &idx) == ERR_OK && idx != WIREGUARDIF_INVALID_INDEX) {
            s_loaded[free_slot].used = true;
            s_loaded[free_slot].idx = idx;
            memcpy(s_loaded[free_slot].pub, peers[j].pub, 32);
            ESP_LOGI(TAG, "peer '%s' loaded (slot %u)", peers[j].name, idx);
        } else {
            ESP_LOGE(TAG, "wireguardif_add_peer failed for '%s'", peers[j].name);
        }
    }
    return ESP_OK;
}

void p2p_tunnel_sync_peers(void)
{
    if (!s_wg) {
        return;
    }
    static p2p_peer_t snap[P2P_MAX_PEERS]; // static: keep it off small task stacks
    static SemaphoreHandle_t sync_lock;
    if (!sync_lock) {
        sync_lock = xSemaphoreCreateMutex();
    }
    xSemaphoreTake(sync_lock, portMAX_DELAY);
    p2p_config_peers_snapshot(snap);
    esp_netif_tcpip_exec(do_sync, snap);
    xSemaphoreGive(sync_lock);
}

static int find_loaded(const uint8_t pub[32])
{
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (s_loaded[i].used && memcmp(s_loaded[i].pub, pub, 32) == 0) {
            return i;
        }
    }
    return -1;
}

typedef struct {
    const uint8_t *pub;
    ip_addr_t ip;
    u16_t port;
} endpoint_ctx_t;

static esp_err_t do_set_endpoint(void *arg)
{
    endpoint_ctx_t *e = arg;
    int i = find_loaded(e->pub);
    if (i < 0) {
        return ESP_ERR_NOT_FOUND;
    }
    if (wireguardif_update_endpoint(s_wg, s_loaded[i].idx, &e->ip, e->port) != ERR_OK ||
        wireguardif_connect(s_wg, s_loaded[i].idx) != ERR_OK) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t p2p_tunnel_set_endpoint(const uint8_t pub[32], const uint8_t ip[4], uint16_t port)
{
    if (!s_wg) {
        return ESP_ERR_INVALID_STATE;
    }
    endpoint_ctx_t e = {.pub = pub, .port = port};
    IP_ADDR4(&e.ip, ip[0], ip[1], ip[2], ip[3]);
    return esp_netif_tcpip_exec(do_set_endpoint, &e);
}

typedef struct {
    const uint8_t *pub;
    p2p_peer_status_t *out;
} status_ctx_t;

static esp_err_t do_status(void *arg)
{
    status_ctx_t *s = arg;
    int i = find_loaded(s->pub);
    if (i < 0) {
        return ESP_OK;
    }
    struct wireguardif_peer_stats st;
    if (wireguardif_get_peer_stats(s_wg, s_loaded[i].idx, &st) != ERR_OK) {
        return ESP_OK;
    }
    s->out->loaded = true;
    s->out->up = st.up;
    if (!ip_addr_isany(&st.ip) && st.port) {
        snprintf(s->out->endpoint, sizeof(s->out->endpoint), "%s:%u", ipaddr_ntoa(&st.ip), st.port);
    }
    uint32_t last = st.last_rx > st.last_handshake_rx ? st.last_rx : st.last_handshake_rx;
    s->out->last_rx_s = last ? (int32_t)((sys_now() - last) / 1000) : -1;
    return ESP_OK;
}

void p2p_tunnel_peer_status(const uint8_t pub[32], p2p_peer_status_t *out)
{
    memset(out, 0, sizeof(*out));
    out->last_rx_s = -1;
    if (!s_wg) {
        return;
    }
    status_ctx_t s = {.pub = pub, .out = out};
    esp_netif_tcpip_exec(do_status, &s);
}
