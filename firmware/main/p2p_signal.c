#include "p2p_signal.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_websocket_client.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"

#include "p2p_config.h"
#include "p2p_crypto.h"
#include "p2p_tunnel.h"

static const char *TAG = "signal";

#define MAX_RELAYS 3
#define MSG_MAX 4096
#define MAX_SKEW_S 120
#define PROTO_VERSION 1

typedef struct {
    esp_websocket_client_handle_t client;
    char url[128];
    char *buf;
    int len;              // bytes assembled so far, -1 = discarding oversized frame
    volatile bool connected;
} relay_t;

static relay_t s_relays[MAX_RELAYS];
static int s_nrelays;
static QueueHandle_t s_queue;
static uint8_t s_nsk[32];
static char s_npub[65];

// Per-peer cached envelope keys and replay counters (signal task only).
typedef struct {
    bool used;
    uint8_t pub[32];
    uint8_t key[32];
    int64_t last_ts;
} peer_state_t;
static peer_state_t s_pstate[P2P_MAX_PEERS];

// Recently seen event ids (the same event arrives from several relays).
static uint64_t s_seen[32];
static int s_seen_pos;

const char *p2p_signal_npub_hex(void) { return s_npub; }

static bool clock_valid(void) { return time(NULL) > 1700000000; }

// ---------------------------------------------------------------------------
// relay connections
// ---------------------------------------------------------------------------
static void send_req(relay_t *r)
{
    char req[256];
    if (clock_valid()) {
        snprintf(req, sizeof(req), "[\"REQ\",\"p2ptun\",{\"kinds\":[%d],\"#p\":[\"%s\"],\"since\":%lld}]",
                 CONFIG_P2PTUN_NOSTR_KIND, s_npub, (long long)time(NULL) - 60);
    } else {
        snprintf(req, sizeof(req), "[\"REQ\",\"p2ptun\",{\"kinds\":[%d],\"#p\":[\"%s\"]}]",
                 CONFIG_P2PTUN_NOSTR_KIND, s_npub);
    }
    esp_websocket_client_send_text(r->client, req, strlen(req), pdMS_TO_TICKS(2000));
}

static void ws_handler(void *arg, esp_event_base_t base, int32_t id, void *event_data)
{
    relay_t *r = arg;
    esp_websocket_event_data_t *d = event_data;

    switch (id) {
    case WEBSOCKET_EVENT_CONNECTED:
        r->connected = true;
        ESP_LOGI(TAG, "relay connected: %s", r->url);
        send_req(r);
        break;
    case WEBSOCKET_EVENT_DISCONNECTED:
    case WEBSOCKET_EVENT_CLOSED:
    case WEBSOCKET_EVENT_ERROR:
        if (r->connected) {
            ESP_LOGW(TAG, "relay disconnected: %s", r->url);
        }
        r->connected = false;
        break;
    case WEBSOCKET_EVENT_DATA:
        if (d->op_code != 0x1 /* text */ || d->data_len <= 0) {
            break;
        }
        if (d->payload_offset == 0) {
            r->len = (d->payload_len < MSG_MAX) ? 0 : -1;
        }
        if (r->len < 0 || d->payload_offset != r->len || r->len + d->data_len >= MSG_MAX) {
            r->len = -1;
            break;
        }
        memcpy(r->buf + r->len, d->data_ptr, d->data_len);
        r->len += d->data_len;
        if (r->len >= d->payload_len) {
            char *msg = malloc(r->len + 1);
            if (msg) {
                memcpy(msg, r->buf, r->len);
                msg[r->len] = '\0';
                if (xQueueSend(s_queue, &msg, 0) != pdTRUE) {
                    free(msg); // busy: drop (also bounds work from relay spam)
                }
            }
            r->len = 0;
        }
        break;
    default:
        break;
    }
}

static void publish(const char *event_json)
{
    size_t n = strlen(event_json) + 16;
    char *msg = malloc(n);
    if (!msg) {
        return;
    }
    snprintf(msg, n, "[\"EVENT\",%s]", event_json);
    int sent = 0;
    for (int i = 0; i < s_nrelays; i++) {
        if (s_relays[i].connected &&
            esp_websocket_client_send_text(s_relays[i].client, msg, strlen(msg), pdMS_TO_TICKS(2000)) > 0) {
            sent++;
        }
    }
    if (!sent) {
        ESP_LOGW(TAG, "ack not delivered: no relay connected");
    }
    free(msg);
}

// ---------------------------------------------------------------------------
// knock handling
// ---------------------------------------------------------------------------
static bool seen_before(const char *id_hex)
{
    uint8_t b[8];
    char head[17];
    memcpy(head, id_hex, 16);
    head[16] = '\0';
    if (!p2p_hex_decode(head, b, 8)) {
        return true;
    }
    uint64_t v;
    memcpy(&v, b, 8);
    for (int i = 0; i < 32; i++) {
        if (s_seen[i] == v) {
            return true;
        }
    }
    s_seen[s_seen_pos] = v;
    s_seen_pos = (s_seen_pos + 1) % 32;
    return false;
}

static peer_state_t *peer_state(const uint8_t pub[32])
{
    peer_state_t *free_slot = NULL;
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (s_pstate[i].used && memcmp(s_pstate[i].pub, pub, 32) == 0) {
            return &s_pstate[i];
        }
        if (!s_pstate[i].used && !free_slot) {
            free_slot = &s_pstate[i];
        }
    }
    if (!free_slot) {
        free_slot = &s_pstate[esp_random() % P2P_MAX_PEERS];
    }
    memset(free_slot, 0, sizeof(*free_slot));
    if (p2p_envelope_key(p2p_config()->wg_priv, pub, free_slot->key) != 0) {
        return NULL;
    }
    memcpy(free_slot->pub, pub, 32);
    free_slot->used = true;
    return free_slot;
}

static bool parse_ep(const char *s, uint8_t ip[4], uint16_t *port)
{
    unsigned a, b, c, d, p;
    char tail;
    if (!s || sscanf(s, "%u.%u.%u.%u:%u%c", &a, &b, &c, &d, &p, &tail) != 5 ||
        a > 255 || b > 255 || c > 255 || d > 255 || p == 0 || p > 65535) {
        return false;
    }
    ip[0] = a; ip[1] = b; ip[2] = c; ip[3] = d;
    *port = (uint16_t)p;
    return true;
}

static bool has_p_tag(const cJSON *tags)
{
    const cJSON *t;
    cJSON_ArrayForEach(t, tags) {
        const cJSON *k = cJSON_GetArrayItem(t, 0), *v = cJSON_GetArrayItem(t, 1);
        if (cJSON_IsString(k) && cJSON_IsString(v) && !strcmp(k->valuestring, "p") && !strcmp(v->valuestring, s_npub)) {
            return true;
        }
    }
    return false;
}

static void handle_knock(const p2p_peer_t *peer, peer_state_t *ps, const cJSON *msg, const char *sender_npub)
{
    const cJSON *ts = cJSON_GetObjectItem(msg, "ts");
    const cJSON *nonce = cJSON_GetObjectItem(msg, "n");
    const cJSON *ep = cJSON_GetObjectItem(msg, "ep");
    const cJSON *lan = cJSON_GetObjectItem(msg, "lan");
    uint8_t nonce_bin[16];
    size_t nonce_len = cJSON_IsString(nonce) ? strlen(nonce->valuestring) : 0;
    // nonce is echoed into the ack: require short lowercase/uppercase hex only
    if (!cJSON_IsNumber(ts) || nonce_len == 0 || nonce_len > 32 || (nonce_len % 2) != 0 ||
        !p2p_hex_decode(nonce->valuestring, nonce_bin, nonce_len / 2) || !cJSON_IsString(ep)) {
        return;
    }
    // Replay protection: fresh timestamp, strictly increasing per peer.
    int64_t now = time(NULL), t = (int64_t)ts->valuedouble;
    if (!clock_valid() || llabs(now - t) > MAX_SKEW_S || t <= ps->last_ts) {
        ESP_LOGW(TAG, "knock from '%s' rejected (stale/replayed)", peer->name);
        return;
    }
    ps->last_ts = t;

    uint8_t ip[4];
    uint16_t port;
    if (!parse_ep(ep->valuestring, ip, &port)) {
        return;
    }
    char my_pub_ep[24] = "", my_lan_ep[24] = "";
    bool have_pub = p2p_tunnel_public_endpoint(my_pub_ep, sizeof(my_pub_ep));
    p2p_tunnel_lan_endpoint(my_lan_ep, sizeof(my_lan_ep));

    // Same public IP => client is behind our NAT; hairpinning often fails, use its LAN address.
    uint8_t lip[4];
    uint16_t lport;
    char my_pub_ip[20] = "";
    snprintf(my_pub_ip, sizeof(my_pub_ip), "%u.%u.%u.%u:", ip[0], ip[1], ip[2], ip[3]);
    if (have_pub && strncmp(my_pub_ep, my_pub_ip, strlen(my_pub_ip)) == 0 &&
        cJSON_IsString(lan) && parse_ep(lan->valuestring, lip, &lport)) {
        memcpy(ip, lip, 4);
        port = lport;
    }

    esp_err_t err = p2p_tunnel_set_endpoint(peer->pub, ip, port);
    ESP_LOGI(TAG, "knock from '%s' -> punching %u.%u.%u.%u:%u (%s)", peer->name, ip[0], ip[1], ip[2], ip[3], port,
             esp_err_to_name(err));
    if (err != ESP_OK) {
        return;
    }

    char pt[256];
    snprintf(pt, sizeof(pt), "{\"v\":%d,\"t\":\"ack\",\"ts\":%lld,\"n\":\"%s\",\"ep\":\"%s\",\"lan\":\"%s\"}",
             PROTO_VERSION, (long long)now, nonce->valuestring, my_pub_ep, my_lan_ep);
    char content[512];
    if (p2p_envelope_seal(ps->key, (const uint8_t *)pt, strlen(pt), content, sizeof(content)) != 0) {
        return;
    }
    char *ev = malloc(1100);
    if (ev && p2p_nostr_event(s_nsk, CONFIG_P2PTUN_NOSTR_KIND, (uint64_t)now, sender_npub, content, ev, 1100) > 0) {
        publish(ev);
    }
    free(ev);
}

static void handle_message(const char *raw)
{
    static p2p_peer_t peers[P2P_MAX_PEERS];
    cJSON *root = cJSON_Parse(raw);
    if (!cJSON_IsArray(root)) {
        goto out;
    }
    const cJSON *type = cJSON_GetArrayItem(root, 0);
    if (!cJSON_IsString(type)) {
        goto out;
    }
    if (!strcmp(type->valuestring, "NOTICE") || !strcmp(type->valuestring, "CLOSED")) {
        const cJSON *m = cJSON_GetArrayItem(root, cJSON_GetArraySize(root) - 1);
        ESP_LOGW(TAG, "relay %s: %s", type->valuestring, cJSON_IsString(m) ? m->valuestring : "?");
        goto out;
    }
    if (strcmp(type->valuestring, "EVENT") != 0 || cJSON_GetArraySize(root) != 3) {
        goto out;
    }
    const cJSON *ev = cJSON_GetArrayItem(root, 2);
    const cJSON *id = cJSON_GetObjectItem(ev, "id");
    const cJSON *pubkey = cJSON_GetObjectItem(ev, "pubkey");
    const cJSON *kind = cJSON_GetObjectItem(ev, "kind");
    const cJSON *content = cJSON_GetObjectItem(ev, "content");
    const cJSON *tags = cJSON_GetObjectItem(ev, "tags");
    uint8_t tmp[32];
    if (!cJSON_IsString(id) || strlen(id->valuestring) != 64 || !cJSON_IsString(pubkey) ||
        !p2p_hex_decode(pubkey->valuestring, tmp, 32) || !cJSON_IsNumber(kind) ||
        kind->valueint != CONFIG_P2PTUN_NOSTR_KIND || !cJSON_IsString(content) || !has_p_tag(tags)) {
        goto out;
    }
    if (seen_before(id->valuestring)) {
        goto out;
    }

    // Authenticate: the envelope only opens with the key shared with an *enabled* peer.
    // (Nostr signatures are not needed for security; relays already verify them.)
    p2p_config_peers_snapshot(peers);
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (!peers[i].host || !peers[i].enabled) {
            continue;
        }
        peer_state_t *ps = peer_state(peers[i].pub);
        uint8_t pt[512];
        int n;
        if (!ps || (n = p2p_envelope_open(ps->key, content->valuestring, pt, sizeof(pt) - 1)) < 0) {
            continue;
        }
        pt[n] = '\0';
        cJSON *msg = cJSON_Parse((const char *)pt);
        const cJSON *v = cJSON_GetObjectItem(msg, "v");
        const cJSON *t = cJSON_GetObjectItem(msg, "t");
        if (cJSON_IsNumber(v) && v->valueint == PROTO_VERSION && cJSON_IsString(t) && !strcmp(t->valuestring, "knock")) {
            handle_knock(&peers[i], ps, msg, pubkey->valuestring);
        }
        cJSON_Delete(msg);
        break;
    }
out:
    cJSON_Delete(root);
}

static void signal_task(void *arg)
{
    for (;;) {
        char *msg;
        if (xQueueReceive(s_queue, &msg, portMAX_DELAY) == pdTRUE) {
            handle_message(msg);
            free(msg);
        }
    }
}

// ---------------------------------------------------------------------------
esp_err_t p2p_signal_start(void)
{
    if (p2p_nostr_key_from_wg(p2p_config()->wg_priv, s_nsk) != 0) {
        return ESP_FAIL;
    }
    uint8_t pub[32];
    if (p2p_schnorr_pubkey(s_nsk, pub) != 0) {
        return ESP_FAIL;
    }
    p2p_hex_encode(pub, 32, s_npub);
    ESP_LOGI(TAG, "device nostr key: %s", s_npub);

    s_queue = xQueueCreate(8, sizeof(char *));
    if (!s_queue || xTaskCreate(signal_task, "signal", 8192, NULL, 5, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    char list[sizeof(p2p_config()->relays)];
    strlcpy(list, p2p_config()->relays, sizeof(list));
    char *save = NULL;
    for (char *url = strtok_r(list, ",", &save); url && s_nrelays < MAX_RELAYS; url = strtok_r(NULL, ",", &save)) {
        while (*url == ' ') url++;
        if (strncmp(url, "wss://", 6) != 0) {
            ESP_LOGW(TAG, "skipping non-TLS relay %s", url);
            continue;
        }
        relay_t *r = &s_relays[s_nrelays];
        strlcpy(r->url, url, sizeof(r->url));
        r->buf = malloc(MSG_MAX);
        if (!r->buf) {
            return ESP_ERR_NO_MEM;
        }
        esp_websocket_client_config_t cfg = {
            .uri = r->url,
            .crt_bundle_attach = esp_crt_bundle_attach, // verify relay TLS certificates
            .buffer_size = 1536,
            .task_stack = 6144,
            .reconnect_timeout_ms = 10000,
            .network_timeout_ms = 10000,
        };
        r->client = esp_websocket_client_init(&cfg);
        if (!r->client) {
            return ESP_FAIL;
        }
        esp_websocket_register_events(r->client, WEBSOCKET_EVENT_ANY, ws_handler, r);
        esp_websocket_client_start(r->client);
        s_nrelays++;
    }
    return s_nrelays ? ESP_OK : ESP_ERR_INVALID_ARG;
}

bool p2p_signal_relays_json(char *out, size_t len)
{
    size_t off = 0;
    int n = snprintf(out, len, "[");
    if (n < 0 || (size_t)n >= len) return false;
    off = n;
    for (int i = 0; i < s_nrelays; i++) {
        n = snprintf(out + off, len - off, "%s{\"url\":\"%s\",\"connected\":%s}", i ? "," : "",
                     s_relays[i].url, s_relays[i].connected ? "true" : "false");
        if (n < 0 || (size_t)n >= len - off) return false;
        off += n;
    }
    n = snprintf(out + off, len - off, "]");
    return n >= 0 && (size_t)n < len - off;
}
