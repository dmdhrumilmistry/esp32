#include "p2p_invites.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "mbedtls/platform_util.h"

#include "p2p_config.h"
#include "p2p_crypto.h"
#include "p2p_events.h"
#include "p2p_tunnel.h"

#define MAX_INVITES 4
#define MAX_SKEW_S 120

enum { INV_FREE = 0, INV_PENDING, INV_USED, INV_REVOKED };

typedef struct {
    int id;
    uint8_t state;
    uint8_t key[32];
    char name[P2P_NAME_LEN];
    char acl[P2P_ACL_TEXT_LEN];
    uint32_t expires;        // access expiry for the peer it creates
    int64_t deadline_us;     // invite expiry (esp_timer clock)
    int64_t created_us;
    int64_t last_ts;         // replay protection
    uint8_t used_pub[32];
    char peer_ip[20];
} invite_t;

static invite_t s_inv[MAX_INVITES];
static int s_next_id = 1;
static SemaphoreHandle_t s_lock;

static void lock(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
}
static void unlock(void) { xSemaphoreGive(s_lock); }

static bool expired(const invite_t *v) { return esp_timer_get_time() > v->deadline_us; }

static void b64url(const uint8_t *in, size_t len, char *out, size_t size)
{
    p2p_b64_encode(in, len, out, size);
    char *w = out;
    for (char *r = out; *r; r++) {
        if (*r == '=') continue;
        *w++ = *r == '+' ? '-' : *r == '/' ? '_' : *r;
    }
    *w = '\0';
}

int p2p_invite_create(const char *name, const char *acl, uint32_t expires, char secret_b64u[24])
{
    uint8_t secret[16];
    if (p2p_random(secret, sizeof(secret)) != 0) {
        return 0;
    }
    lock();
    // Prefer a free / finished slot, otherwise replace the oldest pending invite.
    invite_t *slot = NULL;
    for (int i = 0; i < MAX_INVITES; i++) {
        invite_t *v = &s_inv[i];
        bool reusable = v->state != INV_PENDING || expired(v);
        if (reusable && (!slot || v->created_us < slot->created_us || slot->state == INV_PENDING)) {
            slot = v;
        }
    }
    if (!slot) {
        slot = &s_inv[0];
        for (int i = 1; i < MAX_INVITES; i++) {
            if (s_inv[i].created_us < slot->created_us) slot = &s_inv[i];
        }
    }
    memset(slot, 0, sizeof(*slot));
    slot->id = s_next_id++;
    slot->state = INV_PENDING;
    strlcpy(slot->name, name, sizeof(slot->name));
    strlcpy(slot->acl, acl ? acl : "", sizeof(slot->acl));
    slot->expires = expires;
    slot->created_us = esp_timer_get_time();
    slot->deadline_us = slot->created_us + (int64_t)P2P_INVITE_TTL_S * 1000000;
    int id = slot->id;
    int rc = p2p_pair_key(secret, sizeof(secret), slot->key);
    unlock();
    b64url(secret, sizeof(secret), secret_b64u, 24);
    mbedtls_platform_zeroize(secret, sizeof(secret));
    return rc == 0 ? id : 0;
}

bool p2p_invite_revoke(int id)
{
    bool ok = false;
    lock();
    for (int i = 0; i < MAX_INVITES; i++) {
        if (s_inv[i].state != INV_FREE && s_inv[i].id == id) {
            if (s_inv[i].state == INV_PENDING) {
                s_inv[i].state = INV_REVOKED;
                mbedtls_platform_zeroize(s_inv[i].key, sizeof(s_inv[i].key));
            }
            ok = true;
        }
    }
    unlock();
    return ok;
}

cJSON *p2p_invites_json(void)
{
    cJSON *arr = cJSON_CreateArray();
    int64_t now = esp_timer_get_time();
    lock();
    for (int n = 0; n < MAX_INVITES; n++) {
        // newest first
        invite_t *best = NULL;
        for (int i = 0; i < MAX_INVITES; i++) {
            invite_t *v = &s_inv[i];
            if (v->state == INV_FREE) continue;
            bool listed = false;
            for (cJSON *e = arr->child; e; e = e->next) {
                if (cJSON_GetObjectItem(e, "id")->valueint == v->id) listed = true;
            }
            if (!listed && (!best || v->id > best->id)) best = v;
        }
        if (!best) break;
        const char *state = best->state == INV_USED ? "used" : best->state == INV_REVOKED ? "revoked"
                          : expired(best) ? "expired" : "pending";
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", best->id);
        cJSON_AddStringToObject(o, "name", best->name);
        cJSON_AddStringToObject(o, "state", state);
        int64_t left = (best->deadline_us - now) / 1000000;
        cJSON_AddNumberToObject(o, "expires_in_s", left > 0 && best->state == INV_PENDING ? (double)left : 0);
        cJSON_AddStringToObject(o, "peer", best->peer_ip);
        cJSON_AddItemToArray(arr, o);
    }
    unlock();
    return arr;
}

static bool hex_nonce_ok(const char *s)
{
    size_t n = strlen(s);
    uint8_t tmp[16];
    return n > 0 && n <= 32 && n % 2 == 0 && p2p_hex_decode(s, tmp, n / 2);
}

bool p2p_invite_handle(const char *content, char *reply, size_t reply_size)
{
    uint8_t pt[512];
    int n = -1;
    invite_t *v = NULL;
    reply[0] = '\0';

    lock();
    for (int i = 0; i < MAX_INVITES && n < 0; i++) {
        if (s_inv[i].state == INV_PENDING || s_inv[i].state == INV_USED) {
            n = p2p_envelope_open(s_inv[i].key, content, pt, sizeof(pt) - 1);
            if (n >= 0) v = &s_inv[i];
        }
    }
    if (!v) {
        unlock();
        return false;
    }
    pt[n] = '\0';

    cJSON *msg = cJSON_Parse((const char *)pt);
    const cJSON *jv = cJSON_GetObjectItem(msg, "v"), *jt = cJSON_GetObjectItem(msg, "t");
    const cJSON *jts = cJSON_GetObjectItem(msg, "ts"), *jn = cJSON_GetObjectItem(msg, "n");
    const cJSON *jpub = cJSON_GetObjectItem(msg, "pub");
    uint8_t pub[32], mine[32];
    size_t publen = 0;
    time_t now = time(NULL);
    const char *err = NULL;
    bool send = true, newly_paired = false;
    char name[P2P_NAME_LEN] = "", address[24] = "";
    uint8_t key[32];
    memcpy(key, v->key, 32);

    if (!cJSON_IsNumber(jv) || jv->valueint != 1 || !cJSON_IsString(jt) || strcmp(jt->valuestring, "pair") != 0 ||
        !cJSON_IsNumber(jts) || !cJSON_IsString(jn) || !hex_nonce_ok(jn->valuestring) || !cJSON_IsString(jpub) ||
        !p2p_b64_decode(jpub->valuestring, pub, sizeof(pub), &publen) || publen != 32) {
        send = false; // malformed: stay silent
    } else if (now < 1700000000 || llabs((long long)(now - (time_t)jts->valuedouble)) > MAX_SKEW_S ||
               (int64_t)jts->valuedouble <= v->last_ts) {
        send = false; // stale / replayed / device clock unknown
    } else {
        v->last_ts = (int64_t)jts->valuedouble;
        p2p_wg_pubkey(p2p_config()->wg_priv, mine);
        if (v->state == INV_USED) {
            if (memcmp(pub, v->used_pub, 32) == 0) {
                strlcpy(name, v->name, sizeof(name)); // lost-ack retry
                snprintf(address, sizeof(address), "%s/32", v->peer_ip);
            } else {
                err = "invite already used";
            }
        } else if (expired(v)) {
            err = "invite expired";
        } else if (memcmp(pub, mine, 32) == 0) {
            err = "invalid key";
        } else {
            p2p_peer_t added;
            err = p2p_config_add_peer(v->name, pub, v->acl, v->expires, &added);
            if (!err) {
                v->state = INV_USED;
                memcpy(v->used_pub, pub, 32);
                p2p_tunnel_peer_ip(added.host, v->peer_ip, sizeof(v->peer_ip));
                strlcpy(name, added.name, sizeof(name));
                snprintf(address, sizeof(address), "%s/32", v->peer_ip);
                newly_paired = true;
            }
        }
    }
    char nonce[40] = "";
    if (send) strlcpy(nonce, jn->valuestring, sizeof(nonce));
    cJSON_Delete(msg);
    unlock();

    if (newly_paired) {
        p2p_event("peer '%s' paired via invite (%s)", name, address);
        p2p_tunnel_sync_peers();
    } else if (err) {
        p2p_event("pairing attempt rejected: %s", err);
    }
    if (send) {
        char body[256];
        if (err) {
            snprintf(body, sizeof(body), "{\"v\":1,\"t\":\"pair-error\",\"ts\":%lld,\"n\":\"%s\",\"error\":\"%s\"}",
                     (long long)now, nonce, err);
        } else {
            snprintf(body, sizeof(body),
                     "{\"v\":1,\"t\":\"paired\",\"ts\":%lld,\"n\":\"%s\",\"address\":\"%s\",\"name\":\"%s\"}",
                     (long long)now, nonce, address, name);
        }
        if (p2p_envelope_seal(key, (const uint8_t *)body, strlen(body), reply, reply_size) != 0) {
            reply[0] = '\0';
        }
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    return true;
}
