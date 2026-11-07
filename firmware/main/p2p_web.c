#include "p2p_web.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_http_server.h"
#include <time.h>
#include "cJSON.h"
#include "lwip/sockets.h"

#include "p2p_auth.h"
#include "p2p_config.h"
#include "p2p_acl.h"
#include "p2p_crypto.h"
#include "p2p_events.h"
#include "p2p_invites.h"
#include "p2p_wol.h"
#include "esp_netif.h"
#include "p2p_portmap.h"
#include "p2p_signal.h"
#include "p2p_tunnel.h"

static const char *TAG = "web";
static bool s_setup_mode;

extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[] asm("_binary_index_html_end");
extern const char qr_js_start[] asm("_binary_qr_js_start");
extern const char qr_js_end[] asm("_binary_qr_js_end");

#define MAX_BODY 1024

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
static void security_headers(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "Content-Security-Policy",
                       "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; "
                       "connect-src 'self'; img-src data:; form-action 'none'; frame-ancestors 'none'");
}

static esp_err_t send_json_str(httpd_req_t *req, const char *status, const char *json)
{
    security_headers(req);
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json);
}

static esp_err_t send_json(httpd_req_t *req, const char *status, cJSON *obj)
{
    char *s = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (!s) {
        return send_json_str(req, "500 Internal Server Error", "{\"error\":\"out of memory\"}");
    }
    esp_err_t err = send_json_str(req, status, s);
    free(s);
    return err;
}

static esp_err_t send_error(httpd_req_t *req, const char *status, const char *msg)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "error", msg);
    return send_json(req, status, o);
}

static esp_err_t send_ok(httpd_req_t *req)
{
    return send_json_str(req, "200 OK", "{\"ok\":true}");
}

// Reads a JSON body. Requiring Content-Type: application/json blocks cross-site form posts
// (CSRF): browsers can't send that header cross-origin without a CORS preflight we never allow.
static cJSON *read_json(httpd_req_t *req)
{
    char ctype[48] = "";
    if (httpd_req_get_hdr_value_str(req, "Content-Type", ctype, sizeof(ctype)) != ESP_OK ||
        strncmp(ctype, "application/json", 16) != 0) {
        return NULL;
    }
    if (req->content_len == 0 || req->content_len > MAX_BODY) {
        return NULL;
    }
    char *buf = malloc(req->content_len + 1);
    if (!buf) {
        return NULL;
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, buf + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (r <= 0) {
            free(buf);
            return NULL;
        }
        got += r;
    }
    buf[got] = '\0';
    cJSON *j = cJSON_Parse(buf);
    free(buf);
    if (!cJSON_IsObject(j)) {
        cJSON_Delete(j);
        return NULL;
    }
    return j;
}

static const char *jstr(const cJSON *o, const char *k)
{
    const cJSON *v = cJSON_GetObjectItem(o, k);
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

static bool session_cookie(httpd_req_t *req, char *tok, size_t len)
{
    size_t n = len;
    return httpd_req_get_cookie_val(req, "sid", tok, &n) == ESP_OK;
}

static bool authed(httpd_req_t *req)
{
    char tok[P2P_TOKEN_HEX_LEN + 1];
    return !s_setup_mode && session_cookie(req, tok, sizeof(tok)) && p2p_auth_session_valid(tok);
}

#define REQUIRE_AUTH(req) do { if (!authed(req)) return send_error(req, "401 Unauthorized", "login required"); } while (0)

static void restart_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

static void schedule_restart(void)
{
    xTaskCreate(restart_task, "restart", 2048, NULL, 5, NULL);
}

static bool decode_pub(const char *b64, uint8_t pub[32])
{
    size_t n = 0;
    return b64 && strlen(b64) == 44 && p2p_b64_decode(b64, pub, 32, &n) && n == 32;
}

static bool valid_name(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n == 0 || n >= P2P_NAME_LEN) {
        return false;
    }
    for (; *s; s++) {
        char c = *s;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == ' ' || c == '-' || c == '_' || c == '.')) {
            return false;
        }
    }
    return true;
}

// Remote address of the HTTP client, for the security log.
static void client_ip(httpd_req_t *req, char *out, size_t len)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    strlcpy(out, "?", len);
    if (getpeername(httpd_req_to_sockfd(req), (struct sockaddr *)&ss, &sl) != 0) {
        return;
    }
    if (ss.ss_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, out, len);
    }
#if LWIP_IPV6
    else if (ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)&ss;
        const uint8_t *a = (const uint8_t *)&s6->sin6_addr;
        static const uint8_t v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (memcmp(a, v4mapped, 12) == 0) {
            snprintf(out, len, "%u.%u.%u.%u", a[12], a[13], a[14], a[15]);
        } else {
            inet_ntop(AF_INET6, &s6->sin6_addr, out, len);
        }
    }
#endif
}

static bool clock_valid(void) { return time(NULL) > 1700000000; }
static bool from_tunnel(httpd_req_t *req);

#define MAX_EXPIRY_S (366L * 24 * 3600)

// Optional "acl" (access rules) and "expires_in" (seconds from now, 0 = never) fields.
// Returns an error message or NULL. *has_acl / *has_exp tell whether the field was present.
static const char *parse_access(const cJSON *j, char acl[P2P_ACL_TEXT_LEN], bool *has_acl,
                                uint32_t *expires, bool *has_exp)
{
    const cJSON *a = cJSON_GetObjectItem(j, "acl");
    const cJSON *e = cJSON_GetObjectItem(j, "expires_in");
    *has_acl = a != NULL;
    *has_exp = e != NULL;
    if (a) {
        static char err[112];
        p2p_acl_t parsed;
        if (!cJSON_IsString(a) || strlen(a->valuestring) >= P2P_ACL_TEXT_LEN) {
            return "acl: text of at most 95 characters";
        }
        if (!p2p_acl_parse(a->valuestring, &parsed, err, sizeof(err))) {
            return err;
        }
        strlcpy(acl, a->valuestring, P2P_ACL_TEXT_LEN);
    }
    if (e) {
        if (!cJSON_IsNumber(e) || e->valuedouble < 0 || e->valuedouble > MAX_EXPIRY_S) {
            return "expires_in: seconds from now (0 = never, max 1 year)";
        }
        if (e->valuedouble == 0) {
            *expires = 0;
        } else if (!clock_valid()) {
            return "the device clock isn't synced yet, so it can't set an expiry";
        } else {
            *expires = (uint32_t)(time(NULL) + (time_t)e->valuedouble);
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// state / status
// ---------------------------------------------------------------------------
static void add_relays_array(cJSON *parent, const char *key)
{
    cJSON *arr = cJSON_AddArrayToObject(parent, key);
    char list[sizeof(p2p_config()->relays)];
    strlcpy(list, p2p_config()->relays, sizeof(list));
    char *save = NULL;
    for (char *u = strtok_r(list, ",", &save); u; u = strtok_r(NULL, ",", &save)) {
        while (*u == ' ') u++;
        cJSON_AddItemToArray(arr, cJSON_CreateString(u));
    }
}

static cJSON *client_config(const p2p_peer_t *p)
{
    char buf[48];
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "name", p->name);
    p2p_tunnel_peer_ip(p->host, buf, sizeof(buf));
    strlcat(buf, "/32", sizeof(buf));
    cJSON_AddStringToObject(o, "address", buf);

    cJSON *dev = cJSON_AddObjectToObject(o, "device");
    uint8_t pub[32];
    p2p_wg_pubkey(p2p_config()->wg_priv, pub);
    p2p_b64_encode(pub, 32, buf, sizeof(buf));
    cJSON_AddStringToObject(dev, "wg_pub", buf);
    cJSON_AddStringToObject(dev, "nostr_pub", p2p_signal_npub_hex());
    p2p_tunnel_peer_ip(1, buf, sizeof(buf));
    cJSON_AddStringToObject(dev, "tunnel_ip", buf);
    cJSON *routes = cJSON_AddArrayToObject(dev, "routes");
    if (p2p_tunnel_lan_subnet(buf, sizeof(buf))) {
        cJSON_AddItemToArray(routes, cJSON_CreateString(buf));
    }
    add_relays_array(o, "relays");
    return o;
}

static esp_err_t h_state(httpd_req_t *req)
{
    cJSON *o = cJSON_CreateObject();
    if (s_setup_mode) {
        cJSON_AddStringToObject(o, "mode", "setup");
        return send_json(req, "200 OK", o);
    }
    if (!authed(req)) {
        cJSON_AddStringToObject(o, "mode", "login");
        return send_json(req, "200 OK", o);
    }
    cJSON_AddStringToObject(o, "mode", "admin");

    char buf[512];
    uint8_t pub[32];
    cJSON *dev = cJSON_AddObjectToObject(o, "device");
    p2p_wg_pubkey(p2p_config()->wg_priv, pub);
    p2p_b64_encode(pub, 32, buf, sizeof(buf));
    cJSON_AddStringToObject(dev, "wg_pub", buf);
    cJSON_AddStringToObject(dev, "nostr_pub", p2p_signal_npub_hex());
    p2p_tunnel_peer_ip(1, buf, sizeof(buf));
    cJSON_AddStringToObject(dev, "tunnel_ip", buf);
    cJSON_AddStringToObject(dev, "lan_subnet", p2p_tunnel_lan_subnet(buf, sizeof(buf)) ? buf : "");
    cJSON_AddStringToObject(dev, "public_ep", p2p_tunnel_public_endpoint(buf, sizeof(buf)) ? buf : "");
    cJSON_AddStringToObject(dev, "lan_ep", p2p_tunnel_lan_endpoint(buf, sizeof(buf)) ? buf : "");
    const char *via = "";
    cJSON_AddStringToObject(dev, "reach_ep", p2p_reach_endpoint(buf, sizeof(buf), &via) ? buf : "");
    cJSON_AddStringToObject(dev, "reach_via", via);
    p2p_portmap_status(buf, sizeof(buf));
    cJSON_AddStringToObject(dev, "reach_status", buf);
    cJSON_AddStringToObject(dev, "ep_override", p2p_config()->ep_override);
    if (p2p_signal_relays_json(buf, sizeof(buf))) {
        cJSON_AddItemToObject(dev, "relays", cJSON_Parse(buf));
    }

    static p2p_peer_t peers[P2P_MAX_PEERS];
    p2p_config_peers_snapshot(peers);
    cJSON *arr = cJSON_AddArrayToObject(o, "peers");
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (!peers[i].host) {
            continue;
        }
        p2p_peer_status_t st;
        p2p_tunnel_peer_status(peers[i].pub, &st);
        cJSON *p = cJSON_CreateObject();
        cJSON_AddStringToObject(p, "name", peers[i].name);
        p2p_b64_encode(peers[i].pub, 32, buf, sizeof(buf));
        cJSON_AddStringToObject(p, "pubkey", buf);
        p2p_tunnel_peer_ip(peers[i].host, buf, sizeof(buf));
        cJSON_AddStringToObject(p, "ip", buf);
        cJSON_AddBoolToObject(p, "enabled", peers[i].enabled);
        cJSON_AddBoolToObject(p, "up", st.up);
        cJSON_AddStringToObject(p, "endpoint", st.endpoint);
        cJSON_AddNumberToObject(p, "last_rx_s", st.last_rx_s);
        cJSON_AddStringToObject(p, "acl", peers[i].acl);
        cJSON_AddNumberToObject(p, "expires", peers[i].expires);
        cJSON_AddNumberToObject(p, "denied", st.denied);
        cJSON_AddNumberToObject(p, "rx_bytes", (double)st.rx_bytes);
        cJSON_AddNumberToObject(p, "tx_bytes", (double)st.tx_bytes);
        cJSON_AddStringToObject(p, "last_denied", st.last_denied);
        cJSON_AddItemToArray(arr, p);
    }
    cJSON_AddNumberToObject(o, "max_peers", P2P_MAX_PEERS);
    cJSON_AddNumberToObject(o, "now", clock_valid() ? (double)time(NULL) : 0);
    cJSON_AddItemToObject(o, "events", p2p_events_json());
    cJSON_AddItemToObject(o, "invites", p2p_invites_json());
    cJSON_AddStringToObject(o, "web_client", p2p_config()->web_client);
    cJSON_AddBoolToObject(o, "ui_tunnel_only", p2p_config()->ui_tunnel_only);
    cJSON_AddBoolToObject(o, "via_tunnel", from_tunnel(req));
    cJSON *wol = cJSON_AddArrayToObject(o, "wol");
    p2p_config_lock();
    for (int i = 0; i < P2P_MAX_WOL; i++) {
        if (!p2p_config()->wol[i].name[0]) continue;
        char m[18];
        p2p_format_mac(p2p_config()->wol[i].mac, m);
        cJSON *w = cJSON_CreateObject();
        cJSON_AddStringToObject(w, "name", p2p_config()->wol[i].name);
        cJSON_AddStringToObject(w, "mac", m);
        cJSON_AddItemToArray(wol, w);
    }
    p2p_config_unlock();
    return send_json(req, "200 OK", o);
}

// ---------------------------------------------------------------------------
// setup + auth
// ---------------------------------------------------------------------------
static esp_err_t h_setup(httpd_req_t *req)
{
    if (!s_setup_mode) {
        return send_error(req, "403 Forbidden", "already configured (factory reset to redo setup)");
    }
    cJSON *j = read_json(req);
    if (!j) {
        return send_error(req, "400 Bad Request", "expected JSON body");
    }
    const char *ssid = jstr(j, "ssid"), *wpass = jstr(j, "wifi_pass"), *apass = jstr(j, "admin_pass");
    const char *err = NULL;
    if (!ssid || !*ssid || strlen(ssid) > 32) err = "Wi-Fi name must be 1-32 characters";
    else if (!wpass || (strlen(wpass) > 0 && (strlen(wpass) < 8 || strlen(wpass) > 63))) err = "Wi-Fi password must be empty or 8-63 characters";
    else if (!apass || strlen(apass) < 10 || strlen(apass) > 128) err = "Admin password must be 10-128 characters";
    if (err) {
        cJSON_Delete(j);
        return send_error(req, "400 Bad Request", err);
    }
    esp_err_t e = p2p_config_save_wifi(ssid, wpass);
    if (e == ESP_OK) {
        e = p2p_auth_set_password(apass);
    }
    cJSON_Delete(j);
    if (e != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "saving settings failed");
    }
    p2p_event("first-time setup completed, rebooting onto Wi-Fi '%s'", p2p_config()->ssid);
    schedule_restart();
    return send_ok(req);
}

static esp_err_t h_login(httpd_req_t *req)
{
    if (s_setup_mode) {
        return send_error(req, "403 Forbidden", "setup required");
    }
    cJSON *j = read_json(req);
    const char *pw = j ? jstr(j, "password") : NULL;
    if (!pw || strlen(pw) > 128) {
        cJSON_Delete(j);
        return send_error(req, "400 Bad Request", "expected {\"password\":...}");
    }
    int locked = 0;
    bool ok = p2p_auth_check_password(pw, &locked);
    cJSON_Delete(j);
    char ip[48];
    client_ip(req, ip, sizeof(ip));
    if (!ok) {
        p2p_event(locked ? "admin login failed from %s (locked out)" : "admin login failed from %s", ip);
        if (locked) {
            char msg[64];
            snprintf(msg, sizeof(msg), "too many attempts, try again in %d s", locked);
            return send_error(req, "429 Too Many Requests", msg);
        }
        return send_error(req, "401 Unauthorized", "wrong password");
    }
    char tok[P2P_TOKEN_HEX_LEN + 1], cookie[128];
    if (!p2p_auth_new_session(tok)) {
        return send_error(req, "500 Internal Server Error", "rng failure");
    }
    snprintf(cookie, sizeof(cookie), "sid=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800", tok);
    p2p_event("admin logged in from %s", ip);
    httpd_resp_set_hdr(req, "Set-Cookie", cookie);
    return send_ok(req);
}

static esp_err_t h_logout(httpd_req_t *req)
{
    char tok[P2P_TOKEN_HEX_LEN + 1];
    if (session_cookie(req, tok, sizeof(tok))) {
        p2p_auth_end_session(tok);
    }
    httpd_resp_set_hdr(req, "Set-Cookie", "sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    return send_ok(req);
}

static esp_err_t h_password(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const char *cur = j ? jstr(j, "current") : NULL, *nw = j ? jstr(j, "new") : NULL;
    int locked = 0;
    esp_err_t r;
    if (!cur || !nw || strlen(nw) < 10 || strlen(nw) > 128) {
        r = send_error(req, "400 Bad Request", "new password must be 10-128 characters");
    } else if (!p2p_auth_check_password(cur, &locked)) {
        r = send_error(req, locked ? "429 Too Many Requests" : "403 Forbidden", "current password is wrong");
    } else if (p2p_auth_set_password(nw) != ESP_OK) { // also logs out every session
        r = send_error(req, "500 Internal Server Error", "saving failed");
    } else {
        p2p_event("admin password changed (all sessions logged out)");
        r = send_ok(req);
    }
    cJSON_Delete(j);
    return r;
}

// ---------------------------------------------------------------------------
// peers
// ---------------------------------------------------------------------------
static int find_peer(const uint8_t pub[32]) { return p2p_config_find_peer(pub); }

static esp_err_t h_peer_add(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const char *name = j ? jstr(j, "name") : NULL, *pk = j ? jstr(j, "pubkey") : NULL;
    uint8_t pub[32], mine[32];
    const char *err = NULL;
    char acl[P2P_ACL_TEXT_LEN] = "", pname[P2P_NAME_LEN] = "";
    uint32_t expires = 0;
    bool has_acl, has_exp;
    p2p_wg_pubkey(p2p_config()->wg_priv, mine);
    if (!valid_name(name)) err = "name: 1-23 chars of letters, digits, space, - _ .";
    else if (!decode_pub(pk, pub)) err = "pubkey must be a base64 WireGuard public key";
    else if (memcmp(pub, mine, 32) == 0) err = "that is the device's own key";
    else err = parse_access(j, acl, &has_acl, &expires, &has_exp);
    if (!err) strlcpy(pname, name, sizeof(pname)); // name points into j, which is freed below
    if (err) {
        cJSON_Delete(j);
        return send_error(req, "400 Bad Request", err);
    }

    p2p_peer_t added;
    err = p2p_config_add_peer(pname, pub, acl, expires, &added);
    cJSON_Delete(j);
    if (err) {
        return send_error(req, "409 Conflict", err);
    }
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddItemToObject(resp, "client", client_config(&added));
    p2p_event("peer '%s' authorized (%s%s)", pname, acl[0] ? "access: " : "full access",
              acl[0] ? acl : (expires ? ", expiring" : ""));
    p2p_tunnel_sync_peers();
    return send_json(req, "200 OK", resp);
}

// action: 0 = disable (cut + block), 1 = enable, 2 = delete, 3 = show client config
static esp_err_t peer_action(httpd_req_t *req, int action)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    uint8_t pub[32];
    if (!j || !decode_pub(jstr(j, "pubkey"), pub)) {
        cJSON_Delete(j);
        return send_error(req, "400 Bad Request", "pubkey required");
    }
    cJSON_Delete(j);
    p2p_config_t *c = p2p_config();
    p2p_config_lock();
    int i = find_peer(pub);
    if (i < 0) {
        p2p_config_unlock();
        return send_error(req, "404 Not Found", "unknown peer");
    }
    if (action == 3) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddItemToObject(resp, "client", client_config(&c->peers[i]));
        p2p_config_unlock();
        return send_json(req, "200 OK", resp);
    }
    p2p_peer_t backup = c->peers[i];
    if (action == 2) {
        memset(&c->peers[i], 0, sizeof(c->peers[i]));
    } else {
        c->peers[i].enabled = (action == 1);
        // Re-allowing an expired peer clears the stale expiry (otherwise it'd be blocked again at once).
        if (action == 1 && c->peers[i].expires && clock_valid() && time(NULL) >= (time_t)c->peers[i].expires) {
            c->peers[i].expires = 0;
        }
    }
    esp_err_t e = p2p_config_save_peers();
    if (e != ESP_OK) {
        c->peers[i] = backup;
    }
    p2p_config_unlock();
    if (e != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "saving failed");
    }
    p2p_event("peer '%s' %s", backup.name,
              action == 2 ? "deleted" : action == 1 ? "allowed" : "blocked (live session cut)");
    p2p_tunnel_sync_peers(); // disabling/deleting drops the live WireGuard session immediately
    return send_ok(req);
}

// Change a peer's access rules and/or expiry. Takes effect immediately.
static esp_err_t h_peer_update(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    uint8_t pub[32];
    char acl[P2P_ACL_TEXT_LEN] = "";
    uint32_t expires = 0;
    bool has_acl = false, has_exp = false;
    const char *err = NULL;
    if (!j || !decode_pub(jstr(j, "pubkey"), pub)) err = "pubkey required";
    else err = parse_access(j, acl, &has_acl, &expires, &has_exp);
    cJSON_Delete(j);
    if (err) {
        return send_error(req, "400 Bad Request", err);
    }
    p2p_config_t *c = p2p_config();
    p2p_config_lock();
    int i = find_peer(pub);
    if (i < 0) {
        p2p_config_unlock();
        return send_error(req, "404 Not Found", "unknown peer");
    }
    p2p_peer_t backup = c->peers[i];
    if (has_acl) strlcpy(c->peers[i].acl, acl, sizeof(c->peers[i].acl));
    if (has_exp) c->peers[i].expires = expires;
    esp_err_t e = p2p_config_save_peers();
    if (e != ESP_OK) {
        c->peers[i] = backup;
    }
    p2p_peer_t now = c->peers[i];
    p2p_config_unlock();
    if (e != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "saving failed");
    }
    p2p_event("peer '%s' updated: %s%s%s", now.name, now.acl[0] ? "access " : "full access",
              now.acl[0] ? now.acl : "", now.expires ? ", expiring" : ", no expiry");
    p2p_tunnel_sync_peers(); // new rules apply to the live session immediately
    return send_ok(req);
}

// ---------------------------------------------------------------------------
// invites (one-scan pairing)
// ---------------------------------------------------------------------------
static char *b64url_alloc(const char *in)
{
    size_t n = strlen(in), cap = (n + 2) / 3 * 4 + 1;
    char *out = malloc(cap);
    if (!out || !p2p_b64_encode((const uint8_t *)in, n, out, cap)) {
        free(out);
        return NULL;
    }
    char *w = out;
    for (char *r = out; *r; r++) {
        if (*r == '=') continue;
        *w++ = *r == '+' ? '-' : *r == '/' ? '_' : *r;
    }
    *w = '\0';
    return out;
}

static esp_err_t h_invite_create(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const char *name = j ? jstr(j, "name") : NULL;
    char acl[P2P_ACL_TEXT_LEN] = "", pname[P2P_NAME_LEN] = "", secret[24];
    uint32_t expires = 0;
    bool has_acl, has_exp;
    const char *err = !valid_name(name) ? "name: 1-23 chars of letters, digits, space, - _ ."
                                        : parse_access(j, acl, &has_acl, &expires, &has_exp);
    if (!err) strlcpy(pname, name, sizeof(pname));
    cJSON_Delete(j);
    if (err) {
        return send_error(req, "400 Bad Request", err);
    }
    int id = p2p_invite_create(pname, acl, expires, secret);
    if (!id) {
        return send_error(req, "500 Internal Server Error", "could not create invite");
    }
    // Invite payload = device block + relays + secret; travels only in the URL #fragment.
    p2p_peer_t tmp = {0};
    strlcpy(tmp.name, pname, sizeof(tmp.name));
    tmp.host = 1;
    cJSON *inv = client_config(&tmp);
    cJSON_DeleteItemFromObject(inv, "address"); // assigned when the invite is used
    cJSON_AddNumberToObject(inv, "v", 1);
    cJSON_AddStringToObject(inv, "secret", secret);
    char *payload = cJSON_PrintUnformatted(inv);
    cJSON_Delete(inv);
    char *enc = payload ? b64url_alloc(payload) : NULL;
    free(payload);
    if (!enc) {
        return send_error(req, "500 Internal Server Error", "out of memory");
    }
    size_t link_len = strlen(p2p_config()->web_client) + strlen(enc) + 16;
    char *link = malloc(link_len);
    if (link) {
        snprintf(link, link_len, "%s#p2ptun=%s", p2p_config()->web_client, enc);
    }
    free(enc);
    if (!link) {
        return send_error(req, "500 Internal Server Error", "out of memory");
    }
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "id", id);
    cJSON_AddStringToObject(resp, "link", link);
    cJSON_AddNumberToObject(resp, "expires_in_s", P2P_INVITE_TTL_S);
    free(link);
    p2p_event("invite #%d created for '%s' (valid %d min)", id, pname, P2P_INVITE_TTL_S / 60);
    return send_json(req, "200 OK", resp);
}

static esp_err_t h_invite_revoke(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const cJSON *id = j ? cJSON_GetObjectItem(j, "id") : NULL;
    bool ok = cJSON_IsNumber(id) && p2p_invite_revoke(id->valueint);
    int idv = ok ? id->valueint : 0;
    cJSON_Delete(j);
    if (!ok) {
        return send_error(req, "404 Not Found", "unknown invite");
    }
    p2p_event("invite #%d revoked", idv);
    return send_ok(req);
}

static esp_err_t h_web_client(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const char *url = j ? jstr(j, "url") : NULL;
    esp_err_t r;
    if (!url || strlen(url) >= sizeof(p2p_config()->web_client) || strncmp(url, "https://", 8) != 0 ||
        strlen(url) < 12 || strpbrk(url, "\"'<> #\\")) {
        r = send_error(req, "400 Bad Request", "url must be an https:// address without spaces or #");
    } else if (p2p_config_save_web_client(url) != ESP_OK) {
        r = send_error(req, "500 Internal Server Error", "saving failed");
    } else {
        p2p_event("web client URL changed");
        r = send_ok(req);
    }
    cJSON_Delete(j);
    return r;
}

static esp_err_t h_qr_js(httpd_req_t *req)
{
    security_headers(req);
    httpd_resp_set_type(req, "text/javascript; charset=utf-8");
    return httpd_resp_send(req, qr_js_start, qr_js_end - qr_js_start - 1);
}

static esp_err_t h_peer_disable(httpd_req_t *req) { return peer_action(req, 0); }
static esp_err_t h_peer_enable(httpd_req_t *req) { return peer_action(req, 1); }
static esp_err_t h_peer_delete(httpd_req_t *req) { return peer_action(req, 2); }
static esp_err_t h_peer_config(httpd_req_t *req) { return peer_action(req, 3); }

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------
static esp_err_t h_relays(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const char *r = j ? jstr(j, "relays") : NULL;
    const char *err = NULL;
    if (!r || strlen(r) >= sizeof(p2p_config()->relays)) {
        err = "relays: comma separated wss:// URLs";
    } else {
        char list[sizeof(p2p_config()->relays)];
        strlcpy(list, r, sizeof(list));
        int n = 0;
        char *save = NULL;
        for (char *u = strtok_r(list, ",", &save); u && !err; u = strtok_r(NULL, ",", &save)) {
            while (*u == ' ') u++;
            if (strncmp(u, "wss://", 6) != 0 || strlen(u) < 8 || strlen(u) > 120 || strpbrk(u, "\"\\ <>'")) {
                err = "each relay must be a wss:// URL";
            }
            n++;
        }
        if (!err && (n == 0 || n > 3)) err = "use 1 to 3 relays";
    }
    esp_err_t e = err ? ESP_OK : p2p_config_save_relays(r);
    if (!err && e == ESP_OK) p2p_event("signaling relays changed (reboot to apply)");
    cJSON_Delete(j);
    if (err) return send_error(req, "400 Bad Request", err);
    if (e != ESP_OK) return send_error(req, "500 Internal Server Error", "saving failed");
    return send_json_str(req, "200 OK", "{\"ok\":true,\"reboot_required\":true}");
}

// "host:port" (DNS name or IPv4) or "" to go back to automatic detection.
static bool valid_endpoint(const char *s)
{
    if (!*s) {
        return true;
    }
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || colon - s > 63) {
        return false;
    }
    for (const char *p = s; p < colon; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return false;
        }
    }
    char *end;
    long port = strtol(colon + 1, &end, 10);
    return *end == '\0' && end != colon + 1 && port > 0 && port <= 65535;
}

static esp_err_t h_endpoint(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const char *ep = j ? jstr(j, "endpoint") : NULL;
    esp_err_t r;
    if (!ep || strlen(ep) >= sizeof(p2p_config()->ep_override) || !valid_endpoint(ep)) {
        r = send_error(req, "400 Bad Request", "endpoint must be host:port (or empty for automatic)");
    } else if (p2p_config_save_ep_override(ep) != ESP_OK) {
        r = send_error(req, "500 Internal Server Error", "saving failed");
    } else {
        p2p_event(ep[0] ? "endpoint override set to %s" : "endpoint override cleared%s", ep);
        r = send_ok(req);
    }
    cJSON_Delete(j);
    return r;
}

static esp_err_t h_reboot(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req); // still require the JSON content-type (CSRF)
    if (!j) return send_error(req, "400 Bad Request", "expected JSON body");
    cJSON_Delete(j);
    p2p_event("reboot requested from the web UI");
    schedule_restart();
    return send_ok(req);
}

static esp_err_t h_index(httpd_req_t *req)
{
    security_headers(req);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, index_html_start, index_html_end - index_html_start - 1); // drop NUL from EMBED_TXTFILES
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// admin UI lockdown (tunnel only)
// ---------------------------------------------------------------------------
// Client IPv4 (host byte order) of this request, 0 if unknown.
static uint32_t client_ipv4(httpd_req_t *req)
{
    char ip[48];
    unsigned a, b, c, d;
    client_ip(req, ip, sizeof(ip));
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 || c > 255 || d > 255) {
        return 0;
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static bool from_tunnel(httpd_req_t *req)
{
    char dev[20];
    unsigned a, b, c, d;
    p2p_tunnel_peer_ip(1, dev, sizeof(dev));
    if (sscanf(dev, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return false;
    }
    uint32_t net = (a << 24) | (b << 16) | (c << 8);
    uint32_t ip = client_ipv4(req);
    return ip && (ip & 0xFFFFFF00u) == net && ip != (net | 1);
}

// Every route goes through here: with "tunnel only" on, LAN clients get nothing.
static esp_err_t h_guard(httpd_req_t *req)
{
    if (!s_setup_mode && p2p_config()->ui_tunnel_only && !from_tunnel(req)) {
        return send_error(req, "403 Forbidden", "the admin UI is only reachable through the p2ptun tunnel");
    }
    return ((esp_err_t (*)(httpd_req_t *))req->user_ctx)(req);
}

static esp_err_t h_ui_lock(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const cJSON *on = j ? cJSON_GetObjectItem(j, "tunnel_only") : NULL;
    esp_err_t r;
    if (!cJSON_IsBool(on)) {
        r = send_error(req, "400 Bad Request", "expected {\"tunnel_only\": true|false}");
    } else if (cJSON_IsTrue(on) && !from_tunnel(req)) {
        // Lockout protection: prove the admin can reach the UI through the tunnel first.
        r = send_error(req, "409 Conflict", "open the admin UI through the tunnel (http://<tunnel ip of device>/) to enable this");
    } else if (p2p_config_save_ui_tunnel_only(cJSON_IsTrue(on)) != ESP_OK) {
        r = send_error(req, "500 Internal Server Error", "saving failed");
    } else {
        p2p_event(cJSON_IsTrue(on) ? "admin UI locked to the tunnel" : "admin UI reachable from the LAN again");
        r = send_ok(req);
    }
    cJSON_Delete(j);
    return r;
}

// ---------------------------------------------------------------------------
// Wake-on-LAN
// ---------------------------------------------------------------------------
static esp_err_t send_magic_packet(const uint8_t mac[6])
{
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info;
    if (!sta || esp_netif_get_ip_info(sta, &info) != ESP_OK || !info.ip.addr) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t pkt[P2P_WOL_PACKET_LEN];
    p2p_wol_packet(mac, pkt);
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) {
        return ESP_FAIL;
    }
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(9)};
    to.sin_addr.s_addr = info.ip.addr | ~info.netmask.addr; // directed LAN broadcast
    int sent = 0;
    for (int i = 0; i < 3; i++) { // UDP: send a few times
        sent += sendto(s, pkt, sizeof(pkt), 0, (struct sockaddr *)&to, sizeof(to)) == (int)sizeof(pkt);
    }
    close(s);
    return sent ? ESP_OK : ESP_FAIL;
}

static esp_err_t h_wol(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const char *action = j ? jstr(j, "action") : NULL, *macs = j ? jstr(j, "mac") : NULL, *name = j ? jstr(j, "name") : NULL;
    uint8_t mac[6];
    char pname[P2P_NAME_LEN] = "", mac_txt[18];
    const char *err = NULL;
    if (!action || !macs || !p2p_parse_mac(macs, mac)) err = "mac must look like aa:bb:cc:dd:ee:ff";
    else if (!strcmp(action, "add") && !valid_name(name)) err = "name: 1-23 chars of letters, digits, space, - _ .";
    if (!err && name) strlcpy(pname, name, sizeof(pname));
    cJSON_Delete(j);
    if (err) {
        return send_error(req, "400 Bad Request", err);
    }
    p2p_format_mac(mac, mac_txt);
    p2p_config_t *c = p2p_config();
    p2p_config_lock();
    int idx = -1, free_slot = -1;
    for (int i = 0; i < P2P_MAX_WOL; i++) {
        if (c->wol[i].name[0] && memcmp(c->wol[i].mac, mac, 6) == 0) idx = i;
        if (!c->wol[i].name[0] && free_slot < 0) free_slot = i;
    }
    char target[P2P_NAME_LEN] = "";
    if (idx >= 0) strlcpy(target, c->wol[idx].name, sizeof(target));
    esp_err_t e = ESP_OK;
    if (!strcmp(action, "add")) {
        if (idx >= 0) err = "that MAC is already saved";
        else if (free_slot < 0) err = "list full (8 machines)";
        else {
            strlcpy(c->wol[free_slot].name, pname, sizeof(c->wol[free_slot].name));
            memcpy(c->wol[free_slot].mac, mac, 6);
            e = p2p_config_save_wol();
        }
    } else if (!strcmp(action, "delete")) {
        if (idx < 0) err = "unknown machine";
        else {
            memset(&c->wol[idx], 0, sizeof(c->wol[idx]));
            e = p2p_config_save_wol();
        }
    } else if (strcmp(action, "wake") != 0) {
        err = "action must be add, delete or wake";
    }
    p2p_config_unlock();
    if (err) return send_error(req, "400 Bad Request", err);
    if (e != ESP_OK) return send_error(req, "500 Internal Server Error", "saving failed");
    if (!strcmp(action, "wake")) {
        char who[48];
        client_ip(req, who, sizeof(who));
        if (send_magic_packet(mac) != ESP_OK) {
            return send_error(req, "503 Service Unavailable", "no LAN connection to send on");
        }
        p2p_event("wake-on-LAN sent to %s%s%s (requested from %s)", target[0] ? target : mac_txt,
                  target[0] ? " " : "", target[0] ? mac_txt : "", who);
    }
    return send_ok(req);
}

esp_err_t p2p_web_start(bool setup_mode)
{
    s_setup_mode = setup_mode;
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.max_uri_handlers = 24;
    cfg.stack_size = 8192;
    cfg.lru_purge_enable = true;
    cfg.max_open_sockets = 5;

    httpd_handle_t srv = NULL;
    esp_err_t err = httpd_start(&srv, &cfg);
    if (err != ESP_OK) {
        return err;
    }
    const struct { const char *uri; httpd_method_t m; esp_err_t (*h)(httpd_req_t *); } routes[] = {
        {"/", HTTP_GET, h_index},
        {"/api/state", HTTP_GET, h_state},
        {"/api/setup", HTTP_POST, h_setup},
        {"/api/login", HTTP_POST, h_login},
        {"/api/logout", HTTP_POST, h_logout},
        {"/api/password", HTTP_POST, h_password},
        {"/api/peers/add", HTTP_POST, h_peer_add},
        {"/api/peers/disable", HTTP_POST, h_peer_disable},
        {"/api/peers/enable", HTTP_POST, h_peer_enable},
        {"/api/peers/delete", HTTP_POST, h_peer_delete},
        {"/api/peers/config", HTTP_POST, h_peer_config},
        {"/api/relays", HTTP_POST, h_relays},
        {"/api/endpoint", HTTP_POST, h_endpoint},
        {"/api/peers/update", HTTP_POST, h_peer_update},
        {"/api/invites", HTTP_POST, h_invite_create},
        {"/api/invites/revoke", HTTP_POST, h_invite_revoke},
        {"/api/webclient", HTTP_POST, h_web_client},
        {"/qr.js", HTTP_GET, h_qr_js},
        {"/api/uilock", HTTP_POST, h_ui_lock},
        {"/api/wol", HTTP_POST, h_wol},
        {"/api/reboot", HTTP_POST, h_reboot},
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_uri_t u = {.uri = routes[i].uri, .method = routes[i].m, .handler = h_guard, .user_ctx = (void *)routes[i].h};
        httpd_register_uri_handler(srv, &u);
    }
    ESP_LOGI(TAG, "web UI started (%s mode)", setup_mode ? "setup" : "admin");
    return ESP_OK;
}
