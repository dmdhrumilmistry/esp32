#include "p2p_web.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_http_server.h"
#include "cJSON.h"

#include "p2p_auth.h"
#include "p2p_config.h"
#include "p2p_crypto.h"
#include "p2p_portmap.h"
#include "p2p_signal.h"
#include "p2p_tunnel.h"

static const char *TAG = "web";
static bool s_setup_mode;

extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[] asm("_binary_index_html_end");

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
                       "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
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
        cJSON_AddItemToArray(arr, p);
    }
    cJSON_AddNumberToObject(o, "max_peers", P2P_MAX_PEERS);
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
    ESP_LOGI(TAG, "setup complete, rebooting into station mode");
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
    if (!ok) {
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
        r = send_ok(req);
    }
    cJSON_Delete(j);
    return r;
}

// ---------------------------------------------------------------------------
// peers
// ---------------------------------------------------------------------------
static int find_peer(const uint8_t pub[32])
{
    p2p_config_t *c = p2p_config();
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (c->peers[i].host && memcmp(c->peers[i].pub, pub, 32) == 0) {
            return i;
        }
    }
    return -1;
}

static esp_err_t h_peer_add(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req);
    const char *name = j ? jstr(j, "name") : NULL, *pk = j ? jstr(j, "pubkey") : NULL;
    uint8_t pub[32], mine[32];
    const char *err = NULL;
    p2p_wg_pubkey(p2p_config()->wg_priv, mine);
    if (!valid_name(name)) err = "name: 1-23 chars of letters, digits, space, - _ .";
    else if (!decode_pub(pk, pub)) err = "pubkey must be a base64 WireGuard public key";
    else if (memcmp(pub, mine, 32) == 0) err = "that is the device's own key";
    if (err) {
        cJSON_Delete(j);
        return send_error(req, "400 Bad Request", err);
    }

    p2p_config_t *c = p2p_config();
    p2p_config_lock();
    int slot = -1;
    bool used_host[256] = {false};
    for (int i = 0; i < P2P_MAX_PEERS; i++) {
        if (c->peers[i].host) {
            used_host[c->peers[i].host] = true;
        } else if (slot < 0) {
            slot = i;
        }
    }
    if (find_peer(pub) >= 0) err = "peer already exists";
    else if (slot < 0) err = "peer table full";
    cJSON *resp = NULL;
    if (!err) {
        uint8_t host = 2;
        while (used_host[host] && host < 254) host++;
        p2p_peer_t *p = &c->peers[slot];
        memset(p, 0, sizeof(*p));
        strlcpy(p->name, name, sizeof(p->name));
        memcpy(p->pub, pub, 32);
        p->host = host;
        p->enabled = 1;
        if (p2p_config_save_peers() != ESP_OK) {
            memset(p, 0, sizeof(*p));
            err = "saving failed";
        } else {
            resp = cJSON_CreateObject();
            cJSON_AddItemToObject(resp, "client", client_config(p));
        }
    }
    p2p_config_unlock();
    cJSON_Delete(j);
    if (err) {
        return send_error(req, "409 Conflict", err);
    }
    ESP_LOGI(TAG, "peer '%s' authorized", name);
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
    }
    esp_err_t e = p2p_config_save_peers();
    if (e != ESP_OK) {
        c->peers[i] = backup;
    }
    p2p_config_unlock();
    if (e != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "saving failed");
    }
    ESP_LOGI(TAG, "peer '%s' %s", backup.name, action == 2 ? "deleted" : action == 1 ? "enabled" : "disabled");
    p2p_tunnel_sync_peers(); // disabling/deleting drops the live WireGuard session immediately
    return send_ok(req);
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
esp_err_t p2p_web_start(bool setup_mode)
{
    s_setup_mode = setup_mode;
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.max_uri_handlers = 16;
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
        {"/api/reboot", HTTP_POST, h_reboot},
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_uri_t u = {.uri = routes[i].uri, .method = routes[i].m, .handler = routes[i].h};
        httpd_register_uri_handler(srv, &u);
    }
    ESP_LOGI(TAG, "web UI started (%s mode)", setup_mode ? "setup" : "admin");
    return ESP_OK;
}
