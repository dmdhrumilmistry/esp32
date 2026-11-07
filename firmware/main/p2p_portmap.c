#include "p2p_portmap.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "p2p_config.h"
#include "p2p_portmap_proto.h"
#include "p2p_tunnel.h"

static const char *TAG = "portmap";

#define LEASE_S 7200
#define HTTP_MAX 12288

typedef enum { PM_NONE, PM_NATPMP, PM_UPNP } pm_method_t;

static SemaphoreHandle_t s_lock;
static pm_method_t s_method;
static uint8_t s_ext_ip[4];
static uint16_t s_ext_port;
static char s_note[64] = "probing router…";

static void set_result(pm_method_t m, const uint8_t ip[4], uint16_t port, const char *note)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_method = m;
    if (ip) memcpy(s_ext_ip, ip, 4);
    s_ext_port = port;
    strlcpy(s_note, note, sizeof(s_note));
    xSemaphoreGive(s_lock);
}

static bool sta_info(esp_netif_ip_info_t *info)
{
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    return sta && esp_netif_get_ip_info(sta, info) == ESP_OK && info->ip.addr != 0 && info->gw.addr != 0;
}

static int udp_socket(int timeout_ms)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s >= 0) {
        struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return s;
}

// ---------------------------------------------------------------------------
// NAT-PMP (RFC 6886): gateway UDP 5351, retries at 250 ms, 500 ms, 1 s
// ---------------------------------------------------------------------------
static int natpmp_exchange(uint32_t gw, const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_size)
{
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(P2P_NATPMP_PORT), .sin_addr.s_addr = gw};
    for (int attempt = 0, wait = 250; attempt < 3; attempt++, wait *= 2) {
        int s = udp_socket(wait);
        if (s < 0) return -1;
        sendto(s, req, req_len, 0, (struct sockaddr *)&to, sizeof(to));
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int n = recvfrom(s, resp, resp_size, 0, (struct sockaddr *)&from, &fl);
        close(s);
        if (n > 0 && from.sin_addr.s_addr == gw) {
            return n;
        }
    }
    return -1;
}

static bool try_natpmp(const esp_netif_ip_info_t *info, uint8_t ext_ip[4], uint16_t *ext_port, uint32_t *life)
{
    uint8_t req[12], resp[16];
    int n = natpmp_exchange(info->gw.addr, req, p2p_natpmp_req_extaddr(req), resp, sizeof(resp));
    if (n <= 0 || !p2p_natpmp_parse_extaddr(resp, n, ext_ip)) {
        return false;
    }
    p2p_natpmp_req_map_udp(CONFIG_P2PTUN_WG_PORT, CONFIG_P2PTUN_WG_PORT, LEASE_S, req);
    n = natpmp_exchange(info->gw.addr, req, sizeof(req), resp, sizeof(resp));
    return n > 0 && p2p_natpmp_parse_map_udp(resp, n, CONFIG_P2PTUN_WG_PORT, ext_port, life) && *life > 0;
}

// ---------------------------------------------------------------------------
// UPnP IGD: SSDP discovery, device description, SOAP AddPortMapping
// ---------------------------------------------------------------------------
static bool ssdp_discover(uint32_t gw, char *location, size_t size)
{
    static const char *targets[] = {
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
    };
    struct sockaddr_in mc = {.sin_family = AF_INET, .sin_port = htons(1900)};
    inet_pton(AF_INET, "239.255.255.250", &mc.sin_addr);
    char *buf = malloc(1536);
    if (!buf) return false;
    bool found = false;
    for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]) && !found; t++) {
        int s = udp_socket(2500);
        if (s < 0) break;
        int n = p2p_ssdp_msearch(targets[t], buf, 1536);
        sendto(s, buf, n, 0, (struct sockaddr *)&mc, sizeof(mc));
        for (;;) {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            n = recvfrom(s, buf, 1535, 0, (struct sockaddr *)&from, &fl);
            if (n <= 0) break;
            buf[n] = '\0';
            // Only trust the default gateway (other LAN hosts could answer SSDP too).
            if (from.sin_addr.s_addr == gw && p2p_ssdp_location(buf, location, size)) {
                found = true;
                break;
            }
        }
        close(s);
    }
    free(buf);
    return found;
}

// Plain HTTP/1.0 request to a LAN host. Returns the status code; *body points into out.
static int http_request(const char *url, const char *soap_action, const char *body_in,
                        char *out, size_t out_size, char **body)
{
    char host[64], path[256];
    uint16_t port;
    if (!p2p_url_split(url, host, sizeof(host), &port, path, sizeof(path))) return -1;
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, host, &to.sin_addr) != 1) return -1; // IGDs advertise IP literals

    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    struct timeval tv = {.tv_sec = 4};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(s, (struct sockaddr *)&to, sizeof(to)) != 0) {
        close(s);
        return -1;
    }
    int n;
    if (body_in) {
        n = snprintf(out, out_size,
                     "POST %s HTTP/1.0\r\nHost: %s:%u\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n"
                     "SOAPAction: \"%s\"\r\nContent-Length: %u\r\nConnection: close\r\n\r\n%s",
                     path, host, port, soap_action, (unsigned)strlen(body_in), body_in);
    } else {
        n = snprintf(out, out_size, "GET %s HTTP/1.0\r\nHost: %s:%u\r\nConnection: close\r\n\r\n", path, host, port);
    }
    if (n < 0 || (size_t)n >= out_size || send(s, out, n, 0) != n) {
        close(s);
        return -1;
    }
    size_t got = 0;
    while (got < out_size - 1) {
        int r = recv(s, out + got, out_size - 1 - got, 0);
        if (r <= 0) break;
        got += r;
    }
    close(s);
    out[got] = '\0';
    *body = p2p_http_body(out, got);
    return *body ? p2p_http_status(out) : -1;
}

// Only talk HTTP to the default gateway itself: SSDP answers can be spoofed by other LAN hosts.
static bool url_is_gateway(const char *url, uint32_t gw)
{
    char host[64], path[256];
    uint16_t port;
    struct in_addr a;
    return p2p_url_split(url, host, sizeof(host), &port, path, sizeof(path)) &&
           inet_pton(AF_INET, host, &a) == 1 && a.s_addr == gw;
}

static bool try_upnp(const esp_netif_ip_info_t *info, uint8_t ext_ip[4], uint16_t *ext_port, uint32_t *life)
{
    char location[256], control[320], service[128], cu[256], action[192], client[16];
    if (!ssdp_discover(info->gw.addr, location, sizeof(location)) || !url_is_gateway(location, info->gw.addr)) {
        return false;
    }
    char *http = malloc(HTTP_MAX), *soap = malloc(1024), *body;
    bool ok = false;
    if (!http || !soap) goto out;

    if (http_request(location, NULL, NULL, http, HTTP_MAX, &body) != 200 ||
        !p2p_igd_find_control(body, service, sizeof(service), cu, sizeof(cu)) ||
        !p2p_url_resolve(location, cu, control, sizeof(control)) || !url_is_gateway(control, info->gw.addr)) {
        ESP_LOGW(TAG, "UPnP: no usable WAN connection service at %s", location);
        goto out;
    }
    snprintf(client, sizeof(client), IPSTR, IP2STR(&info->ip));

    // Try the WireGuard port first, then a few alternatives if another device holds it.
    for (int i = 0; i < 6 && !ok; i++) {
        uint16_t want = CONFIG_P2PTUN_WG_PORT + (i == 0 ? 0 : 1000 + i);
        uint32_t lease = LEASE_S;
        for (int lease_try = 0; lease_try < 2; lease_try++) {
            p2p_soap_add_mapping(service, want, CONFIG_P2PTUN_WG_PORT, client, lease, soap, 1024);
            snprintf(action, sizeof(action), "%s#AddPortMapping", service);
            int st = http_request(control, action, soap, http, HTTP_MAX, &body);
            if (st == 200) {
                *ext_port = want;
                *life = lease ? lease : LEASE_S;
                ok = true;
                break;
            }
            int code = body ? p2p_soap_error_code(body) : -1;
            if (code == 725 && lease) { // OnlyPermanentLeasesSupported: we renew anyway
                lease = 0;
                continue;
            }
            ESP_LOGW(TAG, "UPnP AddPortMapping %u failed (HTTP %d, UPnP error %d)", want, st, code);
            if (code != 718) { // 718 = ConflictInMappingEntry -> try another port
                i = 99;
            }
            break;
        }
    }
    if (ok) {
        p2p_soap_get_external_ip(service, soap, 1024);
        snprintf(action, sizeof(action), "%s#GetExternalIPAddress", service);
        ok = http_request(control, action, soap, http, HTTP_MAX, &body) == 200 && p2p_soap_parse_external_ip(body, ext_ip);
    }
out:
    free(http);
    free(soap);
    return ok;
}

// ---------------------------------------------------------------------------
static void portmap_task(void *arg)
{
    for (;;) {
        esp_netif_ip_info_t info;
        uint8_t ip[4] = {0};
        uint16_t port = 0;
        uint32_t life = 0;
        uint32_t next_s = 600;
        pm_method_t m = PM_NONE;
        if (!sta_info(&info)) {
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        if (try_natpmp(&info, ip, &port, &life)) {
            m = PM_NATPMP;
        } else {
            // a partial NAT-PMP answer must not leak into the UPnP attempt
            memset(ip, 0, sizeof(ip));
            port = 0;
            life = 0;
            if (try_upnp(&info, ip, &port, &life)) {
                m = PM_UPNP;
            }
        }
        if (m == PM_NATPMP) {
            set_result(m, ip, port, "router mapping via NAT-PMP");
        } else if (m == PM_UPNP) {
            set_result(m, ip, port, "router mapping via UPnP");
        } else {
            set_result(PM_NONE, NULL, 0, "router has no UPnP/NAT-PMP (or it is disabled)");
        }
        if (m != PM_NONE) {
            ESP_LOGI(TAG, "mapped UDP %u.%u.%u.%u:%u -> :%d (lease %lus)", ip[0], ip[1], ip[2], ip[3], port,
                     CONFIG_P2PTUN_WG_PORT, (unsigned long)life);
            next_s = life / 2 < 1800 ? life / 2 : 1800;
            if (next_s < 60) next_s = 60;
        }
        vTaskDelay(pdMS_TO_TICKS(next_s * 1000));
    }
}

esp_err_t p2p_portmap_start(void)
{
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) return ESP_ERR_NO_MEM;
#if CONFIG_P2PTUN_PORTMAP
    return xTaskCreate(portmap_task, "portmap", 6144, NULL, 3, NULL) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
#else
    set_result(PM_NONE, NULL, 0, "router port mapping disabled in config");
    return ESP_OK;
#endif
}

// A router mapping is only useful if the router's "external" address is the real public one.
// With double NAT (or a lying SSDP responder) it isn't, so cross-check against STUN.
static bool mapping_usable(char *why, size_t why_len)
{
    if (s_method == PM_NONE) return false;
    uint8_t stun_ip[4];
    if (p2p_ip_is_private(s_ext_ip)) {
        snprintf(why, why_len, "router's WAN address is private (double NAT / CGNAT)");
        return false;
    }
    // Fail closed: advertise the mapping only when STUN positively confirms the router's address.
    if (!p2p_tunnel_public_ip(stun_ip)) {
        snprintf(why, why_len, "public address not confirmed by STUN yet");
        return false;
    }
    if (memcmp(stun_ip, s_ext_ip, 4) != 0) {
        snprintf(why, why_len, "router's WAN address differs from STUN (double NAT)");
        return false;
    }
    return true;
}

bool p2p_reach_endpoint(char *out, size_t len, const char **via)
{
    char manual[sizeof(p2p_config()->ep_override)];
    p2p_config_lock(); // the web UI may be rewriting it
    strlcpy(manual, p2p_config()->ep_override, sizeof(manual));
    p2p_config_unlock();
    if (manual[0]) {
        strlcpy(out, manual, len);
        *via = "manual";
        return true;
    }
    char why[80];
    bool ok = false;
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        if (mapping_usable(why, sizeof(why))) {
            snprintf(out, len, "%u.%u.%u.%u:%u", s_ext_ip[0], s_ext_ip[1], s_ext_ip[2], s_ext_ip[3], s_ext_port);
            *via = s_method == PM_NATPMP ? "natpmp" : "upnp";
            ok = true;
        }
        xSemaphoreGive(s_lock);
    }
    if (ok) return true;
    if (p2p_tunnel_public_endpoint(out, len)) {
        *via = "stun";
        return true;
    }
    return false;
}

void p2p_portmap_status(char *out, size_t len)
{
    char manual[sizeof(p2p_config()->ep_override)];
    p2p_config_lock();
    strlcpy(manual, p2p_config()->ep_override, sizeof(manual));
    p2p_config_unlock();
    if (manual[0]) {
        snprintf(out, len, "manual endpoint %s (make sure UDP is forwarded to this device)", manual);
        return;
    }
    if (!s_lock) {
        snprintf(out, len, "starting");
        return;
    }
    char why[80] = "";
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (mapping_usable(why, sizeof(why))) {
        snprintf(out, len, "%s: %u.%u.%u.%u:%u", s_note, s_ext_ip[0], s_ext_ip[1], s_ext_ip[2], s_ext_ip[3], s_ext_port);
    } else if (s_method != PM_NONE) {
        snprintf(out, len, "%s, but %s", s_note, why);
    } else {
        snprintf(out, len, "%s", s_note);
    }
    xSemaphoreGive(s_lock);
}
