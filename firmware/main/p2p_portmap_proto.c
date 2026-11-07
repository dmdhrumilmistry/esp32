#include "p2p_portmap_proto.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

// ---------------------------------------------------------------------------
// NAT-PMP
// ---------------------------------------------------------------------------
size_t p2p_natpmp_req_extaddr(uint8_t out[2])
{
    out[0] = 0; // version
    out[1] = 0; // opcode: external address
    return 2;
}

size_t p2p_natpmp_req_map_udp(uint16_t internal_port, uint16_t external_port, uint32_t lifetime_s, uint8_t out[12])
{
    out[0] = 0;
    out[1] = 1; // map UDP
    out[2] = out[3] = 0;
    wr16(out + 4, internal_port);
    wr16(out + 6, external_port);
    wr32(out + 8, lifetime_s);
    return 12;
}

bool p2p_natpmp_parse_extaddr(const uint8_t *pkt, size_t len, uint8_t ip[4])
{
    if (len < 12 || pkt[0] != 0 || pkt[1] != 128 || rd16(pkt + 2) != 0) {
        return false;
    }
    memcpy(ip, pkt + 8, 4);
    return true;
}

bool p2p_natpmp_parse_map_udp(const uint8_t *pkt, size_t len, uint16_t internal_port,
                              uint16_t *external_port, uint32_t *lifetime_s)
{
    if (len < 16 || pkt[0] != 0 || pkt[1] != 129 || rd16(pkt + 2) != 0 || rd16(pkt + 8) != internal_port) {
        return false;
    }
    *external_port = rd16(pkt + 10);
    *lifetime_s = rd32(pkt + 12);
    return *external_port != 0;
}

// ---------------------------------------------------------------------------
// string helpers
// ---------------------------------------------------------------------------
static const char *ci_find(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] && tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == n) {
            return hay;
        }
    }
    return NULL;
}

// Copy the trimmed text between `open` and `close` found inside [from, limit) (limit may be NULL).
static bool tag_value(const char *from, const char *limit, const char *open, const char *close, char *out, size_t size)
{
    const char *a = strstr(from, open);
    if (!a || (limit && a >= limit)) {
        return false;
    }
    a += strlen(open);
    const char *b = strstr(a, close);
    if (!b || (limit && b > limit)) {
        return false;
    }
    while (a < b && isspace((unsigned char)*a)) a++;
    while (b > a && isspace((unsigned char)b[-1])) b--;
    size_t n = (size_t)(b - a);
    if (n == 0 || n >= size) {
        return false;
    }
    memcpy(out, a, n);
    out[n] = '\0';
    return true;
}

static bool safe_chars(const char *s, const char *extra)
{
    for (; *s; s++) {
        if (!isalnum((unsigned char)*s) && !strchr(extra, *s)) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// SSDP / URLs
// ---------------------------------------------------------------------------
int p2p_ssdp_msearch(const char *st, char *out, size_t size)
{
    int n = snprintf(out, size,
                     "M-SEARCH * HTTP/1.1\r\n"
                     "HOST: 239.255.255.250:1900\r\n"
                     "MAN: \"ssdp:discover\"\r\n"
                     "MX: 2\r\n"
                     "ST: %s\r\n\r\n", st);
    return (n < 0 || (size_t)n >= size) ? -1 : n;
}

bool p2p_ssdp_location(const char *resp, char *url, size_t size)
{
    const char *p = ci_find(resp, "\nlocation:");
    if (!p) {
        return false;
    }
    p += strlen("\nlocation:");
    while (*p == ' ' || *p == '\t') p++;
    size_t n = strcspn(p, "\r\n");
    if (n == 0 || n >= size || strncmp(p, "http://", 7) != 0) {
        return false;
    }
    memcpy(url, p, n);
    url[n] = '\0';
    while (n > 0 && isspace((unsigned char)url[n - 1])) url[--n] = '\0';
    return safe_chars(url, ":/._-~%?=&+");
}

bool p2p_url_split(const char *url, char *host, size_t host_size, uint16_t *port, char *path, size_t path_size)
{
    if (strncmp(url, "http://", 7) != 0) {
        return false;
    }
    const char *h = url + 7;
    size_t hl = strcspn(h, ":/");
    if (hl == 0 || hl >= host_size) {
        return false;
    }
    memcpy(host, h, hl);
    host[hl] = '\0';
    const char *rest = h + hl;
    *port = 80;
    if (*rest == ':') {
        char *end;
        long v = strtol(rest + 1, &end, 10);
        if (v <= 0 || v > 65535 || end == rest + 1) {
            return false;
        }
        *port = (uint16_t)v;
        rest = end;
    }
    if (*rest == '\0') {
        rest = "/";
    }
    if (*rest != '/' || strlen(rest) >= path_size) {
        return false;
    }
    strcpy(path, rest);
    return true;
}

bool p2p_url_resolve(const char *base, const char *ref, char *out, size_t size)
{
    int n;
    if (strncmp(ref, "http://", 7) == 0) {
        n = snprintf(out, size, "%s", ref);
    } else {
        char host[64], path[256];
        uint16_t port;
        if (!p2p_url_split(base, host, sizeof(host), &port, path, sizeof(path))) {
            return false;
        }
        if (ref[0] == '/') {
            n = snprintf(out, size, "http://%s:%u%s", host, port, ref);
        } else {
            char *slash = strrchr(path, '/');
            slash[1] = '\0'; // directory of the description document
            n = snprintf(out, size, "http://%s:%u%s%s", host, port, path, ref);
        }
    }
    return n > 0 && (size_t)n < size;
}

static bool find_service(const char *xml, const char *kind, char *st, size_t st_size, char *cu, size_t cu_size)
{
    const char *p = xml;
    char type[128];
    while ((p = strstr(p, "<serviceType>")) != NULL) {
        const char *end_service = strstr(p, "</service>");
        if (tag_value(p, end_service, "<serviceType>", "</serviceType>", type, sizeof(type)) &&
            strstr(type, kind) && safe_chars(type, ":.-_") &&
            tag_value(p, end_service, "<controlURL>", "</controlURL>", cu, cu_size) &&
            safe_chars(cu, ":/._-~%?=&+")) {
            if (strlen(type) >= st_size) {
                return false;
            }
            strcpy(st, type);
            return true;
        }
        p += strlen("<serviceType>");
    }
    return false;
}

bool p2p_igd_find_control(const char *xml, char *service_type, size_t st_size, char *control_url, size_t cu_size)
{
    return find_service(xml, ":WANIPConnection:", service_type, st_size, control_url, cu_size) ||
           find_service(xml, ":WANPPPConnection:", service_type, st_size, control_url, cu_size);
}

// ---------------------------------------------------------------------------
// SOAP
// ---------------------------------------------------------------------------
#define SOAP_HEAD "<?xml version=\"1.0\"?>\r\n" \
    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " \
    "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>"
#define SOAP_TAIL "</s:Body></s:Envelope>\r\n"

int p2p_soap_add_mapping(const char *service_type, uint16_t external_port, uint16_t internal_port,
                         const char *internal_client, uint32_t lease_s, char *out, size_t size)
{
    if (!safe_chars(service_type, ":.-_") || !safe_chars(internal_client, ".")) {
        return -1;
    }
    int n = snprintf(out, size,
                     SOAP_HEAD "<u:AddPortMapping xmlns:u=\"%s\">"
                     "<NewRemoteHost></NewRemoteHost>"
                     "<NewExternalPort>%u</NewExternalPort>"
                     "<NewProtocol>UDP</NewProtocol>"
                     "<NewInternalPort>%u</NewInternalPort>"
                     "<NewInternalClient>%s</NewInternalClient>"
                     "<NewEnabled>1</NewEnabled>"
                     "<NewPortMappingDescription>p2ptun</NewPortMappingDescription>"
                     "<NewLeaseDuration>%lu</NewLeaseDuration>"
                     "</u:AddPortMapping>" SOAP_TAIL,
                     service_type, external_port, internal_port, internal_client, (unsigned long)lease_s);
    return (n < 0 || (size_t)n >= size) ? -1 : n;
}

int p2p_soap_get_external_ip(const char *service_type, char *out, size_t size)
{
    if (!safe_chars(service_type, ":.-_")) {
        return -1;
    }
    int n = snprintf(out, size, SOAP_HEAD "<u:GetExternalIPAddress xmlns:u=\"%s\"></u:GetExternalIPAddress>" SOAP_TAIL,
                     service_type);
    return (n < 0 || (size_t)n >= size) ? -1 : n;
}

bool p2p_soap_parse_external_ip(const char *resp, uint8_t ip[4])
{
    char v[32];
    unsigned a, b, c, d;
    char tail;
    if (!tag_value(resp, NULL, "<NewExternalIPAddress>", "</NewExternalIPAddress>", v, sizeof(v)) ||
        sscanf(v, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4 || a > 255 || b > 255 || c > 255 || d > 255) {
        return false;
    }
    ip[0] = a; ip[1] = b; ip[2] = c; ip[3] = d;
    return true;
}

int p2p_soap_error_code(const char *resp)
{
    char v[16];
    if (!tag_value(resp, NULL, "<errorCode>", "</errorCode>", v, sizeof(v))) {
        return -1;
    }
    return atoi(v);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------
int p2p_http_status(const char *resp)
{
    int code;
    if (strncmp(resp, "HTTP/1.", 7) != 0 || sscanf(resp + 8, " %d", &code) != 1) {
        return -1;
    }
    return code;
}

char *p2p_http_body(char *resp, size_t len)
{
    char *sep = strstr(resp, "\r\n\r\n");
    if (!sep) {
        return NULL;
    }
    *sep = '\0';
    bool chunked = ci_find(resp, "\ntransfer-encoding: chunked") != NULL;
    char *body = sep + 4;
    if (!chunked) {
        return body;
    }
    // de-chunk in place
    char *src = body, *dst = body, *end = resp + len;
    for (;;) {
        char *e;
        unsigned long n = strtoul(src, &e, 16);
        if (e == src) {
            return NULL;
        }
        char *line_end = strstr(e, "\r\n");
        if (!line_end) {
            return NULL;
        }
        src = line_end + 2;
        if (n == 0) {
            break;
        }
        if (src + n > end) {
            return NULL;
        }
        memmove(dst, src, n);
        dst += n;
        src += n;
        if (src + 2 <= end && src[0] == '\r' && src[1] == '\n') {
            src += 2;
        }
    }
    *dst = '\0';
    return body;
}

bool p2p_ip_is_private(const uint8_t ip[4])
{
    return ip[0] == 0 || ip[0] == 10 || ip[0] == 127 ||
           (ip[0] == 100 && (ip[1] & 0xC0) == 64) ||   // 100.64.0.0/10 carrier-grade NAT
           (ip[0] == 169 && ip[1] == 254) ||
           (ip[0] == 172 && (ip[1] & 0xF0) == 16) ||
           (ip[0] == 192 && ip[1] == 168) ||
           ip[0] >= 224;
}
