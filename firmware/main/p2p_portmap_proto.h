// Portable helpers for asking the home router to forward the WireGuard UDP port:
// NAT-PMP (RFC 6886) and UPnP Internet Gateway Device (SSDP + SOAP). No I/O here, so it is
// unit-tested on the host (tests/). The ESP32 networking lives in p2p_portmap.c.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- NAT-PMP ----
#define P2P_NATPMP_PORT 5351
size_t p2p_natpmp_req_extaddr(uint8_t out[2]);
size_t p2p_natpmp_req_map_udp(uint16_t internal_port, uint16_t external_port, uint32_t lifetime_s, uint8_t out[12]);
bool p2p_natpmp_parse_extaddr(const uint8_t *pkt, size_t len, uint8_t ip[4]);
bool p2p_natpmp_parse_map_udp(const uint8_t *pkt, size_t len, uint16_t internal_port,
                              uint16_t *external_port, uint32_t *lifetime_s);

// ---- UPnP IGD ----
// SSDP M-SEARCH for search target `st`. Returns length or -1.
int p2p_ssdp_msearch(const char *st, char *out, size_t size);
// LOCATION header of an SSDP response (http:// URLs only).
bool p2p_ssdp_location(const char *resp, char *url, size_t size);
// Split http://host[:port]/path. host must be an IPv4 literal or name.
bool p2p_url_split(const char *url, char *host, size_t host_size, uint16_t *port, char *path, size_t path_size);
// Resolve a controlURL against the description URL (absolute, absolute-path or relative).
bool p2p_url_resolve(const char *base, const char *ref, char *out, size_t size);
// Find the WANIPConnection (preferred) or WANPPPConnection service in a device description.
bool p2p_igd_find_control(const char *xml, char *service_type, size_t st_size, char *control_url, size_t cu_size);

int p2p_soap_add_mapping(const char *service_type, uint16_t external_port, uint16_t internal_port,
                         const char *internal_client, uint32_t lease_s, char *out, size_t size);
int p2p_soap_get_external_ip(const char *service_type, char *out, size_t size);
bool p2p_soap_parse_external_ip(const char *resp, uint8_t ip[4]);
int p2p_soap_error_code(const char *resp); // UPnP <errorCode>, or -1

// ---- minimal HTTP/1.x response handling ----
int p2p_http_status(const char *resp);                  // e.g. 200, or -1
// Returns a pointer to the body inside resp (de-chunked in place if needed), or NULL.
char *p2p_http_body(char *resp, size_t len);

// True for addresses that can't be reached from the internet (RFC 1918, CGNAT 100.64/10, etc.).
bool p2p_ip_is_private(const uint8_t ip[4]);

#ifdef __cplusplus
}
#endif
