// Minimal RFC 5389 STUN Binding client (build request / parse response). Portable.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_STUN_REQ_LEN 20

// Build a Binding Request with transaction id `txid` (12 bytes) into out[20].
void p2p_stun_build_request(const uint8_t txid[12], uint8_t out[P2P_STUN_REQ_LEN]);

// Cheap check used to demultiplex STUN from WireGuard on the shared UDP port.
bool p2p_stun_is_stun(const uint8_t *pkt, size_t len);

// Parse a Binding Success Response matching `txid`. On success writes the mapped
// IPv4 address (network byte order bytes a.b.c.d in ip[4]) and port. Returns true on success.
bool p2p_stun_parse_response(const uint8_t *pkt, size_t len, const uint8_t txid[12], uint8_t ip[4], uint16_t *port);

#ifdef __cplusplus
}
#endif
