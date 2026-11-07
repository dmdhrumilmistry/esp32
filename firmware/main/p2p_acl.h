// Per-peer access rules, enforced on every decrypted packet before it enters the IP stack.
// Portable (no ESP-IDF dependencies) and unit-tested on the host (tests/test_acl.py).
//
// Text form: comma/newline separated rules, empty = full access.
//   rule   := "any" | [proto ":"] target [":" port ["-" port]]
//   proto  := "tcp" | "udp" | "icmp"
//   target := "lan" (the device's LAN subnet) | "device" (the device's tunnel IP, i.e. its web UI)
//           | a.b.c.d[/prefix]
// Examples: "lan" · "tcp:192.168.1.20:22" · "192.168.1.0/24:80-443, udp:192.168.1.1:53"
// A port without a protocol matches TCP and UDP. Anything not matched is dropped.
// Packets to the device itself (its tunnel IP or its LAN IP, i.e. the admin web UI) match only
// "device" rules: "lan" or a CIDR covering the device's LAN address never grant access to it.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_ACL_MAX_RULES 8
#define P2P_ACL_TEXT_LEN 96

typedef struct {
    uint8_t kind;    // P2P_ACL_KIND_*
    uint8_t proto;   // 0 = any, 1 = ICMP, 6 = TCP, 17 = UDP
    uint16_t pmin;   // 0 = no port restriction
    uint16_t pmax;
    uint32_t net;    // host byte order (kind ADDR)
    uint32_t mask;
} p2p_acl_rule_t;

enum { P2P_ACL_KIND_ADDR = 0, P2P_ACL_KIND_LAN = 1, P2P_ACL_KIND_DEVICE = 2 };

typedef struct {
    bool all;        // no restrictions
    uint8_t n;
    p2p_acl_rule_t rules[P2P_ACL_MAX_RULES];
} p2p_acl_t;

typedef struct {
    uint32_t lan_net;   // host byte order; lan_mask 0 = unknown (then "lan" matches nothing)
    uint32_t lan_mask;
    uint32_t dev_ip;      // the device's tunnel address
    uint32_t dev_lan_ip;  // the device's own LAN address (0 = unknown)
} p2p_acl_env_t;

// Parse rules. On failure returns false and writes a human-readable reason to err.
bool p2p_acl_parse(const char *text, p2p_acl_t *out, char *err, size_t err_len);

// Should this IPv4 packet (pkt = IP header, len = total length) from the peer be accepted?
bool p2p_acl_allows(const p2p_acl_t *acl, const p2p_acl_env_t *env, const uint8_t *pkt, size_t len);

#ifdef __cplusplus
}
#endif
