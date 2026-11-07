// Wake-on-LAN helpers (portable, unit-tested on the host).
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_WOL_PACKET_LEN 102

// "aa:bb:cc:dd:ee:ff" or "aa-bb-cc-dd-ee-ff" (any case). Rejects all-zero and broadcast MACs.
bool p2p_parse_mac(const char *s, uint8_t mac[6]);
void p2p_format_mac(const uint8_t mac[6], char out[18]);
// Magic packet: 6 x 0xFF followed by the MAC repeated 16 times.
void p2p_wol_packet(const uint8_t mac[6], uint8_t out[P2P_WOL_PACKET_LEN]);

#ifdef __cplusplus
}
#endif
