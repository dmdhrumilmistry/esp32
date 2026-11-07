#include "p2p_wol.h"

#include <stdio.h>
#include <string.h>

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool p2p_parse_mac(const char *s, uint8_t mac[6])
{
    if (!s || strlen(s) != 17) {
        return false;
    }
    char sep = s[2];
    if (sep != ':' && sep != '-') {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        int hi = hexv(s[i * 3]), lo = hexv(s[i * 3 + 1]);
        if (hi < 0 || lo < 0 || (i < 5 && s[i * 3 + 2] != sep)) {
            return false;
        }
        mac[i] = (uint8_t)(hi << 4 | lo);
    }
    static const uint8_t zero[6] = {0}, bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return memcmp(mac, zero, 6) != 0 && memcmp(mac, bcast, 6) != 0;
}

void p2p_format_mac(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void p2p_wol_packet(const uint8_t mac[6], uint8_t out[P2P_WOL_PACKET_LEN])
{
    memset(out, 0xff, 6);
    for (int i = 0; i < 16; i++) {
        memcpy(out + 6 + i * 6, mac, 6);
    }
}
