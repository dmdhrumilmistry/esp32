#include "p2p_stun.h"

#include <string.h>

#define STUN_MAGIC 0x2112A442u
#define STUN_BINDING_REQUEST 0x0001
#define STUN_BINDING_SUCCESS 0x0101
#define ATTR_MAPPED_ADDRESS 0x0001
#define ATTR_XOR_MAPPED_ADDRESS 0x0020

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

void p2p_stun_build_request(const uint8_t txid[12], uint8_t out[P2P_STUN_REQ_LEN])
{
    out[0] = 0x00;
    out[1] = STUN_BINDING_REQUEST;
    out[2] = 0x00; // message length: no attributes
    out[3] = 0x00;
    out[4] = (STUN_MAGIC >> 24) & 0xff;
    out[5] = (STUN_MAGIC >> 16) & 0xff;
    out[6] = (STUN_MAGIC >> 8) & 0xff;
    out[7] = STUN_MAGIC & 0xff;
    memcpy(out + 8, txid, 12);
}

bool p2p_stun_is_stun(const uint8_t *pkt, size_t len)
{
    // Top two bits zero + magic cookie. WireGuard messages start with type 1..4
    // followed by three zero bytes, so bytes 4..7 never equal the magic cookie by design
    // for handshake messages; transport data has a random receiver index there, so we
    // also require a sane STUN length.
    if (len < 20 || (pkt[0] & 0xC0) != 0 || rd32(pkt + 4) != STUN_MAGIC) {
        return false;
    }
    uint16_t mlen = rd16(pkt + 2);
    return (mlen % 4) == 0 && (size_t)mlen + 20 == len;
}

bool p2p_stun_parse_response(const uint8_t *pkt, size_t len, const uint8_t txid[12], uint8_t ip[4], uint16_t *port)
{
    if (!p2p_stun_is_stun(pkt, len) || rd16(pkt) != STUN_BINDING_SUCCESS || memcmp(pkt + 8, txid, 12) != 0) {
        return false;
    }
    bool have_mapped = false;
    uint8_t mip[4] = {0};
    uint16_t mport = 0;

    size_t off = 20;
    while (off + 4 <= len) {
        uint16_t type = rd16(pkt + off);
        uint16_t alen = rd16(pkt + off + 2);
        const uint8_t *v = pkt + off + 4;
        if (off + 4 + alen > len) {
            return false;
        }
        if ((type == ATTR_XOR_MAPPED_ADDRESS || type == ATTR_MAPPED_ADDRESS) && alen >= 8 && v[1] == 0x01 /* IPv4 */) {
            uint16_t p = rd16(v + 2);
            uint8_t a[4] = {v[4], v[5], v[6], v[7]};
            if (type == ATTR_XOR_MAPPED_ADDRESS) {
                p ^= (uint16_t)(STUN_MAGIC >> 16);
                a[0] ^= (STUN_MAGIC >> 24) & 0xff;
                a[1] ^= (STUN_MAGIC >> 16) & 0xff;
                a[2] ^= (STUN_MAGIC >> 8) & 0xff;
                a[3] ^= STUN_MAGIC & 0xff;
                memcpy(ip, a, 4);
                *port = p;
                return true; // XOR-MAPPED-ADDRESS is authoritative
            }
            memcpy(mip, a, 4);
            mport = p;
            have_mapped = true;
        }
        off += 4 + ((alen + 3u) & ~3u);
    }
    if (have_mapped) {
        memcpy(ip, mip, 4);
        *port = mport;
    }
    return have_mapped;
}
