// Host CLI around the portable firmware modules, used by tests/test_interop.py.
//   p2p_host pubkey  <sk_hex>
//   p2p_host sign    <sk_hex> <msg_hex> <aux_hex>
//   p2p_host nostrsk <wg_priv_b64>
//   p2p_host event   <sk_hex> <kind> <created_at> <p_hex> <content>
//   p2p_host wgpub   <wg_priv_b64>
//   p2p_host seal    <my_priv_b64> <peer_pub_b64> <plaintext>
//   p2p_host open    <my_priv_b64> <peer_pub_b64> <content_b64>
//   p2p_host stunreq <txid_hex>
//   p2p_host stunparse <pkt_hex> <txid_hex>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p2p_crypto.h"
#include "p2p_stun.h"

static int urandom(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

static void hexarg(const char *s, uint8_t *out, size_t n)
{
    if (!p2p_hex_decode(s, out, n)) {
        fprintf(stderr, "bad hex: %s\n", s);
        exit(2);
    }
}

static void b64key(const char *s, uint8_t out[32])
{
    size_t n = 0;
    if (!p2p_b64_decode(s, out, 32, &n) || n != 32) {
        fprintf(stderr, "bad key: %s\n", s);
        exit(2);
    }
}

int main(int argc, char **argv)
{
    p2p_crypto_set_rng(urandom, NULL);
    if (argc < 2) return 2;
    const char *cmd = argv[1];
    char hex[256];

    if (!strcmp(cmd, "pubkey") && argc == 3) {
        uint8_t sk[32], pub[32];
        hexarg(argv[2], sk, 32);
        if (p2p_schnorr_pubkey(sk, pub)) return 1;
        p2p_hex_encode(pub, 32, hex);
        puts(hex);
    } else if (!strcmp(cmd, "sign") && argc == 5) {
        uint8_t sk[32], msg[32], aux[32], sig[64];
        hexarg(argv[2], sk, 32);
        hexarg(argv[3], msg, 32);
        hexarg(argv[4], aux, 32);
        if (p2p_schnorr_sign(sk, msg, aux, sig)) return 1;
        p2p_hex_encode(sig, 64, hex);
        puts(hex);
    } else if (!strcmp(cmd, "nostrsk") && argc == 3) {
        uint8_t wg[32], sk[32];
        b64key(argv[2], wg);
        if (p2p_nostr_key_from_wg(wg, sk)) return 1;
        p2p_hex_encode(sk, 32, hex);
        puts(hex);
    } else if (!strcmp(cmd, "event") && argc == 7) {
        uint8_t sk[32];
        char out[2048];
        hexarg(argv[2], sk, 32);
        int n = p2p_nostr_event(sk, (uint32_t)strtoul(argv[3], NULL, 10), strtoull(argv[4], NULL, 10),
                                argv[5], argv[6], out, sizeof(out));
        if (n < 0) return 1;
        puts(out);
    } else if (!strcmp(cmd, "wgpub") && argc == 3) {
        uint8_t priv[32], pub[32];
        char b[64];
        b64key(argv[2], priv);
        p2p_wg_pubkey(priv, pub);
        p2p_b64_encode(pub, 32, b, sizeof(b));
        puts(b);
    } else if (!strcmp(cmd, "seal") && argc == 5) {
        uint8_t priv[32], pub[32], key[32];
        char out[1024];
        b64key(argv[2], priv);
        b64key(argv[3], pub);
        if (p2p_envelope_key(priv, pub, key)) return 1;
        if (p2p_envelope_seal(key, (const uint8_t *)argv[4], strlen(argv[4]), out, sizeof(out))) return 1;
        puts(out);
    } else if (!strcmp(cmd, "open") && argc == 5) {
        uint8_t priv[32], pub[32], key[32], pt[600];
        b64key(argv[2], priv);
        b64key(argv[3], pub);
        if (p2p_envelope_key(priv, pub, key)) return 1;
        int n = p2p_envelope_open(key, argv[4], pt, sizeof(pt) - 1);
        if (n < 0) return 3;
        pt[n] = 0;
        puts((char *)pt);
    } else if (!strcmp(cmd, "stunreq") && argc == 3) {
        uint8_t txid[12], req[P2P_STUN_REQ_LEN];
        hexarg(argv[2], txid, 12);
        p2p_stun_build_request(txid, req);
        p2p_hex_encode(req, sizeof(req), hex);
        puts(hex);
    } else if (!strcmp(cmd, "stunparse") && argc == 4) {
        uint8_t pkt[512], txid[12], ip[4];
        uint16_t port;
        size_t n = strlen(argv[2]) / 2;
        if (n > sizeof(pkt)) return 2;
        hexarg(argv[2], pkt, n);
        hexarg(argv[3], txid, 12);
        if (!p2p_stun_parse_response(pkt, n, txid, ip, &port)) return 3;
        printf("%u.%u.%u.%u:%u\n", ip[0], ip[1], ip[2], ip[3], port);
    } else {
        fprintf(stderr, "bad usage\n");
        return 2;
    }
    return 0;
}
