// Host CLI around the portable firmware modules, used by tests/test_interop.py.
//   p2p_host pubkey  <sk_hex>
//   p2p_host sign    <sk_hex> <msg_hex> <aux_hex>
//   p2p_host nostrsk <wg_priv_b64>
//   p2p_host event   <sk_hex> <kind> <created_at> <p_hex> <content>
//   p2p_host wgpub   <wg_priv_b64>
//   p2p_host seal    <my_priv_b64> <peer_pub_b64> <plaintext>
//   p2p_host open    <my_priv_b64> <peer_pub_b64> <content_b64>
//   p2p_host pairseal <secret_hex> <plaintext> | pairopen <secret_hex> <content_b64>
//   p2p_host stunreq <txid_hex>
//   p2p_host stunparse <pkt_hex> <txid_hex>
//   p2p_host natpmp-map <internal> <external> <lifetime>      -> request hex
//   p2p_host natpmp-ext <resp_hex> | natpmp-mapped <resp_hex> <internal>
//   p2p_host ssdp-location <file> | igd <xml_file> | urlres <base> <ref>
//   p2p_host soap-add <service_type> <ext> <int> <client> <lease> | soap-extip <file> | soap-err <file>
//   p2p_host http <file>                                         -> "<status>\n<body>"
//   p2p_host private <a.b.c.d>
//   p2p_host acl-parse <rules>                                   -> "all" | "<n> rules" (rc 4 + reason)
//   p2p_host acl-check <rules> <lan a.b.c.d/nn | -> <dev a.b.c.d> <pkt_hex>  -> allow | deny
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p2p_crypto.h"
#include "p2p_stun.h"
#include "p2p_portmap_proto.h"
#include "p2p_acl.h"

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

static char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) exit(2);
    static char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    if (len) *len = n;
    return buf;
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
    } else if ((!strcmp(cmd, "pairseal") || !strcmp(cmd, "pairopen")) && argc == 4) {
        uint8_t secret[64], key[32];
        size_t sl = strlen(argv[2]) / 2;
        if (sl == 0 || sl > sizeof(secret)) return 2;
        hexarg(argv[2], secret, sl);
        if (p2p_pair_key(secret, sl, key)) return 1;
        if (!strcmp(cmd, "pairseal")) {
            char out[1024];
            if (p2p_envelope_seal(key, (const uint8_t *)argv[3], strlen(argv[3]), out, sizeof(out))) return 1;
            puts(out);
        } else {
            uint8_t pt[600];
            int n = p2p_envelope_open(key, argv[3], pt, sizeof(pt) - 1);
            if (n < 0) return 3;
            pt[n] = 0;
            puts((char *)pt);
        }
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
    } else if (!strcmp(cmd, "natpmp-map") && argc == 5) {
        uint8_t req[12];
        p2p_natpmp_req_map_udp((uint16_t)atoi(argv[2]), (uint16_t)atoi(argv[3]), (uint32_t)strtoul(argv[4], NULL, 10), req);
        p2p_hex_encode(req, sizeof(req), hex);
        puts(hex);
    } else if (!strcmp(cmd, "natpmp-ext") && argc == 3) {
        uint8_t pkt[64], ip[4];
        size_t n = strlen(argv[2]) / 2;
        if (n > sizeof(pkt)) return 2;
        hexarg(argv[2], pkt, n);
        if (!p2p_natpmp_parse_extaddr(pkt, n, ip)) return 3;
        printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
    } else if (!strcmp(cmd, "natpmp-mapped") && argc == 4) {
        uint8_t pkt[64];
        uint16_t ext;
        uint32_t life;
        size_t n = strlen(argv[2]) / 2;
        if (n > sizeof(pkt)) return 2;
        hexarg(argv[2], pkt, n);
        if (!p2p_natpmp_parse_map_udp(pkt, n, (uint16_t)atoi(argv[3]), &ext, &life)) return 3;
        printf("%u %lu\n", ext, (unsigned long)life);
    } else if (!strcmp(cmd, "ssdp-location") && argc == 3) {
        char url[256];
        if (!p2p_ssdp_location(slurp(argv[2], NULL), url, sizeof(url))) return 3;
        puts(url);
    } else if (!strcmp(cmd, "igd") && argc == 3) {
        char st[128], cu[256];
        if (!p2p_igd_find_control(slurp(argv[2], NULL), st, sizeof(st), cu, sizeof(cu))) return 3;
        printf("%s %s\n", st, cu);
    } else if (!strcmp(cmd, "urlres") && argc == 4) {
        char out[512], host[64], path[256];
        uint16_t port;
        if (!p2p_url_resolve(argv[2], argv[3], out, sizeof(out))) return 3;
        if (!p2p_url_split(out, host, sizeof(host), &port, path, sizeof(path))) return 4;
        printf("%s %s %u %s\n", out, host, port, path);
    } else if (!strcmp(cmd, "soap-add") && argc == 7) {
        char out[2048];
        if (p2p_soap_add_mapping(argv[2], (uint16_t)atoi(argv[3]), (uint16_t)atoi(argv[4]), argv[5],
                                 (uint32_t)strtoul(argv[6], NULL, 10), out, sizeof(out)) < 0) return 3;
        fputs(out, stdout);
    } else if (!strcmp(cmd, "soap-extip") && argc == 3) {
        uint8_t ip[4];
        if (!p2p_soap_parse_external_ip(slurp(argv[2], NULL), ip)) return 3;
        printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
    } else if (!strcmp(cmd, "soap-err") && argc == 3) {
        printf("%d\n", p2p_soap_error_code(slurp(argv[2], NULL)));
    } else if (!strcmp(cmd, "http") && argc == 3) {
        size_t n;
        char *r = slurp(argv[2], &n);
        int st = p2p_http_status(r);
        char *body = p2p_http_body(r, n);
        if (!body) return 3;
        printf("%d\n%s", st, body);
    } else if (!strcmp(cmd, "acl-parse") && argc == 3) {
        p2p_acl_t acl;
        char err[96];
        if (!p2p_acl_parse(argv[2], &acl, err, sizeof(err))) {
            puts(err);
            return 4;
        }
        if (acl.all) puts("all"); else printf("%u rules\n", acl.n);
    } else if (!strcmp(cmd, "acl-check") && argc == 6) {
        p2p_acl_t acl;
        char err[96];
        if (!p2p_acl_parse(argv[2], &acl, err, sizeof(err))) {
            puts(err);
            return 4;
        }
        p2p_acl_env_t env = {0};
        unsigned a, b, cc, d, bits;
        if (strcmp(argv[3], "-") != 0) {
            if (sscanf(argv[3], "%u.%u.%u.%u/%u", &a, &b, &cc, &d, &bits) != 5 || bits == 0 || bits > 32) return 2;
            env.lan_mask = 0xFFFFFFFFu << (32 - bits);
            env.lan_net = ((a << 24) | (b << 16) | (cc << 8) | d) & env.lan_mask;
        }
        if (sscanf(argv[4], "%u.%u.%u.%u", &a, &b, &cc, &d) != 4) return 2;
        env.dev_ip = (a << 24) | (b << 16) | (cc << 8) | d;
        uint8_t pkt[256];
        size_t n = strlen(argv[5]) / 2;
        if (n > sizeof(pkt)) return 2;
        hexarg(argv[5], pkt, n);
        puts(p2p_acl_allows(&acl, &env, pkt, n) ? "allow" : "deny");
    } else if (!strcmp(cmd, "private") && argc == 3) {
        unsigned a, b, c, d;
        if (sscanf(argv[2], "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 2;
        uint8_t ip[4] = {a, b, c, d};
        puts(p2p_ip_is_private(ip) ? "private" : "public");
    } else {
        fprintf(stderr, "bad usage\n");
        return 2;
    }
    return 0;
}
