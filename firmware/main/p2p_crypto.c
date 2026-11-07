// Portable crypto for p2ptun signaling. See p2p_crypto.h.
#include "p2p_crypto.h"

#include <string.h>
#include <stdio.h>

#include "mbedtls/version.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/platform_util.h"

#include "crypto/refc/x25519.h" // from the vendored esp_wireguard component

static p2p_rng_fn s_rng;
static void *s_rng_ctx;

void p2p_crypto_set_rng(p2p_rng_fn fn, void *ctx)
{
    s_rng = fn;
    s_rng_ctx = ctx;
}

int p2p_random(void *out, size_t len)
{
    if (!s_rng) {
        return -1;
    }
    return s_rng(s_rng_ctx, (unsigned char *)out, len);
}

static int rng_for_mbedtls(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return p2p_random(out, len);
}

// ---------------------------------------------------------------------------
// encoding
// ---------------------------------------------------------------------------
void p2p_hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hex[in[i] >> 4];
        out[2 * i + 1] = hex[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool p2p_hex_decode(const char *in, uint8_t *out, size_t out_len)
{
    if (!in || strlen(in) != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval(in[2 * i]), lo = hexval(in[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool p2p_b64_encode(const uint8_t *in, size_t len, char *out, size_t out_size)
{
    size_t olen = 0;
    return mbedtls_base64_encode((unsigned char *)out, out_size, &olen, in, len) == 0;
}

bool p2p_b64_decode(const char *in, uint8_t *out, size_t out_size, size_t *out_len)
{
    size_t olen = 0;
    if (mbedtls_base64_decode(out, out_size, &olen, (const unsigned char *)in, strlen(in)) != 0) {
        return false;
    }
    if (out_len) {
        *out_len = olen;
    }
    return true;
}

// ---------------------------------------------------------------------------
// hashing
// ---------------------------------------------------------------------------
static int sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
#if MBEDTLS_VERSION_MAJOR >= 3
    return mbedtls_sha256(in, len, out, 0);
#else
    return mbedtls_sha256_ret(in, len, out, 0);
#endif
}

// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || a || b || c)
static int tagged_hash(const char *tag, const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                       const uint8_t *c, size_t clen, uint8_t out[32])
{
    uint8_t th[32];
    int ret = sha256((const uint8_t *)tag, strlen(tag), th);
    if (ret != 0) {
        return ret;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
#if MBEDTLS_VERSION_MAJOR >= 3
    if ((ret = mbedtls_sha256_starts(&ctx, 0)) == 0 &&
        (ret = mbedtls_sha256_update(&ctx, th, 32)) == 0 &&
        (ret = mbedtls_sha256_update(&ctx, th, 32)) == 0 &&
        (ret = mbedtls_sha256_update(&ctx, a, alen)) == 0 &&
        (ret = mbedtls_sha256_update(&ctx, b, blen)) == 0 &&
        (ret = mbedtls_sha256_update(&ctx, c, clen)) == 0) {
        ret = mbedtls_sha256_finish(&ctx, out);
    }
#else
    if ((ret = mbedtls_sha256_starts_ret(&ctx, 0)) == 0 &&
        (ret = mbedtls_sha256_update_ret(&ctx, th, 32)) == 0 &&
        (ret = mbedtls_sha256_update_ret(&ctx, th, 32)) == 0 &&
        (ret = mbedtls_sha256_update_ret(&ctx, a, alen)) == 0 &&
        (ret = mbedtls_sha256_update_ret(&ctx, b, blen)) == 0 &&
        (ret = mbedtls_sha256_update_ret(&ctx, c, clen)) == 0) {
        ret = mbedtls_sha256_finish_ret(&ctx, out);
    }
#endif
    mbedtls_sha256_free(&ctx);
    return ret;
}

static int hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, klen, msg, mlen, out);
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------
int p2p_wg_genkey(uint8_t priv[32])
{
    if (p2p_random(priv, 32) != 0) {
        return -1;
    }
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    return 0;
}

void p2p_wg_pubkey(const uint8_t priv[32], uint8_t pub[32])
{
    x25519_base(pub, priv, 1);
}

// ---------------------------------------------------------------------------
// BIP-340 Schnorr over secp256k1 (mbedtls bignum/ecp)
// ---------------------------------------------------------------------------
#define CHK(x) do { if ((ret = (x)) != 0) goto cleanup; } while (0)

// x coordinate (32 bytes) and y parity of point P.
static int point_x_parity(mbedtls_ecp_group *grp, const mbedtls_ecp_point *P, uint8_t x[32], int *odd)
{
    uint8_t buf[33];
    size_t olen = 0;
    int ret = mbedtls_ecp_point_write_binary(grp, P, MBEDTLS_ECP_PF_COMPRESSED, &olen, buf, sizeof(buf));
    if (ret != 0) {
        return ret;
    }
    if (olen != 33) {
        return -1;
    }
    *odd = (buf[0] == 0x03);
    memcpy(x, buf + 1, 32);
    return 0;
}

static int schnorr_core(const uint8_t sk[32], const uint8_t *msg, const uint8_t *aux,
                        uint8_t px_out[32], uint8_t *sig_out)
{
    int ret, odd;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P, R;
    mbedtls_mpi d, k, e, s;
    uint8_t px[32], rx[32], dbytes[32], t[32], h[32];

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&P);
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&s);

    CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1));
    CHK(mbedtls_mpi_read_binary(&d, sk, 32));
    if (mbedtls_mpi_cmp_int(&d, 0) == 0 || mbedtls_mpi_cmp_mpi(&d, &grp.N) >= 0) {
        ret = -1;
        goto cleanup;
    }
    CHK(mbedtls_ecp_mul(&grp, &P, &d, &grp.G, rng_for_mbedtls, NULL));
    CHK(point_x_parity(&grp, &P, px, &odd));
    if (px_out) {
        memcpy(px_out, px, 32);
    }
    if (!sig_out) {
        goto cleanup; // pubkey only
    }
    if (odd) {
        CHK(mbedtls_mpi_sub_mpi(&d, &grp.N, &d));
    }
    CHK(mbedtls_mpi_write_binary(&d, dbytes, 32));

    // t = bytes(d) xor hash_aux(aux)
    CHK(tagged_hash("BIP0340/aux", aux, 32, NULL, 0, NULL, 0, h));
    for (int i = 0; i < 32; i++) {
        t[i] = dbytes[i] ^ h[i];
    }
    // k' = int(hash_nonce(t || px || m)) mod n
    CHK(tagged_hash("BIP0340/nonce", t, 32, px, 32, msg, 32, h));
    CHK(mbedtls_mpi_read_binary(&k, h, 32));
    CHK(mbedtls_mpi_mod_mpi(&k, &k, &grp.N));
    if (mbedtls_mpi_cmp_int(&k, 0) == 0) {
        ret = -1;
        goto cleanup;
    }
    CHK(mbedtls_ecp_mul(&grp, &R, &k, &grp.G, rng_for_mbedtls, NULL));
    CHK(point_x_parity(&grp, &R, rx, &odd));
    if (odd) {
        CHK(mbedtls_mpi_sub_mpi(&k, &grp.N, &k));
    }
    // e = int(hash_challenge(rx || px || m)) mod n
    CHK(tagged_hash("BIP0340/challenge", rx, 32, px, 32, msg, 32, h));
    CHK(mbedtls_mpi_read_binary(&e, h, 32));
    CHK(mbedtls_mpi_mod_mpi(&e, &e, &grp.N));
    // s = (k + e*d) mod n
    CHK(mbedtls_mpi_mul_mpi(&s, &e, &d));
    CHK(mbedtls_mpi_add_mpi(&s, &s, &k));
    CHK(mbedtls_mpi_mod_mpi(&s, &s, &grp.N));

    memcpy(sig_out, rx, 32);
    CHK(mbedtls_mpi_write_binary(&s, sig_out + 32, 32));

cleanup:
    mbedtls_platform_zeroize(dbytes, sizeof(dbytes));
    mbedtls_platform_zeroize(t, sizeof(t));
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&s);
    return ret;
}

int p2p_schnorr_pubkey(const uint8_t sk[32], uint8_t xonly[32])
{
    return schnorr_core(sk, NULL, NULL, xonly, NULL);
}

int p2p_schnorr_sign(const uint8_t sk[32], const uint8_t msg[32], const uint8_t aux[32], uint8_t sig[64])
{
    return schnorr_core(sk, msg, aux, NULL, sig);
}

int p2p_nostr_key_from_wg(const uint8_t wg_priv[32], uint8_t nostr_sk[32])
{
    static const char label[] = "p2ptun/nostr/v1";
    uint8_t buf[sizeof(label) - 1 + 32];
    memcpy(buf, label, sizeof(label) - 1);
    memcpy(buf + sizeof(label) - 1, wg_priv, 32);
    int ret = sha256(buf, sizeof(buf), nostr_sk);
    // Rehash in the astronomically unlikely case the key is out of range.
    uint8_t pub[32];
    for (int i = 0; ret == 0 && i < 8; i++) {
        if (p2p_schnorr_pubkey(nostr_sk, pub) == 0) {
            mbedtls_platform_zeroize(buf, sizeof(buf));
            return 0;
        }
        ret = sha256(nostr_sk, 32, nostr_sk);
    }
    mbedtls_platform_zeroize(buf, sizeof(buf));
    return -1;
}

// ---------------------------------------------------------------------------
// Nostr event
// ---------------------------------------------------------------------------
static bool is_b64(const char *s)
{
    for (; *s; s++) {
        char c = *s;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '+' || c == '/' || c == '=')) {
            return false;
        }
    }
    return true;
}

static bool is_hex64(const char *s)
{
    if (strlen(s) != 64) {
        return false;
    }
    for (; *s; s++) {
        if (hexval(*s) < 0 || (*s >= 'A' && *s <= 'F')) {
            return false; // nostr requires lowercase hex
        }
    }
    return true;
}

int p2p_nostr_event(const uint8_t sk[32], uint32_t kind, uint64_t created_at,
                    const char *p_tag_hex, const char *content, char *out, size_t out_size)
{
    uint8_t pub[32], id[32], aux[32], sig[64];
    char pub_hex[65], id_hex[65], sig_hex[129];

    if (!p_tag_hex || !content || !is_hex64(p_tag_hex) || !is_b64(content)) {
        return -1;
    }
    if (p2p_schnorr_pubkey(sk, pub) != 0) {
        return -1;
    }
    p2p_hex_encode(pub, 32, pub_hex);

    // NIP-01 id: sha256 of [0,pubkey,created_at,kind,tags,content] with no whitespace.
    int n = snprintf(out, out_size, "[0,\"%s\",%llu,%lu,[[\"p\",\"%s\"]],\"%s\"]",
                     pub_hex, (unsigned long long)created_at, (unsigned long)kind, p_tag_hex, content);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    if (sha256((const uint8_t *)out, (size_t)n, id) != 0) {
        return -1;
    }
    if (p2p_random(aux, sizeof(aux)) != 0 || p2p_schnorr_sign(sk, id, aux, sig) != 0) {
        return -1;
    }
    p2p_hex_encode(id, 32, id_hex);
    p2p_hex_encode(sig, 64, sig_hex);

    n = snprintf(out, out_size,
                 "{\"id\":\"%s\",\"pubkey\":\"%s\",\"created_at\":%llu,\"kind\":%lu,"
                 "\"tags\":[[\"p\",\"%s\"]],\"content\":\"%s\",\"sig\":\"%s\"}",
                 id_hex, pub_hex, (unsigned long long)created_at, (unsigned long)kind, p_tag_hex, content, sig_hex);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// envelope
// ---------------------------------------------------------------------------
static const uint8_t ENVELOPE_AAD[] = "p2ptun-v1";
#define AAD_LEN (sizeof(ENVELOPE_AAD) - 1)
#define NONCE_LEN 12
#define TAG_LEN 16
#define MAX_ENVELOPE_PT 512

int p2p_envelope_key(const uint8_t my_wg_priv[32], const uint8_t peer_wg_pub[32], uint8_t key[32])
{
    static const char label[] = "p2ptun-signal-v1";
    uint8_t peer[32], shared[32];
    memcpy(peer, peer_wg_pub, 32);
    peer[31] &= 0x7f; // RFC 7748: ignore the high bit
    if (x25519(shared, my_wg_priv, peer, 1) != 0) {
        return -1; // all-zero shared secret (low-order point)
    }
    int ret = hmac_sha256(shared, 32, (const uint8_t *)label, sizeof(label) - 1, key);
    mbedtls_platform_zeroize(shared, sizeof(shared));
    return ret;
}

int p2p_envelope_seal(const uint8_t key[32], const uint8_t *pt, size_t pt_len, char *out_b64, size_t out_size)
{
    uint8_t buf[NONCE_LEN + MAX_ENVELOPE_PT + TAG_LEN];
    if (pt_len > MAX_ENVELOPE_PT) {
        return -1;
    }
    if (p2p_random(buf, NONCE_LEN) != 0) {
        return -1;
    }
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, pt_len, buf, ENVELOPE_AAD, AAD_LEN, pt,
                                                 buf + NONCE_LEN, buf + NONCE_LEN + pt_len);
    }
    mbedtls_chachapoly_free(&ctx);
    if (ret != 0) {
        return -1;
    }
    return p2p_b64_encode(buf, NONCE_LEN + pt_len + TAG_LEN, out_b64, out_size) ? 0 : -1;
}

int p2p_envelope_open(const uint8_t key[32], const char *in_b64, uint8_t *pt, size_t pt_size)
{
    uint8_t buf[NONCE_LEN + MAX_ENVELOPE_PT + TAG_LEN];
    size_t len = 0;
    if (!p2p_b64_decode(in_b64, buf, sizeof(buf), &len) || len < NONCE_LEN + TAG_LEN) {
        return -1;
    }
    size_t ct_len = len - NONCE_LEN - TAG_LEN;
    if (ct_len > pt_size) {
        return -1;
    }
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_auth_decrypt(&ctx, ct_len, buf, ENVELOPE_AAD, AAD_LEN,
                                              buf + NONCE_LEN + ct_len, buf + NONCE_LEN, pt);
    }
    mbedtls_chachapoly_free(&ctx);
    return ret == 0 ? (int)ct_len : -1;
}
