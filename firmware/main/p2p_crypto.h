// Portable crypto for p2ptun signaling. Builds on ESP-IDF (mbedtls 3.x) and on a
// host with mbedtls 2.28+/3.x so it can be unit tested (see tests/).
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_KEY_LEN 32

// Random source. Must be cryptographically secure. Returns 0 on success.
typedef int (*p2p_rng_fn)(void *ctx, unsigned char *out, size_t len);
void p2p_crypto_set_rng(p2p_rng_fn fn, void *ctx);
int p2p_random(void *out, size_t len);

// ---- encoding helpers ----
void p2p_hex_encode(const uint8_t *in, size_t len, char *out /* 2*len+1 */);
bool p2p_hex_decode(const char *in, uint8_t *out, size_t out_len); // exact length, lowercase/uppercase ok
bool p2p_b64_encode(const uint8_t *in, size_t len, char *out, size_t out_size);
bool p2p_b64_decode(const char *in, uint8_t *out, size_t out_size, size_t *out_len);

// ---- X25519 / WireGuard keys ----
// Generate a clamped Curve25519 private key (same format as `wg genkey`).
int p2p_wg_genkey(uint8_t priv[32]);
void p2p_wg_pubkey(const uint8_t priv[32], uint8_t pub[32]);

// ---- BIP-340 Schnorr (Nostr) ----
// x-only public key of a secp256k1 secret key. Returns 0 on success.
int p2p_schnorr_pubkey(const uint8_t sk[32], uint8_t xonly[32]);
// BIP-340 signature with auxiliary randomness `aux`. Returns 0 on success.
int p2p_schnorr_sign(const uint8_t sk[32], const uint8_t msg[32], const uint8_t aux[32], uint8_t sig[64]);
// Derive the device's Nostr identity from its WireGuard private key so a single
// secret needs protecting: sk = SHA256("p2ptun/nostr/v1" || wg_priv) (rehashed if invalid).
int p2p_nostr_key_from_wg(const uint8_t wg_priv[32], uint8_t nostr_sk[32]);

// Build a signed Nostr event JSON:
//   {"id":..,"pubkey":..,"created_at":..,"kind":..,"tags":[["p",p_tag]],"content":..,"sig":..}
// `content` must be base64 (no JSON escaping is performed; rejected otherwise).
// Returns length written (excluding NUL) or -1.
int p2p_nostr_event(const uint8_t sk[32], uint32_t kind, uint64_t created_at,
                    const char *p_tag_hex, const char *content, char *out, size_t out_size);

// ---- signaling envelope ----
// key = HMAC-SHA256(key = X25519(my_wg_priv, peer_wg_pub), "p2ptun-signal-v1")
// Both sides compute the same key from their own WireGuard keys; nothing new to distribute.
int p2p_envelope_key(const uint8_t my_wg_priv[32], const uint8_t peer_wg_pub[32], uint8_t key[32]);
// Pairing: key = HMAC-SHA256(key = invite secret, "p2ptun-pair-v1"); used with the same envelope.
int p2p_pair_key(const uint8_t *secret, size_t secret_len, uint8_t key[32]);
// content = base64( nonce[12] || ChaCha20-Poly1305(key, nonce, aad="p2ptun-v1", plaintext) || tag[16] )
int p2p_envelope_seal(const uint8_t key[32], const uint8_t *pt, size_t pt_len, char *out_b64, size_t out_size);
// Returns plaintext length, or -1 if authentication fails / malformed.
int p2p_envelope_open(const uint8_t key[32], const char *in_b64, uint8_t *pt, size_t pt_size);

#ifdef __cplusplus
}
#endif
