# p2ptun protocol (v1)

p2ptun connects a client to an ESP32 directly with **WireGuard**. The only third parties are
public **STUN** servers (each side learns its own public `ip:port`) and public **Nostr relays**
(used as a dumb mailbox to swap those `ip:port`s). Neither ever sees tunnel traffic or any key
material, and you don't run a server.

```
 client                         Nostr relay(s)                       ESP32 (behind home NAT)
   │  STUN from UDP :51821  ─► public 203.0.113.9:40001                 │  STUN from WG port :51820 every 20 s
   │                                                                   │  ─► public 198.51.100.20:51820
   │ ── EVENT kind 21820, p=<device npub>, content=Enc(knock) ──►  ──►  │  (device subscribed to #p=<its npub>)
   │                                                                   │  decrypt with each *enabled* peer key
   │                                                                   │  → set WG endpoint, start handshakes (punch)
   │ ◄── EVENT kind 21820, p=<client eph. npub>, content=Enc(ack) ◄──── │
   │  set WG endpoint = device public ip:port                          │
   │ ◄═══════════════ WireGuard handshake + data, direct UDP ═════════►│ ──NAPT──► LAN 192.168.1.0/24
```

## Keys

| Key | Where it lives | Purpose |
|---|---|---|
| Device WireGuard key (X25519) | ESP32 NVS, generated on first boot | WireGuard + signaling envelope |
| Device Nostr key (secp256k1) | derived: `SHA256("p2ptun/nostr/v1" ‖ wg_priv)` | lets clients address the device on relays |
| Client WireGuard key | client `p2ptun.json` (mode 600) | WireGuard + signaling envelope |
| Client Nostr key | random, **new for every knock** | relays can't link sessions to a client |

A client is authorized by pasting its WireGuard **public** key into the device web UI. That is
the only enrollment step: the signaling key is derived from the same keys.

## Envelope

```
shared  = X25519(my_wg_priv, peer_wg_pub)                 # same value on both sides
key     = HMAC-SHA256(key=shared, msg="p2ptun-signal-v1")
content = base64( nonce[12] ‖ ChaCha20-Poly1305(key, nonce, aad="p2ptun-v1", plaintext) )
```

The device tries to open each incoming envelope with the key of every **enabled** peer (at most 8).
A message that opens is authenticated: only the holder of that peer's WireGuard private key could
have produced it. Blocked or deleted peers are never tried, so they get no answer at all.

## Messages (plaintext JSON inside the envelope)

```jsonc
// client → device
{"v":1,"t":"knock","ts":1730000000,"n":"9f2c4a1be07d3355","ep":"203.0.113.9:40001","lan":"10.0.0.5:51821"}
// device → client
{"v":1,"t":"ack","ts":1730000001,"n":"9f2c4a1be07d3355","ep":"198.51.100.20:51820","lan":"192.168.1.50:51820"}
```

* `ts`: Unix time. The device rejects |skew| > 120 s and any `ts` ≤ the last accepted one for that
  peer (replay protection; the device syncs time over SNTP).
* `n`: client nonce (hex, ≤ 32 chars), echoed in the ack so the client only accepts the answer to
  *this* knock.
* `ep`: public endpoint from STUN, discovered on the **same UDP port WireGuard uses**. On the
  ESP32, STUN runs through the WireGuard socket itself (see `firmware/components/esp_wireguard/PATCHES.md`).
* `lan`: local endpoint. If both sides report the same public IP they're behind the same NAT, and
  the LAN address is used (most routers don't support hairpinning).

## Nostr event

NIP-01 event, kind **21820** (ephemeral range: relays forward it but don't store it), with one tag
`["p", <recipient x-only pubkey hex>]` and `content` = the envelope. Signed with BIP-340 Schnorr
(implemented on the ESP32 with mbedtls bignum/ECP and tested byte-for-byte against libsecp256k1).

The device subscribes with `{"kinds":[21820],"#p":[<device npub>],"since":now-60}` on up to 3
relays and de-duplicates events by id.

## Hole punching

After a valid knock the device calls `wireguardif_update_endpoint` + `wireguardif_connect`, so it
starts sending WireGuard handshake initiations to the client's public endpoint while the client
does the same in the other direction. This opens both NATs. Both sides then keep the mapping alive
(the device sends a 25 s persistent keepalive and STUN every 20 s; the client sends a 25 s keepalive).

This works for endpoint-independent ("cone") NAT on at least one side, which covers most home
routers and many mobile networks. It does **not** work when both sides are behind symmetric NAT
(some carrier-grade NAT and corporate networks). There is no relay fallback by design.

## Revocation

*Block* or *Delete* in the web UI removes the peer from WireGuard immediately
(`wireguardif_remove_peer` zeroes its session keys), so the live tunnel stops at once. Its
knocks no longer decrypt, so it can't reconnect.
