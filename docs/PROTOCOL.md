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
{"v":1,"t":"ack","ts":1730000001,"n":"9f2c4a1be07d3355","ep":"198.51.100.20:51820","via":"upnp","lan":"192.168.1.50:51820","pub_ip":"198.51.100.20"}
```

* `ts`: Unix time. The device rejects |skew| > 120 s and any `ts` ≤ the last accepted one for that
  peer (replay protection; the device syncs time over SNTP).
* `n`: client nonce (hex, ≤ 32 chars), echoed in the ack so the client only accepts the answer to
  *this* knock.
* `ep` (knock, **optional**): the client's public endpoint from STUN, discovered on the **same UDP
  port its WireGuard uses**. If present, the device hole-punches towards it. The desktop Python client
  always sends it. The browser client can't know the WireGuard app's mapping, so it sends only its
  public IP (from a WebRTC STUN candidate) plus its fixed `ListenPort` 51821 as a best guess.
* `ep` (ack): the endpoint clients should dial, chosen by `via`:
  `manual` (admin-set `host:port`, may be a DNS name) > `upnp` / `natpmp` (verified router port
  mapping) > `stun` (the device's own STUN result on the WireGuard socket; on the ESP32 STUN runs
  through the WireGuard socket itself, see `firmware/components/esp_wireguard/PATCHES.md`).
* `lan`: local endpoint. `pub_ip` (ack): the device's public IP from STUN. If the client's public IP
  equals `pub_ip` they're behind the same NAT, and the client dials `lan` instead (most routers don't
  support hairpinning). This works even when `ep` is a DNS name.

## Nostr event

NIP-01 event, kind **21820** (ephemeral range: relays forward it but don't store it), with one tag
`["p", <recipient x-only pubkey hex>]` and `content` = the envelope. Signed with BIP-340 Schnorr
(implemented on the ESP32 with mbedtls bignum/ECP and tested byte-for-byte against libsecp256k1).

The device subscribes with `{"kinds":[21820],"#p":[<device npub>],"since":now-60}` on up to 3
relays and de-duplicates events by id.

## Reachability: why phones work

The stock WireGuard apps (Android, iOS, Windows, macOS) can't take part in the knock, so they
only work if the device can be dialled directly. The device tries to make that true:

1. **NAT-PMP** (RFC 6886) to the default gateway, then **UPnP-IGD** (SSDP → device description →
   SOAP `AddPortMapping`) for `UDP <public>:51820 → <esp32>:51820`, renewed at half the lease.
   Only answers from the default gateway are accepted.
2. The router's claimed external IP is **cross-checked against STUN**. If STUN hasn't confirmed it,
   it's private (double NAT or CGNAT), or it differs from what STUN sees, the mapping isn't advertised.
   The UPnP description and control URLs must point at the gateway itself.
3. An admin can set a **manual endpoint** (a router port forward, optionally a DDNS name).

Opening the port is low-risk: only WireGuard listens on it, and WireGuard drops every packet that
isn't authenticated by an authorized key (it doesn't even reply). If none of this is available,
`via` is `stun` and only hole punching remains.

| Client | Device reachable (`manual`/`upnp`/`natpmp`) | Hole punching only (`stun`) |
|---|---|---|
| Python client `up` (Linux) | ✅ | ✅ unless both sides are behind symmetric NAT |
| Python client `resolve` + WireGuard app (Windows/macOS) | ✅ | ✅ if imported within ~30 s |
| Browser client + WireGuard app (Android, iOS, any OS) | ✅ | ⚠️ only with port-preserving, permissive NAT |

## Hole punching

After a valid knock the device calls `wireguardif_update_endpoint` + `wireguardif_connect`, so it
starts sending WireGuard handshake initiations to the client's public endpoint while the client
does the same in the other direction. This opens both NATs. Both sides then keep the mapping alive
(the device sends a 25 s persistent keepalive and STUN every 20 s; the client sends a 25 s keepalive).

This works for endpoint-independent ("cone") NAT on at least one side, which covers most home
routers and many mobile networks. It does **not** work when both sides are behind symmetric NAT
(some carrier-grade NAT and corporate networks). There is no relay fallback by design.

## Pairing (one-scan onboarding)

Goal: add a phone or computer by scanning a QR code / opening a link from the device web UI. There's
no manual public-key copy and no JSON paste. Same transport as knocks: Nostr kind 21820 events with
tag `["p", <device nostr pubkey hex>]`, content = envelope (see "Envelope"), but sealed with a key
derived from a one-time **invite secret** instead of the WireGuard keys (the device doesn't know
the client's key yet).

### Invite (created by an admin in the device UI, kept in RAM only)
* `POST /api/invites {name, acl, expires_in}` (same validation as `/api/peers/add`, minus pubkey)
  creates an invite with a fresh 16-byte random `secret`, valid for **15 minutes**, **single use**,
  at most 4 pending invites (oldest pending is replaced). Lost on reboot. Admin-only.
* Response / UI shows the **invite link**:
  `<web_client_url>#p2ptun=<base64url-no-padding(JSON)>`, where JSON is
  ```json
  {"v":1,"name":"phone","secret":"<base64url-no-padding 16 bytes>",
   "device":{"wg_pub":"<b64>","nostr_pub":"<hex64>","tunnel_ip":"10.77.0.1","routes":["192.168.1.0/24"]},
   "relays":["wss://..."]}
  ```
  `web_client_url` is a device setting (Kconfig `P2PTUN_WEB_CLIENT_URL`, default
  `https://dmdhrumilmistry.github.io/esp32/`, overridable in Settings, saved in NVS key `webclient`).
  The URL fragment is never sent to the web server. Clients must remove it from the address bar after
  reading it (`history.replaceState`).
* `GET /api/state` lists invites: `{"id": <1..>, "name", "state": "pending"|"used"|"expired"|"revoked",
  "expires_in_s", "peer": "<ip once used>"}` and never the secret. `POST /api/invites/revoke {id}` cancels one.
* Invites are tried only for events that don't open with any enabled peer's key.

### Keys
```
pair_key = HMAC-SHA256(key = secret (16 bytes), msg = "p2ptun-pair-v1")
```
Envelope as for knocks (ChaCha20-Poly1305, aad "p2ptun-v1", random 12-byte nonce, base64).

### Messages (inside envelopes sealed with pair_key)
```jsonc
// client -> device   (Nostr event signed by a fresh throwaway key, p-tag = device nostr pubkey)
{"v":1,"t":"pair","ts":1730000000,"n":"<16 hex>","pub":"<client WireGuard public key, base64>"}
// device -> client   (p-tag = the pair event's pubkey)
{"v":1,"t":"paired","ts":1730000001,"n":"<echo>","address":"10.77.0.5/32","name":"phone"}
{"v":1,"t":"pair-error","ts":1730000001,"n":"<echo>","error":"<short reason>"}
```
Device rules, applied when a message opens with an invite's pair_key:
* `ts` within ±120 s of device time (needs SNTP) and newer than the last one seen for this invite (replays are ignored silently), `n` short hex (as for knocks), `pub` = valid 32-byte key,
  not the device's own key.
* Invite **pending** and not expired → create the peer exactly as `/api/peers/add` would (name, acl, expiry from
  the invite; next free tunnel host), save, sync WireGuard, mark invite **used** (remember `pub` + address),
  log event `peer '<name>' paired via invite`, reply `paired`.
* Invite **used** by the **same** `pub` → reply `paired` again (idempotent; lost ack retry).
* Invite used by another key / expired / revoked / peer table full / pub already a peer → reply `pair-error`
  with a short reason (no secret material). An expired invite is never revived.
* After `paired`, the client already has everything for a normal knock: device block + relays from the
  invite and `address` from the ack. Clients save that as their config (same shape as the JSON the
  device UI shows: `{"name","address","device":{...},"relays":[...]}`) and can connect right away.

### Clients
* Web client: on load, if the URL fragment has `#p2ptun=`, decode it, strip it from the URL, show
  "Pair with <device name>?" Create a key if none exists (passphrase prompt optional), send `pair`,
  wait up to 25 s for `paired`/`pair-error`, then save the config and offer **Get WireGuard config**
  immediately.
* Python client: `python3 p2ptun.py pair '<invite link or the base64url blob>'`. It creates a key if
  needed, pairs, and saves `p2ptun.json` (mode 600).

### Security notes
* The invite secret is the only credential: single-use, 15-minute lifetime, RAM only, created only by a
  logged-in admin. Anyone who sees the QR/link before it's used could pair instead. The event log shows
  every pairing, and the admin can block/delete.
* Relays see only ciphertext. Wrong-secret messages don't open and get no answer.

## Revocation

*Block* or *Delete* in the web UI removes the peer from WireGuard immediately
(`wireguardif_remove_peer` zeroes its session keys), so the live tunnel stops at once. Its
knocks no longer decrypt, so it can't reconnect.
