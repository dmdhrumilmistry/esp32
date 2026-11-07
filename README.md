# p2ptun: serverless WireGuard access to your LAN through an ESP32

Plug an ESP32 into a network you own and reach that LAN from anywhere over a **direct,
peer-to-peer WireGuard tunnel**, from **Windows, macOS, Linux, Android or iOS** using the official
WireGuard apps. You don't run a server or hold a cloud account. A small **web UI on the device**
controls who may connect, and can cut off any active connection instantly.

```
  laptop / phone                 public Nostr relays                 ESP32 at home / lab
 ┌──────────────┐   encrypted    ┌───────────────┐   encrypted     ┌──────────────────┐
 │ web client / │──"knock"──────►│ dumb mailbox  │───────────────► │ web UI: allow /  │
 │ p2ptun.py    │◄──────"ack"────│ (sees only    │◄────────────────│ block / delete   │
 │ + WireGuard  │                │  ciphertext)  │                 │ WireGuard + NAPT │──► 192.168.1.0/24
 └──────┬───────┘                └───────────────┘                 └────────┬─────────┘
        └══════ WireGuard, direct UDP (router port mapping or NAT hole punching) ══════┘
```

* **Tunnel:** WireGuard (Noise IK, ChaCha20-Poly1305), up to 8 authorized clients. Traffic is
  source-NATed onto the ESP32's LAN, so LAN devices need no configuration.
* **Rendezvous without a server:** both sides learn their public `ip:port` via STUN, then swap it
  through public **Nostr relays**, end-to-end encrypted with keys derived from the WireGuard keys.
  Relays never see tunnel traffic, keys or plaintext endpoints. See [docs/PROTOCOL.md](docs/PROTOCOL.md).
* **Reachable from phones too:** the device asks your router to forward its WireGuard port
  (NAT-PMP / UPnP-IGD, verified against STUN), or you set a manual endpoint. The stock WireGuard
  app on any OS can then dial it directly, even from carrier networks where hole punching fails.
* **Web UI** (served by the ESP32): authorize a client by pasting its public key, see who is
  connected (endpoint, last seen), **Block** (cuts the live session and refuses reconnects) or
  **Delete** a peer, and change the admin password, relays and endpoint override.
* **Per-peer access rules:** limit each client to what it needs, e.g. `tcp:192.168.1.20:22` (SSH
  to one host) or `lan:80-443`. Rules are enforced on the ESP32 for every packet leaving the
  tunnel, edits apply to live sessions immediately, and dropped packets are counted per peer.
  Peers can never reach each other.
* **Expiring access:** give a guest 1 h, 8 h, 24 h, 7 days or 30 days. When it runs out the device
  blocks the peer, cuts its session and ignores its knocks.
* **Security event log:** admin logins (with source IP), failed logins and lockouts, accepted or
  rejected knocks, peer changes and expiries, all shown in the UI.
* **Browser client** (`web/`, static page, no install): creates the key on the phone or computer,
  does the encrypted knock from the browser and gives you a ready `p2ptun.conf` for the WireGuard app.

## Supported clients

| Platform | How | Notes |
|---|---|---|
| **Android, iOS / iPadOS** | Browser client → *Download p2ptun.conf* → import in the WireGuard app | Needs the device to be directly reachable (router mapping or manual endpoint), which is the default when UPnP/NAT-PMP is on |
| **Windows, macOS** | Browser client, or `p2ptun.py resolve -o p2ptun.conf` → import in the WireGuard app | `resolve` also hole-punches when the device has no router mapping |
| **Linux** | `sudo p2ptun.py up` (all-in-one: knock, hole punch, interface, re-knock), or either of the above with `wg-quick` | |

The reachability panel in the device UI tells you which case you're in.

## Security model

| Threat | Mitigation |
|---|---|
| Someone on the internet connects | Only WireGuard keys authorized in the UI can complete a handshake. The device never answers knocks it can't decrypt with an enabled peer's key. |
| Relay operator snoops or tampers | Signaling is ChaCha20-Poly1305 with an X25519-derived key, so the relay only sees ciphertext. Clients use a fresh Nostr identity per knock. |
| Replayed knock | Per-peer strictly increasing timestamps with ±120 s skew (the device syncs SNTP), plus a nonce echoed in the ack. |
| Revoked client keeps its tunnel | Block/Delete/expiry removes the peer from WireGuard and zeroes its session keys immediately. |
| Authorized client reaches too much | Per-peer allowlist (protocol, address/CIDR, port range) checked on every decrypted packet before it enters the IP stack. The default is deny once any rule is set. Peer-to-peer forwarding is never allowed. |
| Client spoofs another source address | The cryptokey routing check verifies each packet's **source** against the peer's tunnel address. Upstream checked the destination, which is fixed in the vendored copy (see `PATCHES.md`). |
| Web UI attacks | PBKDF2-SHA256 password hash, 5-try lockout, random 256-bit `HttpOnly; SameSite=Strict` session cookie, JSON-only POST (CSRF), strict CSP, `X-Frame-Options: DENY`, no external resources, all output via `textContent`. |
| Router port mapping exposes the device | Only the WireGuard UDP port is mapped. WireGuard silently drops anything not authenticated by an authorized key, and the web UI is never mapped. The router's external IP is cross-checked with STUN, so a fake SSDP/NAT-PMP answer can't redirect clients. Turn it off with `CONFIG_P2PTUN_PORTMAP`. |
| Browser client key theft | The key is created and kept in the browser (optional passphrase: PBKDF2-SHA256 310k + AES-GCM). The page loads no third-party code, and its CSP allows only `wss:` connections. Host it on its **own origin**: every `<user>.github.io/*` Pages site shares one origin, and so one `localStorage`. |
| Unconfigured device hijacked | The setup AP is WPA2 with a random password that is shown only on the serial console. |
| Weak keys at first boot | Keys are generated with the bootloader entropy source enabled (the ESP32 RNG is only a true RNG while RF or that source is on). |
| Device stolen | Enable **Secure Boot v2 + Flash Encryption + NVS encryption** for production (lines in `firmware/sdkconfig.defaults`). Hold BOOT for 5 s while it runs to wipe all keys and settings. |

**Use it only on networks you own or are authorized to access.** A device like this is a bridge
into the LAN it sits on.

Known limits, by design (keeping it simple):
* No relay fallback. Without a router mapping (UPnP/NAT-PMP off, double NAT) phones usually can't
  connect, and the desktop client's hole punching fails if **both** sides are behind
  symmetric / carrier-grade NAT. One cone-NAT side (most home routers) is enough for hole punching.
* Throughput is a few Mbps (software crypto on a 240 MHz MCU). That's fine for SSH, web UIs, RDP
  and IoT, but not for bulk transfer.
* The admin UI is plain HTTP. Reach it over the tunnel (`http://10.77.0.1/`, encrypted by
  WireGuard) or from a trusted LAN.
* IPv4 only.

## Quick start

### 1. Flash the ESP32 (ESP-IDF v5.1–5.x)

```bash
cd firmware
idf.py set-target esp32        # CI-built target; S3/C3 should work but are untested
idf.py build flash monitor
```

Any ESP32 with 4 MB flash works. Boards with PSRAM give more headroom for the relay TLS connections.
CI builds the firmware on every push, and the binaries are attached to the workflow run.

### 2. First-time setup

The serial monitor prints something like:

```
W wifi:  SETUP MODE
W wifi:   Wi-Fi:    p2ptun-setup-3fa2
W wifi:   Password: k7xq2mvh9tnp
W wifi:   Open:     http://192.168.4.1/
```

Join that Wi-Fi, open the page, enter your Wi-Fi credentials and an admin password. The device
reboots onto your network. Open `http://<device-ip>/` and log in.

### 3. Connect a phone or any computer (browser client)

Open the browser client: publish `web/` with GitHub Pages (the `web-client` workflow; enable
*Settings → Pages → Source: GitHub Actions*) or serve it from any static host. Then:

1. **Your key → Create key.** Copy the public key.
2. In the **device** web UI, go to **Authorize a client**, enter a name and the key, and press **Authorize**.
   Copy the JSON it shows.
3. Back in the browser client, paste it into **Device config** and press **Save**.
4. Press **Get WireGuard config**, then **Download p2ptun.conf** and import it in the WireGuard app
   (step-by-step instructions for each OS are on the page). You can then reach the device at
   `10.77.0.1` and the whole LAN behind it.

### 4. Desktop alternative: Python client

```bash
cd client && pip install -r requirements.txt
python3 p2ptun.py genkey            # prints this client's public key: authorize it in the device UI
python3 p2ptun.py join '{"name":"laptop","address":"10.77.0.2/32","device":{...},"relays":[...]}'

sudo python3 p2ptun.py up           # Linux: knock + hole punch + interface, stays connected
# [p2ptun] my public endpoint 203.0.113.9:40001 (LAN 10.0.0.5:51821)
# [p2ptun] device answered: 198.51.100.20:51820 via router port mapping → using 198.51.100.20:51820
# [p2ptun] connected ✔  try: ping 10.77.0.1
ssh pi@192.168.1.20                 # any host on the ESP32's LAN

python3 p2ptun.py resolve -o p2ptun.conf   # Windows/macOS: write a config for the WireGuard app
```

If the client's own LAN uses the same subnet as the device's LAN (both `192.168.1.0/24`, for example), the routes clash.
Connect from another network or renumber one side.

## Repository layout

```
firmware/                      ESP-IDF project
  main/p2p_tunnel.c            WireGuard netif, NAPT to LAN, STUN on the WireGuard socket
  main/p2p_signal.c            Nostr relay client, knock/ack handling, replay protection
  main/p2p_crypto.c            BIP-340 Schnorr, Nostr events, signaling envelope (portable, host-tested)
  main/p2p_stun.c              STUN Binding client (portable, host-tested)
  main/p2p_portmap*.c          NAT-PMP / UPnP-IGD port mapping + reachability (protocol code host-tested)
  main/p2p_acl.c               per-peer access rules: parser + packet matcher (portable, host-tested)
  main/p2p_events.c            in-RAM security event log
  main/p2p_web.c, www/         web UI + JSON API
  main/p2p_auth.c              password hashing, sessions, lockout
  components/esp_wireguard/    vendored trombik/esp_wireguard (BSD-3) + small patch, see PATCHES.md
client/p2ptun.py               desktop CLI client (genkey / join / up / resolve)
web/                           browser client for any OS: index.html, app.js, p2ptun-proto.js (no deps)
docs/PROTOCOL.md               wire protocol and design
tests/                         C / Python / JS interop, libsecp256k1, UPnP fixtures, end-to-end rendezvous
```

## Tests

```bash
sudo apt install libmbedtls-dev     # and Node.js 22+ for the web client tests
pip install -r client/requirements.txt -r tests/requirements.txt
make -C tests/host && python3 -m unittest discover -s tests -v
```

The firmware's crypto and STUN code is compiled for the host and checked against:
* official BIP-340 test vectors, plus byte-for-byte equality with **libsecp256k1** on random inputs,
* the Python client (envelope both directions, tamper and wrong-key rejection, STUN parsing),
* the **browser client** (run under Node): X25519 (WebCrypto and fallback), ChaCha20-Poly1305 vs
  `cryptography`, Schnorr vs libsecp256k1, envelopes both ways with the C code, config parsing,
* per-peer access rules against crafted IPv4 packets (ports, CIDRs, ICMP, IP options, fragments,
  malformed headers, IPv6) and the rule parser's error handling,
* NAT-PMP packets and UPnP-IGD parsing with fixtures from real routers (miniupnpd, FRITZ!Box-style,
  chunked HTTP, hostile descriptions),
* **end-to-end rendezvous** for both the Python and the browser client: real client code ↔ a local
  Nostr relay that verifies signatures ↔ a simulated device whose crypto runs through the
  firmware's C code.

## Why Nostr + WireGuard and not WebRTC?

WebRTC would need ICE, DTLS and SCTP on the microcontroller, and a browser data channel still
can't carry IP packets for your OS. WireGuard already gives authenticated, encrypted, roaming
UDP. The only missing piece was swapping endpoints, and a 300-byte encrypted message over a
public Nostr relay covers that with no server of your own.

Possible next steps: a TURN-style relay fallback for symmetric NAT, per-peer port ACLs, HTTPS
for the admin UI, a QR code in the browser client for laptop→phone transfer, IPv6 endpoints.
