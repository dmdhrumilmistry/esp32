# p2ptun: serverless WireGuard access to your LAN through an ESP32

Plug an ESP32 into a network you own and reach that LAN from anywhere over a **direct,
peer-to-peer WireGuard tunnel**. You don't run a server, open router ports or hold a cloud
account. A small **web UI on the device** controls who may connect, and can cut off any active
connection instantly.

```
  laptop / phone                 public Nostr relays                 ESP32 at home / lab
 ┌──────────────┐   encrypted    ┌───────────────┐   encrypted     ┌──────────────────┐
 │ p2ptun.py    │──"knock"──────►│ dumb mailbox  │───────────────► │ web UI: allow /  │
 │ (WireGuard)  │◄──────"ack"────│ (sees only    │◄────────────────│ block / delete   │
 └──────┬───────┘                │  ciphertext)  │                 │ WireGuard + NAPT │──► 192.168.1.0/24
        │                        └───────────────┘                 └────────┬─────────┘
        └═══════════ WireGuard, direct UDP (NAT hole punching) ═════════════┘
```

* **Tunnel:** WireGuard (Noise IK, ChaCha20-Poly1305), up to 8 authorized clients. Traffic is
  source-NATed onto the ESP32's LAN, so LAN devices need no configuration.
* **Rendezvous without a server:** both sides learn their public `ip:port` via STUN, then swap it
  through public **Nostr relays**, end-to-end encrypted with keys derived from the WireGuard keys.
  Relays never see tunnel traffic, keys or plaintext endpoints. See [docs/PROTOCOL.md](docs/PROTOCOL.md).
* **Web UI** (served by the ESP32): authorize a client by pasting its public key, see who is
  connected (endpoint, last seen), **Block** (cuts the live session and refuses reconnects) or
  **Delete** a peer, change the admin password and relays.

## Security model

| Threat | Mitigation |
|---|---|
| Someone on the internet connects | Only WireGuard keys authorized in the UI can complete a handshake. The device never answers knocks it can't decrypt with an enabled peer's key. |
| Relay operator snoops or tampers | Signaling is ChaCha20-Poly1305 with an X25519-derived key, so the relay only sees ciphertext. Clients use a fresh Nostr identity per knock. |
| Replayed knock | Per-peer strictly increasing timestamps with ±120 s skew (the device syncs SNTP), plus a nonce echoed in the ack. |
| Revoked client keeps its tunnel | Block/Delete removes the peer from WireGuard and zeroes its session keys immediately. |
| Web UI attacks | PBKDF2-SHA256 password hash, 5-try lockout, random 256-bit `HttpOnly; SameSite=Strict` session cookie, JSON-only POST (CSRF), strict CSP, `X-Frame-Options: DENY`, no external resources, all output via `textContent`. |
| Unconfigured device hijacked | The setup AP is WPA2 with a random password that is shown only on the serial console. |
| Weak keys at first boot | Keys are generated with the bootloader entropy source enabled (the ESP32 RNG is only a true RNG while RF or that source is on). |
| Device stolen | Enable **Secure Boot v2 + Flash Encryption + NVS encryption** for production (lines in `firmware/sdkconfig.defaults`). Hold BOOT for 5 s while it runs to wipe all keys and settings. |

**Use it only on networks you own or are authorized to access.** A device like this is a bridge
into the LAN it sits on.

Known limits, by design (keeping it simple):
* No relay fallback. If **both** sides are behind symmetric / carrier-grade NAT, hole punching
  fails. One cone-NAT side (most home routers) is enough.
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

### 3. Authorize a client

On the client (Linux, macOS or Windows with Python 3.9+):

```bash
cd client
pip install -r requirements.txt
python3 p2ptun.py genkey            # prints this client's WireGuard public key
```

In the web UI, go to **Authorize a client**, enter a name and the public key, and press **Authorize**.
The UI shows a one-line command; run it on the client:

```bash
python3 p2ptun.py join '{"name":"laptop","address":"10.77.0.2/32","device":{...},"relays":[...]}'
```

### 4. Connect

```bash
sudo python3 p2ptun.py up           # Linux: needs wireguard-tools + iproute2
# [p2ptun] my public endpoint 203.0.113.9:40001 (LAN 10.0.0.5:51821)
# [p2ptun] device answered: 198.51.100.20:51820 → using 198.51.100.20:51820
# [p2ptun] p2ptun0 up: 10.77.0.2/32 → device 10.77.0.1, routes 10.77.0.1/32, 192.168.1.0/24
# [p2ptun] connected ✔  try: ping 10.77.0.1
ssh pi@192.168.1.20                 # any host on the ESP32's LAN
```

On macOS or Windows, `python3 p2ptun.py resolve` does the same rendezvous and prints a `wg-quick`
config to import into the official WireGuard app right away (keep the printed `ListenPort`).

If the client's own LAN uses the same subnet as the device's LAN (both `192.168.1.0/24`, for example), the routes clash.
Connect from another network or renumber one side.

## Repository layout

```
firmware/                      ESP-IDF project
  main/p2p_tunnel.c            WireGuard netif, NAPT to LAN, STUN on the WireGuard socket
  main/p2p_signal.c            Nostr relay client, knock/ack handling, replay protection
  main/p2p_crypto.c            BIP-340 Schnorr, Nostr events, signaling envelope (portable, host-tested)
  main/p2p_stun.c              STUN Binding client (portable, host-tested)
  main/p2p_web.c, www/         web UI + JSON API
  main/p2p_auth.c              password hashing, sessions, lockout
  components/esp_wireguard/    vendored trombik/esp_wireguard (BSD-3) + small patch, see PATCHES.md
client/p2ptun.py               CLI client (genkey / join / up / resolve)
docs/PROTOCOL.md               wire protocol and design
tests/                         C-vs-Python-vs-libsecp256k1 interop + end-to-end rendezvous tests
```

## Tests

```bash
sudo apt install libmbedtls-dev
pip install -r client/requirements.txt -r tests/requirements.txt
make -C tests/host && python3 -m unittest discover -s tests -v
```

The firmware's crypto and STUN code is compiled for the host and checked against:
* official BIP-340 test vectors, plus byte-for-byte equality with **libsecp256k1** on random inputs,
* the Python client (envelope both directions, tamper and wrong-key rejection, STUN parsing),
* an **end-to-end rendezvous**: real client code ↔ a local Nostr relay that verifies signatures ↔ a
  simulated device whose crypto runs through the firmware's C code.

## Why Nostr + WireGuard and not WebRTC?

WebRTC would need ICE, DTLS and SCTP on the microcontroller, and a browser data channel still
can't carry IP packets for your OS. WireGuard already gives authenticated, encrypted, roaming
UDP. The only missing piece was swapping endpoints, and a 300-byte encrypted message over a
public Nostr relay covers that with no server of your own.

Possible next steps: a TURN-style relay fallback for symmetric NAT, per-peer port ACLs, HTTPS
for the admin UI, a browser-only client via a WebRTC↔WireGuard bridge.
