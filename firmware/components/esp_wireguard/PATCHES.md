# Local changes to the vendored esp_wireguard

Upstream: https://github.com/trombik/esp_wireguard @ `9217c5be0836e908005301ad2c2d42009e560c0e` (BSD-3-Clause).

1. Dropped `src/esp_wireguard.c` / `include/esp_wireguard.h` (single-peer wrapper). p2ptun uses the
   multi-peer `wireguardif_*` API directly, so `src/` is now the public include dir.
2. `wireguardif.c` / `wireguardif.h`, marked `p2ptun patch`:
   - `wireguardif_set_raw_rx_hook()`: the app sees each datagram on the WireGuard port first and can
     consume it. p2ptun uses this to receive STUN responses on the **same** UDP socket as WireGuard,
     so the public `ip:port` that STUN reports is the NAT mapping WireGuard actually uses (required for
     hole punching).
   - `wireguardif_send_raw()`: send a datagram (a STUN request) from the WireGuard socket.
   - `wireguardif_get_peer_stats()`: per-peer endpoint, last rx/tx and session state for the web UI.
