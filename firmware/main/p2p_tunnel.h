// WireGuard interface, LAN forwarding (NAPT) and STUN on the WireGuard port.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

typedef struct {
    bool loaded;        // present in WireGuard (enabled)
    bool up;            // has a live session
    char endpoint[24];  // last seen ip:port, "" if none
    int32_t last_rx_s;  // seconds since last packet from peer, -1 = never
} p2p_peer_status_t;

// Call once the Wi-Fi station has an IP address.
esp_err_t p2p_tunnel_start(void);

// Apply the configured peer table: add enabled peers, remove disabled/deleted ones.
// Removing a peer destroys its session immediately (active connection is cut).
void p2p_tunnel_sync_peers(void);

// Point a peer at a freshly learned public endpoint and start handshaking (hole punch).
esp_err_t p2p_tunnel_set_endpoint(const uint8_t pub[32], const uint8_t ip[4], uint16_t port);

void p2p_tunnel_peer_status(const uint8_t pub[32], p2p_peer_status_t *out);

// Public ip:port of the WireGuard socket as seen by STUN. False if unknown.
bool p2p_tunnel_public_endpoint(char *out, size_t len);
// LAN ip:port of the WireGuard socket (for clients behind the same NAT).
bool p2p_tunnel_lan_endpoint(char *out, size_t len);
// LAN subnet in CIDR form, e.g. "192.168.1.0/24".
bool p2p_tunnel_lan_subnet(char *out, size_t len);
// Tunnel address of a peer host number, e.g. "10.77.0.2".
void p2p_tunnel_peer_ip(uint8_t host, char *out, size_t len);
