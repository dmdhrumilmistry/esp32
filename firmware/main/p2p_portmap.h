// Makes the device directly reachable so that *any* WireGuard client can connect, including
// phones on carrier NAT where hole punching fails: asks the home router to forward the
// WireGuard UDP port (NAT-PMP, then UPnP-IGD) and keeps the mapping renewed.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

esp_err_t p2p_portmap_start(void);

// Best endpoint to hand to clients, in order of preference:
//   "manual" (admin-configured host:port), "upnp"/"natpmp" (verified router mapping), "stun".
// Returns false if nothing is known yet. *via is set to one of the strings above.
bool p2p_reach_endpoint(char *out, size_t len, const char **via);

// Human-readable reachability status for the web UI.
void p2p_portmap_status(char *out, size_t len);
