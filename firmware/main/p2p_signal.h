// Serverless rendezvous over public Nostr relays.
//
// Clients publish an end-to-end encrypted "knock" (their public ip:port) addressed to the
// device's Nostr key. The device authenticates it with the client's WireGuard key, points
// the WireGuard peer at that endpoint (hole punch) and answers with an encrypted "ack"
// carrying its own public ip:port. Relays only ever see ciphertext. See docs/PROTOCOL.md.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

esp_err_t p2p_signal_start(void);

// Device Nostr public key (x-only, lowercase hex) for client configs.
const char *p2p_signal_npub_hex(void);

// Writes a JSON array [{"url":..,"connected":bool},..] into out. Returns false if truncated.
bool p2p_signal_relays_json(char *out, size_t len);
