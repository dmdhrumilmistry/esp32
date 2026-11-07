// Small in-RAM security event log (logins, knocks, peer changes, expiries) shown in the web UI.
#pragma once

#include "cJSON.h"

void p2p_events_init(void);

// printf-style; also written to the serial log. Safe from any task (not from ISRs).
// Admin/security events (logins, peer changes, expiries, pairing).
void p2p_event(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
// Remote traffic (knocks). Kept in a separate ring so it can never evict security events.
void p2p_event_traffic(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// JSON array, newest first, both rings merged: [{"t": unix_or_0, "up": uptime_s, "m": "text", "k": "sec"|"net"}]
cJSON *p2p_events_json(void);
