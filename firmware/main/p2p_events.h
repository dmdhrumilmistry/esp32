// Small in-RAM security event log (logins, knocks, peer changes, expiries) shown in the web UI.
#pragma once

#include "cJSON.h"

void p2p_events_init(void);

// printf-style; also written to the serial log. Safe from any task (not from ISRs).
void p2p_event(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// JSON array, newest first: [{"t": unix_seconds_or_0, "up": uptime_seconds, "m": "text"}, ...]
cJSON *p2p_events_json(void);
