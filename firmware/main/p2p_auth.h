// Admin password (PBKDF2-HMAC-SHA256) and session tokens for the web UI.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define P2P_TOKEN_HEX_LEN 64

esp_err_t p2p_auth_set_password(const char *password); // hashes + stores, invalidates sessions
// Returns true if correct. Applies a lockout after repeated failures (*locked_s = seconds left).
bool p2p_auth_check_password(const char *password, int *locked_s);

bool p2p_auth_new_session(char token[P2P_TOKEN_HEX_LEN + 1]);
bool p2p_auth_session_valid(const char *token); // also refreshes idle timeout
void p2p_auth_end_session(const char *token);
void p2p_auth_end_all_sessions(void);
