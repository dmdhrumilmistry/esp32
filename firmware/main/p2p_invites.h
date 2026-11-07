// One-scan pairing: single-use, short-lived invites (RAM only). See docs/PROTOCOL.md "Pairing".
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

#define P2P_INVITE_TTL_S (15 * 60)

// Create an invite. Returns its id (>0) or 0 on failure; writes the base64url-encoded
// secret (no padding) to secret_b64u. acl/expires describe the peer that pairing will create.
int p2p_invite_create(const char *name, const char *acl, uint32_t expires, char secret_b64u[24]);
bool p2p_invite_revoke(int id);

// [{"id","name","state":"pending|used|expired|revoked","expires_in_s","peer"}], newest first. No secrets.
cJSON *p2p_invites_json(void);

// Try to handle an incoming Nostr event content as a pairing request. Returns true if it opened
// with an invite key (handled, reply written to reply_content, a sealed envelope, possibly empty
// if no reply should be sent).
bool p2p_invite_handle(const char *content, char *reply_content, size_t reply_size);
