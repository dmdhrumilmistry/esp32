#include "p2p_acl.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool fail(char *err, size_t len, const char *tok, const char *why)
{
    if (err && len) {
        snprintf(err, len, "rule \"%.24s\": %s", tok, why);
    }
    return false;
}

static bool parse_u(const char *s, const char *end, unsigned long max, unsigned long *out)
{
    if (s == end || end - s > 5) {
        return false;
    }
    unsigned long v = 0;
    for (const char *p = s; p < end; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
        v = v * 10 + (unsigned long)(*p - '0');
    }
    if (v > max) {
        return false;
    }
    *out = v;
    return true;
}

static bool parse_ipv4(const char *s, const char *end, uint32_t *out)
{
    uint32_t ip = 0;
    for (int i = 0; i < 4; i++) {
        const char *dot = s;
        while (dot < end && *dot != '.') dot++;
        if ((i < 3) != (dot < end)) {
            return false;
        }
        unsigned long oct;
        if (!parse_u(s, dot, 255, &oct) || dot - s > 3) {
            return false;
        }
        ip = (ip << 8) | (uint32_t)oct;
        s = dot + 1;
    }
    *out = ip;
    return true;
}

static bool parse_rule(char *tok, p2p_acl_rule_t *r, bool *any, char *err, size_t err_len)
{
    memset(r, 0, sizeof(*r));
    for (char *p = tok; *p; p++) {
        *p = (char)tolower((unsigned char)*p);
    }
    if (!strcmp(tok, "any") || !strcmp(tok, "all")) {
        *any = true;
        return true;
    }
    char *s = tok;
    if (!strncmp(s, "tcp:", 4)) { r->proto = 6; s += 4; }
    else if (!strncmp(s, "udp:", 4)) { r->proto = 17; s += 4; }
    else if (!strncmp(s, "icmp:", 5)) { r->proto = 1; s += 5; }

    char *colon = strchr(s, ':');
    char *tend = colon ? colon : s + strlen(s);

    if ((size_t)(tend - s) == 3 && !strncmp(s, "lan", 3)) {
        r->kind = P2P_ACL_KIND_LAN;
    } else if ((size_t)(tend - s) == 6 && !strncmp(s, "device", 6)) {
        r->kind = P2P_ACL_KIND_DEVICE;
    } else {
        r->kind = P2P_ACL_KIND_ADDR;
        char *slash = memchr(s, '/', (size_t)(tend - s));
        unsigned long prefix = 32;
        if (!parse_ipv4(s, slash ? slash : tend, &r->net)) {
            return fail(err, err_len, tok, "expected lan, device, any or an IPv4 address[/prefix]");
        }
        if (slash && !parse_u(slash + 1, tend, 32, &prefix)) {
            return fail(err, err_len, tok, "prefix must be 0-32");
        }
        r->mask = prefix ? 0xFFFFFFFFu << (32 - prefix) : 0;
        r->net &= r->mask;
    }

    if (colon) {
        if (r->proto == 1) {
            return fail(err, err_len, tok, "icmp has no ports");
        }
        char *dash = strchr(colon + 1, '-');
        unsigned long lo, hi;
        if (!parse_u(colon + 1, dash ? dash : colon + 1 + strlen(colon + 1), 65535, &lo) || lo == 0) {
            return fail(err, err_len, tok, "port must be 1-65535");
        }
        hi = lo;
        if (dash && (!parse_u(dash + 1, dash + 1 + strlen(dash + 1), 65535, &hi) || hi < lo)) {
            return fail(err, err_len, tok, "port range must be low-high within 1-65535");
        }
        r->pmin = (uint16_t)lo;
        r->pmax = (uint16_t)hi;
    }
    return true;
}

bool p2p_acl_parse(const char *text, p2p_acl_t *out, char *err, size_t err_len)
{
    memset(out, 0, sizeof(*out));
    if (err && err_len) {
        err[0] = '\0';
    }
    if (!text) {
        out->all = true;
        return true;
    }
    if (strlen(text) >= P2P_ACL_TEXT_LEN) {
        if (err && err_len) snprintf(err, err_len, "rules too long (max %d characters)", P2P_ACL_TEXT_LEN - 1);
        return false;
    }
    char buf[P2P_ACL_TEXT_LEN];
    strcpy(buf, text);
    bool any = false, seen = false;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",\n\r", &save); tok; tok = strtok_r(NULL, ",\n\r", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *e = tok + strlen(tok);
        while (e > tok && (e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';
        if (!*tok) {
            continue;
        }
        if (strpbrk(tok, " \t")) {
            return fail(err, err_len, tok, "unexpected space (separate rules with commas)");
        }
        seen = true;
        if (out->n >= P2P_ACL_MAX_RULES) {
            if (err && err_len) snprintf(err, err_len, "too many rules (max %d)", P2P_ACL_MAX_RULES);
            return false;
        }
        if (!parse_rule(tok, &out->rules[out->n], &any, err, err_len)) {
            return false;
        }
        if (!any) {
            out->n++;
        }
    }
    if (any || !seen) {
        out->all = true;
        out->n = 0;
    }
    return true;
}

bool p2p_acl_allows(const p2p_acl_t *acl, const p2p_acl_env_t *env, const uint8_t *pkt, size_t len)
{
    if (acl->all) {
        return true;
    }
    if (len < 20 || (pkt[0] >> 4) != 4) {
        return false; // only IPv4 is routed by p2ptun
    }
    size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > len) {
        return false;
    }
    uint8_t proto = pkt[9];
    uint32_t dst = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) | ((uint32_t)pkt[18] << 8) | pkt[19];
    bool first_fragment = (((pkt[6] & 0x1F) << 8) | pkt[7]) == 0;
    bool have_port = false;
    uint16_t dport = 0;
    if ((proto == 6 || proto == 17) && first_fragment && len >= ihl + 4) {
        dport = (uint16_t)((pkt[ihl + 2] << 8) | pkt[ihl + 3]);
        have_port = true;
    }

    bool to_device = dst == env->dev_ip || (env->dev_lan_ip && dst == env->dev_lan_ip);
    for (uint8_t i = 0; i < acl->n; i++) {
        const p2p_acl_rule_t *r = &acl->rules[i];
        if (r->proto && r->proto != proto) {
            continue;
        }
        bool addr_ok;
        if (r->kind == P2P_ACL_KIND_DEVICE) {
            addr_ok = to_device;
        } else if (to_device) {
            addr_ok = false; // the device (admin UI) is reachable only via an explicit "device" rule
        } else if (r->kind == P2P_ACL_KIND_LAN) {
            addr_ok = env->lan_mask != 0 && (dst & env->lan_mask) == (env->lan_net & env->lan_mask);
        } else {
            addr_ok = (dst & r->mask) == r->net;
        }
        if (!addr_ok) {
            continue;
        }
        if (r->pmin) {
            // Port rules only match TCP/UDP packets whose port we can see (non-first
            // fragments carry no port and are dropped; p2ptun's MTU avoids fragmenting).
            if (!have_port || dport < r->pmin || dport > r->pmax) {
                continue;
            }
        }
        return true;
    }
    return false;
}
