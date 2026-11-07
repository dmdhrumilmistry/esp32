#include "p2p_auth.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "mbedtls/version.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"

#include "p2p_config.h"
#include "p2p_crypto.h"

#define PBKDF2_ITERATIONS 10000
#define MAX_SESSIONS 4
#define SESSION_IDLE_US (30LL * 60 * 1000000)
#define MAX_FAILS 5
#define LOCKOUT_US (60LL * 1000000)

typedef struct {
    uint8_t token[32];
    int64_t expires;
} session_t;

static session_t s_sessions[MAX_SESSIONS];
static int s_fails;
static int64_t s_locked_until;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

static int pbkdf2(const char *password, const uint8_t salt[16], uint8_t out[32])
{
#if MBEDTLS_VERSION_MAJOR >= 3
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)password, strlen(password),
                                         salt, 16, PBKDF2_ITERATIONS, 32, out);
#else
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret == 0) {
        ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const unsigned char *)password, strlen(password), salt, 16,
                                        PBKDF2_ITERATIONS, 32, out);
    }
    mbedtls_md_free(&ctx);
    return ret;
#endif
}

static bool ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) {
        d |= a[i] ^ b[i];
    }
    return d == 0;
}

esp_err_t p2p_auth_set_password(const char *password)
{
    uint8_t salt[16], hash[32];
    if (p2p_random(salt, sizeof(salt)) != 0 || pbkdf2(password, salt, hash) != 0) {
        return ESP_FAIL;
    }
    esp_err_t err = p2p_config_save_admin(salt, hash);
    mbedtls_platform_zeroize(hash, sizeof(hash));
    p2p_auth_end_all_sessions();
    return err;
}

bool p2p_auth_check_password(const char *password, int *locked_s)
{
    int64_t now = esp_timer_get_time();
    *locked_s = 0;
    if (now < s_locked_until) {
        *locked_s = (int)((s_locked_until - now) / 1000000) + 1;
        return false;
    }
    p2p_config_t *cfg = p2p_config();
    uint8_t hash[32];
    bool ok = cfg->admin_set && pbkdf2(password, cfg->admin_salt, hash) == 0 && ct_equal(hash, cfg->admin_hash, 32);
    mbedtls_platform_zeroize(hash, sizeof(hash));
    if (ok) {
        s_fails = 0;
    } else if (++s_fails >= MAX_FAILS) {
        s_fails = 0;
        s_locked_until = now + LOCKOUT_US;
        *locked_s = (int)(LOCKOUT_US / 1000000);
    }
    return ok;
}

bool p2p_auth_new_session(char token[P2P_TOKEN_HEX_LEN + 1])
{
    uint8_t t[32];
    if (p2p_random(t, sizeof(t)) != 0) {
        return false;
    }
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_mux);
    int slot = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (s_sessions[i].expires < s_sessions[slot].expires) {
            slot = i; // reuse expired/oldest
        }
    }
    memcpy(s_sessions[slot].token, t, 32);
    s_sessions[slot].expires = now + SESSION_IDLE_US;
    portEXIT_CRITICAL(&s_mux);
    p2p_hex_encode(t, 32, token);
    mbedtls_platform_zeroize(t, sizeof(t));
    return true;
}

static int find_session(const char *token, int64_t now)
{
    uint8_t t[32];
    if (!token || !p2p_hex_decode(token, t, 32)) {
        return -1;
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (s_sessions[i].expires > now && ct_equal(s_sessions[i].token, t, 32)) {
            return i;
        }
    }
    return -1;
}

bool p2p_auth_session_valid(const char *token)
{
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_mux);
    int i = find_session(token, now);
    if (i >= 0) {
        s_sessions[i].expires = now + SESSION_IDLE_US;
    }
    portEXIT_CRITICAL(&s_mux);
    return i >= 0;
}

void p2p_auth_end_session(const char *token)
{
    portENTER_CRITICAL(&s_mux);
    int i = find_session(token, esp_timer_get_time());
    if (i >= 0) {
        memset(&s_sessions[i], 0, sizeof(s_sessions[i]));
    }
    portEXIT_CRITICAL(&s_mux);
}

void p2p_auth_end_all_sessions(void)
{
    portENTER_CRITICAL(&s_mux);
    memset(s_sessions, 0, sizeof(s_sessions));
    portEXIT_CRITICAL(&s_mux);
}
