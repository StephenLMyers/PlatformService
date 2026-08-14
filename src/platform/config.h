/*
 * Configuration: defaults -> file -> environment, in that order.
 *
 * Two rules are enforced by the loader rather than left to discipline:
 *   1. Secrets can only arrive from the environment. A config file that tries
 *      to set one is a hard startup failure, because config files get
 *      committed and a secret in git history is permanent (plan R14).
 *   2. Secrets are never printed. Redaction is a property of the setting
 *      table, not of each call site that happens to print something.
 */
#ifndef PS_PLATFORM_CONFIG_H
#define PS_PLATFORM_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "platform/log.h"

#define PS_STR_MAX         256
#define PS_PATH_MAX        512
#define PS_SECRET_MAX      512

/* Minimum HS256 key length. Shorter keys weaken the signature (plan 6.1). */
#define PS_JWT_SECRET_MIN  32

typedef struct {
    /* ---- server ---- */
    char     bind_address[PS_STR_MAX];
    uint16_t port;
    bool     dev_mode;
    int      worker_threads;          /* 0 = one per CPU */
    int      accept_queue_depth;
    int      shutdown_grace_s;

    /* ---- http limits (plan 7.2) ---- */
    int      max_request_line_bytes;
    int      max_header_bytes;
    int      max_header_count;
    int      max_body_bytes;
    int      read_timeout_s;
    int      write_timeout_s;
    int      keepalive_idle_timeout_s;
    int      keepalive_max_requests;

    /* ---- tls (plan 7.1) ---- */
    bool     tls_enabled;
    char     tls_cert_path[PS_PATH_MAX];
    char     tls_key_path[PS_PATH_MAX];

    /* ---- database ---- */
    char     db_path[PS_PATH_MAX];
    int      db_busy_timeout_ms;

    /* ---- auth ---- */
    int      access_token_ttl_s;
    int      refresh_idle_ttl_s;
    int      refresh_absolute_ttl_s;
    int      verification_ttl_s;
    int      kdf_iterations;
    int      lockout_threshold;
    int      lockout_duration_s;
    int      password_min_length;
    int      password_max_length;
    char     jwt_issuer[PS_STR_MAX];
    char     jwt_audience[PS_STR_MAX];
    char     jwt_secret[PS_SECRET_MAX];          /* env only */

    /* ---- bootstrap admin (plan 6.7) -- env only ---- */
    char     bootstrap_admin_username[PS_STR_MAX];
    char     bootstrap_admin_email[PS_STR_MAX];
    char     bootstrap_admin_password[PS_SECRET_MAX];

    /* ---- maintenance (plan 3.4) ---- */
    int      maintenance_interval_s;
    int      maintenance_batch_size;
    int      audit_retention_days;

    /* ---- rate limiting (plan 3.5) ---- */
    int      ratelimit_max_entries;
    int      ratelimit_login_per_minute;
    int      ratelimit_register_per_minute;
    int      resend_min_interval_s;
    int      resend_max_per_day;

    /* ---- misc ---- */
    char           common_passwords_path[PS_PATH_MAX];
    ps_log_level_t log_level;
} ps_config_t;

/*
 * Populate cfg. config_path may be NULL, in which case only defaults and the
 * environment apply -- a missing config file is not an error, because every
 * setting has a working default (plan 15.1).
 *
 * On failure returns false and writes a human-readable reason into err.
 * cfg is always safe to pass to ps_config_free() afterwards.
 */
bool ps_config_load(ps_config_t *cfg, const char *config_path,
                    char *err, size_t errlen);

/* Zeroes secret material. Always safe to call. */
void ps_config_free(ps_config_t *cfg);

/* Print effective configuration with every secret redacted. */
void ps_config_print(const ps_config_t *cfg);

/* Validate an already-populated config. Same error contract as load. */
bool ps_config_validate(const ps_config_t *cfg, char *err, size_t errlen);

#endif /* PS_PLATFORM_CONFIG_H */
