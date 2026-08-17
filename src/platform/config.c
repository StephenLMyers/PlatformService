#include "platform/config.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */

#include <openssl/crypto.h>

/* ------------------------------------------------------------------------- */
/* Setting table                                                              */
/*                                                                            */
/* One row per setting. Everything else -- defaults, file parsing, env        */
/* overrides, redaction, and the secrets-must-not-come-from-file rule -- is   */
/* driven from this table, so adding a setting cannot accidentally skip one   */
/* of those behaviours.                                                       */
/* ------------------------------------------------------------------------- */

typedef enum {
    T_STR,
    T_PATH,
    T_INT,
    T_U16,
    T_BOOL,
    T_LOGLEVEL
} ps_type_t;

typedef struct {
    const char *key;          /* config-file key                     */
    const char *env;          /* environment variable, NULL if none  */
    ps_type_t   type;
    size_t      offset;       /* offsetof into ps_config_t           */
    size_t      size;         /* capacity for string fields          */
    const char *dflt;
    bool        secret;       /* redact when printing                */
    bool        env_only;     /* refuse if it appears in a file      */
} ps_setting_t;

#define FIELD(f) offsetof(ps_config_t, f), sizeof (((ps_config_t *)0)->f)

static const ps_setting_t SETTINGS[] = {
    /* key                          env                          type        field                        default              secret env_only */
    { "server.bind_address",        "PS_BIND_ADDRESS",           T_STR,      FIELD(bind_address),         "127.0.0.1",         false, false },
    { "server.port",                "PS_PORT",                   T_U16,      FIELD(port),                 "8443",              false, false },
    { "server.dev_mode",            "PS_DEV_MODE",               T_BOOL,     FIELD(dev_mode),             "false",             false, false },
    { "server.worker_threads",      "PS_WORKER_THREADS",         T_INT,      FIELD(worker_threads),       "0",                 false, false },
    { "server.accept_queue_depth",  "PS_ACCEPT_QUEUE_DEPTH",     T_INT,      FIELD(accept_queue_depth),   "256",               false, false },
    { "server.shutdown_grace_s",    "PS_SHUTDOWN_GRACE_S",       T_INT,      FIELD(shutdown_grace_s),     "30",                false, false },

    { "http.max_request_line",      "PS_MAX_REQUEST_LINE",       T_INT,      FIELD(max_request_line_bytes),   "8192",          false, false },
    { "http.max_header_bytes",      "PS_MAX_HEADER_BYTES",       T_INT,      FIELD(max_header_bytes),         "16384",         false, false },
    { "http.max_header_count",      "PS_MAX_HEADER_COUNT",       T_INT,      FIELD(max_header_count),         "64",            false, false },
    { "http.max_body_bytes",        "PS_MAX_BODY_BYTES",         T_INT,      FIELD(max_body_bytes),           "1048576",       false, false },
    { "http.read_timeout_s",        "PS_READ_TIMEOUT_S",         T_INT,      FIELD(read_timeout_s),           "30",            false, false },
    { "http.write_timeout_s",       "PS_WRITE_TIMEOUT_S",        T_INT,      FIELD(write_timeout_s),          "30",            false, false },
    { "http.keepalive_idle_s",      "PS_KEEPALIVE_IDLE_S",       T_INT,      FIELD(keepalive_idle_timeout_s), "15",            false, false },
    { "http.keepalive_max_requests","PS_KEEPALIVE_MAX_REQUESTS", T_INT,      FIELD(keepalive_max_requests),   "100",           false, false },

    { "cors.allowed_origins",       "PS_CORS_ALLOWED_ORIGINS",   T_STR,      FIELD(cors_allowed_origins),     "",              false, false },
    { "cors.allow_credentials",     "PS_CORS_ALLOW_CREDENTIALS", T_BOOL,     FIELD(cors_allow_credentials),   "false",         false, false },

    { "tls.enabled",                "PS_TLS_ENABLED",            T_BOOL,     FIELD(tls_enabled),          "true",              false, false },
    { "tls.cert_path",              "PS_TLS_CERT_PATH",          T_PATH,     FIELD(tls_cert_path),        "./certs/dev-cert.pem", false, false },
    { "tls.key_path",               "PS_TLS_KEY_PATH",           T_PATH,     FIELD(tls_key_path),         "./certs/dev-key.pem",  false, false },

    { "db.path",                    "PS_DB_PATH",                T_PATH,     FIELD(db_path),              "./data/platform.db",false, false },
    { "db.busy_timeout_ms",         "PS_DB_BUSY_TIMEOUT_MS",     T_INT,      FIELD(db_busy_timeout_ms),   "5000",              false, false },

    { "auth.access_token_ttl_s",    "PS_ACCESS_TOKEN_TTL_S",     T_INT,      FIELD(access_token_ttl_s),   "900",               false, false },
    { "auth.refresh_idle_ttl_s",    "PS_REFRESH_IDLE_TTL_S",     T_INT,      FIELD(refresh_idle_ttl_s),   "2592000",           false, false },
    { "auth.refresh_absolute_ttl_s","PS_REFRESH_ABSOLUTE_TTL_S", T_INT,      FIELD(refresh_absolute_ttl_s), "7776000",         false, false },
    { "auth.verification_ttl_s",    "PS_VERIFICATION_TTL_S",     T_INT,      FIELD(verification_ttl_s),   "86400",             false, false },
    { "auth.kdf_iterations",        "PS_KDF_ITERATIONS",         T_INT,      FIELD(kdf_iterations),       "600000",            false, false },
    { "auth.lockout_threshold",     "PS_LOCKOUT_THRESHOLD",      T_INT,      FIELD(lockout_threshold),    "10",                false, false },
    { "auth.lockout_duration_s",    "PS_LOCKOUT_DURATION_S",     T_INT,      FIELD(lockout_duration_s),   "900",               false, false },
    { "auth.password_min_length",   "PS_PASSWORD_MIN_LENGTH",    T_INT,      FIELD(password_min_length),  "12",                false, false },
    { "auth.password_max_length",   "PS_PASSWORD_MAX_LENGTH",    T_INT,      FIELD(password_max_length),  "128",               false, false },
    { "auth.jwt_issuer",            "PS_JWT_ISSUER",             T_STR,      FIELD(jwt_issuer),           "platformservice",   false, false },
    { "auth.jwt_audience",          "PS_JWT_AUDIENCE",           T_STR,      FIELD(jwt_audience),         "platformservice-api", false, false },
    { "auth.jwt_secret",             "PS_JWT_SECRET",             T_STR,      FIELD(jwt_secret),           "",                  true,  true  },

    { "bootstrap.admin_username", "BOOTSTRAP_ADMIN_USERNAME", T_STR, FIELD(bootstrap_admin_username), "",                      false, true },
    { "bootstrap.admin_email",    "BOOTSTRAP_ADMIN_EMAIL",    T_STR, FIELD(bootstrap_admin_email),    "",                      false, true },
    { "bootstrap.admin_password", "BOOTSTRAP_ADMIN_PASSWORD", T_STR, FIELD(bootstrap_admin_password), "",                      true,  true },

    { "maintenance.interval_s",     "PS_MAINTENANCE_INTERVAL_S", T_INT,      FIELD(maintenance_interval_s), "3600",            false, false },
    { "maintenance.batch_size",     "PS_MAINTENANCE_BATCH_SIZE", T_INT,      FIELD(maintenance_batch_size), "1000",            false, false },
    { "audit.retention_days",       "PS_AUDIT_RETENTION_DAYS",   T_INT,      FIELD(audit_retention_days), "365",               false, false },

    { "ratelimit.max_entries",      "PS_RATELIMIT_MAX_ENTRIES",  T_INT,      FIELD(ratelimit_max_entries),      "100000",      false, false },
    { "ratelimit.login_per_minute", "PS_RATELIMIT_LOGIN",        T_INT,      FIELD(ratelimit_login_per_minute), "10",          false, false },
    { "ratelimit.register_per_minute","PS_RATELIMIT_REGISTER",   T_INT,      FIELD(ratelimit_register_per_minute), "5",        false, false },
    { "ratelimit.resend_min_interval_s","PS_RESEND_MIN_INTERVAL_S", T_INT,   FIELD(resend_min_interval_s),      "60",          false, false },
    { "ratelimit.resend_max_per_day","PS_RESEND_MAX_PER_DAY",    T_INT,      FIELD(resend_max_per_day),         "5",           false, false },

    { "auth.common_passwords_path", "PS_COMMON_PASSWORDS_PATH",  T_PATH,     FIELD(common_passwords_path), "./data/common-passwords.txt", false, false },
    { "log.level",                  "PS_LOG_LEVEL",              T_LOGLEVEL, FIELD(log_level),            "INFO",              false, false },
};

#define SETTINGS_COUNT (sizeof SETTINGS / sizeof SETTINGS[0])

/* ------------------------------------------------------------------------- */
/* Value assignment                                                           */
/* ------------------------------------------------------------------------- */

static void *field_ptr(ps_config_t *cfg, const ps_setting_t *s)
{
    return (char *)cfg + s->offset;
}

static bool parse_bool(const char *v, bool *out)
{
    if (strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 ||
        strcmp(v, "1") == 0 || strcasecmp(v, "on") == 0) {
        *out = true;
        return true;
    }
    if (strcasecmp(v, "false") == 0 || strcasecmp(v, "no") == 0 ||
        strcmp(v, "0") == 0 || strcasecmp(v, "off") == 0) {
        *out = false;
        return true;
    }
    return false;
}

/*
 * strtol with the checks people habitually skip: errno for range, endptr for
 * trailing garbage, and an explicit empty-input rejection. The same discipline
 * the plan requires for userId (7.3) applies here.
 */
static bool parse_long(const char *v, long *out)
{
    if (v == NULL || *v == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    long  n   = strtol(v, &end, 10);
    if (errno == ERANGE || end == v || *end != '\0') {
        return false;
    }
    *out = n;
    return true;
}

static bool apply_value(ps_config_t *cfg, const ps_setting_t *s,
                        const char *value, char *err, size_t errlen)
{
    void *dst = field_ptr(cfg, s);
    const char *name = (s->key != NULL) ? s->key : s->env;

    switch (s->type) {
    case T_STR:
    case T_PATH: {
        size_t n = strlen(value);
        if (n >= s->size) {
            (void)snprintf(err, errlen, "%s: value too long (max %zu bytes)",
                           name, s->size - 1);
            return false;
        }
        memcpy(dst, value, n);
        ((char *)dst)[n] = '\0';
        return true;
    }
    case T_INT: {
        long n;
        if (!parse_long(value, &n) || n < INT_MIN || n > INT_MAX) {
            (void)snprintf(err, errlen, "%s: not a valid integer: '%s'", name, value);
            return false;
        }
        *(int *)dst = (int)n;
        return true;
    }
    case T_U16: {
        long n;
        if (!parse_long(value, &n) || n < 1 || n > 65535) {
            (void)snprintf(err, errlen, "%s: not a valid port (1-65535): '%s'",
                           name, value);
            return false;
        }
        *(uint16_t *)dst = (uint16_t)n;
        return true;
    }
    case T_BOOL: {
        bool b;
        if (!parse_bool(value, &b)) {
            (void)snprintf(err, errlen, "%s: not a boolean: '%s'", name, value);
            return false;
        }
        *(bool *)dst = b;
        return true;
    }
    case T_LOGLEVEL: {
        ps_log_level_t level;
        if (!ps_log_level_from_string(value, &level)) {
            (void)snprintf(err, errlen,
                           "%s: unknown level '%s' (TRACE|DEBUG|INFO|WARN|ERROR)",
                           name, value);
            return false;
        }
        *(ps_log_level_t *)dst = level;
        return true;
    }
    }

    (void)snprintf(err, errlen, "%s: internal error, unhandled type", name);
    return false;
}

/* ------------------------------------------------------------------------- */
/* File parsing                                                               */
/* ------------------------------------------------------------------------- */

static char *trim(char *s)
{
    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
    return s;
}

static const ps_setting_t *find_by_key(const char *key)
{
    for (size_t i = 0; i < SETTINGS_COUNT; i++) {
        if (SETTINGS[i].key != NULL && strcmp(SETTINGS[i].key, key) == 0) {
            return &SETTINGS[i];
        }
    }
    return NULL;
}

static bool load_file(ps_config_t *cfg, const char *path,
                      char *err, size_t errlen)
{
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        (void)snprintf(err, errlen, "cannot open config file '%s': %s",
                       path, strerror(errno));
        return false;
    }

    bool ok      = true;
    int  lineno  = 0;
    char line[1024];

    while (fgets(line, (int)sizeof line, f) != NULL) {
        lineno++;

        char *p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') {
            continue;
        }

        char *eq = strchr(p, '=');
        if (eq == NULL) {
            (void)snprintf(err, errlen, "%s:%d: expected key=value", path, lineno);
            ok = false;
            goto cleanup;
        }

        *eq = '\0';
        char *key   = trim(p);
        char *value = trim(eq + 1);

        const ps_setting_t *s = find_by_key(key);
        if (s == NULL) {
            /*
             * Unknown keys are fatal, not ignored. A silently-dropped typo in
             * a security setting is the worst possible outcome: the operator
             * believes a limit is in force and it is not.
             */
            (void)snprintf(err, errlen, "%s:%d: unknown setting '%s'",
                           path, lineno, key);
            ok = false;
            goto cleanup;
        }

        if (s->env_only) {
            (void)snprintf(err, errlen,
                           "%s:%d: '%s' must come from the environment, never a "
                           "config file (set %s instead)",
                           path, lineno, key, s->env);
            ok = false;
            goto cleanup;
        }

        if (!apply_value(cfg, s, value, err, errlen)) {
            ok = false;
            goto cleanup;
        }
    }

    if (ferror(f)) {
        (void)snprintf(err, errlen, "error reading '%s': %s", path, strerror(errno));
        ok = false;
    }

cleanup:
    (void)fclose(f);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Public interface                                                           */
/* ------------------------------------------------------------------------- */

bool ps_config_load(ps_config_t *cfg, const char *config_path,
                    char *err, size_t errlen)
{
    if (cfg == NULL || err == NULL || errlen == 0) {
        return false;
    }

    memset(cfg, 0, sizeof *cfg);

    /* 1. defaults */
    for (size_t i = 0; i < SETTINGS_COUNT; i++) {
        if (!apply_value(cfg, &SETTINGS[i], SETTINGS[i].dflt, err, errlen)) {
            return false;
        }
    }

    /* 2. file (optional) */
    if (config_path != NULL && !load_file(cfg, config_path, err, errlen)) {
        return false;
    }

    /* 3. environment -- highest precedence */
    for (size_t i = 0; i < SETTINGS_COUNT; i++) {
        if (SETTINGS[i].env == NULL) {
            continue;
        }
        const char *v = getenv(SETTINGS[i].env);
        if (v != NULL && *v != '\0' &&
            !apply_value(cfg, &SETTINGS[i], v, err, errlen)) {
            return false;
        }
    }

    return ps_config_validate(cfg, err, errlen);
}

/* True if the comma-separated origin list contains a bare "*" entry
 * (whitespace around each entry is tolerated, matching the file parser's
 * own trim behavior elsewhere in this file). */
static bool cors_origins_contains_wildcard(const char *csv)
{
    const char *p = csv;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        const char *start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        const char *end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        if (end - start == 1 && *start == '*') {
            return true;
        }
    }
    return false;
}

bool ps_config_validate(const ps_config_t *cfg, char *err, size_t errlen)
{
    if (cfg->jwt_secret[0] == '\0') {
        (void)snprintf(err, errlen,
                       "PS_JWT_SECRET is not set. Generate one with: "
                       "export PS_JWT_SECRET=\"$(openssl rand -base64 48)\"");
        return false;
    }
    if (strlen(cfg->jwt_secret) < PS_JWT_SECRET_MIN) {
        (void)snprintf(err, errlen,
                       "PS_JWT_SECRET is %zu bytes; minimum is %d",
                       strlen(cfg->jwt_secret), PS_JWT_SECRET_MIN);
        return false;
    }
    if (cfg->access_token_ttl_s <= 0) {
        (void)snprintf(err, errlen, "auth.access_token_ttl_s must be positive");
        return false;
    }
    if (cfg->refresh_absolute_ttl_s < cfg->refresh_idle_ttl_s) {
        (void)snprintf(err, errlen,
                       "auth.refresh_absolute_ttl_s (%d) must be >= "
                       "auth.refresh_idle_ttl_s (%d), otherwise the absolute "
                       "cap could never be reached",
                       cfg->refresh_absolute_ttl_s, cfg->refresh_idle_ttl_s);
        return false;
    }
    if (cfg->kdf_iterations < 1000) {
        (void)snprintf(err, errlen,
                       "auth.kdf_iterations is %d; refusing anything below 1000",
                       cfg->kdf_iterations);
        return false;
    }
    if (cfg->password_min_length < 8 ||
        cfg->password_max_length < cfg->password_min_length) {
        (void)snprintf(err, errlen,
                       "password length bounds are invalid (min=%d max=%d)",
                       cfg->password_min_length, cfg->password_max_length);
        return false;
    }
    if (cfg->lockout_threshold < 1) {
        (void)snprintf(err, errlen, "auth.lockout_threshold must be at least 1");
        return false;
    }
    if (cfg->maintenance_batch_size < 1) {
        (void)snprintf(err, errlen, "maintenance.batch_size must be at least 1");
        return false;
    }
    if (cfg->ratelimit_max_entries < 1) {
        (void)snprintf(err, errlen,
                       "ratelimit.max_entries must be at least 1; an unbounded "
                       "limiter is a memory-exhaustion vector (plan R18)");
        return false;
    }
    if (cfg->max_body_bytes < 1 || cfg->max_header_bytes < 1 ||
        cfg->max_request_line_bytes < 1 || cfg->max_header_count < 1) {
        (void)snprintf(err, errlen, "http limits must all be positive");
        return false;
    }
    if (cfg->cors_allow_credentials &&
        cors_origins_contains_wildcard(cfg->cors_allowed_origins)) {
        (void)snprintf(err, errlen,
                       "cors.allowed_origins contains '*' with cors.allow_credentials=true; "
                       "refusing to start (plan 7.2a) -- a wildcard origin combined with "
                       "credentials is a cross-origin credential leak, not merely discouraged");
        return false;
    }
    return true;
}

void ps_config_free(ps_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    /*
     * Wipe every field the table marks secret. OPENSSL_cleanse is used rather
     * than memset because the compiler is entitled to optimise away a memset
     * whose result is never read -- which is exactly this case.
     */
    for (size_t i = 0; i < SETTINGS_COUNT; i++) {
        if (SETTINGS[i].secret) {
            OPENSSL_cleanse((char *)cfg + SETTINGS[i].offset, SETTINGS[i].size);
        }
    }
}

void ps_config_print(const ps_config_t *cfg)
{
    PS_INFO("effective configuration:");
    for (size_t i = 0; i < SETTINGS_COUNT; i++) {
        const ps_setting_t *s = &SETTINGS[i];
        const char *name = (s->key != NULL) ? s->key : s->env;
        const void *src  = (const char *)cfg + s->offset;

        if (s->secret) {
            const char *v = (const char *)src;
            /* Length only. Never the value, not even a prefix. */
            PS_INFO("  %-34s = <redacted, %zu bytes>", name,
                    (v[0] == '\0') ? (size_t)0 : strlen(v));
            continue;
        }

        switch (s->type) {
        case T_STR:
        case T_PATH:
            PS_INFO("  %-34s = %s", name, (const char *)src);
            break;
        case T_INT:
            PS_INFO("  %-34s = %d", name, *(const int *)src);
            break;
        case T_U16:
            PS_INFO("  %-34s = %u", name, (unsigned)*(const uint16_t *)src);
            break;
        case T_BOOL:
            PS_INFO("  %-34s = %s", name, *(const bool *)src ? "true" : "false");
            break;
        case T_LOGLEVEL:
            PS_INFO("  %-34s = %s", name,
                    ps_log_level_name(*(const ps_log_level_t *)src));
            break;
        }
    }
}
