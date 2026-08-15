#include "testutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "platform/config.h"

/*
 * Every environment variable the settings table recognises. Cleared before
 * each test so a developer's sourced .env (README's documented workflow)
 * can never leak into a "defaults only" assertion.
 */
static const char *const ALL_ENV_VARS[] = {
    "PS_BIND_ADDRESS", "PS_PORT", "PS_DEV_MODE", "PS_WORKER_THREADS",
    "PS_ACCEPT_QUEUE_DEPTH", "PS_SHUTDOWN_GRACE_S",
    "PS_MAX_REQUEST_LINE", "PS_MAX_HEADER_BYTES", "PS_MAX_HEADER_COUNT",
    "PS_MAX_BODY_BYTES", "PS_READ_TIMEOUT_S", "PS_WRITE_TIMEOUT_S",
    "PS_KEEPALIVE_IDLE_S", "PS_KEEPALIVE_MAX_REQUESTS",
    "PS_TLS_ENABLED", "PS_TLS_CERT_PATH", "PS_TLS_KEY_PATH",
    "PS_DB_PATH", "PS_DB_BUSY_TIMEOUT_MS",
    "PS_ACCESS_TOKEN_TTL_S", "PS_REFRESH_IDLE_TTL_S",
    "PS_REFRESH_ABSOLUTE_TTL_S", "PS_VERIFICATION_TTL_S",
    "PS_KDF_ITERATIONS", "PS_LOCKOUT_THRESHOLD", "PS_LOCKOUT_DURATION_S",
    "PS_PASSWORD_MIN_LENGTH", "PS_PASSWORD_MAX_LENGTH",
    "PS_JWT_ISSUER", "PS_JWT_AUDIENCE", "PS_JWT_SECRET",
    "BOOTSTRAP_ADMIN_USERNAME", "BOOTSTRAP_ADMIN_EMAIL", "BOOTSTRAP_ADMIN_PASSWORD",
    "PS_MAINTENANCE_INTERVAL_S", "PS_MAINTENANCE_BATCH_SIZE",
    "PS_AUDIT_RETENTION_DAYS",
    "PS_RATELIMIT_MAX_ENTRIES", "PS_RATELIMIT_LOGIN", "PS_RATELIMIT_REGISTER",
    "PS_RESEND_MIN_INTERVAL_S", "PS_RESEND_MAX_PER_DAY",
    "PS_COMMON_PASSWORDS_PATH", "PS_LOG_LEVEL",
};
#define ALL_ENV_COUNT (sizeof ALL_ENV_VARS / sizeof ALL_ENV_VARS[0])

static const char *const VALID_SECRET =
    "0123456789abcdef0123456789abcdef";  /* 33 bytes, >= PS_JWT_SECRET_MIN */

static void clear_env(void)
{
    for (size_t i = 0; i < ALL_ENV_COUNT; i++) {
        unsetenv(ALL_ENV_VARS[i]);
    }
}

static const char *const SCRATCH_PATH = "build/test-scratch-config.conf";

static void write_scratch_file(const char *content)
{
    FILE *f = fopen(SCRATCH_PATH, "we");
    PS_CHECK(f != NULL);
    if (f != NULL) {
        (void)fputs(content, f);
        (void)fclose(f);
    }
}

/* ------------------------------------------------------------------------- */

static void test_defaults_applied_with_no_file_and_minimal_env(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(ok);
    PS_CHECK_STR_EQ(cfg.bind_address, "127.0.0.1");
    PS_CHECK_EQ_INT(cfg.port, 8443);
    PS_CHECK(cfg.dev_mode == false);
    PS_CHECK_EQ_INT(cfg.kdf_iterations, 600000);
    PS_CHECK_EQ_INT(cfg.access_token_ttl_s, 900);
    PS_CHECK_EQ_INT(cfg.log_level, PS_LOG_INFO);

    ps_config_free(&cfg);
}

static void test_env_overrides_default(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_PORT", "9999", 1);
    setenv("PS_BIND_ADDRESS", "0.0.0.0", 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(ok);
    PS_CHECK_EQ_INT(cfg.port, 9999);
    PS_CHECK_STR_EQ(cfg.bind_address, "0.0.0.0");

    ps_config_free(&cfg);
}

static void test_file_overrides_default(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    write_scratch_file("server.port = 7000\n");

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, SCRATCH_PATH, err, sizeof err);

    PS_CHECK(ok);
    PS_CHECK_EQ_INT(cfg.port, 7000);

    ps_config_free(&cfg);
    (void)remove(SCRATCH_PATH);
}

/* The resolution order the README documents: defaults -> file -> env. */
static void test_env_wins_over_file(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_PORT", "1111", 1);
    write_scratch_file("server.port = 2222\n");

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, SCRATCH_PATH, err, sizeof err);

    PS_CHECK(ok);
    PS_CHECK_EQ_INT(cfg.port, 1111);

    ps_config_free(&cfg);
    (void)remove(SCRATCH_PATH);
}

static void test_missing_secret_fails(void)
{
    clear_env();

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);
    PS_CHECK(strstr(err, "PS_JWT_SECRET") != NULL);

    ps_config_free(&cfg);
}

static void test_short_secret_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", "too-short", 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);
    PS_CHECK(strstr(err, "PS_JWT_SECRET") != NULL);

    ps_config_free(&cfg);
}

static void test_unknown_key_in_file_is_fatal(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    write_scratch_file("server.totally_made_up = 1\n");

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, SCRATCH_PATH, err, sizeof err);

    PS_CHECK(!ok);
    PS_CHECK(strstr(err, "unknown setting") != NULL);
    PS_CHECK(strstr(err, "server.totally_made_up") != NULL);

    ps_config_free(&cfg);
    (void)remove(SCRATCH_PATH);
}

/*
 * A secret named in a config file must fail with the specific "comes from
 * the environment" message, not merely the generic unknown-setting one --
 * the whole point is telling the operator what to do instead.
 */
static void test_secret_in_file_is_rejected_with_specific_message(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    write_scratch_file("auth.jwt_secret = whatever\n");

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, SCRATCH_PATH, err, sizeof err);

    PS_CHECK(!ok);
    PS_CHECK(strstr(err, "environment") != NULL);
    PS_CHECK(strstr(err, "PS_JWT_SECRET") != NULL);

    ps_config_free(&cfg);
    (void)remove(SCRATCH_PATH);
}

static void test_bootstrap_password_in_file_is_rejected(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    write_scratch_file("bootstrap.admin_password = hunter2\n");

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, SCRATCH_PATH, err, sizeof err);

    PS_CHECK(!ok);
    PS_CHECK(strstr(err, "environment") != NULL);
    PS_CHECK(strstr(err, "BOOTSTRAP_ADMIN_PASSWORD") != NULL);

    ps_config_free(&cfg);
    (void)remove(SCRATCH_PATH);
}

static void test_malformed_line_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    write_scratch_file("this line has no equals sign\n");

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, SCRATCH_PATH, err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
    (void)remove(SCRATCH_PATH);
}

static void test_comments_and_blank_lines_skipped(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    write_scratch_file(
        "# a comment\n"
        "\n"
        "   \n"
        "; another comment style\n"
        "server.port = 5555\n");

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, SCRATCH_PATH, err, sizeof err);

    PS_CHECK(ok);
    PS_CHECK_EQ_INT(cfg.port, 5555);

    ps_config_free(&cfg);
    (void)remove(SCRATCH_PATH);
}

static void test_missing_file_is_error(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, "build/does-not-exist.conf", err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
}

static void test_invalid_port_value_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_PORT", "70000", 1); /* out of 1-65535 range */

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
}

static void test_invalid_bool_value_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_DEV_MODE", "maybe", 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
}

static void test_invalid_log_level_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_LOG_LEVEL", "SUPER_VERBOSE", 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
}

static void test_refresh_absolute_must_not_be_less_than_idle(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_REFRESH_IDLE_TTL_S", "1000", 1);
    setenv("PS_REFRESH_ABSOLUTE_TTL_S", "500", 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);
    PS_CHECK(strstr(err, "refresh_absolute_ttl_s") != NULL);

    ps_config_free(&cfg);
}

static void test_kdf_iterations_below_floor_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_KDF_ITERATIONS", "999", 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
}

static void test_password_bounds_invalid_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_PASSWORD_MIN_LENGTH", "20", 1);
    setenv("PS_PASSWORD_MAX_LENGTH", "10", 1); /* max < min */

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
}

static void test_ratelimit_max_entries_zero_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("PS_RATELIMIT_MAX_ENTRIES", "0", 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
}

/* OPENSSL_cleanse must actually have run, not been optimised away. */
static void test_free_zeroes_secret_material(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);
    setenv("BOOTSTRAP_ADMIN_PASSWORD", "hunter2hunter2hunter2", 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);
    PS_CHECK(ok);

    ps_config_free(&cfg);

    PS_CHECK_EQ_INT(cfg.jwt_secret[0], '\0');
    PS_CHECK_EQ_INT(cfg.bootstrap_admin_password[0], '\0');
}

static void test_value_too_long_for_field_fails(void)
{
    clear_env();
    setenv("PS_JWT_SECRET", VALID_SECRET, 1);

    char huge[PS_STR_MAX + 64];
    memset(huge, 'a', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';
    setenv("PS_BIND_ADDRESS", huge, 1);

    ps_config_t cfg;
    char        err[256];
    bool        ok = ps_config_load(&cfg, NULL, err, sizeof err);

    PS_CHECK(!ok);

    ps_config_free(&cfg);
}

int main(void)
{
    PS_RUN_TEST(test_defaults_applied_with_no_file_and_minimal_env);
    PS_RUN_TEST(test_env_overrides_default);
    PS_RUN_TEST(test_file_overrides_default);
    PS_RUN_TEST(test_env_wins_over_file);
    PS_RUN_TEST(test_missing_secret_fails);
    PS_RUN_TEST(test_short_secret_fails);
    PS_RUN_TEST(test_unknown_key_in_file_is_fatal);
    PS_RUN_TEST(test_secret_in_file_is_rejected_with_specific_message);
    PS_RUN_TEST(test_bootstrap_password_in_file_is_rejected);
    PS_RUN_TEST(test_malformed_line_fails);
    PS_RUN_TEST(test_comments_and_blank_lines_skipped);
    PS_RUN_TEST(test_missing_file_is_error);
    PS_RUN_TEST(test_invalid_port_value_fails);
    PS_RUN_TEST(test_invalid_bool_value_fails);
    PS_RUN_TEST(test_invalid_log_level_fails);
    PS_RUN_TEST(test_refresh_absolute_must_not_be_less_than_idle);
    PS_RUN_TEST(test_kdf_iterations_below_floor_fails);
    PS_RUN_TEST(test_password_bounds_invalid_fails);
    PS_RUN_TEST(test_ratelimit_max_entries_zero_fails);
    PS_RUN_TEST(test_free_zeroes_secret_material);
    PS_RUN_TEST(test_value_too_long_for_field_fails);

    PS_TEST_EXIT();
}
