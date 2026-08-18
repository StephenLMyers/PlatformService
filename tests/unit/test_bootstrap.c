#include "testutil.h"

#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "auth/bootstrap.h"
#include "auth/password.h"
#include "store/db.h"
#include "store/user_store.h"

static const char *const TEST_DB_PATH = "build/test-scratch-bootstrap.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-bootstrap.sqlite3-wal");
    (void)unlink("build/test-scratch-bootstrap.sqlite3-shm");
    (void)unlink("build/test-scratch-bootstrap.sqlite3-journal");
}

static ps_db_pool_t *open_fresh_pool(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    return pool;
}

static ps_config_t base_config(void)
{
    ps_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    (void)snprintf(cfg.bootstrap_admin_username, sizeof cfg.bootstrap_admin_username, "rootadmin");
    (void)snprintf(cfg.bootstrap_admin_email, sizeof cfg.bootstrap_admin_email,
                   "admin@example.com");
    (void)snprintf(cfg.bootstrap_admin_password, sizeof cfg.bootstrap_admin_password,
                   "correct horse battery staple");
    cfg.password_min_length = 12;
    cfg.password_max_length = 128;
    return cfg;
}

static void test_creates_admin_with_both_roles_and_active_status(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    ps_config_t    cfg  = base_config();

    char                   err[256];
    ps_bootstrap_result_t r = ps_bootstrap_admin(conn, &cfg, 100, NULL, 1700000000, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_BOOTSTRAP_OK);

    ps_user_row_t user;
    PS_CHECK(ps_user_store_get_by_username(conn, "rootadmin", &user));
    PS_CHECK_EQ_INT(user.status, PS_USER_STATUS_ACTIVE); /* bypasses verification -- plan 6.7 */

    char   roles[4][32];
    size_t count = 0;
    PS_CHECK(ps_user_store_get_roles(conn, user.user_id, roles, 4, &count));
    PS_CHECK_EQ_INT(count, 2);
    bool has_user = false, has_admin = false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(roles[i], "USER") == 0) has_user = true;
        if (strcmp(roles[i], "ADMIN") == 0) has_admin = true;
    }
    PS_CHECK(has_user);
    PS_CHECK(has_admin);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_password_buffer_is_cleansed_after_use(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    ps_config_t    cfg  = base_config();

    char err[256];
    PS_CHECK(ps_bootstrap_admin(conn, &cfg, 100, NULL, 1700000000, err, sizeof err) ==
            PS_BOOTSTRAP_OK);
    PS_CHECK_EQ_INT(cfg.bootstrap_admin_password[0], '\0');

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_idempotent_when_admin_already_exists(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    ps_config_t    cfg  = base_config();

    char err[256];
    PS_CHECK(ps_bootstrap_admin(conn, &cfg, 100, NULL, 1700000000, err, sizeof err) ==
            PS_BOOTSTRAP_OK);

    /* Second call: different credentials, but an admin already exists, so
     * it must do nothing -- not create a second admin, not touch these
     * (already-cleansed) credentials. */
    ps_config_t cfg2 = base_config();
    (void)snprintf(cfg2.bootstrap_admin_username, sizeof cfg2.bootstrap_admin_username, "different");
    PS_CHECK(ps_bootstrap_admin(conn, &cfg2, 100, NULL, 1700000001, err, sizeof err) ==
            PS_BOOTSTRAP_OK);

    ps_user_row_t user;
    PS_CHECK(!ps_user_store_get_by_username(conn, "different", &user));
    PS_CHECK(ps_user_store_get_by_username(conn, "rootadmin", &user));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_missing_credentials_refuses_to_start(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    ps_config_t    cfg  = base_config();
    cfg.bootstrap_admin_password[0] = '\0';

    char err[256];
    ps_bootstrap_result_t r = ps_bootstrap_admin(conn, &cfg, 100, NULL, 1700000000, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_BOOTSTRAP_MISSING_CREDENTIALS);

    ps_user_row_t user;
    PS_CHECK(!ps_user_store_get_by_username(conn, "rootadmin", &user));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_weak_password_refuses_to_start(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    ps_config_t    cfg  = base_config();
    (void)snprintf(cfg.bootstrap_admin_password, sizeof cfg.bootstrap_admin_password, "short");

    char err[256];
    ps_bootstrap_result_t r = ps_bootstrap_admin(conn, &cfg, 100, NULL, 1700000000, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_BOOTSTRAP_WEAK_PASSWORD);

    ps_user_row_t user;
    PS_CHECK(!ps_user_store_get_by_username(conn, "rootadmin", &user));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_reserved_name_allowed_for_bootstrap(void)
{
    /* plan 6.7: "admin" is exactly the right name for this one account. */
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    ps_config_t    cfg  = base_config();
    (void)snprintf(cfg.bootstrap_admin_username, sizeof cfg.bootstrap_admin_username, "admin");

    char err[256];
    PS_CHECK(ps_bootstrap_admin(conn, &cfg, 100, NULL, 1700000000, err, sizeof err) ==
            PS_BOOTSTRAP_OK);

    ps_user_row_t user;
    PS_CHECK(ps_user_store_get_by_username(conn, "admin", &user));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_created_admin_password_is_actually_verifiable(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    ps_config_t    cfg  = base_config();

    char err[256];
    PS_CHECK(ps_bootstrap_admin(conn, &cfg, 100, NULL, 1700000000, err, sizeof err) ==
            PS_BOOTSTRAP_OK);

    ps_user_row_t user;
    PS_CHECK(ps_user_store_get_by_username(conn, "rootadmin", &user));

    ps_password_hash_t stored;
    memcpy(stored.salt, user.password_salt, sizeof stored.salt);
    memcpy(stored.hash, user.password_hash, sizeof stored.hash);
    stored.iterations = user.kdf_iters;

    static const char *pw = "correct horse battery staple";
    PS_CHECK(ps_password_verify(pw, strlen(pw), &stored));
    PS_CHECK(!ps_password_verify("wrong password", 15, &stored));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_bootstrap_audit_row_written(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    ps_config_t    cfg  = base_config();

    char err[256];
    PS_CHECK(ps_bootstrap_admin(conn, &cfg, 100, NULL, 1700000000, err, sizeof err) ==
            PS_BOOTSTRAP_OK);

    sqlite3_stmt *stmt = NULL;
    PS_CHECK(sqlite3_prepare_v2(conn, "SELECT event, outcome FROM audit_log", -1, &stmt, NULL) ==
            SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    PS_CHECK_STR_EQ((const char *)sqlite3_column_text(stmt, 0), "BOOTSTRAP_ADMIN_CREATED");
    PS_CHECK_STR_EQ((const char *)sqlite3_column_text(stmt, 1), "SUCCESS");
    sqlite3_finalize(stmt);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

int main(void)
{
    PS_RUN_TEST(test_creates_admin_with_both_roles_and_active_status);
    PS_RUN_TEST(test_password_buffer_is_cleansed_after_use);
    PS_RUN_TEST(test_idempotent_when_admin_already_exists);
    PS_RUN_TEST(test_missing_credentials_refuses_to_start);
    PS_RUN_TEST(test_weak_password_refuses_to_start);
    PS_RUN_TEST(test_reserved_name_allowed_for_bootstrap);
    PS_RUN_TEST(test_created_admin_password_is_actually_verifiable);
    PS_RUN_TEST(test_bootstrap_audit_row_written);
    PS_TEST_EXIT();
}
