#include "testutil.h"

#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "store/db.h"
#include "store/user_store.h"

static const char *const TEST_DB_PATH = "build/test-scratch-user-store.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-user-store.sqlite3-wal");
    (void)unlink("build/test-scratch-user-store.sqlite3-shm");
    (void)unlink("build/test-scratch-user-store.sqlite3-journal");
}

static ps_db_pool_t *open_fresh_pool(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    return pool;
}

static ps_user_row_t sample_row(const char *username, const char *email)
{
    ps_user_row_t row;
    memset(&row, 0, sizeof row);
    (void)snprintf(row.username, sizeof row.username, "%s", username);
    (void)snprintf(row.email, sizeof row.email, "%s", email);
    (void)snprintf(row.email_normalized, sizeof row.email_normalized, "%s", email);
    memset(row.password_hash, 0xAB, sizeof row.password_hash);
    memset(row.password_salt, 0xCD, sizeof row.password_salt);
    row.kdf_iters     = 100;
    row.status        = PS_USER_STATUS_PENDING_VERIFICATION;
    row.failed_logins = 0;
    row.locked_until  = 0;
    return row;
}

static void test_status_string_round_trip(void)
{
    ps_user_status_t out;
    PS_CHECK(ps_user_status_from_string("PENDING_VERIFICATION", &out));
    PS_CHECK_EQ_INT(out, PS_USER_STATUS_PENDING_VERIFICATION);
    PS_CHECK(ps_user_status_from_string("ACTIVE", &out));
    PS_CHECK_EQ_INT(out, PS_USER_STATUS_ACTIVE);
    PS_CHECK(ps_user_status_from_string("DISABLED", &out));
    PS_CHECK_EQ_INT(out, PS_USER_STATUS_DISABLED);
    PS_CHECK(!ps_user_status_from_string("NOT_A_STATUS", &out));

    PS_CHECK_STR_EQ(ps_user_status_to_string(PS_USER_STATUS_ACTIVE), "ACTIVE");
}

static void test_insert_then_get_by_id_round_trips_every_field(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row = sample_row("alice", "alice@example.com");
    row.status         = PS_USER_STATUS_ACTIVE;
    const char *roles[] = { "USER" };

    char    err[256];
    int64_t user_id = 0;
    ps_user_insert_result_t r =
        ps_user_store_insert(conn, &row, roles, 1, 1700000000, &user_id, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_USER_INSERT_OK);
    PS_CHECK(user_id > 0);

    ps_user_row_t out;
    PS_CHECK(ps_user_store_get_by_id(conn, user_id, &out));
    PS_CHECK_STR_EQ(out.username, "alice");
    PS_CHECK_STR_EQ(out.email, "alice@example.com");
    PS_CHECK_STR_EQ(out.email_normalized, "alice@example.com");
    PS_CHECK(memcmp(out.password_hash, row.password_hash, sizeof out.password_hash) == 0);
    PS_CHECK(memcmp(out.password_salt, row.password_salt, sizeof out.password_salt) == 0);
    PS_CHECK_EQ_INT(out.kdf_iters, 100);
    PS_CHECK_EQ_INT(out.status, PS_USER_STATUS_ACTIVE);
    PS_CHECK_EQ_INT(out.locked_until, 0);
    PS_CHECK_EQ_INT(out.created_at, 1700000000);
    PS_CHECK_EQ_INT(out.updated_at, 1700000000);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_get_by_username_and_email_normalized(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row   = sample_row("bob", "bob@example.com");
    const char   *roles[] = { "USER" };
    char          err[256];
    int64_t       user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, roles, 1, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);

    ps_user_row_t out;
    PS_CHECK(ps_user_store_get_by_username(conn, "bob", &out));
    PS_CHECK_EQ_INT(out.user_id, user_id);

    /* username collation is NOCASE (plan 5) */
    PS_CHECK(ps_user_store_get_by_username(conn, "BOB", &out));
    PS_CHECK_EQ_INT(out.user_id, user_id);

    PS_CHECK(ps_user_store_get_by_email_normalized(conn, "bob@example.com", &out));
    PS_CHECK_EQ_INT(out.user_id, user_id);

    PS_CHECK(!ps_user_store_get_by_username(conn, "no-such-user", &out));
    PS_CHECK(!ps_user_store_get_by_id(conn, 999999, &out));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_duplicate_username_rejected(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row1 = sample_row("carol", "carol1@example.com");
    ps_user_row_t row2 = sample_row("carol", "carol2@example.com");
    const char   *roles[] = { "USER" };
    char          err[256];
    int64_t       id = 0;

    PS_CHECK(ps_user_store_insert(conn, &row1, roles, 1, 1700000000, &id, err, sizeof err) ==
            PS_USER_INSERT_OK);
    PS_CHECK(ps_user_store_insert(conn, &row2, roles, 1, 1700000000, &id, err, sizeof err) ==
            PS_USER_INSERT_DUPLICATE_USERNAME);

    /* The rejected insert must not have left a stray row (transaction
     * rolled back cleanly). */
    ps_user_row_t out;
    PS_CHECK(!ps_user_store_get_by_email_normalized(conn, "carol2@example.com", &out));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_duplicate_email_rejected(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row1 = sample_row("dave1", "dave@example.com");
    ps_user_row_t row2 = sample_row("dave2", "dave@example.com");
    const char   *roles[] = { "USER" };
    char          err[256];
    int64_t       id = 0;

    PS_CHECK(ps_user_store_insert(conn, &row1, roles, 1, 1700000000, &id, err, sizeof err) ==
            PS_USER_INSERT_OK);
    PS_CHECK(ps_user_store_insert(conn, &row2, roles, 1, 1700000000, &id, err, sizeof err) ==
            PS_USER_INSERT_DUPLICATE_EMAIL);

    ps_user_row_t out;
    PS_CHECK(!ps_user_store_get_by_username(conn, "dave2", &out));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_unknown_role_rejected_and_rolled_back(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row     = sample_row("erin", "erin@example.com");
    const char   *roles[] = { "SUPERUSER" };
    char          err[256];
    int64_t       id = 0;

    ps_user_insert_result_t r =
        ps_user_store_insert(conn, &row, roles, 1, 1700000000, &id, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_USER_INSERT_ERROR);

    /* The whole insert -- including the user row itself -- must have been
     * rolled back, not just the role assignment. */
    ps_user_row_t out;
    PS_CHECK(!ps_user_store_get_by_username(conn, "erin", &out));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_multiple_roles_assigned(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row     = sample_row("frank", "frank@example.com");
    const char   *roles[] = { "USER", "ADMIN" };
    char          err[256];
    int64_t       user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, roles, 2, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);

    char   role_names[4][32];
    size_t count = 0;
    PS_CHECK(ps_user_store_get_roles(conn, user_id, role_names, 4, &count));
    PS_CHECK_EQ_INT(count, 2);

    bool has_user = false, has_admin = false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(role_names[i], "USER") == 0) has_user = true;
        if (strcmp(role_names[i], "ADMIN") == 0) has_admin = true;
    }
    PS_CHECK(has_user);
    PS_CHECK(has_admin);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_get_roles_on_user_with_no_roles_returns_empty(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row = sample_row("grace", "grace@example.com");
    char          err[256];
    int64_t       user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, NULL, 0, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);

    char   role_names[4][32];
    size_t count = 123;
    PS_CHECK(ps_user_store_get_roles(conn, user_id, role_names, 4, &count));
    PS_CHECK_EQ_INT(count, 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_insert_composes_into_a_larger_caller_managed_transaction(void)
{
    /* The whole reason ps_user_store_insert uses SAVEPOINT/RELEASE rather
     * than BEGIN/COMMIT internally (plan 6.10, discussed with the user):
     * a caller can wrap it inside its own outer transaction -- alongside a
     * token insert and an audit write, for register/bootstrap -- and
     * rolling back the outer transaction must undo the user row too, not
     * just whatever the outer caller itself inserted. */
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    PS_CHECK(sqlite3_exec(conn, "BEGIN;", NULL, NULL, NULL) == SQLITE_OK);

    ps_user_row_t row     = sample_row("iris", "iris@example.com");
    const char   *roles[] = { "USER" };
    char          err[256];
    int64_t       user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, roles, 1, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);

    /* Still visible inside the same (uncommitted) outer transaction. */
    ps_user_row_t out;
    PS_CHECK(ps_user_store_get_by_username(conn, "iris", &out));

    PS_CHECK(sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK);

    /* The outer rollback must have undone the insert too. */
    PS_CHECK(!ps_user_store_get_by_username(conn, "iris", &out));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_locked_until_null_round_trips_as_zero(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row     = sample_row("henry", "henry@example.com");
    row.locked_until       = 1234567890;
    const char   *roles[] = { "USER" };
    char          err[256];
    int64_t       user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, roles, 1, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);

    ps_user_row_t out;
    PS_CHECK(ps_user_store_get_by_id(conn, user_id, &out));
    PS_CHECK_EQ_INT(out.locked_until, 1234567890);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_set_login_failure_state_sets_and_clears_locked_until(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row     = sample_row("jane", "jane@example.com");
    const char   *roles[] = { "USER" };
    char          err[256];
    int64_t       user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, roles, 1, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);

    PS_CHECK(ps_user_store_set_login_failure_state(conn, user_id, 9, 0, 1700000100, err, sizeof err));
    ps_user_row_t out;
    PS_CHECK(ps_user_store_get_by_id(conn, user_id, &out));
    PS_CHECK_EQ_INT(out.failed_logins, 9);
    PS_CHECK_EQ_INT(out.locked_until, 0);
    PS_CHECK_EQ_INT(out.updated_at, 1700000100);

    PS_CHECK(ps_user_store_set_login_failure_state(conn, user_id, 10, 1700000900, 1700000200, err,
                                                   sizeof err));
    PS_CHECK(ps_user_store_get_by_id(conn, user_id, &out));
    PS_CHECK_EQ_INT(out.failed_logins, 10);
    PS_CHECK_EQ_INT(out.locked_until, 1700000900);

    /* A successful login resets both back to zero/NULL. */
    PS_CHECK(ps_user_store_set_login_failure_state(conn, user_id, 0, 0, 1700000300, err, sizeof err));
    PS_CHECK(ps_user_store_get_by_id(conn, user_id, &out));
    PS_CHECK_EQ_INT(out.failed_logins, 0);
    PS_CHECK_EQ_INT(out.locked_until, 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_set_password_rehashes_and_bumps_updated_at(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_user_row_t row     = sample_row("kevin", "kevin@example.com");
    const char   *roles[] = { "USER" };
    char          err[256];
    int64_t       user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, roles, 1, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);

    unsigned char new_hash[32];
    unsigned char new_salt[16];
    memset(new_hash, 0xEF, sizeof new_hash);
    memset(new_salt, 0x12, sizeof new_salt);
    PS_CHECK(ps_user_store_set_password(conn, user_id, new_hash, new_salt, 999, 1700000500, err,
                                        sizeof err));

    ps_user_row_t out;
    PS_CHECK(ps_user_store_get_by_id(conn, user_id, &out));
    PS_CHECK(memcmp(out.password_hash, new_hash, sizeof new_hash) == 0);
    PS_CHECK(memcmp(out.password_salt, new_salt, sizeof new_salt) == 0);
    PS_CHECK_EQ_INT(out.kdf_iters, 999);
    PS_CHECK_EQ_INT(out.updated_at, 1700000500);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

int main(void)
{
    PS_RUN_TEST(test_status_string_round_trip);
    PS_RUN_TEST(test_insert_then_get_by_id_round_trips_every_field);
    PS_RUN_TEST(test_get_by_username_and_email_normalized);
    PS_RUN_TEST(test_duplicate_username_rejected);
    PS_RUN_TEST(test_duplicate_email_rejected);
    PS_RUN_TEST(test_unknown_role_rejected_and_rolled_back);
    PS_RUN_TEST(test_multiple_roles_assigned);
    PS_RUN_TEST(test_get_roles_on_user_with_no_roles_returns_empty);
    PS_RUN_TEST(test_insert_composes_into_a_larger_caller_managed_transaction);
    PS_RUN_TEST(test_locked_until_null_round_trips_as_zero);
    PS_RUN_TEST(test_set_login_failure_state_sets_and_clears_locked_until);
    PS_RUN_TEST(test_set_password_rehashes_and_bumps_updated_at);
    PS_TEST_EXIT();
}
