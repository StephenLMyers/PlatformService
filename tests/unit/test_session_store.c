#include "testutil.h"

#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "store/db.h"
#include "store/session_store.h"
#include "store/user_store.h"

static const char *const TEST_DB_PATH = "build/test-scratch-session-store.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-session-store.sqlite3-wal");
    (void)unlink("build/test-scratch-session-store.sqlite3-shm");
    (void)unlink("build/test-scratch-session-store.sqlite3-journal");
}

static ps_db_pool_t *open_fresh_pool(void)
{
    remove_scratch_db();
    char           err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    return pool;
}

static int64_t insert_test_user(sqlite3 *conn, const char *username)
{
    ps_user_row_t row;
    memset(&row, 0, sizeof row);
    (void)snprintf(row.username, sizeof row.username, "%s", username);
    (void)snprintf(row.email, sizeof row.email, "%s@example.com", username);
    (void)snprintf(row.email_normalized, sizeof row.email_normalized, "%s@example.com", username);
    row.kdf_iters = 1;
    row.status    = PS_USER_STATUS_ACTIVE;

    const char *roles[] = { "USER" };
    char        err[256];
    int64_t     user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, roles, 1, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);
    return user_id;
}

static void fill(unsigned char *out, size_t len, unsigned char byte)
{
    memset(out, byte, len);
}

static void test_create_then_get_family_round_trips(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "alice");

    unsigned char family_id[PS_FAMILY_ID_LEN];
    fill(family_id, sizeof family_id, 0xAA);

    char err[256];
    PS_CHECK(ps_session_store_create_family(conn, family_id, user_id, 1700000000, 1707776000, err,
                                            sizeof err));

    ps_session_family_row_t row;
    PS_CHECK(ps_session_store_get_family(conn, family_id, &row));
    PS_CHECK(memcmp(row.family_id, family_id, sizeof family_id) == 0);
    PS_CHECK_EQ_INT(row.user_id, user_id);
    PS_CHECK_EQ_INT(row.created_at, 1700000000);
    PS_CHECK_EQ_INT(row.absolute_exp, 1707776000);
    PS_CHECK_EQ_INT(row.revoked_at, 0);
    PS_CHECK_STR_EQ(row.revoke_cause, "");

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_get_family_on_missing_id_returns_false(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);

    unsigned char family_id[PS_FAMILY_ID_LEN];
    fill(family_id, sizeof family_id, 0xFF);

    ps_session_family_row_t row;
    PS_CHECK(!ps_session_store_get_family(conn, family_id, &row));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_revoke_family_sets_revoked_at_and_cause_and_is_idempotent(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "bob");

    unsigned char family_id[PS_FAMILY_ID_LEN];
    fill(family_id, sizeof family_id, 0xBB);
    char err[256];
    PS_CHECK(ps_session_store_create_family(conn, family_id, user_id, 1700000000, 1707776000, err,
                                            sizeof err));

    PS_CHECK(ps_session_store_revoke_family(conn, family_id, "LOGOUT", 1700000500, err, sizeof err));

    ps_session_family_row_t row;
    PS_CHECK(ps_session_store_get_family(conn, family_id, &row));
    PS_CHECK_EQ_INT(row.revoked_at, 1700000500);
    PS_CHECK_STR_EQ(row.revoke_cause, "LOGOUT");

    /* Idempotent: revoking again with a different cause/time doesn't
     * disturb the first revocation (WHERE revoked_at IS NULL). */
    PS_CHECK(ps_session_store_revoke_family(conn, family_id, "REUSE_DETECTED", 1700000999, err,
                                            sizeof err));
    PS_CHECK(ps_session_store_get_family(conn, family_id, &row));
    PS_CHECK_EQ_INT(row.revoked_at, 1700000500);
    PS_CHECK_STR_EQ(row.revoke_cause, "LOGOUT");

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_insert_then_get_token_round_trips(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "carol");

    unsigned char family_id[PS_FAMILY_ID_LEN];
    fill(family_id, sizeof family_id, 0xCC);
    char err[256];
    PS_CHECK(ps_session_store_create_family(conn, family_id, user_id, 1700000000, 1707776000, err,
                                            sizeof err));

    unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN];
    fill(token_hash, sizeof token_hash, 0x01);
    PS_CHECK(ps_session_store_insert_token(conn, token_hash, family_id, 1, 1702592000, 1700000000,
                                           err, sizeof err));

    ps_refresh_token_row_t row;
    PS_CHECK(ps_session_store_get_token(conn, token_hash, &row));
    PS_CHECK(memcmp(row.token_hash, token_hash, sizeof token_hash) == 0);
    PS_CHECK(memcmp(row.family_id, family_id, sizeof family_id) == 0);
    PS_CHECK_EQ_INT(row.generation, 1);
    PS_CHECK_EQ_INT(row.idle_exp, 1702592000);
    PS_CHECK_EQ_INT(row.consumed_at, 0);
    PS_CHECK_EQ_INT(row.issued_at, 1700000000);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_get_token_on_missing_hash_returns_false(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);

    unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN];
    fill(token_hash, sizeof token_hash, 0xEE);

    ps_refresh_token_row_t row;
    PS_CHECK(!ps_session_store_get_token(conn, token_hash, &row));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_try_consume_token_claims_once_then_reports_unclaimed(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "dave");

    unsigned char family_id[PS_FAMILY_ID_LEN];
    fill(family_id, sizeof family_id, 0xDD);
    char err[256];
    PS_CHECK(ps_session_store_create_family(conn, family_id, user_id, 1700000000, 1707776000, err,
                                            sizeof err));
    unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN];
    fill(token_hash, sizeof token_hash, 0x02);
    PS_CHECK(ps_session_store_insert_token(conn, token_hash, family_id, 1, 1702592000, 1700000000,
                                           err, sizeof err));

    bool claimed = false;
    PS_CHECK(ps_session_store_try_consume_token(conn, token_hash, 1700000100, &claimed, err,
                                                sizeof err));
    PS_CHECK(claimed);

    ps_refresh_token_row_t row;
    PS_CHECK(ps_session_store_get_token(conn, token_hash, &row));
    PS_CHECK_EQ_INT(row.consumed_at, 1700000100);

    /* A second claim attempt on the now-consumed token -- the race-loser
     * path -- must report unclaimed rather than silently re-consuming or
     * overwriting the original consumed_at. */
    claimed = true; /* deliberately pre-set to a wrong value to prove it's overwritten */
    PS_CHECK(ps_session_store_try_consume_token(conn, token_hash, 1700000200, &claimed, err,
                                                sizeof err));
    PS_CHECK(!claimed);
    PS_CHECK(ps_session_store_get_token(conn, token_hash, &row));
    PS_CHECK_EQ_INT(row.consumed_at, 1700000100);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_try_consume_token_on_missing_hash_reports_unclaimed(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);

    unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN];
    fill(token_hash, sizeof token_hash, 0xF0);

    bool claimed = true;
    char err[256];
    PS_CHECK(ps_session_store_try_consume_token(conn, token_hash, 1700000100, &claimed, err,
                                                sizeof err));
    PS_CHECK(!claimed);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_revoke_all_for_user_except_one_leaves_the_exception_live(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "erin");

    unsigned char f1[PS_FAMILY_ID_LEN];
    unsigned char f2[PS_FAMILY_ID_LEN];
    unsigned char f3[PS_FAMILY_ID_LEN];
    fill(f1, sizeof f1, 0x01);
    fill(f2, sizeof f2, 0x02);
    fill(f3, sizeof f3, 0x03);
    char err[256];
    PS_CHECK(ps_session_store_create_family(conn, f1, user_id, 1700000000, 1707776000, err,
                                            sizeof err));
    PS_CHECK(ps_session_store_create_family(conn, f2, user_id, 1700000000, 1707776000, err,
                                            sizeof err));
    PS_CHECK(ps_session_store_create_family(conn, f3, user_id, 1700000000, 1707776000, err,
                                            sizeof err));

    int count = -1;
    PS_CHECK(ps_session_store_revoke_all_for_user(conn, user_id, f2, "PASSWORD_CHANGE", 1700001000,
                                                  &count, err, sizeof err));
    PS_CHECK_EQ_INT(count, 2);

    ps_session_family_row_t row;
    PS_CHECK(ps_session_store_get_family(conn, f1, &row));
    PS_CHECK_EQ_INT(row.revoked_at, 1700001000);
    PS_CHECK(ps_session_store_get_family(conn, f2, &row));
    PS_CHECK_EQ_INT(row.revoked_at, 0); /* the exception survives */
    PS_CHECK(ps_session_store_get_family(conn, f3, &row));
    PS_CHECK_EQ_INT(row.revoked_at, 1700001000);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_revoke_all_for_user_with_no_exception_revokes_every_family(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "frank");

    unsigned char f1[PS_FAMILY_ID_LEN];
    unsigned char f2[PS_FAMILY_ID_LEN];
    fill(f1, sizeof f1, 0x11);
    fill(f2, sizeof f2, 0x12);
    char err[256];
    PS_CHECK(ps_session_store_create_family(conn, f1, user_id, 1700000000, 1707776000, err,
                                            sizeof err));
    PS_CHECK(ps_session_store_create_family(conn, f2, user_id, 1700000000, 1707776000, err,
                                            sizeof err));

    int count = -1;
    PS_CHECK(ps_session_store_revoke_all_for_user(conn, user_id, NULL, "ACCOUNT_DISABLED", 1700002000,
                                                  &count, err, sizeof err));
    PS_CHECK_EQ_INT(count, 2);

    ps_session_family_row_t row;
    PS_CHECK(ps_session_store_get_family(conn, f1, &row));
    PS_CHECK_EQ_INT(row.revoked_at, 1700002000);
    PS_CHECK(ps_session_store_get_family(conn, f2, &row));
    PS_CHECK_EQ_INT(row.revoked_at, 1700002000);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_revoke_all_for_user_does_not_touch_other_users_families(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_a = insert_test_user(conn, "gina");
    int64_t       user_b = insert_test_user(conn, "hank");

    unsigned char fa[PS_FAMILY_ID_LEN];
    unsigned char fb[PS_FAMILY_ID_LEN];
    fill(fa, sizeof fa, 0x21);
    fill(fb, sizeof fb, 0x22);
    char err[256];
    PS_CHECK(ps_session_store_create_family(conn, fa, user_a, 1700000000, 1707776000, err,
                                            sizeof err));
    PS_CHECK(ps_session_store_create_family(conn, fb, user_b, 1700000000, 1707776000, err,
                                            sizeof err));

    int count = -1;
    PS_CHECK(ps_session_store_revoke_all_for_user(conn, user_a, NULL, "PASSWORD_CHANGE", 1700003000,
                                                  &count, err, sizeof err));
    PS_CHECK_EQ_INT(count, 1);

    ps_session_family_row_t row;
    PS_CHECK(ps_session_store_get_family(conn, fb, &row));
    PS_CHECK_EQ_INT(row.revoked_at, 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

int main(void)
{
    PS_RUN_TEST(test_create_then_get_family_round_trips);
    PS_RUN_TEST(test_get_family_on_missing_id_returns_false);
    PS_RUN_TEST(test_revoke_family_sets_revoked_at_and_cause_and_is_idempotent);
    PS_RUN_TEST(test_insert_then_get_token_round_trips);
    PS_RUN_TEST(test_get_token_on_missing_hash_returns_false);
    PS_RUN_TEST(test_try_consume_token_claims_once_then_reports_unclaimed);
    PS_RUN_TEST(test_try_consume_token_on_missing_hash_reports_unclaimed);
    PS_RUN_TEST(test_revoke_all_for_user_except_one_leaves_the_exception_live);
    PS_RUN_TEST(test_revoke_all_for_user_with_no_exception_revokes_every_family);
    PS_RUN_TEST(test_revoke_all_for_user_does_not_touch_other_users_families);
    PS_TEST_EXIT();
}
