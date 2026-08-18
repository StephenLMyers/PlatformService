#include "testutil.h"

#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "auth/session.h"
#include "crypto/sha256.h"
#include "store/db.h"
#include "store/user_store.h"

static const char *const TEST_DB_PATH = "build/test-scratch-session.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-session.sqlite3-wal");
    (void)unlink("build/test-scratch-session.sqlite3-shm");
    (void)unlink("build/test-scratch-session.sqlite3-journal");
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

#define IDLE_TTL_S     (30 * 24 * 60 * 60)
#define ABSOLUTE_TTL_S (90 * 24 * 60 * 60)

static void test_create_opens_a_family_with_generation_one_token(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "alice");

    ps_session_created_t session;
    char                 err[256];
    PS_CHECK(ps_session_create(conn, user_id, ABSOLUTE_TTL_S, IDLE_TTL_S, 1700000000, &session, err,
                               sizeof err));
    PS_CHECK_EQ_INT(session.refresh_idle_exp, 1700000000 + IDLE_TTL_S);

    ps_session_family_row_t family;
    PS_CHECK(ps_session_store_get_family(conn, session.family_id, &family));
    PS_CHECK_EQ_INT(family.user_id, user_id);
    PS_CHECK_EQ_INT(family.absolute_exp, 1700000000 + ABSOLUTE_TTL_S);

    unsigned char hash[PS_SHA256_LEN];
    PS_CHECK(ps_sha256(session.raw_refresh_token, sizeof session.raw_refresh_token, hash));
    ps_refresh_token_row_t token;
    PS_CHECK(ps_session_store_get_token(conn, hash, &token));
    PS_CHECK_EQ_INT(token.generation, 1);
    PS_CHECK_EQ_INT(token.consumed_at, 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_refresh_on_unknown_token_is_invalid_with_no_user_attributed(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);

    unsigned char unknown_hash[PS_SHA256_LEN];
    memset(unknown_hash, 0x99, sizeof unknown_hash);

    ps_session_refreshed_t out;
    char                   err[256];
    ps_session_refresh_result_t r =
        ps_session_refresh(conn, unknown_hash, IDLE_TTL_S, 1700000100, &out, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_SESSION_REFRESH_INVALID);
    PS_CHECK_EQ_INT(out.user_id, 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_refresh_rotates_the_token_and_advances_generation(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "bob");

    ps_session_created_t session;
    char                 err[256];
    PS_CHECK(ps_session_create(conn, user_id, ABSOLUTE_TTL_S, IDLE_TTL_S, 1700000000, &session, err,
                               sizeof err));
    unsigned char old_hash[PS_SHA256_LEN];
    PS_CHECK(ps_sha256(session.raw_refresh_token, sizeof session.raw_refresh_token, old_hash));

    ps_session_refreshed_t      refreshed;
    ps_session_refresh_result_t r =
        ps_session_refresh(conn, old_hash, IDLE_TTL_S, 1700000100, &refreshed, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_SESSION_REFRESH_OK);
    PS_CHECK_EQ_INT(refreshed.user_id, user_id);
    PS_CHECK(memcmp(refreshed.family_id, session.family_id, sizeof session.family_id) == 0);
    PS_CHECK(memcmp(refreshed.raw_refresh_token, session.raw_refresh_token,
                    sizeof session.raw_refresh_token) != 0);

    /* The old token is now consumed and can never succeed again. */
    ps_refresh_token_row_t old_row;
    PS_CHECK(ps_session_store_get_token(conn, old_hash, &old_row));
    PS_CHECK_EQ_INT(old_row.consumed_at, 1700000100);

    unsigned char new_hash[PS_SHA256_LEN];
    PS_CHECK(ps_sha256(refreshed.raw_refresh_token, sizeof refreshed.raw_refresh_token, new_hash));
    ps_refresh_token_row_t new_row;
    PS_CHECK(ps_session_store_get_token(conn, new_hash, &new_row));
    PS_CHECK_EQ_INT(new_row.generation, 2);
    PS_CHECK_EQ_INT(new_row.consumed_at, 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_presenting_an_already_consumed_token_revokes_the_family(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "carol");

    ps_session_created_t session;
    char                 err[256];
    PS_CHECK(ps_session_create(conn, user_id, ABSOLUTE_TTL_S, IDLE_TTL_S, 1700000000, &session, err,
                               sizeof err));
    unsigned char r1_hash[PS_SHA256_LEN];
    PS_CHECK(ps_sha256(session.raw_refresh_token, sizeof session.raw_refresh_token, r1_hash));

    /* The attacker refreshes first. */
    ps_session_refreshed_t attacker_refresh;
    PS_CHECK_EQ_INT(ps_session_refresh(conn, r1_hash, IDLE_TTL_S, 1700000100, &attacker_refresh, err,
                                       sizeof err),
                   PS_SESSION_REFRESH_OK);

    /* The real user then presents the same, now-consumed R1. */
    ps_session_refreshed_t victim_refresh;
    ps_session_refresh_result_t r =
        ps_session_refresh(conn, r1_hash, IDLE_TTL_S, 1700000200, &victim_refresh, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_SESSION_REFRESH_REUSE_DETECTED);
    PS_CHECK_EQ_INT(victim_refresh.user_id, user_id); /* attributable for the audit row */

    /* The whole family -- including the attacker's already-issued R2 -- is
     * now dead. */
    ps_session_family_row_t family;
    PS_CHECK(ps_session_store_get_family(conn, session.family_id, &family));
    PS_CHECK(family.revoked_at != 0);
    PS_CHECK_STR_EQ(family.revoke_cause, "REUSE_DETECTED");

    unsigned char r2_hash[PS_SHA256_LEN];
    PS_CHECK(
        ps_sha256(attacker_refresh.raw_refresh_token, sizeof attacker_refresh.raw_refresh_token, r2_hash));
    ps_session_refreshed_t dead_refresh;
    PS_CHECK_EQ_INT(
        ps_session_refresh(conn, r2_hash, IDLE_TTL_S, 1700000300, &dead_refresh, err, sizeof err),
        PS_SESSION_REFRESH_INVALID); /* family revoked, even though R2 itself was never consumed */

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_refresh_past_absolute_expiry_is_invalid_but_still_consumes(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3      *conn = ps_db_pool_acquire(pool);
    int64_t       user_id = insert_test_user(conn, "dave");

    ps_session_created_t session;
    char                 err[256];
    PS_CHECK(ps_session_create(conn, user_id, /*absolute_ttl_s=*/1000, IDLE_TTL_S, 1700000000,
                               &session, err, sizeof err));
    unsigned char hash[PS_SHA256_LEN];
    PS_CHECK(ps_sha256(session.raw_refresh_token, sizeof session.raw_refresh_token, hash));

    /* now is past absolute_exp (1700000000 + 1000). */
    ps_session_refreshed_t out;
    ps_session_refresh_result_t r =
        ps_session_refresh(conn, hash, IDLE_TTL_S, 1700005000, &out, err, sizeof err);
    PS_CHECK_EQ_INT(r, PS_SESSION_REFRESH_INVALID);
    PS_CHECK_EQ_INT(out.user_id, user_id);

    /* Single-use is still enforced unconditionally: the old token is
     * consumed even though no new one was issued. */
    ps_refresh_token_row_t row;
    PS_CHECK(ps_session_store_get_token(conn, hash, &row));
    PS_CHECK(row.consumed_at != 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

int main(void)
{
    PS_RUN_TEST(test_create_opens_a_family_with_generation_one_token);
    PS_RUN_TEST(test_refresh_on_unknown_token_is_invalid_with_no_user_attributed);
    PS_RUN_TEST(test_refresh_rotates_the_token_and_advances_generation);
    PS_RUN_TEST(test_presenting_an_already_consumed_token_revokes_the_family);
    PS_RUN_TEST(test_refresh_past_absolute_expiry_is_invalid_but_still_consumes);
    PS_TEST_EXIT();
}
