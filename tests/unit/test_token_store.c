#include "testutil.h"

#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "store/db.h"
#include "store/token_store.h"
#include "store/user_store.h"

static const char *const TEST_DB_PATH = "build/test-scratch-token-store.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-token-store.sqlite3-wal");
    (void)unlink("build/test-scratch-token-store.sqlite3-shm");
    (void)unlink("build/test-scratch-token-store.sqlite3-journal");
}

static ps_db_pool_t *open_fresh_pool(void)
{
    remove_scratch_db();
    char err[256];
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
    row.status    = PS_USER_STATUS_PENDING_VERIFICATION;

    const char *roles[] = { "USER" };
    char        err[256];
    int64_t     user_id = 0;
    PS_CHECK(ps_user_store_insert(conn, &row, roles, 1, 1700000000, &user_id, err, sizeof err) ==
            PS_USER_INSERT_OK);
    return user_id;
}

static void fill_hash(unsigned char out[PS_TOKEN_HASH_LEN], unsigned char byte)
{
    memset(out, byte, PS_TOKEN_HASH_LEN);
}

static void test_insert_then_get_by_hash_round_trips(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    int64_t         user_id = insert_test_user(conn, "alice");

    unsigned char hash[PS_TOKEN_HASH_LEN];
    fill_hash(hash, 0xAA);

    char err[256];
    PS_CHECK(ps_token_store_insert(conn, hash, user_id, 1700100000, 1700000000, err, sizeof err));

    ps_verification_token_row_t row;
    PS_CHECK(ps_token_store_get_by_hash(conn, hash, &row));
    PS_CHECK(memcmp(row.token_hash, hash, PS_TOKEN_HASH_LEN) == 0);
    PS_CHECK_EQ_INT(row.user_id, user_id);
    PS_CHECK_EQ_INT(row.expires_at, 1700100000);
    PS_CHECK_EQ_INT(row.consumed_at, 0);
    PS_CHECK_EQ_INT(row.created_at, 1700000000);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_get_by_hash_on_missing_token_returns_false(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    unsigned char hash[PS_TOKEN_HASH_LEN];
    fill_hash(hash, 0xFF);

    ps_verification_token_row_t row;
    PS_CHECK(!ps_token_store_get_by_hash(conn, hash, &row));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_consume_marks_token_and_is_idempotent_on_the_flag(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    int64_t         user_id = insert_test_user(conn, "bob");

    unsigned char hash[PS_TOKEN_HASH_LEN];
    fill_hash(hash, 0xBB);
    char err[256];
    PS_CHECK(ps_token_store_insert(conn, hash, user_id, 1700100000, 1700000000, err, sizeof err));

    PS_CHECK(ps_token_store_consume(conn, hash, 1700050000, err, sizeof err));

    ps_verification_token_row_t row;
    PS_CHECK(ps_token_store_get_by_hash(conn, hash, &row));
    PS_CHECK_EQ_INT(row.consumed_at, 1700050000);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_invalidate_all_for_user_only_touches_outstanding_tokens(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    int64_t         user_id = insert_test_user(conn, "carol");

    unsigned char h1[PS_TOKEN_HASH_LEN];
    unsigned char h2[PS_TOKEN_HASH_LEN];
    unsigned char h3_already_consumed[PS_TOKEN_HASH_LEN];
    fill_hash(h1, 0x01);
    fill_hash(h2, 0x02);
    fill_hash(h3_already_consumed, 0x03);

    char err[256];
    PS_CHECK(ps_token_store_insert(conn, h1, user_id, 1700100000, 1700000000, err, sizeof err));
    PS_CHECK(ps_token_store_insert(conn, h2, user_id, 1700100000, 1700000001, err, sizeof err));
    PS_CHECK(ps_token_store_insert(conn, h3_already_consumed, user_id, 1700100000, 1700000002, err,
                                   sizeof err));
    PS_CHECK(ps_token_store_consume(conn, h3_already_consumed, 1700000003, err, sizeof err));

    PS_CHECK(ps_token_store_invalidate_all_for_user(conn, user_id, 1700000010, err, sizeof err));

    ps_verification_token_row_t row;
    PS_CHECK(ps_token_store_get_by_hash(conn, h1, &row));
    PS_CHECK_EQ_INT(row.consumed_at, 1700000010);
    PS_CHECK(ps_token_store_get_by_hash(conn, h2, &row));
    PS_CHECK_EQ_INT(row.consumed_at, 1700000010);
    /* Already-consumed token keeps its original consumed_at -- WHERE
     * consumed_at IS NULL excludes it. */
    PS_CHECK(ps_token_store_get_by_hash(conn, h3_already_consumed, &row));
    PS_CHECK_EQ_INT(row.consumed_at, 1700000003);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_count_created_since(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    int64_t         user_id = insert_test_user(conn, "dave");

    char          err[256];
    unsigned char h1[PS_TOKEN_HASH_LEN];
    unsigned char h2[PS_TOKEN_HASH_LEN];
    unsigned char h3[PS_TOKEN_HASH_LEN];
    fill_hash(h1, 0x11);
    fill_hash(h2, 0x12);
    fill_hash(h3, 0x13);
    PS_CHECK(ps_token_store_insert(conn, h1, user_id, 1700100000, 1000, err, sizeof err));
    PS_CHECK(ps_token_store_insert(conn, h2, user_id, 1700100000, 2000, err, sizeof err));
    PS_CHECK(ps_token_store_insert(conn, h3, user_id, 1700100000, 3000, err, sizeof err));

    int64_t count = -1;
    PS_CHECK(ps_token_store_count_created_since(conn, user_id, 0, &count));
    PS_CHECK_EQ_INT(count, 3);

    PS_CHECK(ps_token_store_count_created_since(conn, user_id, 2000, &count));
    PS_CHECK_EQ_INT(count, 2);

    PS_CHECK(ps_token_store_count_created_since(conn, user_id, 3001, &count));
    PS_CHECK_EQ_INT(count, 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

int main(void)
{
    PS_RUN_TEST(test_insert_then_get_by_hash_round_trips);
    PS_RUN_TEST(test_get_by_hash_on_missing_token_returns_false);
    PS_RUN_TEST(test_consume_marks_token_and_is_idempotent_on_the_flag);
    PS_RUN_TEST(test_invalidate_all_for_user_only_touches_outstanding_tokens);
    PS_RUN_TEST(test_count_created_since);
    PS_TEST_EXIT();
}
