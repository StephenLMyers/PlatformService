#include "testutil.h"

#include <unistd.h>

#include <sqlite3.h>

#include "mail/mailer.h"
#include "store/db.h"

static const char *const TEST_DB_PATH = "build/test-scratch-mailer.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-mailer.sqlite3-wal");
    (void)unlink("build/test-scratch-mailer.sqlite3-shm");
    (void)unlink("build/test-scratch-mailer.sqlite3-journal");
}

static ps_db_pool_t *open_fresh_pool(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    return pool;
}

static void test_send_writes_to_dev_outbox(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_mail_message_t msg = { .to_email = "alice@example.com", .subject = "Hello",
                              .body = "This is the body." };
    char err[256];
    PS_CHECK(ps_mailer_send(conn, &msg, 1700000000, err, sizeof err));

    sqlite3_stmt *stmt = NULL;
    PS_CHECK(sqlite3_prepare_v2(conn, "SELECT to_email, subject, body, created_at FROM dev_outbox",
                                -1, &stmt, NULL) == SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    PS_CHECK_STR_EQ((const char *)sqlite3_column_text(stmt, 0), "alice@example.com");
    PS_CHECK_STR_EQ((const char *)sqlite3_column_text(stmt, 1), "Hello");
    PS_CHECK_STR_EQ((const char *)sqlite3_column_text(stmt, 2), "This is the body.");
    PS_CHECK_EQ_INT(sqlite3_column_int64(stmt, 3), 1700000000);
    sqlite3_finalize(stmt);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_multiple_sends_all_persist(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    char           err[256];

    for (int i = 0; i < 3; i++) {
        ps_mail_message_t msg = { .to_email = "bob@example.com", .subject = "Subject",
                                  .body = "Body" };
        PS_CHECK(ps_mailer_send(conn, &msg, 1700000000 + i, err, sizeof err));
    }

    sqlite3_stmt *stmt = NULL;
    PS_CHECK(sqlite3_prepare_v2(conn, "SELECT COUNT(*) FROM dev_outbox", -1, &stmt, NULL) ==
            SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    PS_CHECK_EQ_INT(sqlite3_column_int64(stmt, 0), 3);
    sqlite3_finalize(stmt);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_send_composes_into_a_larger_caller_managed_transaction(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    char           err[256];

    PS_CHECK(sqlite3_exec(conn, "BEGIN;", NULL, NULL, NULL) == SQLITE_OK);
    ps_mail_message_t msg = { .to_email = "x@x", .subject = "s", .body = "b" };
    PS_CHECK(ps_mailer_send(conn, &msg, 1700000000, err, sizeof err));
    PS_CHECK(sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK);

    sqlite3_stmt *stmt = NULL;
    PS_CHECK(sqlite3_prepare_v2(conn, "SELECT COUNT(*) FROM dev_outbox", -1, &stmt, NULL) ==
            SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    PS_CHECK_EQ_INT(sqlite3_column_int64(stmt, 0), 0); /* rolled back along with the rest */
    sqlite3_finalize(stmt);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

int main(void)
{
    PS_RUN_TEST(test_send_writes_to_dev_outbox);
    PS_RUN_TEST(test_multiple_sends_all_persist);
    PS_RUN_TEST(test_send_composes_into_a_larger_caller_managed_transaction);
    PS_TEST_EXIT();
}
