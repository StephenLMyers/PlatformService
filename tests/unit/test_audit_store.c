#include "testutil.h"

#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "store/audit_store.h"
#include "store/db.h"

static const char *const TEST_DB_PATH = "build/test-scratch-audit-store.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-audit-store.sqlite3-wal");
    (void)unlink("build/test-scratch-audit-store.sqlite3-shm");
    (void)unlink("build/test-scratch-audit-store.sqlite3-journal");
}

static ps_db_pool_t *open_fresh_pool(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    return pool;
}

static ps_audit_entry_t minimal_entry(const char *event, const char *outcome)
{
    ps_audit_entry_t e;
    memset(&e, 0, sizeof e);
    e.occurred_at = 1700000000;
    (void)snprintf(e.event, sizeof e.event, "%s", event);
    (void)snprintf(e.outcome, sizeof e.outcome, "%s", outcome);
    return e;
}

static void test_write_then_get_by_id_round_trips_full_entry(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_audit_entry_t e = minimal_entry("LOGIN", "SUCCESS");
    e.has_actor_user_id  = true;
    e.actor_user_id       = 42;
    e.has_target_user_id  = true;
    e.target_user_id       = 42;
    e.has_source_ip        = true;
    (void)snprintf(e.source_ip, sizeof e.source_ip, "203.0.113.7");
    e.has_request_id = true;
    (void)snprintf(e.request_id, sizeof e.request_id, "req-abc123");
    e.has_detail = true;
    (void)snprintf(e.detail, sizeof e.detail, "{\"reason\":\"n/a\"}");

    char err[256];
    PS_CHECK(ps_audit_store_write(conn, &e, err, sizeof err));

    sqlite3_stmt *stmt = NULL;
    PS_CHECK(sqlite3_prepare_v2(conn, "SELECT id FROM audit_log", -1, &stmt, NULL) == SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    int64_t id = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    ps_audit_entry_t out;
    PS_CHECK(ps_audit_store_get_by_id(conn, id, &out));
    PS_CHECK_EQ_INT(out.occurred_at, 1700000000);
    PS_CHECK_STR_EQ(out.event, "LOGIN");
    PS_CHECK_STR_EQ(out.outcome, "SUCCESS");
    PS_CHECK(out.has_actor_user_id);
    PS_CHECK_EQ_INT(out.actor_user_id, 42);
    PS_CHECK(out.has_target_user_id);
    PS_CHECK_EQ_INT(out.target_user_id, 42);
    PS_CHECK(out.has_source_ip);
    PS_CHECK_STR_EQ(out.source_ip, "203.0.113.7");
    PS_CHECK(out.has_request_id);
    PS_CHECK_STR_EQ(out.request_id, "req-abc123");
    PS_CHECK(out.has_detail);
    PS_CHECK_STR_EQ(out.detail, "{\"reason\":\"n/a\"}");

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_nullable_fields_round_trip_as_absent(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    /* REGISTER: no actor, no source_ip/request_id/detail supplied. */
    ps_audit_entry_t e = minimal_entry("REGISTER", "SUCCESS");
    e.has_target_user_id = true;
    e.target_user_id      = 7;

    char err[256];
    PS_CHECK(ps_audit_store_write(conn, &e, err, sizeof err));

    sqlite3_stmt *stmt = NULL;
    PS_CHECK(sqlite3_prepare_v2(conn, "SELECT id FROM audit_log", -1, &stmt, NULL) == SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    int64_t id = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    ps_audit_entry_t out;
    PS_CHECK(ps_audit_store_get_by_id(conn, id, &out));
    PS_CHECK(!out.has_actor_user_id);
    PS_CHECK(out.has_target_user_id);
    PS_CHECK_EQ_INT(out.target_user_id, 7);
    PS_CHECK(!out.has_source_ip);
    PS_CHECK(!out.has_request_id);
    PS_CHECK(!out.has_detail);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_get_by_id_on_missing_row_returns_false(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);

    ps_audit_entry_t out;
    PS_CHECK(!ps_audit_store_get_by_id(conn, 999999, &out));

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_count_by_event(void)
{
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    char           err[256];

    ps_audit_entry_t login_ok   = minimal_entry("LOGIN", "SUCCESS");
    ps_audit_entry_t login_fail = minimal_entry("LOGIN", "FAILURE");
    ps_audit_entry_t reg        = minimal_entry("REGISTER", "SUCCESS");

    PS_CHECK(ps_audit_store_write(conn, &login_ok, err, sizeof err));
    PS_CHECK(ps_audit_store_write(conn, &login_fail, err, sizeof err));
    PS_CHECK(ps_audit_store_write(conn, &reg, err, sizeof err));

    int64_t count = -1;
    PS_CHECK(ps_audit_store_count_by_event(conn, "LOGIN", &count));
    PS_CHECK_EQ_INT(count, 2);

    PS_CHECK(ps_audit_store_count_by_event(conn, "REGISTER", &count));
    PS_CHECK_EQ_INT(count, 1);

    PS_CHECK(ps_audit_store_count_by_event(conn, "NO_SUCH_EVENT", &count));
    PS_CHECK_EQ_INT(count, 0);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_write_composes_into_a_larger_caller_managed_transaction(void)
{
    /* plan 6.10: an audit write for a state change shares the transaction
     * with the change itself. ps_audit_store_write issues no BEGIN/COMMIT
     * of its own, so a caller-managed transaction wrapping it (and some
     * other write) must roll both back together on failure. */
    ps_db_pool_t *pool = open_fresh_pool();
    sqlite3       *conn = ps_db_pool_acquire(pool);
    char           err[256];

    PS_CHECK(sqlite3_exec(conn, "BEGIN;", NULL, NULL, NULL) == SQLITE_OK);
    ps_audit_entry_t e = minimal_entry("LOGIN", "SUCCESS");
    PS_CHECK(ps_audit_store_write(conn, &e, err, sizeof err));
    PS_CHECK(sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK);

    int64_t count = -1;
    PS_CHECK(ps_audit_store_count_by_event(conn, "LOGIN", &count));
    PS_CHECK_EQ_INT(count, 0); /* rolled back along with the rest of the transaction */

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

int main(void)
{
    PS_RUN_TEST(test_write_then_get_by_id_round_trips_full_entry);
    PS_RUN_TEST(test_nullable_fields_round_trip_as_absent);
    PS_RUN_TEST(test_get_by_id_on_missing_row_returns_false);
    PS_RUN_TEST(test_count_by_event);
    PS_RUN_TEST(test_write_composes_into_a_larger_caller_managed_transaction);
    PS_TEST_EXIT();
}
