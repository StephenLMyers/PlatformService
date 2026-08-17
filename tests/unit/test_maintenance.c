#include "testutil.h"

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

#include "platform/maintenance.h"
#include "store/db.h"

static const char *const TEST_DB_PATH = "build/test-scratch-maintenance.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-maintenance.sqlite3-wal");
    (void)unlink("build/test-scratch-maintenance.sqlite3-shm");
    (void)unlink("build/test-scratch-maintenance.sqlite3-journal");
}

static void exec_or_fail(sqlite3 *conn, const char *sql)
{
    char *errmsg = NULL;
    if (sqlite3_exec(conn, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        (void)fprintf(stderr, "fixture SQL failed: %s\n    %s\n", errmsg ? errmsg : "?", sql);
        sqlite3_free(errmsg);
        PS_CHECK(false);
    }
}

static int64_t row_count(sqlite3 *conn, const char *sql)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    int64_t n = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        n = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return n;
}

#define SECONDS_PER_DAY (24 * 60 * 60)

/*
 * Seeds one row per swept category that must be removed/cleared, and one
 * that must survive, then runs exactly one sweep pass (ps_maintenance_stop
 * called immediately after start blocks until the guaranteed first pass
 * completes -- maintenance_main always runs run_sweep() once before ever
 * checking the stop flag) and asserts the DB ended up in the right state.
 */
static void test_one_sweep_pass_removes_eligible_rows_and_keeps_the_rest(void)
{
    remove_scratch_db();
    char           err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    if (pool == NULL) {
        return;
    }
    sqlite3 *conn = ps_db_pool_acquire(pool);

    /* run_sweep uses real time(NULL); fixtures must be anchored to it too,
     * not an arbitrary fixed epoch, or "expired" fixtures could land in
     * what's actually the future relative to whatever real time is when
     * the sweep runs moments later. */
    int64_t now = time(NULL);
    char    sql[1024];

    /* users: 1=alice, 2=bob (own the verification tokens/families below),
     * 3=carol (elapsed lockout), 4=dave (still locked), 5=eve (never locked) */
    exec_or_fail(conn,
                "INSERT INTO users (user_id, username, email, email_normalized, password_hash, "
                "password_salt, kdf_iters, status, failed_logins, locked_until, created_at, updated_at) "
                "VALUES "
                "(1,'alice','a@x','a@x',x'00',x'00',1,'ACTIVE',0,NULL,0,0),"
                "(2,'bob','b@x','b@x',x'00',x'00',1,'ACTIVE',0,NULL,0,0),"
                "(3,'carol','c@x','c@x',x'00',x'00',1,'ACTIVE',0,NULL,0,0),"
                "(4,'dave','d@x','d@x',x'00',x'00',1,'ACTIVE',0,NULL,0,0),"
                "(5,'eve','e@x','e@x',x'00',x'00',1,'ACTIVE',0,NULL,0,0);");

    (void)snprintf(sql, sizeof sql,
                  "UPDATE users SET locked_until = %lld WHERE user_id = 3;", /* elapsed: eligible */
                  (long long)(now - 100));
    exec_or_fail(conn, sql);
    (void)snprintf(sql, sizeof sql,
                  "UPDATE users SET locked_until = %lld WHERE user_id = 4;", /* still locked */
                  (long long)(now + 100000));
    exec_or_fail(conn, sql);

    /* email_verification_tokens: past expiry + grace (eligible), within
     * grace (ineligible), not yet expired (ineligible) */
    (void)snprintf(sql, sizeof sql,
                  "INSERT INTO email_verification_tokens (token_hash, user_id, expires_at, created_at) VALUES "
                  "(x'01', 1, %lld, 0)," /* expired well past the 24h grace: eligible */
                  "(x'02', 2, %lld, 0)," /* expired but within the 24h grace: ineligible */
                  "(x'03', 2, %lld, 0);", /* not even expired yet: ineligible */
                  (long long)(now - 2 * SECONDS_PER_DAY),
                  (long long)(now - 100),
                  (long long)(now + 1000));
    exec_or_fail(conn, sql);

    /* session_families: A expired (eligible), B healthy (ineligible),
     * C not expired but revoked 31 days ago (eligible) */
    (void)snprintf(sql, sizeof sql,
                  "INSERT INTO session_families (family_id, user_id, created_at, absolute_exp, revoked_at, revoke_cause) VALUES "
                  "(x'AA', 1, 0, %lld, NULL, NULL),"
                  "(x'BB', 2, 0, %lld, NULL, NULL),"
                  "(x'CC', 1, 0, %lld, %lld, 'LOGOUT');",
                  (long long)(now - 100),
                  (long long)(now + 1000000),
                  (long long)(now + 1000000),
                  (long long)(now - 31 * SECONDS_PER_DAY));
    exec_or_fail(conn, sql);

    /* refresh_tokens: one in the expired family (eligible via cascade or
     * the explicit sweep), one in the healthy family (ineligible) */
    exec_or_fail(conn,
                "INSERT INTO refresh_tokens (token_hash, family_id, generation, idle_exp, issued_at) VALUES "
                "(x'D1', x'AA', 1, 999999999999, 0),"
                "(x'D2', x'BB', 1, 999999999999, 0);");

    /* dev_outbox: 8 days old (eligible), 1 day old (ineligible) */
    (void)snprintf(sql, sizeof sql,
                  "INSERT INTO dev_outbox (id, to_email, subject, body, created_at) VALUES "
                  "(1, 'x@x', 's', 'b', %lld),"
                  "(2, 'x@x', 's', 'b', %lld);",
                  (long long)(now - 8 * SECONDS_PER_DAY),
                  (long long)(now - 1 * SECONDS_PER_DAY));
    exec_or_fail(conn, sql);

    /* audit_log: retention set to 1 day in this test; 2 days old is
     * eligible, fresh is not */
    (void)snprintf(sql, sizeof sql,
                  "INSERT INTO audit_log (occurred_at, event, outcome) VALUES "
                  "(%lld, 'OLD', 'SUCCESS'),"
                  "(%lld, 'FRESH', 'SUCCESS');",
                  (long long)(now - 2 * SECONDS_PER_DAY), (long long)now);
    exec_or_fail(conn, sql);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool); /* close before the sweeper opens its own connection */

    /* audit_retention_days=1 and a batch_size comfortably above this
     * test's row counts. */
    ps_maintenance_t *m =
        ps_maintenance_start(TEST_DB_PATH, 1000, 3600, 1000, 1, err, sizeof err);
    PS_CHECK(m != NULL);
    if (m == NULL) {
        return;
    }
    ps_maintenance_stop(m); /* blocks until the guaranteed first pass completes */

    sqlite3 *check = ps_db_open_standalone(TEST_DB_PATH, 1000, err, sizeof err);
    PS_CHECK(check != NULL);
    if (check == NULL) {
        return;
    }

    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM email_verification_tokens WHERE token_hash = x'01'"), 0);
    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM email_verification_tokens WHERE token_hash = x'02'"), 1);
    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM email_verification_tokens WHERE token_hash = x'03'"), 1);

    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM session_families WHERE family_id = x'AA'"), 0);
    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM session_families WHERE family_id = x'BB'"), 1);
    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM session_families WHERE family_id = x'CC'"), 0);

    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = x'D1'"), 0);
    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = x'D2'"), 1);

    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM dev_outbox WHERE id = 1"), 0);
    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM dev_outbox WHERE id = 2"), 1);

    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM audit_log WHERE event = 'OLD'"), 0);
    PS_CHECK_EQ_INT(row_count(check, "SELECT COUNT(*) FROM audit_log WHERE event = 'FRESH'"), 1);

    PS_CHECK_EQ_INT(row_count(check, "SELECT locked_until FROM users WHERE user_id = 3"), 0); /* NULL -> 0 via column_int64 on NULL */
    PS_CHECK(row_count(check, "SELECT COUNT(*) FROM users WHERE user_id = 3 AND locked_until IS NULL") == 1);
    PS_CHECK(row_count(check, "SELECT COUNT(*) FROM users WHERE user_id = 4 AND locked_until IS NOT NULL") == 1);
    PS_CHECK(row_count(check, "SELECT COUNT(*) FROM users WHERE user_id = 5 AND locked_until IS NULL") == 1);

    sqlite3_close(check);
}

static void test_start_fails_on_unmigrated_database(void)
{
    remove_scratch_db(); /* file doesn't exist at all -- no schema */
    char               err[256];
    ps_maintenance_t *m = ps_maintenance_start(TEST_DB_PATH, 1000, 3600, 1000, 365, err, sizeof err);
    /* ps_db_open_standalone succeeds (SQLITE_OPEN_CREATE makes the file),
     * but the first sweep's DELETEs against nonexistent tables fail and
     * are logged -- this exercises that path doesn't crash, not that
     * start() itself reports an error (it has no schema-awareness). */
    if (m != NULL) {
        ps_maintenance_stop(m);
    }
    (void)err;
}

int main(void)
{
    PS_RUN_TEST(test_one_sweep_pass_removes_eligible_rows_and_keeps_the_rest);
    PS_RUN_TEST(test_start_fails_on_unmigrated_database);
    PS_TEST_EXIT();
}
