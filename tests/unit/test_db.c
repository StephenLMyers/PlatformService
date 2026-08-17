#include "testutil.h"

#include <unistd.h>

#include <sqlite3.h>

#include "store/db.h"

static const char *const TEST_DB_PATH = "build/test-scratch-db.sqlite3";

static void remove_scratch_db(void)
{
    (void)unlink(TEST_DB_PATH);
    (void)unlink("build/test-scratch-db.sqlite3-wal");
    (void)unlink("build/test-scratch-db.sqlite3-shm");
    (void)unlink("build/test-scratch-db.sqlite3-journal");
}

static bool table_exists(sqlite3 *conn, const char *name)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    bool exists = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return exists;
}

static void test_create_applies_migration_and_seeds_roles(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 2, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    if (pool == NULL) {
        return;
    }

    sqlite3 *conn = ps_db_pool_acquire(pool);
    PS_CHECK(table_exists(conn, "users"));
    PS_CHECK(table_exists(conn, "audit_log"));
    PS_CHECK(table_exists(conn, "schema_version"));

    sqlite3_stmt *stmt = NULL;
    PS_CHECK(sqlite3_prepare_v2(conn, "SELECT MAX(version) FROM schema_version", -1, &stmt, NULL) ==
            SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    PS_CHECK_EQ_INT(sqlite3_column_int(stmt, 0), 1);
    sqlite3_finalize(stmt);

    PS_CHECK(sqlite3_prepare_v2(conn, "SELECT COUNT(*) FROM roles", -1, &stmt, NULL) == SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    PS_CHECK_EQ_INT(sqlite3_column_int(stmt, 0), 2);
    sqlite3_finalize(stmt);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_reopening_an_already_migrated_db_succeeds(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *first = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(first != NULL);
    ps_db_pool_destroy(first);

    /* Second open must not try to re-run migration 1 (it would fail on
     * "table users already exists" if it did). */
    ps_db_pool_t *second = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(second != NULL);
    if (second != NULL) {
        ps_db_pool_destroy(second);
    }
}

static void test_pool_size_zero_resolves_to_at_least_one_connection(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 0, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    if (pool == NULL) {
        return;
    }
    /* If the pool has zero usable connections, acquire would hang forever;
     * this only returns because at least one connection exists. */
    sqlite3 *conn = ps_db_pool_acquire(pool);
    PS_CHECK(conn != NULL);
    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_acquire_release_cycle_reuses_connections(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    if (pool == NULL) {
        return;
    }

    sqlite3 *first = ps_db_pool_acquire(pool);
    ps_db_pool_release(pool, first);
    sqlite3 *second = ps_db_pool_acquire(pool);
    PS_CHECK(first == second); /* pool size 1: must be the same connection */
    ps_db_pool_release(pool, second);

    ps_db_pool_destroy(pool);
}

static void test_foreign_keys_and_wal_are_enabled(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    if (pool == NULL) {
        return;
    }
    sqlite3 *conn = ps_db_pool_acquire(pool);

    sqlite3_stmt *stmt = NULL;
    PS_CHECK(sqlite3_prepare_v2(conn, "PRAGMA foreign_keys", -1, &stmt, NULL) == SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    PS_CHECK_EQ_INT(sqlite3_column_int(stmt, 0), 1);
    sqlite3_finalize(stmt);

    PS_CHECK(sqlite3_prepare_v2(conn, "PRAGMA journal_mode", -1, &stmt, NULL) == SQLITE_OK);
    PS_CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    PS_CHECK_STR_EQ((const char *)sqlite3_column_text(stmt, 0), "wal");
    sqlite3_finalize(stmt);

    ps_db_pool_release(pool, conn);
    ps_db_pool_destroy(pool);
}

static void test_open_standalone_connects_to_already_migrated_db(void)
{
    remove_scratch_db();
    char err[256];
    ps_db_pool_t *pool = ps_db_pool_create(TEST_DB_PATH, 1, 1000, err, sizeof err);
    PS_CHECK(pool != NULL);
    ps_db_pool_destroy(pool);

    sqlite3 *standalone = ps_db_open_standalone(TEST_DB_PATH, 1000, err, sizeof err);
    PS_CHECK(standalone != NULL);
    if (standalone != NULL) {
        PS_CHECK(table_exists(standalone, "users"));
        sqlite3_close(standalone);
    }
}

int main(void)
{
    PS_RUN_TEST(test_create_applies_migration_and_seeds_roles);
    PS_RUN_TEST(test_reopening_an_already_migrated_db_succeeds);
    PS_RUN_TEST(test_pool_size_zero_resolves_to_at_least_one_connection);
    PS_RUN_TEST(test_acquire_release_cycle_reuses_connections);
    PS_RUN_TEST(test_foreign_keys_and_wal_are_enabled);
    PS_RUN_TEST(test_open_standalone_connects_to_already_migrated_db);
    PS_TEST_EXIT();
}
