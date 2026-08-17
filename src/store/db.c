#include "store/db.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "generated/schema_001_init.h"

struct ps_db_pool {
    sqlite3        **conns;      /* every connection this pool owns, size `size` */
    sqlite3        **free_stack; /* currently-available connections */
    int              size;
    int              free_count;
    pthread_mutex_t  lock;
    pthread_cond_t   not_empty;
};

static bool configure_connection(sqlite3 *conn, int busy_timeout_ms, char *err, size_t errlen)
{
    char *errmsg = NULL;
    if (sqlite3_exec(conn, "PRAGMA journal_mode=WAL;", NULL, NULL, &errmsg) != SQLITE_OK) {
        (void)snprintf(err, errlen, "PRAGMA journal_mode: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        return false;
    }
    if (sqlite3_exec(conn, "PRAGMA foreign_keys=ON;", NULL, NULL, &errmsg) != SQLITE_OK) {
        (void)snprintf(err, errlen, "PRAGMA foreign_keys: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        return false;
    }
    sqlite3_busy_timeout(conn, busy_timeout_ms);
    return true;
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

static int current_schema_version(sqlite3 *conn)
{
    if (!table_exists(conn, "schema_version")) {
        return 0;
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, "SELECT MAX(version) FROM schema_version", -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    int version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        version = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return version;
}

/* Applies every migration not yet recorded in schema_version, in order,
 * each inside its own transaction (plan 5). There is exactly one migration
 * today; the version check and the per-migration transaction are already
 * shaped for a second one to be added as a new `if` block below, not a
 * rewrite. */
static bool run_migrations(sqlite3 *conn, char *err, size_t errlen)
{
    int version = current_schema_version(conn);
    if (version >= 1) {
        return true;
    }

    char *errmsg = NULL;
    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        (void)snprintf(err, errlen, "BEGIN: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        return false;
    }
    if (sqlite3_exec(conn, PS_SCHEMA_001_INIT, NULL, NULL, &errmsg) != SQLITE_OK) {
        (void)snprintf(err, errlen, "migration 001_init: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        return false;
    }
    if (sqlite3_exec(conn, "COMMIT;", NULL, NULL, &errmsg) != SQLITE_OK) {
        (void)snprintf(err, errlen, "COMMIT: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        return false;
    }
    return true;
}

sqlite3 *ps_db_open_standalone(const char *db_path, int busy_timeout_ms, char *err, size_t errlen)
{
    sqlite3 *conn = NULL;
    if (sqlite3_open_v2(db_path, &conn, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "sqlite3_open_v2(%s): %s", db_path,
                       conn ? sqlite3_errmsg(conn) : "unknown error");
        sqlite3_close(conn);
        return NULL;
    }
    if (!configure_connection(conn, busy_timeout_ms, err, errlen)) {
        sqlite3_close(conn);
        return NULL;
    }
    return conn;
}

ps_db_pool_t *ps_db_pool_create(const char *db_path, int pool_size,
                                int busy_timeout_ms, char *err, size_t errlen)
{
    /* pool_size < 1 means one connection per CPU, mirroring
     * ps_threadpool_create's exact convention -- main.c passes
     * cfg.worker_threads (which may be 0, "auto") to both and lets each
     * resolve it independently rather than plumbing the resolved count
     * from one to the other. */
    if (pool_size < 1) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        pool_size = (n < 1) ? 1 : (int)n;
    }

    ps_db_pool_t *pool = calloc(1, sizeof *pool);
    if (pool == NULL) {
        (void)snprintf(err, errlen, "out of memory");
        return NULL;
    }

    pool->conns      = calloc((size_t)pool_size, sizeof *pool->conns);
    pool->free_stack = calloc((size_t)pool_size, sizeof *pool->free_stack);
    if (pool->conns == NULL || pool->free_stack == NULL) {
        (void)snprintf(err, errlen, "out of memory");
        free(pool->conns);
        free(pool->free_stack);
        free(pool);
        return NULL;
    }
    pool->size = pool_size;

    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        (void)snprintf(err, errlen, "pthread_mutex_init failed");
        free(pool->conns);
        free(pool->free_stack);
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&pool->not_empty, NULL) != 0) {
        (void)snprintf(err, errlen, "pthread_cond_init failed");
        (void)pthread_mutex_destroy(&pool->lock);
        free(pool->conns);
        free(pool->free_stack);
        free(pool);
        return NULL;
    }

    for (int i = 0; i < pool_size; i++) {
        sqlite3 *conn = ps_db_open_standalone(db_path, busy_timeout_ms, err, errlen);
        if (conn == NULL) {
            for (int j = 0; j < i; j++) {
                sqlite3_close(pool->conns[j]);
            }
            (void)pthread_mutex_destroy(&pool->lock);
            (void)pthread_cond_destroy(&pool->not_empty);
            free(pool->conns);
            free(pool->free_stack);
            free(pool);
            return NULL;
        }
        pool->conns[i]      = conn;
        pool->free_stack[i] = conn;
    }
    pool->free_count = pool_size;

    if (!run_migrations(pool->conns[0], err, errlen)) {
        for (int j = 0; j < pool_size; j++) {
            sqlite3_close(pool->conns[j]);
        }
        (void)pthread_mutex_destroy(&pool->lock);
        (void)pthread_cond_destroy(&pool->not_empty);
        free(pool->conns);
        free(pool->free_stack);
        free(pool);
        return NULL;
    }

    return pool;
}

sqlite3 *ps_db_pool_acquire(ps_db_pool_t *pool)
{
    (void)pthread_mutex_lock(&pool->lock);
    while (pool->free_count == 0) {
        (void)pthread_cond_wait(&pool->not_empty, &pool->lock);
    }
    sqlite3 *conn = pool->free_stack[--pool->free_count];
    (void)pthread_mutex_unlock(&pool->lock);
    return conn;
}

void ps_db_pool_release(ps_db_pool_t *pool, sqlite3 *conn)
{
    (void)pthread_mutex_lock(&pool->lock);
    pool->free_stack[pool->free_count++] = conn;
    (void)pthread_cond_signal(&pool->not_empty);
    (void)pthread_mutex_unlock(&pool->lock);
}

void ps_db_pool_destroy(ps_db_pool_t *pool)
{
    if (pool == NULL) {
        return;
    }
    for (int i = 0; i < pool->size; i++) {
        sqlite3_close(pool->conns[i]);
    }
    (void)pthread_mutex_destroy(&pool->lock);
    (void)pthread_cond_destroy(&pool->not_empty);
    free(pool->conns);
    free(pool->free_stack);
    free(pool);
}
