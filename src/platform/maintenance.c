/*
 * This file lives in platform/ per the plan's tree (3.2) but the sweep
 * necessarily touches the database. It depends on store/db.h only for
 * ps_db_open_standalone -- a raw `sqlite3 *` with no business types
 * attached -- and writes its own SQL directly rather than going through
 * user_store.c/audit_store.c's business-shaped APIs, so no business type
 * or query crosses from store/ into platform/. Only the mechanical act of
 * opening a configured connection is shared.
 */
#include "platform/maintenance.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sqlite3.h>

#include "platform/log.h"
#include "store/db.h"

#define SECONDS_PER_DAY (24 * 60 * 60)

struct ps_maintenance {
    pthread_t       thread;
    pthread_mutex_t lock;
    pthread_cond_t  cond; /* CLOCK_MONOTONIC -- plan 3.5: interval measurements never use wall time */
    bool            stop;
    sqlite3        *conn;
    int             interval_s;
    int             batch_size;
    int             audit_retention_days;
};

/*
 * Deletes rows matching where_clause (bound to ? = cutoff) in batches of
 * at most m->batch_size, via a subquery + IN rather than DELETE ... LIMIT
 * -- the LIMIT clause on DELETE is a non-standard SQLite build option this
 * project cannot assume is compiled in. Loops until a batch removes fewer
 * than batch_size rows (nothing left) or shutdown is requested, so a large
 * backlog is still fully cleared within one wake cycle rather than
 * trickling out one batch per hour.
 */
static int sweep_table(ps_maintenance_t *m, const char *table, const char *key_column,
                       const char *where_clause, int64_t cutoff)
{
    char sql[512];
    (void)snprintf(sql, sizeof sql,
                  "DELETE FROM %s WHERE %s IN (SELECT %s FROM %s WHERE %s LIMIT ?)",
                  table, key_column, key_column, table, where_clause);

    /* Always runs at least one batch before ever looking at the stop flag
     * -- a shutdown request racing in right as the sweeper starts must not
     * skip the very first pass (maintenance.h promises one at startup).
     * The stop check only decides whether to keep going after that. */
    int total_removed = 0;
    for (;;) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(m->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
            PS_ERROR("maintenance: prepare sweep of %s: %s", table, sqlite3_errmsg(m->conn));
            break;
        }
        (void)sqlite3_bind_int64(stmt, 1, cutoff);
        (void)sqlite3_bind_int(stmt, 2, m->batch_size);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            PS_ERROR("maintenance: sweep of %s: %s", table, sqlite3_errmsg(m->conn));
            break;
        }

        int changed = sqlite3_changes(m->conn);
        total_removed += changed;
        if (changed < m->batch_size) {
            break;
        }

        (void)pthread_mutex_lock(&m->lock);
        bool stopping = m->stop;
        (void)pthread_mutex_unlock(&m->lock);
        if (stopping) {
            break;
        }
    }
    return total_removed;
}

/*
 * session_families needs two independent cutoffs in one WHERE clause
 * (absolute_exp compared against `now`, revoked_at against `now - 30d`),
 * which sweep_table's single-cutoff signature can't express -- special
 * cased rather than generalizing that helper for its one caller.
 */
static int sweep_session_families(ps_maintenance_t *m, int64_t now)
{
    static const char *sql =
        "DELETE FROM session_families WHERE family_id IN "
        "(SELECT family_id FROM session_families "
        " WHERE absolute_exp < ?1 OR (revoked_at IS NOT NULL AND revoked_at < ?2) LIMIT ?3)";
    int64_t revoked_cutoff = now - 30 * SECONDS_PER_DAY;

    /* Always runs at least one batch before checking stop -- see sweep_table. */
    int total_removed = 0;
    for (;;) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(m->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
            PS_ERROR("maintenance: prepare session_families sweep: %s", sqlite3_errmsg(m->conn));
            break;
        }
        (void)sqlite3_bind_int64(stmt, 1, now);
        (void)sqlite3_bind_int64(stmt, 2, revoked_cutoff);
        (void)sqlite3_bind_int(stmt, 3, m->batch_size);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            PS_ERROR("maintenance: session_families sweep: %s", sqlite3_errmsg(m->conn));
            break;
        }

        int changed = sqlite3_changes(m->conn);
        total_removed += changed;
        if (changed < m->batch_size) {
            break;
        }

        (void)pthread_mutex_lock(&m->lock);
        bool stopping = m->stop;
        (void)pthread_mutex_unlock(&m->lock);
        if (stopping) {
            break;
        }
    }
    return total_removed;
}

/* Same batching discipline as sweep_table, but clearing a column rather
 * than removing rows -- users.locked_until (plan 6.9). Always runs at
 * least one batch before checking stop -- see sweep_table. */
static int sweep_expired_lockouts(ps_maintenance_t *m, int64_t now)
{
    static const char *sql =
        "UPDATE users SET locked_until = NULL, updated_at = ?1 WHERE user_id IN "
        "(SELECT user_id FROM users WHERE locked_until IS NOT NULL AND locked_until < ?1 LIMIT ?2)";

    int total_cleared = 0;
    for (;;) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(m->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
            PS_ERROR("maintenance: prepare lockout sweep: %s", sqlite3_errmsg(m->conn));
            break;
        }
        (void)sqlite3_bind_int64(stmt, 1, now);
        (void)sqlite3_bind_int(stmt, 2, m->batch_size);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            PS_ERROR("maintenance: lockout sweep: %s", sqlite3_errmsg(m->conn));
            break;
        }

        int changed = sqlite3_changes(m->conn);
        total_cleared += changed;
        if (changed < m->batch_size) {
            break;
        }

        (void)pthread_mutex_lock(&m->lock);
        bool stopping = m->stop;
        (void)pthread_mutex_unlock(&m->lock);
        if (stopping) {
            break;
        }
    }
    return total_cleared;
}

static void run_sweep(ps_maintenance_t *m)
{
    int64_t now = time(NULL); /* expiry comparisons use wall time (plan 3.5) */

    int evt = sweep_table(m, "email_verification_tokens", "token_hash",
                          "expires_at < ?", now - SECONDS_PER_DAY);
    int rt  = sweep_table(m, "refresh_tokens", "token_hash",
                          "family_id IN (SELECT family_id FROM session_families WHERE absolute_exp < ?)",
                          now);
    int sf     = sweep_session_families(m, now);
    int outbox = sweep_table(m, "dev_outbox", "id", "created_at < ?", now - 7 * SECONDS_PER_DAY);
    /* The one exception to "audit_log is append-only" (plan 6.10): the
     * retention sweep. tools/check_banned_functions.sh's audit-log check
     * allows this file to reference "audit_log" as a table name; nothing
     * else in src/ may. */
    int audit = sweep_table(m, "audit_log", "id", "occurred_at < ?",
                            now - (int64_t)m->audit_retention_days * SECONDS_PER_DAY);
    int locks = sweep_expired_lockouts(m, now);

    if (evt || rt || sf || outbox || audit || locks) {
        PS_INFO("maintenance sweep: %d verification tokens, %d refresh tokens, "
                "%d session families, %d outbox rows, %d audit rows, %d lockouts cleared",
                evt, rt, sf, outbox, audit, locks);
    }
}

static void *maintenance_main(void *arg)
{
    ps_maintenance_t *m = arg;

    for (;;) {
        run_sweep(m);

        (void)pthread_mutex_lock(&m->lock);
        if (!m->stop) {
            struct timespec deadline;
            (void)clock_gettime(CLOCK_MONOTONIC, &deadline);
            deadline.tv_sec += m->interval_s;
            (void)pthread_cond_timedwait(&m->cond, &m->lock, &deadline);
        }
        bool stopping = m->stop;
        (void)pthread_mutex_unlock(&m->lock);
        if (stopping) {
            break;
        }
    }
    return NULL;
}

ps_maintenance_t *ps_maintenance_start(const char *db_path, int busy_timeout_ms,
                                       int interval_s, int batch_size,
                                       int audit_retention_days,
                                       char *err, size_t errlen)
{
    ps_maintenance_t *m = calloc(1, sizeof *m);
    if (m == NULL) {
        (void)snprintf(err, errlen, "out of memory");
        return NULL;
    }

    m->conn = ps_db_open_standalone(db_path, busy_timeout_ms, err, errlen);
    if (m->conn == NULL) {
        free(m);
        return NULL;
    }

    m->interval_s            = interval_s;
    m->batch_size            = batch_size;
    m->audit_retention_days  = audit_retention_days;
    m->stop                  = false;

    if (pthread_mutex_init(&m->lock, NULL) != 0) {
        (void)snprintf(err, errlen, "pthread_mutex_init failed");
        sqlite3_close(m->conn);
        free(m);
        return NULL;
    }

    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) != 0 ||
        pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0 ||
        pthread_cond_init(&m->cond, &attr) != 0) {
        (void)snprintf(err, errlen, "failed to initialize monotonic condition variable");
        (void)pthread_condattr_destroy(&attr);
        (void)pthread_mutex_destroy(&m->lock);
        sqlite3_close(m->conn);
        free(m);
        return NULL;
    }
    (void)pthread_condattr_destroy(&attr);

    if (pthread_create(&m->thread, NULL, maintenance_main, m) != 0) {
        (void)snprintf(err, errlen, "pthread_create failed");
        (void)pthread_mutex_destroy(&m->lock);
        (void)pthread_cond_destroy(&m->cond);
        sqlite3_close(m->conn);
        free(m);
        return NULL;
    }

    return m;
}

void ps_maintenance_stop(ps_maintenance_t *m)
{
    if (m == NULL) {
        return;
    }
    (void)pthread_mutex_lock(&m->lock);
    m->stop = true;
    (void)pthread_cond_signal(&m->cond);
    (void)pthread_mutex_unlock(&m->lock);

    (void)pthread_join(m->thread, NULL);
    (void)pthread_mutex_destroy(&m->lock);
    (void)pthread_cond_destroy(&m->cond);
    sqlite3_close(m->conn);
    free(m);
}
