/*
 * SQLite connection pool and migration runner (plan 5, 3.2).
 *
 * SQLite's own threading model allows many connections to the same
 * database file from different threads concurrently (each connection used
 * by one thread at a time); it does not make one connection object safe to
 * share across threads without external synchronization. The pool exists
 * for exactly that reason: each worker checks out its own connection for
 * the duration of a request and returns it, rather than every request
 * fighting over one shared handle.
 */
#ifndef PS_STORE_DB_H
#define PS_STORE_DB_H

#include <stdbool.h>
#include <stddef.h>

#include <sqlite3.h>

typedef struct ps_db_pool ps_db_pool_t;

/*
 * Opens pool_size connections to db_path, applies WAL journaling and
 * foreign keys on each, and runs any migration not yet recorded in
 * schema_version -- once, using the first connection, inside a
 * transaction. pool_size < 1 means one connection per CPU, mirroring
 * ps_threadpool_create's exact convention. Returns NULL and writes a
 * reason into err on failure.
 */
ps_db_pool_t *ps_db_pool_create(const char *db_path, int pool_size,
                                int busy_timeout_ms, char *err, size_t errlen);

/* Blocks until a connection is available. Every acquire must be matched by
 * exactly one release. */
sqlite3 *ps_db_pool_acquire(ps_db_pool_t *pool);
void     ps_db_pool_release(ps_db_pool_t *pool, sqlite3 *conn);

/* Closes every connection and frees pool. Call only once nothing still
 * holds an acquired connection. */
void ps_db_pool_destroy(ps_db_pool_t *pool);

/*
 * Opens one connection outside the pool, with the same PRAGMAs applied but
 * without running migrations (the pool's creation already applied them) --
 * for the maintenance thread's own dedicated connection (plan 3.4), which
 * deliberately never competes with request-handling workers for a pooled
 * one. Returns NULL and writes a reason into err on failure.
 */
sqlite3 *ps_db_open_standalone(const char *db_path, int busy_timeout_ms,
                               char *err, size_t errlen);

#endif /* PS_STORE_DB_H */
