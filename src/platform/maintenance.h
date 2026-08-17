/*
 * Maintenance sweeper (plan 3.4): one dedicated thread, its own SQLite
 * connection, removing rows that nothing else would ever remove --
 * expired verification tokens, refresh tokens and session families past
 * their absolute expiry, old dev_outbox rows, audit rows past the
 * retention window, and elapsed account lockouts. Runs once at startup
 * and then on a configurable interval.
 */
#ifndef PS_PLATFORM_MAINTENANCE_H
#define PS_PLATFORM_MAINTENANCE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ps_maintenance ps_maintenance_t;

/*
 * Opens its own connection to db_path (independent of any request-serving
 * pool, so a slow sweep never competes with a worker for one) and starts
 * the sweeper thread, which runs one pass immediately before this call
 * returns control to the caller's thread scheduling (the pass itself still
 * runs on the new thread). Returns NULL and writes a reason into err on
 * failure.
 */
ps_maintenance_t *ps_maintenance_start(const char *db_path, int busy_timeout_ms,
                                       int interval_s, int batch_size,
                                       int audit_retention_days,
                                       char *err, size_t errlen);

/* Wakes the sweeper if it's sleeping, waits for its current pass to finish,
 * joins the thread, and closes its connection. */
void ps_maintenance_stop(ps_maintenance_t *m);

#endif /* PS_PLATFORM_MAINTENANCE_H */
