/*
 * Bounded worker pool: a fixed ring of pending jobs drained by N worker
 * threads (plan 3.3). Submission never blocks waiting for room -- a full
 * queue is backpressure, and the caller turns that into 503, never into a
 * queue that grows without bound.
 */
#ifndef PS_PLATFORM_THREADPOOL_H
#define PS_PLATFORM_THREADPOOL_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ps_threadpool ps_threadpool_t;

typedef void (*ps_job_fn)(void *arg);

/*
 * n_workers < 1 means one worker per CPU (sysconf(_SC_NPROCESSORS_ONLN),
 * falling back to 1). queue_capacity must be at least 1.
 * Returns NULL and writes a reason into err on failure.
 */
ps_threadpool_t *ps_threadpool_create(int n_workers, int queue_capacity,
                                      char *err, size_t errlen);

/*
 * Enqueue fn(arg) to run on a worker thread. Returns false immediately,
 * without blocking, if the queue is full or shutdown has been requested.
 */
bool ps_threadpool_submit(ps_threadpool_t *pool, ps_job_fn fn, void *arg);

/*
 * Stop accepting new submissions (further ps_threadpool_submit calls return
 * false). If drain is true, every already-queued job still runs before
 * workers exit; if false, queued-but-not-started jobs are discarded and only
 * jobs already in flight finish. Call exactly once, then ps_threadpool_destroy.
 */
void ps_threadpool_shutdown(ps_threadpool_t *pool, bool drain);

/* Joins every worker thread and frees the pool. Call after shutdown. */
void ps_threadpool_destroy(ps_threadpool_t *pool);

/*
 * Like ps_threadpool_destroy, but gives up waiting after timeout_s seconds
 * total (not per worker). Call ps_threadpool_shutdown first, exactly as for
 * ps_threadpool_destroy.
 *
 * Returns true if every worker joined in time, in which case pool has been
 * freed exactly as ps_threadpool_destroy would. Returns false if the
 * deadline passed first, in which case pool is deliberately NOT freed and
 * must never be used or destroyed again -- some workers are still running.
 * This is safe only because the intended caller is a bounded graceful
 * shutdown (plan 7.2a) that proceeds straight to process exit either way;
 * the leaked pool is reclaimed by the OS along with everything else, and
 * nothing is ever freed out from under a still-running worker.
 */
bool ps_threadpool_destroy_timed(ps_threadpool_t *pool, int timeout_s);

/* Jobs currently queued (not yet started running). For tests/diagnostics. */
size_t ps_threadpool_queue_length(ps_threadpool_t *pool);

#endif /* PS_PLATFORM_THREADPOOL_H */
