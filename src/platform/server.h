/*
 * Ties the listener, TLS context, thread pool, and connection loop together
 * into the actual accept-and-dispatch loop, plus the bounded shutdown
 * sequence (plan 7.2a steps 2-3: stop accepting, drain in-flight work within
 * a grace period). Steps 1 (/readyz) and 4 (DB checkpoint, SSL_CTX free)
 * belong to later phases and are not this module's concern.
 */
#ifndef PS_PLATFORM_SERVER_H
#define PS_PLATFORM_SERVER_H

#include <stdbool.h>

#include <openssl/ssl.h>

#include "platform/conn.h"
#include "platform/net.h"
#include "platform/threadpool.h"

typedef struct {
    ps_listener_t     listener;
    SSL_CTX           *tls_ctx;   /* not owned by ps_server_t; caller creates/frees it */
    ps_threadpool_t   *pool;      /* owned once ps_server_shutdown returns true; see below */
    ps_conn_limits_t   conn_limits;
} ps_server_t;

/*
 * Runs the accept loop on the calling thread: pulls connections from the
 * already-open listener and dispatches each to pool as a job running
 * ps_conn_handle. A queue-full submission is backpressure (plan 3.3) --
 * without an HTTP layer yet to answer 503, the only correct move is to
 * close the connection rather than block or grow the queue.
 *
 * Returns once ps_listener_stop has been called (from any thread) and the
 * loop observes PS_ACCEPT_SHUTDOWN, or on a fatal accept error. Intended to
 * run on a dedicated acceptor thread.
 */
void ps_server_run(ps_server_t *server);

/*
 * Signals the listener to stop (ps_server_run's accept loop observes
 * PS_ACCEPT_SHUTDOWN and returns; no new connections accepted from this
 * point), then waits up to grace_period_s for every already-accepted
 * connection to finish -- never longer.
 *
 * Deliberately does NOT close the listener's file descriptors. Only the
 * caller knows when the acceptor thread running ps_server_run has actually
 * returned; closing them here, before that, would race that thread's own
 * read of them inside ps_listener_accept. The caller must join its acceptor
 * thread first, and only then call ps_listener_close(&server->listener).
 *
 * Returns true if every in-flight connection drained in time: the thread
 * pool is fully torn down, and server->pool must not be used again. Returns
 * false if the deadline passed first: server->pool is deliberately left
 * running and unfreed (see ps_threadpool_destroy_timed) -- the caller must
 * not touch it again and must proceed straight to process exit, which is
 * the only situation this bounded contract is safe to use in.
 */
bool ps_server_shutdown(ps_server_t *server, int grace_period_s);

#endif /* PS_PLATFORM_SERVER_H */
