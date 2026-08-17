/*
 * Ties the listener, TLS context, thread pool, router, and connection loop
 * together into the actual accept-and-dispatch loop, plus the bounded
 * shutdown sequence (plan 7.2a steps 1-3: fail readiness, stop accepting,
 * drain in-flight work within a grace period). Step 4 (DB checkpoint,
 * SSL_CTX free) belongs to later phases and is not this module's concern.
 *
 * This file lives at the top level with main.c, not inside any layer in
 * plan 3.1's diagram -- its job is wiring layers together (foundation:
 * listener/TLS/threadpool; protocol: the connection loop), which is
 * exactly what a strict layering rule says no single layer should do.
 */
#ifndef PS_SERVER_H
#define PS_SERVER_H

#include <stdbool.h>

#include <openssl/ssl.h>

#include "http/conn.h"
#include "http/router.h"
#include "platform/net.h"
#include "platform/threadpool.h"

typedef struct {
    ps_listener_t     listener;
    SSL_CTX           *tls_ctx;   /* not owned by ps_server_t; caller creates/frees it */
    ps_threadpool_t   *pool;      /* owned once ps_server_shutdown returns true; see below */
    ps_conn_limits_t   conn_limits;

    const ps_router_t   *router;    /* not owned; caller builds and keeps it alive */
    ps_route_dispatch_fn dispatch;
    void                 *app_ctx;  /* passed through to dispatch unexamined */
    const ps_cors_policy_t *cors;   /* not owned; NULL = CORS off (plan 7.2a default) */

    /* Set by ps_server_shutdown before anything else (plan 7.2a step 1).
     * The caller's app_ctx typically points a ps_app_ctx_t.draining field
     * at this, so /readyz can see it without any lock: it only ever goes
     * false -> true, once, so a plain read is safe without one. */
    volatile bool draining;
} ps_server_t;

/*
 * Runs the accept loop on the calling thread: pulls connections from the
 * already-open listener and dispatches each to pool as a job running
 * ps_conn_handle (which uses server->router/dispatch/app_ctx to actually
 * serve requests). A queue-full submission is backpressure (plan 3.3) --
 * without a full auth/RBAC stack yet to answer 503 from deeper in the
 * stack, closing at this layer is still the correct move for an overload
 * this early.
 *
 * Returns once ps_listener_stop has been called (from any thread) and the
 * loop observes PS_ACCEPT_SHUTDOWN, or on a fatal accept error. Intended to
 * run on a dedicated acceptor thread.
 */
void ps_server_run(ps_server_t *server);

/*
 * Sets server->draining = true first, before anything else (plan 7.2a step
 * 1) -- a /readyz request already in flight, or one that lands in the
 * brief window before the listener actually stops, sees it immediately.
 * Then signals the listener to stop (ps_server_run's accept loop observes
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

#endif /* PS_SERVER_H */
