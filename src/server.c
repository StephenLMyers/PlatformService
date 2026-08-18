#include "server.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int                      client_fd;
    SSL_CTX                 *tls_ctx;
    ps_conn_limits_t         limits;
    const ps_router_t       *router;
    ps_route_dispatch_fn     dispatch;
    void                     *app_ctx;
    const ps_cors_policy_t   *cors;
    char                     peer[PS_PEER_MAX];
} conn_job_arg_t;

static void conn_job_fn(void *arg)
{
    conn_job_arg_t *job = arg;
    (void)ps_conn_handle(job->client_fd, job->tls_ctx, &job->limits, job->router,
                         job->dispatch, job->app_ctx, job->cors, job->peer, NULL);
    free(job);
}

void ps_server_run(ps_server_t *server)
{
    for (;;) {
        char err[256];
        int  client_fd = -1;
        char peer[PS_PEER_MAX];
        ps_accept_result_t rc = ps_listener_accept(&server->listener, &client_fd,
                                                    peer, sizeof peer, err, sizeof err);
        if (rc == PS_ACCEPT_SHUTDOWN || rc == PS_ACCEPT_ERROR) {
            break;
        }

        conn_job_arg_t *job = malloc(sizeof *job);
        if (job == NULL) {
            (void)close(client_fd);
            continue;
        }
        job->client_fd = client_fd;
        job->tls_ctx   = server->tls_ctx;
        job->limits    = server->conn_limits;
        job->router    = server->router;
        job->dispatch  = server->dispatch;
        job->app_ctx   = server->app_ctx;
        job->cors      = server->cors;
        memcpy(job->peer, peer, sizeof job->peer);

        if (!ps_threadpool_submit(server->pool, conn_job_fn, job)) {
            /* Queue full (plan 3.3 backpressure): reject cleanly rather
             * than block the acceptor or grow the queue without bound. */
            (void)close(client_fd);
            free(job);
        }
    }
}

bool ps_server_shutdown(ps_server_t *server, int grace_period_s)
{
    /* plan 7.2a step 1, first, before anything else -- __atomic_store_n so
     * a /readyz request on another thread is guaranteed to observe this,
     * not just eventually see a compiler-unelided write (see server.h). */
    __atomic_store_n(&server->draining, true, __ATOMIC_SEQ_CST);

    ps_listener_stop(&server->listener);
    /* Closing the listener fds is the caller's job, after it has joined its
     * own acceptor thread -- see the header comment. */

    ps_threadpool_shutdown(server->pool, true); /* drain, don't discard */
    bool drained = ps_threadpool_destroy_timed(server->pool, grace_period_s);
    if (drained) {
        server->pool = NULL;
    }
    return drained;
}
