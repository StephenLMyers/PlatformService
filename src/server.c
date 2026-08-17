#include "server.h"

#include <stdlib.h>
#include <unistd.h>

typedef struct {
    int                      client_fd;
    SSL_CTX                 *tls_ctx;
    ps_conn_limits_t         limits;
    const ps_router_t       *router;
    ps_route_dispatch_fn     dispatch;
    void                     *app_ctx;
    const ps_cors_policy_t   *cors;
} conn_job_arg_t;

static void conn_job_fn(void *arg)
{
    conn_job_arg_t *job = arg;
    (void)ps_conn_handle(job->client_fd, job->tls_ctx, &job->limits,
                         job->router, job->dispatch, job->app_ctx, job->cors, NULL);
    free(job);
}

void ps_server_run(ps_server_t *server)
{
    for (;;) {
        char err[256];
        int  client_fd = -1;
        ps_accept_result_t rc = ps_listener_accept(&server->listener, &client_fd,
                                                    NULL, 0, err, sizeof err);
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
    server->draining = true; /* plan 7.2a step 1, first, before anything else */

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
