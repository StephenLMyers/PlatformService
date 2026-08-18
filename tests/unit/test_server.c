#include "testutil.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "http/router.h"
#include "json/json_parse.h"
#include "platform/tls.h"
#include "server.h"

static const char *const CERT_PATH = "build/test-scratch-server-cert.pem";
static const char *const KEY_PATH  = "build/test-scratch-server-key.pem";

static bool generate_self_signed(void)
{
    char cmd[1024];
    (void)snprintf(cmd, sizeof cmd,
                   "openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes "
                   "-keyout %s -out %s -subj '/CN=localhost' >/dev/null 2>&1",
                   KEY_PATH, CERT_PATH);
    if (system(cmd) != 0) {
        return false;
    }
    return chmod(KEY_PATH, 0600) == 0;
}

static uint16_t bound_port(int listen_fd)
{
    struct sockaddr_in addr;
    socklen_t          len = sizeof addr;
    (void)getsockname(listen_fd, (struct sockaddr *)&addr, &len);
    return ntohs(addr.sin_port);
}

static int connect_loopback(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static SSL *client_handshake(int fd, SSL_CTX **out_ctx)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL *cssl = SSL_new(cctx);
    (void)SSL_set_fd(cssl, fd);
    if (SSL_connect(cssl) != 1) {
        SSL_free(cssl);
        SSL_CTX_free(cctx);
        return NULL;
    }
    *out_ctx = cctx;
    return cssl;
}

static bool send_request(SSL *ssl, const char *method, const char *path)
{
    char req[256];
    int  len = snprintf(req, sizeof req, "%s %s HTTP/1.1\r\nHost: test\r\n\r\n", method, path);
    if (len < 0 || (size_t)len >= sizeof req) {
        return false;
    }
    return SSL_write(ssl, req, len) == len;
}

typedef struct {
    int  status;
    char body[256];
} test_response_t;

/* Minimal HTTP/1.1 response reader for driving these tests -- see
 * tests/unit/test_conn.c, which has the same helper for the same reason. */
static bool recv_response(SSL *ssl, test_response_t *out)
{
    static char buf[4096];
    size_t       total = 0;
    out->status  = -1;
    out->body[0] = '\0';

    for (;;) {
        int n = SSL_read(ssl, buf + total, (int)(sizeof buf - total - 1));
        if (n <= 0) {
            return false;
        }
        total += (size_t)n;
        buf[total] = '\0';

        char *hdrs_end = strstr(buf, "\r\n\r\n");
        if (hdrs_end == NULL) {
            continue;
        }
        size_t header_bytes = (size_t)(hdrs_end + 4 - buf);

        size_t      want_body = 0;
        const char *cl        = strstr(buf, "Content-Length: ");
        if (cl != NULL && cl < hdrs_end) {
            want_body = (size_t)strtoul(cl + strlen("Content-Length: "), NULL, 10);
        }
        if (total - header_bytes < want_body) {
            continue;
        }

        if (sscanf(buf, "HTTP/1.%*d %d", &out->status) != 1) {
            return false;
        }
        size_t body_len = total - header_bytes;
        if (body_len >= sizeof out->body) {
            body_len = sizeof out->body - 1;
        }
        memcpy(out->body, buf + header_bytes, body_len);
        out->body[body_len] = '\0';
        return true;
    }
}

/* Local test router + dispatch, independent of api/routes.c -- see
 * tests/unit/test_conn.c for the same pattern and its rationale. */
enum { TEST_ROUTE_ECHO = 1 };

static void build_test_router(ps_router_t *r)
{
    char err[256];
    ps_router_init(r);
    PS_CHECK(ps_router_add(r, "GET", "/echo", TEST_ROUTE_ECHO, err, sizeof err));
}

static ps_handler_result_t test_dispatch(int route_id, const ps_http_request_t *req,
                                         const ps_route_params_t *params,
                                         const char *peer_addr, void *app_ctx)
{
    (void)req;
    (void)params;
    (void)peer_addr;
    (void)app_ctx;

    ps_handler_result_t result = { .status = 200, .body = NULL, .no_store = false };
    if (route_id != TEST_ROUTE_ECHO) {
        result.status = 500;
        return result;
    }
    result.body = ps_json_new_object();
    if (result.body != NULL) {
        (void)ps_json_object_set(result.body, "ok", ps_json_new_bool(true));
    }
    return result;
}

static const ps_http_limits_t DEFAULT_HTTP_LIMITS = {
    .max_request_line_bytes = 8192,
    .max_header_bytes       = 16384,
    .max_header_count       = 64,
    .max_body_bytes         = 1048576,
};

static double elapsed_seconds(struct timeval start, struct timeval end)
{
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_usec - start.tv_usec) / 1e6;
}

static void *server_run_thread(void *arg)
{
    ps_server_run((ps_server_t *)arg);
    return NULL;
}

static bool make_server(ps_server_t *server, ps_conn_limits_t limits, const ps_router_t *router)
{
    char err[256];
    server->draining = false;
    server->cors     = NULL; /* CORS off -- these tests don't exercise it */

    if (!ps_listener_open(&server->listener, "127.0.0.1", 0, 16, err, sizeof err)) {
        return false;
    }
    server->tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    if (server->tls_ctx == NULL) {
        ps_listener_close(&server->listener);
        return false;
    }
    server->pool = ps_threadpool_create(2, 8, err, sizeof err);
    if (server->pool == NULL) {
        ps_tls_ctx_free(server->tls_ctx);
        ps_listener_close(&server->listener);
        return false;
    }
    server->conn_limits = limits;
    server->router      = router;
    server->dispatch    = test_dispatch;
    server->app_ctx      = NULL;
    return true;
}

/* ------------------------------------------------------------------------- */

typedef struct {
    uint16_t port;
    bool     ok;
    char     received[256];

    /* Signalled once request 1 has round-tripped, so the main thread knows
     * the connection is genuinely already-accepted and in-flight before it
     * races shutdown against request 2 -- without this, shutdown could win
     * and close the listener before the client even connects. */
    pthread_mutex_t m;
    pthread_cond_t  cv;
    bool            first_ack_received;
} client_two_round_trips_arg_t;

static void client_arg_init(client_two_round_trips_arg_t *a, uint16_t port)
{
    a->port               = port;
    a->ok                 = false;
    a->received[0]        = '\0';
    a->first_ack_received = false;
    (void)pthread_mutex_init(&a->m, NULL);
    (void)pthread_cond_init(&a->cv, NULL);
}

static void wait_for_first_ack(client_two_round_trips_arg_t *a)
{
    (void)pthread_mutex_lock(&a->m);
    while (!a->first_ack_received) {
        (void)pthread_cond_wait(&a->cv, &a->m);
    }
    (void)pthread_mutex_unlock(&a->m);
}

static void *client_two_round_trips(void *arg)
{
    client_two_round_trips_arg_t *a = arg;

    int fd = connect_loopback(a->port);
    if (fd < 0) {
        return NULL;
    }
    SSL_CTX *cctx = NULL;
    SSL     *ssl  = client_handshake(fd, &cctx);
    if (ssl == NULL) {
        (void)close(fd);
        return NULL;
    }

    test_response_t resp;
    bool ok = send_request(ssl, "GET", "/echo") && recv_response(ssl, &resp) &&
              resp.status == 200;

    (void)pthread_mutex_lock(&a->m);
    a->first_ack_received = true;
    (void)pthread_cond_signal(&a->cv);
    (void)pthread_mutex_unlock(&a->m);

    if (ok) {
        ok = send_request(ssl, "GET", "/echo") && recv_response(ssl, &resp) &&
             resp.status == 200;
        if (ok) {
            (void)snprintf(a->received, sizeof a->received, "%s", resp.body);
        }
    }
    a->ok = ok;

    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    (void)close(fd);
    return NULL;
}

/*
 * The core graceful-shutdown property (plan 7.2a): a connection already
 * in flight when shutdown is requested is allowed to finish, not cut off,
 * and shutdown returns as soon as it does -- well inside a generous grace
 * period, not after waiting out the whole thing.
 */
static void test_in_flight_connection_drains_before_shutdown_returns(void)
{
    ps_server_t       server;
    ps_router_t       router;
    build_test_router(&router);
    ps_conn_limits_t limits = { .read_timeout_s = 5, .write_timeout_s = 5,
                                .keepalive_max_requests = 5,
                                .http_limits = DEFAULT_HTTP_LIMITS };
    PS_CHECK(make_server(&server, limits, &router));
    uint16_t port = bound_port(server.listener.listen_fd);

    pthread_t acceptor;
    PS_CHECK(pthread_create(&acceptor, NULL, server_run_thread, &server) == 0);

    client_two_round_trips_arg_t carg;
    client_arg_init(&carg, port);
    pthread_t client;
    PS_CHECK(pthread_create(&client, NULL, client_two_round_trips, &carg) == 0);

    /* Block until the connection is provably already-accepted and
     * in-flight (one full round trip done) before racing shutdown against
     * its second, still-pending request. */
    wait_for_first_ack(&carg);

    struct timeval start, end;
    (void)gettimeofday(&start, NULL);
    bool drained = ps_server_shutdown(&server, 5);
    (void)gettimeofday(&end, NULL);

    PS_CHECK(pthread_join(client, NULL) == 0);
    PS_CHECK(pthread_join(acceptor, NULL) == 0);
    ps_listener_close(&server.listener); /* only now provably safe -- see server.h */

    PS_CHECK(drained);
    PS_CHECK(elapsed_seconds(start, end) < 5.0); /* returned early, not by waiting out the grace period */
    PS_CHECK(carg.ok);
    PS_CHECK(strstr(carg.received, "\"ok\":true") != NULL);

    /* The listener is really gone: a fresh connection attempt must fail. */
    int fd = connect_loopback(port);
    PS_CHECK(fd < 0);

    (void)pthread_mutex_destroy(&carg.m);
    (void)pthread_cond_destroy(&carg.cv);
    ps_tls_ctx_free(server.tls_ctx);
}

/*
 * A connection that does not finish in time must not hang shutdown forever
 * -- the deadline is a real deadline, not advisory.
 */
static void test_shutdown_returns_false_when_grace_period_exceeded(void)
{
    ps_server_t       server;
    ps_router_t       router;
    build_test_router(&router);
    ps_conn_limits_t limits = { .read_timeout_s = 30, .write_timeout_s = 30,
                                .keepalive_max_requests = 5,
                                .http_limits = DEFAULT_HTTP_LIMITS };
    PS_CHECK(make_server(&server, limits, &router));
    uint16_t port = bound_port(server.listener.listen_fd);

    pthread_t acceptor;
    PS_CHECK(pthread_create(&acceptor, NULL, server_run_thread, &server) == 0);

    int fd = connect_loopback(port);
    PS_CHECK(fd >= 0);
    SSL_CTX *cctx = NULL;
    SSL     *ssl  = client_handshake(fd, &cctx);
    PS_CHECK(ssl != NULL);

    /* Give the acceptor a moment to actually dispatch the job before we
     * race it with shutdown. */
    struct timespec nap = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&nap, NULL);

    struct timeval start, end;
    (void)gettimeofday(&start, NULL);
    bool drained = ps_server_shutdown(&server, 1); /* far shorter than the 30s read timeout */
    (void)gettimeofday(&end, NULL);

    PS_CHECK(!drained);
    double elapsed = elapsed_seconds(start, end);
    PS_CHECK(elapsed >= 0.9);
    PS_CHECK(elapsed < 5.0);

    PS_CHECK(pthread_join(acceptor, NULL) == 0);
    ps_listener_close(&server.listener); /* only now provably safe -- see server.h */

    /* Recover: closing the client unsticks the worker's read promptly
     * (poll() returns on peer-close well before its own long timeout), then
     * the still-valid, still-unfreed pool (see ps_server_shutdown's false
     * contract) can be joined and freed normally instead of leaking a
     * thread for the rest of this binary. */
    if (ssl != NULL) {
        SSL_free(ssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);
    ps_threadpool_destroy(server.pool);
    ps_tls_ctx_free(server.tls_ctx);
}

int main(void)
{
    /* Server and client can each observe the other having already closed
     * its end mid-teardown (SSL_shutdown writing a close_notify to an
     * already-gone peer); the default SIGPIPE disposition would kill the
     * whole test binary instead of failing one assertion. */
    signal(SIGPIPE, SIG_IGN);

    if (!generate_self_signed()) {
        (void)fprintf(stderr, "fixture setup failed: could not generate test certs "
                              "(is the 'openssl' CLI on PATH?)\n");
        return 1;
    }

    PS_RUN_TEST(test_in_flight_connection_drains_before_shutdown_returns);
    PS_RUN_TEST(test_shutdown_returns_false_when_grace_period_exceeded);

    (void)remove(CERT_PATH);
    (void)remove(KEY_PATH);

    PS_TEST_EXIT();
}
