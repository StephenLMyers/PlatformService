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

#include "platform/server.h"
#include "platform/tls.h"

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

static bool send_line(SSL *ssl, const char *line)
{
    int len = (int)strlen(line);
    return SSL_write(ssl, line, len) == len;
}

static bool recv_line(SSL *ssl, char *buf, size_t buflen)
{
    size_t n = 0;
    while (n + 1 < buflen) {
        char c;
        int  rc = SSL_read(ssl, &c, 1);
        if (rc <= 0) {
            return false;
        }
        buf[n++] = c;
        if (c == '\n') {
            break;
        }
    }
    buf[n] = '\0';
    return true;
}

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

static bool make_server(ps_server_t *server, ps_conn_limits_t limits)
{
    char err[256];
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
    return true;
}

/* ------------------------------------------------------------------------- */

typedef struct {
    uint16_t port;
    bool     ok;
    char     received[64];

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

    char buf[64];
    bool ok = send_line(ssl, "one\n") && recv_line(ssl, buf, sizeof buf) &&
              strcmp(buf, "ps-ack 1\n") == 0;

    (void)pthread_mutex_lock(&a->m);
    a->first_ack_received = true;
    (void)pthread_cond_signal(&a->cv);
    (void)pthread_mutex_unlock(&a->m);

    if (ok) {
        ok = send_line(ssl, "two\n") && recv_line(ssl, buf, sizeof buf);
        if (ok) {
            (void)snprintf(a->received, sizeof a->received, "%s", buf);
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
    ps_server_t server;
    ps_conn_limits_t limits = { .read_timeout_s = 5, .write_timeout_s = 5,
                                .keepalive_max_requests = 5 };
    PS_CHECK(make_server(&server, limits));
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
    PS_CHECK_STR_EQ(carg.received, "ps-ack 2\n");

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
    ps_server_t server;
    ps_conn_limits_t limits = { .read_timeout_s = 30, .write_timeout_s = 30,
                                .keepalive_max_requests = 5 };
    PS_CHECK(make_server(&server, limits));
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
