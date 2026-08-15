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

#include "platform/conn.h"
#include "platform/net.h"
#include "platform/tls.h"

static const char *const CERT_PATH = "build/test-scratch-conn-cert.pem";
static const char *const KEY_PATH  = "build/test-scratch-conn-key.pem";

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

/* ------------------------------------------------------------------------- */

typedef struct {
    ps_listener_t          *l;
    SSL_CTX                 *tls_ctx;
    ps_conn_limits_t         limits;
    ps_conn_close_reason_t   reason;
    int                      served;
} server_arg_t;

static void *server_thread_fn(void *arg)
{
    server_arg_t *a = arg;
    int  client_fd = -1;
    char err[256];

    ps_accept_result_t rc =
        ps_listener_accept(a->l, &client_fd, NULL, 0, err, sizeof err);
    if (rc != PS_ACCEPT_OK) {
        a->reason = PS_CONN_CLOSED_ERROR;
        a->served = 0;
        return NULL;
    }

    a->reason = ps_conn_handle(client_fd, a->tls_ctx, &a->limits, &a->served);
    return NULL;
}

/* The plan's own phase-2 exit criterion, proven directly: two requests
 * served over a single TLS connection, the client then disconnecting. */
static void test_two_requests_on_one_connection(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 5 },
        .reason = PS_CONN_CLOSED_ERROR, .served = -1,
    };
    pthread_t t;
    PS_CHECK(pthread_create(&t, NULL, server_thread_fn, &sarg) == 0);

    int      fd = connect_loopback(port);
    PS_CHECK(fd >= 0);
    SSL_CTX *cctx = NULL;
    SSL     *cssl = client_handshake(fd, &cctx);
    PS_CHECK(cssl != NULL);

    if (cssl != NULL) {
        char buf[64];
        PS_CHECK(send_line(cssl, "request one\n"));
        PS_CHECK(recv_line(cssl, buf, sizeof buf));
        PS_CHECK_STR_EQ(buf, "ps-ack 1\n");

        PS_CHECK(send_line(cssl, "request two\n"));
        PS_CHECK(recv_line(cssl, buf, sizeof buf));
        PS_CHECK_STR_EQ(buf, "ps-ack 2\n");

        (void)SSL_shutdown(cssl);
        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);

    PS_CHECK(pthread_join(t, NULL) == 0);
    PS_CHECK_EQ_INT(sarg.served, 2);
    PS_CHECK_EQ_INT(sarg.reason, PS_CONN_CLOSED_BY_PEER);

    ps_tls_ctx_free(tls_ctx);
    ps_listener_close(&l);
}

static void test_connection_closes_after_max_requests(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 3 },
        .reason = PS_CONN_CLOSED_ERROR, .served = -1,
    };
    pthread_t t;
    PS_CHECK(pthread_create(&t, NULL, server_thread_fn, &sarg) == 0);

    int      fd = connect_loopback(port);
    PS_CHECK(fd >= 0);
    SSL_CTX *cctx = NULL;
    SSL     *cssl = client_handshake(fd, &cctx);
    PS_CHECK(cssl != NULL);

    if (cssl != NULL) {
        char buf[64];
        for (int i = 1; i <= 3; i++) {
            PS_CHECK(send_line(cssl, "req\n"));
            PS_CHECK(recv_line(cssl, buf, sizeof buf));
        }
        /* Server has hit its cap and torn the connection down; one more
         * read must observe that, one way or another. */
        int rc = SSL_read(cssl, buf, sizeof buf);
        PS_CHECK(rc <= 0);

        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);

    PS_CHECK(pthread_join(t, NULL) == 0);
    PS_CHECK_EQ_INT(sarg.served, 3);
    PS_CHECK_EQ_INT(sarg.reason, PS_CONN_CLOSED_MAX_REQUESTS);

    ps_tls_ctx_free(tls_ctx);
    ps_listener_close(&l);
}

static void test_idle_timeout_closes_connection(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx,
        .limits = { .read_timeout_s = 1, .write_timeout_s = 1, .keepalive_max_requests = 5 },
        .reason = PS_CONN_CLOSED_ERROR, .served = -1,
    };
    pthread_t t;
    PS_CHECK(pthread_create(&t, NULL, server_thread_fn, &sarg) == 0);

    int      fd = connect_loopback(port);
    PS_CHECK(fd >= 0);
    SSL_CTX *cctx = NULL;
    SSL     *cssl = client_handshake(fd, &cctx);
    PS_CHECK(cssl != NULL);

    struct timeval start, end;
    (void)gettimeofday(&start, NULL);
    /* Client sends nothing and just waits -- the server's read timeout,
     * not any action here, must be what ends the connection. */
    PS_CHECK(pthread_join(t, NULL) == 0);
    (void)gettimeofday(&end, NULL);

    double elapsed = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_usec - start.tv_usec) / 1e6;
    PS_CHECK(elapsed >= 0.9);
    PS_CHECK(elapsed < 10.0);

    PS_CHECK_EQ_INT(sarg.served, 0);
    PS_CHECK_EQ_INT(sarg.reason, PS_CONN_CLOSED_TIMEOUT);

    if (cssl != NULL) {
        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);
    ps_tls_ctx_free(tls_ctx);
    ps_listener_close(&l);
}

static void test_handshake_failure_still_closes_fd(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx,
        .limits = { .read_timeout_s = 2, .write_timeout_s = 2, .keepalive_max_requests = 5 },
        .reason = PS_CONN_CLOSED_MAX_REQUESTS, .served = -1,
    };
    pthread_t t;
    PS_CHECK(pthread_create(&t, NULL, server_thread_fn, &sarg) == 0);

    /* A plain TCP client that never speaks TLS -- the handshake itself
     * must fail, not hang. */
    int fd = connect_loopback(port);
    PS_CHECK(fd >= 0);

    PS_CHECK(pthread_join(t, NULL) == 0);
    PS_CHECK_EQ_INT(sarg.reason, PS_CONN_CLOSED_ERROR);

    (void)close(fd);
    ps_tls_ctx_free(tls_ctx);
    ps_listener_close(&l);
}

int main(void)
{
    /* A TLS teardown race (writing close_notify to an already-gone peer)
     * can raise SIGPIPE at the raw socket layer; default disposition would
     * kill the whole binary instead of failing one assertion. */
    signal(SIGPIPE, SIG_IGN);

    if (!generate_self_signed()) {
        (void)fprintf(stderr, "fixture setup failed: could not generate test certs "
                              "(is the 'openssl' CLI on PATH?)\n");
        return 1;
    }

    PS_RUN_TEST(test_two_requests_on_one_connection);
    PS_RUN_TEST(test_connection_closes_after_max_requests);
    PS_RUN_TEST(test_idle_timeout_closes_connection);
    PS_RUN_TEST(test_handshake_failure_still_closes_fd);

    (void)remove(CERT_PATH);
    (void)remove(KEY_PATH);

    PS_TEST_EXIT();
}
