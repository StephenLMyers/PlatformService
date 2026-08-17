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

#include "http/conn.h"
#include "http/router.h"
#include "json/json_parse.h"
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

static bool send_request(SSL *ssl, const char *method, const char *path, const char *extra_headers)
{
    char req[512];
    int  len = snprintf(req, sizeof req, "%s %s HTTP/1.1\r\nHost: test\r\n%s\r\n",
                        method, path, extra_headers != NULL ? extra_headers : "");
    if (len < 0 || (size_t)len >= sizeof req) {
        return false;
    }
    return SSL_write(ssl, req, len) == len;
}

typedef struct {
    int  status;
    char headers[1024]; /* raw header block, for tests that check specific header lines */
    char body[512];
} test_response_t;

/* Minimal HTTP/1.1 response reader for driving these tests -- not a real
 * client, just enough to know the status code and when a response is
 * fully received (headers, then exactly Content-Length body bytes). */
static bool recv_response(SSL *ssl, test_response_t *out)
{
    static char buf[4096];
    size_t       total = 0;
    out->status     = -1;
    out->headers[0] = '\0';
    out->body[0]    = '\0';

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
        size_t hdr_len = header_bytes;
        if (hdr_len >= sizeof out->headers) {
            hdr_len = sizeof out->headers - 1;
        }
        memcpy(out->headers, buf, hdr_len);
        out->headers[hdr_len] = '\0';
        size_t body_len = total - header_bytes;
        if (body_len >= sizeof out->body) {
            body_len = sizeof out->body - 1;
        }
        memcpy(out->body, buf + header_bytes, body_len);
        out->body[body_len] = '\0';
        return true;
    }
}

/* ------------------------------------------------------------------------- */
/* A tiny local router + dispatch, independent of api/routes.c -- conn.c's
 * own tests shouldn't depend on the real business routes. */

enum { TEST_ROUTE_ECHO = 1 };

static void build_test_router(ps_router_t *r)
{
    char err[256];
    ps_router_init(r);
    PS_CHECK(ps_router_add(r, "GET", "/echo", TEST_ROUTE_ECHO, err, sizeof err));
}

static ps_handler_result_t test_dispatch(int route_id, const ps_http_request_t *req,
                                         const ps_route_params_t *params, void *app_ctx)
{
    (void)req;
    (void)params;
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

/* ------------------------------------------------------------------------- */

typedef struct {
    ps_listener_t            *l;
    SSL_CTX                   *tls_ctx;
    ps_conn_limits_t           limits;
    const ps_router_t         *router;
    const ps_cors_policy_t    *cors; /* NULL = CORS off, the default for most tests here */
    ps_conn_close_reason_t     reason;
    int                        served;
} server_arg_t;

static const ps_http_limits_t DEFAULT_HTTP_LIMITS = {
    .max_request_line_bytes = 8192,
    .max_header_bytes       = 16384,
    .max_header_count       = 64,
    .max_body_bytes         = 1048576,
};

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

    a->reason = ps_conn_handle(client_fd, a->tls_ctx, &a->limits, a->router,
                               test_dispatch, NULL, a->cors, &a->served);
    return NULL;
}

/* The plan's own phase-2/3 exit criterion, proven directly: two requests
 * served over a single TLS connection, the client then disconnecting. */
static void test_two_requests_on_one_connection(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    ps_router_t router;
    build_test_router(&router);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 5,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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
        test_response_t resp;

        PS_CHECK(send_request(cssl, "GET", "/echo", NULL));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 200);

        PS_CHECK(send_request(cssl, "GET", "/echo", NULL));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 200);

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

    ps_router_t router;
    build_test_router(&router);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 3,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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
        test_response_t resp;
        for (int i = 0; i < 3; i++) {
            PS_CHECK(send_request(cssl, "GET", "/echo", NULL));
            PS_CHECK(recv_response(cssl, &resp));
            PS_CHECK_EQ_INT(resp.status, 200);
        }
        /* Server has hit its cap and torn the connection down; one more
         * read must observe that, one way or another. */
        char c;
        int  rc = SSL_read(cssl, &c, 1);
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

/* New in phase 3: an explicit "Connection: close" ends the connection
 * after one response even though the request cap hasn't been reached. */
static void test_connection_close_header_ends_connection_early(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    ps_router_t router;
    build_test_router(&router);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 10,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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
        test_response_t resp;
        PS_CHECK(send_request(cssl, "GET", "/echo", "Connection: close\r\n"));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 200);
        PS_CHECK(strstr(resp.body, "\"ok\":true") != NULL);

        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);

    PS_CHECK(pthread_join(t, NULL) == 0);
    PS_CHECK_EQ_INT(sarg.served, 1);
    PS_CHECK_EQ_INT(sarg.reason, PS_CONN_CLOSED_CONNECTION_HEADER);

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

    ps_router_t router;
    build_test_router(&router);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router,
        .limits = { .read_timeout_s = 1, .write_timeout_s = 1, .keepalive_max_requests = 5,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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

    ps_router_t router;
    build_test_router(&router);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router,
        .limits = { .read_timeout_s = 2, .write_timeout_s = 2, .keepalive_max_requests = 5,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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

static void test_unknown_path_returns_404_and_stays_alive(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    ps_router_t router;
    build_test_router(&router);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 5,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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
        test_response_t resp;
        PS_CHECK(send_request(cssl, "GET", "/nope", NULL));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 404);

        /* A 404 is not a parse error -- the connection stays alive and can
         * serve a real route right after it. */
        PS_CHECK(send_request(cssl, "GET", "/echo", NULL));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 200);

        (void)SSL_shutdown(cssl);
        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);

    PS_CHECK(pthread_join(t, NULL) == 0);
    PS_CHECK_EQ_INT(sarg.served, 2);

    ps_tls_ctx_free(tls_ctx);
    ps_listener_close(&l);
}

/* ------------------------------------------------------------------------- */
/* CORS (plan 7.2a) -- exercising the real conn.c wiring, not just cors.c   */
/* and response.c in isolation.                                              */

static void test_options_returns_405_when_cors_disabled(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    ps_router_t router;
    build_test_router(&router);

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router, .cors = NULL,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 5,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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
        test_response_t resp;
        PS_CHECK(send_request(cssl, "OPTIONS", "/echo", "Origin: https://example.com\r\n"));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 405);
        PS_CHECK(strstr(resp.headers, "Access-Control-") == NULL);

        (void)SSL_shutdown(cssl);
        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);

    PS_CHECK(pthread_join(t, NULL) == 0);
    ps_tls_ctx_free(tls_ctx);
    ps_listener_close(&l);
}

static void test_options_preflight_succeeds_for_allowed_origin(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    ps_router_t router;
    build_test_router(&router);

    char              origins[] = "https://allowed.example";
    ps_cors_policy_t  cors;
    PS_CHECK(ps_cors_policy_init(&cors, origins, false, err, sizeof err));

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router, .cors = &cors,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 5,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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
        test_response_t resp;
        PS_CHECK(send_request(cssl, "OPTIONS", "/echo", "Origin: https://allowed.example\r\n"));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 204);
        PS_CHECK(strstr(resp.headers, "Access-Control-Allow-Origin: https://allowed.example\r\n")
                 != NULL);
        PS_CHECK(strstr(resp.headers, "Access-Control-Allow-Methods:") != NULL);
        PS_CHECK(strstr(resp.headers, "Access-Control-Allow-Headers:") != NULL);
        PS_CHECK(strstr(resp.headers, "Vary: Origin\r\n") != NULL);

        (void)SSL_shutdown(cssl);
        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);

    PS_CHECK(pthread_join(t, NULL) == 0);
    ps_tls_ctx_free(tls_ctx);
    ps_listener_close(&l);
}

static void test_options_preflight_omits_headers_for_disallowed_origin(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    ps_router_t router;
    build_test_router(&router);

    char              origins[] = "https://allowed.example";
    ps_cors_policy_t  cors;
    PS_CHECK(ps_cors_policy_init(&cors, origins, false, err, sizeof err));

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router, .cors = &cors,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 5,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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
        test_response_t resp;
        /* CORS is on, but this Origin isn't on the allowlist: the browser
         * (not this server) is what's supposed to enforce the block, by
         * never seeing the header it needs -- so this is still 204, just
         * without any Access-Control-* header, never a 403. Telling a
         * disallowed origin "you're disallowed" via status code would be
         * an oracle a same-origin-policy check should never need. */
        PS_CHECK(send_request(cssl, "OPTIONS", "/echo", "Origin: https://evil.example\r\n"));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 204);
        PS_CHECK(strstr(resp.headers, "Access-Control-") == NULL);

        (void)SSL_shutdown(cssl);
        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);

    PS_CHECK(pthread_join(t, NULL) == 0);
    ps_tls_ctx_free(tls_ctx);
    ps_listener_close(&l);
}

static void test_normal_response_gets_cors_header_when_origin_allowed(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *tls_ctx = ps_tls_ctx_create(CERT_PATH, KEY_PATH, err, sizeof err);
    PS_CHECK(tls_ctx != NULL);

    ps_router_t router;
    build_test_router(&router);

    char              origins[] = "https://allowed.example";
    ps_cors_policy_t  cors;
    PS_CHECK(ps_cors_policy_init(&cors, origins, true, err, sizeof err));

    server_arg_t sarg = {
        .l = &l, .tls_ctx = tls_ctx, .router = &router, .cors = &cors,
        .limits = { .read_timeout_s = 5, .write_timeout_s = 5, .keepalive_max_requests = 5,
                   .http_limits = DEFAULT_HTTP_LIMITS },
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
        test_response_t resp;
        PS_CHECK(send_request(cssl, "GET", "/echo", "Origin: https://allowed.example\r\n"));
        PS_CHECK(recv_response(cssl, &resp));
        PS_CHECK_EQ_INT(resp.status, 200);
        PS_CHECK(strstr(resp.headers, "Access-Control-Allow-Origin: https://allowed.example\r\n")
                 != NULL);
        PS_CHECK(strstr(resp.headers, "Access-Control-Allow-Credentials: true\r\n") != NULL);
        /* Allow-Methods/Allow-Headers are preflight-only; a real response
         * doesn't need them. */
        PS_CHECK(strstr(resp.headers, "Access-Control-Allow-Methods:") == NULL);

        (void)SSL_shutdown(cssl);
        SSL_free(cssl);
        SSL_CTX_free(cctx);
    }
    (void)close(fd);

    PS_CHECK(pthread_join(t, NULL) == 0);
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
    PS_RUN_TEST(test_connection_close_header_ends_connection_early);
    PS_RUN_TEST(test_idle_timeout_closes_connection);
    PS_RUN_TEST(test_handshake_failure_still_closes_fd);
    PS_RUN_TEST(test_unknown_path_returns_404_and_stays_alive);
    PS_RUN_TEST(test_options_returns_405_when_cors_disabled);
    PS_RUN_TEST(test_options_preflight_succeeds_for_allowed_origin);
    PS_RUN_TEST(test_options_preflight_omits_headers_for_disallowed_origin);
    PS_RUN_TEST(test_normal_response_gets_cors_header_when_origin_allowed);

    (void)remove(CERT_PATH);
    (void)remove(KEY_PATH);

    PS_TEST_EXIT();
}
