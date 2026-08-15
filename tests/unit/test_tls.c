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
#include <unistd.h>

#include "platform/net.h"
#include "platform/tls.h"

static const char *const CERT_A = "build/test-scratch-tls-a-cert.pem";
static const char *const KEY_A  = "build/test-scratch-tls-a-key.pem";
static const char *const CERT_B = "build/test-scratch-tls-b-cert.pem";
static const char *const KEY_B  = "build/test-scratch-tls-b-key.pem";
static const char *const KEY_LOOSE_PERMS = "build/test-scratch-tls-loose-key.pem";

static bool generate_self_signed(const char *cert_path, const char *key_path)
{
    char cmd[1024];
    (void)snprintf(cmd, sizeof cmd,
                   "openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes "
                   "-keyout %s -out %s -subj '/CN=localhost' >/dev/null 2>&1",
                   key_path, cert_path);
    if (system(cmd) != 0) {
        return false;
    }
    return chmod(key_path, 0600) == 0;
}

static bool copy_file(const char *src, const char *dst)
{
    char cmd[1024];
    (void)snprintf(cmd, sizeof cmd, "cp %s %s", src, dst);
    return system(cmd) == 0;
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

/* ------------------------------------------------------------------------- */

static void test_ctx_create_rejects_loose_key_permissions(void)
{
    PS_CHECK(chmod(KEY_LOOSE_PERMS, 0644) == 0);

    char     err[256];
    SSL_CTX *ctx = ps_tls_ctx_create(CERT_A, KEY_LOOSE_PERMS, err, sizeof err);
    PS_CHECK(ctx == NULL);
    PS_CHECK(strstr(err, "0600") != NULL);
}

static void test_ctx_create_succeeds_with_valid_cert_and_key(void)
{
    char     err[256];
    SSL_CTX *ctx = ps_tls_ctx_create(CERT_A, KEY_A, err, sizeof err);
    PS_CHECK(ctx != NULL);
    ps_tls_ctx_free(ctx);
}

static void test_ctx_create_fails_on_missing_cert(void)
{
    char     err[256];
    SSL_CTX *ctx = ps_tls_ctx_create("build/does-not-exist.pem", KEY_A, err, sizeof err);
    PS_CHECK(ctx == NULL);
}

static void test_ctx_create_fails_on_mismatched_cert_and_key(void)
{
    char     err[256];
    SSL_CTX *ctx = ps_tls_ctx_create(CERT_A, KEY_B, err, sizeof err);
    PS_CHECK(ctx == NULL);
}

static void test_free_and_close_are_null_safe(void)
{
    ps_tls_ctx_free(NULL);
    ps_tls_close(NULL);
}

typedef struct {
    uint16_t port;
    int      max_version; /* 0 = no cap */
    bool     handshake_ok;
    char     received[128];
} client_arg_t;

static void *client_handshake_thread(void *arg)
{
    client_arg_t *a = arg;
    a->handshake_ok = false;
    a->received[0]  = '\0';

    int fd = connect_loopback(a->port);
    if (fd < 0) {
        return NULL;
    }

    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL); /* self-signed dev cert */
    if (a->max_version != 0) {
        (void)SSL_CTX_set_max_proto_version(cctx, a->max_version);
    }

    SSL *cssl = SSL_new(cctx);
    (void)SSL_set_fd(cssl, fd);

    if (SSL_connect(cssl) == 1) {
        a->handshake_ok = true;
        int n = SSL_read(cssl, a->received, sizeof a->received - 1);
        if (n > 0) {
            a->received[n] = '\0';
        }
    }

    (void)SSL_shutdown(cssl);
    SSL_free(cssl);
    SSL_CTX_free(cctx);
    (void)close(fd);
    return NULL;
}

static void test_end_to_end_handshake_and_data_transfer(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *ctx = ps_tls_ctx_create(CERT_A, KEY_A, err, sizeof err);
    PS_CHECK(ctx != NULL);

    client_arg_t carg = { .port = port, .max_version = 0 };
    pthread_t    t;
    PS_CHECK(pthread_create(&t, NULL, client_handshake_thread, &carg) == 0);

    int server_fd = -1;
    ps_accept_result_t rc = ps_listener_accept(&l, &server_fd, NULL, 0, err, sizeof err);
    PS_CHECK_EQ_INT(rc, PS_ACCEPT_OK);

    SSL *sssl = ps_tls_accept(ctx, server_fd, err, sizeof err);
    PS_CHECK(sssl != NULL);

    if (sssl != NULL) {
        const char *msg = "hello over TLS";
        PS_CHECK(SSL_write(sssl, msg, (int)strlen(msg)) == (int)strlen(msg));
    }

    PS_CHECK(pthread_join(t, NULL) == 0);

    PS_CHECK(carg.handshake_ok);
    PS_CHECK_STR_EQ(carg.received, "hello over TLS");

    ps_tls_close(sssl);
    (void)close(server_fd);
    ps_tls_ctx_free(ctx);
    ps_listener_close(&l);
}

/* Functional proof of the "TLS 1.2 minimum" requirement (plan 7.1), not
 * just that the setter call succeeded: a client capped at TLS 1.1 must be
 * refused by the handshake itself. */
static void test_client_below_minimum_version_is_refused(void)
{
    char          err[256];
    ps_listener_t l;
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    SSL_CTX *ctx = ps_tls_ctx_create(CERT_A, KEY_A, err, sizeof err);
    PS_CHECK(ctx != NULL);

    client_arg_t carg = { .port = port, .max_version = TLS1_1_VERSION };
    pthread_t    t;
    PS_CHECK(pthread_create(&t, NULL, client_handshake_thread, &carg) == 0);

    int server_fd = -1;
    ps_accept_result_t rc = ps_listener_accept(&l, &server_fd, NULL, 0, err, sizeof err);
    PS_CHECK_EQ_INT(rc, PS_ACCEPT_OK);

    SSL *sssl = ps_tls_accept(ctx, server_fd, err, sizeof err);
    PS_CHECK(sssl == NULL); /* server must refuse the handshake */

    PS_CHECK(pthread_join(t, NULL) == 0);
    PS_CHECK(!carg.handshake_ok);

    ps_tls_close(sssl);
    (void)close(server_fd);
    ps_tls_ctx_free(ctx);
    ps_listener_close(&l);
}

int main(void)
{
    /* A TLS teardown race (writing close_notify to an already-gone peer)
     * can raise SIGPIPE at the raw socket layer; default disposition would
     * kill the whole binary instead of failing one assertion. */
    signal(SIGPIPE, SIG_IGN);

    if (!generate_self_signed(CERT_A, KEY_A) ||
        !generate_self_signed(CERT_B, KEY_B) ||
        !copy_file(KEY_A, KEY_LOOSE_PERMS)) {
        (void)fprintf(stderr, "fixture setup failed: could not generate test certs "
                              "(is the 'openssl' CLI on PATH?)\n");
        return 1;
    }

    PS_RUN_TEST(test_ctx_create_rejects_loose_key_permissions);
    PS_RUN_TEST(test_ctx_create_succeeds_with_valid_cert_and_key);
    PS_RUN_TEST(test_ctx_create_fails_on_missing_cert);
    PS_RUN_TEST(test_ctx_create_fails_on_mismatched_cert_and_key);
    PS_RUN_TEST(test_free_and_close_are_null_safe);
    PS_RUN_TEST(test_end_to_end_handshake_and_data_transfer);
    PS_RUN_TEST(test_client_below_minimum_version_is_refused);

    (void)remove(CERT_A);
    (void)remove(KEY_A);
    (void)remove(CERT_B);
    (void)remove(KEY_B);
    (void)remove(KEY_LOOSE_PERMS);

    PS_TEST_EXIT();
}
