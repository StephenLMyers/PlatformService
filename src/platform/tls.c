#include "platform/tls.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/err.h>

/* TLS 1.2 suites. TLS 1.3 uses SSL_CTX_set_ciphersuites below instead --
 * the two version families have separate, non-overlapping cipher lists. */
static const char *const TLS12_CIPHERS =
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";

static const char *const TLS13_CIPHERSUITES =
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";

static void set_ssl_err(char *err, size_t errlen, const char *what)
{
    unsigned long code = ERR_get_error();
    if (code != 0) {
        char buf[256];
        ERR_error_string_n(code, buf, sizeof buf);
        (void)snprintf(err, errlen, "%s: %s", what, buf);
    } else {
        (void)snprintf(err, errlen, "%s: unknown TLS error", what);
    }
}

/*
 * The private key must be readable by no one but the running user (plan
 * 7.1). Checked before OpenSSL ever opens the file, so a bad mode is
 * reported in plain language rather than as a cryptic library error.
 */
static bool check_key_permissions(const char *key_path, char *err, size_t errlen)
{
    struct stat st;
    if (stat(key_path, &st) != 0) {
        (void)snprintf(err, errlen, "cannot stat TLS key '%s': %s",
                       key_path, strerror(errno));
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        (void)snprintf(err, errlen, "TLS key '%s' is not a regular file", key_path);
        return false;
    }

    mode_t perm = st.st_mode & 07777;
    if (perm != 0600) {
        (void)snprintf(err, errlen,
                       "TLS key '%s' has mode %04o; refusing to start unless it "
                       "is exactly 0600 (plan 7.1) -- fix with: chmod 600 %s",
                       key_path, (unsigned)perm, key_path);
        return false;
    }

    if (st.st_uid != geteuid()) {
        (void)snprintf(err, errlen,
                       "TLS key '%s' is not owned by the running user (uid %u); "
                       "refusing to start", key_path, (unsigned)geteuid());
        return false;
    }

    return true;
}

SSL_CTX *ps_tls_ctx_create(const char *cert_path, const char *key_path,
                           char *err, size_t errlen)
{
    if (!check_key_permissions(key_path, err, errlen)) {
        return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        set_ssl_err(err, errlen, "SSL_CTX_new");
        return NULL;
    }

    /* CRIME-class attacks target TLS compression; there is no reason to
     * have it on for an API service. */
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);

    /* Blocking sockets throughout (plan 3.3); AUTO_RETRY makes SSL_read/
     * SSL_write behave like plain blocking calls instead of surfacing
     * WANT_READ/WANT_WRITE for the caller to loop on. */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        set_ssl_err(err, errlen, "SSL_CTX_set_min_proto_version");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_set_cipher_list(ctx, TLS12_CIPHERS) != 1) {
        set_ssl_err(err, errlen, "SSL_CTX_set_cipher_list");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_set_ciphersuites(ctx, TLS13_CIPHERSUITES) != 1) {
        set_ssl_err(err, errlen, "SSL_CTX_set_ciphersuites");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
        set_ssl_err(err, errlen, "loading TLS certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        set_ssl_err(err, errlen, "loading TLS private key");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        set_ssl_err(err, errlen, "TLS certificate and private key do not match");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

void ps_tls_ctx_free(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx); /* NULL-safe */
}

SSL *ps_tls_accept(SSL_CTX *ctx, int client_fd, char *err, size_t errlen)
{
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        set_ssl_err(err, errlen, "SSL_new");
        return NULL;
    }

    if (SSL_set_fd(ssl, client_fd) != 1) {
        set_ssl_err(err, errlen, "SSL_set_fd");
        SSL_free(ssl);
        return NULL;
    }

    int rc = SSL_accept(ssl);
    if (rc != 1) {
        int ssl_err = SSL_get_error(ssl, rc);
        (void)snprintf(err, errlen, "TLS handshake failed (SSL_get_error=%d)", ssl_err);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

void ps_tls_close(SSL *ssl)
{
    if (ssl == NULL) {
        return;
    }

    /*
     * First call sends our close_notify; a return of 0 means that much
     * succeeded and the peer's close_notify hasn't arrived yet, so a second
     * call gives it one more chance. Bounded by whatever read timeout is
     * set on the fd -- never blocks indefinitely on a peer that vanished.
     * A negative return (abrupt disconnect) is not an error worth reporting
     * here; we still proceed to free ssl either way.
     */
    int rc = SSL_shutdown(ssl);
    if (rc == 0) {
        (void)SSL_shutdown(ssl);
    }

    SSL_free(ssl);
}
