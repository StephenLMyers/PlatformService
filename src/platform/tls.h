/*
 * In-process TLS (plan 7.1, D4). One SSL_CTX built once at startup from the
 * configured cert/key and shared read-only across worker threads; a fresh
 * SSL per accepted connection.
 */
#ifndef PS_PLATFORM_TLS_H
#define PS_PLATFORM_TLS_H

#include <stddef.h>

#include <openssl/ssl.h>

/*
 * Loads cert_path/key_path into a new SSL_CTX configured for TLS 1.2 minimum
 * (1.3 preferred) with a modern cipher list. Refuses to start if key_path is
 * not mode 0600 and owned by the running user -- enforceable now that D2 is
 * Linux-only. Returns NULL and writes a reason into err on any failure.
 */
SSL_CTX *ps_tls_ctx_create(const char *cert_path, const char *key_path,
                           char *err, size_t errlen);

void ps_tls_ctx_free(SSL_CTX *ctx);

/*
 * Performs the server-side handshake over an already-accepted client_fd
 * (see net.h). The caller keeps ownership of client_fd in every case,
 * including failure -- only the returned SSL* is owned by the caller here.
 * Apply ps_socket_set_timeouts to client_fd first, or a stalled peer can
 * hang this call indefinitely.
 */
SSL *ps_tls_accept(SSL_CTX *ctx, int client_fd, char *err, size_t errlen);

/*
 * Attempts a clean bidirectional close_notify exchange, bounded by whatever
 * timeouts are set on the underlying fd, then always frees ssl -- correct
 * whether the peer closes gracefully or vanishes abruptly (plan 7.1). Safe
 * to call with ssl == NULL. Does not touch the underlying file descriptor;
 * that stays owned by whoever called ps_listener_accept for it.
 */
void ps_tls_close(SSL *ssl);

#endif /* PS_PLATFORM_TLS_H */
