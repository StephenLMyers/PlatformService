#include "platform/conn.h"

#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "platform/net.h"
#include "platform/tls.h"

#define PS_CONN_LINE_MAX 4096

/*
 * Reads one line at a time. Byte-at-a-time SSL_read is the wrong shape for
 * a real parser, but this loop exists only to prove keep-alive/timeout/cap
 * mechanics (see header); phase 3's buffered HTTP parser replaces it.
 *
 * Waiting is done with poll() on the raw fd rather than leaning on
 * SO_RCVTIMEO and inspecting SSL_get_error/errno afterward: how a timed-out
 * blocking read surfaces through the TLS layer is not consistently
 * SSL_ERROR_SYSCALL+EAGAIN across OpenSSL versions and modes (in particular
 * with SSL_MODE_AUTO_RETRY), whereas poll() returning 0 is an unambiguous
 * timeout with no TLS-layer guessing involved. SSL_pending() is checked
 * first because a TLS record can already hold more plaintext than the last
 * SSL_read call consumed, which poll() on the raw fd cannot see.
 */
static bool read_line(SSL *ssl, int fd, char *buf, size_t buflen, int timeout_s,
                      ps_conn_close_reason_t *reason)
{
    size_t n = 0;
    while (n + 1 < buflen) {
        if (SSL_pending(ssl) <= 0) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
            int            rc = poll(&pfd, 1, timeout_s * 1000);
            if (rc == 0) {
                *reason = PS_CONN_CLOSED_TIMEOUT;
                return false;
            }
            if (rc < 0) {
                *reason = PS_CONN_CLOSED_ERROR;
                return false;
            }
        }

        char c;
        int  rc2 = SSL_read(ssl, &c, 1);
        if (rc2 <= 0) {
            int ssl_err = SSL_get_error(ssl, rc2);
            if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                *reason = PS_CONN_CLOSED_BY_PEER;
            } else if (ssl_err == SSL_ERROR_SYSCALL && n == 0) {
                /* Abrupt disconnect (no close_notify) right at a request
                 * boundary reads the same as a graceful close. */
                *reason = PS_CONN_CLOSED_BY_PEER;
            } else {
                *reason = PS_CONN_CLOSED_ERROR;
            }
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

static bool write_ack(SSL *ssl, int index)
{
    char resp[64];
    int  len = snprintf(resp, sizeof resp, "ps-ack %d\n", index);
    if (len < 0 || (size_t)len >= sizeof resp) {
        return false;
    }
    return SSL_write(ssl, resp, len) == len;
}

ps_conn_close_reason_t ps_conn_handle(int client_fd, SSL_CTX *tls_ctx,
                                      const ps_conn_limits_t *limits,
                                      int *requests_served)
{
    if (requests_served != NULL) {
        *requests_served = 0;
    }

    char err[256];
    if (!ps_socket_set_timeouts(client_fd, limits->read_timeout_s,
                                limits->write_timeout_s, err, sizeof err)) {
        (void)close(client_fd);
        return PS_CONN_CLOSED_ERROR;
    }

    SSL *ssl = ps_tls_accept(tls_ctx, client_fd, err, sizeof err);
    if (ssl == NULL) {
        (void)close(client_fd);
        return PS_CONN_CLOSED_ERROR;
    }

    /* Reached only by falling out of the loop with every iteration
     * succeeding, i.e. exactly keepalive_max_requests completed cycles. */
    ps_conn_close_reason_t reason = PS_CONN_CLOSED_MAX_REQUESTS;
    char                    line[PS_CONN_LINE_MAX];
    int                     served;

    for (served = 0; served < limits->keepalive_max_requests; served++) {
        if (!read_line(ssl, client_fd, line, sizeof line, limits->read_timeout_s, &reason)) {
            break;
        }
        if (!write_ack(ssl, served + 1)) {
            reason = PS_CONN_CLOSED_ERROR;
            break;
        }
    }

    if (requests_served != NULL) {
        *requests_served = served;
    }

    ps_tls_close(ssl);
    (void)close(client_fd);
    return reason;
}
