/*
 * Per-connection keep-alive loop over an already-accepted client (plan
 * 7.2a): persistent by default, bounded by a request cap and a read/write
 * timeout, closing rather than resynchronizing on any error.
 *
 * Phase 2 scope. ps_conn_handle proves the connection lifecycle itself --
 * handshake, keep-alive, cap, timeout, teardown -- using a minimal
 * line-oriented placeholder protocol ("request line in, ack line out").
 * Phase 3 replaces the placeholder read/write with real HTTP/1.1 parsing
 * and routing without changing this loop's shape.
 */
#ifndef PS_PLATFORM_CONN_H
#define PS_PLATFORM_CONN_H

#include <openssl/ssl.h>

typedef struct {
    int read_timeout_s;         /* SO_RCVTIMEO for the life of the connection */
    int write_timeout_s;        /* SO_SNDTIMEO for the life of the connection */
    int keepalive_max_requests; /* connection closes once this many complete */
} ps_conn_limits_t;

typedef enum {
    PS_CONN_CLOSED_BY_PEER,       /* peer closed or disconnected between requests */
    PS_CONN_CLOSED_MAX_REQUESTS,  /* keepalive_max_requests reached */
    PS_CONN_CLOSED_TIMEOUT,       /* no next request within read_timeout_s */
    PS_CONN_CLOSED_ERROR,         /* handshake, protocol, or I/O error */
} ps_conn_close_reason_t;

/*
 * Owns the full lifecycle of one accepted connection: applies timeouts,
 * performs the TLS handshake, runs the request loop, and tears down --
 * always closing client_fd before returning, discharging the "caller must
 * close" contract client_fd arrived under from ps_listener_accept.
 *
 * requests_served, if non-NULL, receives the number of complete
 * request/response cycles this connection actually served.
 */
ps_conn_close_reason_t ps_conn_handle(int client_fd, SSL_CTX *tls_ctx,
                                      const ps_conn_limits_t *limits,
                                      int *requests_served);

#endif /* PS_PLATFORM_CONN_H */
