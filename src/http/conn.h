/*
 * Per-connection keep-alive loop over an already-accepted client (plan
 * 7.2a): parses each request, routes it, dispatches to a handler, writes
 * the response, and repeats -- persistent by default, bounded by a request
 * cap and a read/write timeout, closing rather than resynchronizing on any
 * parse error (plan 7.2a's anti-smuggling rule).
 *
 * Lives in http/, not platform/: now that it speaks real HTTP (request.h,
 * response.h, router.h), it belongs in the protocol layer those live in,
 * not the foundation layer below it (plan 3.1's strict downward-dependency
 * rule -- foundation code must never reach up into protocol code).
 *
 * conn.c never calls into business logic (api/) directly, and never will:
 * ps_route_dispatch_fn is a callback whose concrete implementation
 * (api/routes.c's ps_routes_dispatch) is wired in by main.c, the one place
 * allowed to depend on every layer. This is what keeps http/ from having
 * to depend on api/ just to serve a request.
 */
#ifndef PS_HTTP_CONN_H
#define PS_HTTP_CONN_H

#include <stdbool.h>

#include <openssl/ssl.h>

#include "http/cors.h"
#include "http/request.h"
#include "http/router.h"
#include "json/json_parse.h"

typedef struct {
    int read_timeout_s;          /* SO_RCVTIMEO for the life of the connection */
    int write_timeout_s;         /* SO_SNDTIMEO for the life of the connection */
    int keepalive_max_requests;  /* connection closes once this many complete */
    ps_http_limits_t http_limits;
} ps_conn_limits_t;

typedef enum {
    PS_CONN_CLOSED_BY_PEER,             /* peer closed or disconnected between requests */
    PS_CONN_CLOSED_MAX_REQUESTS,        /* keepalive_max_requests reached */
    PS_CONN_CLOSED_TIMEOUT,             /* no next request within read_timeout_s */
    PS_CONN_CLOSED_ERROR,               /* handshake, protocol, or I/O error */
    PS_CONN_CLOSED_CONNECTION_HEADER,   /* client (or HTTP/1.0 default) declined keep-alive */
} ps_conn_close_reason_t;

/* What a route handler returns; ps_conn_handle wraps this into a full
 * response (status line, security headers, body) via response.h. */
typedef struct {
    int               status;
    ps_json_value_t  *body;   /* NULL for none; ps_conn_handle frees it after writing */
    bool              no_store;
} ps_handler_result_t;

/*
 * Implemented by whoever owns the real route table (api/routes.c) and
 * wired in by main.c. conn.c only ever sees this signature, never the
 * implementation -- see the header comment above.
 */
typedef ps_handler_result_t (*ps_route_dispatch_fn)(int route_id, const ps_http_request_t *req,
                                                    const ps_route_params_t *params,
                                                    const char *peer_addr, void *app_ctx);

/*
 * Owns the full lifecycle of one accepted connection: applies timeouts,
 * performs the TLS handshake, runs the parse/route/dispatch/respond loop,
 * and tears down -- always closing client_fd before returning, discharging
 * the "caller must close" contract client_fd arrived under from
 * ps_listener_accept.
 *
 * app_ctx is passed through to dispatch unexamined; conn.c has no idea
 * what it points to. peer_addr (may be NULL) is likewise passed straight
 * through to every dispatch call on this connection, unexamined -- it's
 * the "address:port" ps_listener_accept captured at accept() time, for
 * handlers that need it (e.g. an audit trail's source_ip).
 *
 * cors may be NULL (CORS off, the v1 default -- plan 7.2a): OPTIONS then
 * always returns 405, and no response ever carries an Access-Control-*
 * header. When non-NULL, must outlive every connection that references it
 * (a single shared, read-only policy every worker thread reads from).
 *
 * requests_served, if non-NULL, receives the number of complete
 * request/response cycles this connection actually served.
 */
ps_conn_close_reason_t ps_conn_handle(int client_fd, SSL_CTX *tls_ctx,
                                      const ps_conn_limits_t *limits,
                                      const ps_router_t *router,
                                      ps_route_dispatch_fn dispatch, void *app_ctx,
                                      const ps_cors_policy_t *cors,
                                      const char *peer_addr,
                                      int *requests_served);

#endif /* PS_HTTP_CONN_H */
