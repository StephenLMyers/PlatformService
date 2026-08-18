#include "http/conn.h"

#include <ctype.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "http/response.h"
#include "platform/buf.h"
#include "platform/net.h"
#include "platform/tls.h"

static bool header_value_equals_ci(const ps_http_header_t *h, const char *token)
{
    if (h == NULL) {
        return false;
    }
    size_t token_len = strlen(token);
    if (h->value_len != token_len) {
        return false;
    }
    for (size_t i = 0; i < token_len; i++) {
        if (tolower((unsigned char)h->value[i]) != tolower((unsigned char)token[i])) {
            return false;
        }
    }
    return true;
}

/* Plan 7.2a: HTTP/1.1 defaults to persistent, HTTP/1.0 does not; either is
 * overridden by an explicit Connection header. completed_after is the
 * count including the response about to be sent -- once it reaches the
 * cap, this connection closes regardless of what the client asked for. */
static bool connection_should_stay_alive(const ps_http_request_t *req, int completed_after,
                                         int max_requests)
{
    if (completed_after >= max_requests) {
        return false;
    }
    const ps_http_header_t *conn_hdr = ps_http_request_header(req, "Connection");
    if (header_value_equals_ci(conn_hdr, "close")) {
        return false;
    }
    if (req->minor_version == 0) {
        return header_value_equals_ci(conn_hdr, "keep-alive");
    }
    return true;
}

/*
 * Reads at least one more byte into buf, waiting up to timeout_s via
 * poll() first. As in phase 2: poll()'s timeout is unambiguous, unlike
 * inspecting SSL_get_error/errno after a timed-out blocking read (that
 * mapping isn't consistent across OpenSSL versions/modes, particularly
 * with SSL_MODE_AUTO_RETRY). SSL_pending() is checked first because a TLS
 * record can already hold more plaintext than the last SSL_read consumed,
 * which poll() on the raw fd cannot see.
 */
static bool read_more(SSL *ssl, int fd, ps_buf_t *buf, int timeout_s,
                      ps_conn_close_reason_t *reason)
{
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

    char chunk[4096];
    int  n = SSL_read(ssl, chunk, sizeof chunk);
    if (n <= 0) {
        int ssl_err = SSL_get_error(ssl, n);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            *reason = PS_CONN_CLOSED_BY_PEER;
        } else if (ssl_err == SSL_ERROR_SYSCALL && buf->len == 0) {
            /* Abrupt disconnect (no close_notify) right at a request
             * boundary reads the same as a graceful close. */
            *reason = PS_CONN_CLOSED_BY_PEER;
        } else {
            *reason = PS_CONN_CLOSED_ERROR;
        }
        return false;
    }

    if (!ps_buf_append(buf, chunk, (size_t)n)) {
        *reason = PS_CONN_CLOSED_ERROR;
        return false;
    }
    return true;
}

static bool method_is(const ps_http_request_t *req, const char *method)
{
    size_t len = strlen(method);
    return req->method_len == len && memcmp(req->method, method, len) == 0;
}

/*
 * Fills resp's cors_* fields from the request's Origin header and the
 * configured policy (plan 7.2a). Leaves them at their zero-initialized
 * defaults (no Access-Control-* headers emitted) when CORS is off or the
 * Origin doesn't match the allowlist -- callers must zero-init resp
 * themselves first. origin_buf must be supplied by the caller and must
 * outlive the ps_http_response_write call, since ps_http_response_t only
 * ever holds pointers, never copies. is_preflight sets Allow-Methods/
 * Allow-Headers too, meaningful only on an OPTIONS response.
 */
static void apply_cors(const ps_cors_policy_t *cors, const ps_http_request_t *req,
                       char *origin_buf, size_t origin_buf_len, bool is_preflight,
                       ps_http_response_t *resp)
{
    if (!ps_cors_enabled(cors)) {
        return;
    }
    const ps_http_header_t *origin = ps_http_request_header(req, "Origin");
    if (origin == NULL || !ps_cors_origin_allowed(cors, origin->value, origin->value_len)) {
        return;
    }

    size_t n = origin->value_len < origin_buf_len - 1 ? origin->value_len : origin_buf_len - 1;
    memcpy(origin_buf, origin->value, n);
    origin_buf[n] = '\0';

    resp->cors_origin            = origin_buf;
    resp->cors_allow_credentials = cors->allow_credentials;
    if (is_preflight) {
        resp->cors_allow_methods = "GET, POST, PUT, DELETE, OPTIONS";
        resp->cors_allow_headers = "Content-Type, Authorization";
    }
}

/* Every ps_http_parse_error_t has its own case (not folded behind
 * `default`) so -Wswitch-enum catches a forgotten mapping the moment a
 * new error kind is added to request.h. */
static void error_status_and_code(ps_http_parse_error_t kind, int *status, const char **code)
{
    switch (kind) {
    case PS_HTTP_ERR_BODY_TOO_LARGE:
        *status = 413;
        *code   = "PAYLOAD_TOO_LARGE";
        break;
    case PS_HTTP_ERR_CHUNKED_UNSUPPORTED:
        *status = 501;
        *code   = "NOT_IMPLEMENTED";
        break;
    case PS_HTTP_ERR_NONE:
    case PS_HTTP_ERR_MALFORMED:
    case PS_HTTP_ERR_LINE_TOO_LONG:
    case PS_HTTP_ERR_TOO_MANY_HEADERS:
    case PS_HTTP_ERR_HEADERS_TOO_LARGE:
    case PS_HTTP_ERR_CONTENT_LENGTH_INVALID:
        *status = 400;
        *code   = "BAD_REQUEST";
        break;
    }
}

ps_conn_close_reason_t ps_conn_handle(int client_fd, SSL_CTX *tls_ctx,
                                      const ps_conn_limits_t *limits,
                                      const ps_router_t *router,
                                      ps_route_dispatch_fn dispatch, void *app_ctx,
                                      const ps_cors_policy_t *cors,
                                      const char *peer_addr,
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

    ps_buf_t readbuf;
    ps_buf_init(&readbuf);

    ps_conn_close_reason_t reason    = PS_CONN_CLOSED_ERROR;
    int                     completed = 0;

    for (;;) {
        if (completed >= limits->keepalive_max_requests) {
            reason = PS_CONN_CLOSED_MAX_REQUESTS;
            break;
        }

        ps_http_request_t     req;
        size_t                 consumed = 0;
        ps_http_parse_error_t  parse_err_kind;
        char                    parse_err[256];
        ps_http_parse_result_t rc;

        /* A pipelined next request may already be sitting fully in
         * readbuf from the previous iteration's leftover bytes -- only
         * read more off the wire if parsing says it actually needs more. */
        for (;;) {
            rc = ps_http_request_parse(readbuf.data, readbuf.len, &limits->http_limits,
                                       &req, &consumed, &parse_err_kind,
                                       parse_err, sizeof parse_err);
            if (rc != PS_HTTP_PARSE_INCOMPLETE) {
                break;
            }
            if (!read_more(ssl, client_fd, &readbuf, limits->read_timeout_s, &reason)) {
                goto done;
            }
        }

        if (rc == PS_HTTP_PARSE_ERROR) {
            int         status = 400;
            const char *code   = "BAD_REQUEST";
            error_status_and_code(parse_err_kind, &status, &code);

            ps_buf_t out;
            ps_buf_init(&out);
            if (ps_http_response_write_error(status, code, parse_err, false, &out) &&
                out.len > 0) {
                (void)SSL_write(ssl, out.data, (int)out.len);
            }
            ps_buf_free(&out);
            reason = PS_CONN_CLOSED_ERROR; /* never resynchronize after a parse error */
            break;
        }

        bool alive_if_written =
            connection_should_stay_alive(&req, completed + 1, limits->keepalive_max_requests);

        ps_buf_t out;
        ps_buf_init(&out);
        bool write_ok;
        char origin_buf[256];

        if (method_is(&req, "OPTIONS")) {
            /* Plan 7.2a: OPTIONS returns 405 unless an origin allowlist is
             * configured -- decided uniformly here, before routing, so it
             * applies the same way regardless of whether the target path
             * happens to exist. */
            if (!ps_cors_enabled(cors)) {
                write_ok = ps_http_response_write_error(405, "METHOD_NOT_ALLOWED",
                                                         "CORS is not configured",
                                                         alive_if_written, &out);
            } else {
                ps_http_response_t resp = { .status = 204, .keep_alive = alive_if_written,
                                           .no_store = false, .json_body = NULL };
                apply_cors(cors, &req, origin_buf, sizeof origin_buf, true, &resp);
                write_ok = ps_http_response_write(&resp, &out);
            }
        } else {
            int                      route_id = -1;
            ps_route_params_t        params;
            ps_route_match_result_t  match = ps_router_match(router, req.method, req.method_len,
                                                              req.path, req.path_len,
                                                              &route_id, &params);

            if (match == PS_ROUTE_NOT_FOUND) {
                write_ok = ps_http_response_write_error(404, "NOT_FOUND", "no such route",
                                                         alive_if_written, &out);
            } else if (match == PS_ROUTE_METHOD_NOT_ALLOWED) {
                write_ok = ps_http_response_write_error(405, "METHOD_NOT_ALLOWED",
                                                         "path exists, method does not",
                                                         alive_if_written, &out);
            } else {
                ps_handler_result_t result = dispatch(route_id, &req, &params, peer_addr, app_ctx);
                ps_http_response_t  resp   = {
                    .status     = result.status,
                    .keep_alive = alive_if_written,
                    .no_store   = result.no_store,
                    .json_body  = result.body,
                };
                apply_cors(cors, &req, origin_buf, sizeof origin_buf, false, &resp);
                write_ok = ps_http_response_write(&resp, &out);
                ps_json_free(result.body);
            }
        }

        if (!write_ok || out.len == 0 ||
            SSL_write(ssl, out.data, (int)out.len) != (int)out.len) {
            ps_buf_free(&out);
            reason = PS_CONN_CLOSED_ERROR;
            break;
        }
        ps_buf_free(&out);
        completed++;

        if (!alive_if_written) {
            reason = (completed >= limits->keepalive_max_requests)
                     ? PS_CONN_CLOSED_MAX_REQUESTS
                     : PS_CONN_CLOSED_CONNECTION_HEADER;
            break;
        }

        /* Slide any leftover pipelined bytes to the front. The buffer's
         * backing storage is never shrunk back down after growing for a
         * large request -- bounded by keepalive_max_requests connections
         * living only so long, and simpler than a shrink policy that
         * §8.5's memory testing would calibrate against real numbers
         * before this is worth adding. */
        if (consumed >= readbuf.len) {
            readbuf.len = 0;
        } else {
            memmove(readbuf.data, readbuf.data + consumed, readbuf.len - consumed);
            readbuf.len -= consumed;
        }
    }

done:
    ps_buf_free(&readbuf);
    if (requests_served != NULL) {
        *requests_served = completed;
    }
    ps_tls_close(ssl);
    (void)close(client_fd);
    return reason;
}
