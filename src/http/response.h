/*
 * HTTP/1.1 response writer (plan 7.5). Builds a complete response --
 * status line, headers, body -- into a ps_buf_t. Security headers are
 * applied by this module alone, not left to individual call sites, so
 * "did this handler remember nosniff" is never a question that needs
 * asking per-route.
 */
#ifndef PS_HTTP_RESPONSE_H
#define PS_HTTP_RESPONSE_H

#include <stdbool.h>

#include "json/json_parse.h"
#include "platform/buf.h"

typedef struct {
    int status;

    /* Connection: keep-alive or close -- the connection loop decides this
     * from its own state (request cap, client's own Connection header,
     * etc.), not this module. */
    bool keep_alive;

    /* Emits Cache-Control: no-store when true. Plan 7.5 scopes this to
     * authenticated responses specifically, not every response -- a
     * cached /healthz result is harmless, a cached authenticated body
     * is not. The caller decides. */
    bool no_store;

    /* NULL for a bodyless response (e.g. 204). Not owned/freed by
     * ps_http_response_write -- exactly like ps_json_write, the caller
     * keeps and frees it. */
    const ps_json_value_t *json_body;

    /*
     * CORS (plan 7.2a). cors_origin == NULL (the default when this struct
     * is zero-initialized) means no Access-Control-* headers are emitted
     * at all -- correct for every response when CORS is off or the
     * request's Origin didn't match the configured allowlist; the caller
     * decides which by setting this field only when it should be set.
     * When non-NULL, must be a NUL-terminated string that outlives the
     * ps_http_response_write call (it is echoed verbatim, not copied).
     */
    const char *cors_origin;
    bool         cors_allow_credentials;
    /* Only meaningful (and normally only set) on an OPTIONS preflight
     * response; NULL omits the corresponding header. */
    const char  *cors_allow_methods;
    const char  *cors_allow_headers;
} ps_http_response_t;

/* Appends the full response to buf. Returns false only on allocation
 * failure, in which case buf may hold a partial write and should be
 * discarded rather than reused. */
bool ps_http_response_write(const ps_http_response_t *resp, ps_buf_t *buf);

/*
 * Convenience for the plan 4.12 error envelope:
 *   { "error": { "code": "...", "message": "..." } }
 * Always sets Cache-Control: no-store (an error body is exactly the kind
 * of thing that must never be cached and replayed to a different caller).
 */
bool ps_http_response_write_error(int status, const char *code, const char *message,
                                  bool keep_alive, ps_buf_t *buf);

/*
 * Builds the same plan 4.12 envelope as a JSON value rather than writing
 * it to a buffer -- for a route handler that needs to return an error as
 * its ps_handler_result_t.body (http/conn.h), which conn.c writes via the
 * normal ps_http_response_write path, not this module's own error path.
 * Returns NULL only on allocation failure. Caller owns the result.
 */
ps_json_value_t *ps_error_envelope(const char *code, const char *message);

#endif /* PS_HTTP_RESPONSE_H */
