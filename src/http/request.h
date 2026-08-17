/*
 * Hand-written HTTP/1.1 request parser (plan 7.2, R5 -- the highest-risk
 * code in the project: hand-written C consuming untrusted bytes straight
 * off the network, before authentication exists).
 *
 * Zero-copy by design: every string in ps_http_request_t is a (pointer,
 * length) into the caller's own buffer, never NUL-terminated, never
 * copied. `data` must outlive `out`. This is not an optimization for its
 * own sake -- it's what makes "every parser takes (ptr, len), never a bare
 * char *" (plan 7.2) actually true throughout, not just at the entry point.
 *
 * A pure function, not a streaming parser: it does no I/O. Whoever reads
 * bytes off the socket (the connection loop) calls this repeatedly as more
 * bytes arrive, exactly like picohttpparser's proven design -- the parser
 * says OK, INCOMPLETE ("call me again with more bytes"), or ERROR ("stop,
 * close the connection, never resynchronize" -- plan 7.2a's anti-smuggling
 * rule).
 *
 * Percent-decoding of the path is deliberately NOT performed here. Every
 * route this service has or plans to have is either a static literal path
 * or a numeric path parameter, neither of which is ever legitimately
 * percent-encoded -- adding a decode step "for completeness" would be
 * guessing at a requirement that doesn't exist (plan's own "reject rather
 * than guess" philosophy, §7.2/R5), and would itself become new attack
 * surface (double-decoding, encoded traversal sequences) with no offsetting
 * benefit.
 */
#ifndef PS_HTTP_REQUEST_H
#define PS_HTTP_REQUEST_H

#include <stddef.h>

#define PS_HTTP_MAX_HEADERS 64

typedef enum {
    PS_HTTP_PARSE_OK,          /* out is populated; *consumed bytes were used */
    PS_HTTP_PARSE_INCOMPLETE,  /* not an error -- call again with more bytes */
    PS_HTTP_PARSE_ERROR,       /* malformed; close the connection, never resync */
} ps_http_parse_result_t;

typedef enum {
    PS_HTTP_ERR_NONE = 0,
    PS_HTTP_ERR_MALFORMED,              /* -> 400 */
    PS_HTTP_ERR_LINE_TOO_LONG,          /* -> 400 */
    PS_HTTP_ERR_TOO_MANY_HEADERS,       /* -> 400 */
    PS_HTTP_ERR_HEADERS_TOO_LARGE,      /* -> 400 */
    PS_HTTP_ERR_BODY_TOO_LARGE,         /* -> 413 */
    PS_HTTP_ERR_CHUNKED_UNSUPPORTED,    /* -> 501 (plan 7.2: reject, don't half-implement) */
    PS_HTTP_ERR_CONTENT_LENGTH_INVALID, /* -> 400: missing, malformed, duplicate-conflicting,
                                          * or combined with Transfer-Encoding (smuggling) */
} ps_http_parse_error_t;

typedef struct {
    const char *name;
    size_t      name_len;
    const char *value;
    size_t      value_len;
} ps_http_header_t;

typedef struct {
    const char *method;
    size_t      method_len;

    const char *path;   /* origin-form only; always starts with '/' */
    size_t      path_len;

    const char *query;  /* NULL if the target had no '?' */
    size_t      query_len;

    int minor_version;  /* 0 = HTTP/1.0, 1 = HTTP/1.1 */

    ps_http_header_t headers[PS_HTTP_MAX_HEADERS];
    size_t            header_count;

    const char *body;   /* NULL if this request has no body */
    size_t      body_len;
} ps_http_request_t;

typedef struct {
    int max_request_line_bytes;
    int max_header_bytes;   /* combined, every header line, not counting the request line */
    int max_header_count;
    int max_body_bytes;
} ps_http_limits_t;

/*
 * Attempts to parse one complete request from the start of (data, len),
 * which may be a partial read from the socket -- there is no assumption
 * that len covers a whole request.
 *
 * PS_HTTP_PARSE_OK: out is populated, *consumed is how many bytes of data
 * the request occupied (request line + headers + body). A pipelined
 * second request, if any, starts at data + *consumed.
 *
 * PS_HTTP_PARSE_INCOMPLETE: nothing is wrong yet; the caller should read
 * more bytes and call again with the larger buffer.
 *
 * PS_HTTP_PARSE_ERROR: *error_kind classifies why (for status-code
 * mapping) and err holds a human-readable reason. The connection must be
 * closed, never resynchronized -- plan 7.2a is explicit that guessing where
 * a new request might start after a parse error is how request smuggling
 * happens.
 */
ps_http_parse_result_t ps_http_request_parse(const char *data, size_t len,
                                             const ps_http_limits_t *limits,
                                             ps_http_request_t *out, size_t *consumed,
                                             ps_http_parse_error_t *error_kind,
                                             char *err, size_t errlen);

/*
 * Case-insensitive lookup of the first header matching name (a NUL-terminated
 * C string naming a known header to look for -- e.g. "Content-Type"). The
 * request's own header names/values are never NUL-terminated since they
 * point into the wire buffer; this exists so callers don't have to do
 * length-aware comparison by hand at every call site. Returns NULL if absent.
 */
const ps_http_header_t *ps_http_request_header(const ps_http_request_t *req,
                                               const char *name);

#endif /* PS_HTTP_REQUEST_H */
