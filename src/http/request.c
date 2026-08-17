#include "http/request.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool is_tchar(unsigned char c)
{
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~':
        return true;
    default:
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }
}

static bool is_sp_or_htab(char c)
{
    return c == ' ' || c == '\t';
}

/* Finds "\r\n" at or after start, searching only within [0, limit). Never
 * scans past limit -- callers choose limit to keep this bounded by a
 * configured cap rather than by however much garbage a peer has sent. */
static long find_crlf(const char *data, size_t limit, size_t start)
{
    if (start >= limit) {
        return -1;
    }
    for (size_t i = start; i + 1 < limit; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            return (long)i;
        }
    }
    return -1;
}

static bool ci_equal(const char *a, size_t a_len, const char *b)
{
    size_t b_len = strlen(b);
    if (a_len != b_len) {
        return false;
    }
    for (size_t i = 0; i < a_len; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
            return false;
        }
    }
    return true;
}

static bool header_name_is(const ps_http_header_t *h, const char *name)
{
    return ci_equal(h->name, h->name_len, name);
}

static bool header_value_is_token(const ps_http_header_t *h, const char *token)
{
    return ci_equal(h->value, h->value_len, token);
}

/* Strict 1*DIGIT, no sign, no leading-zero exception needed (RFC 7230's
 * Content-Length grammar permits leading zeros; unlike JSON numbers, there
 * is no ambiguity they could introduce here). Capped at 18 digits so the
 * accumulation below can never overflow a 64-bit long before the caller's
 * own max_body_bytes check rejects it anyway. */
static bool parse_nonneg_decimal(const char *s, size_t len, long *out)
{
    if (len == 0 || len > 18) {
        return false;
    }
    long val = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c < '0' || c > '9') {
            return false;
        }
        val = val * 10 + (c - '0');
    }
    *out = val;
    return true;
}

static ps_http_parse_result_t fail(ps_http_parse_error_t *error_kind, char *err, size_t errlen,
                                   ps_http_parse_error_t kind, const char *msg)
{
    if (error_kind != NULL) {
        *error_kind = kind;
    }
    if (err != NULL && errlen > 0) {
        (void)snprintf(err, errlen, "%s", msg);
    }
    return PS_HTTP_PARSE_ERROR;
}

const ps_http_header_t *ps_http_request_header(const ps_http_request_t *req, const char *name)
{
    for (size_t i = 0; i < req->header_count; i++) {
        if (header_name_is(&req->headers[i], name)) {
            return &req->headers[i];
        }
    }
    return NULL;
}

ps_http_parse_result_t ps_http_request_parse(const char *data, size_t len,
                                             const ps_http_limits_t *limits,
                                             ps_http_request_t *out, size_t *consumed,
                                             ps_http_parse_error_t *error_kind,
                                             char *err, size_t errlen)
{
    if (error_kind != NULL) {
        *error_kind = PS_HTTP_ERR_NONE;
    }
    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    memset(out, 0, sizeof *out);
    *consumed = 0;

    /* ---- request line, bounded to max_request_line_bytes ---- */

    size_t line_scan_limit = len;
    if ((size_t)limits->max_request_line_bytes < line_scan_limit) {
        line_scan_limit = (size_t)limits->max_request_line_bytes;
    }
    long line_end = find_crlf(data, line_scan_limit, 0);
    if (line_end < 0) {
        if (len >= (size_t)limits->max_request_line_bytes) {
            return fail(error_kind, err, errlen, PS_HTTP_ERR_LINE_TOO_LONG,
                       "request line too long");
        }
        return PS_HTTP_PARSE_INCOMPLETE;
    }

    size_t line_len = (size_t)line_end;
    size_t pos       = 0;

    size_t method_start = pos;
    while (pos < line_len && data[pos] != ' ') {
        if (!is_tchar((unsigned char)data[pos])) {
            return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED, "invalid method token");
        }
        pos++;
    }
    if (pos == method_start || pos >= line_len) {
        return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED,
                   "malformed request line (method)");
    }
    out->method     = data + method_start;
    out->method_len = pos - method_start;
    pos++; /* space */

    size_t target_start = pos;
    while (pos < line_len && data[pos] != ' ') {
        pos++;
    }
    if (pos == target_start || pos >= line_len) {
        return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED,
                   "malformed request line (target)");
    }
    const char *target     = data + target_start;
    size_t      target_len = pos - target_start;
    pos++; /* space */

    if (target_len == 0 || target[0] != '/') {
        return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED,
                   "only origin-form request targets are supported");
    }
    size_t qmark = target_len;
    for (size_t i = 0; i < target_len; i++) {
        if (target[i] == '?') {
            qmark = i;
            break;
        }
    }
    out->path     = target;
    out->path_len = qmark;
    if (qmark < target_len) {
        out->query     = target + qmark + 1;
        out->query_len = target_len - qmark - 1;
    }

    size_t version_len = line_len - pos;
    if (version_len == 8 && memcmp(data + pos, "HTTP/1.1", 8) == 0) {
        out->minor_version = 1;
    } else if (version_len == 8 && memcmp(data + pos, "HTTP/1.0", 8) == 0) {
        out->minor_version = 0;
    } else {
        return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED,
                   "unsupported or malformed HTTP version");
    }

    size_t header_section_start = (size_t)line_end + 2;

    /* ---- headers: locate the whole block first, bounded, then parse
     * lines inside it. Bounding the block search up front (rather than
     * accumulating a running byte count line by line) means a peer can
     * never make this scan arbitrarily far into an oversized header
     * section before the cap is noticed. ---- */

    size_t header_region_limit = header_section_start + (size_t)limits->max_header_bytes + 2;
    if (header_region_limit > len) {
        header_region_limit = len;
    }

    /*
     * Scan starts at line_end (the request line's OWN terminating CRLF),
     * not header_section_start: when there are zero headers, the blank
     * line's CRLF immediately follows the request line's CRLF, so the
     * 4-byte "\r\n\r\n" pattern begins there, not two bytes later. Starting
     * the scan at header_section_start would miss the zero-header case
     * entirely and report every such request as perpetually incomplete.
     */
    long headers_terminator = -1;
    for (size_t i = (size_t)line_end; i + 3 < header_region_limit; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
            headers_terminator = (long)i;
            break;
        }
    }
    if (headers_terminator < 0) {
        if (len >= header_section_start + (size_t)limits->max_header_bytes + 2) {
            return fail(error_kind, err, errlen, PS_HTTP_ERR_HEADERS_TOO_LARGE,
                       "headers too large");
        }
        return PS_HTTP_PARSE_INCOMPLETE;
    }

    size_t headers_block_end = (size_t)headers_terminator + 2; /* up through the last header's CRLF */
    size_t after_headers      = (size_t)headers_terminator + 4; /* past the blank-line terminator too */

    bool have_content_length      = false;
    long content_length           = 0;
    bool have_transfer_encoding   = false;
    bool transfer_encoding_chunked = false;

    size_t cursor = header_section_start;
    while (cursor < headers_block_end) {
        long h_end = find_crlf(data, headers_block_end, cursor);
        if (h_end < 0) {
            /* Cannot happen: headers_block_end was derived from a CRLF we
             * already found. Treated as malformed rather than asserted,
             * since untrusted-input code should never trust its own
             * invariants that far (plan 7.2). */
            return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED, "malformed headers");
        }

        if (is_sp_or_htab(data[cursor])) {
            return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED,
                       "obsolete line folding is not supported");
        }

        size_t name_start = cursor;
        size_t p           = cursor;
        while (p < (size_t)h_end && data[p] != ':') {
            if (!is_tchar((unsigned char)data[p])) {
                return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED, "invalid header name");
            }
            p++;
        }
        if (p == name_start || p >= (size_t)h_end) {
            return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED, "malformed header line");
        }
        size_t name_len = p - name_start;
        p++; /* ':' */

        while (p < (size_t)h_end && is_sp_or_htab(data[p])) {
            p++;
        }
        size_t value_start = p;
        size_t value_end    = (size_t)h_end;
        while (value_end > value_start && is_sp_or_htab(data[value_end - 1])) {
            value_end--;
        }

        if (out->header_count >= PS_HTTP_MAX_HEADERS ||
            (int)out->header_count >= limits->max_header_count) {
            return fail(error_kind, err, errlen, PS_HTTP_ERR_TOO_MANY_HEADERS, "too many headers");
        }

        ps_http_header_t *h = &out->headers[out->header_count++];
        h->name              = data + name_start;
        h->name_len           = name_len;
        h->value              = data + value_start;
        h->value_len          = value_end - value_start;

        /*
         * Request-smuggling guard (RFC 7230 3.3.3): examined as each
         * header is parsed, not after the fact, so duplicates and
         * conflicts are caught deterministically regardless of ordering.
         */
        if (header_name_is(h, "Content-Length")) {
            if (have_content_length) {
                return fail(error_kind, err, errlen, PS_HTTP_ERR_CONTENT_LENGTH_INVALID,
                           "duplicate Content-Length header");
            }
            long v;
            if (!parse_nonneg_decimal(h->value, h->value_len, &v)) {
                return fail(error_kind, err, errlen, PS_HTTP_ERR_CONTENT_LENGTH_INVALID,
                           "invalid Content-Length");
            }
            have_content_length = true;
            content_length      = v;
        } else if (header_name_is(h, "Transfer-Encoding")) {
            have_transfer_encoding = true;
            if (header_value_is_token(h, "chunked")) {
                transfer_encoding_chunked = true;
            }
        }

        cursor = (size_t)h_end + 2;
    }

    if (have_content_length && have_transfer_encoding) {
        return fail(error_kind, err, errlen, PS_HTTP_ERR_CONTENT_LENGTH_INVALID,
                   "Content-Length and Transfer-Encoding must not both be present");
    }
    if (have_transfer_encoding) {
        if (!transfer_encoding_chunked) {
            return fail(error_kind, err, errlen, PS_HTTP_ERR_MALFORMED,
                       "unsupported Transfer-Encoding");
        }
        return fail(error_kind, err, errlen, PS_HTTP_ERR_CHUNKED_UNSUPPORTED,
                   "chunked request bodies are not supported");
    }

    /* ---- body ---- */

    if (!have_content_length || content_length == 0) {
        *consumed = after_headers;
        return PS_HTTP_PARSE_OK;
    }

    if (content_length > limits->max_body_bytes) {
        return fail(error_kind, err, errlen, PS_HTTP_ERR_BODY_TOO_LARGE,
                   "request body exceeds the configured limit");
    }

    size_t body_len = (size_t)content_length;
    if (len - after_headers < body_len) {
        return PS_HTTP_PARSE_INCOMPLETE;
    }

    out->body     = data + after_headers;
    out->body_len = body_len;
    *consumed      = after_headers + body_len;
    return PS_HTTP_PARSE_OK;
}
