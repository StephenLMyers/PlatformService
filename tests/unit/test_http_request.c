#include "testutil.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "http/request.h"

static const ps_http_limits_t DEFAULT_LIMITS = {
    .max_request_line_bytes = 8192,
    .max_header_bytes       = 16384,
    .max_header_count       = 64,
    .max_body_bytes         = 1048576,
};

static ps_http_parse_result_t parse(const char *src, const ps_http_limits_t *limits,
                                    ps_http_request_t *out, size_t *consumed,
                                    ps_http_parse_error_t *error_kind)
{
    char err[256];
    return ps_http_request_parse(src, strlen(src), limits, out, consumed, error_kind,
                                 err, sizeof err);
}

static bool header_eq(const ps_http_header_t *h, const char *name, const char *value)
{
    return h != NULL &&
           strncmp(h->name, name, h->name_len) == 0 && strlen(name) == h->name_len &&
           strncmp(h->value, value, h->value_len) == 0 && strlen(value) == h->value_len;
}

/* ------------------------------------------------------------------------- */
/* Happy path                                                                 */
/* ------------------------------------------------------------------------- */

static void test_minimal_request(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    const char *src = "GET / HTTP/1.1\r\n\r\n";

    ps_http_parse_result_t rc = parse(src, &DEFAULT_LIMITS, &req, &consumed, &err_kind);

    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_OK);
    PS_CHECK(strncmp(req.method, "GET", req.method_len) == 0 && req.method_len == 3);
    PS_CHECK(strncmp(req.path, "/", req.path_len) == 0 && req.path_len == 1);
    PS_CHECK(req.query == NULL);
    PS_CHECK_EQ_INT(req.minor_version, 1);
    PS_CHECK_EQ_INT(req.header_count, 0);
    PS_CHECK(req.body == NULL);
    PS_CHECK_EQ_INT(req.body_len, 0);
    PS_CHECK_EQ_INT(consumed, strlen(src));
}

static void test_http_1_0_version(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc =
        parse("GET / HTTP/1.0\r\n\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);

    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_OK);
    PS_CHECK_EQ_INT(req.minor_version, 0);
}

static void test_request_with_headers(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    const char *src =
        "GET /v1/users/1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Bearer abc.def.ghi\r\n"
        "\r\n";

    ps_http_parse_result_t rc = parse(src, &DEFAULT_LIMITS, &req, &consumed, &err_kind);

    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_OK);
    PS_CHECK_EQ_INT(req.header_count, 2);
    PS_CHECK(header_eq(&req.headers[0], "Host", "example.com"));
    PS_CHECK(header_eq(&req.headers[1], "Authorization", "Bearer abc.def.ghi"));
    PS_CHECK_EQ_INT(consumed, strlen(src));
}

static void test_header_lookup_is_case_insensitive(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    parse("GET / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
         &DEFAULT_LIMITS, &req, &consumed, &err_kind);

    const ps_http_header_t *h = ps_http_request_header(&req, "content-type");
    PS_CHECK(h != NULL);
    PS_CHECK(header_eq(h, "Content-Type", "application/json"));
    PS_CHECK(ps_http_request_header(&req, "X-Missing") == NULL);
}

static void test_header_value_ows_trimmed(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    parse("GET / HTTP/1.1\r\nX-Test:   value with spaces   \r\n\r\n",
         &DEFAULT_LIMITS, &req, &consumed, &err_kind);

    const ps_http_header_t *h = ps_http_request_header(&req, "X-Test");
    PS_CHECK(h != NULL);
    PS_CHECK(strncmp(h->value, "value with spaces", h->value_len) == 0 &&
             h->value_len == strlen("value with spaces"));
}

static void test_query_string_split(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    parse("GET /v1/admin/users?after_id=1000&limit=500 HTTP/1.1\r\n\r\n",
         &DEFAULT_LIMITS, &req, &consumed, &err_kind);

    PS_CHECK(strncmp(req.path, "/v1/admin/users", req.path_len) == 0 &&
             req.path_len == strlen("/v1/admin/users"));
    PS_CHECK(req.query != NULL);
    PS_CHECK(strncmp(req.query, "after_id=1000&limit=500", req.query_len) == 0 &&
             req.query_len == strlen("after_id=1000&limit=500"));
}

static void test_request_with_body(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    const char *body = "{\"username\":\"a\",\"pw\":\"b\"}"; /* 25 bytes */
    char        src[256];
    (void)snprintf(src, sizeof src, "POST /v1/auth/login HTTP/1.1\r\nContent-Length: %zu\r\n\r\n%s",
                   strlen(body), body);

    ps_http_parse_result_t rc = parse(src, &DEFAULT_LIMITS, &req, &consumed, &err_kind);

    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_OK);
    PS_CHECK(req.body != NULL);
    if (req.body != NULL) {
        PS_CHECK_EQ_INT(req.body_len, strlen(body));
        PS_CHECK(strncmp(req.body, body, req.body_len) == 0);
    }
    PS_CHECK_EQ_INT(consumed, strlen(src));
}

static void test_content_length_zero_means_no_body(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc =
        parse("POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
             &DEFAULT_LIMITS, &req, &consumed, &err_kind);

    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_OK);
    PS_CHECK(req.body == NULL);
    PS_CHECK_EQ_INT(req.body_len, 0);
}

static void test_pipelined_requests_second_starts_at_consumed(void)
{
    const char *src = "GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
    ps_http_request_t     req1;
    size_t                 consumed1;
    ps_http_parse_error_t  err_kind;
    char err[256];

    ps_http_parse_result_t rc1 = ps_http_request_parse(
        src, strlen(src), &DEFAULT_LIMITS, &req1, &consumed1, &err_kind, err, sizeof err);
    PS_CHECK_EQ_INT(rc1, PS_HTTP_PARSE_OK);
    PS_CHECK(strncmp(req1.path, "/a", req1.path_len) == 0 && req1.path_len == 2);

    ps_http_request_t req2;
    size_t             consumed2;
    ps_http_parse_result_t rc2 = ps_http_request_parse(
        src + consumed1, strlen(src) - consumed1, &DEFAULT_LIMITS, &req2, &consumed2,
        &err_kind, err, sizeof err);
    PS_CHECK_EQ_INT(rc2, PS_HTTP_PARSE_OK);
    PS_CHECK(strncmp(req2.path, "/b", req2.path_len) == 0 && req2.path_len == 2);
    PS_CHECK_EQ_INT(consumed1 + consumed2, strlen(src));
}

/* ------------------------------------------------------------------------- */
/* Incomplete -- not an error, needs more bytes                              */
/* ------------------------------------------------------------------------- */

static void test_incomplete_request_line(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse("GET / HTTP/1.1", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_INCOMPLETE);
}

static void test_incomplete_headers(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc =
        parse("GET / HTTP/1.1\r\nHost: example.com\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_INCOMPLETE);
}

static void test_incomplete_body(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc =
        parse("POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort",
             &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_INCOMPLETE);
}

/* ------------------------------------------------------------------------- */
/* Malformed request line                                                    */
/* ------------------------------------------------------------------------- */

static void test_invalid_method_token_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc =
        parse("GE(T / HTTP/1.1\r\n\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_MALFORMED);
}

static void test_missing_target_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse("GET  \r\n\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
}

static void test_non_origin_form_target_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc =
        parse("GET http://example.com/ HTTP/1.1\r\n\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_MALFORMED);
}

static void test_asterisk_form_target_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc =
        parse("OPTIONS * HTTP/1.1\r\n\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
}

static void test_unsupported_version_rejected(void)
{
    static const char *const bad[] = {
        "GET / HTTP/2.0\r\n\r\n",
        "GET / HTTP/0.9\r\n\r\n",
        "GET / HTTP/1.1x\r\n\r\n",
        "GET / garbage\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        ps_http_request_t     req;
        size_t                 consumed;
        ps_http_parse_error_t  err_kind;
        ps_http_parse_result_t rc = parse(bad[i], &DEFAULT_LIMITS, &req, &consumed, &err_kind);
        PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    }
}

static void test_request_line_too_long_rejected(void)
{
    ps_http_limits_t tiny_limits = DEFAULT_LIMITS;
    tiny_limits.max_request_line_bytes = 16;

    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc =
        parse("GET /a/very/long/path/that/exceeds/the/limit HTTP/1.1\r\n\r\n",
             &tiny_limits, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_LINE_TOO_LONG);
}

/* ------------------------------------------------------------------------- */
/* Malformed headers                                                         */
/* ------------------------------------------------------------------------- */

static void test_obs_fold_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "GET / HTTP/1.1\r\nX-Test: a\r\n b\r\n\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_MALFORMED);
}

static void test_space_before_colon_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "GET / HTTP/1.1\r\nX-Test : value\r\n\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
}

static void test_header_without_colon_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "GET / HTTP/1.1\r\nNotAHeader\r\n\r\n", &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
}

static void test_too_many_headers_rejected(void)
{
    ps_http_limits_t limits = DEFAULT_LIMITS;
    limits.max_header_count = 2;

    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", &limits, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_TOO_MANY_HEADERS);
}

static void test_headers_too_large_rejected(void)
{
    ps_http_limits_t limits = DEFAULT_LIMITS;
    limits.max_header_bytes = 32;

    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "GET / HTTP/1.1\r\nX-Long-Header-Name: a-fairly-long-value-here\r\n\r\n",
        &limits, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_HEADERS_TOO_LARGE);
}

/* ------------------------------------------------------------------------- */
/* Content-Length / Transfer-Encoding -- request smuggling guards            */
/* ------------------------------------------------------------------------- */

static void test_invalid_content_length_rejected(void)
{
    static const char *const bad[] = {
        "POST /x HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
        "POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        "POST /x HTTP/1.1\r\nContent-Length: 1.5\r\n\r\n",
        "POST /x HTTP/1.1\r\nContent-Length: \r\n\r\n",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        ps_http_request_t     req;
        size_t                 consumed;
        ps_http_parse_error_t  err_kind;
        ps_http_parse_result_t rc = parse(bad[i], &DEFAULT_LIMITS, &req, &consumed, &err_kind);
        PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
        PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_CONTENT_LENGTH_INVALID);
    }
}

static void test_duplicate_content_length_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_CONTENT_LENGTH_INVALID);
}

static void test_content_length_and_transfer_encoding_both_present_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "POST /x HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
        &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_CONTENT_LENGTH_INVALID);
}

static void test_chunked_transfer_encoding_rejected_as_unsupported(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_CHUNKED_UNSUPPORTED);
}

static void test_unknown_transfer_encoding_rejected(void)
{
    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "POST /x HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
        &DEFAULT_LIMITS, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_MALFORMED);
}

static void test_body_too_large_rejected(void)
{
    ps_http_limits_t limits = DEFAULT_LIMITS;
    limits.max_body_bytes = 10;

    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  err_kind;
    ps_http_parse_result_t rc = parse(
        "POST /x HTTP/1.1\r\nContent-Length: 1000\r\n\r\n",
        &limits, &req, &consumed, &err_kind);
    PS_CHECK_EQ_INT(rc, PS_HTTP_PARSE_ERROR);
    PS_CHECK_EQ_INT(err_kind, PS_HTTP_ERR_BODY_TOO_LARGE);
}

int main(void)
{
    PS_RUN_TEST(test_minimal_request);
    PS_RUN_TEST(test_http_1_0_version);
    PS_RUN_TEST(test_request_with_headers);
    PS_RUN_TEST(test_header_lookup_is_case_insensitive);
    PS_RUN_TEST(test_header_value_ows_trimmed);
    PS_RUN_TEST(test_query_string_split);
    PS_RUN_TEST(test_request_with_body);
    PS_RUN_TEST(test_content_length_zero_means_no_body);
    PS_RUN_TEST(test_pipelined_requests_second_starts_at_consumed);

    PS_RUN_TEST(test_incomplete_request_line);
    PS_RUN_TEST(test_incomplete_headers);
    PS_RUN_TEST(test_incomplete_body);

    PS_RUN_TEST(test_invalid_method_token_rejected);
    PS_RUN_TEST(test_missing_target_rejected);
    PS_RUN_TEST(test_non_origin_form_target_rejected);
    PS_RUN_TEST(test_asterisk_form_target_rejected);
    PS_RUN_TEST(test_unsupported_version_rejected);
    PS_RUN_TEST(test_request_line_too_long_rejected);

    PS_RUN_TEST(test_obs_fold_rejected);
    PS_RUN_TEST(test_space_before_colon_rejected);
    PS_RUN_TEST(test_header_without_colon_rejected);
    PS_RUN_TEST(test_too_many_headers_rejected);
    PS_RUN_TEST(test_headers_too_large_rejected);

    PS_RUN_TEST(test_invalid_content_length_rejected);
    PS_RUN_TEST(test_duplicate_content_length_rejected);
    PS_RUN_TEST(test_content_length_and_transfer_encoding_both_present_rejected);
    PS_RUN_TEST(test_chunked_transfer_encoding_rejected_as_unsupported);
    PS_RUN_TEST(test_unknown_transfer_encoding_rejected);
    PS_RUN_TEST(test_body_too_large_rejected);

    PS_TEST_EXIT();
}
