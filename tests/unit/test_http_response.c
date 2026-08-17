#include "testutil.h"

#include <stdio.h>
#include <string.h>

#include "http/response.h"
#include "json/json_parse.h"
#include "platform/buf.h"

/* NUL-terminates buf's content so the standard string functions below can
 * be used directly in assertions -- test-only convenience, never done in
 * the real response path (which stays purely length-based throughout). */
static const char *cstr(ps_buf_t *buf)
{
    PS_CHECK(ps_buf_append_char(buf, '\0'));
    return buf->data;
}

static void test_status_line_and_reason_phrase(void)
{
    ps_json_value_t *body = ps_json_new_object();
    PS_CHECK(ps_json_object_set(body, "status", ps_json_new_string("ACTIVE")));

    ps_http_response_t resp = { .status = 200, .keep_alive = true, .no_store = false,
                                .json_body = body };
    ps_buf_t buf;
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp, &buf));

    const char *out = cstr(&buf);
    PS_CHECK(strncmp(out, "HTTP/1.1 200 OK\r\n", strlen("HTTP/1.1 200 OK\r\n")) == 0);

    ps_buf_free(&buf);
    ps_json_free(body);
}

static void test_json_body_included_with_content_type_and_length(void)
{
    ps_json_value_t *body = ps_json_new_object();
    PS_CHECK(ps_json_object_set(body, "count", ps_json_new_number(2500)));

    ps_http_response_t resp = { .status = 200, .keep_alive = true, .no_store = false,
                                .json_body = body };
    ps_buf_t buf;
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp, &buf));

    const char *out = cstr(&buf);
    PS_CHECK(strstr(out, "Content-Type: application/json\r\n") != NULL);
    PS_CHECK(strstr(out, "Content-Length: 14\r\n") != NULL); /* {"count":2500} = 14 bytes */
    PS_CHECK(strstr(out, "\r\n\r\n{\"count\":2500}") != NULL);

    ps_buf_free(&buf);
    ps_json_free(body);
}

static void test_no_body_response(void)
{
    ps_http_response_t resp = { .status = 204, .keep_alive = true, .no_store = false,
                                .json_body = NULL };
    ps_buf_t buf;
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp, &buf));

    const char *out = cstr(&buf);
    PS_CHECK(strncmp(out, "HTTP/1.1 204 No Content\r\n", strlen("HTTP/1.1 204 No Content\r\n")) == 0);
    PS_CHECK(strstr(out, "Content-Type:") == NULL);
    PS_CHECK(strstr(out, "Content-Length: 0\r\n") != NULL);
    /* Nothing at all after the blank line that ends the headers. */
    const char *headers_end = strstr(out, "\r\n\r\n");
    PS_CHECK(headers_end != NULL);
    PS_CHECK_STR_EQ(headers_end + 4, "");

    ps_buf_free(&buf);
}

static void test_connection_header_reflects_keep_alive(void)
{
    ps_buf_t buf;

    ps_http_response_t resp_keep = { .status = 200, .keep_alive = true, .no_store = false,
                                     .json_body = NULL };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp_keep, &buf));
    PS_CHECK(strstr(cstr(&buf), "Connection: keep-alive\r\n") != NULL);
    ps_buf_free(&buf);

    ps_http_response_t resp_close = { .status = 200, .keep_alive = false, .no_store = false,
                                      .json_body = NULL };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp_close, &buf));
    PS_CHECK(strstr(cstr(&buf), "Connection: close\r\n") != NULL);
    ps_buf_free(&buf);
}

static void test_nosniff_always_present(void)
{
    ps_buf_t buf;
    ps_http_response_t resp = { .status = 200, .keep_alive = true, .no_store = false,
                                .json_body = NULL };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp, &buf));
    PS_CHECK(strstr(cstr(&buf), "X-Content-Type-Options: nosniff\r\n") != NULL);
    ps_buf_free(&buf);
}

static void test_no_store_is_conditional(void)
{
    ps_buf_t buf;

    ps_http_response_t resp_public = { .status = 200, .keep_alive = true, .no_store = false,
                                       .json_body = NULL };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp_public, &buf));
    PS_CHECK(strstr(cstr(&buf), "Cache-Control:") == NULL);
    ps_buf_free(&buf);

    ps_http_response_t resp_authed = { .status = 200, .keep_alive = true, .no_store = true,
                                       .json_body = NULL };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp_authed, &buf));
    PS_CHECK(strstr(cstr(&buf), "Cache-Control: no-store\r\n") != NULL);
    ps_buf_free(&buf);
}

static void test_error_envelope_shape(void)
{
    ps_buf_t buf;
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write_error(403, "FORBIDDEN", "Insufficient privileges",
                                          true, &buf));

    const char *out = cstr(&buf);
    PS_CHECK(strncmp(out, "HTTP/1.1 403 Forbidden\r\n", strlen("HTTP/1.1 403 Forbidden\r\n")) == 0);
    PS_CHECK(strstr(out, "{\"error\":{\"code\":\"FORBIDDEN\",\"message\":\"Insufficient privileges\"}}")
             != NULL);
    /* Error bodies are never cacheable, unconditionally. */
    PS_CHECK(strstr(out, "Cache-Control: no-store\r\n") != NULL);

    ps_buf_free(&buf);
}

static void test_various_status_reason_phrases(void)
{
    static const struct { int status; const char *phrase; } cases[] = {
        { 400, "Bad Request" },
        { 401, "Unauthorized" },
        { 404, "Not Found" },
        { 405, "Method Not Allowed" },
        { 409, "Conflict" },
        { 413, "Payload Too Large" },
        { 429, "Too Many Requests" },
        { 500, "Internal Server Error" },
        { 501, "Not Implemented" },
        { 503, "Service Unavailable" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ps_buf_t buf;
        ps_buf_init(&buf);
        PS_CHECK(ps_http_response_write_error(cases[i].status, "X", "y", false, &buf));

        char expected[64];
        (void)snprintf(expected, sizeof expected, "HTTP/1.1 %d %s\r\n", cases[i].status,
                       cases[i].phrase);
        PS_CHECK(strncmp(cstr(&buf), expected, strlen(expected)) == 0);
        ps_buf_free(&buf);
    }
}

static void test_cors_headers_absent_by_default(void)
{
    ps_buf_t            buf;
    ps_http_response_t  resp = { .status = 200, .keep_alive = true, .no_store = false,
                                .json_body = NULL };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp, &buf));

    const char *out = cstr(&buf);
    PS_CHECK(strstr(out, "Access-Control-") == NULL);
    PS_CHECK(strstr(out, "Vary:") == NULL);

    ps_buf_free(&buf);
}

static void test_cors_origin_echoed_when_set(void)
{
    ps_buf_t            buf;
    ps_http_response_t  resp = { .status = 200, .keep_alive = true, .no_store = false,
                                .json_body = NULL, .cors_origin = "https://example.com" };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp, &buf));

    const char *out = cstr(&buf);
    PS_CHECK(strstr(out, "Access-Control-Allow-Origin: https://example.com\r\n") != NULL);
    PS_CHECK(strstr(out, "Vary: Origin\r\n") != NULL);
    PS_CHECK(strstr(out, "Access-Control-Allow-Credentials:") == NULL);
    PS_CHECK(strstr(out, "Access-Control-Allow-Methods:") == NULL);
    PS_CHECK(strstr(out, "Access-Control-Allow-Headers:") == NULL);

    ps_buf_free(&buf);
}

static void test_cors_credentials_header_conditional(void)
{
    ps_buf_t            buf;
    ps_http_response_t  resp = { .status = 200, .keep_alive = true, .no_store = false,
                                .json_body = NULL, .cors_origin = "https://example.com",
                                .cors_allow_credentials = true };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp, &buf));

    PS_CHECK(strstr(cstr(&buf), "Access-Control-Allow-Credentials: true\r\n") != NULL);
    ps_buf_free(&buf);
}

static void test_cors_preflight_headers(void)
{
    ps_buf_t            buf;
    ps_http_response_t  resp = {
        .status = 204, .keep_alive = true, .no_store = false, .json_body = NULL,
        .cors_origin = "https://example.com",
        .cors_allow_methods = "GET, POST, PUT, DELETE, OPTIONS",
        .cors_allow_headers = "Content-Type, Authorization",
    };
    ps_buf_init(&buf);
    PS_CHECK(ps_http_response_write(&resp, &buf));

    const char *out = cstr(&buf);
    PS_CHECK(strstr(out, "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n")
             != NULL);
    PS_CHECK(strstr(out, "Access-Control-Allow-Headers: Content-Type, Authorization\r\n")
             != NULL);

    ps_buf_free(&buf);
}

int main(void)
{
    PS_RUN_TEST(test_status_line_and_reason_phrase);
    PS_RUN_TEST(test_json_body_included_with_content_type_and_length);
    PS_RUN_TEST(test_no_body_response);
    PS_RUN_TEST(test_connection_header_reflects_keep_alive);
    PS_RUN_TEST(test_nosniff_always_present);
    PS_RUN_TEST(test_no_store_is_conditional);
    PS_RUN_TEST(test_error_envelope_shape);
    PS_RUN_TEST(test_various_status_reason_phrases);
    PS_RUN_TEST(test_cors_headers_absent_by_default);
    PS_RUN_TEST(test_cors_origin_echoed_when_set);
    PS_RUN_TEST(test_cors_credentials_header_conditional);
    PS_RUN_TEST(test_cors_preflight_headers);

    PS_TEST_EXIT();
}
