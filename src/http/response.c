#include "http/response.h"

#include <stdio.h>

#include "json/json_write.h"

static const char *reason_phrase(int status)
{
    switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
    }
}

bool ps_http_response_write(const ps_http_response_t *resp, ps_buf_t *buf)
{
    ps_buf_t body;
    ps_buf_init(&body);
    if (resp->json_body != NULL) {
        if (!ps_json_write(resp->json_body, &body)) {
            ps_buf_free(&body);
            return false;
        }
    }

    char status_line[64];
    int  n = snprintf(status_line, sizeof status_line, "HTTP/1.1 %d %s\r\n",
                      resp->status, reason_phrase(resp->status));
    if (n < 0 || (size_t)n >= sizeof status_line) {
        ps_buf_free(&body);
        return false;
    }

    bool ok = ps_buf_append(buf, status_line, (size_t)n);

    if (ok && resp->json_body != NULL) {
        ok = ps_buf_append_str(buf, "Content-Type: application/json\r\n");
    }

    if (ok) {
        char cl_line[64];
        int  cl_n = snprintf(cl_line, sizeof cl_line, "Content-Length: %zu\r\n", body.len);
        ok = (cl_n > 0 && (size_t)cl_n < sizeof cl_line) &&
             ps_buf_append(buf, cl_line, (size_t)cl_n);
    }

    if (ok) {
        ok = ps_buf_append_str(buf, resp->keep_alive ? "Connection: keep-alive\r\n"
                                                     : "Connection: close\r\n");
    }
    if (ok) {
        /* Unconditional, unlike Cache-Control: there is no response shape
         * where letting a browser MIME-sniff the body is ever desirable. */
        ok = ps_buf_append_str(buf, "X-Content-Type-Options: nosniff\r\n");
    }
    if (ok && resp->no_store) {
        ok = ps_buf_append_str(buf, "Cache-Control: no-store\r\n");
    }
    if (ok && resp->cors_origin != NULL) {
        char cors_line[320];
        int  cors_n = snprintf(cors_line, sizeof cors_line,
                               "Access-Control-Allow-Origin: %s\r\n"
                               "Vary: Origin\r\n",
                               resp->cors_origin);
        ok = (cors_n > 0 && (size_t)cors_n < sizeof cors_line) &&
             ps_buf_append(buf, cors_line, (size_t)cors_n);
        if (ok && resp->cors_allow_credentials) {
            ok = ps_buf_append_str(buf, "Access-Control-Allow-Credentials: true\r\n");
        }
        if (ok && resp->cors_allow_methods != NULL) {
            ok = ps_buf_append_str(buf, "Access-Control-Allow-Methods: ") &&
                 ps_buf_append_str(buf, resp->cors_allow_methods) &&
                 ps_buf_append_str(buf, "\r\n");
        }
        if (ok && resp->cors_allow_headers != NULL) {
            ok = ps_buf_append_str(buf, "Access-Control-Allow-Headers: ") &&
                 ps_buf_append_str(buf, resp->cors_allow_headers) &&
                 ps_buf_append_str(buf, "\r\n");
        }
    }
    if (ok) {
        ok = ps_buf_append_str(buf, "\r\n");
    }
    if (ok && body.len > 0) {
        ok = ps_buf_append(buf, body.data, body.len);
    }

    ps_buf_free(&body);
    return ok;
}

bool ps_http_response_write_error(int status, const char *code, const char *message,
                                  bool keep_alive, ps_buf_t *buf)
{
    ps_json_value_t *inner = ps_json_new_object();
    if (inner == NULL) {
        return false;
    }

    ps_json_value_t *code_val = ps_json_new_string(code);
    if (code_val == NULL || !ps_json_object_set(inner, "code", code_val)) {
        ps_json_free(code_val);
        ps_json_free(inner);
        return false;
    }

    ps_json_value_t *message_val = ps_json_new_string(message);
    if (message_val == NULL || !ps_json_object_set(inner, "message", message_val)) {
        ps_json_free(message_val);
        ps_json_free(inner);
        return false;
    }

    ps_json_value_t *outer = ps_json_new_object();
    if (outer == NULL) {
        ps_json_free(inner);
        return false;
    }
    if (!ps_json_object_set(outer, "error", inner)) {
        ps_json_free(inner);
        ps_json_free(outer);
        return false;
    }

    ps_http_response_t resp = {
        .status     = status,
        .keep_alive = keep_alive,
        .no_store   = true,
        .json_body  = outer,
    };
    bool wrote = ps_http_response_write(&resp, buf);
    ps_json_free(outer);
    return wrote;
}
