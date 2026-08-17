/*
 * libFuzzer target for the HTTP/1.1 request parser (plan 8.6) -- the
 * highest-risk code in the project (R5): hand-written C consuming
 * untrusted bytes straight off the network, before authentication exists.
 *
 * Clang-only, CI-only (plan 8.6, 16.2): see fuzz_json_parse.c.
 */
#include <stddef.h>
#include <stdint.h>

#include "http/request.h"

/* libFuzzer's own runtime supplies main() and calls this; nothing in this
 * translation unit declares it otherwise, which -Wmissing-prototypes (the
 * project's own warning set, applied here too) correctly flags without one. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const ps_http_limits_t limits = {
        .max_request_line_bytes = 8192,
        .max_header_bytes       = 16384,
        .max_header_count       = 64,
        .max_body_bytes         = 1048576,
    };

    ps_http_request_t     req;
    size_t                 consumed;
    ps_http_parse_error_t  error_kind;
    char                    err[256];

    (void)ps_http_request_parse((const char *)data, size, &limits, &req, &consumed,
                                &error_kind, err, sizeof err);
    return 0;
}
