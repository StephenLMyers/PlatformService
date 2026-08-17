/*
 * libFuzzer target for the JSON parser (plan 8.6).
 *
 * Clang-only, CI-only (plan 8.6, 16.2): built and run exclusively via
 * `make fuzz` / `make fuzz-smoke`, which use Clang directly and never touch
 * the GCC-built build/ tree the rest of the project uses.
 */
#include <stddef.h>
#include <stdint.h>

#include "json/json_parse.h"

/* libFuzzer's own runtime supplies main() and calls this; nothing in this
 * translation unit declares it otherwise, which -Wmissing-prototypes (the
 * project's own warning set, applied here too) correctly flags without one. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char err[256];
    ps_json_value_t *v = ps_json_parse((const char *)data, size, err, sizeof err);
    ps_json_free(v);
    return 0;
}
