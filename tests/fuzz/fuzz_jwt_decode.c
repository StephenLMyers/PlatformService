/*
 * libFuzzer target for JWT verification (plan 8.6) -- the third of the
 * three entry points named from the start of phase 3's fuzzing work,
 * deferred until jwt.c existed to fuzz. Exercises the full plan 6.2
 * pipeline: segment parsing, header comparison, HMAC verification, and
 * claims parsing, all on attacker-controlled bytes.
 *
 * Clang-only, CI-only (plan 8.6, 16.2): see fuzz_json_parse.c.
 */
#include <stddef.h>
#include <stdint.h>

#include "auth/jwt.h"

/* Fixed verifier configuration -- what a real deployment's config would
 * supply. The fuzzer mutates the token, not these. */
static const char SECRET[]   = "fuzz-harness-secret-at-least-32-bytes-long";
static const char ISSUER[]   = "platformservice";
static const char AUDIENCE[] = "platformservice-api";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ps_jwt_claims_t claims;
    (void)ps_jwt_verify((const char *)data, size, ISSUER, AUDIENCE,
                        SECRET, sizeof SECRET - 1, 1700000000, 60, &claims);
    return 0;
}
