/*
 * JWS Compact, HS256 only (plan 6.1). The accepted `alg` is a compile-time
 * constant, never read from the token: ps_jwt_verify compares the token's
 * header segment against that constant byte-for-byte and rejects any
 * deviation, including "none" -- there is no code path that decodes or
 * dispatches on an attacker-supplied `alg` (plan 6.2's critical warning).
 */
#ifndef PS_AUTH_JWT_H
#define PS_AUTH_JWT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "auth/claims.h"
#include "platform/buf.h"

/* Encodes claims into a signed, compact JWS: base64url(header) "."
 * base64url(payload) "." base64url(signature). Appends to out; out must
 * already be initialized and empty (ps_buf_init) -- the signature is
 * computed over out's own bytes partway through, so anything already in
 * it would be signed as part of the token. */
bool ps_jwt_encode(const ps_jwt_claims_t *claims,
                   const char *issuer, const char *audience,
                   const void *secret, size_t secret_len,
                   ps_buf_t *out);

typedef enum {
    PS_JWT_OK = 0,
    PS_JWT_MALFORMED,       /* not exactly 3 non-empty segments, or a segment fails base64url decode */
    PS_JWT_BAD_ALG,         /* header segment isn't the one literal header this service accepts */
    PS_JWT_BAD_SIGNATURE,
    PS_JWT_BAD_CLAIMS,      /* payload decodes but fails ps_claims_parse's structural checks */
    PS_JWT_EXPIRED,
    PS_JWT_NOT_YET_VALID,
    PS_JWT_BAD_ISSUER,
    PS_JWT_BAD_AUDIENCE,
} ps_jwt_verify_result_t;

/*
 * Verifies a compact JWS end to end (plan 6.2, steps 2-6, in that exact
 * order): segment count, header, HMAC-SHA256 signature (constant-time),
 * then claims. Signature verification always precedes claim parsing, so a
 * forged token's payload bytes never reach the JSON parser.
 * now/clock_skew_s pass straight through to ps_claims_parse.
 */
ps_jwt_verify_result_t ps_jwt_verify(const char *token, size_t token_len,
                                     const char *issuer, const char *audience,
                                     const void *secret, size_t secret_len,
                                     int64_t now, int clock_skew_s,
                                     ps_jwt_claims_t *out);

#endif /* PS_AUTH_JWT_H */
