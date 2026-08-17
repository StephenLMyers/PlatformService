/*
 * JWT claim struct and its JSON shape (plan 6.1). Split from jwt.c: this
 * file owns the claim struct and semantic validation (issuer, audience,
 * time window); jwt.c owns the JWS wire format and signature.
 */
#ifndef PS_AUTH_CLAIMS_H
#define PS_AUTH_CLAIMS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "platform/buf.h"

#define PS_JWT_ROLE_USER  (1u << 0)
#define PS_JWT_ROLE_ADMIN (1u << 1)

/* 128-bit jti, hex-encoded: 32 chars + NUL (plan 6.1). */
#define PS_JWT_JTI_HEX_LEN 32

typedef struct {
    int64_t  user_id;   /* sub */
    uint32_t roles;     /* PS_JWT_ROLE_* bitmask */
    int64_t  iat;
    int64_t  nbf;
    int64_t  exp;
    char     jti[PS_JWT_JTI_HEX_LEN + 1];
} ps_jwt_claims_t;

/* Serializes claims as the JWT payload JSON object (plan 6.1's exact
 * shape), including iss/aud -- those live in config rather than the
 * claims struct, since every token this service issues shares one issuer
 * and audience. Appends to out. */
bool ps_claims_write(const ps_jwt_claims_t *claims, const char *issuer,
                     const char *audience, ps_buf_t *out);

typedef enum {
    PS_CLAIMS_OK = 0,
    PS_CLAIMS_MALFORMED,     /* not a JSON object, or a required field missing/wrong type/shape */
    PS_CLAIMS_BAD_ISSUER,
    PS_CLAIMS_BAD_AUDIENCE,
    PS_CLAIMS_EXPIRED,
    PS_CLAIMS_NOT_YET_VALID,
} ps_claims_result_t;

/*
 * Parses payload JSON and validates iss/aud/exp/nbf (plan 6.2 steps 5-6).
 * now/clock_skew_s implement the plan's +-60s allowance around exp/nbf.
 * iat is parsed but not itself validated -- it has no window of its own,
 * it's purely informational.
 *
 * Trusts every byte it's given: signature verification is jwt.c's job and
 * must happen before this is ever called on untrusted input.
 */
ps_claims_result_t ps_claims_parse(const char *json, size_t len,
                                   const char *issuer, const char *audience,
                                   int64_t now, int clock_skew_s,
                                   ps_jwt_claims_t *out);

#endif /* PS_AUTH_CLAIMS_H */
