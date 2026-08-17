#include "auth/jwt.h"

#include <string.h>

#include "auth/claims.h"
#include "crypto/base64url.h"
#include "crypto/ct.h"
#include "crypto/hmac.h"
#include "platform/buf.h"

/*
 * base64url(`{"alg":"HS256","typ":"JWT"}`) -- the only header this service
 * ever emits or accepts. Verify compares a token's header segment against
 * this constant directly instead of decoding and parsing it, so there is
 * no code path that ever reads an attacker-supplied `alg`. test_jwt.c
 * round-trips this literal back through ps_base64url_decode, so a typo
 * here fails loudly instead of silently accepting a different header.
 */
#define PS_JWT_HEADER_B64 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

bool ps_jwt_encode(const ps_jwt_claims_t *claims,
                   const char *issuer, const char *audience,
                   const void *secret, size_t secret_len,
                   ps_buf_t *out)
{
    ps_buf_t payload_json;
    ps_buf_init(&payload_json);
    bool ok = ps_claims_write(claims, issuer, audience, &payload_json);

    ok = ok && ps_buf_append_str(out, PS_JWT_HEADER_B64);
    ok = ok && ps_buf_append_char(out, '.');
    ok = ok && ps_base64url_encode((const unsigned char *)payload_json.data,
                                   payload_json.len, out);
    ps_buf_free(&payload_json);
    if (!ok) {
        return false;
    }

    unsigned char sig[PS_HMAC_SHA256_LEN];
    if (!ps_hmac_sha256(secret, secret_len, out->data, out->len, sig)) {
        return false;
    }

    return ps_buf_append_char(out, '.') && ps_base64url_encode(sig, sizeof sig, out);
}

ps_jwt_verify_result_t ps_jwt_verify(const char *token, size_t token_len,
                                     const char *issuer, const char *audience,
                                     const void *secret, size_t secret_len,
                                     int64_t now, int clock_skew_s,
                                     ps_jwt_claims_t *out)
{
    const char *dot1 = memchr(token, '.', token_len);
    if (dot1 == NULL) {
        return PS_JWT_MALFORMED;
    }
    size_t      after_dot1 = (size_t)(dot1 - token) + 1;
    const char *dot2       = memchr(token + after_dot1, '.', token_len - after_dot1);
    if (dot2 == NULL) {
        return PS_JWT_MALFORMED;
    }
    size_t after_dot2 = (size_t)(dot2 - token) + 1;
    if (memchr(token + after_dot2, '.', token_len - after_dot2) != NULL) {
        return PS_JWT_MALFORMED; /* a fourth segment: reject rather than ignore the tail */
    }

    size_t header_len  = (size_t)(dot1 - token);
    size_t payload_len = (size_t)(dot2 - dot1 - 1);
    size_t sig_len      = token_len - after_dot2;
    if (header_len == 0 || payload_len == 0 || sig_len == 0) {
        return PS_JWT_MALFORMED;
    }

    if (header_len != sizeof(PS_JWT_HEADER_B64) - 1 ||
        memcmp(token, PS_JWT_HEADER_B64, header_len) != 0) {
        return PS_JWT_BAD_ALG;
    }

    ps_buf_t sig_bytes;
    ps_buf_init(&sig_bytes);
    bool sig_decoded = ps_base64url_decode(dot2 + 1, sig_len, &sig_bytes);
    if (!sig_decoded || sig_bytes.len != PS_HMAC_SHA256_LEN) {
        ps_buf_free(&sig_bytes);
        return PS_JWT_MALFORMED;
    }

    size_t        signing_input_len = after_dot2 - 1; /* header "." payload, no trailing dot */
    unsigned char expected_sig[PS_HMAC_SHA256_LEN];
    bool hmac_ok     = ps_hmac_sha256(secret, secret_len, token, signing_input_len, expected_sig);
    bool sig_matches = hmac_ok &&
                       ps_ct_equal(sig_bytes.data, expected_sig, PS_HMAC_SHA256_LEN);
    ps_buf_free(&sig_bytes);
    if (!sig_matches) {
        return PS_JWT_BAD_SIGNATURE;
    }

    ps_buf_t payload_json;
    ps_buf_init(&payload_json);
    bool payload_decoded = ps_base64url_decode(dot1 + 1, payload_len, &payload_json);
    if (!payload_decoded) {
        ps_buf_free(&payload_json);
        return PS_JWT_MALFORMED;
    }

    ps_claims_result_t claims_result = ps_claims_parse(
        payload_json.data, payload_json.len, issuer, audience, now, clock_skew_s, out);
    ps_buf_free(&payload_json);

    switch (claims_result) {
    case PS_CLAIMS_OK:            return PS_JWT_OK;
    case PS_CLAIMS_MALFORMED:     return PS_JWT_BAD_CLAIMS;
    case PS_CLAIMS_BAD_ISSUER:    return PS_JWT_BAD_ISSUER;
    case PS_CLAIMS_BAD_AUDIENCE:  return PS_JWT_BAD_AUDIENCE;
    case PS_CLAIMS_EXPIRED:       return PS_JWT_EXPIRED;
    case PS_CLAIMS_NOT_YET_VALID: return PS_JWT_NOT_YET_VALID;
    }
    return PS_JWT_BAD_CLAIMS; /* unreachable: every ps_claims_result_t is handled above */
}
