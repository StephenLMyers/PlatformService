#include "testutil.h"

#include <string.h>

#include "auth/jwt.h"
#include "crypto/base64url.h"
#include "platform/buf.h"

#define ISSUER   "platformservice"
#define AUDIENCE "platformservice-api"
#define SECRET   "0123456789abcdef0123456789abcdef" /* 33 bytes, well over PS_JWT_SECRET_MIN */

static ps_jwt_claims_t sample_claims(int64_t now)
{
    ps_jwt_claims_t c;
    c.user_id = 7;
    c.roles   = PS_JWT_ROLE_USER;
    c.iat     = now;
    c.nbf     = now;
    c.exp     = now + 900;
    memcpy(c.jti, "fedcba9876543210fedcba9876543210", PS_JWT_JTI_HEX_LEN);
    c.jti[PS_JWT_JTI_HEX_LEN] = '\0';
    memcpy(c.family_id, "0123456789abcdef0123456789abcdef", PS_JWT_FAMILY_ID_HEX_LEN);
    c.family_id[PS_JWT_FAMILY_ID_HEX_LEN] = '\0';
    return c;
}

static void encode_sample(ps_buf_t *out, int64_t now)
{
    ps_jwt_claims_t c = sample_claims(now);
    ps_buf_init(out);
    PS_CHECK(ps_jwt_encode(&c, ISSUER, AUDIENCE, SECRET, strlen(SECRET), out));
}

static void test_encode_produces_three_dot_separated_segments(void)
{
    ps_buf_t token;
    encode_sample(&token, 1000);

    int dots = 0;
    for (size_t i = 0; i < token.len; i++) {
        if (token.data[i] == '.') {
            dots++;
        }
    }
    PS_CHECK_EQ_INT(dots, 2);
    ps_buf_free(&token);
}

static void test_header_constant_decodes_to_the_documented_header(void)
{
    /* Regression net for jwt.c's hardcoded PS_JWT_HEADER_B64: if that
     * literal is ever edited incorrectly, this fails immediately instead
     * of silently accepting/emitting the wrong header. */
    ps_buf_t token;
    encode_sample(&token, 1000);

    const char *dot = memchr(token.data, '.', token.len);
    PS_CHECK(dot != NULL);
    size_t header_len = (size_t)(dot - token.data);

    ps_buf_t decoded;
    ps_buf_init(&decoded);
    PS_CHECK(ps_base64url_decode(token.data, header_len, &decoded));
    PS_CHECK(memcmp(decoded.data, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", decoded.len) == 0);

    ps_buf_free(&decoded);
    ps_buf_free(&token);
}

static void test_round_trip_encode_then_verify_succeeds(void)
{
    ps_buf_t token;
    encode_sample(&token, 1000);

    ps_jwt_claims_t          out;
    ps_jwt_verify_result_t r = ps_jwt_verify(token.data, token.len, ISSUER, AUDIENCE,
                                             SECRET, strlen(SECRET), 1000, 60, &out);
    ps_buf_free(&token);

    PS_CHECK_EQ_INT(r, PS_JWT_OK);
    PS_CHECK_EQ_INT(out.user_id, 7);
    PS_CHECK_EQ_INT(out.roles, PS_JWT_ROLE_USER);
}

static void test_wrong_secret_rejected(void)
{
    ps_buf_t token;
    encode_sample(&token, 1000);

    ps_jwt_claims_t          out;
    ps_jwt_verify_result_t r = ps_jwt_verify(token.data, token.len, ISSUER, AUDIENCE,
                                             "a-completely-different-secret-value", 36,
                                             1000, 60, &out);
    ps_buf_free(&token);
    PS_CHECK_EQ_INT(r, PS_JWT_BAD_SIGNATURE);
}

static void test_tampered_payload_rejected(void)
{
    ps_buf_t token;
    encode_sample(&token, 1000);

    /* Flip one bit in the middle of the payload segment (past the first
     * '.'), leaving the signature untouched -- must fail signature
     * verification, not silently parse a different set of claims. */
    const char *dot = memchr(token.data, '.', token.len);
    size_t      idx = (size_t)(dot - token.data) + 4;
    token.data[idx] ^= 0x01;

    ps_jwt_claims_t          out;
    ps_jwt_verify_result_t r = ps_jwt_verify(token.data, token.len, ISSUER, AUDIENCE,
                                             SECRET, strlen(SECRET), 1000, 60, &out);
    ps_buf_free(&token);
    PS_CHECK_EQ_INT(r, PS_JWT_BAD_SIGNATURE);
}

static void test_alg_none_header_rejected(void)
{
    /* The classic JWT break: an attacker swaps the header to claim
     * alg=none. ps_jwt_verify must reject this by comparing the header
     * segment against its one fixed accepted value, never by decoding and
     * trusting the token's own alg field. */
    ps_buf_t forged;
    ps_buf_init(&forged);
    PS_CHECK(ps_base64url_encode((const unsigned char *)"{\"alg\":\"none\",\"typ\":\"JWT\"}",
                                 27, &forged));

    /* Splice a real token's payload and signature segments (everything
     * from its first '.' onward) after our forged header. */
    ps_buf_t real;
    encode_sample(&real, 1000);
    const char *dot1 = memchr(real.data, '.', real.len);
    PS_CHECK(ps_buf_append(&forged, dot1, real.len - (size_t)(dot1 - real.data)));
    ps_buf_free(&real);

    ps_jwt_claims_t          out;
    ps_jwt_verify_result_t r = ps_jwt_verify(forged.data, forged.len, ISSUER, AUDIENCE,
                                             SECRET, strlen(SECRET), 1000, 60, &out);
    ps_buf_free(&forged);
    PS_CHECK_EQ_INT(r, PS_JWT_BAD_ALG);
}

static void test_two_segments_rejected(void)
{
    ps_jwt_claims_t          out;
    ps_jwt_verify_result_t r =
        ps_jwt_verify("onlyone.segments", 16, ISSUER, AUDIENCE, SECRET, strlen(SECRET), 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_JWT_MALFORMED);
}

static void test_four_segments_rejected(void)
{
    ps_jwt_claims_t          out;
    static const char        token[] = "a.b.c.d";
    ps_jwt_verify_result_t r = ps_jwt_verify(token, sizeof token - 1, ISSUER, AUDIENCE,
                                             SECRET, strlen(SECRET), 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_JWT_MALFORMED);
}

static void test_empty_segment_rejected(void)
{
    ps_jwt_claims_t          out;
    static const char        token[] = "..sig";
    ps_jwt_verify_result_t r = ps_jwt_verify(token, sizeof token - 1, ISSUER, AUDIENCE,
                                             SECRET, strlen(SECRET), 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_JWT_MALFORMED);
}

static void test_expired_token_rejected(void)
{
    ps_buf_t token;
    encode_sample(&token, 1000); /* exp = 1900 */

    ps_jwt_claims_t          out;
    ps_jwt_verify_result_t r = ps_jwt_verify(token.data, token.len, ISSUER, AUDIENCE,
                                             SECRET, strlen(SECRET), 5000, 60, &out);
    ps_buf_free(&token);
    PS_CHECK_EQ_INT(r, PS_JWT_EXPIRED);
}

static void test_malformed_base64_segment_rejected(void)
{
    ps_jwt_claims_t          out;
    static const char        token[] = "has spaces.also bad.sig!!";
    ps_jwt_verify_result_t r = ps_jwt_verify(token, sizeof token - 1, ISSUER, AUDIENCE,
                                             SECRET, strlen(SECRET), 1000, 60, &out);
    PS_CHECK(r == PS_JWT_MALFORMED || r == PS_JWT_BAD_ALG);
}

int main(void)
{
    PS_RUN_TEST(test_encode_produces_three_dot_separated_segments);
    PS_RUN_TEST(test_header_constant_decodes_to_the_documented_header);
    PS_RUN_TEST(test_round_trip_encode_then_verify_succeeds);
    PS_RUN_TEST(test_wrong_secret_rejected);
    PS_RUN_TEST(test_tampered_payload_rejected);
    PS_RUN_TEST(test_alg_none_header_rejected);
    PS_RUN_TEST(test_two_segments_rejected);
    PS_RUN_TEST(test_four_segments_rejected);
    PS_RUN_TEST(test_empty_segment_rejected);
    PS_RUN_TEST(test_expired_token_rejected);
    PS_RUN_TEST(test_malformed_base64_segment_rejected);
    PS_TEST_EXIT();
}
