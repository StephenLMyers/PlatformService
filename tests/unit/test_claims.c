#include "testutil.h"

#include <string.h>

#include "auth/claims.h"
#include "platform/buf.h"

#define ISSUER   "platformservice"
#define AUDIENCE "platformservice-api"

static ps_jwt_claims_t sample_claims(int64_t now)
{
    ps_jwt_claims_t c;
    c.user_id = 42;
    c.roles   = PS_JWT_ROLE_USER;
    c.iat     = now;
    c.nbf     = now;
    c.exp     = now + 900;
    memcpy(c.jti, "0123456789abcdef0123456789abcdef", PS_JWT_JTI_HEX_LEN);
    c.jti[PS_JWT_JTI_HEX_LEN] = '\0';
    return c;
}

static void test_write_produces_expected_shape(void)
{
    ps_jwt_claims_t c = sample_claims(1000);
    ps_buf_t        out;
    ps_buf_init(&out);
    PS_CHECK(ps_claims_write(&c, ISSUER, AUDIENCE, &out));

    /* Spot-check the pieces rather than the whole string, so key
     * reordering in json_write.c (if it ever happened) wouldn't make this
     * an overly brittle test. */
    PS_CHECK(memmem(out.data, out.len, "\"iss\":\"platformservice\"", 23) != NULL);
    PS_CHECK(memmem(out.data, out.len, "\"sub\":\"42\"", 10) != NULL);
    PS_CHECK(memmem(out.data, out.len, "\"aud\":\"platformservice-api\"", 27) != NULL);
    PS_CHECK(memmem(out.data, out.len, "\"roles\":[\"USER\"]", 16) != NULL);
    ps_buf_free(&out);
}

static void test_round_trip_preserves_all_fields(void)
{
    ps_jwt_claims_t written = sample_claims(1000);
    written.roles           = PS_JWT_ROLE_USER | PS_JWT_ROLE_ADMIN;

    ps_buf_t json;
    ps_buf_init(&json);
    PS_CHECK(ps_claims_write(&written, ISSUER, AUDIENCE, &json));

    ps_jwt_claims_t parsed;
    ps_claims_result_t r =
        ps_claims_parse(json.data, json.len, ISSUER, AUDIENCE, 1000, 60, &parsed);
    ps_buf_free(&json);

    PS_CHECK_EQ_INT(r, PS_CLAIMS_OK);
    PS_CHECK_EQ_INT(parsed.user_id, written.user_id);
    PS_CHECK_EQ_INT(parsed.roles, written.roles);
    PS_CHECK_EQ_INT(parsed.iat, written.iat);
    PS_CHECK_EQ_INT(parsed.nbf, written.nbf);
    PS_CHECK_EQ_INT(parsed.exp, written.exp);
    PS_CHECK_STR_EQ(parsed.jti, written.jti);
}

static void test_no_roles_round_trips_to_empty_bitmask(void)
{
    ps_jwt_claims_t written = sample_claims(1000);
    written.roles           = 0;

    ps_buf_t json;
    ps_buf_init(&json);
    PS_CHECK(ps_claims_write(&written, ISSUER, AUDIENCE, &json));

    ps_jwt_claims_t parsed;
    ps_claims_result_t r =
        ps_claims_parse(json.data, json.len, ISSUER, AUDIENCE, 1000, 60, &parsed);
    ps_buf_free(&json);

    PS_CHECK_EQ_INT(r, PS_CLAIMS_OK);
    PS_CHECK_EQ_INT(parsed.roles, 0);
}

static void test_wrong_issuer_rejected(void)
{
    ps_jwt_claims_t c = sample_claims(1000);
    ps_buf_t        json;
    ps_buf_init(&json);
    PS_CHECK(ps_claims_write(&c, ISSUER, AUDIENCE, &json));

    ps_jwt_claims_t out;
    ps_claims_result_t r =
        ps_claims_parse(json.data, json.len, "someone-else", AUDIENCE, 1000, 60, &out);
    ps_buf_free(&json);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_BAD_ISSUER);
}

static void test_wrong_audience_rejected(void)
{
    ps_jwt_claims_t c = sample_claims(1000);
    ps_buf_t        json;
    ps_buf_init(&json);
    PS_CHECK(ps_claims_write(&c, ISSUER, AUDIENCE, &json));

    ps_jwt_claims_t out;
    ps_claims_result_t r =
        ps_claims_parse(json.data, json.len, ISSUER, "someone-elses-api", 1000, 60, &out);
    ps_buf_free(&json);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_BAD_AUDIENCE);
}

static void test_expired_token_rejected(void)
{
    ps_jwt_claims_t c = sample_claims(1000); /* exp = 1900 */
    ps_buf_t        json;
    ps_buf_init(&json);
    PS_CHECK(ps_claims_write(&c, ISSUER, AUDIENCE, &json));

    ps_jwt_claims_t out;
    /* now is well past exp + skew */
    ps_claims_result_t r =
        ps_claims_parse(json.data, json.len, ISSUER, AUDIENCE, 3000, 60, &out);
    ps_buf_free(&json);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_EXPIRED);
}

static void test_expiry_within_clock_skew_still_accepted(void)
{
    ps_jwt_claims_t c = sample_claims(1000); /* exp = 1900 */
    ps_buf_t        json;
    ps_buf_init(&json);
    PS_CHECK(ps_claims_write(&c, ISSUER, AUDIENCE, &json));

    ps_jwt_claims_t out;
    /* now is 30s past exp, within the 60s skew allowance */
    ps_claims_result_t r =
        ps_claims_parse(json.data, json.len, ISSUER, AUDIENCE, 1930, 60, &out);
    ps_buf_free(&json);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_OK);
}

static void test_not_yet_valid_token_rejected(void)
{
    ps_jwt_claims_t c = sample_claims(1000);
    c.nbf             = 5000; /* far in the future relative to "now" below */
    ps_buf_t json;
    ps_buf_init(&json);
    PS_CHECK(ps_claims_write(&c, ISSUER, AUDIENCE, &json));

    ps_jwt_claims_t out;
    ps_claims_result_t r =
        ps_claims_parse(json.data, json.len, ISSUER, AUDIENCE, 1000, 60, &out);
    ps_buf_free(&json);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_NOT_YET_VALID);
}

static void test_malformed_json_rejected(void)
{
    static const char bad[] = "not json";
    ps_jwt_claims_t    out;
    ps_claims_result_t r = ps_claims_parse(bad, sizeof bad - 1, ISSUER, AUDIENCE, 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_MALFORMED);
}

static void test_non_object_json_rejected(void)
{
    static const char arr[] = "[1,2,3]";
    ps_jwt_claims_t    out;
    ps_claims_result_t r = ps_claims_parse(arr, sizeof arr - 1, ISSUER, AUDIENCE, 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_MALFORMED);
}

static void test_missing_field_rejected(void)
{
    static const char json[] =
        "{\"iss\":\"platformservice\",\"aud\":\"platformservice-api\"}";
    ps_jwt_claims_t    out;
    ps_claims_result_t r =
        ps_claims_parse(json, sizeof json - 1, ISSUER, AUDIENCE, 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_MALFORMED);
}

static void test_sub_as_json_number_rejected(void)
{
    /* plan 6.1: sub must be a string, never a JSON number -- large userIds
     * would otherwise lose precision through an IEEE754 double. */
    static const char json[] =
        "{\"iss\":\"platformservice\",\"sub\":42,\"aud\":\"platformservice-api\","
        "\"exp\":1900,\"iat\":1000,\"nbf\":1000,"
        "\"jti\":\"0123456789abcdef0123456789abcdef\",\"roles\":[\"USER\"]}";
    ps_jwt_claims_t    out;
    ps_claims_result_t r =
        ps_claims_parse(json, sizeof json - 1, ISSUER, AUDIENCE, 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_MALFORMED);
}

static void test_unrecognized_role_rejected(void)
{
    static const char json[] =
        "{\"iss\":\"platformservice\",\"sub\":\"42\",\"aud\":\"platformservice-api\","
        "\"exp\":1900,\"iat\":1000,\"nbf\":1000,"
        "\"jti\":\"0123456789abcdef0123456789abcdef\",\"roles\":[\"SUPERUSER\"]}";
    ps_jwt_claims_t    out;
    ps_claims_result_t r =
        ps_claims_parse(json, sizeof json - 1, ISSUER, AUDIENCE, 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_MALFORMED);
}

static void test_wrong_length_jti_rejected(void)
{
    static const char json[] =
        "{\"iss\":\"platformservice\",\"sub\":\"42\",\"aud\":\"platformservice-api\","
        "\"exp\":1900,\"iat\":1000,\"nbf\":1000,\"jti\":\"tooshort\",\"roles\":[]}";
    ps_jwt_claims_t    out;
    ps_claims_result_t r =
        ps_claims_parse(json, sizeof json - 1, ISSUER, AUDIENCE, 1000, 60, &out);
    PS_CHECK_EQ_INT(r, PS_CLAIMS_MALFORMED);
}

int main(void)
{
    PS_RUN_TEST(test_write_produces_expected_shape);
    PS_RUN_TEST(test_round_trip_preserves_all_fields);
    PS_RUN_TEST(test_no_roles_round_trips_to_empty_bitmask);
    PS_RUN_TEST(test_wrong_issuer_rejected);
    PS_RUN_TEST(test_wrong_audience_rejected);
    PS_RUN_TEST(test_expired_token_rejected);
    PS_RUN_TEST(test_expiry_within_clock_skew_still_accepted);
    PS_RUN_TEST(test_not_yet_valid_token_rejected);
    PS_RUN_TEST(test_malformed_json_rejected);
    PS_RUN_TEST(test_non_object_json_rejected);
    PS_RUN_TEST(test_missing_field_rejected);
    PS_RUN_TEST(test_sub_as_json_number_rejected);
    PS_RUN_TEST(test_unrecognized_role_rejected);
    PS_RUN_TEST(test_wrong_length_jti_rejected);
    PS_TEST_EXIT();
}
