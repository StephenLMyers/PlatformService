#include "testutil.h"

#include <string.h>

#include "crypto/base64url.h"
#include "platform/buf.h"

static void assert_encode(const unsigned char *data, size_t len, const char *expect)
{
    ps_buf_t out;
    ps_buf_init(&out);
    PS_CHECK(ps_base64url_encode(data, len, &out));
    PS_CHECK_EQ_INT(out.len, strlen(expect));
    /* out.data is NULL until the first append -- memcmp(NULL, ..., 0) is
     * fine by the standard's own text but glibc marks memcmp nonnull, and
     * UBSan flags passing NULL to it even with a zero count. */
    if (out.len > 0) {
        PS_CHECK(memcmp(out.data, expect, out.len) == 0);
    }
    ps_buf_free(&out);
}

static void assert_decode_ok(const char *text, const unsigned char *expect, size_t expect_len)
{
    ps_buf_t out;
    ps_buf_init(&out);
    PS_CHECK(ps_base64url_decode(text, strlen(text), &out));
    PS_CHECK_EQ_INT(out.len, expect_len);
    if (out.len > 0) {
        PS_CHECK(memcmp(out.data, expect, expect_len) == 0);
    }
    ps_buf_free(&out);
}

static void assert_decode_fails(const char *text)
{
    ps_buf_t out;
    ps_buf_init(&out);
    PS_CHECK(!ps_base64url_decode(text, strlen(text), &out));
    ps_buf_free(&out);
}

/* RFC 4648 test vectors, cross-checked independently against Python's
 * base64.urlsafe_b64encode with padding stripped. */
static void test_rfc4648_vectors(void)
{
    assert_encode((const unsigned char *)"", 0, "");
    assert_encode((const unsigned char *)"f", 1, "Zg");
    assert_encode((const unsigned char *)"fo", 2, "Zm8");
    assert_encode((const unsigned char *)"foo", 3, "Zm9v");
    assert_encode((const unsigned char *)"foob", 4, "Zm9vYg");
    assert_encode((const unsigned char *)"fooba", 5, "Zm9vYmE");
    assert_encode((const unsigned char *)"foobar", 6, "Zm9vYmFy");
}

static void test_jwt_header_example(void)
{
    /* RFC 7515's own worked example header. */
    static const char json[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    assert_encode((const unsigned char *)json, sizeof json - 1,
                  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
}

static void test_round_trip_all_byte_values(void)
{
    unsigned char data[256];
    for (int i = 0; i < 256; i++) {
        data[i] = (unsigned char)i;
    }
    ps_buf_t encoded;
    ps_buf_init(&encoded);
    PS_CHECK(ps_base64url_encode(data, sizeof data, &encoded));

    ps_buf_t decoded;
    ps_buf_init(&decoded);
    PS_CHECK(ps_base64url_decode(encoded.data, encoded.len, &decoded));
    PS_CHECK_EQ_INT(decoded.len, sizeof data);
    PS_CHECK(memcmp(decoded.data, data, sizeof data) == 0);

    ps_buf_free(&encoded);
    ps_buf_free(&decoded);
}

static void test_decode_matches_encode_vectors(void)
{
    assert_decode_ok("", (const unsigned char *)"", 0);
    assert_decode_ok("Zg", (const unsigned char *)"f", 1);
    assert_decode_ok("Zm8", (const unsigned char *)"fo", 2);
    assert_decode_ok("Zm9v", (const unsigned char *)"foo", 3);
    assert_decode_ok("Zm9vYg", (const unsigned char *)"foob", 4);
    assert_decode_ok("Zm9vYmE", (const unsigned char *)"fooba", 5);
    assert_decode_ok("Zm9vYmFy", (const unsigned char *)"foobar", 6);
}

static void test_decode_rejects_padding(void)
{
    assert_decode_fails("Zg==");
    assert_decode_fails("Zm8=");
}

static void test_decode_rejects_standard_alphabet_chars(void)
{
    assert_decode_fails("+g==");  /* '+' is not in the url-safe alphabet */
    assert_decode_fails("/g==");  /* neither is '/' */
}

static void test_decode_rejects_length_congruent_to_1_mod_4(void)
{
    assert_decode_fails("Z");
    assert_decode_fails("ZgZgZ");
}

static void test_decode_rejects_nonzero_padding_bits(void)
{
    /* "Zh" would decode a 2-char tail whose low 4 bits are nonzero --
     * non-canonical, must be rejected rather than silently masked. */
    assert_decode_fails("Zh");
}

static void test_decode_rejects_garbage(void)
{
    assert_decode_fails("!!!!");
    assert_decode_fails("has spaces");
}

int main(void)
{
    PS_RUN_TEST(test_rfc4648_vectors);
    PS_RUN_TEST(test_jwt_header_example);
    PS_RUN_TEST(test_round_trip_all_byte_values);
    PS_RUN_TEST(test_decode_matches_encode_vectors);
    PS_RUN_TEST(test_decode_rejects_padding);
    PS_RUN_TEST(test_decode_rejects_standard_alphabet_chars);
    PS_RUN_TEST(test_decode_rejects_length_congruent_to_1_mod_4);
    PS_RUN_TEST(test_decode_rejects_nonzero_padding_bits);
    PS_RUN_TEST(test_decode_rejects_garbage);
    PS_TEST_EXIT();
}
