#include "testutil.h"

#include <stdio.h>
#include <string.h>

#include "crypto/hmac.h"

static void hex_encode(const unsigned char *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static void assert_hmac_hex(const unsigned char *key, size_t key_len,
                            const unsigned char *data, size_t data_len,
                            const char *expect_hex)
{
    unsigned char out[PS_HMAC_SHA256_LEN];
    PS_CHECK(ps_hmac_sha256(key, key_len, data, data_len, out));

    char hex[PS_HMAC_SHA256_LEN * 2 + 1];
    hex_encode(out, sizeof out, hex);
    PS_CHECK_STR_EQ(hex, expect_hex);
}

/*
 * RFC 4231 HMAC-SHA-256 test cases 1-3, cross-checked independently
 * against Python's hmac.new(..., hashlib.sha256) before being embedded
 * here.
 */
static void test_rfc4231_case1(void)
{
    unsigned char key[20];
    memset(key, 0x0b, sizeof key);
    assert_hmac_hex(key, sizeof key, (const unsigned char *)"Hi There", 8,
                    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

static void test_rfc4231_case2(void)
{
    static const char *key  = "Jefe";
    static const char *data = "what do ya want for nothing?";
    assert_hmac_hex((const unsigned char *)key, strlen(key),
                    (const unsigned char *)data, strlen(data),
                    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

static void test_rfc4231_case3(void)
{
    unsigned char key[20];
    unsigned char data[50];
    memset(key, 0xaa, sizeof key);
    memset(data, 0xdd, sizeof data);
    assert_hmac_hex(key, sizeof key, data, sizeof data,
                    "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
}

static void test_zero_length_key_and_message(void)
{
    unsigned char out[PS_HMAC_SHA256_LEN];
    PS_CHECK(ps_hmac_sha256("", 0, "", 0, out));
}

static void test_different_data_gives_different_mac(void)
{
    unsigned char out1[PS_HMAC_SHA256_LEN];
    unsigned char out2[PS_HMAC_SHA256_LEN];
    PS_CHECK(ps_hmac_sha256("key", 3, "a", 1, out1));
    PS_CHECK(ps_hmac_sha256("key", 3, "b", 1, out2));
    PS_CHECK(memcmp(out1, out2, sizeof out1) != 0);
}

int main(void)
{
    PS_RUN_TEST(test_rfc4231_case1);
    PS_RUN_TEST(test_rfc4231_case2);
    PS_RUN_TEST(test_rfc4231_case3);
    PS_RUN_TEST(test_zero_length_key_and_message);
    PS_RUN_TEST(test_different_data_gives_different_mac);
    PS_TEST_EXIT();
}
