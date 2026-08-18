#include "testutil.h"

#include <string.h>

#include "crypto/sha256.h"

static void hex_encode(const unsigned char *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

/* Standard SHA-256 test vectors, cross-checked independently against
 * Python's hashlib.sha256 before being embedded here. */
static void assert_sha256_hex(const char *input, const char *expect_hex)
{
    unsigned char out[PS_SHA256_LEN];
    PS_CHECK(ps_sha256(input, strlen(input), out));

    char hex[PS_SHA256_LEN * 2 + 1];
    hex_encode(out, sizeof out, hex);
    PS_CHECK_STR_EQ(hex, expect_hex);
}

static void test_empty_input(void)
{
    assert_sha256_hex("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_abc(void)
{
    assert_sha256_hex("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_quick_brown_fox(void)
{
    assert_sha256_hex("The quick brown fox jumps over the lazy dog",
                      "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
}

static void test_different_input_gives_different_hash(void)
{
    unsigned char a[PS_SHA256_LEN];
    unsigned char b[PS_SHA256_LEN];
    PS_CHECK(ps_sha256("input-a", 7, a));
    PS_CHECK(ps_sha256("input-b", 7, b));
    PS_CHECK(memcmp(a, b, sizeof a) != 0);
}

int main(void)
{
    PS_RUN_TEST(test_empty_input);
    PS_RUN_TEST(test_abc);
    PS_RUN_TEST(test_quick_brown_fox);
    PS_RUN_TEST(test_different_input_gives_different_hash);
    PS_TEST_EXIT();
}
