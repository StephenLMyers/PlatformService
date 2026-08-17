#include "testutil.h"

#include <string.h>

#include "crypto/kdf.h"

static void hex_encode(const unsigned char *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

/* Salt 0x00..0x0f -- PS_KDF_SALT_LEN (16) bytes, matching what
 * ps_kdf_derive's signature fixes the salt length to. */
static void fixed_salt(unsigned char salt[PS_KDF_SALT_LEN])
{
    for (int i = 0; i < PS_KDF_SALT_LEN; i++) {
        salt[i] = (unsigned char)i;
    }
}

/*
 * PBKDF2-HMAC-SHA256(password, salt=00..0f, iterations, 32), cross-checked
 * independently against Python's hashlib.pbkdf2_hmac before being
 * embedded here.
 */
static void assert_pbkdf2_vector(const char *password, int iterations, const char *expect_hex)
{
    unsigned char salt[PS_KDF_SALT_LEN];
    fixed_salt(salt);

    unsigned char out[PS_KDF_OUTPUT_LEN];
    PS_CHECK(ps_kdf_derive(password, strlen(password), salt, iterations, out));

    char hex[PS_KDF_OUTPUT_LEN * 2 + 1];
    hex_encode(out, sizeof out, hex);
    PS_CHECK_STR_EQ(hex, expect_hex);
}

static void test_vector_one_iteration(void)
{
    assert_pbkdf2_vector("password123", 1,
                         "c4b9b88d01ed7ce604416b33ba2aee8c8d2c9026bd61aa7b1a3f606a7e487d69");
}

static void test_vector_1000_iterations(void)
{
    assert_pbkdf2_vector("password123", 1000,
                         "799de743e4b234cb58db04543f758194620229162d4cf779c51fb81d1a59e9db");
}

static void test_vector_different_password_and_iterations(void)
{
    assert_pbkdf2_vector("correct horse battery staple", 5000,
                         "0211223e7cb98e6dd4e7593fbb996ac7ba490db54d1a4de004d6e623acb31bd3");
}

static void test_different_salt_gives_different_output(void)
{
    unsigned char salt_a[PS_KDF_SALT_LEN];
    unsigned char salt_b[PS_KDF_SALT_LEN];
    fixed_salt(salt_a);
    fixed_salt(salt_b);
    salt_b[0] ^= 0xFF;

    unsigned char out_a[PS_KDF_OUTPUT_LEN];
    unsigned char out_b[PS_KDF_OUTPUT_LEN];
    PS_CHECK(ps_kdf_derive("same-password", 13, salt_a, 100, out_a));
    PS_CHECK(ps_kdf_derive("same-password", 13, salt_b, 100, out_b));
    PS_CHECK(memcmp(out_a, out_b, sizeof out_a) != 0);
}

static void test_round_trip_is_deterministic(void)
{
    unsigned char salt[PS_KDF_SALT_LEN];
    fixed_salt(salt);

    unsigned char out1[PS_KDF_OUTPUT_LEN];
    unsigned char out2[PS_KDF_OUTPUT_LEN];
    PS_CHECK(ps_kdf_derive("hunter2", 7, salt, 200, out1));
    PS_CHECK(ps_kdf_derive("hunter2", 7, salt, 200, out2));
    PS_CHECK(memcmp(out1, out2, sizeof out1) == 0);
}

int main(void)
{
    PS_RUN_TEST(test_vector_one_iteration);
    PS_RUN_TEST(test_vector_1000_iterations);
    PS_RUN_TEST(test_vector_different_password_and_iterations);
    PS_RUN_TEST(test_different_salt_gives_different_output);
    PS_RUN_TEST(test_round_trip_is_deterministic);
    PS_TEST_EXIT();
}
