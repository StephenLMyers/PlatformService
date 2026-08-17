#include "testutil.h"

#include "auth/password.h"

#define TEST_ITERATIONS 100 /* real config default is 600,000; kept low here for test speed */

static void test_round_trip_succeeds(void)
{
    ps_password_hash_t stored;
    PS_CHECK(ps_password_hash("correct horse battery staple", 29, TEST_ITERATIONS, &stored));
    PS_CHECK(ps_password_verify("correct horse battery staple", 29, &stored));
}

static void test_wrong_password_fails(void)
{
    ps_password_hash_t stored;
    PS_CHECK(ps_password_hash("correct horse battery staple", 29, TEST_ITERATIONS, &stored));
    PS_CHECK(!ps_password_verify("wrong password entirely", 24, &stored));
}

static void test_empty_password_round_trips(void)
{
    ps_password_hash_t stored;
    PS_CHECK(ps_password_hash("", 0, TEST_ITERATIONS, &stored));
    PS_CHECK(ps_password_verify("", 0, &stored));
    PS_CHECK(!ps_password_verify("a", 1, &stored));
}

static void test_same_password_hashed_twice_gets_different_salts(void)
{
    ps_password_hash_t a, b;
    PS_CHECK(ps_password_hash("same password", 14, TEST_ITERATIONS, &a));
    PS_CHECK(ps_password_hash("same password", 14, TEST_ITERATIONS, &b));
    PS_CHECK(memcmp(a.salt, b.salt, sizeof a.salt) != 0);
    PS_CHECK(memcmp(a.hash, b.hash, sizeof a.hash) != 0);
    /* Both still verify against their own hash regardless. */
    PS_CHECK(ps_password_verify("same password", 14, &a));
    PS_CHECK(ps_password_verify("same password", 14, &b));
}

static void test_tampered_hash_byte_fails_verification(void)
{
    ps_password_hash_t stored;
    PS_CHECK(ps_password_hash("tamper test", 11, TEST_ITERATIONS, &stored));
    stored.hash[0] ^= 0xFF;
    PS_CHECK(!ps_password_verify("tamper test", 11, &stored));
}

static void test_wrong_stored_iteration_count_fails_verification(void)
{
    ps_password_hash_t stored;
    PS_CHECK(ps_password_hash("iteration test", 15, TEST_ITERATIONS, &stored));
    stored.iterations = TEST_ITERATIONS + 1;
    PS_CHECK(!ps_password_verify("iteration test", 15, &stored));
}

int main(void)
{
    PS_RUN_TEST(test_round_trip_succeeds);
    PS_RUN_TEST(test_wrong_password_fails);
    PS_RUN_TEST(test_empty_password_round_trips);
    PS_RUN_TEST(test_same_password_hashed_twice_gets_different_salts);
    PS_RUN_TEST(test_tampered_hash_byte_fails_verification);
    PS_RUN_TEST(test_wrong_stored_iteration_count_fails_verification);
    PS_TEST_EXIT();
}
