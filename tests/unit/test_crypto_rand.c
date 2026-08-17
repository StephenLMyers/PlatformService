#include "testutil.h"

#include <string.h>

#include "crypto/rand.h"

static void test_fills_requested_length(void)
{
    unsigned char buf[32];
    memset(buf, 0xAB, sizeof buf);
    PS_CHECK(ps_rand_bytes(buf, sizeof buf));
    /* Not a proof of randomness, just a sanity check that something wrote
     * over the sentinel pattern. */
    PS_CHECK(memcmp(buf, "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB", 8) != 0);
}

static void test_zero_length_succeeds(void)
{
    PS_CHECK(ps_rand_bytes(NULL, 0));
}

static void test_two_calls_differ(void)
{
    unsigned char a[16];
    unsigned char b[16];
    PS_CHECK(ps_rand_bytes(a, sizeof a));
    PS_CHECK(ps_rand_bytes(b, sizeof b));
    PS_CHECK(memcmp(a, b, sizeof a) != 0);
}

int main(void)
{
    PS_RUN_TEST(test_fills_requested_length);
    PS_RUN_TEST(test_zero_length_succeeds);
    PS_RUN_TEST(test_two_calls_differ);
    PS_TEST_EXIT();
}
