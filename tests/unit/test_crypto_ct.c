#include "testutil.h"

#include "crypto/ct.h"

static void test_equal_buffers(void)
{
    PS_CHECK(ps_ct_equal("hello world", "hello world", 11));
}

static void test_differing_in_first_byte(void)
{
    PS_CHECK(!ps_ct_equal("Xello world", "hello world", 11));
}

static void test_differing_in_last_byte(void)
{
    PS_CHECK(!ps_ct_equal("hello worlX", "hello world", 11));
}

static void test_zero_length_is_equal(void)
{
    PS_CHECK(ps_ct_equal("", "", 0));
}

int main(void)
{
    PS_RUN_TEST(test_equal_buffers);
    PS_RUN_TEST(test_differing_in_first_byte);
    PS_RUN_TEST(test_differing_in_last_byte);
    PS_RUN_TEST(test_zero_length_is_equal);
    PS_TEST_EXIT();
}
