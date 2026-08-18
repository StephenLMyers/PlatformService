#include "testutil.h"

#include <string.h>

#include "api/routes.h"

static bool parse(const char *s, int64_t *out)
{
    return ps_parse_int64(s, strlen(s), out);
}

static void test_zero_accepted(void)
{
    int64_t out = -1;
    PS_CHECK(parse("0", &out));
    PS_CHECK_EQ_INT(out, 0);
}

static void test_negative_one_accepted(void)
{
    int64_t out = 0;
    PS_CHECK(parse("-1", &out));
    PS_CHECK_EQ_INT(out, -1);
}

static void test_int64_max_accepted(void)
{
    int64_t out = 0;
    PS_CHECK(parse("9223372036854775807", &out));
    PS_CHECK_EQ_INT(out, INT64_MAX);
}

static void test_int64_min_accepted(void)
{
    int64_t out = 0;
    PS_CHECK(parse("-9223372036854775808", &out));
    PS_CHECK_EQ_INT(out, INT64_MIN);
}

static void test_int64_max_plus_one_overflows(void)
{
    int64_t out = 0;
    PS_CHECK(!parse("9223372036854775808", &out));
}

static void test_int64_min_minus_one_underflows(void)
{
    int64_t out = 0;
    PS_CHECK(!parse("-9223372036854775809", &out));
}

static void test_non_numeric_rejected(void)
{
    int64_t out = 0;
    PS_CHECK(!parse("abc", &out));
    PS_CHECK(!parse("12abc", &out));
    PS_CHECK(!parse("1.5", &out));
}

static void test_empty_input_rejected(void)
{
    int64_t out = 0;
    PS_CHECK(!ps_parse_int64("", 0, &out));
}

static void test_lone_sign_rejected(void)
{
    int64_t out = 0;
    PS_CHECK(!parse("+", &out));
    PS_CHECK(!parse("-", &out));
}

static void test_leading_whitespace_rejected(void)
{
    /* strtoll would otherwise silently skip past it and succeed -- plan
     * 7.3 explicitly forbids that. */
    int64_t out = 0;
    PS_CHECK(!parse(" 1", &out));
    PS_CHECK(!parse("\t1", &out));
}

static void test_trailing_garbage_rejected(void)
{
    int64_t out = 0;
    PS_CHECK(!parse("1x", &out));
    PS_CHECK(!parse("1 ", &out));
}

static void test_overlong_input_rejected(void)
{
    /* Bounded to a 32-byte stack buffer -- anything that could never fit
     * a valid int64_t (at most 20 digits + sign) is rejected outright. */
    int64_t out = 0;
    char    too_long[64];
    memset(too_long, '1', sizeof too_long - 1);
    too_long[sizeof too_long - 1] = '\0';
    PS_CHECK(!ps_parse_int64(too_long, strlen(too_long), &out));
}

static void test_plus_prefixed_positive_accepted(void)
{
    /* strtoll accepts a leading '+' on an otherwise well-formed number;
     * nothing in plan 7.3 forbids it (only a *lone* sign is rejected). */
    int64_t out = 0;
    PS_CHECK(parse("+5", &out));
    PS_CHECK_EQ_INT(out, 5);
}

int main(void)
{
    PS_RUN_TEST(test_zero_accepted);
    PS_RUN_TEST(test_negative_one_accepted);
    PS_RUN_TEST(test_int64_max_accepted);
    PS_RUN_TEST(test_int64_min_accepted);
    PS_RUN_TEST(test_int64_max_plus_one_overflows);
    PS_RUN_TEST(test_int64_min_minus_one_underflows);
    PS_RUN_TEST(test_non_numeric_rejected);
    PS_RUN_TEST(test_empty_input_rejected);
    PS_RUN_TEST(test_lone_sign_rejected);
    PS_RUN_TEST(test_leading_whitespace_rejected);
    PS_RUN_TEST(test_trailing_garbage_rejected);
    PS_RUN_TEST(test_overlong_input_rejected);
    PS_RUN_TEST(test_plus_prefixed_positive_accepted);
    PS_TEST_EXIT();
}
