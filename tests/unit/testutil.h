/*
 * Minimal C unit-test harness. No external test framework, matching D1 --
 * pulling one in here would be exactly the dependency the plan avoids
 * everywhere else.
 *
 * Each tests/unit/test_*.c is its own translation unit with its own main(),
 * built and run as a standalone binary by `make test`. Include this header,
 * write `static void test_foo(void) { PS_CHECK(...); }` functions, and call
 * them through PS_RUN_TEST from main().
 */
#ifndef PS_UNIT_TESTUTIL_H
#define PS_UNIT_TESTUTIL_H

#include <stdio.h>
#include <string.h>

static int ps_test_total_failures  = 0;
static int ps_test_case_failures   = 0;

#define PS_CHECK(cond) \
    do { \
        if (!(cond)) { \
            ps_test_case_failures++; \
            (void)fprintf(stderr, "    FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        } \
    } while (0)

#define PS_CHECK_EQ_INT(a, b) \
    do { \
        long ps_a_ = (long)(a), ps_b_ = (long)(b); \
        if (ps_a_ != ps_b_) { \
            ps_test_case_failures++; \
            (void)fprintf(stderr, "    FAIL %s:%d: %s == %s (%ld != %ld)\n", \
                          __FILE__, __LINE__, #a, #b, ps_a_, ps_b_); \
        } \
    } while (0)

#define PS_CHECK_STR_EQ(a, b) \
    do { \
        const char *ps_a_ = (a), *ps_b_ = (b); \
        if (strcmp(ps_a_, ps_b_) != 0) { \
            ps_test_case_failures++; \
            (void)fprintf(stderr, "    FAIL %s:%d: %s == %s (\"%s\" != \"%s\")\n", \
                          __FILE__, __LINE__, #a, #b, ps_a_, ps_b_); \
        } \
    } while (0)

#define PS_RUN_TEST(fn) \
    do { \
        ps_test_case_failures = 0; \
        fn(); \
        if (ps_test_case_failures == 0) { \
            (void)printf("  ok    %s\n", #fn); \
        } else { \
            (void)printf("  FAIL  %s\n", #fn); \
            ps_test_total_failures += ps_test_case_failures; \
        } \
    } while (0)

#define PS_TEST_EXIT() return (ps_test_total_failures == 0) ? 0 : 1

#endif /* PS_UNIT_TESTUTIL_H */
