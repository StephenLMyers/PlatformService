#include "testutil.h"

#include <stdio.h>
#include <string.h>

#include "http/cors.h"

static void test_empty_origins_means_disabled(void)
{
    char             csv[] = "";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(ps_cors_policy_init(&policy, csv, false, err, sizeof err));
    PS_CHECK(!ps_cors_enabled(&policy));
}

static void test_whitespace_only_origins_means_disabled(void)
{
    char             csv[] = "   ,  ,\t";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(ps_cors_policy_init(&policy, csv, false, err, sizeof err));
    PS_CHECK(!ps_cors_enabled(&policy));
}

static void test_single_origin_parsed_and_matched(void)
{
    char             csv[] = "https://example.com";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(ps_cors_policy_init(&policy, csv, false, err, sizeof err));
    PS_CHECK(ps_cors_enabled(&policy));
    PS_CHECK_EQ_INT(policy.count, 1);

    const char *origin = "https://example.com";
    PS_CHECK(ps_cors_origin_allowed(&policy, origin, strlen(origin)));
}

static void test_multiple_origins_comma_separated(void)
{
    char             csv[] = "https://a.example, https://b.example ,https://c.example";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(ps_cors_policy_init(&policy, csv, false, err, sizeof err));
    PS_CHECK_EQ_INT(policy.count, 3);

    PS_CHECK(ps_cors_origin_allowed(&policy, "https://a.example", strlen("https://a.example")));
    PS_CHECK(ps_cors_origin_allowed(&policy, "https://b.example", strlen("https://b.example")));
    PS_CHECK(ps_cors_origin_allowed(&policy, "https://c.example", strlen("https://c.example")));
}

static void test_origin_not_in_list_is_rejected(void)
{
    char             csv[] = "https://allowed.example";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(ps_cors_policy_init(&policy, csv, false, err, sizeof err));

    const char *origin = "https://evil.example";
    PS_CHECK(!ps_cors_origin_allowed(&policy, origin, strlen(origin)));
}

static void test_match_is_exact_not_prefix(void)
{
    char             csv[] = "https://example.com";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(ps_cors_policy_init(&policy, csv, false, err, sizeof err));

    /* A naive prefix/substring match would wrongly allow either of these. */
    const char *longer  = "https://example.com.evil.example";
    const char *shorter = "https://example.co";
    PS_CHECK(!ps_cors_origin_allowed(&policy, longer, strlen(longer)));
    PS_CHECK(!ps_cors_origin_allowed(&policy, shorter, strlen(shorter)));
}

static void test_wildcard_alone_is_allowed(void)
{
    char             csv[] = "*";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(ps_cors_policy_init(&policy, csv, false, err, sizeof err));
    PS_CHECK(ps_cors_enabled(&policy));
    PS_CHECK(ps_cors_origin_allowed(&policy, "*", 1));
}

static void test_wildcard_with_credentials_is_refused(void)
{
    char             csv[] = "*";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(!ps_cors_policy_init(&policy, csv, true, err, sizeof err));
    PS_CHECK(err[0] != '\0');
}

static void test_wildcard_among_others_with_credentials_is_refused(void)
{
    char             csv[] = "https://good.example, *, https://also-good.example";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(!ps_cors_policy_init(&policy, csv, true, err, sizeof err));
}

static void test_named_origins_with_credentials_is_fine(void)
{
    char             csv[] = "https://good.example";
    ps_cors_policy_t policy;
    char             err[256];

    PS_CHECK(ps_cors_policy_init(&policy, csv, true, err, sizeof err));
    PS_CHECK(policy.allow_credentials);
}

static void test_too_many_origins_rejected(void)
{
    char buf[512];
    buf[0] = '\0';
    for (int i = 0; i < PS_CORS_MAX_ORIGINS + 1; i++) {
        char one[32];
        (void)snprintf(one, sizeof one, "https://o%d.example,", i);
        strcat(buf, one);
    }

    ps_cors_policy_t policy;
    char              err[256];
    PS_CHECK(!ps_cors_policy_init(&policy, buf, false, err, sizeof err));
}

static void test_enabled_is_null_safe(void)
{
    PS_CHECK(!ps_cors_enabled(NULL));
}

static void test_origin_allowed_is_null_safe(void)
{
    ps_cors_policy_t policy;
    char              csv[] = "https://example.com";
    char              err[256];
    PS_CHECK(ps_cors_policy_init(&policy, csv, false, err, sizeof err));

    PS_CHECK(!ps_cors_origin_allowed(NULL, "https://example.com", 20));
    PS_CHECK(!ps_cors_origin_allowed(&policy, NULL, 0));
}

int main(void)
{
    PS_RUN_TEST(test_empty_origins_means_disabled);
    PS_RUN_TEST(test_whitespace_only_origins_means_disabled);
    PS_RUN_TEST(test_single_origin_parsed_and_matched);
    PS_RUN_TEST(test_multiple_origins_comma_separated);
    PS_RUN_TEST(test_origin_not_in_list_is_rejected);
    PS_RUN_TEST(test_match_is_exact_not_prefix);
    PS_RUN_TEST(test_wildcard_alone_is_allowed);
    PS_RUN_TEST(test_wildcard_with_credentials_is_refused);
    PS_RUN_TEST(test_wildcard_among_others_with_credentials_is_refused);
    PS_RUN_TEST(test_named_origins_with_credentials_is_fine);
    PS_RUN_TEST(test_too_many_origins_rejected);
    PS_RUN_TEST(test_enabled_is_null_safe);
    PS_RUN_TEST(test_origin_allowed_is_null_safe);

    PS_TEST_EXIT();
}
