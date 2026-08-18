#include "testutil.h"

#include <string.h>

#include "auth/validate.h"

/* ---- username ---- */

static void test_valid_username_lowercased(void)
{
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate("SMyers", out, sizeof out, true), PS_USERNAME_VALID);
    PS_CHECK_STR_EQ(out, "smyers");
}

static void test_username_too_short(void)
{
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate("ab", out, sizeof out, true), PS_USERNAME_TOO_SHORT);
}

static void test_username_too_long(void)
{
    char raw[40];
    memset(raw, 'a', sizeof raw - 1);
    raw[sizeof raw - 1] = '\0';
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate(raw, out, sizeof out, true), PS_USERNAME_TOO_LONG);
}

static void test_username_exactly_32_is_valid(void)
{
    char raw[33];
    memset(raw, 'a', 32);
    raw[32] = '\0';
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate(raw, out, sizeof out, true), PS_USERNAME_VALID);
}

static void test_username_exactly_3_is_valid(void)
{
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate("abc", out, sizeof out, true), PS_USERNAME_VALID);
}

static void test_username_bad_charset(void)
{
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate("bad name!", out, sizeof out, true),
                    PS_USERNAME_BAD_CHARSET);
    PS_CHECK_EQ_INT(ps_username_validate("bad.name", out, sizeof out, true),
                    PS_USERNAME_BAD_CHARSET);
}

static void test_username_underscore_and_hyphen_allowed(void)
{
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate("foo_bar-baz", out, sizeof out, true), PS_USERNAME_VALID);
}

static void test_username_must_start_alphanumeric(void)
{
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate("_foobar", out, sizeof out, true),
                    PS_USERNAME_STARTS_NON_ALPHANUMERIC);
    PS_CHECK_EQ_INT(ps_username_validate("-foobar", out, sizeof out, true),
                    PS_USERNAME_STARTS_NON_ALPHANUMERIC);
}

static void test_reserved_usernames_rejected_when_checked(void)
{
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate("admin", out, sizeof out, true), PS_USERNAME_RESERVED);
    PS_CHECK_EQ_INT(ps_username_validate("Root", out, sizeof out, true), PS_USERNAME_RESERVED);
    PS_CHECK_EQ_INT(ps_username_validate("system", out, sizeof out, true), PS_USERNAME_RESERVED);
}

static void test_reserved_usernames_allowed_when_not_checked(void)
{
    /* plan 6.7: the bootstrap admin is exactly the legitimate case for
     * naming an account "admin". */
    char out[64];
    PS_CHECK_EQ_INT(ps_username_validate("admin", out, sizeof out, false), PS_USERNAME_VALID);
    PS_CHECK_STR_EQ(out, "admin");
}

/* ---- email ---- */

static void test_valid_email_lowercased_and_trimmed(void)
{
    char out[300];
    PS_CHECK_EQ_INT(ps_email_validate("  S@Example.COM  ", out, sizeof out), PS_EMAIL_VALID);
    PS_CHECK_STR_EQ(out, "s@example.com");
}

static void test_email_missing_at_rejected(void)
{
    char out[300];
    PS_CHECK_EQ_INT(ps_email_validate("not-an-email", out, sizeof out), PS_EMAIL_MALFORMED);
}

static void test_email_two_at_rejected(void)
{
    char out[300];
    PS_CHECK_EQ_INT(ps_email_validate("a@b@c.com", out, sizeof out), PS_EMAIL_MALFORMED);
}

static void test_email_empty_local_part_rejected(void)
{
    char out[300];
    PS_CHECK_EQ_INT(ps_email_validate("@example.com", out, sizeof out), PS_EMAIL_MALFORMED);
}

static void test_email_empty_domain_rejected(void)
{
    char out[300];
    PS_CHECK_EQ_INT(ps_email_validate("foo@", out, sizeof out), PS_EMAIL_MALFORMED);
}

static void test_email_no_dot_in_domain_rejected(void)
{
    char out[300];
    PS_CHECK_EQ_INT(ps_email_validate("foo@localhost", out, sizeof out), PS_EMAIL_MALFORMED);
}

static void test_email_too_long_rejected(void)
{
    char local_part[280];
    memset(local_part, 'a', sizeof local_part - 1);
    local_part[sizeof local_part - 1] = '\0';
    char raw[320];
    (void)snprintf(raw, sizeof raw, "%s@example.com", local_part); /* well over 254 trimmed */
    char out[400];
    PS_CHECK_EQ_INT(ps_email_validate(raw, out, sizeof out), PS_EMAIL_TOO_LONG);
}

static void test_email_at_exactly_254_is_valid(void)
{
    /* 254 chars total: 242 'a's + "@example.com" (12 chars) = 254. */
    char raw[255];
    memset(raw, 'a', 242);
    memcpy(raw + 242, "@example.com", 12);
    raw[254] = '\0';
    char out[300];
    PS_CHECK_EQ_INT(ps_email_validate(raw, out, sizeof out), PS_EMAIL_VALID);
}

int main(void)
{
    PS_RUN_TEST(test_valid_username_lowercased);
    PS_RUN_TEST(test_username_too_short);
    PS_RUN_TEST(test_username_too_long);
    PS_RUN_TEST(test_username_exactly_32_is_valid);
    PS_RUN_TEST(test_username_exactly_3_is_valid);
    PS_RUN_TEST(test_username_bad_charset);
    PS_RUN_TEST(test_username_underscore_and_hyphen_allowed);
    PS_RUN_TEST(test_username_must_start_alphanumeric);
    PS_RUN_TEST(test_reserved_usernames_rejected_when_checked);
    PS_RUN_TEST(test_reserved_usernames_allowed_when_not_checked);
    PS_RUN_TEST(test_valid_email_lowercased_and_trimmed);
    PS_RUN_TEST(test_email_missing_at_rejected);
    PS_RUN_TEST(test_email_two_at_rejected);
    PS_RUN_TEST(test_email_empty_local_part_rejected);
    PS_RUN_TEST(test_email_empty_domain_rejected);
    PS_RUN_TEST(test_email_no_dot_in_domain_rejected);
    PS_RUN_TEST(test_email_too_long_rejected);
    PS_RUN_TEST(test_email_at_exactly_254_is_valid);
    PS_TEST_EXIT();
}
