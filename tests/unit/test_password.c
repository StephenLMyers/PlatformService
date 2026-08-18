#include "testutil.h"

#include <string.h>

#include "auth/password.h"

#define TEST_ITERATIONS 100 /* real config default is 600,000; kept low here for test speed */
#define DENYLIST_PATH "data/common-passwords.txt" /* relative to repo root, matching `make test` */

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

static void test_denylist_load_succeeds_on_real_file(void)
{
    ps_password_denylist_t list;
    char                    err[256];
    PS_CHECK(ps_password_denylist_load(DENYLIST_PATH, &list, err, sizeof err));
    PS_CHECK_EQ_INT(list.count, 10000);
    ps_password_denylist_free(&list);
}

static void test_denylist_load_fails_on_missing_file(void)
{
    ps_password_denylist_t list;
    char                    err[256];
    PS_CHECK(!ps_password_denylist_load("build/does-not-exist.txt", &list, err, sizeof err));
}

static void test_policy_rejects_too_short(void)
{
    ps_password_policy_result_t r = ps_password_policy_check("short", 5, 12, 128, NULL);
    PS_CHECK_EQ_INT(r, PS_PASSWORD_POLICY_TOO_SHORT);
}

static void test_policy_rejects_too_long(void)
{
    char pw[200];
    memset(pw, 'a', sizeof pw);
    ps_password_policy_result_t r = ps_password_policy_check(pw, sizeof pw, 12, 128, NULL);
    PS_CHECK_EQ_INT(r, PS_PASSWORD_POLICY_TOO_LONG);
}

static void test_policy_accepts_boundary_lengths(void)
{
    char min_pw[12];
    memset(min_pw, 'a', sizeof min_pw);
    PS_CHECK_EQ_INT(ps_password_policy_check(min_pw, sizeof min_pw, 12, 128, NULL),
                    PS_PASSWORD_POLICY_OK);

    char max_pw[128];
    memset(max_pw, 'a', sizeof max_pw);
    PS_CHECK_EQ_INT(ps_password_policy_check(max_pw, sizeof max_pw, 12, 128, NULL),
                    PS_PASSWORD_POLICY_OK);
}

static void test_policy_without_denylist_skips_breach_check(void)
{
    /* "password" would fail the breach check if a denylist were supplied
     * (see test_policy_rejects_breached_password below); with denylist =
     * NULL, only the length bounds apply. */
    static const char *pw = "password12345";
    ps_password_policy_result_t r =
        ps_password_policy_check(pw, strlen(pw), 12, 128, NULL);
    PS_CHECK_EQ_INT(r, PS_PASSWORD_POLICY_OK);
}

static void test_policy_rejects_breached_password(void)
{
    ps_password_denylist_t list;
    char                    err[256];
    PS_CHECK(ps_password_denylist_load(DENYLIST_PATH, &list, err, sizeof err));

    /* Verified present in data/common-passwords.txt, not assumed. */
    static const char *pw = "password";
    ps_password_policy_result_t r =
        ps_password_policy_check(pw, strlen(pw), 1, 128, &list);
    PS_CHECK_EQ_INT(r, PS_PASSWORD_POLICY_BREACHED);

    ps_password_denylist_free(&list);
}

static void test_policy_breach_check_is_case_insensitive(void)
{
    ps_password_denylist_t list;
    char                    err[256];
    PS_CHECK(ps_password_denylist_load(DENYLIST_PATH, &list, err, sizeof err));

    static const char *pw = "PaSsWoRd";
    ps_password_policy_result_t r =
        ps_password_policy_check(pw, strlen(pw), 1, 128, &list);
    PS_CHECK_EQ_INT(r, PS_PASSWORD_POLICY_BREACHED);

    ps_password_denylist_free(&list);
}

static void test_policy_accepts_a_non_breached_passphrase(void)
{
    ps_password_denylist_t list;
    char                    err[256];
    PS_CHECK(ps_password_denylist_load(DENYLIST_PATH, &list, err, sizeof err));

    static const char *pw = "correct horse battery staple xyz789 unlikely";
    ps_password_policy_result_t r =
        ps_password_policy_check(pw, strlen(pw), 12, 128, &list);
    PS_CHECK_EQ_INT(r, PS_PASSWORD_POLICY_OK);

    ps_password_denylist_free(&list);
}

int main(void)
{
    PS_RUN_TEST(test_round_trip_succeeds);
    PS_RUN_TEST(test_wrong_password_fails);
    PS_RUN_TEST(test_empty_password_round_trips);
    PS_RUN_TEST(test_same_password_hashed_twice_gets_different_salts);
    PS_RUN_TEST(test_tampered_hash_byte_fails_verification);
    PS_RUN_TEST(test_wrong_stored_iteration_count_fails_verification);
    PS_RUN_TEST(test_denylist_load_succeeds_on_real_file);
    PS_RUN_TEST(test_denylist_load_fails_on_missing_file);
    PS_RUN_TEST(test_policy_rejects_too_short);
    PS_RUN_TEST(test_policy_rejects_too_long);
    PS_RUN_TEST(test_policy_accepts_boundary_lengths);
    PS_RUN_TEST(test_policy_without_denylist_skips_breach_check);
    PS_RUN_TEST(test_policy_rejects_breached_password);
    PS_RUN_TEST(test_policy_breach_check_is_case_insensitive);
    PS_RUN_TEST(test_policy_accepts_a_non_breached_passphrase);
    PS_TEST_EXIT();
}
