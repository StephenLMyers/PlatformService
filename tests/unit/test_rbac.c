#include "testutil.h"

#include <string.h>

#include "api/rbac.h"
#include "api/routes.h"

static ps_jwt_claims_t make_claims(int64_t user_id, uint32_t roles)
{
    ps_jwt_claims_t c;
    memset(&c, 0, sizeof c);
    c.user_id = user_id;
    c.roles   = roles;
    return c;
}

static void test_policy_for_route_finds_a_known_route(void)
{
    const ps_route_policy_t *p = ps_rbac_policy_for_route(PS_ROUTE_ID_REGISTER);
    PS_CHECK(p != NULL);
    PS_CHECK_EQ_INT(p->kind, PS_POLICY_PUBLIC);
    PS_CHECK_STR_EQ(p->method, "POST");
    PS_CHECK_STR_EQ(p->path_pattern, "/v1/auth/register");
}

static void test_policy_for_route_returns_null_for_unknown_route(void)
{
    /* Default deny (plan 6.5, D10): a route_id with no row is unreachable,
     * never treated as "allow". */
    PS_CHECK(ps_rbac_policy_for_route(999999) == NULL);
}

static void test_public_allowlist_has_exactly_seven_entries(void)
{
    /* plan 6.5/8.3: "The public allowlist contains exactly [seven]..." --
     * asserted directly against the table itself, not just via the
     * harness, so a stray new PUBLIC row fails here immediately. */
    size_t public_count = 0;
    for (size_t i = 0; i < PS_RBAC_POLICIES_COUNT; i++) {
        if (PS_RBAC_POLICIES[i].kind == PS_POLICY_PUBLIC) {
            public_count++;
        }
    }
    PS_CHECK_EQ_INT(public_count, 7);
}

static void test_every_route_id_appears_at_most_once(void)
{
    for (size_t i = 0; i < PS_RBAC_POLICIES_COUNT; i++) {
        for (size_t j = i + 1; j < PS_RBAC_POLICIES_COUNT; j++) {
            PS_CHECK(PS_RBAC_POLICIES[i].route_id != PS_RBAC_POLICIES[j].route_id);
        }
    }
}

static void test_check_public_always_passes(void)
{
    const ps_route_policy_t *policy = ps_rbac_policy_for_route(PS_ROUTE_ID_HEALTHZ);
    ps_jwt_claims_t          claims = make_claims(0, 0);
    PS_CHECK(ps_rbac_check(policy, &claims, 0));
}

static void test_check_authenticated_passes_regardless_of_role(void)
{
    const ps_route_policy_t *policy = ps_rbac_policy_for_route(PS_ROUTE_ID_LOGOUT);
    ps_jwt_claims_t          no_roles = make_claims(1, 0);
    ps_jwt_claims_t          admin    = make_claims(1, PS_JWT_ROLE_ADMIN);
    PS_CHECK(ps_rbac_check(policy, &no_roles, 0));
    PS_CHECK(ps_rbac_check(policy, &admin, 0));
}

/* PS_ROUTE_ID_GET_USER is the only PS_POLICY_SELF_OR_ROLE route in v1;
 * PS_POLICY_ROLE has no route of its own yet (plan 9's admin endpoints),
 * so ps_rbac_check's ROLE branch is exercised directly against a
 * synthetic policy here rather than skipped until phase 9. */
static const ps_route_policy_t ROLE_ONLY_POLICY = {
    .route_id = -1, .method = "GET", .path_pattern = "/v1/admin/synthetic",
    .kind = PS_POLICY_ROLE, .required_role = PS_JWT_ROLE_ADMIN,
};

static void test_check_role_requires_the_exact_bit(void)
{
    ps_jwt_claims_t admin     = make_claims(1, PS_JWT_ROLE_ADMIN);
    ps_jwt_claims_t user_only = make_claims(1, PS_JWT_ROLE_USER);
    ps_jwt_claims_t no_roles  = make_claims(1, 0);

    PS_CHECK(ps_rbac_check(&ROLE_ONLY_POLICY, &admin, 0));
    PS_CHECK(!ps_rbac_check(&ROLE_ONLY_POLICY, &user_only, 0));
    PS_CHECK(!ps_rbac_check(&ROLE_ONLY_POLICY, &no_roles, 0));
}

static void test_check_self_or_role_passes_on_ownership_alone(void)
{
    const ps_route_policy_t *policy = ps_rbac_policy_for_route(PS_ROUTE_ID_GET_USER);
    /* D9: an ADMIN-only account (not holding USER) still reads its own
     * record -- ownership and role are independent grants; either
     * suffices. Modeled here with a plain USER-role caller instead, since
     * ps_rbac_check's ownership branch never even looks at roles: the
     * D9 guarantee holds structurally, not by checking for USER. */
    ps_jwt_claims_t self = make_claims(42, PS_JWT_ROLE_USER);
    PS_CHECK(ps_rbac_check(policy, &self, 42));
}

static void test_check_self_or_role_passes_on_role_alone(void)
{
    const ps_route_policy_t *policy = ps_rbac_policy_for_route(PS_ROUTE_ID_GET_USER);
    ps_jwt_claims_t          admin  = make_claims(1, PS_JWT_ROLE_ADMIN);
    PS_CHECK(ps_rbac_check(policy, &admin, 999)); /* reading someone else's record */
}

static void test_check_self_or_role_denies_neither(void)
{
    const ps_route_policy_t *policy = ps_rbac_policy_for_route(PS_ROUTE_ID_GET_USER);
    ps_jwt_claims_t          user   = make_claims(1, PS_JWT_ROLE_USER);
    PS_CHECK(!ps_rbac_check(policy, &user, 999)); /* not self, not ADMIN */
}

int main(void)
{
    PS_RUN_TEST(test_policy_for_route_finds_a_known_route);
    PS_RUN_TEST(test_policy_for_route_returns_null_for_unknown_route);
    PS_RUN_TEST(test_public_allowlist_has_exactly_seven_entries);
    PS_RUN_TEST(test_every_route_id_appears_at_most_once);
    PS_RUN_TEST(test_check_public_always_passes);
    PS_RUN_TEST(test_check_authenticated_passes_regardless_of_role);
    PS_RUN_TEST(test_check_role_requires_the_exact_bit);
    PS_RUN_TEST(test_check_self_or_role_passes_on_ownership_alone);
    PS_RUN_TEST(test_check_self_or_role_passes_on_role_alone);
    PS_RUN_TEST(test_check_self_or_role_denies_neither);
    PS_TEST_EXIT();
}
