#include "api/rbac.h"

#include "api/routes.h"

/*
 * plan 6.5's exact seven-entry public allowlist, plus the two
 * currently-authenticated routes and GET /v1/users/{userId} (plan 8's
 * scope). /v1/admin/users/count and /v1/admin/users are plan 9's job --
 * they get their own rows here once their handlers exist, not before:
 * a route with no handler has no route_id to key a row on, and adding a
 * phantom row for a route that doesn't exist yet would be worse than
 * useless (untestable, and default-deny-by-absence should mean exactly
 * what it says).
 */
const ps_route_policy_t PS_RBAC_POLICIES[] = {
    { PS_ROUTE_ID_HEALTHZ,             "GET",  "/healthz",                     PS_POLICY_PUBLIC,        0 },
    { PS_ROUTE_ID_READYZ,              "GET",  "/readyz",                      PS_POLICY_PUBLIC,        0 },
    { PS_ROUTE_ID_REGISTER,            "POST", "/v1/auth/register",            PS_POLICY_PUBLIC,        0 },
    { PS_ROUTE_ID_VERIFY,              "POST", "/v1/auth/verify",              PS_POLICY_PUBLIC,        0 },
    { PS_ROUTE_ID_RESEND_VERIFICATION, "POST", "/v1/auth/resend-verification", PS_POLICY_PUBLIC,        0 },
    { PS_ROUTE_ID_LOGIN,               "POST", "/v1/auth/login",               PS_POLICY_PUBLIC,        0 },
    { PS_ROUTE_ID_REFRESH,             "POST", "/v1/auth/refresh",             PS_POLICY_PUBLIC,        0 },
    { PS_ROUTE_ID_LOGOUT,              "POST", "/v1/auth/logout",              PS_POLICY_AUTHENTICATED, 0 },
    { PS_ROUTE_ID_PASSWORD_CHANGE,     "POST", "/v1/auth/password",            PS_POLICY_AUTHENTICATED, 0 },
    { PS_ROUTE_ID_GET_USER,            "GET",  "/v1/users/{userId}",
      PS_POLICY_SELF_OR_ROLE, PS_JWT_ROLE_ADMIN },
};
const size_t PS_RBAC_POLICIES_COUNT = sizeof PS_RBAC_POLICIES / sizeof PS_RBAC_POLICIES[0];

const ps_route_policy_t *ps_rbac_policy_for_route(int route_id)
{
    for (size_t i = 0; i < PS_RBAC_POLICIES_COUNT; i++) {
        if (PS_RBAC_POLICIES[i].route_id == route_id) {
            return &PS_RBAC_POLICIES[i];
        }
    }
    return NULL;
}

bool ps_rbac_check(const ps_route_policy_t *policy, const ps_jwt_claims_t *claims,
                   int64_t target_user_id)
{
    switch (policy->kind) {
    case PS_POLICY_PUBLIC:
    case PS_POLICY_AUTHENTICATED:
        /* A valid token was already required to reach this call (plan
         * 6.5: the dispatch layer authenticates before ever consulting
         * this function for non-public policies) -- nothing further to
         * check. */
        return true;
    case PS_POLICY_ROLE:
        return (claims->roles & policy->required_role) != 0;
    case PS_POLICY_SELF_OR_ROLE:
        return claims->user_id == target_user_id ||
               (claims->roles & policy->required_role) != 0;
    }
    return false; /* unreachable: every ps_policy_kind_t is handled above */
}
