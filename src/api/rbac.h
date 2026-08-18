/*
 * RBAC policy table and evaluation (plan 6.5, D10): a declarative table
 * rather than `if` statements scattered through handlers, so the whole
 * security posture is auditable in one screen. Lives in api/, not auth/,
 * matching plan 3.1's architecture diagram ("api/ handlers, RBAC policy
 * binding") -- the table is keyed by api/routes.h's route_id, an api/-layer
 * concept, so this module would create an upward dependency (auth/ -> api/,
 * forbidden by plan 3.1) if it lived a layer down.
 *
 * Default deny is structural -- ps_rbac_policy_for_route returns NULL for
 * any route_id not in the table, and api/routes.c's dispatch treats that
 * as a hard deny, never as "allow" (plan: "a forgotten policy costs an
 * outage, not a breach").
 *
 * Keyed by route_id rather than the plan's own illustrative (method,
 * path_pattern) string sketch: route_id already *is* the stable identity
 * of one (method, path) pair, assigned once by http/router.c's match --
 * re-deriving that with a second string comparison here would only
 * duplicate the router's job. method/path_pattern are still carried on
 * each row (as plain display strings, never matched against) purely so
 * --dump-routes and the default-deny test (plan 8.3) can print/compare
 * them without a second source of truth.
 *
 * ps_rbac_check answers "does this already-verified claims set satisfy
 * this policy" -- it never sees raw request bytes or an unverified token;
 * extracting and verifying the bearer token is api/auth_api.c's job
 * (ps_auth_authenticate_bearer), called once per request by api/routes.c's
 * dispatch before this is ever consulted.
 */
#ifndef PS_API_RBAC_H
#define PS_API_RBAC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "auth/claims.h"

typedef enum {
    PS_POLICY_PUBLIC,        /* no token required */
    PS_POLICY_AUTHENTICATED, /* any valid token suffices, no role/ownership check */
    PS_POLICY_ROLE,          /* valid token AND required_role held */
    PS_POLICY_SELF_OR_ROLE,  /* valid token AND (claims.user_id == target OR required_role held) */
} ps_policy_kind_t;

typedef struct {
    int              route_id;
    const char      *method;       /* display only (--dump-routes, tests) */
    const char      *path_pattern; /* ditto */
    ps_policy_kind_t kind;
    uint32_t         required_role; /* a PS_JWT_ROLE_* bit; 0 when not applicable */
} ps_route_policy_t;

extern const ps_route_policy_t PS_RBAC_POLICIES[];
extern const size_t            PS_RBAC_POLICIES_COUNT;

/* NULL if route_id has no policy row -- default deny (see header comment). */
const ps_route_policy_t *ps_rbac_policy_for_route(int route_id);

/*
 * Evaluates policy->kind against already-verified claims. target_user_id
 * is only consulted for PS_POLICY_SELF_OR_ROLE (pass the route's own path
 * parameter, already parsed and validated by the caller -- a malformed
 * path parameter is a 400 the caller must handle before ever reaching
 * this call, not a policy question). Ignored for every other policy kind;
 * pass 0.
 */
bool ps_rbac_check(const ps_route_policy_t *policy, const ps_jwt_claims_t *claims,
                   int64_t target_user_id);

#endif /* PS_API_RBAC_H */
