#include "api/routes.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api/admin_api.h"
#include "api/auth_api.h"
#include "api/health_api.h"
#include "api/rbac.h"
#include "api/user_api.h"
#include "http/response.h"

bool ps_routes_register(ps_router_t *router, char *err, size_t errlen)
{
    ps_router_init(router);

    if (!ps_router_add(router, "GET", "/healthz", PS_ROUTE_ID_HEALTHZ, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "GET", "/readyz", PS_ROUTE_ID_READYZ, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "POST", "/v1/auth/register", PS_ROUTE_ID_REGISTER, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "POST", "/v1/auth/verify", PS_ROUTE_ID_VERIFY, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "POST", "/v1/auth/resend-verification",
                       PS_ROUTE_ID_RESEND_VERIFICATION, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "POST", "/v1/auth/login", PS_ROUTE_ID_LOGIN, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "POST", "/v1/auth/refresh", PS_ROUTE_ID_REFRESH, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "POST", "/v1/auth/logout", PS_ROUTE_ID_LOGOUT, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "POST", "/v1/auth/password", PS_ROUTE_ID_PASSWORD_CHANGE, err,
                       errlen)) {
        return false;
    }
    if (!ps_router_add(router, "GET", "/v1/users/{userId}", PS_ROUTE_ID_GET_USER, err, errlen)) {
        return false;
    }
    if (!ps_router_add(router, "GET", "/v1/admin/users/count", PS_ROUTE_ID_ADMIN_COUNT_USERS, err,
                       errlen)) {
        return false;
    }
    if (!ps_router_add(router, "GET", "/v1/admin/users", PS_ROUTE_ID_ADMIN_LIST_USERS, err,
                       errlen)) {
        return false;
    }
    return true;
}

static ps_handler_result_t error_result(int status, const char *code, const char *message)
{
    ps_handler_result_t r = { .status = status, .body = ps_error_envelope(code, message),
                              .no_store = true };
    return r;
}

bool ps_parse_int64(const char *text, size_t len, int64_t *out)
{
    if (text == NULL || len == 0 || len >= 32) {
        return false;
    }
    char buf[32];
    memcpy(buf, text, len);
    buf[len] = '\0';

    if (isspace((unsigned char)buf[0])) {
        return false;
    }

    errno = 0;
    char     *endptr = NULL;
    long long parsed = strtoll(buf, &endptr, 10);
    if (endptr == buf || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    *out = (int64_t)parsed;
    return true;
}

static bool parse_path_user_id(const ps_route_param_t *param, int64_t *out)
{
    if (param == NULL) {
        return false;
    }
    return ps_parse_int64(param->value, param->value_len, out);
}

ps_handler_result_t ps_routes_dispatch(int route_id, const ps_http_request_t *req,
                                       const ps_route_params_t *params,
                                       const char *peer_addr, void *app_ctx)
{
    const ps_app_ctx_t *ctx = app_ctx;

    /*
     * plan 6.5, D10: default deny is structural, enforced here once for
     * every route rather than repeated per handler. A route_id with no
     * policy row is unreachable -- never treated as "allow" -- which is
     * what makes a forgotten policy an outage, not a breach.
     */
    const ps_route_policy_t *policy = ps_rbac_policy_for_route(route_id);
    if (policy == NULL) {
        return error_result(401, "UNAUTHORIZED", "no access token provided");
    }

    ps_jwt_claims_t claims;
    memset(&claims, 0, sizeof claims);
    if (policy->kind != PS_POLICY_PUBLIC) {
        int64_t now = time(NULL);
        if (ps_auth_authenticate_bearer(req, ctx, now, &claims) != PS_BEARER_OK) {
            return error_result(401, "UNAUTHORIZED", "missing or invalid access token");
        }
    }

    /* plan 7.3: parsed once here (never re-parsed by ps_user_handle_get_user)
     * so the same validated value backs both the ownership check below and
     * the handler's own DB lookup. */
    int64_t target_user_id = 0;
    if (policy->kind == PS_POLICY_SELF_OR_ROLE) {
        const ps_route_param_t *user_id_param = ps_route_params_get(params, "userId");
        if (!parse_path_user_id(user_id_param, &target_user_id)) {
            return error_result(400, "BAD_REQUEST", "userId is invalid");
        }
    }

    if (policy->kind == PS_POLICY_ROLE || policy->kind == PS_POLICY_SELF_OR_ROLE) {
        if (!ps_rbac_check(policy, &claims, target_user_id)) {
            return error_result(403, "FORBIDDEN", "insufficient permissions");
        }
    }

    switch (route_id) {
    case PS_ROUTE_ID_HEALTHZ:
        return ps_health_handle_healthz(req, params, ctx);
    case PS_ROUTE_ID_READYZ:
        return ps_health_handle_readyz(req, params, ctx);
    case PS_ROUTE_ID_REGISTER:
        return ps_auth_handle_register(req, params, peer_addr, ctx);
    case PS_ROUTE_ID_VERIFY:
        return ps_auth_handle_verify(req, params, peer_addr, ctx);
    case PS_ROUTE_ID_RESEND_VERIFICATION:
        return ps_auth_handle_resend_verification(req, params, peer_addr, ctx);
    case PS_ROUTE_ID_LOGIN:
        return ps_auth_handle_login(req, params, peer_addr, ctx);
    case PS_ROUTE_ID_REFRESH:
        return ps_auth_handle_refresh(req, params, peer_addr, ctx);
    case PS_ROUTE_ID_LOGOUT:
        return ps_auth_handle_logout(req, params, peer_addr, &claims, ctx);
    case PS_ROUTE_ID_PASSWORD_CHANGE:
        return ps_auth_handle_password_change(req, params, peer_addr, &claims, ctx);
    case PS_ROUTE_ID_GET_USER:
        return ps_user_handle_get_user(req, params, peer_addr, &claims, target_user_id, ctx);
    case PS_ROUTE_ID_ADMIN_COUNT_USERS:
        return ps_admin_handle_count_users(req, params, peer_addr, &claims, ctx);
    case PS_ROUTE_ID_ADMIN_LIST_USERS:
        return ps_admin_handle_list_users(req, params, peer_addr, &claims, ctx);
    default: {
        /* Unreachable in practice: every route_id the router can return
         * comes from ps_routes_register above, and every one of those has
         * both a policy row and a case here. Fail closed rather than
         * assume, exactly like the rest of this codebase treats its own
         * invariants under untrusted input (plan 7.2). */
        ps_handler_result_t result = { .status = 500, .body = NULL, .no_store = true };
        return result;
    }
    }
}
