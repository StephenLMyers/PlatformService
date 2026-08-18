#include "api/routes.h"

#include "api/auth_api.h"
#include "api/health_api.h"

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
    return true;
}

ps_handler_result_t ps_routes_dispatch(int route_id, const ps_http_request_t *req,
                                       const ps_route_params_t *params,
                                       const char *peer_addr, void *app_ctx)
{
    const ps_app_ctx_t *ctx = app_ctx;

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
    default: {
        /* Unreachable in practice: every route_id the router can return
         * comes from ps_routes_register above, and every one of those is
         * handled here. Fail closed rather than assume, exactly like the
         * rest of this codebase treats its own invariants under untrusted
         * input (plan 7.2). */
        ps_handler_result_t result = { .status = 500, .body = NULL, .no_store = true };
        return result;
    }
    }
}
