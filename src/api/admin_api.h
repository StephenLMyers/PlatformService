/*
 * GET /v1/admin/users/count and GET /v1/admin/users (plan 4.9, 4.10).
 * Both ADMIN-only (PS_POLICY_ROLE, enforced by api/routes.c's dispatch
 * before either handler ever runs -- claims is already-verified for the
 * same reason api/user_api.h's handler receives it).
 */
#ifndef PS_API_ADMIN_API_H
#define PS_API_ADMIN_API_H

#include "api/routes.h"
#include "auth/claims.h"
#include "http/conn.h"
#include "http/request.h"
#include "http/router.h"

ps_handler_result_t ps_admin_handle_count_users(const ps_http_request_t *req,
                                                const ps_route_params_t *params,
                                                const char *peer_addr,
                                                const ps_jwt_claims_t *claims,
                                                const ps_app_ctx_t *app_ctx);

/*
 * plan 4.10: keyset pagination via ?after_id={n}&limit={n}, both optional
 * (after_id defaults to 0 -- the first page; limit defaults to and is
 * capped at 1000). limit <= 0 (present but zero or negative) and either
 * parameter failing plan 7.3's parse are both 400 BAD_REQUEST -- a
 * positive page size is a precondition for pagination to make forward
 * progress at all, not a degenerate valid case (discussed with the user).
 */
ps_handler_result_t ps_admin_handle_list_users(const ps_http_request_t *req,
                                               const ps_route_params_t *params,
                                               const char *peer_addr,
                                               const ps_jwt_claims_t *claims,
                                               const ps_app_ctx_t *app_ctx);

#endif /* PS_API_ADMIN_API_H */
