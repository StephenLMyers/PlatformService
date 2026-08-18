/*
 * GET /v1/users/{userId} (plan 4.8). Ownership-or-role gated by
 * api/rbac.c/api/routes.c before this ever runs -- see the header comment
 * on ps_user_handle_get_user for exactly what this handler still decides
 * for itself.
 */
#ifndef PS_API_USER_API_H
#define PS_API_USER_API_H

#include <stdint.h>

#include "api/routes.h"
#include "auth/claims.h"
#include "http/conn.h"
#include "http/request.h"
#include "http/router.h"

/*
 * claims is the caller's already-verified access-token claims (plan 8:
 * api/routes.c's dispatch authenticates once, centrally). target_user_id
 * is the path parameter, already parsed and validated as a well-formed
 * int64_t by the caller (plan 7.3) -- a malformed userId is a 400 the
 * caller returns before ever reaching this handler. ps_rbac_check has
 * already confirmed claims.user_id == target_user_id OR the caller holds
 * ADMIN; this handler still decides, from that same comparison, whether
 * the response includes email (plan 4.8's "two views, not a conditional
 * field": the subject always sees it, an admin viewing someone else never
 * does) and whether to write an ADMIN_USER_READ audit row (plan 6.10:
 * only when an admin reads a record that is not their own).
 */
ps_handler_result_t ps_user_handle_get_user(const ps_http_request_t *req,
                                            const ps_route_params_t *params,
                                            const char *peer_addr,
                                            const ps_jwt_claims_t *claims,
                                            int64_t target_user_id,
                                            const ps_app_ctx_t *app_ctx);

#endif /* PS_API_USER_API_H */
