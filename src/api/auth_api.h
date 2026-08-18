/*
 * register, verify, resend-verification (plan 4.1-4.3, 6.6), plus login,
 * refresh, logout, and password change (plan 4.4-4.7, 6.8, 6.9, D12) added
 * in phase 7.
 */
#ifndef PS_API_AUTH_API_H
#define PS_API_AUTH_API_H

#include "api/routes.h"
#include "http/conn.h"
#include "http/request.h"
#include "http/router.h"

ps_handler_result_t ps_auth_handle_register(const ps_http_request_t *req,
                                            const ps_route_params_t *params,
                                            const char *peer_addr, const ps_app_ctx_t *app_ctx);

ps_handler_result_t ps_auth_handle_verify(const ps_http_request_t *req,
                                          const ps_route_params_t *params,
                                          const char *peer_addr, const ps_app_ctx_t *app_ctx);

ps_handler_result_t ps_auth_handle_resend_verification(const ps_http_request_t *req,
                                                        const ps_route_params_t *params,
                                                        const char *peer_addr,
                                                        const ps_app_ctx_t *app_ctx);

/* plan 4.4: public. Identical 401 for unknown/wrong-password/unverified/
 * locked/disabled (plan 7.4). */
ps_handler_result_t ps_auth_handle_login(const ps_http_request_t *req,
                                         const ps_route_params_t *params,
                                         const char *peer_addr, const ps_app_ctx_t *app_ctx);

/* plan 4.5: POLICY_PUBLIC -- carries no Authorization header, the refresh
 * token itself is the credential. */
ps_handler_result_t ps_auth_handle_refresh(const ps_http_request_t *req,
                                           const ps_route_params_t *params,
                                           const char *peer_addr, const ps_app_ctx_t *app_ctx);

/* plan 4.6: authenticated (Authorization: Bearer) + refresh_token body
 * field naming which family to end. */
ps_handler_result_t ps_auth_handle_logout(const ps_http_request_t *req,
                                          const ps_route_params_t *params,
                                          const char *peer_addr, const ps_app_ctx_t *app_ctx);

/* plan 4.7: authenticated; requires current_password even though the caller
 * already holds a valid access token. */
ps_handler_result_t ps_auth_handle_password_change(const ps_http_request_t *req,
                                                    const ps_route_params_t *params,
                                                    const char *peer_addr,
                                                    const ps_app_ctx_t *app_ctx);

#endif /* PS_API_AUTH_API_H */
