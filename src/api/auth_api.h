/*
 * register, verify, resend-verification (plan 4.1-4.3, 6.6). login/
 * refresh/logout land in phase 7 in this same file.
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

#endif /* PS_API_AUTH_API_H */
