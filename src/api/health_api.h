/*
 * GET /healthz and GET /readyz (plan 4.11). Both public, both return
 * status and nothing more -- no internal detail, ever.
 */
#ifndef PS_API_HEALTH_API_H
#define PS_API_HEALTH_API_H

#include "api/routes.h"
#include "http/conn.h"
#include "http/request.h"
#include "http/router.h"

/* "Is the process alive?" -- always 200 if this code is running at all. */
ps_handler_result_t ps_health_handle_healthz(const ps_http_request_t *req,
                                             const ps_route_params_t *params,
                                             const ps_app_ctx_t *app_ctx);

/* "Should traffic be sent here?" -- 503 while draining (plan 7.2a step 1);
 * DB-unreachable and migrations-in-progress checks arrive with the phases
 * that add a database to check. */
ps_handler_result_t ps_health_handle_readyz(const ps_http_request_t *req,
                                            const ps_route_params_t *params,
                                            const ps_app_ctx_t *app_ctx);

#endif /* PS_API_HEALTH_API_H */
