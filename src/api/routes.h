/*
 * Owns the real route table and is the sole place conn.c's generic
 * dispatch callback (http/conn.h's ps_route_dispatch_fn) meets concrete
 * business logic. main.c wires ps_routes_dispatch into ps_server_t; conn.c
 * itself never includes this header (plan 3.1 layering).
 */
#ifndef PS_API_ROUTES_H
#define PS_API_ROUTES_H

#include <stdbool.h>
#include <stddef.h>

#include "http/conn.h"
#include "http/router.h"

enum {
    PS_ROUTE_ID_HEALTHZ = 1,
    PS_ROUTE_ID_READYZ  = 2,
};

/*
 * Read-only state handlers may need. A struct rather than several loose
 * void* parameters so adding a field (a DB handle, later) is one place,
 * not a signature change at every call site.
 */
typedef struct {
    /* /readyz fails while true. Points at a flag ps_server_shutdown sets
     * (plan 7.2a step 1); owned by the server, never by a handler. */
    const volatile bool *draining;
} ps_app_ctx_t;

/* Registers every route this build serves. */
bool ps_routes_register(ps_router_t *router, char *err, size_t errlen);

/* The ps_route_dispatch_fn implementation: switches on route_id and calls
 * the matching handler. */
ps_handler_result_t ps_routes_dispatch(int route_id, const ps_http_request_t *req,
                                       const ps_route_params_t *params, void *app_ctx);

#endif /* PS_API_ROUTES_H */
