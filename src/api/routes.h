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

#include "auth/password.h"
#include "crypto/kdf_semaphore.h"
#include "http/conn.h"
#include "http/router.h"
#include "platform/config.h"
#include "store/db.h"

enum {
    PS_ROUTE_ID_HEALTHZ             = 1,
    PS_ROUTE_ID_READYZ              = 2,
    PS_ROUTE_ID_REGISTER            = 3,
    PS_ROUTE_ID_VERIFY              = 4,
    PS_ROUTE_ID_RESEND_VERIFICATION = 5,
    PS_ROUTE_ID_LOGIN               = 6,
    PS_ROUTE_ID_REFRESH             = 7,
    PS_ROUTE_ID_LOGOUT              = 8,
    PS_ROUTE_ID_PASSWORD_CHANGE     = 9,
};

/*
 * Read-only state handlers may need. A struct rather than several loose
 * void* parameters so adding a field is one place, not a signature change
 * at every call site.
 */
typedef struct {
    /* /readyz fails while true. Points at a flag ps_server_shutdown sets
     * (plan 7.2a step 1); owned by the server, never by a handler. Read
     * exclusively through __atomic_load_n (api/health_api.c) -- see
     * server.h's comment on the field this points at. */
    const bool *draining;

    /* Every handler acquires its own connection for the duration of one
     * request and releases it before returning -- never held across a
     * dispatch call boundary. */
    ps_db_pool_t *db_pool;

    /* Bounds concurrent PBKDF2 calls (plan 7.7); a handler that can't
     * acquire a slot returns 503 rather than hashing anyway. */
    ps_kdf_semaphore_t *kdf_semaphore;

    /* NULL is valid (breach checking skipped, length bounds still
     * enforced -- see ps_password_policy_check). Owned by main.c, loaded
     * once at startup, read-only for the rest of the process. */
    const ps_password_denylist_t *password_denylist;

    /* Read-only policy thresholds, TTLs, and identity strings (issuer/
     * audience/dev_mode/...) a handler needs. Owned by main.c; outlives
     * every request. */
    const ps_config_t *config;
} ps_app_ctx_t;

/* Registers every route this build serves. */
bool ps_routes_register(ps_router_t *router, char *err, size_t errlen);

/* The ps_route_dispatch_fn implementation: switches on route_id and calls
 * the matching handler. */
ps_handler_result_t ps_routes_dispatch(int route_id, const ps_http_request_t *req,
                                       const ps_route_params_t *params,
                                       const char *peer_addr, void *app_ctx);

#endif /* PS_API_ROUTES_H */
