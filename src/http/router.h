/*
 * Method + path routing with path-parameter capture (e.g. "/v1/users/{userId}").
 *
 * Deliberately just matching, not dispatch: this module has no idea what a
 * "handler" is, and never will -- it maps (method, path) to a route_id the
 * caller chose at registration time (an index into its own handler table,
 * typically) plus any captured path params. Wiring route_id to actual
 * business logic is the connection loop / a future middleware layer's job
 * (plan 3.2 keeps router.c and middleware.c as separate files for exactly
 * this reason).
 *
 * No heap allocation: ps_router_t is a plain, fixed-capacity struct a
 * caller can put on the stack or in static storage, matching the
 * declarative-table style the plan's own RBAC policy table (§6.5) uses.
 */
#ifndef PS_HTTP_ROUTER_H
#define PS_HTTP_ROUTER_H

#include <stdbool.h>
#include <stddef.h>

#define PS_ROUTER_MAX_ROUTES  32
#define PS_ROUTE_METHOD_MAX   8
#define PS_ROUTE_PATTERN_MAX  128
#define PS_ROUTE_MAX_PARAMS   4

typedef struct {
    const char *name;
    size_t      name_len;
    const char *value;  /* points into the path string passed to ps_router_match */
    size_t      value_len;
} ps_route_param_t;

typedef struct {
    ps_route_param_t params[PS_ROUTE_MAX_PARAMS];
    size_t            count;
} ps_route_params_t;

typedef struct {
    char method[PS_ROUTE_METHOD_MAX];
    char pattern[PS_ROUTE_PATTERN_MAX];
    int  route_id;
} ps_route_entry_t;

typedef struct {
    ps_route_entry_t routes[PS_ROUTER_MAX_ROUTES];
    size_t            count;
} ps_router_t;

void ps_router_init(ps_router_t *router);

/*
 * Registers one route. pattern must start with '/'; a "{name}" segment
 * matches exactly one non-empty path segment (no embedded '/') and is
 * captured under that name. route_id is opaque to this module -- whatever
 * the caller passes here is exactly what comes back from ps_router_match.
 */
bool ps_router_add(ps_router_t *router, const char *method, const char *pattern,
                   int route_id, char *err, size_t errlen);

typedef enum {
    PS_ROUTE_MATCH,               /* route_id and params populated */
    PS_ROUTE_NOT_FOUND,           /* no route matches this path at all -> 404 */
    PS_ROUTE_METHOD_NOT_ALLOWED,  /* path matches, but not with this method -> 405 */
} ps_route_match_result_t;

/*
 * method/path are (pointer, length) pairs, typically straight from a
 * parsed ps_http_request_t -- never NUL-terminated, never copied. params
 * may be NULL if the caller doesn't need captures (e.g. checking a static
 * route). On PS_ROUTE_MATCH, *params (if given) holds pointers into the
 * `path` the caller passed in, which must outlive them.
 */
ps_route_match_result_t ps_router_match(const ps_router_t *router,
                                        const char *method, size_t method_len,
                                        const char *path, size_t path_len,
                                        int *route_id, ps_route_params_t *params);

/* Case-insensitive-by-name lookup within an already-matched params set.
 * NULL if absent. name is a NUL-terminated C string naming a known param
 * (e.g. "userId"). */
const ps_route_param_t *ps_route_params_get(const ps_route_params_t *params, const char *name);

#endif /* PS_HTTP_ROUTER_H */
