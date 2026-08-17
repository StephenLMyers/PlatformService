#include "http/router.h"

#include <stdio.h>
#include <string.h>

void ps_router_init(ps_router_t *router)
{
    router->count = 0;
}

bool ps_router_add(ps_router_t *router, const char *method, const char *pattern,
                   int route_id, char *err, size_t errlen)
{
    if (err == NULL || errlen == 0) {
        return false;
    }
    err[0] = '\0';

    if (router->count >= PS_ROUTER_MAX_ROUTES) {
        (void)snprintf(err, errlen, "router is full (max %d routes)", PS_ROUTER_MAX_ROUTES);
        return false;
    }

    size_t method_len  = strlen(method);
    size_t pattern_len = strlen(pattern);
    if (method_len == 0 || method_len >= PS_ROUTE_METHOD_MAX) {
        (void)snprintf(err, errlen, "invalid method '%s'", method);
        return false;
    }
    if (pattern_len == 0 || pattern_len >= PS_ROUTE_PATTERN_MAX || pattern[0] != '/') {
        (void)snprintf(err, errlen, "invalid route pattern '%s'", pattern);
        return false;
    }

    ps_route_entry_t *r = &router->routes[router->count];
    memcpy(r->method, method, method_len + 1);
    memcpy(r->pattern, pattern, pattern_len + 1);
    r->route_id = route_id;
    router->count++;
    return true;
}

/*
 * Segment-by-segment match between a registered pattern and an incoming
 * path, both '/'-delimited. Requires the same number of segments -- no
 * prefix or wildcard-tail matching. A "{name}" pattern segment captures
 * exactly one non-empty path segment; every other segment must match the
 * path byte-for-byte.
 */
static bool match_path(const char *pattern, size_t pattern_len,
                       const char *path, size_t path_len,
                       ps_route_params_t *params)
{
    if (params != NULL) {
        params->count = 0;
    }

    size_t pp = 0;
    size_t qp = 0;

    for (;;) {
        bool pattern_done = (pp >= pattern_len);
        bool path_done    = (qp >= path_len);
        if (pattern_done != path_done) {
            return false; /* different segment counts */
        }
        if (pattern_done) {
            return true; /* both exhausted together: full match */
        }
        if (pattern[pp] != '/' || path[qp] != '/') {
            return false; /* both operands are expected to be segment-aligned here */
        }
        pp++;
        qp++;

        size_t pat_seg_start = pp;
        while (pp < pattern_len && pattern[pp] != '/') {
            pp++;
        }
        size_t pat_seg_len = pp - pat_seg_start;

        size_t path_seg_start = qp;
        while (qp < path_len && path[qp] != '/') {
            qp++;
        }
        size_t path_seg_len = qp - path_seg_start;

        bool is_capture = pat_seg_len >= 2 &&
                          pattern[pat_seg_start] == '{' &&
                          pattern[pat_seg_start + pat_seg_len - 1] == '}';

        if (is_capture) {
            if (path_seg_len == 0) {
                return false; /* a param can't be satisfied by an empty segment */
            }
            if (params != NULL) {
                if (params->count >= PS_ROUTE_MAX_PARAMS) {
                    return false; /* pattern authored with too many {params} -- fail safe */
                }
                ps_route_param_t *prm = &params->params[params->count++];
                prm->name      = pattern + pat_seg_start + 1;
                prm->name_len  = pat_seg_len - 2;
                prm->value     = path + path_seg_start;
                prm->value_len = path_seg_len;
            }
        } else if (pat_seg_len != path_seg_len ||
                  memcmp(pattern + pat_seg_start, path + path_seg_start, pat_seg_len) != 0) {
            return false;
        }
    }
}

ps_route_match_result_t ps_router_match(const ps_router_t *router,
                                        const char *method, size_t method_len,
                                        const char *path, size_t path_len,
                                        int *route_id, ps_route_params_t *params)
{
    bool path_matched_some_method = false;

    for (size_t i = 0; i < router->count; i++) {
        const ps_route_entry_t *r = &router->routes[i];
        size_t                  pattern_len = strlen(r->pattern);

        ps_route_params_t local_params;
        if (!match_path(r->pattern, pattern_len, path, path_len, &local_params)) {
            continue;
        }
        path_matched_some_method = true;

        size_t route_method_len = strlen(r->method);
        if (route_method_len == method_len && memcmp(r->method, method, method_len) == 0) {
            if (route_id != NULL) {
                *route_id = r->route_id;
            }
            if (params != NULL) {
                *params = local_params;
            }
            return PS_ROUTE_MATCH;
        }
    }

    return path_matched_some_method ? PS_ROUTE_METHOD_NOT_ALLOWED : PS_ROUTE_NOT_FOUND;
}

const ps_route_param_t *ps_route_params_get(const ps_route_params_t *params, const char *name)
{
    if (params == NULL) {
        return NULL;
    }
    size_t name_len = strlen(name);
    for (size_t i = 0; i < params->count; i++) {
        if (params->params[i].name_len == name_len &&
            memcmp(params->params[i].name, name, name_len) == 0) {
            return &params->params[i];
        }
    }
    return NULL;
}
