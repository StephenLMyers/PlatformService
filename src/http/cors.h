/*
 * CORS (plan 7.2a). Off by default: no origins configured means no
 * Access-Control-* headers are ever emitted and OPTIONS returns 405. This
 * is a configuration hook, not a feature this build actively uses -- there
 * is no browser client for this API in v1. The one rule that is not merely
 * a default, and is enforced rather than documented: a wildcard origin
 * combined with credentials is refused outright, both here and at config
 * load time (platform/config.c), because no browser honors that
 * combination anyway and it is a cross-origin credential leak on paper.
 */
#ifndef PS_HTTP_CORS_H
#define PS_HTTP_CORS_H

#include <stdbool.h>
#include <stddef.h>

#define PS_CORS_MAX_ORIGINS 16

typedef struct {
    const char *origins[PS_CORS_MAX_ORIGINS]; /* NUL-terminated; point into origins_csv */
    size_t      count;
    bool        allow_credentials;
} ps_cors_policy_t;

/*
 * Parses a comma-separated origin list. origins_csv is split IN PLACE
 * (commas and surrounding whitespace become NUL bytes) and policy's
 * origins point directly into it -- origins_csv must outlive policy and
 * must not be used as a C string again afterward. An empty/blank
 * origins_csv yields a policy with count == 0 (CORS disabled).
 */
bool ps_cors_policy_init(ps_cors_policy_t *policy, char *origins_csv, bool allow_credentials,
                         char *err, size_t errlen);

/* False (CORS off) for a NULL policy or one with no configured origins. */
bool ps_cors_enabled(const ps_cors_policy_t *policy);

/* Exact match against the configured allowlist. origin is typically a
 * request's raw Origin header value -- (pointer, length), never NUL-terminated. */
bool ps_cors_origin_allowed(const ps_cors_policy_t *policy, const char *origin, size_t origin_len);

#endif /* PS_HTTP_CORS_H */
