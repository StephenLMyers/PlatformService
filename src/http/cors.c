#include "http/cors.h"

#include <stdio.h>
#include <string.h>

bool ps_cors_policy_init(ps_cors_policy_t *policy, char *origins_csv, bool allow_credentials,
                         char *err, size_t errlen)
{
    if (err == NULL || errlen == 0) {
        return false;
    }
    err[0] = '\0';

    policy->count            = 0;
    policy->allow_credentials = allow_credentials;

    char *cursor = origins_csv;
    while (*cursor != '\0') {
        while (*cursor == ',' || *cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        char *start = cursor;
        while (*cursor != '\0' && *cursor != ',') {
            cursor++;
        }
        bool  more      = (*cursor == ',');
        char *value_end = cursor;
        if (more) {
            *cursor = '\0';
            cursor++;
        }
        while (value_end > start && (value_end[-1] == ' ' || value_end[-1] == '\t')) {
            value_end--;
            *value_end = '\0';
        }

        if (*start == '\0') {
            continue; /* stray comma or all-whitespace segment */
        }

        if (allow_credentials && strcmp(start, "*") == 0) {
            (void)snprintf(err, errlen,
                           "origin '*' combined with allow_credentials=true is refused "
                           "(plan 7.2a)");
            return false;
        }
        if (policy->count >= PS_CORS_MAX_ORIGINS) {
            (void)snprintf(err, errlen, "too many CORS origins (max %d)", PS_CORS_MAX_ORIGINS);
            return false;
        }
        policy->origins[policy->count++] = start;
    }

    return true;
}

bool ps_cors_enabled(const ps_cors_policy_t *policy)
{
    return policy != NULL && policy->count > 0;
}

bool ps_cors_origin_allowed(const ps_cors_policy_t *policy, const char *origin, size_t origin_len)
{
    if (policy == NULL || origin == NULL) {
        return false;
    }
    for (size_t i = 0; i < policy->count; i++) {
        size_t len = strlen(policy->origins[i]);
        if (len == origin_len && memcmp(policy->origins[i], origin, origin_len) == 0) {
            return true;
        }
    }
    return false;
}
