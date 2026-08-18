/*
 * Username and email validation/normalization (plan 7.6). Lives in auth/,
 * not api/, so both the public register handler (api/, above auth/) and
 * auth/bootstrap.c (same layer, can't reach upward into api/) can share
 * it.
 */
#ifndef PS_AUTH_VALIDATE_H
#define PS_AUTH_VALIDATE_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    PS_USERNAME_VALID = 0,
    PS_USERNAME_TOO_SHORT,
    PS_USERNAME_TOO_LONG,
    PS_USERNAME_BAD_CHARSET,
    PS_USERNAME_STARTS_NON_ALPHANUMERIC,
    PS_USERNAME_RESERVED,
} ps_username_validate_result_t;

/*
 * Normalizes raw to ASCII-lowercase into out (out_size must be at least
 * PS_USERNAME_MAX) and validates: 3-32 characters, [a-z0-9_-] after
 * lowering, must start alphanumeric (plan 7.6). check_reserved controls
 * whether the reserved-name denylist (admin, root, ...) applies -- public
 * registration always passes true; the operator-controlled bootstrap
 * admin (plan 6.7) passes false, since naming that one legitimate account
 * "admin" is exactly the point, and its credentials come from the trusted
 * server environment, not an anonymous HTTP request. out is written
 * (truncated normalization) even on a validation failure, for error
 * messages that want to echo back what was checked; never trust it as a
 * real username unless the result is PS_USERNAME_VALID.
 */
ps_username_validate_result_t ps_username_validate(const char *raw, char *out, size_t out_size,
                                                    bool check_reserved);

typedef enum {
    PS_EMAIL_VALID = 0,
    PS_EMAIL_TOO_LONG,
    PS_EMAIL_MALFORMED,
} ps_email_validate_result_t;

/*
 * Normalizes raw (trim + ASCII-lowercase, plan 6.6) into out (out_size
 * must be at least PS_EMAIL_MAX) and validates loosely (plan 7.6): <=254
 * characters, exactly one '@', non-empty local and domain parts, a dot in
 * the domain. Deliberately not full RFC 5322 -- deliverability is proven
 * by the verification email arriving, not by parsing.
 */
ps_email_validate_result_t ps_email_validate(const char *raw, char *out, size_t out_size);

#endif /* PS_AUTH_VALIDATE_H */
