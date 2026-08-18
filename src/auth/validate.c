#include "auth/validate.h"

#include <ctype.h>
#include <string.h>

/* "and similar" (plan 7.6) -- a curated, not exhaustive, set of names
 * that would let a registered account impersonate authority. */
static const char *const RESERVED_USERNAMES[] = {
    "admin", "administrator", "root", "system", "support", "security",
    "null", "undefined", "moderator", "staff", "owner", "superuser",
    "sysadmin", "webmaster", "postmaster", "api", "test",
};
#define RESERVED_USERNAMES_COUNT (sizeof RESERVED_USERNAMES / sizeof RESERVED_USERNAMES[0])

static bool is_username_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
}

static bool is_alnum_ascii(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

ps_username_validate_result_t ps_username_validate(const char *raw, char *out, size_t out_size,
                                                    bool check_reserved)
{
    size_t raw_len = strlen(raw);
    size_t n       = raw_len < out_size - 1 ? raw_len : out_size - 1;
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)tolower((unsigned char)raw[i]);
    }
    out[n] = '\0';

    if (raw_len < 3) {
        return PS_USERNAME_TOO_SHORT;
    }
    if (raw_len > 32) {
        return PS_USERNAME_TOO_LONG;
    }
    for (size_t i = 0; i < n; i++) {
        if (!is_username_char((unsigned char)out[i])) {
            return PS_USERNAME_BAD_CHARSET;
        }
    }
    if (!is_alnum_ascii((unsigned char)out[0])) {
        return PS_USERNAME_STARTS_NON_ALPHANUMERIC;
    }
    if (check_reserved) {
        for (size_t i = 0; i < RESERVED_USERNAMES_COUNT; i++) {
            if (strcmp(out, RESERVED_USERNAMES[i]) == 0) {
                return PS_USERNAME_RESERVED;
            }
        }
    }
    return PS_USERNAME_VALID;
}

ps_email_validate_result_t ps_email_validate(const char *raw, char *out, size_t out_size)
{
    const char *start = raw;
    while (*start == ' ' || *start == '\t') {
        start++;
    }
    const char *end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }
    size_t trimmed_len = (size_t)(end - start);

    size_t n = trimmed_len < out_size - 1 ? trimmed_len : out_size - 1;
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)tolower((unsigned char)start[i]);
    }
    out[n] = '\0';

    if (trimmed_len > 254) {
        return PS_EMAIL_TOO_LONG;
    }

    const char *at = strchr(out, '@');
    if (at == NULL || strchr(at + 1, '@') != NULL) {
        return PS_EMAIL_MALFORMED; /* missing, or a second '@' */
    }
    size_t local_len = (size_t)(at - out);
    if (local_len == 0 || *(at + 1) == '\0' || strchr(at + 1, '.') == NULL) {
        return PS_EMAIL_MALFORMED; /* empty local part, empty domain, or no dot in domain */
    }
    return PS_EMAIL_VALID;
}
