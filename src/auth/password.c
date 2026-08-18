#include "auth/password.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/ct.h"
#include "crypto/rand.h"

bool ps_password_hash(const char *password, size_t password_len,
                      int iterations, ps_password_hash_t *out)
{
    if (!ps_rand_bytes(out->salt, sizeof out->salt)) {
        return false;
    }
    out->iterations = iterations;
    return ps_kdf_derive(password, password_len, out->salt, iterations, out->hash);
}

bool ps_password_verify(const char *password, size_t password_len,
                        const ps_password_hash_t *stored)
{
    unsigned char computed[PS_KDF_OUTPUT_LEN];
    if (!ps_kdf_derive(password, password_len, stored->salt, stored->iterations, computed)) {
        return false;
    }
    return ps_ct_equal(computed, stored->hash, PS_KDF_OUTPUT_LEN);
}

static int compare_lines(const void *a, const void *b)
{
    const char *sa = *(const char *const *)a;
    const char *sb = *(const char *const *)b;
    return strcmp(sa, sb);
}

bool ps_password_denylist_load(const char *path, ps_password_denylist_t *out,
                               char *err, size_t errlen)
{
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        (void)snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return false;
    }

    if (fseek(f, 0, SEEK_END) != 0 || ftell(f) < 0) {
        (void)snprintf(err, errlen, "seek %s: %s", path, strerror(errno));
        (void)fclose(f);
        return false;
    }
    long size = ftell(f);
    rewind(f);

    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        (void)snprintf(err, errlen, "out of memory reading %s", path);
        (void)fclose(f);
        return false;
    }
    size_t nread = fread(buf, 1, (size_t)size, f);
    (void)fclose(f);
    buf[nread] = '\0';

    size_t       capacity = 16;
    const char **lines    = malloc(capacity * sizeof *lines);
    if (lines == NULL) {
        free(buf);
        (void)snprintf(err, errlen, "out of memory reading %s", path);
        return false;
    }
    size_t count = 0;

    char *line_start = buf;
    for (char *p = buf; p < buf + nread; p++) {
        if (*p != '\n') {
            continue;
        }
        *p = '\0';
        size_t linelen = (size_t)(p - line_start);
        if (linelen > 0 && line_start[linelen - 1] == '\r') {
            line_start[linelen - 1] = '\0';
        }
        if (*line_start != '\0') {
            if (count == capacity) {
                capacity *= 2;
                const char **grown = realloc(lines, capacity * sizeof *lines);
                if (grown == NULL) {
                    free(lines);
                    free(buf);
                    (void)snprintf(err, errlen, "out of memory reading %s", path);
                    return false;
                }
                lines = grown;
            }
            lines[count++] = line_start;
        }
        line_start = p + 1;
    }
    /* A final line with no trailing newline -- buf[nread] is already the
     * NUL fread stopped short of, so line_start already reads as a
     * properly terminated string ending there. */
    if (line_start < buf + nread && *line_start != '\0') {
        if (count == capacity) {
            capacity += 1;
            const char **grown = realloc(lines, capacity * sizeof *lines);
            if (grown == NULL) {
                free(lines);
                free(buf);
                (void)snprintf(err, errlen, "out of memory reading %s", path);
                return false;
            }
            lines = grown;
        }
        lines[count++] = line_start;
    }

    /* The file is documented as already sorted-unique; sorted again here
     * regardless, so a lookup this security-relevant never silently
     * starts returning false negatives if that guarantee is ever violated
     * by a future edit to the bundled file. */
    qsort(lines, count, sizeof *lines, compare_lines);

    out->buf   = buf;
    out->lines = lines;
    out->count = count;
    return true;
}

void ps_password_denylist_free(ps_password_denylist_t *list)
{
    if (list == NULL) {
        return;
    }
    free(list->lines);
    free(list->buf);
    list->lines = NULL;
    list->buf   = NULL;
    list->count = 0;
}

static bool denylist_contains(const ps_password_denylist_t *list, const char *candidate)
{
    size_t lo = 0;
    size_t hi = list->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int    cmp = strcmp(list->lines[mid], candidate);
        if (cmp == 0) {
            return true;
        }
        if (cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return false;
}

ps_password_policy_result_t ps_password_policy_check(const char *password, size_t password_len,
                                                      int min_length, int max_length,
                                                      const ps_password_denylist_t *denylist)
{
    if ((int)password_len < min_length) {
        return PS_PASSWORD_POLICY_TOO_SHORT;
    }
    if ((int)password_len > max_length) {
        return PS_PASSWORD_POLICY_TOO_LONG;
    }
    if (denylist == NULL) {
        return PS_PASSWORD_POLICY_OK;
    }

    /* ASCII-range lowercasing only, matching plan 6.6's "no Unicode
     * normalization" scope -- non-ASCII bytes pass through unchanged. */
    char *lowered = malloc(password_len + 1);
    if (lowered == NULL) {
        return PS_PASSWORD_POLICY_ERROR;
    }
    for (size_t i = 0; i < password_len; i++) {
        unsigned char c = (unsigned char)password[i];
        lowered[i]      = (c < 0x80) ? (char)tolower(c) : (char)c;
    }
    lowered[password_len] = '\0';

    bool breached = denylist_contains(denylist, lowered);
    free(lowered);
    return breached ? PS_PASSWORD_POLICY_BREACHED : PS_PASSWORD_POLICY_OK;
}
