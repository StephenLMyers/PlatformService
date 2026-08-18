/*
 * Password hashing, verification, and the plan 6.6 policy predicate:
 * length bounds and the data/common-passwords.txt breach denylist.
 */
#ifndef PS_AUTH_PASSWORD_H
#define PS_AUTH_PASSWORD_H

#include <stdbool.h>
#include <stddef.h>

#include "crypto/kdf.h"

/*
 * A password hash as stored in a user row. iterations is recorded per row
 * rather than read from current config, so raising the configured default
 * later doesn't invalidate existing hashes -- ps_password_verify always
 * uses the row's own stored count (plan 6.3).
 */
typedef struct {
    unsigned char salt[PS_KDF_SALT_LEN];
    unsigned char hash[PS_KDF_OUTPUT_LEN];
    int            iterations;
} ps_password_hash_t;

/* Generates a fresh CSPRNG salt and derives out->hash from password using
 * iterations. Returns false only on an underlying RNG or KDF failure. */
bool ps_password_hash(const char *password, size_t password_len,
                      int iterations, ps_password_hash_t *out);

/* Constant-time comparison against a stored hash -- password verification
 * is exactly the kind of comparison that must not leak timing (plan 6.2). */
bool ps_password_verify(const char *password, size_t password_len,
                        const ps_password_hash_t *stored);

/*
 * The breach denylist (plan 6.6): data/common-passwords.txt loaded into a
 * sorted array of line pointers into one heap buffer, looked up by binary
 * search. The file is documented as already sorted-unique, but this sorts
 * it again after loading regardless -- a security-relevant lookup should
 * not silently start returning false negatives if that guarantee is ever
 * violated by a future edit to the bundled file.
 */
typedef struct {
    char        *buf;    /* whole file contents; owns every pointer in lines */
    const char **lines;  /* sorted; count entries */
    size_t       count;
} ps_password_denylist_t;

bool ps_password_denylist_load(const char *path, ps_password_denylist_t *out,
                               char *err, size_t errlen);
void ps_password_denylist_free(ps_password_denylist_t *list);

typedef enum {
    PS_PASSWORD_POLICY_OK = 0,
    PS_PASSWORD_POLICY_TOO_SHORT,
    PS_PASSWORD_POLICY_TOO_LONG,
    PS_PASSWORD_POLICY_BREACHED,
    PS_PASSWORD_POLICY_ERROR, /* out of memory forming the lowercased candidate */
} ps_password_policy_result_t;

/*
 * Length checked first (NIST SP 800-63B: length over composition, no
 * forced character-class rules -- plan 6.6), so the breach lookup only
 * ever compares an already-length-valid candidate. denylist may be NULL,
 * in which case the breach check is skipped -- callers that haven't
 * loaded one yet (e.g. before startup finishes) still get the length
 * bounds enforced rather than being unable to call this at all.
 */
ps_password_policy_result_t ps_password_policy_check(const char *password, size_t password_len,
                                                      int min_length, int max_length,
                                                      const ps_password_denylist_t *denylist);

#endif /* PS_AUTH_PASSWORD_H */
