/*
 * Password hashing and verification (plan 6.3). The policy predicate
 * (length bounds, breach-denylist check) is registration business logic
 * and lands in phase 6 alongside data/common-passwords.txt; this is just
 * the KDF wrapper.
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

#endif /* PS_AUTH_PASSWORD_H */
