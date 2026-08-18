/*
 * Email verification tokens (plan 6.6). Stored as their SHA-256 hash, per
 * the same reasoning as password hashing: a database compromise must not
 * yield a usable activation link. The raw token never reaches this module
 * -- callers hash it first (crypto/hmac.h has no SHA-256-alone primitive
 * today; a plain digest is sufficient here since the token is already
 * 256 bits of full-entropy CSPRNG output, not a guessable human secret).
 */
#ifndef PS_STORE_TOKEN_STORE_H
#define PS_STORE_TOKEN_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#define PS_TOKEN_HASH_LEN 32 /* SHA-256 */

typedef struct {
    unsigned char token_hash[PS_TOKEN_HASH_LEN];
    int64_t       user_id;
    int64_t       expires_at;
    int64_t       consumed_at; /* 0 means SQL NULL / not yet consumed */
    int64_t       created_at;
} ps_verification_token_row_t;

bool ps_token_store_insert(sqlite3 *conn, const unsigned char token_hash[PS_TOKEN_HASH_LEN],
                           int64_t user_id, int64_t expires_at, int64_t now,
                           char *err, size_t errlen);

/* False if no row with that hash exists; out left untouched. */
bool ps_token_store_get_by_hash(sqlite3 *conn, const unsigned char token_hash[PS_TOKEN_HASH_LEN],
                                ps_verification_token_row_t *out);

bool ps_token_store_consume(sqlite3 *conn, const unsigned char token_hash[PS_TOKEN_HASH_LEN],
                            int64_t now, char *err, size_t errlen);

/* Marks every outstanding (consumed_at IS NULL) token for user_id
 * consumed, without deleting them -- live tokens must not accumulate
 * (plan 4.3: a resend invalidates all prior ones), but the rows themselves
 * are still retained until the maintenance sweep's normal retention
 * window, same as any other consumed token. */
bool ps_token_store_invalidate_all_for_user(sqlite3 *conn, int64_t user_id, int64_t now,
                                            char *err, size_t errlen);

/* Count of tokens created for user_id at or after `since` -- the building
 * block for resend's per-email throttle (plan 4.3): call with
 * since = now-60 for the 1-per-60s check, since = now-86400 for the
 * 5-per-day check. */
bool ps_token_store_count_created_since(sqlite3 *conn, int64_t user_id, int64_t since,
                                        int64_t *out_count);

#endif /* PS_STORE_TOKEN_STORE_H */
