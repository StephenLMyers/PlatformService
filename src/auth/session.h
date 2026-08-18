/*
 * Session creation and refresh-token rotation with reuse detection
 * (plan 6.8, D12). Sits above store/session_store.c the same way
 * store/user_store.c and auth/bootstrap.c relate: this owns the
 * algorithm (what counts as valid, what reuse means, what a rotation
 * produces), store/session_store.c owns the raw rows.
 */
#ifndef PS_AUTH_SESSION_H
#define PS_AUTH_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#include "store/session_store.h"

typedef struct {
    unsigned char family_id[PS_FAMILY_ID_LEN];
    unsigned char raw_refresh_token[PS_REFRESH_TOKEN_HASH_LEN]; /* 256-bit CSPRNG, pre-hash */
    int64_t       refresh_idle_exp;
} ps_session_created_t;

/* Opens a new session family (plan 6.8) with its first refresh token
 * (generation 1). Composes into a caller-managed transaction -- no
 * BEGIN/COMMIT of its own. */
bool ps_session_create(sqlite3 *conn, int64_t user_id, int absolute_ttl_s, int idle_ttl_s,
                       int64_t now, ps_session_created_t *out, char *err, size_t errlen);

typedef enum {
    PS_SESSION_REFRESH_OK = 0,
    PS_SESSION_REFRESH_INVALID,        /* unknown, expired, or a revoked/expired family */
    PS_SESSION_REFRESH_REUSE_DETECTED, /* the presented token was already consumed */
    PS_SESSION_REFRESH_ERROR,
} ps_session_refresh_result_t;

typedef struct {
    int64_t       user_id;    /* the family's owner; 0 only if the token was never found at all */
    unsigned char family_id[PS_FAMILY_ID_LEN]; /* likewise zero only if never found */
    unsigned char raw_refresh_token[PS_REFRESH_TOKEN_HASH_LEN]; /* only set on PS_SESSION_REFRESH_OK */
    int64_t       refresh_idle_exp;
} ps_session_refreshed_t;

/*
 * Rotates old_token_hash (the SHA-256 hash of the token the caller
 * presented -- hashing is the caller's job, matching how verify/resend
 * already handle their own tokens in api/auth_api.c). On
 * PS_SESSION_REFRESH_OK, out->raw_refresh_token is the new token; the old
 * one is already consumed and can never be presented again.
 *
 * out->user_id and out->family_id are populated as soon as the token is
 * found at all -- on every result except a token that was never found,
 * even PS_SESSION_REFRESH_INVALID and PS_SESSION_REFRESH_REUSE_DETECTED --
 * so the caller can always attribute an audit row to the right account
 * without a second lookup. On PS_SESSION_REFRESH_REUSE_DETECTED, the
 * family has already been revoked as a side effect of this call; the
 * caller does not need to revoke it again.
 *
 * Composes into a caller-managed transaction -- no BEGIN/COMMIT of its
 * own. The atomic claim inside (store/session_store.c's
 * ps_session_store_try_consume_token) is what makes this race-free even
 * without one: two concurrent presentations of the same token can only
 * ever have one winner, and the loser is treated as reuse, never as a
 * silent no-op.
 */
ps_session_refresh_result_t ps_session_refresh(sqlite3 *conn,
                                               const unsigned char old_token_hash[PS_REFRESH_TOKEN_HASH_LEN],
                                               int idle_ttl_s, int64_t now,
                                               ps_session_refreshed_t *out, char *err, size_t errlen);

#endif /* PS_AUTH_SESSION_H */
