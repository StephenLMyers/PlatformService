/*
 * Session families and refresh tokens (plan 6.8, D12). Refresh tokens are
 * stored SHA-256-hashed, exactly like verification tokens (plan 6.6) --
 * a database leak must not yield a usable session. Consumed tokens are
 * retained, never deleted here: reuse detection depends on telling
 * "already spent" from "never existed" apart, and only the maintenance
 * sweep (plan 3.4) ever removes them, once their family is long past
 * absolute_exp.
 */
#ifndef PS_STORE_SESSION_STORE_H
#define PS_STORE_SESSION_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#define PS_FAMILY_ID_LEN 16 /* 128-bit CSPRNG */
#define PS_REFRESH_TOKEN_HASH_LEN 32 /* SHA-256 */

typedef struct {
    unsigned char family_id[PS_FAMILY_ID_LEN];
    int64_t       user_id;
    int64_t       created_at;
    int64_t       absolute_exp;
    int64_t       revoked_at;               /* 0 means SQL NULL / still live */
    char          revoke_cause[32];         /* empty when revoked_at == 0 */
} ps_session_family_row_t;

typedef struct {
    unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN];
    unsigned char family_id[PS_FAMILY_ID_LEN];
    int           generation;
    int64_t       idle_exp;
    int64_t       consumed_at; /* 0 means SQL NULL / not yet consumed */
    int64_t       issued_at;
} ps_refresh_token_row_t;

bool ps_session_store_create_family(sqlite3 *conn, const unsigned char family_id[PS_FAMILY_ID_LEN],
                                    int64_t user_id, int64_t now, int64_t absolute_exp,
                                    char *err, size_t errlen);

/* False if no row with that family_id exists; out left untouched. */
bool ps_session_store_get_family(sqlite3 *conn, const unsigned char family_id[PS_FAMILY_ID_LEN],
                                 ps_session_family_row_t *out);

/* Idempotent: revoking an already-revoked family is a no-op success
 * (plan 4.6's logout is idempotent), not an error -- the WHERE clause
 * only touches a row whose revoked_at is still NULL. */
bool ps_session_store_revoke_family(sqlite3 *conn, const unsigned char family_id[PS_FAMILY_ID_LEN],
                                    const char *cause, int64_t now, char *err, size_t errlen);

bool ps_session_store_insert_token(sqlite3 *conn, const unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN],
                                   const unsigned char family_id[PS_FAMILY_ID_LEN], int generation,
                                   int64_t idle_exp, int64_t now, char *err, size_t errlen);

/* False if no row with that hash exists; out left untouched. */
bool ps_session_store_get_token(sqlite3 *conn, const unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN],
                                ps_refresh_token_row_t *out);

/*
 * Atomically claims a not-yet-consumed token: *out_claimed is true only if
 * THIS call transitioned it from unconsumed to consumed, false if it was
 * already consumed by the time this ran (whether by a legitimate earlier
 * rotation or a concurrent request racing this same call) or doesn't
 * exist. This is the race-free primitive reuse detection is built on --
 * plan 6.8's threat model treats losing this race exactly like a stolen
 * token, not as a benign retry. Returns false only on a genuine SQL
 * failure, distinct from "didn't claim it".
 */
bool ps_session_store_try_consume_token(sqlite3 *conn,
                                        const unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN],
                                        int64_t now, bool *out_claimed, char *err, size_t errlen);

/*
 * Revokes every live family belonging to user_id except except_family_id
 * (pass NULL to revoke all of them) -- the plan 4.7 password-change rule
 * ("the session issuing the change survives; all others die") and, with
 * except_family_id NULL, the plan 6.9 DISABLED-account rule (all session
 * families revoked). *out_count receives how many rows were actually
 * revoked, for the PASSWORD_CHANGE audit detail (plan 6.10: "the count of
 * sessions revoked"). Idempotent and composable the same way
 * ps_session_store_revoke_family is.
 */
bool ps_session_store_revoke_all_for_user(sqlite3 *conn, int64_t user_id,
                                          const unsigned char *except_family_id,
                                          const char *cause, int64_t now, int *out_count,
                                          char *err, size_t errlen);

#endif /* PS_STORE_SESSION_STORE_H */
