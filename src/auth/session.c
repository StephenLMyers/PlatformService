#include "auth/session.h"

#include <stdio.h>
#include <string.h>

#include "crypto/rand.h"
#include "crypto/sha256.h"

bool ps_session_create(sqlite3 *conn, int64_t user_id, int absolute_ttl_s, int idle_ttl_s,
                       int64_t now, ps_session_created_t *out, char *err, size_t errlen)
{
    unsigned char family_id[PS_FAMILY_ID_LEN];
    if (!ps_rand_bytes(family_id, sizeof family_id)) {
        (void)snprintf(err, errlen, "failed to generate session family id");
        return false;
    }
    int64_t absolute_exp = now + absolute_ttl_s;
    if (!ps_session_store_create_family(conn, family_id, user_id, now, absolute_exp, err, errlen)) {
        return false;
    }

    unsigned char raw_token[PS_REFRESH_TOKEN_HASH_LEN];
    if (!ps_rand_bytes(raw_token, sizeof raw_token)) {
        (void)snprintf(err, errlen, "failed to generate refresh token");
        return false;
    }
    unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN];
    if (!ps_sha256(raw_token, sizeof raw_token, token_hash)) {
        (void)snprintf(err, errlen, "failed to hash refresh token");
        return false;
    }
    int64_t idle_exp = now + idle_ttl_s;
    if (!ps_session_store_insert_token(conn, token_hash, family_id, 1, idle_exp, now, err, errlen)) {
        return false;
    }

    memcpy(out->family_id, family_id, sizeof family_id);
    memcpy(out->raw_refresh_token, raw_token, sizeof raw_token);
    out->refresh_idle_exp = idle_exp;
    return true;
}

ps_session_refresh_result_t ps_session_refresh(sqlite3 *conn,
                                               const unsigned char old_token_hash[PS_REFRESH_TOKEN_HASH_LEN],
                                               int idle_ttl_s, int64_t now,
                                               ps_session_refreshed_t *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof *out);

    ps_refresh_token_row_t token_row;
    if (!ps_session_store_get_token(conn, old_token_hash, &token_row)) {
        return PS_SESSION_REFRESH_INVALID;
    }

    /* Look up the owning family as soon as the token itself is found, before
     * branching on consumed_at -- this is what lets out->user_id/family_id
     * be populated on every remaining path, including reuse and expiry, so
     * callers can attribute an audit row without a second lookup. */
    ps_session_family_row_t family;
    if (!ps_session_store_get_family(conn, token_row.family_id, &family)) {
        (void)snprintf(err, errlen, "refresh token referenced a family that doesn't exist");
        return PS_SESSION_REFRESH_ERROR;
    }
    memcpy(out->family_id, token_row.family_id, sizeof out->family_id);
    out->user_id = family.user_id;

    if (token_row.consumed_at != 0) {
        /* Already consumed as of our read -- unambiguous reuse, no race
         * to resolve. */
        (void)ps_session_store_revoke_family(conn, token_row.family_id, "REUSE_DETECTED", now, err,
                                             errlen);
        return PS_SESSION_REFRESH_REUSE_DETECTED;
    }

    bool claimed = false;
    if (!ps_session_store_try_consume_token(conn, old_token_hash, now, &claimed, err, errlen)) {
        return PS_SESSION_REFRESH_ERROR;
    }
    if (!claimed) {
        /* Lost a race against a concurrent presentation of the same
         * token between our read above and this claim -- plan 6.8 treats
         * this exactly like reuse, not as a benign retry: two parties
         * held the same unconsumed-looking token, and only one may win. */
        (void)ps_session_store_revoke_family(conn, token_row.family_id, "REUSE_DETECTED", now, err,
                                             errlen);
        return PS_SESSION_REFRESH_REUSE_DETECTED;
    }

    /* We now own the only valid consumption of this token. It must never
     * become presentable again regardless of what happens next, which is
     * why the claim above already happened unconditionally -- everything
     * from here on decides whether a *new* token is issued, not whether
     * the old one stays dead. */
    if (family.revoked_at != 0 || family.absolute_exp < now || token_row.idle_exp < now) {
        return PS_SESSION_REFRESH_INVALID;
    }

    unsigned char new_raw[PS_REFRESH_TOKEN_HASH_LEN];
    if (!ps_rand_bytes(new_raw, sizeof new_raw)) {
        (void)snprintf(err, errlen, "failed to generate refresh token");
        return PS_SESSION_REFRESH_ERROR;
    }
    unsigned char new_hash[PS_REFRESH_TOKEN_HASH_LEN];
    if (!ps_sha256(new_raw, sizeof new_raw, new_hash)) {
        (void)snprintf(err, errlen, "failed to hash refresh token");
        return PS_SESSION_REFRESH_ERROR;
    }
    int64_t new_idle_exp = now + idle_ttl_s;
    if (!ps_session_store_insert_token(conn, new_hash, token_row.family_id, token_row.generation + 1,
                                       new_idle_exp, now, err, errlen)) {
        return PS_SESSION_REFRESH_ERROR;
    }

    memcpy(out->raw_refresh_token, new_raw, sizeof new_raw);
    out->refresh_idle_exp = new_idle_exp;
    return PS_SESSION_REFRESH_OK;
}
