#include "store/session_store.h"

#include <stdio.h>
#include <string.h>

bool ps_session_store_create_family(sqlite3 *conn, const unsigned char family_id[PS_FAMILY_ID_LEN],
                                    int64_t user_id, int64_t now, int64_t absolute_exp,
                                    char *err, size_t errlen)
{
    static const char *sql =
        "INSERT INTO session_families (family_id, user_id, created_at, absolute_exp) "
        "VALUES (?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare family insert: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_blob(stmt, 1, family_id, PS_FAMILY_ID_LEN, SQLITE_STATIC);
    (void)sqlite3_bind_int64(stmt, 2, user_id);
    (void)sqlite3_bind_int64(stmt, 3, now);
    (void)sqlite3_bind_int64(stmt, 4, absolute_exp);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "insert session_families: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool ps_session_store_get_family(sqlite3 *conn, const unsigned char family_id[PS_FAMILY_ID_LEN],
                                 ps_session_family_row_t *out)
{
    static const char *sql =
        "SELECT family_id, user_id, created_at, absolute_exp, revoked_at, revoke_cause "
        "FROM session_families WHERE family_id = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_blob(stmt, 1, family_id, PS_FAMILY_ID_LEN, SQLITE_STATIC);

    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    if (found) {
        memcpy(out->family_id, sqlite3_column_blob(stmt, 0), PS_FAMILY_ID_LEN);
        out->user_id      = sqlite3_column_int64(stmt, 1);
        out->created_at   = sqlite3_column_int64(stmt, 2);
        out->absolute_exp = sqlite3_column_int64(stmt, 3);
        out->revoked_at =
            sqlite3_column_type(stmt, 4) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 4);
        if (sqlite3_column_type(stmt, 5) == SQLITE_NULL) {
            out->revoke_cause[0] = '\0';
        } else {
            (void)snprintf(out->revoke_cause, sizeof out->revoke_cause, "%s",
                           (const char *)sqlite3_column_text(stmt, 5));
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

bool ps_session_store_revoke_family(sqlite3 *conn, const unsigned char family_id[PS_FAMILY_ID_LEN],
                                    const char *cause, int64_t now, char *err, size_t errlen)
{
    static const char *sql =
        "UPDATE session_families SET revoked_at = ?, revoke_cause = ? "
        "WHERE family_id = ? AND revoked_at IS NULL";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare family revoke: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, now);
    (void)sqlite3_bind_text(stmt, 2, cause, -1, SQLITE_STATIC);
    (void)sqlite3_bind_blob(stmt, 3, family_id, PS_FAMILY_ID_LEN, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "revoke session_families: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool ps_session_store_insert_token(sqlite3 *conn,
                                   const unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN],
                                   const unsigned char family_id[PS_FAMILY_ID_LEN], int generation,
                                   int64_t idle_exp, int64_t now, char *err, size_t errlen)
{
    static const char *sql =
        "INSERT INTO refresh_tokens (token_hash, family_id, generation, idle_exp, issued_at) "
        "VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare token insert: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_blob(stmt, 1, token_hash, PS_REFRESH_TOKEN_HASH_LEN, SQLITE_STATIC);
    (void)sqlite3_bind_blob(stmt, 2, family_id, PS_FAMILY_ID_LEN, SQLITE_STATIC);
    (void)sqlite3_bind_int(stmt, 3, generation);
    (void)sqlite3_bind_int64(stmt, 4, idle_exp);
    (void)sqlite3_bind_int64(stmt, 5, now);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "insert refresh_tokens: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool ps_session_store_get_token(sqlite3 *conn,
                                const unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN],
                                ps_refresh_token_row_t *out)
{
    static const char *sql =
        "SELECT token_hash, family_id, generation, idle_exp, consumed_at, issued_at "
        "FROM refresh_tokens WHERE token_hash = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_blob(stmt, 1, token_hash, PS_REFRESH_TOKEN_HASH_LEN, SQLITE_STATIC);

    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    if (found) {
        memcpy(out->token_hash, sqlite3_column_blob(stmt, 0), PS_REFRESH_TOKEN_HASH_LEN);
        memcpy(out->family_id, sqlite3_column_blob(stmt, 1), PS_FAMILY_ID_LEN);
        out->generation = sqlite3_column_int(stmt, 2);
        out->idle_exp   = sqlite3_column_int64(stmt, 3);
        out->consumed_at =
            sqlite3_column_type(stmt, 4) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 4);
        out->issued_at = sqlite3_column_int64(stmt, 5);
    }
    sqlite3_finalize(stmt);
    return found;
}

bool ps_session_store_try_consume_token(sqlite3 *conn,
                                        const unsigned char token_hash[PS_REFRESH_TOKEN_HASH_LEN],
                                        int64_t now, bool *out_claimed, char *err, size_t errlen)
{
    static const char *sql =
        "UPDATE refresh_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare token consume: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, now);
    (void)sqlite3_bind_blob(stmt, 2, token_hash, PS_REFRESH_TOKEN_HASH_LEN, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "consume refresh_tokens: %s", sqlite3_errmsg(conn));
        sqlite3_finalize(stmt);
        return false;
    }
    *out_claimed = sqlite3_changes(conn) > 0;
    sqlite3_finalize(stmt);
    return true;
}

bool ps_session_store_revoke_all_for_user(sqlite3 *conn, int64_t user_id,
                                          const unsigned char *except_family_id,
                                          const char *cause, int64_t now, int *out_count,
                                          char *err, size_t errlen)
{
    const char *sql = except_family_id == NULL
        ? "UPDATE session_families SET revoked_at = ?, revoke_cause = ? "
          "WHERE user_id = ? AND revoked_at IS NULL"
        : "UPDATE session_families SET revoked_at = ?, revoke_cause = ? "
          "WHERE user_id = ? AND revoked_at IS NULL AND family_id != ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare revoke-all-for-user: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, now);
    (void)sqlite3_bind_text(stmt, 2, cause, -1, SQLITE_STATIC);
    (void)sqlite3_bind_int64(stmt, 3, user_id);
    if (except_family_id != NULL) {
        (void)sqlite3_bind_blob(stmt, 4, except_family_id, PS_FAMILY_ID_LEN, SQLITE_STATIC);
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "revoke all session_families for user: %s", sqlite3_errmsg(conn));
        sqlite3_finalize(stmt);
        return false;
    }
    if (out_count != NULL) {
        *out_count = sqlite3_changes(conn);
    }
    sqlite3_finalize(stmt);
    return true;
}
