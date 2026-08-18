#include "store/token_store.h"

#include <stdio.h>
#include <string.h>

bool ps_token_store_insert(sqlite3 *conn, const unsigned char token_hash[PS_TOKEN_HASH_LEN],
                           int64_t user_id, int64_t expires_at, int64_t now,
                           char *err, size_t errlen)
{
    static const char *sql =
        "INSERT INTO email_verification_tokens (token_hash, user_id, expires_at, created_at) "
        "VALUES (?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare token insert: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_blob(stmt, 1, token_hash, PS_TOKEN_HASH_LEN, SQLITE_STATIC);
    (void)sqlite3_bind_int64(stmt, 2, user_id);
    (void)sqlite3_bind_int64(stmt, 3, expires_at);
    (void)sqlite3_bind_int64(stmt, 4, now);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "insert verification token: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool ps_token_store_get_by_hash(sqlite3 *conn, const unsigned char token_hash[PS_TOKEN_HASH_LEN],
                                ps_verification_token_row_t *out)
{
    static const char *sql =
        "SELECT token_hash, user_id, expires_at, consumed_at, created_at "
        "FROM email_verification_tokens WHERE token_hash = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_blob(stmt, 1, token_hash, PS_TOKEN_HASH_LEN, SQLITE_STATIC);

    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    if (found) {
        memcpy(out->token_hash, sqlite3_column_blob(stmt, 0), PS_TOKEN_HASH_LEN);
        out->user_id     = sqlite3_column_int64(stmt, 1);
        out->expires_at  = sqlite3_column_int64(stmt, 2);
        out->consumed_at =
            sqlite3_column_type(stmt, 3) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 3);
        out->created_at = sqlite3_column_int64(stmt, 4);
    }
    sqlite3_finalize(stmt);
    return found;
}

bool ps_token_store_consume(sqlite3 *conn, const unsigned char token_hash[PS_TOKEN_HASH_LEN],
                            int64_t now, char *err, size_t errlen)
{
    static const char *sql =
        "UPDATE email_verification_tokens SET consumed_at = ? WHERE token_hash = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare token consume: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, now);
    (void)sqlite3_bind_blob(stmt, 2, token_hash, PS_TOKEN_HASH_LEN, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "consume verification token: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool ps_token_store_invalidate_all_for_user(sqlite3 *conn, int64_t user_id, int64_t now,
                                            char *err, size_t errlen)
{
    static const char *sql =
        "UPDATE email_verification_tokens SET consumed_at = ? "
        "WHERE user_id = ? AND consumed_at IS NULL";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare token invalidate: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, now);
    (void)sqlite3_bind_int64(stmt, 2, user_id);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "invalidate verification tokens: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool ps_token_store_count_created_since(sqlite3 *conn, int64_t user_id, int64_t since,
                                        int64_t *out_count)
{
    static const char *sql =
        "SELECT COUNT(*) FROM email_verification_tokens WHERE user_id = ? AND created_at >= ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, user_id);
    (void)sqlite3_bind_int64(stmt, 2, since);

    bool ok = sqlite3_step(stmt) == SQLITE_ROW;
    if (ok) {
        *out_count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return ok;
}
