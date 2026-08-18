#include "store/user_store.h"

#include <stdio.h>
#include <string.h>

#define SELECT_COLUMNS \
    "user_id, username, email, email_normalized, password_hash, password_salt, kdf_iters, " \
    "status, failed_logins, locked_until, created_at, updated_at"

const char *ps_user_status_to_string(ps_user_status_t status)
{
    switch (status) {
    case PS_USER_STATUS_PENDING_VERIFICATION: return "PENDING_VERIFICATION";
    case PS_USER_STATUS_ACTIVE:               return "ACTIVE";
    case PS_USER_STATUS_DISABLED:             return "DISABLED";
    }
    return "PENDING_VERIFICATION"; /* unreachable: every ps_user_status_t is handled above */
}

bool ps_user_status_from_string(const char *s, ps_user_status_t *out)
{
    if (strcmp(s, "PENDING_VERIFICATION") == 0) {
        *out = PS_USER_STATUS_PENDING_VERIFICATION;
        return true;
    }
    if (strcmp(s, "ACTIVE") == 0) {
        *out = PS_USER_STATUS_ACTIVE;
        return true;
    }
    if (strcmp(s, "DISABLED") == 0) {
        *out = PS_USER_STATUS_DISABLED;
        return true;
    }
    return false;
}

static bool row_exists(sqlite3 *conn, const char *sql, const char *value)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_text(stmt, 1, value, -1, SQLITE_STATIC);
    bool exists = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return exists;
}

/* SAVEPOINT/RELEASE rather than BEGIN/COMMIT: SQLite savepoints nest, so
 * this composes correctly whether called standalone (acts as its own
 * mini-transaction, same as before) or from inside a caller's own
 * transaction -- e.g. register/bootstrap wrapping this together with a
 * verification-token insert and an audit-log write so the whole state
 * change commits or rolls back as one unit (plan 6.10). Plain BEGIN
 * cannot nest and would fail outright in the second case. */
#define PS_USER_INSERT_SAVEPOINT "ps_user_insert"

static void rollback_insert(sqlite3 *conn)
{
    (void)sqlite3_exec(conn,
                       "ROLLBACK TO " PS_USER_INSERT_SAVEPOINT ";"
                       "RELEASE " PS_USER_INSERT_SAVEPOINT ";",
                       NULL, NULL, NULL);
}

ps_user_insert_result_t ps_user_store_insert(sqlite3 *conn, const ps_user_row_t *row,
                                             const char *const *role_names, size_t role_count,
                                             int64_t now, int64_t *out_user_id,
                                             char *err, size_t errlen)
{
    char *errmsg = NULL;
    if (sqlite3_exec(conn, "SAVEPOINT " PS_USER_INSERT_SAVEPOINT ";", NULL, NULL, &errmsg) !=
        SQLITE_OK) {
        (void)snprintf(err, errlen, "SAVEPOINT: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        return PS_USER_INSERT_ERROR;
    }

    if (row_exists(conn, "SELECT 1 FROM users WHERE username = ?", row->username)) {
        rollback_insert(conn);
        return PS_USER_INSERT_DUPLICATE_USERNAME;
    }
    if (row_exists(conn, "SELECT 1 FROM users WHERE email_normalized = ?", row->email_normalized)) {
        rollback_insert(conn);
        return PS_USER_INSERT_DUPLICATE_EMAIL;
    }

    sqlite3_stmt *stmt = NULL;
    static const char *insert_sql =
        "INSERT INTO users (username, email, email_normalized, password_hash, password_salt, "
        "kdf_iters, status, failed_logins, locked_until, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    if (sqlite3_prepare_v2(conn, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare insert: %s", sqlite3_errmsg(conn));
        rollback_insert(conn);
        return PS_USER_INSERT_ERROR;
    }
    (void)sqlite3_bind_text(stmt, 1, row->username, -1, SQLITE_STATIC);
    (void)sqlite3_bind_text(stmt, 2, row->email, -1, SQLITE_STATIC);
    (void)sqlite3_bind_text(stmt, 3, row->email_normalized, -1, SQLITE_STATIC);
    (void)sqlite3_bind_blob(stmt, 4, row->password_hash, (int)sizeof row->password_hash, SQLITE_STATIC);
    (void)sqlite3_bind_blob(stmt, 5, row->password_salt, (int)sizeof row->password_salt, SQLITE_STATIC);
    (void)sqlite3_bind_int(stmt, 6, row->kdf_iters);
    (void)sqlite3_bind_text(stmt, 7, ps_user_status_to_string(row->status), -1, SQLITE_STATIC);
    (void)sqlite3_bind_int(stmt, 8, row->failed_logins);
    if (row->locked_until == 0) {
        (void)sqlite3_bind_null(stmt, 9);
    } else {
        (void)sqlite3_bind_int64(stmt, 9, row->locked_until);
    }
    (void)sqlite3_bind_int64(stmt, 10, now);
    (void)sqlite3_bind_int64(stmt, 11, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "insert user: %s", sqlite3_errmsg(conn));
        rollback_insert(conn);
        return PS_USER_INSERT_ERROR;
    }

    int64_t user_id = sqlite3_last_insert_rowid(conn);

    /* SELECT-based INSERT rather than a lookup-then-insert pair: a role
     * name with no matching row simply inserts nothing, detected via
     * sqlite3_changes() below, in one prepared statement instead of two. */
    static const char *role_insert_sql =
        "INSERT INTO user_roles (user_id, role_id) SELECT ?, role_id FROM roles WHERE name = ?";
    for (size_t i = 0; i < role_count; i++) {
        sqlite3_stmt *role_stmt = NULL;
        if (sqlite3_prepare_v2(conn, role_insert_sql, -1, &role_stmt, NULL) != SQLITE_OK) {
            (void)snprintf(err, errlen, "prepare role insert: %s", sqlite3_errmsg(conn));
            rollback_insert(conn);
            return PS_USER_INSERT_ERROR;
        }
        (void)sqlite3_bind_int64(role_stmt, 1, user_id);
        (void)sqlite3_bind_text(role_stmt, 2, role_names[i], -1, SQLITE_STATIC);
        rc = sqlite3_step(role_stmt);
        sqlite3_finalize(role_stmt);
        if (rc != SQLITE_DONE) {
            (void)snprintf(err, errlen, "insert user_roles: %s", sqlite3_errmsg(conn));
            rollback_insert(conn);
            return PS_USER_INSERT_ERROR;
        }
        if (sqlite3_changes(conn) == 0) {
            (void)snprintf(err, errlen, "unknown role: %s", role_names[i]);
            rollback_insert(conn);
            return PS_USER_INSERT_ERROR;
        }
    }

    if (sqlite3_exec(conn, "RELEASE " PS_USER_INSERT_SAVEPOINT ";", NULL, NULL, &errmsg) !=
        SQLITE_OK) {
        (void)snprintf(err, errlen, "RELEASE: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        return PS_USER_INSERT_ERROR;
    }

    *out_user_id = user_id;
    return PS_USER_INSERT_OK;
}

/* Trusts every column's shape: every row this function ever reads was
 * written by ps_user_store_insert above, so the blob lengths and status
 * string are already known-good (plan: trust internal invariants). */
static void populate_row(sqlite3_stmt *stmt, ps_user_row_t *out)
{
    out->user_id = sqlite3_column_int64(stmt, 0);
    (void)snprintf(out->username, sizeof out->username, "%s",
                   (const char *)sqlite3_column_text(stmt, 1));
    (void)snprintf(out->email, sizeof out->email, "%s",
                   (const char *)sqlite3_column_text(stmt, 2));
    (void)snprintf(out->email_normalized, sizeof out->email_normalized, "%s",
                   (const char *)sqlite3_column_text(stmt, 3));
    memcpy(out->password_hash, sqlite3_column_blob(stmt, 4), sizeof out->password_hash);
    memcpy(out->password_salt, sqlite3_column_blob(stmt, 5), sizeof out->password_salt);
    out->kdf_iters = sqlite3_column_int(stmt, 6);
    (void)ps_user_status_from_string((const char *)sqlite3_column_text(stmt, 7), &out->status);
    out->failed_logins = sqlite3_column_int(stmt, 8);
    out->locked_until =
        sqlite3_column_type(stmt, 9) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 9);
    out->created_at = sqlite3_column_int64(stmt, 10);
    out->updated_at = sqlite3_column_int64(stmt, 11);
}

static bool get_by_text_column(sqlite3 *conn, const char *column, const char *value,
                               ps_user_row_t *out)
{
    char sql[256];
    (void)snprintf(sql, sizeof sql, "SELECT " SELECT_COLUMNS " FROM users WHERE %s = ?", column);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_text(stmt, 1, value, -1, SQLITE_STATIC);
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    if (found) {
        populate_row(stmt, out);
    }
    sqlite3_finalize(stmt);
    return found;
}

bool ps_user_store_get_by_id(sqlite3 *conn, int64_t user_id, ps_user_row_t *out)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, "SELECT " SELECT_COLUMNS " FROM users WHERE user_id = ?", -1,
                           &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, user_id);
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    if (found) {
        populate_row(stmt, out);
    }
    sqlite3_finalize(stmt);
    return found;
}

bool ps_user_store_get_by_username(sqlite3 *conn, const char *username, ps_user_row_t *out)
{
    return get_by_text_column(conn, "username", username, out);
}

bool ps_user_store_get_by_email_normalized(sqlite3 *conn, const char *email_normalized,
                                           ps_user_row_t *out)
{
    return get_by_text_column(conn, "email_normalized", email_normalized, out);
}

bool ps_user_store_get_roles(sqlite3 *conn, int64_t user_id, char out[][32], size_t cap,
                             size_t *out_count)
{
    static const char *sql =
        "SELECT roles.name FROM roles JOIN user_roles ON roles.role_id = user_roles.role_id "
        "WHERE user_roles.user_id = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, user_id);

    size_t count = 0;
    int    rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (count < cap) {
            (void)snprintf(out[count], 32, "%s", (const char *)sqlite3_column_text(stmt, 0));
        }
        count++;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return false;
    }
    *out_count = count;
    return true;
}

bool ps_user_store_update_status(sqlite3 *conn, int64_t user_id, ps_user_status_t status,
                                 int64_t now, char *err, size_t errlen)
{
    static const char *sql = "UPDATE users SET status = ?, updated_at = ? WHERE user_id = ?";
    sqlite3_stmt       *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare status update: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_text(stmt, 1, ps_user_status_to_string(status), -1, SQLITE_STATIC);
    (void)sqlite3_bind_int64(stmt, 2, now);
    (void)sqlite3_bind_int64(stmt, 3, user_id);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "update user status: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}
