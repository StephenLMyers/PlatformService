#include "store/audit_store.h"

#include <stdio.h>

bool ps_audit_store_write(sqlite3 *conn, const ps_audit_entry_t *entry, char *err, size_t errlen)
{
    static const char *sql =
        "INSERT INTO audit_log (occurred_at, event, outcome, actor_user_id, target_user_id, "
        "source_ip, request_id, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare audit insert: %s", sqlite3_errmsg(conn));
        return false;
    }

    (void)sqlite3_bind_int64(stmt, 1, entry->occurred_at);
    (void)sqlite3_bind_text(stmt, 2, entry->event, -1, SQLITE_STATIC);
    (void)sqlite3_bind_text(stmt, 3, entry->outcome, -1, SQLITE_STATIC);

    if (entry->has_actor_user_id) {
        (void)sqlite3_bind_int64(stmt, 4, entry->actor_user_id);
    } else {
        (void)sqlite3_bind_null(stmt, 4);
    }
    if (entry->has_target_user_id) {
        (void)sqlite3_bind_int64(stmt, 5, entry->target_user_id);
    } else {
        (void)sqlite3_bind_null(stmt, 5);
    }
    if (entry->has_source_ip) {
        (void)sqlite3_bind_text(stmt, 6, entry->source_ip, -1, SQLITE_STATIC);
    } else {
        (void)sqlite3_bind_null(stmt, 6);
    }
    if (entry->has_request_id) {
        (void)sqlite3_bind_text(stmt, 7, entry->request_id, -1, SQLITE_STATIC);
    } else {
        (void)sqlite3_bind_null(stmt, 7);
    }
    if (entry->has_detail) {
        (void)sqlite3_bind_text(stmt, 8, entry->detail, -1, SQLITE_STATIC);
    } else {
        (void)sqlite3_bind_null(stmt, 8);
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "insert audit_log: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

static void populate_entry(sqlite3_stmt *stmt, ps_audit_entry_t *out)
{
    out->id          = sqlite3_column_int64(stmt, 0);
    out->occurred_at = sqlite3_column_int64(stmt, 1);
    (void)snprintf(out->event, sizeof out->event, "%s", (const char *)sqlite3_column_text(stmt, 2));
    (void)snprintf(out->outcome, sizeof out->outcome, "%s",
                   (const char *)sqlite3_column_text(stmt, 3));

    out->has_actor_user_id = sqlite3_column_type(stmt, 4) != SQLITE_NULL;
    out->actor_user_id     = out->has_actor_user_id ? sqlite3_column_int64(stmt, 4) : 0;
    out->has_target_user_id = sqlite3_column_type(stmt, 5) != SQLITE_NULL;
    out->target_user_id     = out->has_target_user_id ? sqlite3_column_int64(stmt, 5) : 0;

    out->has_source_ip = sqlite3_column_type(stmt, 6) != SQLITE_NULL;
    if (out->has_source_ip) {
        (void)snprintf(out->source_ip, sizeof out->source_ip, "%s",
                       (const char *)sqlite3_column_text(stmt, 6));
    } else {
        out->source_ip[0] = '\0';
    }
    out->has_request_id = sqlite3_column_type(stmt, 7) != SQLITE_NULL;
    if (out->has_request_id) {
        (void)snprintf(out->request_id, sizeof out->request_id, "%s",
                       (const char *)sqlite3_column_text(stmt, 7));
    } else {
        out->request_id[0] = '\0';
    }
    out->has_detail = sqlite3_column_type(stmt, 8) != SQLITE_NULL;
    if (out->has_detail) {
        (void)snprintf(out->detail, sizeof out->detail, "%s",
                       (const char *)sqlite3_column_text(stmt, 8));
    } else {
        out->detail[0] = '\0';
    }
}

bool ps_audit_store_get_by_id(sqlite3 *conn, int64_t id, ps_audit_entry_t *out)
{
    static const char *sql =
        "SELECT id, occurred_at, event, outcome, actor_user_id, target_user_id, source_ip, "
        "request_id, detail FROM audit_log WHERE id = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_int64(stmt, 1, id);
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    if (found) {
        populate_entry(stmt, out);
    }
    sqlite3_finalize(stmt);
    return found;
}

bool ps_audit_store_count_by_event(sqlite3 *conn, const char *event, int64_t *out_count)
{
    static const char *sql = "SELECT COUNT(*) FROM audit_log WHERE event = ?";
    sqlite3_stmt       *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    (void)sqlite3_bind_text(stmt, 1, event, -1, SQLITE_STATIC);
    bool ok = sqlite3_step(stmt) == SQLITE_ROW;
    if (ok) {
        *out_count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return ok;
}
