/*
 * v1 delivery: writes to dev_outbox (plan D8, 6.6). Never SMTP, never an
 * outbound connection of any kind.
 */
#include "mail/mailer.h"

#include <stdio.h>

bool ps_mailer_send(sqlite3 *conn, const ps_mail_message_t *msg, int64_t now,
                    char *err, size_t errlen)
{
    static const char *sql =
        "INSERT INTO dev_outbox (to_email, subject, body, created_at) VALUES (?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare outbox insert: %s", sqlite3_errmsg(conn));
        return false;
    }
    (void)sqlite3_bind_text(stmt, 1, msg->to_email, -1, SQLITE_STATIC);
    (void)sqlite3_bind_text(stmt, 2, msg->subject, -1, SQLITE_STATIC);
    (void)sqlite3_bind_text(stmt, 3, msg->body, -1, SQLITE_STATIC);
    (void)sqlite3_bind_int64(stmt, 4, now);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)snprintf(err, errlen, "insert dev_outbox: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}
