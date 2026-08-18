/*
 * Delivery interface (plan 6.6). v1 has exactly one implementation
 * (mailer_outbox.c, writing to the dev_outbox table) and no mail
 * transport of any kind -- nothing sends SMTP, nothing connects outbound.
 * A real transport later means adding a new .c file behind this same
 * signature, not touching registration logic.
 *
 * No BEGIN/COMMIT of its own, matching store/audit_store.c's
 * ps_audit_store_write -- composes into a caller-managed transaction, or
 * stands alone for a best-effort send.
 */
#ifndef PS_MAIL_MAILER_H
#define PS_MAIL_MAILER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

typedef struct {
    const char *to_email;
    const char *subject;
    const char *body;
} ps_mail_message_t;

bool ps_mailer_send(sqlite3 *conn, const ps_mail_message_t *msg, int64_t now,
                    char *err, size_t errlen);

#endif /* PS_MAIL_MAILER_H */
