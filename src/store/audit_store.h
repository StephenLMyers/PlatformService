/*
 * Append-only security audit trail (plan 6.10). Distinct from application
 * logging: different purpose, different retention, different consumer.
 * Deliberately has no update/delete entry point -- the only code allowed to
 * remove a row is the maintenance sweep's retention pass (plan 3.4), and
 * that goes through raw SQL there, not through this module, so this file
 * itself never contains an UPDATE or DELETE against audit_log.
 *
 * ps_audit_store_write issues a single INSERT and nothing else -- no BEGIN,
 * no COMMIT -- so a caller changing account state can include the audit
 * row in its own transaction (plan 6.10: "the audit write for a state
 * change shares the transaction with the change itself"), while a
 * best-effort read-event caller can call it standalone.
 */
#ifndef PS_STORE_AUDIT_STORE_H
#define PS_STORE_AUDIT_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#define PS_AUDIT_EVENT_MAX      32
#define PS_AUDIT_OUTCOME_MAX    8 /* "SUCCESS" or "FAILURE" */
#define PS_AUDIT_IP_MAX         46 /* IPv6 text form, longest case, + NUL */
#define PS_AUDIT_REQUEST_ID_MAX 64
#define PS_AUDIT_DETAIL_MAX     512 /* a small JSON object (plan 6.10), never secrets */

typedef struct {
    int64_t id; /* ignored on write (SQLite assigns it); populated on read */
    int64_t occurred_at;
    char    event[PS_AUDIT_EVENT_MAX];
    char    outcome[PS_AUDIT_OUTCOME_MAX];

    bool    has_actor_user_id;
    int64_t actor_user_id;
    bool    has_target_user_id;
    int64_t target_user_id;

    bool has_source_ip;
    char source_ip[PS_AUDIT_IP_MAX];
    bool has_request_id;
    char request_id[PS_AUDIT_REQUEST_ID_MAX];
    bool has_detail;
    char detail[PS_AUDIT_DETAIL_MAX];
} ps_audit_entry_t;

bool ps_audit_store_write(sqlite3 *conn, const ps_audit_entry_t *entry, char *err, size_t errlen);

/* For tests and any future admin audit-read endpoint. Returns false (out
 * untouched) if no row with that id exists. */
bool ps_audit_store_get_by_id(sqlite3 *conn, int64_t id, ps_audit_entry_t *out);

/* Count of rows for a given event name -- the shape most tests need
 * ("did writing X produce exactly one REGISTER row"), without building a
 * full query API ahead of a real caller needing one. */
bool ps_audit_store_count_by_event(sqlite3 *conn, const char *event, int64_t *out_count);

#endif /* PS_STORE_AUDIT_STORE_H */
