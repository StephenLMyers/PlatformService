/*
 * User row access (plan 5). Deliberately independent of auth/ -- store/ and
 * auth/ are peers in the domain-services layer (plan 3.1), and auth/
 * already depends on store/ (registration needs to insert a row), so
 * store/ never depends back on auth/ to avoid a cycle between them. Roles
 * are passed and returned as name strings for the same reason: no shared
 * bitmask type with auth/claims.h.
 */
#ifndef PS_STORE_USER_STORE_H
#define PS_STORE_USER_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#define PS_USERNAME_MAX 33  /* 32 chars + NUL (plan 7.6) */
#define PS_EMAIL_MAX    255 /* 254 chars + NUL (plan 7.6) */

typedef enum {
    PS_USER_STATUS_PENDING_VERIFICATION,
    PS_USER_STATUS_ACTIVE,
    PS_USER_STATUS_DISABLED,
} ps_user_status_t;

typedef struct {
    int64_t          user_id;
    char             username[PS_USERNAME_MAX];
    char             email[PS_EMAIL_MAX];
    char             email_normalized[PS_EMAIL_MAX];
    unsigned char    password_hash[32];
    unsigned char    password_salt[16];
    int              kdf_iters;
    ps_user_status_t status;
    int              failed_logins;
    int64_t          locked_until; /* 0 means SQL NULL / not locked */
    int64_t          created_at;
    int64_t          updated_at;
} ps_user_row_t;

const char *ps_user_status_to_string(ps_user_status_t status);
/* Returns false for any string other than the three canonical values --
 * fail closed rather than default to some particular status. */
bool ps_user_status_from_string(const char *s, ps_user_status_t *out);

typedef enum {
    PS_USER_INSERT_OK,
    PS_USER_INSERT_DUPLICATE_USERNAME,
    PS_USER_INSERT_DUPLICATE_EMAIL,
    PS_USER_INSERT_ERROR,
} ps_user_insert_result_t;

/*
 * Inserts a new user row and its role assignments (role_names, e.g.
 * {"USER"}) in one transaction -- a partially-created user with no roles
 * is not a state this function will ever leave behind. created_at and
 * updated_at are both set to now. Returns the new user_id via *out_user_id
 * on PS_USER_INSERT_OK; distinguishes which uniqueness constraint failed
 * so a caller can map it to the right error, without needing to parse a
 * SQLite error string.
 */
ps_user_insert_result_t ps_user_store_insert(sqlite3 *conn, const ps_user_row_t *row,
                                             const char *const *role_names, size_t role_count,
                                             int64_t now, int64_t *out_user_id,
                                             char *err, size_t errlen);

/* Every lookup below returns false (row left untouched) if no matching row
 * exists -- absence is not an error, callers decide what that means. */
bool ps_user_store_get_by_id(sqlite3 *conn, int64_t user_id, ps_user_row_t *out);
bool ps_user_store_get_by_username(sqlite3 *conn, const char *username, ps_user_row_t *out);
bool ps_user_store_get_by_email_normalized(sqlite3 *conn, const char *email_normalized,
                                           ps_user_row_t *out);

/*
 * Writes role names into out[0..*out_count) (capped at cap entries) in no
 * particular order. Returns false only on a query failure, not on a user
 * holding zero roles.
 */
bool ps_user_store_get_roles(sqlite3 *conn, int64_t user_id, char out[][32], size_t cap,
                             size_t *out_count);

/* Sets status and updated_at = now. No SAVEPOINT of its own (a single
 * UPDATE is already atomic); composes into a caller-managed transaction
 * the same way store/audit_store.c's writer does. Returns false only on a
 * query failure, not on user_id not existing (sqlite3_changes() would be
 * 0 in that case, which callers of this specific function are not
 * expected to need to distinguish -- verify already looked the row up by
 * its token before ever reaching this call). */
bool ps_user_store_update_status(sqlite3 *conn, int64_t user_id, ps_user_status_t status,
                                 int64_t now, char *err, size_t errlen);

/*
 * Sets failed_logins and locked_until (0 = clear to SQL NULL) and
 * updated_at = now -- the one write both sides of login's outcome need
 * (plan 6.9): a failed attempt on a found, not-already-locked account
 * passes the incremented count and a nonzero locked_until only once the
 * configured threshold is reached; any successful login passes (0, 0) to
 * reset the counter unconditionally. Same no-SAVEPOINT-of-its-own,
 * composes-into-a-caller-transaction shape as ps_user_store_update_status.
 */
bool ps_user_store_set_login_failure_state(sqlite3 *conn, int64_t user_id, int failed_logins,
                                           int64_t locked_until, int64_t now,
                                           char *err, size_t errlen);

/* Rehashes at plan 4.7's "current kdf_iters" -- password_hash/salt/kdf_iters
 * and updated_at all move together, atomically, so a row is never left with
 * a hash from one iteration count and kdf_iters recording a different one. */
bool ps_user_store_set_password(sqlite3 *conn, int64_t user_id,
                                const unsigned char password_hash[32],
                                const unsigned char password_salt[16], int kdf_iters,
                                int64_t now, char *err, size_t errlen);

/* plan 4.10's hard cap: limit is capped at 1000 regardless of what a
 * caller asks for, so a fixed-size buffer of exactly this many rows is
 * always enough -- no VLA, no heap allocation needed for a batch page. */
#define PS_USER_LIST_MAX 1000

/* The two fields plan 4.10's batch listing ever discloses -- deliberately
 * not a full ps_user_row_t (which also carries the password hash/salt,
 * email, etc.): a 1000-row page of full rows would needlessly triple or
 * quadruple the memory a batch response actually needs (plan 8.5's ceiling
 * on peak VmHWM during a 1000-row response). */
typedef struct {
    int64_t user_id;
    char    username[PS_USERNAME_MAX];
} ps_user_brief_row_t;

/* Plan 4.9: a bare count, no filtering -- every user regardless of status. */
bool ps_user_store_count(sqlite3 *conn, int64_t *out_count);

/*
 * Plan 4.10's exact keyset (seek) pagination query:
 *   SELECT user_id, username FROM users WHERE user_id > ? ORDER BY user_id ASC LIMIT ?
 * Never OFFSET -- keyset pagination stays O(limit) per page regardless of
 * how deep into the table after_id points, where OFFSET would rescan and
 * discard every row before it on every single page.
 *
 * Writes up to cap rows into out (ascending by user_id); limit itself is
 * the caller's already-validated, already-clamped-to-<=cap page size, not
 * re-clamped here. *out_count receives how many rows were actually
 * written -- fewer than limit means this was the last page. Returns false
 * only on a query failure.
 */
bool ps_user_store_list_after(sqlite3 *conn, int64_t after_id, int limit,
                              ps_user_brief_row_t out[PS_USER_LIST_MAX], size_t *out_count);

#endif /* PS_STORE_USER_STORE_H */
