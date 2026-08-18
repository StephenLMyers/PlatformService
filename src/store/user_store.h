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

#endif /* PS_STORE_USER_STORE_H */
