#include "auth/bootstrap.h"

#include <string.h>

#include <openssl/crypto.h>

#include "auth/validate.h"
#include "platform/log.h"
#include "store/audit_store.h"
#include "store/user_store.h"

static bool count_admins(sqlite3 *conn, int64_t *out_count, char *err, size_t errlen)
{
    static const char *sql =
        "SELECT COUNT(*) FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id "
        "WHERE r.name = 'ADMIN'";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        (void)snprintf(err, errlen, "prepare admin count: %s", sqlite3_errmsg(conn));
        return false;
    }
    bool ok = sqlite3_step(stmt) == SQLITE_ROW;
    if (ok) {
        *out_count = sqlite3_column_int64(stmt, 0);
    } else {
        (void)snprintf(err, errlen, "admin count: %s", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return ok;
}

ps_bootstrap_result_t ps_bootstrap_admin(sqlite3 *conn, ps_config_t *cfg, int kdf_iterations,
                                         const ps_password_denylist_t *denylist,
                                         int64_t now, char *err, size_t errlen)
{
    int64_t admin_count = 0;
    if (!count_admins(conn, &admin_count, err, errlen)) {
        return PS_BOOTSTRAP_ERROR;
    }
    if (admin_count > 0) {
        PS_INFO("admin present");
        return PS_BOOTSTRAP_OK;
    }

    if (cfg->bootstrap_admin_username[0] == '\0' || cfg->bootstrap_admin_email[0] == '\0' ||
        cfg->bootstrap_admin_password[0] == '\0') {
        (void)snprintf(err, errlen,
                       "no administrator exists and BOOTSTRAP_ADMIN_USERNAME, "
                       "BOOTSTRAP_ADMIN_EMAIL, and BOOTSTRAP_ADMIN_PASSWORD are not all set");
        return PS_BOOTSTRAP_MISSING_CREDENTIALS;
    }

    /* check_reserved=false: this is the one account "admin" is the right
     * name for, and its credentials come from the trusted server
     * environment, not an anonymous request (plan 6.7). */
    char                          username[PS_USERNAME_MAX];
    ps_username_validate_result_t uname_result =
        ps_username_validate(cfg->bootstrap_admin_username, username, sizeof username, false);
    if (uname_result != PS_USERNAME_VALID) {
        (void)snprintf(err, errlen, "BOOTSTRAP_ADMIN_USERNAME is invalid (code %d)", uname_result);
        OPENSSL_cleanse(cfg->bootstrap_admin_password, sizeof cfg->bootstrap_admin_password);
        return PS_BOOTSTRAP_MISSING_CREDENTIALS;
    }

    char                        email_normalized[PS_EMAIL_MAX];
    ps_email_validate_result_t email_result = ps_email_validate(
        cfg->bootstrap_admin_email, email_normalized, sizeof email_normalized);
    if (email_result != PS_EMAIL_VALID) {
        (void)snprintf(err, errlen, "BOOTSTRAP_ADMIN_EMAIL is invalid (code %d)", email_result);
        OPENSSL_cleanse(cfg->bootstrap_admin_password, sizeof cfg->bootstrap_admin_password);
        return PS_BOOTSTRAP_MISSING_CREDENTIALS;
    }

    size_t password_len = strlen(cfg->bootstrap_admin_password);
    ps_password_policy_result_t policy = ps_password_policy_check(
        cfg->bootstrap_admin_password, password_len, cfg->password_min_length,
        cfg->password_max_length, denylist);
    if (policy != PS_PASSWORD_POLICY_OK) {
        (void)snprintf(err, errlen, "BOOTSTRAP_ADMIN_PASSWORD fails password policy (code %d)",
                       policy);
        OPENSSL_cleanse(cfg->bootstrap_admin_password, sizeof cfg->bootstrap_admin_password);
        return PS_BOOTSTRAP_WEAK_PASSWORD;
    }

    ps_password_hash_t hash;
    bool hashed =
        ps_password_hash(cfg->bootstrap_admin_password, password_len, kdf_iterations, &hash);
    OPENSSL_cleanse(cfg->bootstrap_admin_password, sizeof cfg->bootstrap_admin_password);
    if (!hashed) {
        (void)snprintf(err, errlen, "failed to hash bootstrap admin password");
        return PS_BOOTSTRAP_ERROR;
    }

    ps_user_row_t row;
    memset(&row, 0, sizeof row);
    (void)snprintf(row.username, sizeof row.username, "%s", username);
    (void)snprintf(row.email, sizeof row.email, "%s", email_normalized);
    (void)snprintf(row.email_normalized, sizeof row.email_normalized, "%s", email_normalized);
    memcpy(row.password_hash, hash.hash, sizeof row.password_hash);
    memcpy(row.password_salt, hash.salt, sizeof row.password_salt);
    row.kdf_iters       = hash.iterations;
    row.status          = PS_USER_STATUS_ACTIVE; /* bypasses verification -- plan 6.7 */
    row.failed_logins   = 0;
    row.locked_until    = 0;

    char *errmsg = NULL;
    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        (void)snprintf(err, errlen, "BEGIN: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        return PS_BOOTSTRAP_ERROR;
    }

    const char *roles[] = { "USER", "ADMIN" }; /* both explicit -- plan 6.4's flat model */
    int64_t     user_id = 0;
    ps_user_insert_result_t insert_result =
        ps_user_store_insert(conn, &row, roles, 2, now, &user_id, err, errlen);
    if (insert_result != PS_USER_INSERT_OK) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        return PS_BOOTSTRAP_ERROR;
    }

    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at = now;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "BOOTSTRAP_ADMIN_CREATED");
    (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "SUCCESS");
    audit_entry.has_target_user_id = true;
    audit_entry.target_user_id     = user_id;
    if (!ps_audit_store_write(conn, &audit_entry, err, errlen)) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        return PS_BOOTSTRAP_ERROR;
    }

    if (sqlite3_exec(conn, "COMMIT;", NULL, NULL, &errmsg) != SQLITE_OK) {
        (void)snprintf(err, errlen, "COMMIT: %s", errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        return PS_BOOTSTRAP_ERROR;
    }

    PS_INFO("bootstrap admin created: %s", username);
    return PS_BOOTSTRAP_OK;
}
