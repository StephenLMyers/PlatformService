/*
 * First-admin seeding (plan 6.7, D11). Registration can never grant
 * ADMIN, so a fresh database would otherwise contain no administrator and
 * the admin endpoints would be permanently unreachable.
 */
#ifndef PS_AUTH_BOOTSTRAP_H
#define PS_AUTH_BOOTSTRAP_H

#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#include "auth/password.h"
#include "platform/config.h"

typedef enum {
    PS_BOOTSTRAP_OK = 0,             /* an admin already existed, or one was just created */
    PS_BOOTSTRAP_MISSING_CREDENTIALS,
    PS_BOOTSTRAP_WEAK_PASSWORD,
    PS_BOOTSTRAP_ERROR,
} ps_bootstrap_result_t;

/*
 * Idempotent: does nothing (besides logging) if any user already holds
 * ADMIN. Otherwise reads cfg->bootstrap_admin_{username,email,password},
 * validates and hashes the password, and creates the account ACTIVE with
 * both USER and ADMIN (plan 6.4's flat model -- ADMIN never implies
 * USER). cfg->bootstrap_admin_password is OPENSSL_cleanse'd before this
 * returns, on every path, success or failure, so the plaintext credential
 * doesn't sit in memory for the rest of the process lifetime.
 *
 * Runs the user-row creation, its role grants, and its
 * BOOTSTRAP_ADMIN_CREATED audit row in one transaction (plan 6.10) via
 * ps_user_store_insert's SAVEPOINT-based composability.
 */
ps_bootstrap_result_t ps_bootstrap_admin(sqlite3 *conn, ps_config_t *cfg, int kdf_iterations,
                                         const ps_password_denylist_t *denylist,
                                         int64_t now, char *err, size_t errlen);

#endif /* PS_AUTH_BOOTSTRAP_H */
