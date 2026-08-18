#include "api/user_api.h"

#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "http/response.h"
#include "json/json_parse.h"
#include "store/audit_store.h"
#include "store/user_store.h"

static bool obj_set_str(ps_json_value_t *obj, const char *key, const char *val)
{
    ps_json_value_t *v = ps_json_new_string(val);
    if (v == NULL || !ps_json_object_set(obj, key, v)) {
        ps_json_free(v);
        return false;
    }
    return true;
}

static void set_audit_source_ip(ps_audit_entry_t *entry, const char *peer_addr)
{
    if (peer_addr == NULL) {
        return;
    }
    entry->has_source_ip = true;
    (void)snprintf(entry->source_ip, sizeof entry->source_ip, "%s", peer_addr);
}

ps_handler_result_t ps_user_handle_get_user(const ps_http_request_t *req,
                                            const ps_route_params_t *params,
                                            const char *peer_addr,
                                            const ps_jwt_claims_t *claims,
                                            int64_t target_user_id,
                                            const ps_app_ctx_t *app_ctx)
{
    (void)req;
    (void)params;

    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);

    ps_user_row_t target;
    bool          found = ps_user_store_get_by_id(conn, target_user_id, &target);
    if (!found) {
        ps_db_pool_release(app_ctx->db_pool, conn);
        ps_handler_result_t r = { .status = 404,
                                  .body = ps_error_envelope("NOT_FOUND", "no such user"),
                                  .no_store = true };
        return r;
    }

    /* ps_rbac_check (api/routes.c's dispatch, before this handler ever
     * runs) already confirmed claims->user_id == target_user_id or the
     * caller holds ADMIN -- an admin reaching this branch is therefore
     * exactly the case plan 6.10 calls out for ADMIN_USER_READ: "when an
     * admin reads someone else's record, and not when a user reads their
     * own." Best-effort, outside any transaction (plan 6.10: read events
     * are best-effort). */
    bool is_self = claims->user_id == target_user_id;
    if (!is_self) {
        ps_audit_entry_t audit_entry;
        memset(&audit_entry, 0, sizeof audit_entry);
        audit_entry.occurred_at        = time(NULL);
        audit_entry.has_actor_user_id  = true;
        audit_entry.actor_user_id      = claims->user_id;
        audit_entry.has_target_user_id = true;
        audit_entry.target_user_id     = target_user_id;
        (void)snprintf(audit_entry.event, sizeof audit_entry.event, "ADMIN_USER_READ");
        (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "SUCCESS");
        set_audit_source_ip(&audit_entry, peer_addr);
        char aerr[256];
        (void)ps_audit_store_write(conn, &audit_entry, aerr, sizeof aerr);
    }

    ps_db_pool_release(app_ctx->db_pool, conn);

    /* userId as a JSON string, not a bare number, matching json_parse.h's
     * documented service-wide convention (a JSON number only round-trips
     * exactly through an IEEE 754 double, which loses precision above
     * 2^53 -- exactly the int64_t range D7 exists to support). Plan 4.8's
     * own illustrative example shows a bare number; that snippet predates
     * this convention and was never updated, so this follows the
     * documented, already-implemented rule (see the JWT sub claim)
     * instead of the stale example. */
    char user_id_str[32];
    (void)snprintf(user_id_str, sizeof user_id_str, "%" PRId64, target.user_id);

    ps_json_value_t *body = ps_json_new_object();
    bool             ok   = body != NULL;
    ok = ok && obj_set_str(body, "userId", user_id_str);
    ok = ok && obj_set_str(body, "username", target.username);
    /* plan 4.8: two views, not a conditional field -- email is present at
     * all only when the subject is asking, never null/empty for anyone
     * else. */
    if (ok && is_self) {
        ok = obj_set_str(body, "email", target.email);
    }
    if (!ok) {
        ps_json_free(body);
        ps_handler_result_t r = { .status = 500, .body = NULL, .no_store = true };
        return r;
    }

    ps_handler_result_t r = { .status = 200, .body = body, .no_store = true };
    return r;
}
