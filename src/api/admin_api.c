#include "api/admin_api.h"

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

static bool obj_set_num(ps_json_value_t *obj, const char *key, double val)
{
    ps_json_value_t *v = ps_json_new_number(val);
    if (v == NULL || !ps_json_object_set(obj, key, v)) {
        ps_json_free(v);
        return false;
    }
    return true;
}

static bool obj_set_bool(ps_json_value_t *obj, const char *key, bool val)
{
    ps_json_value_t *v = ps_json_new_bool(val);
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

/*
 * query is the raw "a=1&b=2" bytes past '?' -- never percent-decoded,
 * matching http/request.h's own reasoning for path segments: the only
 * values this endpoint ever reads are plain decimal integers, which are
 * never legitimately percent-encoded. Returns false if key is absent; a
 * duplicated key resolves to its first occurrence -- after_id/limit are
 * pagination cursors an already-ADMIN caller fully controls, not an
 * identity boundary the way {userId} is (plan 8.4), so there is no
 * ambiguity here worth rejecting over.
 */
static bool query_param_get(const char *query, size_t query_len, const char *key,
                            const char **out_value, size_t *out_value_len)
{
    size_t key_len = strlen(key);
    size_t i       = 0;
    while (i < query_len) {
        size_t pair_end = i;
        while (pair_end < query_len && query[pair_end] != '&') {
            pair_end++;
        }
        size_t eq = i;
        while (eq < pair_end && query[eq] != '=') {
            eq++;
        }
        size_t this_key_len = eq - i;
        if (this_key_len == key_len && memcmp(query + i, key, key_len) == 0) {
            if (eq < pair_end) {
                *out_value     = query + eq + 1;
                *out_value_len = pair_end - eq - 1;
            } else {
                *out_value     = query + eq;
                *out_value_len = 0;
            }
            return true;
        }
        i = pair_end + 1;
    }
    return false;
}

/* ---- GET /v1/admin/users/count ---- */

ps_handler_result_t ps_admin_handle_count_users(const ps_http_request_t *req,
                                                const ps_route_params_t *params,
                                                const char *peer_addr,
                                                const ps_jwt_claims_t *claims,
                                                const ps_app_ctx_t *app_ctx)
{
    (void)req;
    (void)params;
    (void)peer_addr;
    (void)claims;

    sqlite3 *conn  = ps_db_pool_acquire(app_ctx->db_pool);
    int64_t  count = 0;
    bool     ok    = ps_user_store_count(conn, &count);
    ps_db_pool_release(app_ctx->db_pool, conn);
    if (!ok) {
        ps_handler_result_t r = { .status = 500, .body = NULL, .no_store = true };
        return r;
    }

    /* count is an aggregate statistic, not a userId -- safe as a bare
     * JSON number regardless of table size (a user count anywhere near
     * 2^53 is not a realistic scenario this service needs to plan for). */
    ps_json_value_t *body = ps_json_new_object();
    ok                    = body != NULL && obj_set_num(body, "count", (double)count);
    if (!ok) {
        ps_json_free(body);
        ps_handler_result_t r = { .status = 500, .body = NULL, .no_store = true };
        return r;
    }
    ps_handler_result_t r = { .status = 200, .body = body, .no_store = true };
    return r;
}

/* ---- GET /v1/admin/users?after_id={n}&limit={n} ---- */

ps_handler_result_t ps_admin_handle_list_users(const ps_http_request_t *req,
                                               const ps_route_params_t *params,
                                               const char *peer_addr,
                                               const ps_jwt_claims_t *claims,
                                               const ps_app_ctx_t *app_ctx)
{
    (void)params;

    const char *value     = NULL;
    size_t      value_len = 0;

    int64_t after_id = 0; /* absent -> start from the beginning */
    if (req->query != NULL &&
        query_param_get(req->query, req->query_len, "after_id", &value, &value_len)) {
        if (!ps_parse_int64(value, value_len, &after_id)) {
            ps_handler_result_t r = { .status = 400,
                                      .body = ps_error_envelope("BAD_REQUEST", "after_id is invalid"),
                                      .no_store = true };
            return r;
        }
    }

    /* plan 4.10: limit defaults to and is capped at 1000. limit <= 0 is
     * rejected as malformed, not treated as "use the default" or "return
     * nothing" -- a positive page size is a precondition for pagination
     * to make forward progress at all (discussed with the user). */
    int64_t limit_parsed = PS_USER_LIST_MAX;
    if (req->query != NULL &&
        query_param_get(req->query, req->query_len, "limit", &value, &value_len)) {
        if (!ps_parse_int64(value, value_len, &limit_parsed)) {
            ps_handler_result_t r = { .status = 400,
                                      .body = ps_error_envelope("BAD_REQUEST", "limit is invalid"),
                                      .no_store = true };
            return r;
        }
        if (limit_parsed <= 0) {
            ps_handler_result_t r = { .status = 400,
                                      .body = ps_error_envelope("BAD_REQUEST",
                                                                "limit must be positive"),
                                      .no_store = true };
            return r;
        }
    }
    int limit = limit_parsed > PS_USER_LIST_MAX ? PS_USER_LIST_MAX : (int)limit_parsed;

    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);

    ps_user_brief_row_t rows[PS_USER_LIST_MAX];
    size_t               row_count = 0;
    if (!ps_user_store_list_after(conn, after_id, limit, rows, &row_count)) {
        ps_db_pool_release(app_ctx->db_pool, conn);
        ps_handler_result_t r = { .status = 500, .body = NULL, .no_store = true };
        return r;
    }

    /* plan 6.10: ADMIN_USER_LIST, "includes the page range requested" --
     * best-effort, outside any transaction (a read event). */
    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at       = time(NULL);
    audit_entry.has_actor_user_id = true;
    audit_entry.actor_user_id     = claims->user_id;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "ADMIN_USER_LIST");
    (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "SUCCESS");
    audit_entry.has_detail = true;
    (void)snprintf(audit_entry.detail, sizeof audit_entry.detail,
                   "{\"after_id\":%" PRId64 ",\"limit\":%d}", after_id, limit);
    set_audit_source_ip(&audit_entry, peer_addr);
    char aerr[256];
    (void)ps_audit_store_write(conn, &audit_entry, aerr, sizeof aerr);

    ps_db_pool_release(app_ctx->db_pool, conn);

    ps_json_value_t *users    = ps_json_new_array();
    bool             build_ok = users != NULL;
    for (size_t i = 0; build_ok && i < row_count; i++) {
        char user_id_str[32];
        (void)snprintf(user_id_str, sizeof user_id_str, "%" PRId64, rows[i].user_id);
        ps_json_value_t *entry = ps_json_new_object();
        build_ok               = entry != NULL;
        build_ok               = build_ok && obj_set_str(entry, "userId", user_id_str);
        build_ok               = build_ok && obj_set_str(entry, "username", rows[i].username);
        build_ok               = build_ok && ps_json_array_append(users, entry);
        if (!build_ok) {
            ps_json_free(entry);
        }
    }

    /* plan 4.10's own example never shows the empty-page case; when
     * row_count is 0 (after_id already at or past the end -- plan 8.2:
     * "returns an empty list, not an error"), nextAfterId echoes the
     * after_id that was queried, so a client that blindly keeps using it
     * gets another empty, hasMore:false page rather than an undefined
     * cursor. */
    int64_t next_after_id = row_count > 0 ? rows[row_count - 1].user_id : after_id;
    char    next_after_id_str[32];
    (void)snprintf(next_after_id_str, sizeof next_after_id_str, "%" PRId64, next_after_id);

    ps_json_value_t *body = ps_json_new_object();
    build_ok              = build_ok && body != NULL;
    build_ok              = build_ok && ps_json_object_set(body, "users", users);
    if (!build_ok) {
        ps_json_free(users);
    }
    /* userId-shaped values as JSON strings throughout (json_parse.h's
     * documented convention -- see gotchas.md); count/hasMore are not
     * userId-shaped, so they stay a number/bool. */
    build_ok = build_ok && obj_set_num(body, "count", (double)row_count);
    build_ok = build_ok && obj_set_str(body, "nextAfterId", next_after_id_str);
    /* A full page (exactly `limit` rows) implies more might exist; a
     * short page proves there is nothing left. The one case this can't
     * distinguish -- the true last page happening to be exactly `limit`
     * rows -- costs one extra round trip that correctly comes back empty,
     * not an extra COUNT query on every page (the whole performance point
     * of keyset over OFFSET pagination). */
    build_ok = build_ok && obj_set_bool(body, "hasMore", (int64_t)row_count == limit);

    if (!build_ok) {
        ps_json_free(body);
        ps_handler_result_t r = { .status = 500, .body = NULL, .no_store = true };
        return r;
    }

    ps_handler_result_t r = { .status = 200, .body = body, .no_store = true };
    return r;
}
