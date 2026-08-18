#include "api/auth_api.h"

#include <string.h>
#include <time.h>

#include "auth/password.h"
#include "auth/validate.h"
#include "crypto/base64url.h"
#include "crypto/kdf_semaphore.h"
#include "crypto/rand.h"
#include "crypto/sha256.h"
#include "http/response.h"
#include "json/json_write.h"
#include "mail/mailer.h"
#include "platform/buf.h"
#include "platform/log.h"
#include "store/audit_store.h"
#include "store/token_store.h"
#include "store/user_store.h"

#define PS_RAW_FIELD_MAX 512
#define PS_TOKEN_RAW_LEN 32 /* 256-bit CSPRNG (plan 6.6) */

/* ---- small shared helpers ---- */

static ps_handler_result_t error_result(int status, const char *code, const char *message)
{
    ps_handler_result_t r = { .status = status, .body = ps_error_envelope(code, message),
                              .no_store = true };
    return r;
}

/* plan 7.5: a 500 body carries no detail at all (a correlation ID would go
 * here once the log/response layers share one; the request itself is
 * already in the server log via platform/log.c) -- matches
 * api/routes.c's own unreachable-route 500 case exactly. */
static ps_handler_result_t internal_error_result(void)
{
    ps_handler_result_t r = { .status = 500, .body = NULL, .no_store = true };
    return r;
}

/* Trims leading/trailing spaces/tabs only, preserving case -- for the
 * "email" display column (plan 5: "as supplied"), which still must not
 * carry whatever padding a client sent, unlike email_normalized (trim +
 * lowercase) that ps_email_validate already produces. Bounded to out_size
 * exactly like ps_email_validate's own trim, so a value that already
 * passed validation (<=254 chars trimmed) can never overflow a
 * PS_EMAIL_MAX-sized destination here regardless of how much surrounding
 * whitespace the original raw field carried. */
static void trim_into(const char *raw, char *out, size_t out_size)
{
    const char *start = raw;
    while (*start == ' ' || *start == '\t') {
        start++;
    }
    const char *end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }
    size_t len = (size_t)(end - start);
    size_t n   = len < out_size - 1 ? len : out_size - 1;
    memcpy(out, start, n);
    out[n] = '\0';
}

static bool obj_set_str(ps_json_value_t *obj, const char *key, const char *val)
{
    ps_json_value_t *v = ps_json_new_string(val);
    if (v == NULL || !ps_json_object_set(obj, key, v)) {
        ps_json_free(v);
        return false;
    }
    return true;
}

static bool read_string_field(const ps_json_value_t *obj, const char *key, char *out,
                              size_t out_size)
{
    ps_json_value_t *v = ps_json_object_get(obj, key);
    if (v == NULL || ps_json_type(v) != PS_JSON_STRING) {
        return false;
    }
    size_t len = ps_json_get_string_len(v);
    if (len >= out_size) {
        return false;
    }
    memcpy(out, ps_json_get_string(v), len);
    out[len] = '\0';
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

/* Generates a fresh CSPRNG token, hashes it, and inserts the hash --
 * caller supplies the transaction (or lack of one). out_raw_token is
 * needed by the caller afterward to actually send the email; the token
 * itself is never persisted, only its hash (plan 6.6). */
static bool insert_fresh_token(sqlite3 *conn, int64_t user_id, const ps_app_ctx_t *app_ctx,
                               int64_t now, unsigned char out_raw_token[PS_TOKEN_RAW_LEN],
                               char *err, size_t errlen)
{
    if (!ps_rand_bytes(out_raw_token, PS_TOKEN_RAW_LEN)) {
        (void)snprintf(err, errlen, "failed to generate verification token");
        return false;
    }
    unsigned char token_hash[PS_SHA256_LEN];
    if (!ps_sha256(out_raw_token, PS_TOKEN_RAW_LEN, token_hash)) {
        (void)snprintf(err, errlen, "failed to hash verification token");
        return false;
    }
    int64_t expires_at = now + app_ctx->config->verification_ttl_s;
    return ps_token_store_insert(conn, token_hash, user_id, expires_at, now, err, errlen);
}

/* Best-effort: a delivery failure here never fails the request (plan
 * 4.1/4.3's responses don't vary on mail delivery). Called after the
 * state-changing transaction has already committed -- conn is still
 * checked out from the pool but back in autocommit mode. */
static void send_verification_email(sqlite3 *conn, const unsigned char raw_token[PS_TOKEN_RAW_LEN],
                                    const char *to_email, const char *username,
                                    const ps_app_ctx_t *app_ctx, int64_t now)
{
    ps_buf_t token_buf;
    ps_buf_init(&token_buf);
    if (!ps_base64url_encode(raw_token, PS_TOKEN_RAW_LEN, &token_buf)) {
        ps_buf_free(&token_buf);
        PS_WARN("failed to encode verification token for %s", to_email);
        return;
    }
    char token_b64[64];
    (void)snprintf(token_b64, sizeof token_b64, "%.*s", (int)token_buf.len, token_buf.data);
    ps_buf_free(&token_buf);

    char body_text[512];
    (void)snprintf(body_text, sizeof body_text,
                   "Welcome! To activate your account, submit this verification token to "
                   "POST /v1/auth/verify:\n\n%s\n\nThis token expires in %d hours.",
                   token_b64, app_ctx->config->verification_ttl_s / 3600);

    ps_mail_message_t msg = { .to_email = to_email, .subject = "Verify your account",
                              .body = body_text };
    char mail_err[256];
    if (!ps_mailer_send(conn, &msg, now, mail_err, sizeof mail_err)) {
        PS_WARN("failed to send verification email: %s", mail_err);
    }

    /* plan 15.3 escape hatch 2: a human can read this straight from the
     * server log without ever touching the database. */
    if (app_ctx->config->dev_mode) {
        PS_INFO("verification token (dev_mode) for %s: %s", username, token_b64);
    }
}

static ps_json_value_t *pending_verification_body(void)
{
    ps_json_value_t *obj = ps_json_new_object();
    if (obj == NULL) {
        return NULL;
    }
    bool ok = obj_set_str(obj, "status", "PENDING_VERIFICATION");
    ok      = ok && obj_set_str(obj, "message",
                               "If this email address is not already registered, a "
                               "verification link has been sent.");
    if (!ok) {
        ps_json_free(obj);
        return NULL;
    }
    return obj;
}

/* Register hit a duplicate email: no new user is created (plan 4.1), but
 * the existing owner is told someone tried, and the attempt is still
 * audited -- distinct from the caller's response, which stays the
 * byte-identical 202 either way. */
static void notify_duplicate_registration(sqlite3 *conn, const char *email_normalized,
                                          const char *peer_addr, int64_t now)
{
    ps_user_row_t existing;
    bool          found = ps_user_store_get_by_email_normalized(conn, email_normalized, &existing);

    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at = now;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "REGISTER");
    (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "FAILURE");
    audit_entry.has_detail = true;
    (void)snprintf(audit_entry.detail, sizeof audit_entry.detail, "{\"reason\":\"duplicate_email\"}");
    if (found) {
        audit_entry.has_target_user_id = true;
        audit_entry.target_user_id     = existing.user_id;
    }
    set_audit_source_ip(&audit_entry, peer_addr);
    char aerr[256];
    (void)ps_audit_store_write(conn, &audit_entry, aerr, sizeof aerr);

    if (!found) {
        return;
    }
    char body_text[512];
    (void)snprintf(body_text, sizeof body_text,
                   "Someone attempted to register a new account using your email address "
                   "(%s). If this wasn't you, no action is needed -- your existing account "
                   "is unaffected.",
                   existing.email);
    ps_mail_message_t msg = { .to_email = existing.email,
                              .subject  = "Registration attempt using your email",
                              .body     = body_text };
    char mail_err[256];
    if (!ps_mailer_send(conn, &msg, now, mail_err, sizeof mail_err)) {
        PS_WARN("failed to send duplicate-registration notice: %s", mail_err);
    }
}

/* ---- POST /v1/auth/register ---- */

ps_handler_result_t ps_auth_handle_register(const ps_http_request_t *req,
                                            const ps_route_params_t *params,
                                            const char *peer_addr, const ps_app_ctx_t *app_ctx)
{
    (void)params;

    char              json_err[128];
    ps_json_value_t  *body = ps_json_parse(req->body, req->body_len, json_err, sizeof json_err);
    if (body == NULL || ps_json_type(body) != PS_JSON_OBJECT) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "request body must be a JSON object");
    }

    /* Exactly three fields read, from an explicit allowlist (plan 7.6) --
     * userId/roles/status/kdf_iters, if present in the body, are simply
     * never looked at. */
    char raw_username[PS_RAW_FIELD_MAX];
    char raw_email[PS_RAW_FIELD_MAX];
    if (!read_string_field(body, "username", raw_username, sizeof raw_username) ||
        !read_string_field(body, "email", raw_email, sizeof raw_email)) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "username and email are required string fields");
    }
    ps_json_value_t *password_field = ps_json_object_get(body, "password");
    if (password_field == NULL || ps_json_type(password_field) != PS_JSON_STRING) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "password is a required string field");
    }
    const char *password     = ps_json_get_string(password_field);
    size_t      password_len = ps_json_get_string_len(password_field);

    char username[PS_USERNAME_MAX];
    if (ps_username_validate(raw_username, username, sizeof username, true) != PS_USERNAME_VALID) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "username is invalid");
    }

    char email_normalized[PS_EMAIL_MAX];
    if (ps_email_validate(raw_email, email_normalized, sizeof email_normalized) != PS_EMAIL_VALID) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "email is invalid");
    }

    ps_password_policy_result_t policy = ps_password_policy_check(
        password, password_len, app_ctx->config->password_min_length,
        app_ctx->config->password_max_length, app_ctx->password_denylist);
    if (policy == PS_PASSWORD_POLICY_ERROR) {
        ps_json_free(body);
        return internal_error_result();
    }
    if (policy != PS_PASSWORD_POLICY_OK) {
        ps_json_free(body);
        return error_result(400, "WEAK_PASSWORD", "password does not meet the policy requirements");
    }

    if (!ps_kdf_semaphore_try_acquire(app_ctx->kdf_semaphore)) {
        ps_json_free(body);
        return error_result(503, "SERVICE_UNAVAILABLE",
                            "too many concurrent registrations; try again shortly");
    }
    ps_password_hash_t hash;
    bool                hashed = ps_password_hash(password, password_len,
                                                  app_ctx->config->kdf_iterations, &hash);
    ps_kdf_semaphore_release(app_ctx->kdf_semaphore);
    ps_json_free(body); /* every field needed has been copied out by now */
    if (!hashed) {
        return internal_error_result();
    }

    int64_t now = time(NULL);

    ps_user_row_t row;
    memset(&row, 0, sizeof row);
    (void)snprintf(row.username, sizeof row.username, "%s", username);
    trim_into(raw_email, row.email, sizeof row.email); /* as supplied, trimmed -- plan 5 */
    (void)snprintf(row.email_normalized, sizeof row.email_normalized, "%s", email_normalized);
    memcpy(row.password_hash, hash.hash, sizeof row.password_hash);
    memcpy(row.password_salt, hash.salt, sizeof row.password_salt);
    row.kdf_iters = hash.iterations;
    row.status    = PS_USER_STATUS_PENDING_VERIFICATION;

    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);
    char     db_err[256];
    char    *errmsg = NULL;

    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    const char *roles[]  = { "USER" };
    int64_t     user_id  = 0;
    ps_user_insert_result_t insert_result =
        ps_user_store_insert(conn, &row, roles, 1, now, &user_id, db_err, sizeof db_err);

    if (insert_result == PS_USER_INSERT_DUPLICATE_USERNAME) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return error_result(409, "CONFLICT", "username is already taken");
    }
    if (insert_result == PS_USER_INSERT_DUPLICATE_EMAIL) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        notify_duplicate_registration(conn, email_normalized, peer_addr, now);
        ps_db_pool_release(app_ctx->db_pool, conn);
        ps_handler_result_t r = { .status = 202, .body = pending_verification_body(),
                                  .no_store = true };
        return r;
    }
    if (insert_result != PS_USER_INSERT_OK) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    unsigned char raw_token[PS_TOKEN_RAW_LEN];
    if (!insert_fresh_token(conn, user_id, app_ctx, now, raw_token, db_err, sizeof db_err)) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at = now;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "REGISTER");
    (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "SUCCESS");
    audit_entry.has_target_user_id = true;
    audit_entry.target_user_id     = user_id;
    set_audit_source_ip(&audit_entry, peer_addr);
    if (!ps_audit_store_write(conn, &audit_entry, db_err, sizeof db_err)) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    if (sqlite3_exec(conn, "COMMIT;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    send_verification_email(conn, raw_token, row.email, row.username, app_ctx, now);
    ps_db_pool_release(app_ctx->db_pool, conn);

    ps_handler_result_t r = { .status = 202, .body = pending_verification_body(), .no_store = true };
    return r;
}

/* ---- POST /v1/auth/verify ---- */

ps_handler_result_t ps_auth_handle_verify(const ps_http_request_t *req,
                                          const ps_route_params_t *params,
                                          const char *peer_addr, const ps_app_ctx_t *app_ctx)
{
    (void)params;

    char             json_err[128];
    ps_json_value_t *body = ps_json_parse(req->body, req->body_len, json_err, sizeof json_err);
    if (body == NULL || ps_json_type(body) != PS_JSON_OBJECT) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "request body must be a JSON object");
    }
    char raw_token_b64[128];
    if (!read_string_field(body, "token", raw_token_b64, sizeof raw_token_b64)) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "token is a required string field");
    }
    ps_json_free(body);

    ps_buf_t decoded;
    ps_buf_init(&decoded);
    bool decode_ok = ps_base64url_decode(raw_token_b64, strlen(raw_token_b64), &decoded);
    bool right_len = decode_ok && decoded.len == PS_TOKEN_RAW_LEN;

    unsigned char token_hash[PS_SHA256_LEN];
    if (right_len) {
        (void)ps_sha256(decoded.data, decoded.len, token_hash);
    }
    ps_buf_free(&decoded);
    if (!right_len) {
        /* Same 400 INVALID_TOKEN as a token that decodes fine but doesn't
         * exist -- a malformed submission is not distinguished from an
         * absent one (plan 4.2). */
        return error_result(400, "INVALID_TOKEN", "invalid or expired verification token");
    }

    int64_t  now  = time(NULL);
    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);

    ps_verification_token_row_t token_row;
    bool found = ps_token_store_get_by_hash(conn, token_hash, &token_row);
    bool usable = found && token_row.consumed_at == 0 && token_row.expires_at >= now;

    if (!usable) {
        ps_audit_entry_t audit_entry;
        memset(&audit_entry, 0, sizeof audit_entry);
        audit_entry.occurred_at = now;
        (void)snprintf(audit_entry.event, sizeof audit_entry.event, "VERIFY");
        (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "FAILURE");
        if (found) {
            audit_entry.has_target_user_id = true;
            audit_entry.target_user_id     = token_row.user_id;
        }
        set_audit_source_ip(&audit_entry, peer_addr);
        char aerr[256];
        (void)ps_audit_store_write(conn, &audit_entry, aerr, sizeof aerr);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return error_result(400, "INVALID_TOKEN", "invalid or expired verification token");
    }

    char *errmsg = NULL;
    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    char db_err[256];
    bool ok = ps_token_store_consume(conn, token_hash, now, db_err, sizeof db_err);
    ok      = ok && ps_user_store_update_status(conn, token_row.user_id, PS_USER_STATUS_ACTIVE,
                                                now, db_err, sizeof db_err);

    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at        = now;
    audit_entry.has_target_user_id = true;
    audit_entry.target_user_id     = token_row.user_id;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "VERIFY");
    (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, ok ? "SUCCESS" : "FAILURE");
    set_audit_source_ip(&audit_entry, peer_addr);
    ok = ok && ps_audit_store_write(conn, &audit_entry, db_err, sizeof db_err);

    if (!ok) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }
    if (sqlite3_exec(conn, "COMMIT;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }
    ps_db_pool_release(app_ctx->db_pool, conn);

    ps_json_value_t *resp_body = ps_json_new_object();
    if (resp_body != NULL && !obj_set_str(resp_body, "status", "ACTIVE")) {
        ps_json_free(resp_body);
        resp_body = NULL;
    }
    ps_handler_result_t r = { .status = 200, .body = resp_body, .no_store = true };
    return r;
}

/* ---- POST /v1/auth/resend-verification ---- */

static ps_json_value_t *resend_response_body(void)
{
    ps_json_value_t *obj = ps_json_new_object();
    if (obj == NULL) {
        return NULL;
    }
    if (!obj_set_str(obj, "message",
                     "If this email address requires verification, a new link has been sent.")) {
        ps_json_free(obj);
        return NULL;
    }
    return obj;
}

static void audit_resend(sqlite3 *conn, int64_t now, const char *peer_addr, bool have_user_id,
                         int64_t user_id, const char *outcome, const char *reason)
{
    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at = now;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "RESEND_REQUESTED");
    (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "%s", outcome);
    if (have_user_id) {
        audit_entry.has_target_user_id = true;
        audit_entry.target_user_id     = user_id;
    }
    if (reason != NULL) {
        audit_entry.has_detail = true;
        (void)snprintf(audit_entry.detail, sizeof audit_entry.detail, "{\"reason\":\"%s\"}", reason);
    }
    set_audit_source_ip(&audit_entry, peer_addr);
    char aerr[256];
    (void)ps_audit_store_write(conn, &audit_entry, aerr, sizeof aerr);
}

ps_handler_result_t ps_auth_handle_resend_verification(const ps_http_request_t *req,
                                                        const ps_route_params_t *params,
                                                        const char *peer_addr,
                                                        const ps_app_ctx_t *app_ctx)
{
    (void)params;

    char             json_err[128];
    ps_json_value_t *body = ps_json_parse(req->body, req->body_len, json_err, sizeof json_err);
    if (body == NULL || ps_json_type(body) != PS_JSON_OBJECT) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "request body must be a JSON object");
    }
    char raw_email[PS_RAW_FIELD_MAX];
    if (!read_string_field(body, "email", raw_email, sizeof raw_email)) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "email is a required string field");
    }
    ps_json_free(body);

    char email_normalized[PS_EMAIL_MAX];
    if (ps_email_validate(raw_email, email_normalized, sizeof email_normalized) != PS_EMAIL_VALID) {
        return error_result(400, "BAD_REQUEST", "email is invalid");
    }

    int64_t  now  = time(NULL);
    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);

    ps_user_row_t user;
    bool found = ps_user_store_get_by_email_normalized(conn, email_normalized, &user);
    if (!found) {
        audit_resend(conn, now, peer_addr, false, 0, "FAILURE", "no_such_account");
        ps_db_pool_release(app_ctx->db_pool, conn);
        ps_handler_result_t r = { .status = 202, .body = resend_response_body(), .no_store = true };
        return r;
    }
    if (user.status != PS_USER_STATUS_PENDING_VERIFICATION) {
        audit_resend(conn, now, peer_addr, true, user.user_id, "FAILURE", "not_pending");
        ps_db_pool_release(app_ctx->db_pool, conn);
        ps_handler_result_t r = { .status = 202, .body = resend_response_body(), .no_store = true };
        return r;
    }

    /* Per-email throttle, DB-backed (plan 4.3): 1 per 60s, 5 per 24h. The
     * general per-IP/global limiter (platform/ratelimit.c) is phase 10 --
     * discussed with the user -- this is scoped specifically to this
     * endpoint's own abuse vector (a third party's inbox, not this
     * service), using the existing ratelimit.resend_* config fields. */
    int64_t recent_minute = 0;
    int64_t recent_day    = 0;
    bool    counted = ps_token_store_count_created_since(conn, user.user_id,
                                                         now - app_ctx->config->resend_min_interval_s,
                                                         &recent_minute) &&
                    ps_token_store_count_created_since(
                        conn, user.user_id, now - 24 * 60 * 60, &recent_day);
    if (!counted) {
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }
    if (recent_minute > 0 || recent_day >= app_ctx->config->resend_max_per_day) {
        audit_resend(conn, now, peer_addr, true, user.user_id, "FAILURE", "throttled");
        ps_db_pool_release(app_ctx->db_pool, conn);
        ps_handler_result_t r = { .status = 202, .body = resend_response_body(), .no_store = true };
        return r;
    }

    char *errmsg = NULL;
    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    char db_err[256];
    /* Every outstanding token invalidated first -- live tokens must not
     * accumulate (plan 4.3). */
    bool ok = ps_token_store_invalidate_all_for_user(conn, user.user_id, now, db_err, sizeof db_err);

    unsigned char raw_token[PS_TOKEN_RAW_LEN];
    ok = ok && insert_fresh_token(conn, user.user_id, app_ctx, now, raw_token, db_err, sizeof db_err);

    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at        = now;
    audit_entry.has_target_user_id = true;
    audit_entry.target_user_id     = user.user_id;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "RESEND_REQUESTED");
    (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, ok ? "SUCCESS" : "FAILURE");
    set_audit_source_ip(&audit_entry, peer_addr);
    ok = ok && ps_audit_store_write(conn, &audit_entry, db_err, sizeof db_err);

    if (!ok) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }
    if (sqlite3_exec(conn, "COMMIT;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    send_verification_email(conn, raw_token, user.email, user.username, app_ctx, now);
    ps_db_pool_release(app_ctx->db_pool, conn);

    ps_handler_result_t r = { .status = 202, .body = resend_response_body(), .no_store = true };
    return r;
}
