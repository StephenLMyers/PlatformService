#include "api/auth_api.h"

#include <string.h>
#include <time.h>

#include "auth/claims.h"
#include "auth/jwt.h"
#include "auth/password.h"
#include "auth/session.h"
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
#include "store/session_store.h"
#include "store/token_store.h"
#include "store/user_store.h"

#define PS_RAW_FIELD_MAX 512
#define PS_TOKEN_RAW_LEN 32 /* 256-bit CSPRNG (plan 6.6) */
#define PS_JWT_CLOCK_SKEW_S 60 /* plan 6.2's fixed +-60s allowance */
#define PS_JTI_RAW_LEN 16 /* 128-bit, matches PS_JWT_JTI_HEX_LEN once hex-encoded */

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

/* Same as obj_set_str, for a (data, len) value that isn't NUL-terminated --
 * a freshly built ps_buf_t (an encoded JWT, a base64url token), unlike
 * every other string this file writes into a response body. */
static bool obj_set_str_n(ps_json_value_t *obj, const char *key, const char *val, size_t len)
{
    ps_json_value_t *v = ps_json_new_string_n(val, len);
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

static void hex_encode_lower(const unsigned char *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

/* Inverse of hex_encode_lower. Only ever called on a claims.family_id that
 * ps_claims_parse already validated as exactly PS_JWT_FAMILY_ID_HEX_LEN
 * lowercase-hex-shaped bytes coming out of a signature-verified token, so
 * failure here would mean that invariant broke, not attacker input. */
static bool hex_decode(const char *hex, size_t hex_len, unsigned char *out)
{
    if (hex_len % 2 != 0) {
        return false;
    }
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

/* Builds a signed access token (plan 6.1) for user_id/family_id/roles, with
 * a fresh jti every call. family_id is PS_FAMILY_ID_LEN raw bytes (auth/
 * session.h's shape), hex-encoded into the claim the same way jti is. */
static bool build_access_token(const ps_app_ctx_t *app_ctx, int64_t user_id,
                               const unsigned char family_id[PS_FAMILY_ID_LEN], uint32_t roles,
                               int64_t now, ps_buf_t *out_token)
{
    unsigned char jti_raw[PS_JTI_RAW_LEN];
    if (!ps_rand_bytes(jti_raw, sizeof jti_raw)) {
        return false;
    }
    ps_jwt_claims_t claims;
    memset(&claims, 0, sizeof claims);
    claims.user_id = user_id;
    claims.roles   = roles;
    claims.iat     = now;
    claims.nbf     = now;
    claims.exp     = now + app_ctx->config->access_token_ttl_s;
    hex_encode_lower(jti_raw, sizeof jti_raw, claims.jti);
    hex_encode_lower(family_id, PS_FAMILY_ID_LEN, claims.family_id);

    return ps_jwt_encode(&claims, app_ctx->config->jwt_issuer, app_ctx->config->jwt_audience,
                         app_ctx->config->jwt_secret, strlen(app_ctx->config->jwt_secret),
                         out_token);
}

/* plan 4.4/4.5's exact response shape, shared by login and refresh. Takes
 * ownership of nothing; access_token/raw_refresh are read-only inputs. */
static ps_json_value_t *token_pair_body(const ps_buf_t *access_token,
                                        const unsigned char raw_refresh[PS_REFRESH_TOKEN_HASH_LEN],
                                        int access_token_ttl_s)
{
    ps_buf_t refresh_b64;
    ps_buf_init(&refresh_b64);
    if (!ps_base64url_encode(raw_refresh, PS_REFRESH_TOKEN_HASH_LEN, &refresh_b64)) {
        ps_buf_free(&refresh_b64);
        return NULL;
    }

    ps_json_value_t *obj = ps_json_new_object();
    bool ok = obj != NULL;
    ok = ok && obj_set_str_n(obj, "access_token", access_token->data, access_token->len);
    ok = ok && obj_set_str_n(obj, "refresh_token", refresh_b64.data, refresh_b64.len);
    ok = ok && obj_set_str(obj, "token_type", "Bearer");
    ok = ok && obj_set_num(obj, "expires_in", (double)access_token_ttl_s);
    ps_buf_free(&refresh_b64);

    if (!ok) {
        ps_json_free(obj);
        return NULL;
    }
    return obj;
}

/*
 * plan 4.6/4.7's minimal bearer-token authentication: extract, verify, hand
 * back claims. Deliberately not the RBAC policy engine (phase 8's job) --
 * logout and password-change only need "prove who is asking", not
 * role-based gating.
 */
typedef enum {
    PS_BEARER_OK = 0,
    PS_BEARER_MISSING,
    PS_BEARER_INVALID,
} ps_bearer_result_t;

static ps_bearer_result_t authenticate_bearer(const ps_http_request_t *req,
                                              const ps_app_ctx_t *app_ctx, int64_t now,
                                              ps_jwt_claims_t *out)
{
    static const char PREFIX[]    = "Bearer ";
    const size_t       PREFIX_LEN = sizeof PREFIX - 1;

    const ps_http_header_t *h = ps_http_request_header(req, "Authorization");
    if (h == NULL || h->value_len <= PREFIX_LEN || memcmp(h->value, PREFIX, PREFIX_LEN) != 0) {
        return PS_BEARER_MISSING;
    }

    const char *token     = h->value + PREFIX_LEN;
    size_t      token_len = h->value_len - PREFIX_LEN;

    ps_jwt_verify_result_t r =
        ps_jwt_verify(token, token_len, app_ctx->config->jwt_issuer, app_ctx->config->jwt_audience,
                     app_ctx->config->jwt_secret, strlen(app_ctx->config->jwt_secret), now,
                     PS_JWT_CLOCK_SKEW_S, out);
    return r == PS_JWT_OK ? PS_BEARER_OK : PS_BEARER_INVALID;
}

/* plan 7.4: run on an unknown username (login) or an unknown/wrong-owner
 * user_id (password change) so response timing doesn't leak account
 * existence -- a real PBKDF2 pass at the configured cost, output discarded. */
static void run_dummy_kdf(int iterations)
{
    static const char dummy_password[] = "dummy-password-for-timing-parity";
    ps_password_hash_t dummy;
    (void)ps_password_hash(dummy_password, sizeof dummy_password - 1, iterations, &dummy);
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

/* ---- POST /v1/auth/login ---- */

ps_handler_result_t ps_auth_handle_login(const ps_http_request_t *req,
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
    char raw_username[PS_RAW_FIELD_MAX];
    if (!read_string_field(body, "username", raw_username, sizeof raw_username)) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "username and password are required string fields");
    }
    ps_json_value_t *password_field = ps_json_object_get(body, "password");
    if (password_field == NULL || ps_json_type(password_field) != PS_JSON_STRING) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "username and password are required string fields");
    }
    const char *password     = ps_json_get_string(password_field);
    size_t      password_len = ps_json_get_string_len(password_field);

    if (!ps_kdf_semaphore_try_acquire(app_ctx->kdf_semaphore)) {
        ps_json_free(body);
        return error_result(503, "SERVICE_UNAVAILABLE", "too many concurrent logins; try again shortly");
    }

    int64_t  now  = time(NULL);
    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);

    ps_user_row_t user;
    bool found = ps_user_store_get_by_username(conn, raw_username, &user);

    /* plan 7.4: the real hash always runs when a row was found -- even
     * locked or unverified -- so timing never leaks *why* a login failed,
     * only that it did. Only a truly unknown username takes the dummy
     * path. */
    bool password_ok;
    if (found) {
        ps_password_hash_t stored;
        memcpy(stored.salt, user.password_salt, sizeof stored.salt);
        memcpy(stored.hash, user.password_hash, sizeof stored.hash);
        stored.iterations = user.kdf_iters;
        password_ok = ps_password_verify(password, password_len, &stored);
    } else {
        run_dummy_kdf(app_ctx->config->kdf_iterations);
        password_ok = false;
    }
    ps_kdf_semaphore_release(app_ctx->kdf_semaphore);
    ps_json_free(body);

    bool locked  = found && user.locked_until != 0 && user.locked_until > now;
    bool success = found && password_ok && user.status == PS_USER_STATUS_ACTIVE && !locked;

    char *errmsg = NULL;
    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    if (!success) {
        const char *reason = !found          ? "no_such_user"
                            : locked          ? "locked"
                            : !password_ok    ? "wrong_password"
                                              : "not_active";

        /* plan 6.9: the counter only tracks actual wrong-password attempts
         * against a currently-unlocked, known account -- a correct
         * password against a not-yet-verified account is not a guessing
         * attempt, and an already-locked account gains nothing from a
         * higher count while the lock itself already blocks it. */
        bool    just_locked = false;
        char    db_err[256];
        bool    ok = true;
        if (found && !locked && !password_ok) {
            int     failed           = user.failed_logins + 1;
            int64_t new_locked_until = 0;
            if (failed >= app_ctx->config->lockout_threshold) {
                new_locked_until = now + app_ctx->config->lockout_duration_s;
                just_locked      = true;
            }
            ok = ps_user_store_set_login_failure_state(conn, user.user_id, failed, new_locked_until,
                                                       now, db_err, sizeof db_err);
        }

        ps_audit_entry_t audit_entry;
        memset(&audit_entry, 0, sizeof audit_entry);
        audit_entry.occurred_at = now;
        (void)snprintf(audit_entry.event, sizeof audit_entry.event, "LOGIN");
        (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "FAILURE");
        if (found) {
            audit_entry.has_target_user_id = true;
            audit_entry.target_user_id     = user.user_id;
        }
        audit_entry.has_detail = true;
        (void)snprintf(audit_entry.detail, sizeof audit_entry.detail, "{\"reason\":\"%s\"}", reason);
        set_audit_source_ip(&audit_entry, peer_addr);
        ok = ok && ps_audit_store_write(conn, &audit_entry, db_err, sizeof db_err);

        if (ok && just_locked) {
            ps_audit_entry_t locked_entry;
            memset(&locked_entry, 0, sizeof locked_entry);
            locked_entry.occurred_at        = now;
            locked_entry.has_target_user_id = true;
            locked_entry.target_user_id     = user.user_id;
            (void)snprintf(locked_entry.event, sizeof locked_entry.event, "ACCOUNT_LOCKED");
            (void)snprintf(locked_entry.outcome, sizeof locked_entry.outcome, "SUCCESS");
            set_audit_source_ip(&locked_entry, peer_addr);
            ok = ps_audit_store_write(conn, &locked_entry, db_err, sizeof db_err);
        }

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
        return error_result(401, "UNAUTHORIZED", "invalid username or password");
    }

    char db_err[256];
    bool ok = ps_user_store_set_login_failure_state(conn, user.user_id, 0, 0, now, db_err,
                                                    sizeof db_err);

    ps_session_created_t session;
    ok = ok && ps_session_create(conn, user.user_id, app_ctx->config->refresh_absolute_ttl_s,
                                 app_ctx->config->refresh_idle_ttl_s, now, &session, db_err,
                                 sizeof db_err);

    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at        = now;
    audit_entry.has_target_user_id = true;
    audit_entry.target_user_id     = user.user_id;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "LOGIN");
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

    char   role_names[8][32];
    size_t role_count = 0;
    bool   roles_ok   = ps_user_store_get_roles(conn, user.user_id, role_names, 8, &role_count);
    uint32_t roles    = roles_ok ? ps_claims_roles_from_names(role_names, role_count) : 0;

    ps_buf_t access_token;
    ps_buf_init(&access_token);
    bool built = roles_ok && build_access_token(app_ctx, user.user_id, session.family_id, roles, now,
                                                &access_token);
    ps_json_value_t *resp_body =
        built ? token_pair_body(&access_token, session.raw_refresh_token,
                                app_ctx->config->access_token_ttl_s)
              : NULL;
    ps_buf_free(&access_token);
    ps_db_pool_release(app_ctx->db_pool, conn);

    if (resp_body == NULL) {
        return internal_error_result();
    }
    ps_handler_result_t r = { .status = 200, .body = resp_body, .no_store = true };
    return r;
}

/* ---- POST /v1/auth/refresh ---- */

ps_handler_result_t ps_auth_handle_refresh(const ps_http_request_t *req,
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
    if (!read_string_field(body, "refresh_token", raw_token_b64, sizeof raw_token_b64)) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "refresh_token is a required string field");
    }
    ps_json_free(body);

    ps_buf_t decoded;
    ps_buf_init(&decoded);
    bool decode_ok = ps_base64url_decode(raw_token_b64, strlen(raw_token_b64), &decoded);
    bool right_len = decode_ok && decoded.len == PS_REFRESH_TOKEN_HASH_LEN;

    unsigned char token_hash[PS_SHA256_LEN];
    if (right_len) {
        (void)ps_sha256(decoded.data, decoded.len, token_hash);
    }
    ps_buf_free(&decoded);
    if (!right_len) {
        return error_result(401, "UNAUTHORIZED", "invalid or expired refresh token");
    }

    int64_t  now  = time(NULL);
    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);

    char *errmsg = NULL;
    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    char                        db_err[256];
    ps_session_refreshed_t      refreshed;
    ps_session_refresh_result_t result = ps_session_refresh(
        conn, token_hash, app_ctx->config->refresh_idle_ttl_s, now, &refreshed, db_err, sizeof db_err);

    if (result == PS_SESSION_REFRESH_ERROR) {
        (void)sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    /* plan 6.10: TOKEN_REFRESH is success-only; a failed refresh lands as
     * REFRESH_REUSE_DETECTED or a plain FAILURE row instead. user_id/
     * family_id are known (auth/session.c populates them) whenever the
     * token was found at all, which is every case except INVALID on a
     * token that never existed. */
    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at = now;
    if (refreshed.user_id != 0) {
        audit_entry.has_target_user_id = true;
        audit_entry.target_user_id     = refreshed.user_id;
    }
    set_audit_source_ip(&audit_entry, peer_addr);
    if (result == PS_SESSION_REFRESH_REUSE_DETECTED) {
        (void)snprintf(audit_entry.event, sizeof audit_entry.event, "REFRESH_REUSE_DETECTED");
        (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "FAILURE");
    } else {
        (void)snprintf(audit_entry.event, sizeof audit_entry.event, "TOKEN_REFRESH");
        (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome,
                       result == PS_SESSION_REFRESH_OK ? "SUCCESS" : "FAILURE");
    }
    bool ok = ps_audit_store_write(conn, &audit_entry, db_err, sizeof db_err);

    /* Whatever ps_session_refresh already did to the old token (the atomic
     * claim, or a family revocation on reuse) must persist regardless of
     * the overall outcome -- only a genuine audit-write failure rolls this
     * back, never "the refresh itself didn't succeed". */
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

    if (result != PS_SESSION_REFRESH_OK) {
        ps_db_pool_release(app_ctx->db_pool, conn);
        return error_result(401, "UNAUTHORIZED", "invalid or expired refresh token");
    }

    char   role_names[8][32];
    size_t role_count = 0;
    bool   roles_ok = ps_user_store_get_roles(conn, refreshed.user_id, role_names, 8, &role_count);
    uint32_t roles  = roles_ok ? ps_claims_roles_from_names(role_names, role_count) : 0;

    ps_buf_t access_token;
    ps_buf_init(&access_token);
    bool built = roles_ok && build_access_token(app_ctx, refreshed.user_id, refreshed.family_id, roles,
                                                now, &access_token);
    ps_json_value_t *resp_body =
        built ? token_pair_body(&access_token, refreshed.raw_refresh_token,
                                app_ctx->config->access_token_ttl_s)
              : NULL;
    ps_buf_free(&access_token);
    ps_db_pool_release(app_ctx->db_pool, conn);

    if (resp_body == NULL) {
        return internal_error_result();
    }
    ps_handler_result_t r = { .status = 200, .body = resp_body, .no_store = true };
    return r;
}

/* ---- POST /v1/auth/logout ---- */

ps_handler_result_t ps_auth_handle_logout(const ps_http_request_t *req,
                                          const ps_route_params_t *params,
                                          const char *peer_addr, const ps_app_ctx_t *app_ctx)
{
    (void)params;

    int64_t now = time(NULL);

    ps_jwt_claims_t claims;
    if (authenticate_bearer(req, app_ctx, now, &claims) != PS_BEARER_OK) {
        return error_result(401, "UNAUTHORIZED", "missing or invalid access token");
    }

    char             json_err[128];
    ps_json_value_t *body = ps_json_parse(req->body, req->body_len, json_err, sizeof json_err);
    if (body == NULL || ps_json_type(body) != PS_JSON_OBJECT) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "request body must be a JSON object");
    }
    char raw_token_b64[128];
    if (!read_string_field(body, "refresh_token", raw_token_b64, sizeof raw_token_b64)) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "refresh_token is a required string field");
    }
    ps_json_free(body);

    ps_buf_t decoded;
    ps_buf_init(&decoded);
    bool decode_ok = ps_base64url_decode(raw_token_b64, strlen(raw_token_b64), &decoded);
    bool right_len = decode_ok && decoded.len == PS_REFRESH_TOKEN_HASH_LEN;
    unsigned char token_hash[PS_SHA256_LEN];
    if (right_len) {
        (void)ps_sha256(decoded.data, decoded.len, token_hash);
    }
    ps_buf_free(&decoded);
    if (!right_len) {
        return error_result(400, "BAD_REQUEST", "refresh_token is invalid");
    }

    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);

    ps_refresh_token_row_t token_row;
    bool found = ps_session_store_get_token(conn, token_hash, &token_row);
    if (!found) {
        /* plan 4.6: logout is idempotent, and an unrecognized token names
         * no family to revoke -- indistinguishable here from a session
         * that's already gone. */
        ps_db_pool_release(app_ctx->db_pool, conn);
        ps_handler_result_t r = { .status = 204, .body = NULL, .no_store = true };
        return r;
    }

    ps_session_family_row_t family;
    if (!ps_session_store_get_family(conn, token_row.family_id, &family)) {
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }
    if (family.user_id != claims.user_id) {
        /* plan 4.6: sub from the access token must match the family's
         * owner, or 403 -- a valid token must never end a session it
         * doesn't own. */
        ps_db_pool_release(app_ctx->db_pool, conn);
        return error_result(403, "FORBIDDEN", "refresh token does not belong to this account");
    }

    char *errmsg = NULL;
    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    char db_err[256];
    bool ok = ps_session_store_revoke_family(conn, token_row.family_id, "LOGOUT", now, db_err,
                                             sizeof db_err);

    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at        = now;
    audit_entry.has_target_user_id = true;
    audit_entry.target_user_id     = family.user_id;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "LOGOUT");
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

    ps_handler_result_t r = { .status = 204, .body = NULL, .no_store = true };
    return r;
}

/* ---- POST /v1/auth/password ---- */

ps_handler_result_t ps_auth_handle_password_change(const ps_http_request_t *req,
                                                    const ps_route_params_t *params,
                                                    const char *peer_addr,
                                                    const ps_app_ctx_t *app_ctx)
{
    (void)params;

    int64_t now = time(NULL);

    ps_jwt_claims_t claims;
    if (authenticate_bearer(req, app_ctx, now, &claims) != PS_BEARER_OK) {
        return error_result(401, "UNAUTHORIZED", "missing or invalid access token");
    }

    char             json_err[128];
    ps_json_value_t *body = ps_json_parse(req->body, req->body_len, json_err, sizeof json_err);
    if (body == NULL || ps_json_type(body) != PS_JSON_OBJECT) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST", "request body must be a JSON object");
    }
    ps_json_value_t *current_field = ps_json_object_get(body, "current_password");
    ps_json_value_t *new_field     = ps_json_object_get(body, "new_password");
    if (current_field == NULL || ps_json_type(current_field) != PS_JSON_STRING ||
        new_field == NULL || ps_json_type(new_field) != PS_JSON_STRING) {
        ps_json_free(body);
        return error_result(400, "BAD_REQUEST",
                            "current_password and new_password are required string fields");
    }
    const char *current_password     = ps_json_get_string(current_field);
    size_t      current_password_len = ps_json_get_string_len(current_field);
    const char *new_password         = ps_json_get_string(new_field);
    size_t      new_password_len     = ps_json_get_string_len(new_field);

    ps_password_policy_result_t policy = ps_password_policy_check(
        new_password, new_password_len, app_ctx->config->password_min_length,
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
                            "too many concurrent password changes; try again shortly");
    }

    sqlite3 *conn = ps_db_pool_acquire(app_ctx->db_pool);

    /* claims.user_id came from a signature-verified token, so the row is
     * expected to exist -- but re-authentication (plan 4.7) still means
     * checking the *current* password for real, never trusting the token
     * alone, and running the same dummy-hash path if the row is somehow
     * gone so this call's timing doesn't vary either way. */
    ps_user_row_t user;
    bool          found      = ps_user_store_get_by_id(conn, claims.user_id, &user);
    bool          current_ok = false;
    if (found) {
        ps_password_hash_t stored;
        memcpy(stored.salt, user.password_salt, sizeof stored.salt);
        memcpy(stored.hash, user.password_hash, sizeof stored.hash);
        stored.iterations = user.kdf_iters;
        current_ok = ps_password_verify(current_password, current_password_len, &stored);
    } else {
        run_dummy_kdf(app_ctx->config->kdf_iterations);
    }

    ps_password_hash_t new_hash;
    bool hashed = current_ok && ps_password_hash(new_password, new_password_len,
                                                 app_ctx->config->kdf_iterations, &new_hash);
    ps_kdf_semaphore_release(app_ctx->kdf_semaphore);
    ps_json_free(body);

    if (!found || !current_ok) {
        char             db_err[256];
        ps_audit_entry_t audit_entry;
        memset(&audit_entry, 0, sizeof audit_entry);
        audit_entry.occurred_at        = now;
        audit_entry.has_target_user_id = true;
        audit_entry.target_user_id     = claims.user_id;
        (void)snprintf(audit_entry.event, sizeof audit_entry.event, "PASSWORD_CHANGE");
        (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, "FAILURE");
        audit_entry.has_detail = true;
        (void)snprintf(audit_entry.detail, sizeof audit_entry.detail,
                       "{\"reason\":\"wrong_current_password\"}");
        set_audit_source_ip(&audit_entry, peer_addr);
        (void)ps_audit_store_write(conn, &audit_entry, db_err, sizeof db_err);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return error_result(401, "UNAUTHORIZED", "current password is incorrect");
    }
    if (!hashed) {
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    unsigned char surviving_family_id[PS_FAMILY_ID_LEN];
    if (!hex_decode(claims.family_id, PS_JWT_FAMILY_ID_HEX_LEN, surviving_family_id)) {
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    char *errmsg = NULL;
    if (sqlite3_exec(conn, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg) != SQLITE_OK) {
        sqlite3_free(errmsg);
        ps_db_pool_release(app_ctx->db_pool, conn);
        return internal_error_result();
    }

    char db_err[256];
    bool ok = ps_user_store_set_password(conn, claims.user_id, new_hash.hash, new_hash.salt,
                                         new_hash.iterations, now, db_err, sizeof db_err);

    /* plan 4.7: every other session family dies; the one that issued this
     * very request survives. */
    int revoked_count = 0;
    ok = ok && ps_session_store_revoke_all_for_user(conn, claims.user_id, surviving_family_id,
                                                    "PASSWORD_CHANGE", now, &revoked_count, db_err,
                                                    sizeof db_err);

    ps_audit_entry_t audit_entry;
    memset(&audit_entry, 0, sizeof audit_entry);
    audit_entry.occurred_at        = now;
    audit_entry.has_target_user_id = true;
    audit_entry.target_user_id     = claims.user_id;
    (void)snprintf(audit_entry.event, sizeof audit_entry.event, "PASSWORD_CHANGE");
    (void)snprintf(audit_entry.outcome, sizeof audit_entry.outcome, ok ? "SUCCESS" : "FAILURE");
    if (ok) {
        audit_entry.has_detail = true;
        (void)snprintf(audit_entry.detail, sizeof audit_entry.detail, "{\"sessions_revoked\":%d}",
                       revoked_count);
    }
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

    ps_handler_result_t r = { .status = 204, .body = NULL, .no_store = true };
    return r;
}
