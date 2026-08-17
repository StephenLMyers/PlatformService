-- PlatformService schema, migration 1 (plan 5).
-- Embedded into the binary at build time (Makefile rule) rather than read
-- from disk at startup -- unlike certs/config/the common-passwords
-- denylist, this file must always exactly match what the compiled
-- queries expect, so it is part of the binary, not a deployable alongside it.

CREATE TABLE users (
    user_id          INTEGER PRIMARY KEY,
    username         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email            TEXT    NOT NULL,
    email_normalized TEXT    NOT NULL UNIQUE,
    password_hash    BLOB    NOT NULL,
    password_salt    BLOB    NOT NULL,
    kdf_iters        INTEGER NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'PENDING_VERIFICATION',
    failed_logins    INTEGER NOT NULL DEFAULT 0,
    locked_until     INTEGER,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);

CREATE TABLE roles (
    role_id INTEGER PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE
);

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE email_verification_tokens (
    token_hash  BLOB    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL,
    consumed_at INTEGER,
    created_at  INTEGER NOT NULL
);
CREATE INDEX idx_evt_user ON email_verification_tokens(user_id);

CREATE TABLE session_families (
    family_id    BLOB    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    absolute_exp INTEGER NOT NULL,
    revoked_at   INTEGER,
    revoke_cause TEXT
);
CREATE INDEX idx_sf_user ON session_families(user_id);

CREATE TABLE refresh_tokens (
    token_hash  BLOB    PRIMARY KEY,
    family_id   BLOB    NOT NULL REFERENCES session_families(family_id) ON DELETE CASCADE,
    generation  INTEGER NOT NULL,
    idle_exp    INTEGER NOT NULL,
    consumed_at INTEGER,
    issued_at   INTEGER NOT NULL
);
CREATE INDEX idx_rt_family ON refresh_tokens(family_id);

CREATE TABLE dev_outbox (
    id         INTEGER PRIMARY KEY,
    to_email   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id             INTEGER PRIMARY KEY,
    occurred_at    INTEGER NOT NULL,
    event          TEXT    NOT NULL,
    outcome        TEXT    NOT NULL,
    actor_user_id  INTEGER,
    target_user_id INTEGER,
    source_ip      TEXT,
    request_id     TEXT,
    detail         TEXT
);
CREATE INDEX idx_audit_time   ON audit_log(occurred_at);
CREATE INDEX idx_audit_actor  ON audit_log(actor_user_id, occurred_at);
CREATE INDEX idx_audit_target ON audit_log(target_user_id, occurred_at);
CREATE INDEX idx_audit_event  ON audit_log(event, occurred_at);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_status   ON users(status);

CREATE TABLE schema_version (version INTEGER NOT NULL);

-- Fixed reference data, not user-generated: the flat two-role model (plan
-- 6.4) never grows a third role without a new migration, so these rows are
-- part of the schema, not something later code inserts.
INSERT INTO roles (name) VALUES ('USER'), ('ADMIN');

INSERT INTO schema_version (version) VALUES (1);
