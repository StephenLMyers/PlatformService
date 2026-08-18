"""
Black-box tests for POST /v1/auth/register, /verify, /resend-verification
(plan 4.1-4.3, 6.6). Each test launches its own dedicated instance (not
the shared `service` fixture) so it can inspect that instance's own
database directly -- the same "SQL, always available" escape hatch plan
15.3 documents for reading a verification token out of dev_outbox.
"""
import contextlib
import re
import sqlite3
import ssl
import subprocess
import time

import httpx

from conftest import base_env, free_port, generate_dev_cert, stop_and_reap, wait_for_healthz


@contextlib.contextmanager
def launch(built_binary, tmp_path_factory, name, env_overrides=None):
    work_dir = tmp_path_factory.mktemp(name)
    cert_path, key_path = generate_dev_cert(work_dir)
    port = free_port()
    env = base_env(port, cert_path, key_path)
    env["PS_KDF_ITERATIONS"] = "1000"  # fast hashing for test speed, not a security boundary here
    env["PS_DEV_MODE"] = "true"  # needed for the dev_mode verification-token log line (plan 15.3)
    if env_overrides:
        env.update(env_overrides)

    log_path = work_dir / "service.log"
    with open(log_path, "wb") as log_file:
        proc = subprocess.Popen(
            [str(built_binary)], env=env, stdout=log_file, stderr=subprocess.STDOUT,
        )
    base_url = f"https://127.0.0.1:{port}"
    wait_for_healthz(base_url, cert_path, proc)
    try:
        yield base_url, cert_path, env["PS_DB_PATH"], log_path
    finally:
        exit_code = stop_and_reap(proc, log_path)
        assert exit_code == 0, (
            f"service exited {exit_code}, expected 0; log:\n"
            f"{log_path.read_text(errors='replace')}"
        )


def db_query(db_path: str, sql: str, params: tuple = ()) -> list:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def latest_verification_token(log_path, username: str, timeout: float = 5.0) -> str:
    """Reads the dev_mode verification-link log line (plan 15.3 escape
    hatch 2) rather than the database -- exercises that path directly,
    and sidesteps hashing the raw token back out of its stored digest."""
    pattern = re.compile(rf"verification token \(dev_mode\) for {re.escape(username)}: (\S+)")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = log_path.read_text(errors="replace")
        matches = pattern.findall(text)
        if matches:
            return matches[-1]
        time.sleep(0.05)
    raise AssertionError(f"no verification token logged for {username} within {timeout}s")


def register(client, username, email, password, extra_fields=None):
    body = {"username": username, "email": email, "password": password}
    if extra_fields:
        body.update(extra_fields)
    return client.post("/v1/auth/register", json=body)


PENDING_BODY = {
    "status": "PENDING_VERIFICATION",
    "message": "If this email address is not already registered, a verification link has been sent.",
}
RESEND_BODY = {
    "message": "If this email address requires verification, a new link has been sent."
}


def test_register_success(client):
    resp = register(client, "alice1", "alice1@example.com", "correct horse battery staple")
    assert resp.status_code == 202
    assert resp.json() == PENDING_BODY


def test_register_mass_assignment_ignored(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "mass-assign") as (base_url, cert_path, db_path, _log):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        with httpx.Client(base_url=base_url, verify=ctx, timeout=5.0) as c:
            resp = register(
                c, "masstest", "masstest@example.com", "correct horse battery staple",
                extra_fields={"roles": ["ADMIN"], "status": "ACTIVE", "userId": "999999", "kdf_iters": 1},
            )
            assert resp.status_code == 202

        rows = db_query(db_path, "SELECT status FROM users WHERE username = 'masstest'")
        assert rows == [("PENDING_VERIFICATION",)]
        roles = db_query(
            db_path,
            "SELECT r.name FROM roles r JOIN user_roles ur ON r.role_id = ur.role_id "
            "JOIN users u ON u.user_id = ur.user_id WHERE u.username = 'masstest'",
        )
        assert roles == [("USER",)]


def test_register_duplicate_username_conflicts(client):
    register(client, "dupuser", "dupuser1@example.com", "correct horse battery staple")
    resp = register(client, "dupuser", "dupuser2@example.com", "correct horse battery staple")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "CONFLICT"


def test_register_duplicate_email_returns_identical_202(client):
    register(client, "originalowner", "shared@example.com", "correct horse battery staple")
    resp = register(client, "impersonator", "shared@example.com", "correct horse battery staple")
    assert resp.status_code == 202
    assert resp.json() == PENDING_BODY


def test_register_weak_password_rejected(client):
    resp = register(client, "weakpwuser", "weakpw@example.com", "password")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "WEAK_PASSWORD"


def test_register_short_password_rejected(client):
    resp = register(client, "shortpwuser", "shortpw@example.com", "short1")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "WEAK_PASSWORD"


def test_register_malformed_email_rejected(client):
    resp = register(client, "bademailuser", "not-an-email", "correct horse battery staple")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "BAD_REQUEST"


def test_register_reserved_username_rejected(client):
    resp = register(client, "administrator", "notreallyadmin@example.com",
                    "correct horse battery staple")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "BAD_REQUEST"


def test_register_username_too_short_rejected(client):
    resp = register(client, "ab", "shortname@example.com", "correct horse battery staple")
    assert resp.status_code == 400


def test_register_missing_field_rejected(client):
    resp = client.post("/v1/auth/register", json={"username": "onlyusername"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "BAD_REQUEST"


def test_verify_activates_pending_account(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "verify-ok") as (base_url, cert_path, db_path, log_path):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        with httpx.Client(base_url=base_url, verify=ctx, timeout=5.0) as c:
            register(c, "verifyme", "verifyme@example.com", "correct horse battery staple")
            token = latest_verification_token(log_path, "verifyme")

            resp = c.post("/v1/auth/verify", json={"token": token})
            assert resp.status_code == 200
            assert resp.json() == {"status": "ACTIVE"}

        rows = db_query(db_path, "SELECT status FROM users WHERE username = 'verifyme'")
        assert rows == [("ACTIVE",)]


def test_verify_token_is_single_use(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "verify-single-use") as (base_url, cert_path, db_path,
                                                                         log_path):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        with httpx.Client(base_url=base_url, verify=ctx, timeout=5.0) as c:
            register(c, "singleuse", "singleuse@example.com", "correct horse battery staple")
            token = latest_verification_token(log_path, "singleuse")

            first = c.post("/v1/auth/verify", json={"token": token})
            assert first.status_code == 200

            second = c.post("/v1/auth/verify", json={"token": token})
            assert second.status_code == 400
            assert second.json()["error"]["code"] == "INVALID_TOKEN"


def test_verify_invalid_token_rejected(client):
    resp = client.post("/v1/auth/verify", json={"token": "A" * 43})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


def test_verify_malformed_token_rejected(client):
    resp = client.post("/v1/auth/verify", json={"token": "not-base64url!!"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


def test_verify_missing_field_rejected(client):
    resp = client.post("/v1/auth/verify", json={})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "BAD_REQUEST"


def test_resend_unknown_email_returns_202(client):
    resp = client.post("/v1/auth/resend-verification", json={"email": "nosuchperson@example.com"})
    assert resp.status_code == 202
    assert resp.json() == RESEND_BODY


def test_resend_for_active_account_returns_202_and_sends_nothing(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "resend-active") as (base_url, cert_path, db_path,
                                                                      log_path):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        with httpx.Client(base_url=base_url, verify=ctx, timeout=5.0) as c:
            register(c, "alreadyactive", "alreadyactive@example.com", "correct horse battery staple")
            token = latest_verification_token(log_path, "alreadyactive")
            c.post("/v1/auth/verify", json={"token": token})

            before = db_query(db_path, "SELECT COUNT(*) FROM dev_outbox")[0][0]
            resp = c.post("/v1/auth/resend-verification", json={"email": "alreadyactive@example.com"})
            assert resp.status_code == 202
            assert resp.json() == RESEND_BODY
            after = db_query(db_path, "SELECT COUNT(*) FROM dev_outbox")[0][0]
            assert after == before


def test_resend_throttled_within_60s_sends_nothing_new(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "resend-throttle") as (base_url, cert_path, db_path,
                                                                        _log_path):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        with httpx.Client(base_url=base_url, verify=ctx, timeout=5.0) as c:
            register(c, "throttleme", "throttleme@example.com", "correct horse battery staple")

            before = db_query(db_path, "SELECT COUNT(*) FROM dev_outbox")[0][0]
            resp = c.post("/v1/auth/resend-verification", json={"email": "throttleme@example.com"})
            assert resp.status_code == 202
            assert resp.json() == RESEND_BODY
            after = db_query(db_path, "SELECT COUNT(*) FROM dev_outbox")[0][0]
            assert after == before  # still just the original registration email


def test_resend_invalidates_prior_token(built_binary, tmp_path_factory):
    """plan 4.3: a resend invalidates every outstanding token first --
    verified here by forcing the 60s throttle window open via a fixed low
    ratelimit.resend_min_interval_s, then confirming the *old* token no
    longer verifies once a new one has been issued.

    The throttle check compares against time(NULL), which only has
    1-second resolution -- PS_RESEND_MIN_INTERVAL_S=0 alone isn't enough
    if register and resend land in the same wall-clock second (the
    registration's own token then still counts as "created since
    now-0"). The sleep crosses a real second boundary so the throttle
    check actually sees a token created strictly before `now`.
    """
    with launch(
        built_binary, tmp_path_factory, "resend-invalidate",
        env_overrides={"PS_RESEND_MIN_INTERVAL_S": "0"},
    ) as (base_url, cert_path, db_path, log_path):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        with httpx.Client(base_url=base_url, verify=ctx, timeout=5.0) as c:
            register(c, "invalidateme", "invalidateme@example.com", "correct horse battery staple")
            old_token = latest_verification_token(log_path, "invalidateme")

            time.sleep(1.1)
            resp = c.post("/v1/auth/resend-verification", json={"email": "invalidateme@example.com"})
            assert resp.status_code == 202

            old_result = c.post("/v1/auth/verify", json={"token": old_token})
            assert old_result.status_code == 400
            assert old_result.json()["error"]["code"] == "INVALID_TOKEN"
