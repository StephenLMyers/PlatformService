"""
Black-box tests for POST /v1/auth/login, /refresh, /logout, /password
(plan 4.4-4.7, 6.8, 6.9, D12). Each test launches its own dedicated
instance -- login/lockout/reuse-detection all mutate shared per-account
state (failed_logins, session families) in ways that must not leak between
tests sharing one instance.
"""
from client import make_client
from conftest import db_query, latest_verification_token, launch

PASSWORD = "correct horse battery staple"


def register_and_activate(client, log_path, username, email, password=PASSWORD):
    resp = client.post("/v1/auth/register", json={
        "username": username, "email": email, "password": password,
    })
    assert resp.status_code == 202, resp.text
    token = latest_verification_token(log_path, username)
    resp = client.post("/v1/auth/verify", json={"token": token})
    assert resp.status_code == 200, resp.text


def login(client, username, password=PASSWORD):
    return client.post("/v1/auth/login", json={"username": username, "password": password})


def assert_token_pair_shape(body):
    assert set(body.keys()) == {"access_token", "refresh_token", "token_type", "expires_in"}
    assert body["token_type"] == "Bearer"
    assert isinstance(body["expires_in"], (int, float))
    assert body["access_token"].count(".") == 2
    assert len(body["refresh_token"]) > 0


def test_login_success_returns_token_pair(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "login-ok") as (base_url, cert_path, db_path,
                                                                 log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "loginok", "loginok@example.com")
            resp = login(c, "loginok")
            assert resp.status_code == 200
            assert_token_pair_shape(resp.json())


def test_login_unverified_account_matches_unknown_user_response(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "login-enum") as (base_url, cert_path, db_path,
                                                                    log_path):
        with make_client(base_url, cert_path) as c:
            resp = c.post("/v1/auth/register", json={
                "username": "unverified1", "email": "unverified1@example.com", "password": PASSWORD,
            })
            assert resp.status_code == 202

            unverified_resp = login(c, "unverified1")
            unknown_resp = login(c, "totally-unknown-user")
            wrong_pw_resp = login(c, "unverified1", password="wrong password entirely")

            assert unverified_resp.status_code == 401
            assert unknown_resp.status_code == 401
            assert wrong_pw_resp.status_code == 401
            assert unverified_resp.json() == unknown_resp.json() == wrong_pw_resp.json()


def test_login_wrong_password_rejected(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "login-wrongpw") as (base_url, cert_path, db_path,
                                                                       log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "wrongpwuser", "wrongpwuser@example.com")
            resp = login(c, "wrongpwuser", password="not the right password")
            assert resp.status_code == 401
            assert resp.json()["error"]["code"] == "UNAUTHORIZED"


def test_login_lockout_after_threshold_failures(built_binary, tmp_path_factory):
    with launch(
        built_binary, tmp_path_factory, "login-lockout",
        env_overrides={"PS_LOCKOUT_THRESHOLD": "3", "PS_LOCKOUT_DURATION_S": "900"},
    ) as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "lockoutuser", "lockoutuser@example.com")

            for _ in range(3):
                resp = login(c, "lockoutuser", password="wrong password")
                assert resp.status_code == 401

            # The 4th attempt uses the *correct* password but the account
            # is now locked -- still an identical 401 (plan 6.9).
            locked_resp = login(c, "lockoutuser")
            assert locked_resp.status_code == 401

            rows = db_query(db_path, "SELECT locked_until FROM users WHERE username = 'lockoutuser'")
            assert rows[0][0] is not None

            audit_events = db_query(
                db_path, "SELECT event FROM audit_log WHERE event = 'ACCOUNT_LOCKED'"
            )
            assert len(audit_events) == 1


def test_login_success_resets_failed_login_counter(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "login-reset") as (base_url, cert_path, db_path,
                                                                     log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "resetcounter", "resetcounter@example.com")
            login(c, "resetcounter", password="wrong")
            login(c, "resetcounter", password="wrong")

            rows = db_query(db_path, "SELECT failed_logins FROM users WHERE username = 'resetcounter'")
            assert rows[0][0] == 2

            ok = login(c, "resetcounter")
            assert ok.status_code == 200

            rows = db_query(db_path, "SELECT failed_logins FROM users WHERE username = 'resetcounter'")
            assert rows[0][0] == 0


def test_refresh_rotates_and_old_token_then_fails(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "refresh-rotate") as (base_url, cert_path, db_path,
                                                                        log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "refreshuser", "refreshuser@example.com")
            pair = login(c, "refreshuser").json()

            resp = c.post("/v1/auth/refresh", json={"refresh_token": pair["refresh_token"]})
            assert resp.status_code == 200
            new_pair = resp.json()
            assert_token_pair_shape(new_pair)
            assert new_pair["refresh_token"] != pair["refresh_token"]

            # The old, already-rotated token is now dead.
            replay = c.post("/v1/auth/refresh", json={"refresh_token": pair["refresh_token"]})
            assert replay.status_code == 401
            assert replay.json()["error"]["code"] == "UNAUTHORIZED"


def test_refresh_reuse_revokes_the_whole_family(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "refresh-reuse") as (base_url, cert_path, db_path,
                                                                       log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "reuseuser", "reuseuser@example.com")
            r1 = login(c, "reuseuser").json()

            # Legitimate first rotation: R1 -> R2.
            r2 = c.post("/v1/auth/refresh", json={"refresh_token": r1["refresh_token"]}).json()

            # R1 presented again (theft simulation) -- reuse detected.
            reuse_resp = c.post("/v1/auth/refresh", json={"refresh_token": r1["refresh_token"]})
            assert reuse_resp.status_code == 401

            # R2, though never itself consumed, is now dead too -- the
            # entire family was revoked, not just the reused token.
            r2_resp = c.post("/v1/auth/refresh", json={"refresh_token": r2["refresh_token"]})
            assert r2_resp.status_code == 401

            events = db_query(
                db_path, "SELECT event FROM audit_log WHERE event = 'REFRESH_REUSE_DETECTED'"
            )
            assert len(events) == 1


def test_refresh_unknown_token_rejected(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "refresh-unknown") as (base_url, cert_path, db_path,
                                                                         log_path):
        with make_client(base_url, cert_path) as c:
            resp = c.post("/v1/auth/refresh", json={"refresh_token": "A" * 43})
            assert resp.status_code == 401
            assert resp.json()["error"]["code"] == "UNAUTHORIZED"


def test_logout_without_bearer_token_rejected(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "logout-noauth") as (base_url, cert_path, db_path,
                                                                       log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "logoutnoauth", "logoutnoauth@example.com")
            pair = login(c, "logoutnoauth").json()
            resp = c.post("/v1/auth/logout", json={"refresh_token": pair["refresh_token"]})
            assert resp.status_code == 401


def test_logout_revokes_family_and_refresh_then_fails(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "logout-ok") as (base_url, cert_path, db_path,
                                                                   log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "logoutok", "logoutok@example.com")
            pair = login(c, "logoutok").json()

            resp = c.post(
                "/v1/auth/logout",
                json={"refresh_token": pair["refresh_token"]},
                headers={"Authorization": f"Bearer {pair['access_token']}"},
            )
            assert resp.status_code == 204

            # Idempotent: logging out again (family already revoked, but
            # the token itself, never consumed, is still findable) still
            # succeeds.
            resp2 = c.post(
                "/v1/auth/logout",
                json={"refresh_token": pair["refresh_token"]},
                headers={"Authorization": f"Bearer {pair['access_token']}"},
            )
            assert resp2.status_code == 204

            refresh_resp = c.post("/v1/auth/refresh", json={"refresh_token": pair["refresh_token"]})
            assert refresh_resp.status_code == 401


def test_logout_wrong_owner_forbidden(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "logout-wrongowner") as (base_url, cert_path, db_path,
                                                                          log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "ownera", "ownera@example.com")
            register_and_activate(c, log_path, "ownerb", "ownerb@example.com")
            pair_a = login(c, "ownera").json()
            pair_b = login(c, "ownerb").json()

            # B's access token, A's refresh token -- must not be allowed to
            # end a session B doesn't own.
            resp = c.post(
                "/v1/auth/logout",
                json={"refresh_token": pair_a["refresh_token"]},
                headers={"Authorization": f"Bearer {pair_b['access_token']}"},
            )
            assert resp.status_code == 403

            # A's own session must still be alive.
            refresh_resp = c.post("/v1/auth/refresh", json={"refresh_token": pair_a["refresh_token"]})
            assert refresh_resp.status_code == 200


def test_password_change_requires_current_password(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "pwchange-wrong") as (base_url, cert_path, db_path,
                                                                        log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "pwchangewrong", "pwchangewrong@example.com")
            pair = login(c, "pwchangewrong").json()

            resp = c.post(
                "/v1/auth/password",
                json={"current_password": "totally wrong", "new_password": "a brand new passphrase"},
                headers={"Authorization": f"Bearer {pair['access_token']}"},
            )
            assert resp.status_code == 401

            # The old password must still work.
            still_works = login(c, "pwchangewrong")
            assert still_works.status_code == 200


def test_password_change_weak_new_password_rejected(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "pwchange-weak") as (base_url, cert_path, db_path,
                                                                       log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "pwchangeweak", "pwchangeweak@example.com")
            pair = login(c, "pwchangeweak").json()

            resp = c.post(
                "/v1/auth/password",
                json={"current_password": PASSWORD, "new_password": "password"},
                headers={"Authorization": f"Bearer {pair['access_token']}"},
            )
            assert resp.status_code == 400
            assert resp.json()["error"]["code"] == "WEAK_PASSWORD"


def test_password_change_success_revokes_other_sessions_but_not_this_one(built_binary,
                                                                          tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "pwchange-ok") as (base_url, cert_path, db_path,
                                                                     log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "pwchangeok", "pwchangeok@example.com")

            # Two independent sessions -- e.g. phone and laptop.
            session_a = login(c, "pwchangeok").json()
            session_b = login(c, "pwchangeok").json()

            new_password = "a brand new passphrase nobody guessed"
            resp = c.post(
                "/v1/auth/password",
                json={"current_password": PASSWORD, "new_password": new_password},
                headers={"Authorization": f"Bearer {session_a['access_token']}"},
            )
            assert resp.status_code == 204

            # Session A (the one that issued the change) survives.
            still_alive = c.post(
                "/v1/auth/refresh", json={"refresh_token": session_a["refresh_token"]}
            )
            assert still_alive.status_code == 200

            # Session B was revoked.
            dead = c.post("/v1/auth/refresh", json={"refresh_token": session_b["refresh_token"]})
            assert dead.status_code == 401

            # The new password now works; the old one no longer does.
            old_login = login(c, "pwchangeok", password=PASSWORD)
            assert old_login.status_code == 401
            new_login = login(c, "pwchangeok", password=new_password)
            assert new_login.status_code == 200


def test_password_change_without_bearer_token_rejected(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "pwchange-noauth") as (base_url, cert_path, db_path,
                                                                         log_path):
        with make_client(base_url, cert_path) as c:
            resp = c.post(
                "/v1/auth/password",
                json={"current_password": PASSWORD, "new_password": "a brand new passphrase"},
            )
            assert resp.status_code == 401
