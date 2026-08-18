"""
GET /v1/users/{userId} (plan 4.8): the RBAC matrix and PII disclosure
boundary (plan 8.2), and the dedicated IDOR suite (plan 8.4) -- ownership
must derive only from the verified token's sub, never from a body field,
query parameter, or header.

Each test launches its own dedicated instance: exercising the bootstrap
admin (the only account that starts out holding ADMIN) alongside freshly
registered USER accounts needs a clean, known DB per test.
"""
import sqlite3

from conftest import BOOTSTRAP_PASSWORD, BOOTSTRAP_USERNAME, db_query, latest_verification_token, \
    launch
from client import make_client

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
    resp = client.post("/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth_header(pair):
    return {"Authorization": f"Bearer {pair['access_token']}"}


def test_no_token_rejected(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-notoken") as (base_url, cert_path, db_path,
                                                                        log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "notokenuser", "notokenuser@example.com")
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'notokenuser'")
            user_id = rows[0][0]

            resp = c.get(f"/v1/users/{user_id}")
            assert resp.status_code == 401
            assert resp.json()["error"]["code"] == "UNAUTHORIZED"


def test_user_reads_own_record_with_email(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-self") as (base_url, cert_path, db_path,
                                                                      log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "selfreader", "selfreader@example.com")
            pair = login(c, "selfreader")
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'selfreader'")
            user_id = rows[0][0]

            resp = c.get(f"/v1/users/{user_id}", headers=auth_header(pair))
            assert resp.status_code == 200
            body = resp.json()
            assert body["userId"] == str(user_id)
            assert body["username"] == "selfreader"
            assert body["email"] == "selfreader@example.com"


def test_user_reading_another_user_forbidden(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-other") as (base_url, cert_path, db_path,
                                                                       log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "readerone", "readerone@example.com")
            register_and_activate(c, log_path, "readertwo", "readertwo@example.com")
            pair = login(c, "readerone")
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'readertwo'")
            other_id = rows[0][0]

            resp = c.get(f"/v1/users/{other_id}", headers=auth_header(pair))
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "FORBIDDEN"


def test_user_reading_a_nonexistent_id_still_forbidden_not_404(built_binary, tmp_path_factory):
    """A USER caller must get 403 for someone else's id whether or not
    that id actually exists -- RBAC denies before the handler ever looks
    the row up, so a nonexistent id doesn't leak as a distinguishable 404
    (plan 7.4-adjacent anti-enumeration property)."""
    with launch(built_binary, tmp_path_factory, "getuser-other-404") as (base_url, cert_path,
                                                                          db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "loneuser", "loneuser@example.com")
            pair = login(c, "loneuser")

            resp = c.get("/v1/users/999999999", headers=auth_header(pair))
            assert resp.status_code == 403


def test_admin_reads_own_record_with_email(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-admin-self") as (base_url, cert_path,
                                                                           db_path, log_path):
        with make_client(base_url, cert_path) as c:
            pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = ?",
                            (BOOTSTRAP_USERNAME,))
            admin_id = rows[0][0]

            resp = c.get(f"/v1/users/{admin_id}", headers=auth_header(pair))
            assert resp.status_code == 200
            body = resp.json()
            assert body["email"] == "harnessadmin@example.test"


def test_admin_reads_another_users_record_without_email(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-admin-other") as (base_url, cert_path,
                                                                            db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "subjectuser", "subjectuser@example.com")
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'subjectuser'")
            subject_id = rows[0][0]

            resp = c.get(f"/v1/users/{subject_id}", headers=auth_header(admin_pair))
            assert resp.status_code == 200
            body = resp.json()
            assert body["userId"] == str(subject_id)
            assert body["username"] == "subjectuser"
            # plan 4.8/8.2: absent entirely, not null, not empty string.
            assert "email" not in body


def test_admin_read_of_another_user_is_audited(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-admin-audit") as (base_url, cert_path,
                                                                            db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "auditsubject", "auditsubject@example.com")
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'auditsubject'")
            subject_id = rows[0][0]
            admin_rows = db_query(db_path, "SELECT user_id FROM users WHERE username = ?",
                                  (BOOTSTRAP_USERNAME,))
            admin_id = admin_rows[0][0]

            resp = c.get(f"/v1/users/{subject_id}", headers=auth_header(admin_pair))
            assert resp.status_code == 200

            events = db_query(
                db_path,
                "SELECT actor_user_id, target_user_id, outcome FROM audit_log "
                "WHERE event = 'ADMIN_USER_READ'",
            )
            assert events == [(admin_id, subject_id, "SUCCESS")]


def test_admin_reading_own_record_is_not_audited_as_admin_user_read(built_binary,
                                                                     tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-admin-self-audit") as (base_url,
                                                                                 cert_path, db_path,
                                                                                 log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = ?",
                            (BOOTSTRAP_USERNAME,))
            admin_id = rows[0][0]

            resp = c.get(f"/v1/users/{admin_id}", headers=auth_header(admin_pair))
            assert resp.status_code == 200

            events = db_query(db_path, "SELECT 1 FROM audit_log WHERE event = 'ADMIN_USER_READ'")
            assert events == []


def test_user_reading_own_record_is_not_audited_as_admin_user_read(built_binary,
                                                                    tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-self-audit") as (base_url, cert_path,
                                                                           db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "selfaudit", "selfaudit@example.com")
            pair = login(c, "selfaudit")
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'selfaudit'")
            user_id = rows[0][0]

            resp = c.get(f"/v1/users/{user_id}", headers=auth_header(pair))
            assert resp.status_code == 200

            events = db_query(db_path, "SELECT 1 FROM audit_log WHERE event = 'ADMIN_USER_READ'")
            assert events == []


def test_admin_only_account_still_reads_own_record(built_binary, tmp_path_factory):
    """plan D9: an ADMIN-only account (not holding USER) still passes the
    ownership branch, since ownership and role are independent grants and
    the ownership check never looks at roles at all. The bootstrap admin
    holds both USER and ADMIN (plan 6.7), so this needs a role-only
    account created directly via SQL -- there is no self-service path to
    ADMIN (plan 6.4), and that's by design."""
    with launch(built_binary, tmp_path_factory, "getuser-admin-only") as (base_url, cert_path,
                                                                           db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "adminonly", "adminonly@example.com")

            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    "INSERT INTO user_roles (user_id, role_id) "
                    "SELECT u.user_id, r.role_id FROM users u, roles r "
                    "WHERE u.username = 'adminonly' AND r.name = 'ADMIN'"
                )
                conn.execute(
                    "DELETE FROM user_roles WHERE user_id = "
                    "(SELECT user_id FROM users WHERE username = 'adminonly') AND role_id = "
                    "(SELECT role_id FROM roles WHERE name = 'USER')"
                )
                conn.commit()
            finally:
                conn.close()

            pair = login(c, "adminonly")
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'adminonly'")
            user_id = rows[0][0]

            resp = c.get(f"/v1/users/{user_id}", headers=auth_header(pair))
            assert resp.status_code == 200
            assert resp.json()["email"] == "adminonly@example.com"


# ---- IDOR suite (plan 8.4): ownership derives only from the verified
# token's sub -- never a body field, query parameter, header, or path
# trickery. ----

def test_idor_body_userid_ignored(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "idor-body") as (base_url, cert_path, db_path,
                                                                   log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "idorbodyuser", "idorbodyuser@example.com")
            register_and_activate(c, log_path, "idorbodytarget", "idorbodytarget@example.com")
            pair = login(c, "idorbodyuser")
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'idorbodyuser'")
            self_id = rows[0][0]
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'idorbodytarget'")
            target_id = rows[0][0]

            # A GET request with a body naming a different userId -- must
            # still resolve ownership from the path (which names self)
            # and/or be denied for the other id in the path, never grant
            # access to target_id via the body.
            resp = c.request("GET", f"/v1/users/{target_id}", headers=auth_header(pair),
                             json={"userId": self_id})
            assert resp.status_code == 403


def test_idor_query_param_userid_ignored(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "idor-query") as (base_url, cert_path, db_path,
                                                                    log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "idorqueryuser", "idorqueryuser@example.com")
            register_and_activate(c, log_path, "idorquerytarget", "idorquerytarget@example.com")
            pair = login(c, "idorqueryuser")
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'idorqueryuser'")
            self_id = rows[0][0]
            rows = db_query(db_path,
                            "SELECT user_id FROM users WHERE username = 'idorquerytarget'")
            target_id = rows[0][0]

            resp = c.get(f"/v1/users/{target_id}?userId={self_id}&userId={self_id}",
                        headers=auth_header(pair))
            assert resp.status_code == 403


def test_idor_x_user_id_header_ignored(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "idor-header") as (base_url, cert_path, db_path,
                                                                     log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "idorheaduser", "idorheaduser@example.com")
            register_and_activate(c, log_path, "idorheadtarget", "idorheadtarget@example.com")
            pair = login(c, "idorheaduser")
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'idorheaduser'")
            self_id = rows[0][0]
            rows = db_query(db_path, "SELECT user_id FROM users WHERE username = 'idorheadtarget'")
            target_id = rows[0][0]

            headers = auth_header(pair)
            headers["X-User-Id"] = str(self_id)
            resp = c.get(f"/v1/users/{target_id}", headers=headers)
            assert resp.status_code == 403


# plan 8.4's path-traversal-style case ("/v1/users/1001/../1002") is
# intentionally NOT tested here: httpx (like every RFC 3986-conforming
# client) collapses ".." dot-segments out of a URL before ever
# transmitting it, so a black-box request through this harness can never
# actually put those literal bytes on the wire -- there is nothing for the
# server to defend against at this layer that the client hasn't already
# erased. The property the plan cares about (http/router.h's {userId}
# pattern matches exactly one segment, so a 5-segment path never matches a
# 3-segment pattern regardless of what those segments spell) is verified
# with genuinely raw bytes instead, in
# tests/unit/test_http_router.c::test_path_traversal_style_id_does_not_match.


def test_userid_malformed_rejected(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "getuser-malformed") as (base_url, cert_path,
                                                                          db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "malformeduser", "malformeduser@example.com")
            pair = login(c, "malformeduser")

            for bad_id in ("abc", "1.5", "-", "+", " 1", "99999999999999999999"):
                resp = c.get(f"/v1/users/{bad_id}", headers=auth_header(pair))
                assert resp.status_code == 400, f"userId={bad_id!r} expected 400, got " \
                    f"{resp.status_code}"


def test_userid_boundary_values(built_binary, tmp_path_factory):
    """plan 7.3's explicit boundary set: 0, -1, INT64_MAX, INT64_MIN,
    INT64_MAX + 1. None of these are the caller's own id and none exist,
    so each is well-formed (parses) but denied -- 403, not 400 or 404."""
    with launch(built_binary, tmp_path_factory, "getuser-boundary") as (base_url, cert_path,
                                                                         db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "boundaryuser", "boundaryuser@example.com")
            pair = login(c, "boundaryuser")

            for well_formed_id in ("0", "-1", "9223372036854775807", "-9223372036854775808"):
                resp = c.get(f"/v1/users/{well_formed_id}", headers=auth_header(pair))
                assert resp.status_code == 403, f"userId={well_formed_id!r} expected 403, got " \
                    f"{resp.status_code}"

            # INT64_MAX + 1 overflows a 64-bit signed parse -- 400, not 403.
            resp = c.get("/v1/users/9223372036854775808", headers=auth_header(pair))
            assert resp.status_code == 400
