"""
GET /v1/admin/users/count and GET /v1/admin/users (plan 4.9, 4.10, 8.2):
ADMIN-only RBAC, keyset pagination correctness over a genuinely large
(2500+) seeded population, the no-email PII boundary, and plan 7.3's
input-validation boundary set for after_id/limit.
"""
import subprocess
import sys

from conftest import BOOTSTRAP_PASSWORD, BOOTSTRAP_USERNAME, REPO_ROOT, db_query, \
    latest_verification_token, launch
from client import make_client

PASSWORD = "correct horse battery staple"
SEED_TOOL = REPO_ROOT / "tools" / "seed_users.py"


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


def seed(db_path, count, start_index=1):
    result = subprocess.run(
        [sys.executable, str(SEED_TOOL), "--db-path", str(db_path), "--count", str(count),
         "--start-index", str(start_index)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"seed_users.py failed:\n{result.stdout}\n{result.stderr}"


def test_count_and_list_require_admin(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-rbac") as (base_url, cert_path, db_path,
                                                                    log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, log_path, "plainuser", "plainuser@example.com")
            user_pair = login(c, "plainuser")
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)

            # No token.
            assert c.get("/v1/admin/users/count").status_code == 401
            assert c.get("/v1/admin/users").status_code == 401

            # USER, not ADMIN.
            resp = c.get("/v1/admin/users/count", headers=auth_header(user_pair))
            assert resp.status_code == 403
            resp = c.get("/v1/admin/users", headers=auth_header(user_pair))
            assert resp.status_code == 403

            # ADMIN.
            resp = c.get("/v1/admin/users/count", headers=auth_header(admin_pair))
            assert resp.status_code == 200
            resp = c.get("/v1/admin/users", headers=auth_header(admin_pair))
            assert resp.status_code == 200


def test_count_matches_actual_row_count(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-count") as (base_url, cert_path, db_path,
                                                                     log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            seed(db_path, 50)

            resp = c.get("/v1/admin/users/count", headers=auth_header(admin_pair))
            assert resp.status_code == 200
            expected = db_query(db_path, "SELECT COUNT(*) FROM users")[0][0]
            assert resp.json()["count"] == expected == 51  # 50 seeded + bootstrap admin


def test_list_contains_no_email_field(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-noemail") as (base_url, cert_path, db_path,
                                                                       log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            seed(db_path, 10)

            resp = c.get("/v1/admin/users", headers=auth_header(admin_pair))
            assert resp.status_code == 200
            body = resp.json()
            assert len(body["users"]) > 0
            for user in body["users"]:
                assert "email" not in user
                assert set(user.keys()) == {"userId", "username"}


def test_list_userid_is_a_string(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-useridtype") as (base_url, cert_path,
                                                                         db_path, log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            seed(db_path, 5)

            resp = c.get("/v1/admin/users", headers=auth_header(admin_pair))
            body = resp.json()
            for user in body["users"]:
                assert isinstance(user["userId"], str)
            assert isinstance(body["nextAfterId"], str)


def test_after_id_beyond_last_user_returns_empty_list(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-beyond") as (base_url, cert_path, db_path,
                                                                      log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            seed(db_path, 5)

            resp = c.get("/v1/admin/users?after_id=999999999", headers=auth_header(admin_pair))
            assert resp.status_code == 200
            body = resp.json()
            assert body["users"] == []
            assert body["count"] == 0
            assert body["hasMore"] is False
            assert body["nextAfterId"] == "999999999"  # echoes the queried after_id


def test_limit_above_1000_is_clamped_not_honored(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-clamp") as (base_url, cert_path, db_path,
                                                                     log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            seed(db_path, 1200)

            resp = c.get("/v1/admin/users?limit=5000", headers=auth_header(admin_pair))
            assert resp.status_code == 200
            assert resp.json()["count"] == 1000


def test_limit_zero_negative_and_non_numeric_rejected(built_binary, tmp_path_factory):
    """Discussed with the user: limit <= 0 or non-numeric is 400, not
    silently coerced to the default or to an empty page -- a positive page
    size is a precondition for pagination to make forward progress."""
    with launch(built_binary, tmp_path_factory, "admin-badlimit") as (base_url, cert_path, db_path,
                                                                        log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)

            for bad_limit in ("0", "-1", "abc", "1.5"):
                resp = c.get(f"/v1/admin/users?limit={bad_limit}", headers=auth_header(admin_pair))
                assert resp.status_code == 400, f"limit={bad_limit!r} expected 400, got " \
                    f"{resp.status_code}"
                assert resp.json()["error"]["code"] == "BAD_REQUEST"


def test_after_id_non_numeric_rejected(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-badafter") as (base_url, cert_path, db_path,
                                                                        log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)

            resp = c.get("/v1/admin/users?after_id=notanumber", headers=auth_header(admin_pair))
            assert resp.status_code == 400
            assert resp.json()["error"]["code"] == "BAD_REQUEST"


def test_list_is_audited_as_admin_user_list(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-audit") as (base_url, cert_path, db_path,
                                                                     log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            admin_id = db_query(db_path, "SELECT user_id FROM users WHERE username = ?",
                                (BOOTSTRAP_USERNAME,))[0][0]

            resp = c.get("/v1/admin/users?after_id=0&limit=7", headers=auth_header(admin_pair))
            assert resp.status_code == 200

            events = db_query(
                db_path, "SELECT actor_user_id, event, outcome, detail FROM audit_log "
                "WHERE event = 'ADMIN_USER_LIST'",
            )
            assert len(events) == 1
            actor_id, event, outcome, detail = events[0]
            assert actor_id == admin_id
            assert outcome == "SUCCESS"
            assert '"after_id":0' in detail
            assert '"limit":7' in detail


def test_full_walk_over_2500_users_visits_every_row_exactly_once(built_binary, tmp_path_factory):
    with launch(built_binary, tmp_path_factory, "admin-fullwalk") as (base_url, cert_path, db_path,
                                                                        log_path):
        with make_client(base_url, cert_path) as c:
            admin_pair = login(c, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
            seed(db_path, 2500)

            total = db_query(db_path, "SELECT COUNT(*) FROM users")[0][0]
            assert total == 2501  # 2500 seeded + bootstrap admin

            headers = auth_header(admin_pair)
            seen_ids = []
            after_id = "0"
            pages = []
            while True:
                resp = c.get(f"/v1/admin/users?after_id={after_id}&limit=1000", headers=headers)
                assert resp.status_code == 200
                body = resp.json()
                pages.append(body)
                seen_ids.extend(u["userId"] for u in body["users"])
                if not body["hasMore"]:
                    break
                after_id = body["nextAfterId"]
                assert len(pages) <= 10, "runaway pagination loop"

            # Exactly three pages: 1000, 1000, 501.
            assert [len(p["users"]) for p in pages] == [1000, 1000, 501]
            assert pages[0]["hasMore"] is True
            assert pages[1]["hasMore"] is True
            assert pages[2]["hasMore"] is False

            # Every row exactly once, no gaps, no duplicates.
            assert len(seen_ids) == len(set(seen_ids)) == total

            expected_ids = {str(row[0]) for row in db_query(db_path, "SELECT user_id FROM users")}
            assert set(seen_ids) == expected_ids

            # Strictly ascending overall.
            seen_ints = [int(i) for i in seen_ids]
            assert seen_ints == sorted(seen_ints)

            # Stable across a repeated call to the same page.
            resp_again = c.get("/v1/admin/users?after_id=0&limit=1000", headers=headers)
            assert resp_again.json()["users"] == pages[0]["users"]
