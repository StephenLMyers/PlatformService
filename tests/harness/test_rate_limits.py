"""
Register/login/password-change throttling (plan 3.5, 7.4, 4.7). Every test
here launches its own dedicated instance with dev_mode OFF (production
throttle enforcement path) and small, deterministic per-minute budgets
overridden via env -- small enough to trip in a handful of requests, no
sleeping required (refill-over-time is already covered deterministically
at the unit level, tests/unit/test_ratelimit.c; this file is about
*integration*: are the right endpoints wired to the right buckets with the
right keys).
"""
import time

from conftest import db_query, verification_token_from_outbox, launch
from client import make_client

PASSWORD = "correct horse battery staple"


def register(client, username, email, password=PASSWORD):
    return client.post("/v1/auth/register", json={
        "username": username, "email": email, "password": password,
    })


def register_and_activate(client, db_path, username, email, password=PASSWORD):
    resp = register(client, username, email, password)
    assert resp.status_code == 202, resp.text
    # SQL escape hatch (plan 15.3 #1), not the dev_mode log line -- these
    # tests run with PS_DEV_MODE=false for real rate-limit enforcement,
    # which also turns off the log-line escape hatch that needs it.
    token = verification_token_from_outbox(db_path, email)
    resp = client.post("/v1/auth/verify", json={"token": token})
    assert resp.status_code == 200, resp.text


def login(client, username, password=PASSWORD):
    return client.post("/v1/auth/login", json={"username": username, "password": password})


def launch_production(built_binary, tmp_path_factory, name, env_overrides):
    """dev_mode explicitly OFF -- launch()'s base env turns it on for
    every other harness test (plan 15.2/16.2); these tests need the real,
    unrelaxed throttle path."""
    overrides = {"PS_DEV_MODE": "false"}
    overrides.update(env_overrides)
    return launch(built_binary, tmp_path_factory, name, env_overrides=overrides)


def test_register_trips_per_ip_limit(built_binary, tmp_path_factory):
    with launch_production(built_binary, tmp_path_factory, "rl-register-ip",
                           {"PS_RATELIMIT_REGISTER": "3", "PS_RATELIMIT_REGISTER_GLOBAL": "1000"}) \
            as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            for i in range(3):
                resp = register(c, f"riplim{i}", f"riplim{i}@example.com")
                assert resp.status_code == 202, f"attempt {i} unexpectedly throttled: {resp.text}"

            resp = register(c, "riplim3", "riplim3@example.com")
            assert resp.status_code == 429
            assert resp.json()["error"]["code"] == "RATE_LIMITED"


def test_register_limit_consumed_even_by_invalid_requests(built_binary, tmp_path_factory):
    """The rate-limit check runs before body parsing/validation (cheapest,
    most decisive check first) -- a malformed request still consumes a
    token, so an attacker can't dodge the budget by sending garbage."""
    with launch_production(built_binary, tmp_path_factory, "rl-register-invalid",
                           {"PS_RATELIMIT_REGISTER": "2", "PS_RATELIMIT_REGISTER_GLOBAL": "1000"}) \
            as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            resp = c.post("/v1/auth/register", json={"username": "onlyusername"})
            assert resp.status_code == 400

            resp = c.post("/v1/auth/register", json={})
            assert resp.status_code == 400

            # Budget (2) already spent by the two invalid requests above.
            resp = register(c, "afterinvalid", "afterinvalid@example.com")
            assert resp.status_code == 429


def test_register_trips_global_limit_across_different_ips(built_binary, tmp_path_factory):
    """A per-IP budget alone can't catch many distinct IPs each staying
    under their own limit -- the global bucket exists for exactly that
    (plan 7.4). Can't literally originate from different IPs in this
    harness, but the global bucket is keyed independently of IP, so
    driving it to exhaustion via one client still proves it's enforced as
    its own, separate dimension from the per-IP one (set very high here so
    only the global bucket can be the one that trips)."""
    with launch_production(built_binary, tmp_path_factory, "rl-register-global",
                           {"PS_RATELIMIT_REGISTER": "1000", "PS_RATELIMIT_REGISTER_GLOBAL": "3"}) \
            as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            for i in range(3):
                resp = register(c, f"rglobal{i}", f"rglobal{i}@example.com")
                assert resp.status_code == 202, f"attempt {i} unexpectedly throttled: {resp.text}"

            resp = register(c, "rglobal3", "rglobal3@example.com")
            assert resp.status_code == 429


def test_login_trips_per_username_limit(built_binary, tmp_path_factory):
    with launch_production(
        built_binary, tmp_path_factory, "rl-login-username",
        {"PS_RATELIMIT_LOGIN_USERNAME": "3", "PS_RATELIMIT_LOGIN": "1000"},
    ) as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, db_path, "loginlimuser", "loginlimuser@example.com")

            for i in range(3):
                resp = login(c, "loginlimuser", password="wrong password")
                assert resp.status_code == 401, f"attempt {i} unexpectedly throttled: {resp.text}"

            # Budget exhausted -- even the *correct* password now gets 429,
            # not 200, matching account-lockout's own "don't let a correct
            # password bypass a triggered defense" property.
            resp = login(c, "loginlimuser")
            assert resp.status_code == 429
            assert resp.json()["error"]["code"] == "RATE_LIMITED"


def test_login_per_username_key_is_case_insensitive(built_binary, tmp_path_factory):
    with launch_production(
        built_binary, tmp_path_factory, "rl-login-case",
        {"PS_RATELIMIT_LOGIN_USERNAME": "2", "PS_RATELIMIT_LOGIN": "1000"},
    ) as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, db_path, "caseuser", "caseuser@example.com")

            assert login(c, "CaseUser", password="wrong").status_code == 401
            assert login(c, "CASEUSER", password="wrong").status_code == 401
            # Same bucket as the two attempts above, regardless of typed case.
            resp = login(c, "caseuser")
            assert resp.status_code == 429


def test_different_usernames_have_independent_login_budgets(built_binary, tmp_path_factory):
    with launch_production(
        built_binary, tmp_path_factory, "rl-login-independent",
        {"PS_RATELIMIT_LOGIN_USERNAME": "2", "PS_RATELIMIT_LOGIN": "1000"},
    ) as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, db_path, "indepuserone", "indepuserone@example.com")
            register_and_activate(c, db_path, "indeputertwo", "indeputertwo@example.com")

            assert login(c, "indepuserone", password="wrong").status_code == 401
            assert login(c, "indepuserone", password="wrong").status_code == 401
            assert login(c, "indepuserone").status_code == 429  # exhausted

            # indeputertwo's own budget is untouched.
            assert login(c, "indeputertwo").status_code == 200


def test_password_change_shares_login_username_counter(built_binary, tmp_path_factory):
    """plan 4.7: 'rate-limited on the same counter as login' -- exhausting
    the budget via login must also throttle password-change for the same
    account, and vice versa."""
    with launch_production(
        built_binary, tmp_path_factory, "rl-shared-counter",
        {"PS_RATELIMIT_LOGIN_USERNAME": "3", "PS_RATELIMIT_LOGIN": "1000"},
    ) as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, db_path, "shareduser", "shareduser@example.com")
            pair = login(c, "shareduser").json()

            # Spend the budget via login...
            assert login(c, "shareduser", password="wrong").status_code == 401
            assert login(c, "shareduser", password="wrong").status_code == 401

            # ...and password-change for the same account is now throttled,
            # without ever calling password-change before this.
            resp = c.post(
                "/v1/auth/password",
                json={"current_password": PASSWORD, "new_password": "a brand new passphrase"},
                headers={"Authorization": f"Bearer {pair['access_token']}"},
            )
            assert resp.status_code == 429
            assert resp.json()["error"]["code"] == "RATE_LIMITED"


def test_login_trips_per_ip_limit_across_different_usernames(built_binary, tmp_path_factory):
    with launch_production(
        built_binary, tmp_path_factory, "rl-login-ip",
        {"PS_RATELIMIT_LOGIN": "3", "PS_RATELIMIT_LOGIN_USERNAME": "1000"},
    ) as (base_url, cert_path, db_path, log_path):
        with make_client(base_url, cert_path) as c:
            register_and_activate(c, db_path, "ipuserone", "ipuserone@example.com")
            register_and_activate(c, db_path, "ipusertwo", "ipusertwo@example.com")
            register_and_activate(c, db_path, "ipuserthree", "ipuserthree@example.com")
            register_and_activate(c, db_path, "ipuserfour", "ipuserfour@example.com")

            # All from the same client (same peer IP) -- 3 different
            # usernames, each with its own untouched per-username budget,
            # but the single shared per-IP budget (3) is exhausted by the
            # third attempt regardless of which username each one names.
            assert login(c, "ipuserone").status_code == 200
            assert login(c, "ipusertwo").status_code == 200
            assert login(c, "ipuserthree").status_code == 200
            resp = login(c, "ipuserfour")
            assert resp.status_code == 429


def test_resend_relaxed_interval_under_dev_mode(built_binary, tmp_path_factory):
    """plan 15.2/16.2: dev_mode shrinks resend's interval by a documented,
    fixed factor rather than removing the throttle -- confirms it's
    actually wired, not just declared. PS_RESEND_MIN_INTERVAL_S=40 under
    dev_mode's /20 relaxation divides to 2s.

    time(NULL) has 1-second resolution (see gotchas.md's phase-6 entry on
    this exact pitfall in the un-relaxed test) -- sleeping only just past
    the relaxed window risks the registration and resend timestamps
    floor-rounding to the same or an adjacent wall-clock second depending
    on alignment. Sleeping comfortably past window + 1s of slop avoids it
    deterministically rather than relying on lucky timing.
    """
    with launch(built_binary, tmp_path_factory, "rl-resend-dev-relaxed",
               env_overrides={"PS_RESEND_MIN_INTERVAL_S": "40"}) as (base_url, cert_path, db_path,
                                                                       log_path):
        with make_client(base_url, cert_path) as c:
            resp = register(c, "resenddevuser", "resenddevuser@example.com")
            assert resp.status_code == 202

            time.sleep(3.2)
            resp = c.post("/v1/auth/resend-verification", json={"email": "resenddevuser@example.com"})
            assert resp.status_code == 202
            # A new token must actually have been issued -- the throttled
            # path returns the identical 202 but sends nothing new, so
            # check the outbox grew instead of trusting the status alone.
            count = db_query(db_path, "SELECT COUNT(*) FROM dev_outbox")[0][0]
            assert count == 2
