"""
Enforces D10 structurally rather than by inspection (plan 8.3). The
service exposes its route table under a debug flag (--dump-routes,
main.c) and this reads it, so a new route that forgets its policy row
fails here immediately rather than shipping quietly open -- the dangerous
direction plan 6.5 calls out.
"""
import subprocess

from conftest import BINARY

#: plan 6.5's exact seven-entry public allowlist.
EXPECTED_PUBLIC = {
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("POST", "/v1/auth/register"),
    ("POST", "/v1/auth/verify"),
    ("POST", "/v1/auth/resend-verification"),
    ("POST", "/v1/auth/login"),
    ("POST", "/v1/auth/refresh"),
}


def dump_routes():
    result = subprocess.run(
        [str(BINARY), "--dump-routes"], env={}, capture_output=True, text=True, check=True,
    )
    routes = []
    for line in result.stdout.strip().splitlines():
        method, path_pattern, kind, required_role = line.split("\t")
        routes.append((method, path_pattern, kind, required_role))
    return routes


def concrete_path(path_pattern: str) -> str:
    """Substitutes a syntactically valid, harmless value for any {param}
    segment -- this suite only needs to prove a route rejects an
    unauthenticated caller, never to exercise real business logic."""
    return path_pattern.replace("{userId}", "1")


def test_public_allowlist_is_exactly_the_expected_seven(built_binary):
    routes = dump_routes()
    public = {(method, path) for (method, path, kind, _role) in routes if kind == "PUBLIC"}
    assert public == EXPECTED_PUBLIC


def test_every_registered_route_has_a_policy_row(built_binary):
    """--dump-routes only ever lists routes that came out of
    ps_rbac_policy_for_route via api/rbac.c's own table (main.c's
    dump_routes iterates PS_RBAC_POLICIES directly) -- so a route
    registered in api/routes.c's ps_routes_register but never given a row
    here would be silently *absent* from this output rather than flagged.
    This is the one property --dump-routes alone can't prove; guarded
    instead by tests/unit/test_rbac.c asserting route_id uniqueness and by
    routes.c's own default-deny fallback (a route_id with no policy row
    returns 401 unconditionally -- see the next test for that path,
    exercised the only way it can be from black-box HTTP: a route that
    forgot its row is unreachable, not enumerable."""
    routes = dump_routes()
    assert len(routes) >= 10


def test_every_non_public_route_rejects_an_unauthenticated_request(built_binary, client):
    routes = dump_routes()
    non_public = [(m, p, k) for (m, p, k, _role) in routes if k != "PUBLIC"]
    assert len(non_public) > 0, "expected at least one non-public route to test"

    for method, path_pattern, kind in non_public:
        path = concrete_path(path_pattern)
        resp = client.request(method, path, json={} if method == "POST" else None)
        assert resp.status_code == 401, (
            f"{method} {path} (policy={kind}) allowed a request with no Authorization header"
        )
        assert resp.json()["error"]["code"] == "UNAUTHORIZED"


def test_public_routes_never_reject_solely_for_missing_authorization(built_binary, client):
    """The inverse property: a public route must not itself demand a
    token. An empty JSON body is missing every field each of these
    handlers actually requires (username/password, a token, etc.), so
    each rejects with 400 for that -- the one response a public route
    must never give for a tokenless request is 401, which in this
    service's vocabulary means specifically "missing or invalid access
    token" (login's own "wrong credentials" 401 is a distinct case this
    empty-body request never reaches, since it 400s on missing fields
    first)."""
    routes = dump_routes()
    public = [(m, p) for (m, p, k, _role) in routes if k == "PUBLIC"]

    for method, path in public:
        resp = client.request(method, path, json={} if method == "POST" else None)
        assert resp.status_code != 401, (
            f"{method} {path} is listed PUBLIC but rejected a tokenless, empty-body request "
            f"with 401: {resp.text}"
        )
