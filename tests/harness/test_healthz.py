"""Black-box tests for GET /healthz (plan 8.1, api/health_api.c)."""


def test_returns_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_headers(client):
    resp = client.get("/healthz")
    assert resp.headers["content-type"] == "application/json"
    assert resp.headers["x-content-type-options"] == "nosniff"
    # healthz is unauthenticated and carries no sensitive state -- unlike
    # error responses, it does not set no_store (src/api/health_api.c).
    assert "cache-control" not in resp.headers


def test_wrong_method_is_405(client):
    resp = client.post("/healthz")
    assert resp.status_code == 405
    assert resp.json()["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_unknown_path_is_404(client):
    resp = client.get("/no-such-route")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "NOT_FOUND"
