"""Smoke tests added by the `repo review` Phase 6 spec.

- All registered GET routes must respond with status <500 when called
  (auth required → 302/401 is fine; we just don't want server crashes).
- Every API endpoint must return the documented `{success, data, error}`
  JSON shape, even when the request is rejected for auth reasons.
"""
import json

import pytest

from app import create_app


@pytest.fixture
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# Routes that stream (Server-Sent Events / chunked generators) never return a
# complete response to the test client, so a plain GET would hang forever.
# Skip them in the route-enumeration smoke test.
STREAMING_ROUTES = {"/api/home/events"}


def _skip_route(rule) -> bool:
    if "GET" not in (rule.methods or set()):
        return True
    if "<" in rule.rule:          # needs a real path param value
        return True
    if rule.rule.startswith("/static"):
        return True
    if rule.rule in STREAMING_ROUTES:
        return True
    return False


def test_all_get_routes_non_5xx(client):
    """Every registered GET route should respond with status <500.

    Auth-protected routes returning 302/401 are expected and acceptable;
    we just want to confirm there are no Python exceptions or server
    crashes triggered by visiting any page. Streaming endpoints are skipped
    (they never return a complete response to the test client).
    """
    app = client.application
    failures = []
    for rule in app.url_map.iter_rules():
        if _skip_route(rule):
            continue
        try:
            r = client.get(rule.rule, follow_redirects=False)
        except Exception as e:  # noqa: BLE001
            failures.append((rule.rule, "exception", str(e)))
            continue
        if r.status_code >= 500:
            failures.append((rule.rule, r.status_code,
                             r.get_data(as_text=True)[:200]))
    assert not failures, f"{len(failures)} routes 5xx'd: {failures}"


def test_all_api_endpoints_return_documented_shape(client):
    """`/api/*` endpoints — even when 401-rejecting — must return
    `{success, data, error}` JSON.
    """
    app = client.application
    bad_shape = []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/"):
            continue
        # /api/home/* is a separate consumer API (jacknet-home) with its own
        # response contract — not the {success,data,error} dashboard shape.
        if rule.rule.startswith("/api/home/"):
            continue
        if "GET" not in (rule.methods or set()):
            continue
        if "<" in rule.rule:
            continue
        r = client.get(rule.rule, follow_redirects=False)
        # Auth middleware redirects to /login when no session — that's 401
        # for API paths (auth.login_required_globally), 302 otherwise.
        # In either case the response should be JSON-parseable for /api.
        try:
            body = json.loads(r.get_data(as_text=True))
        except json.JSONDecodeError:
            bad_shape.append((rule.rule, r.status_code, "not JSON"))
            continue
        # Documented shape: success / data / error
        if not all(k in body for k in ("success", "data", "error")):
            bad_shape.append((rule.rule, r.status_code, list(body.keys())))
    assert not bad_shape, f"{len(bad_shape)} endpoints off-spec: {bad_shape}"


def test_security_headers_present(client):
    """Security response headers are set on every response (added in
    response to the repo-review M1 finding)."""
    r = client.get("/login")
    for header in ("Content-Security-Policy", "X-Content-Type-Options",
                   "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"):
        assert header in r.headers, f"missing {header}"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"


def test_login_setup_static_are_public(client):
    """Auth-bypass endpoints must remain reachable without a session
    (so the first-run setup flow works)."""
    # /setup should redirect to /login when users exist (and DB is empty here,
    # so it should render directly with 200)
    r = client.get("/setup", follow_redirects=False)
    assert r.status_code in (200, 302)

    r = client.get("/login", follow_redirects=False)
    assert r.status_code == 200

    # /static/* is handled by Flask directly; if a file exists it's 200
    r = client.get("/static/css/main.css", follow_redirects=False)
    assert r.status_code == 200
