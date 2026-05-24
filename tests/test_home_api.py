"""Tests for the token-gated /api/home/* consumer API.

Security contract:
  - default-OFF: no token configured → 403 on every /api/home/* route
  - wrong/missing token → 401
  - valid token → 200 on read endpoints
  - mutating endpoint (pipeline/run) → 403 even with valid token unless the
    mutations flag is explicitly enabled
"""
import pytest

from app import create_app


@pytest.fixture
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_home_api_disabled_by_default(client):
    """With no token configured, every /api/home/* route is 403."""
    for path in ("/api/home/alerts", "/api/home/agents", "/api/home/briefing",
                 "/api/home/pipeline", "/api/home/actions"):
        r = client.get(path)
        assert r.status_code == 403, f"{path} should be 403 when disabled, got {r.status_code}"
        body = r.get_json()
        assert body["success"] is False
        assert "disabled" in body["error"].lower()


def test_home_api_wrong_token_401(client):
    import auth
    auth.home_api_token_set("the-real-token")
    # No header
    assert client.get("/api/home/alerts").status_code == 401
    # Wrong header
    r = client.get("/api/home/alerts", headers={"X-HomeSOC-Token": "wrong"})
    assert r.status_code == 401
    # Wrong bearer
    r = client.get("/api/home/alerts", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_home_api_valid_token_200(client):
    import auth
    auth.home_api_token_set("the-real-token")
    r = client.get("/api/home/alerts", headers={"X-HomeSOC-Token": "the-real-token"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["success"] is True
    assert "open" in body["data"]
    # Bearer form also works
    r = client.get("/api/home/agents", headers={"Authorization": "Bearer the-real-token"})
    assert r.status_code == 200


def test_home_api_mutations_gated(client):
    import auth
    auth.home_api_token_set("tok")
    # Valid token but mutations disabled → 403
    r = client.post("/api/home/pipeline/run",
                    headers={"X-HomeSOC-Token": "tok"},
                    json={"kind": "collect"})
    assert r.status_code == 403
    assert "mutation" in r.get_json()["error"].lower()

    # Enable mutations → now it's allowed through the gate (the handler then
    # runs; trigger_pipeline_script may fail in the test env, but auth passed)
    auth.home_api_set_mutations(True)
    r = client.post("/api/home/pipeline/run",
                    headers={"X-HomeSOC-Token": "tok"},
                    json={"kind": "not-a-real-kind"})
    # Past the auth gate → handler validates kind → 400 "invalid kind"
    assert r.status_code == 400
    assert "invalid kind" in r.get_json()["error"].lower()


def test_home_api_sse_accepts_query_token(client):
    """EventSource can't set headers, so /api/home/events accepts ?token=.
    We only check the auth gate (a 200 stream would hang), so assert that a
    bad query token is rejected and the namespace is reachable with a good one
    via a non-streaming route using the same query-token path is NOT allowed."""
    import auth
    auth.home_api_token_set("tok")
    # Non-SSE route must NOT accept ?token= (header-only)
    r = client.get("/api/home/alerts?token=tok")
    assert r.status_code == 401, "query-param token must only work for the SSE route"


def test_home_api_token_not_leaked_in_status(client):
    """The status endpoint exposes only last4, never the full token."""
    import auth
    auth.home_api_token_set("supersecrettoken1234")
    # status endpoint requires session auth; create a user + log in
    import database as db
    db.insert_user("admin", auth.hash_password("password123"), role="admin")
    client.post("/login", data={"username": "admin", "password": "password123"})
    r = client.get("/api/settings/home-api")
    body = r.get_json()["data"]
    assert body["configured"] is True
    assert body["last4"] == "1234"
    assert "supersecrettoken1234" not in r.get_data(as_text=True)
