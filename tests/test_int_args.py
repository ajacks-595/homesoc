"""Bad integer request params return 400 JSON, not an uncaught 500 (B8)."""
import pytest


@pytest.fixture
def auth_client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        c.post("/setup", data={"username": "admin", "password": "supersecret"})  # logs in
        yield c


def test_bad_page_returns_400(auth_client):
    r = auth_client.get("/api/alerts?page=abc")
    assert r.status_code == 400
    body = r.get_json()
    assert body["success"] is False and "integer" in body["error"]


def test_bad_min_level_returns_400(auth_client):
    assert auth_client.get("/api/alerts?min_level=xyz").status_code == 400


def test_valid_paging_ok(auth_client):
    r = auth_client.get("/api/alerts?page=2&per_page=10")
    assert r.status_code == 200 and r.get_json()["success"] is True


def test_bad_days_returns_400(auth_client):
    assert auth_client.post("/api/dns/sync?days=lots").status_code == 400


def test_webhook_bad_severity_returns_400(auth_client):
    # 10.0.0.5 is an IP literal → passes the SSRF check without DNS, so we reach
    # the severity_min parse.
    r = auth_client.post("/api/webhooks", json={
        "name": "w", "platform": "mattermost",
        "url": "http://10.0.0.5/hooks/x", "severity_min": "high"})
    assert r.status_code == 400
    assert "integer" in r.get_json()["error"]
