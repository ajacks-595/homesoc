"""Administrative endpoints require the 'admin' role (L7).

The first user (created via /setup) is admin. Subsequent users default to
'user' and must be denied the admin-only surface (user mgmt, host-config writes,
home-API token, backups, audit log, shared API keys) while keeping the normal
analyst surface.
"""
import pytest

import auth


@pytest.fixture
def app(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    auth._login_fails.clear()
    from app import create_app
    a = create_app()
    a.config["TESTING"] = True
    return a


def _admin_client(app):
    c = app.test_client()
    c.post("/setup", data={"username": "admin", "password": "supersecret"})
    return c


def _make_user_and_login(app, admin_client):
    # admin creates a non-admin user, then we log in as that user on a fresh client
    r = admin_client.post("/api/users", json={
        "username": "analyst", "password": "analystpass", "role": "user"})
    assert r.status_code == 200, r.get_json()
    c = app.test_client()
    c.post("/login", data={"username": "analyst", "password": "analystpass"})
    return c


ADMIN_GET = ["/api/users", "/api/audit-log", "/api/settings/home-api",
             "/api/backup/history"]


def test_admin_can_reach_admin_endpoints(app):
    c = _admin_client(app)
    for path in ADMIN_GET:
        assert c.get(path).status_code == 200, path


def test_non_admin_denied_admin_endpoints(app):
    admin = _admin_client(app)
    user = _make_user_and_login(app, admin)
    # confirm the analyst is actually logged in
    assert user.get("/api/me").status_code == 200
    for path in ADMIN_GET:
        r = user.get(path)
        assert r.status_code == 403, f"{path} should be admin-only, got {r.status_code}"
        assert "admin" in r.get_json()["error"].lower()
    # mutating admin routes too
    assert user.post("/api/users", json={"username": "x", "password": "longenough"}).status_code == 403
    assert user.post("/api/host-config", json={"wazuh_user": "z"}).status_code == 403
    assert user.get("/api/backup/download/config").status_code == 403


def test_non_admin_keeps_analyst_surface(app):
    admin = _admin_client(app)
    user = _make_user_and_login(app, admin)
    # Normal analyst endpoints stay available to a 'user' role
    assert user.get("/api/alerts").status_code == 200
    assert user.get("/api/dashboard/metrics").status_code == 200
    assert user.get("/api/fp/list").status_code == 200
