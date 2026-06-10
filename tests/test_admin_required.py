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


def test_pipeline_run_admin_only(app):
    admin = _admin_client(app)
    user = _make_user_and_login(app, admin)
    # collect/analyse/weekly execute shell scripts on claude-dev → admin-only
    assert user.post("/api/pipeline/run", json={"kind": "collect"}).status_code == 403
    assert admin.post("/api/pipeline/run", json={"kind": "nonsense"}).status_code == 400


def test_settings_page_hides_admin_cards_for_non_admin(app):
    admin = _admin_client(app)
    user = _make_user_and_login(app, admin)
    admin_html = admin.get("/settings").get_data(as_text=True)
    user_html = user.get("/settings").get_data(as_text=True)
    # Admin sees the admin cards; the analyst does not.
    for marker in ('id="host-config-card"', 'id="users-table"', 'id="audit-table"',
                   'data-act="pipelineRun"'):
        assert marker in admin_html, marker
        assert marker not in user_html, f"non-admin should not see {marker}"
    # Shared cards (2FA, theme) remain for both.
    assert 'id="twofa-status"' in user_html
