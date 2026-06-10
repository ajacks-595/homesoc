"""CSRF protection: cookie-authenticated mutating requests must carry a valid
X-CSRF-Token. Bearer-token (/api/home/*) and the login/setup forms are exempt.

Enforcement is gated off under TESTING so the rest of the suite can issue
cookie-only API calls; these tests opt in with CSRF_FORCE=True to exercise the
real path.
"""
import re

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
    a.config["CSRF_FORCE"] = True     # turn the real CSRF gate ON for this suite
    return a


def _admin_client(app):
    c = app.test_client()
    # /setup is a form POST and is CSRF-exempt (it establishes the session).
    r = c.post("/setup", data={"username": "admin", "password": "supersecret"})
    assert r.status_code in (302, 200)
    return c


def _token(client):
    r = client.get("/api/csrf")
    assert r.status_code == 200
    return r.get_json()["data"]["csrf_token"]


def test_mutating_request_without_token_is_blocked(app):
    c = _admin_client(app)
    r = c.post("/api/hosts", json={"ip": "10.0.0.42"})
    assert r.status_code == 403
    assert "csrf" in r.get_json()["error"].lower()


def test_mutating_request_with_token_succeeds(app):
    c = _admin_client(app)
    tok = _token(c)
    r = c.post("/api/hosts", json={"ip": "10.0.0.42"},
               headers={"X-CSRF-Token": tok})
    assert r.status_code == 200, r.get_json()


def test_wrong_token_is_blocked(app):
    c = _admin_client(app)
    _token(c)
    r = c.post("/api/hosts", json={"ip": "10.0.0.42"},
               headers={"X-CSRF-Token": "not-the-real-token"})
    assert r.status_code == 403


def test_get_requests_need_no_token(app):
    c = _admin_client(app)
    assert c.get("/api/alerts").status_code == 200
    assert c.get("/api/dashboard/metrics").status_code == 200


def test_login_form_is_exempt(app):
    # A wrong-credential login must reach the handler (401), not be CSRF-blocked.
    c = app.test_client()
    _admin_client(app)  # create the admin so the user table isn't empty
    c2 = app.test_client()
    r = c2.post("/login", data={"username": "admin", "password": "wrongpass"})
    assert r.status_code == 401  # handled by login, not a 403 CSRF rejection


def test_token_is_embedded_in_page_meta(app):
    c = _admin_client(app)
    html = c.get("/").get_data(as_text=True)
    m = re.search(r'name="csrf-token" content="([^"]+)"', html)
    assert m and len(m.group(1)) > 20
    # The embedded token is the one the API accepts.
    r = c.post("/api/hosts", json={"ip": "10.0.0.7"},
               headers={"X-CSRF-Token": m.group(1)})
    assert r.status_code == 200


def test_home_api_bearer_path_is_csrf_exempt(app, monkeypatch):
    # /api/home/* is gated by a bearer token, not the session cookie, so CSRF
    # does not apply. With mutations enabled, a POST with a valid home token and
    # NO csrf header must succeed.
    admin = _admin_client(app)
    tok = _token(admin)
    gen = admin.post("/api/settings/home-api/token", headers={"X-CSRF-Token": tok})
    home_token = gen.get_json()["data"]["token"]
    admin.post("/api/settings/home-api/mutations", json={"enabled": True},
               headers={"X-CSRF-Token": tok})
    anon = app.test_client()  # no session cookie at all
    r = anon.post("/api/home/pipeline/run", json={"kind": "collect"},
                  headers={"X-HomeSOC-Token": home_token})
    # Not a CSRF rejection; reaches the handler (which validates kind).
    assert r.status_code != 403 or "csrf" not in r.get_json().get("error", "").lower()
