"""CSP: script-src is nonce-gated (no 'unsafe-inline'), and rendered inline
<script> blocks carry the matching per-request nonce (F7)."""
import re

import pytest


@pytest.fixture
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _script_src(csp):
    return next(p.strip() for p in csp.split(";") if p.strip().startswith("script-src"))


def test_script_src_uses_nonce_not_unsafe_inline(client):
    csp = client.get("/login").headers["Content-Security-Policy"]
    seg = _script_src(csp)
    assert "'nonce-" in seg
    assert "'unsafe-inline'" not in seg


def test_inline_script_nonce_matches_header(client):
    client.post("/setup", data={"username": "admin", "password": "supersecret"})
    r = client.get("/")   # dashboard, now authenticated, has an inline init script
    csp = r.headers["Content-Security-Policy"]
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp).group(1)
    body = r.get_data(as_text=True)
    assert f'<script nonce="{nonce}">' in body          # inline script carries the nonce
    assert "<script src=" in body                        # external scripts unchanged ('self')


def test_nonce_differs_per_request(client):
    a = re.search(r"'nonce-([A-Za-z0-9_-]+)'",
                  client.get("/login").headers["Content-Security-Policy"]).group(1)
    b = re.search(r"'nonce-([A-Za-z0-9_-]+)'",
                  client.get("/login").headers["Content-Security-Policy"]).group(1)
    assert a != b
