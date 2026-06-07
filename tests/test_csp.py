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


PAGES = ["/", "/alerts", "/briefings", "/osint", "/fp-manager",
         "/actions", "/hosts", "/threat-intel", "/vulns", "/settings"]


def test_html_is_no_store_static_is_cacheable(client):
    """The per-request CSP nonce makes every HTML response unique, so HTML must
    be Cache-Control: no-store — otherwise a cached body's stale nonce gets its
    inline <script> blocked under a fresh CSP header (the /settings breakage,
    2026-06-07). Static assets must stay cacheable."""
    client.post("/setup", data={"username": "admin", "password": "supersecret"})
    for path in ("/", "/vulns", "/settings"):
        r = client.get(path)
        assert r.headers.get("Cache-Control") == "no-store", (path, r.headers.get("Cache-Control"))
    # a static asset keeps its own caching (no-store would defeat the point)
    s = client.get("/static/js/main.js")
    assert "no-store" not in (s.headers.get("Cache-Control") or "")


def test_pages_have_no_inline_handlers_and_nonced_scripts(client):
    """Every rendered page must be CSP-clean: no inline on* handlers (the nonce
    CSP would silently break them) and every inline <script> carries the
    request nonce. This is the static stand-in for the browser E2E."""
    client.post("/setup", data={"username": "admin", "password": "supersecret"})
    for path in PAGES:
        r = client.get(path)
        assert r.status_code == 200, (path, r.status_code)
        html = r.get_data(as_text=True)
        nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'",
                          r.headers["Content-Security-Policy"]).group(1)
        # inline event handlers would be blocked by the nonce CSP — there must be none
        assert not re.findall(r"\son[a-z]+=", html), (path, set(re.findall(r"\son[a-z]+=", html)))
        # every inline <script> (no src) must carry the matching nonce
        for m in re.finditer(r"<script(\s[^>]*)?>", html):
            attrs = m.group(1) or ""
            if "src=" in attrs:
                continue
            assert f'nonce="{nonce}"' in attrs, (path, attrs)


def test_nonce_differs_per_request(client):
    a = re.search(r"'nonce-([A-Za-z0-9_-]+)'",
                  client.get("/login").headers["Content-Security-Policy"]).group(1)
    b = re.search(r"'nonce-([A-Za-z0-9_-]+)'",
                  client.get("/login").headers["Content-Security-Policy"]).group(1)
    assert a != b
