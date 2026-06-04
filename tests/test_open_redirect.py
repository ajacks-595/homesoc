"""The post-login `next` redirect must stay same-origin (M1).

Guards against the open-redirect class, including the `next=/\\evil.com`
bypass: a leading slash then backslash slips past a naive startswith('//')
check, but browsers fold '\\' to '/', yielding '//evil.com' (off-origin).
"""
import auth


def test_safe_next_path_allows_same_origin_paths():
    assert auth.safe_next_path("/") == "/"
    assert auth.safe_next_path("/alerts") == "/alerts"
    assert auth.safe_next_path("/alerts?focus=12&x=1") == "/alerts?focus=12&x=1"
    assert auth.safe_next_path("/threat-intel#dns") == "/threat-intel#dns"


def test_safe_next_path_blocks_open_redirects():
    bad = [
        "//evil.com",            # protocol-relative
        "/\\evil.com",           # backslash → folds to //evil.com
        "/\\/evil.com",
        "https://evil.com",      # absolute
        "http://evil.com",
        "javascript:alert(1)",   # scheme
        "  //evil.com",          # leading whitespace then protocol-relative
        "\\evil.com",
        "evil.com",              # no leading slash → not same-origin
        "",
        None,
    ]
    for n in bad:
        assert auth.safe_next_path(n) == "/", f"{n!r} should be neutralised to '/'"


def test_login_redirect_uses_safe_next(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    auth._login_fails.clear()
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/setup", data={"username": "admin", "password": "supersecret"})
    c.get("/logout")
    r = c.post("/login",
               data={"username": "admin", "password": "supersecret",
                     "next": "/\\evil.com"},
               follow_redirects=False)
    assert r.status_code in (302, 303)
    loc = r.headers["Location"]
    assert "evil.com" not in loc, f"open redirect not blocked: {loc}"
    assert loc.endswith("/")
