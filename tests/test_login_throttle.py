"""Login brute-force throttle (auth.login_throttle_check + /login integration)."""
import pytest

import auth


@pytest.fixture(autouse=True)
def _reset_throttle():
    auth._login_fails.clear()
    yield
    auth._login_fails.clear()


# ---- unit: the limiter ----------------------------------------------------

def test_not_locked_under_threshold():
    for _ in range(auth._LOGIN_MAX_PER_USER - 1):
        auth.login_record_failure("1.2.3.4", "alice")
    assert auth.login_throttle_check("1.2.3.4", "alice") == 0.0


def test_locks_per_username():
    for _ in range(auth._LOGIN_MAX_PER_USER):
        auth.login_record_failure("1.2.3.4", "alice")
    assert auth.login_throttle_check("1.2.3.4", "alice") > 0
    # case-insensitive username keying
    assert auth.login_throttle_check("1.2.3.4", "ALICE") > 0


def test_locks_per_ip_across_usernames():
    for i in range(auth._LOGIN_MAX_PER_IP):
        auth.login_record_failure("9.9.9.9", f"user{i}")
    # a brand-new username from the same IP is still locked (per-IP cap)
    assert auth.login_throttle_check("9.9.9.9", "brand-new") > 0


def test_success_clears_failures():
    for _ in range(auth._LOGIN_MAX_PER_USER):
        auth.login_record_failure("1.2.3.4", "alice")
    assert auth.login_throttle_check("1.2.3.4", "alice") > 0
    auth.login_record_success("1.2.3.4", "alice")
    assert auth.login_throttle_check("1.2.3.4", "alice") == 0.0


def test_window_expiry(monkeypatch):
    base = 1000.0
    monkeypatch.setattr(auth.time, "monotonic", lambda: base)
    for _ in range(auth._LOGIN_MAX_PER_USER):
        auth.login_record_failure("1.2.3.4", "alice")
    assert auth.login_throttle_check("1.2.3.4", "alice") > 0
    monkeypatch.setattr(auth.time, "monotonic", lambda: base + auth._LOGIN_WINDOW_S + 1)
    assert auth.login_throttle_check("1.2.3.4", "alice") == 0.0


# ---- integration: the /login route ----------------------------------------

@pytest.fixture
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")   # don't start background pollers
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        c.post("/setup", data={"username": "admin", "password": "supersecret"})
        yield c


def test_login_lockout_after_max_user_failures(client):
    auth._login_fails.clear()
    for _ in range(auth._LOGIN_MAX_PER_USER):
        r = client.post("/login", data={"username": "admin", "password": "wrong"})
        assert r.status_code == 401
    # now throttled — even the CORRECT password is refused while locked
    r = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert r.status_code == 429
    r = client.post("/login", data={"username": "admin", "password": "supersecret"})
    assert r.status_code == 429
