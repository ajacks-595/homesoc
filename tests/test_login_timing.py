"""Login does equal PBKDF2 work whether or not the username exists (M4).

Removes the account-enumeration timing oracle: a non-existent user must still
trigger a password verify (against a dummy hash), so the response time can't
distinguish valid usernames.
"""
import auth


def test_dummy_hash_present_and_valid():
    assert auth._DUMMY_PASSWORD_HASH.startswith("pbkdf2$")
    # It must not actually match a guessable password.
    assert auth.verify_password("", auth._DUMMY_PASSWORD_HASH) is False


def test_verify_called_for_unknown_user(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    auth._login_fails.clear()
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/setup", data={"username": "admin", "password": "supersecret"})
    c.get("/logout")

    calls = []
    real_verify = auth.verify_password
    monkeypatch.setattr(auth, "verify_password",
                        lambda pw, stored: calls.append(stored) or real_verify(pw, stored))

    # Unknown username → must still call verify_password (against the dummy hash)
    r = c.post("/login", data={"username": "nobody-here", "password": "whatever"})
    assert r.status_code == 401
    assert calls, "verify_password was not called for an unknown user (timing oracle)"
    assert auth._DUMMY_PASSWORD_HASH in calls
