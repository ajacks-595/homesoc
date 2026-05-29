"""TOTP 2FA: enrollment, verification, disable, and the two-step login (F6)."""
import pyotp

import auth
import database as db


def test_totp_enroll_confirm_verify_disable(tmp_db):
    uid = db.insert_user("alice", auth.hash_password("longpassword"), role="admin")
    user = dict(db.get_user(uid))

    data = auth.totp_begin_enroll(user)
    assert data["otpauth_uri"].startswith("otpauth://")
    secret = data["secret"]

    # stored but not enabled until a code is confirmed
    assert auth.totp_verify(uid, pyotp.TOTP(secret).now()) is False
    assert auth.totp_confirm_enroll(uid, pyotp.TOTP(secret).now()) is True
    assert db.get_user(uid)["totp_enabled"] == 1

    assert auth.totp_verify(uid, pyotp.TOTP(secret).now()) is True
    assert auth.totp_verify(uid, "000000") is False

    # disabling requires a valid current code
    assert auth.totp_disable(uid, "000000") is False
    assert auth.totp_disable(uid, pyotp.TOTP(secret).now()) is True
    assert db.get_user(uid)["totp_enabled"] == 0


def test_two_step_login(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    from app import create_app
    auth._login_fails.clear()
    app = create_app()
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/setup", data={"username": "admin", "password": "supersecret"})

    # enroll + confirm 2FA via the API (client is authenticated from setup)
    secret = c.post("/api/2fa/enroll").get_json()["data"]["secret"]
    conf = c.post("/api/2fa/confirm", json={"code": pyotp.TOTP(secret).now()}).get_json()
    assert conf["success"] and conf["data"]["enabled"] is True

    c.get("/logout")

    # password step alone must NOT authenticate — it returns the TOTP form
    r = c.post("/login", data={"username": "admin", "password": "supersecret"})
    assert r.status_code == 200 and b"Authentication code" in r.data
    assert c.get("/api/me").status_code == 401

    # wrong code is rejected
    assert c.post("/login/2fa", data={"code": "000000"}).status_code == 401
    assert c.get("/api/me").status_code == 401

    # correct code completes login
    r = c.post("/login/2fa", data={"code": pyotp.TOTP(secret).now()}, follow_redirects=False)
    assert r.status_code in (302, 303)
    me = c.get("/api/me").get_json()
    assert me["success"] and me["data"]["totp_enabled"] is True


def test_confirm_rejects_bad_code(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/setup", data={"username": "admin", "password": "supersecret"})
    c.post("/api/2fa/enroll")
    r = c.post("/api/2fa/confirm", json={"code": "000000"})
    assert r.status_code == 400
    assert c.get("/api/2fa/status").get_json()["data"]["enabled"] is False
