"""PBKDF2 iteration target (600k) + transparent rehash-on-login of old hashes."""
import base64
import hashlib
import secrets

import auth


def _make_hash(pw: str, iters: int) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return f"pbkdf2${iters}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def test_target_is_owasp_minimum():
    assert auth._PBKDF2_ITERATIONS == 600_000


def test_new_hashes_use_target_iterations():
    parts = auth.hash_password("whatever").split("$")
    assert int(parts[1]) == 600_000


def test_needs_rehash():
    assert auth.needs_rehash(_make_hash("x", 200_000)) is True
    assert auth.needs_rehash(_make_hash("x", 600_000)) is False
    assert auth.needs_rehash(_make_hash("x", 1_000_000)) is False
    assert auth.needs_rehash("not-a-hash") is False
    assert auth.needs_rehash("") is False


def test_legacy_hash_still_verifies():
    legacy = _make_hash("supersecret", 200_000)
    assert auth.verify_password("supersecret", legacy)
    assert not auth.verify_password("wrong", legacy)


def test_login_transparently_upgrades_legacy_hash(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    import database
    from app import create_app

    auth._login_fails.clear()
    database.insert_user("legacy", _make_hash("supersecret", 200_000), role="admin")

    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        r = c.post("/login", data={"username": "legacy", "password": "supersecret"},
                   follow_redirects=False)
        assert r.status_code in (302, 303), r.status_code  # success → redirect

    row = database.get_user_by_username("legacy")
    iters = int(row["password_hash"].split("$")[1])
    assert iters == 600_000, f"expected upgrade to 600k, got {iters}"
    # and the upgraded hash still authenticates the same password
    assert auth.verify_password("supersecret", row["password_hash"])
