"""User role is validated against a fixed set server-side (B9)."""
import pytest


@pytest.fixture
def auth_client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        c.post("/setup", data={"username": "admin", "password": "supersecret"})
        yield c


def test_invalid_role_rejected(auth_client):
    r = auth_client.post("/api/users", json={
        "username": "bob", "password": "longenough", "role": "<img src=x>"})
    assert r.status_code == 400
    assert "role" in r.get_json()["error"]


def test_valid_roles_accepted(auth_client):
    import database as db
    for role in ("user", "admin"):
        r = auth_client.post("/api/users", json={
            "username": f"u_{role}", "password": "longenough", "role": role})
        assert r.status_code == 200, role
    assert db.get_user_by_username("u_admin")["role"] == "admin"
    assert db.get_user_by_username("u_user")["role"] == "user"


def test_role_defaults_to_user(auth_client):
    import database as db
    r = auth_client.post("/api/users", json={"username": "norole", "password": "longenough"})
    assert r.status_code == 200
    assert db.get_user_by_username("norole")["role"] == "user"
