"""GET /api/webhooks must never leak any of the secret URL path (L1).

Webhook URLs embed their token in the path/query; the list view should expose
only the (non-secret) host as a hint.
"""
import pytest


@pytest.fixture
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    from app import create_app
    a = create_app()
    a.config["TESTING"] = True
    with a.test_client() as c:
        c.post("/setup", data={"username": "admin", "password": "supersecret"})
        yield c


def test_webhook_list_hides_secret_path(client):
    secret = "SECRETTOKEN1234567890"
    r = client.post("/api/webhooks", json={
        "name": "mm", "platform": "mattermost",
        "url": f"http://10.0.0.5/hooks/{secret}"})
    assert r.status_code == 200, r.get_json()

    r = client.get("/api/webhooks")
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert secret not in text, "decrypted webhook secret leaked in list view"
    # No trailing-fragment leak either (old behaviour returned the last 6 chars)
    assert secret[-6:] not in text
    hint = r.get_json()["data"][0]["url_hint"]
    assert "10.0.0.5" in hint and "hooks" not in hint
