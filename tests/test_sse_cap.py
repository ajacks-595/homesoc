"""The SSE endpoint (/api/home/events) caps concurrent streams so it can't
exhaust the waitress worker pool. We only exercise the 503 path — a successful
stream is an infinite generator that would hang the test client."""
import pytest

import app as app_module
import auth


@pytest.fixture
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    app = app_module.create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_sse_endpoint_503_when_slots_exhausted(client):
    # Enable the home API with a known token (the SSE route is token-gated).
    auth.home_api_token_set("testtoken")

    # Drain every slot so the next stream request is refused.
    drained = 0
    while app_module._sse_slots.acquire(blocking=False):
        drained += 1
    assert drained >= 1, "semaphore should have at least one slot"
    try:
        r = client.get("/api/home/events", headers={"X-HomeSOC-Token": "testtoken"})
        assert r.status_code == 503
        body = r.get_json()
        assert body["success"] is False
    finally:
        for _ in range(drained):
            app_module._sse_slots.release()


def test_sse_requires_token_before_cap(client):
    # No token presented → 401/403 from the home-API gate, never reaching the cap.
    auth.home_api_token_set("testtoken")
    r = client.get("/api/home/events")
    assert r.status_code in (401, 403)
