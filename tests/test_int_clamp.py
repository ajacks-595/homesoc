"""Unbounded integer query params are clamped to a maximum (L3).

A non-integer still 400s (see test_int_args); here we assert that an absurd
in-range value is clamped rather than driving an unbounded allocation.
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


def test_int_arg_clamps_to_maximum(client):
    import app as app_module
    with client.application.test_request_context("/x?days=100000000"):
        assert app_module.int_arg("days", 7, minimum=1, maximum=365) == 365
    with client.application.test_request_context("/x?days=-5"):
        assert app_module.int_arg("days", 7, minimum=1, maximum=365) == 1


def test_dns_sync_huge_days_does_not_explode(client, monkeypatch):
    # Capture the value the route hands to sync_dns_last_n — must be capped at 90.
    import sync
    seen = {}
    monkeypatch.setattr(sync, "sync_dns_last_n",
                        lambda n: seen.setdefault("n", n) or [{"day": "x"}])
    monkeypatch.setattr(sync, "_adguard_configured", lambda: True)
    r = client.post("/api/dns/sync?days=100000000")
    assert r.status_code == 200
    assert seen["n"] == 90


def test_audit_limit_clamped(client):
    # Should not 500 / should return a normal payload even with an absurd limit.
    r = client.get("/api/audit-log?limit=99999999")
    assert r.status_code == 200
    assert r.get_json()["success"] is True
