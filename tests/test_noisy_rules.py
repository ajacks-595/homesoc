"""Noisy-rule detector: rank rules by volume, flag already-suppressed (F3)."""
from datetime import datetime, timezone

import pytest

import database as db


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _alert(wid, rule_id, level=5, desc="d"):
    return {"wazuh_id": wid, "timestamp": _now(), "agent_name": "h", "agent_ip": "10.0.0.1",
            "rule_id": rule_id, "rule_level": level, "rule_description": desc,
            "rule_groups": [], "full_log": "x", "location": "/l", "raw": {"rule": {"id": rule_id}}}


def test_noisy_rules_ranks_and_flags_suppressed(tmp_db):
    rows = [_alert(f"a{i}", "5710", desc="auth fail") for i in range(5)]
    rows += [_alert(f"b{i}", "1002", desc="syslog") for i in range(2)]
    db.insert_alerts_bulk(rows)
    db.insert_fp("5710", None, "noisy", "100001", "<x>")

    out = db.noisy_rules(days=7, limit=10)
    assert out[0]["rule_id"] == "5710" and out[0]["count"] == 5
    assert out[0]["suppressed"] is True
    by = {r["rule_id"]: r for r in out}
    assert by["1002"]["count"] == 2 and by["1002"]["suppressed"] is False


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


def test_noisy_rules_endpoint(auth_client):
    db.insert_alerts_bulk([_alert("z", "5710")])
    r = auth_client.get("/api/fp/noisy-rules")
    assert r.status_code == 200
    body = r.get_json()
    assert body["success"] and isinstance(body["data"], list)
    assert body["data"][0]["rule_id"] == "5710"
