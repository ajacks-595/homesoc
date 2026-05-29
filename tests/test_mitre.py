"""MITRE ATT&CK summary aggregation + technique filter (F2)."""
from datetime import datetime, timezone

import pytest

import database as db


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _alert(wid, mitre=None):
    raw = {"rule": {"id": "5710", "level": 10}}
    if mitre is not None:
        raw["rule"]["mitre"] = mitre
    return {"wazuh_id": wid, "timestamp": _now(), "agent_name": "h", "agent_ip": "10.0.0.1",
            "rule_id": "5710", "rule_level": 10, "rule_description": "d",
            "rule_groups": [], "full_log": "x", "location": "/l", "raw": raw}


def test_mitre_summary_aggregates(tmp_db):
    db.insert_alerts_bulk([
        _alert("a1", {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}),
        _alert("a2", {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}),
        _alert("a3", {"id": ["T1059"], "tactic": ["Execution"], "technique": ["Command and Scripting Interpreter"]}),
        _alert("a4", None),   # no mitre → not counted
    ])
    s = db.mitre_summary(days=7)
    assert s["alerts_with_mitre"] == 3
    tac = {t["name"]: t["count"] for t in s["tactics"]}
    assert tac["Credential Access"] == 2 and tac["Execution"] == 1
    tech = {t["name"]: t["count"] for t in s["techniques"]}
    assert tech["Brute Force"] == 2
    ids = {t["id"]: t["count"] for t in s["ids"]}
    assert ids["T1110"] == 2 and ids["T1059"] == 1


def test_query_alerts_mitre_filter(tmp_db):
    db.insert_alerts_bulk([
        _alert("m1", {"id": ["T1110"], "technique": ["Brute Force"]}),
        _alert("m2", {"id": ["T1059"], "technique": ["Command and Scripting Interpreter"]}),
    ])
    rows, total = db.query_alerts(mitre="Brute Force", statuses=None)
    assert total == 1 and rows[0]["wazuh_id"] == "m1"
    rows, total = db.query_alerts(mitre="T1059", statuses=None)
    assert total == 1 and rows[0]["wazuh_id"] == "m2"


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


def test_mitre_endpoint_shape(auth_client):
    db.insert_alerts_bulk([_alert("e1", {"tactic": ["Execution"], "technique": ["X"]})])
    r = auth_client.get("/api/mitre/summary")
    assert r.status_code == 200
    body = r.get_json()
    assert body["success"]
    assert {"tactics", "techniques", "ids", "days", "alerts_with_mitre"} <= set(body["data"])
