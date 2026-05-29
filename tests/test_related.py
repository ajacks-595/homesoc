"""Related-activity panel: non-AI IOC cross-correlation (F1)."""
from datetime import datetime, timezone

import pytest

import ai
import database as db


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _alert(wid, raw, full_log="", rule_id="5710", level=10, agent="host-a"):
    return {"wazuh_id": wid, "timestamp": _now(), "agent_name": agent, "agent_ip": "10.0.0.1",
            "rule_id": rule_id, "rule_level": level, "rule_description": "desc",
            "rule_groups": [], "full_log": full_log, "location": "/var/log/x", "raw": raw}


def _id(wid):
    with db.conn() as c:
        return c.execute("SELECT id FROM alerts WHERE wazuh_id=?", (wid,)).fetchone()[0]


def test_related_finds_shared_ioc_excludes_self_and_unrelated(tmp_db):
    a_raw = {"data": {"srcip": "8.8.8.8"}}
    db.insert_alerts_bulk([
        _alert("A", a_raw, full_log="conn from 8.8.8.8"),
        _alert("B", {"data": {"dstip": "8.8.8.8"}}, full_log="seen 8.8.8.8", rule_id="9999"),
        _alert("C", {"data": {"srcip": "1.1.1.1"}}, full_log="unrelated"),
    ])
    out = ai.related_observations(_id("A"), a_raw)
    assert "8.8.8.8" in out["iocs"]
    rule_ids = [x["rule_id"] for x in out["alerts"]]
    assert "9999" in rule_ids                       # B matched
    assert all(x["ioc"] == "8.8.8.8" for x in out["alerts"])
    assert _id("A") not in [x["id"] for x in out["alerts"]]   # self excluded


def test_related_skips_rfc1918_and_empty(tmp_db):
    # purely internal IPs aren't treated as IOCs, and a no-indicator alert is empty
    out = ai.related_observations(1, {"data": {"srcip": "10.0.0.5", "note": "nothing"}})
    assert out == {"iocs": [], "alerts": [], "dns": []}


# ---- endpoint ----

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


def test_related_endpoint_shape(auth_client):
    db.insert_alerts_bulk([_alert("Z", {"data": {"srcip": "8.8.8.8"}}, full_log="x 8.8.8.8")])
    r = auth_client.get(f"/api/alerts/{_id('Z')}/related")
    assert r.status_code == 200
    body = r.get_json()
    assert body["success"] and set(body["data"].keys()) == {"iocs", "alerts", "dns"}
    assert "8.8.8.8" in body["data"]["iocs"]


def test_related_endpoint_404(auth_client):
    assert auth_client.get("/api/alerts/999999/related").status_code == 404
