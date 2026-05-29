"""SOC performance metrics: MTTR, FP rate, triage volume (F5)."""
from datetime import datetime, timezone, timedelta

import pytest

import database as db


def _alert(wid, ts):
    return {"wazuh_id": wid, "timestamp": ts, "agent_name": "h", "agent_ip": "10.0.0.1",
            "rule_id": "5710", "rule_level": 10, "rule_description": "d",
            "rule_groups": [], "full_log": "x", "location": "/l", "raw": {}}


def _id(wid):
    with db.conn() as c:
        return c.execute("SELECT id FROM alerts WHERE wazuh_id=?", (wid,)).fetchone()[0]


def test_soc_metrics_mttr_fp_and_backlog(tmp_db):
    two_h_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
    db.insert_alerts_bulk([_alert("a", two_h_ago), _alert("b", two_h_ago), _alert("c", two_h_ago)])
    db.set_alert_status(_id("a"), "tp_remediated", "fixed")     # acked_at = now
    db.set_alert_status(_id("b"), "false_positive", "noise")    # acked_at = now
    # c stays open

    m = db.soc_metrics(days=7)
    assert m["open_alerts"] == 1
    assert m["triaged"] == 2
    assert m["false_positive_rate"] == 50.0
    assert m["by_status"]["tp_remediated"] == 1
    assert 1.5 <= m["mttr_hours"] <= 2.5     # ~2h from timestamp → acked_at
    assert m["closed_per_day"]               # at least one day bucket


def test_soc_metrics_empty(tmp_db):
    m = db.soc_metrics(days=7)
    assert m["open_alerts"] == 0 and m["triaged"] == 0
    assert m["mttr_hours"] is None and m["false_positive_rate"] == 0.0


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


def test_soc_metrics_endpoint(auth_client):
    r = auth_client.get("/api/metrics/soc")
    assert r.status_code == 200
    keys = {"open_alerts", "triaged", "mttr_hours", "false_positive_rate",
            "by_status", "closed_per_day", "days"}
    assert keys <= set(r.get_json()["data"])
