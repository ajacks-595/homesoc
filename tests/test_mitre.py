"""MITRE ATT&CK summary aggregation + technique filter (F2) + denormalised
alert_mitre table / matrix view."""
import json
from datetime import datetime, timezone

import pytest

import database as db
from parsers import extract_mitre


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
    assert {"tactics", "techniques", "ids", "days", "alerts_with_mitre", "matrix"} <= set(body["data"])


# ---- extract_mitre ---------------------------------------------------------

def test_extract_mitre_pairs_parallel_arrays():
    raw = {"rule": {"mitre": {"id": ["T1110"], "tactic": ["Credential Access"],
                              "technique": ["Brute Force"]}}}
    assert extract_mitre(raw) == [("T1110", "Brute Force", "Credential Access")]


def test_extract_mitre_multi_tactic_cross_product():
    # Real Wazuh shape: T1078 Valid Accounts maps to 4 tactics on one alert.
    raw = {"rule": {"mitre": {
        "id": ["T1078"], "technique": ["Valid Accounts"],
        "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]}}}
    got = extract_mitre(raw)
    assert len(got) == 4
    assert all(t[0] == "T1078" and t[1] == "Valid Accounts" for t in got)
    assert {t[2] for t in got} == {"Defense Evasion", "Persistence",
                                   "Privilege Escalation", "Initial Access"}


def test_extract_mitre_length_mismatch_and_missing():
    # id/technique arrays of different lengths pad with "" instead of dropping
    raw = {"rule": {"mitre": {"id": ["T1110", "T1059"], "technique": ["Brute Force"],
                              "tactic": ["Execution"]}}}
    assert set(extract_mitre(raw)) == {("T1110", "Brute Force", "Execution"),
                                       ("T1059", "", "Execution")}
    assert extract_mitre({"rule": {}}) == []
    assert extract_mitre({}) == []
    assert extract_mitre({"rule": {"mitre": "bogus"}}) == []
    # scalar (non-list) values are tolerated
    raw = {"rule": {"mitre": {"id": "T1110", "tactic": "Credential Access"}}}
    assert extract_mitre(raw) == [("T1110", "", "Credential Access")]


# ---- alert_mitre population ------------------------------------------------

def test_insert_populates_alert_mitre(tmp_db):
    db.insert_alerts_bulk([
        _alert("p1", {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}),
        _alert("p2", None),
    ])
    with db.conn() as c:
        mapped = c.execute(
            "SELECT technique_id, technique, tactic FROM alert_mitre m "
            "JOIN alerts a ON a.id=m.alert_id WHERE a.wazuh_id='p1'").fetchall()
        sentinel = c.execute(
            "SELECT technique_id, technique, tactic FROM alert_mitre m "
            "JOIN alerts a ON a.id=m.alert_id WHERE a.wazuh_id='p2'").fetchall()
    assert [(r[0], r[1], r[2]) for r in mapped] == [("T1110", "Brute Force", "Credential Access")]
    # no-mitre alerts get the all-empty sentinel so they're never re-parsed
    assert [(r[0], r[1], r[2]) for r in sentinel] == [("", "", "")]


def test_backfill_existing_rows_idempotent(tmp_db):
    # Simulate a pre-upgrade DB: alerts present, alert_mitre empty.
    raw = {"rule": {"id": "5710", "level": 10,
                    "mitre": {"id": ["T1110"], "tactic": ["Credential Access"],
                              "technique": ["Brute Force"]}}}
    with db.conn() as c:
        c.execute(
            "INSERT INTO alerts(wazuh_id,timestamp,rule_id,rule_level,raw_json) "
            "VALUES('b1',?,'5710',10,?)", (_now(), json.dumps(raw)))
        assert db._populate_alert_mitre(c) == 1
        assert db._populate_alert_mitre(c) == 0          # second pass: nothing pending
        n = c.execute("SELECT COUNT(*) FROM alert_mitre").fetchone()[0]
    assert n == 1
    rows, total = db.query_alerts(mitre="T1110", statuses=None)
    assert total == 1 and rows[0]["wazuh_id"] == "b1"


def test_mitre_filter_no_substring_false_positive(tmp_db):
    # A log line that merely *mentions* T1110 must not match the filter
    # (the old raw_json LIKE behaviour did).
    a = _alert("fp1", None)
    a["full_log"] = "user searched for T1110 Brute Force docs"
    a["raw"]["full_log"] = a["full_log"]
    db.insert_alerts_bulk([a, _alert("fp2", {"id": ["T1110"], "tactic": ["Credential Access"],
                                             "technique": ["Brute Force"]})])
    rows, total = db.query_alerts(mitre="T1110", statuses=None)
    assert total == 1 and rows[0]["wazuh_id"] == "fp2"
    # tactic name filters too, case-insensitively
    rows, total = db.query_alerts(mitre="credential access", statuses=None)
    assert total == 1 and rows[0]["wazuh_id"] == "fp2"


def test_mitre_summary_matrix_multi_tactic(tmp_db):
    db.insert_alerts_bulk([
        _alert("m1", {"id": ["T1078"], "technique": ["Valid Accounts"],
                      "tactic": ["Defense Evasion", "Initial Access"]}),
        _alert("m2", {"id": ["T1110"], "technique": ["Brute Force"],
                      "tactic": ["Credential Access"]}),
    ])
    s = db.mitre_summary(days=7)
    # one alert, two tactics → counted once overall, once per tactic cell
    assert s["alerts_with_mitre"] == 2
    assert s["matrix"]["Defense Evasion"] == [{"id": "T1078", "name": "Valid Accounts", "count": 1}]
    assert s["matrix"]["Initial Access"] == [{"id": "T1078", "name": "Valid Accounts", "count": 1}]
    assert s["matrix"]["Credential Access"] == [{"id": "T1110", "name": "Brute Force", "count": 1}]
    tac = {t["name"]: t["count"] for t in s["tactics"]}
    assert tac == {"Defense Evasion": 1, "Initial Access": 1, "Credential Access": 1}
