"""Per-(rule, agent) expected-behaviour notes: CRUD + agent-specific-over-
rule-wide resolution, and surfacing on the alert detail endpoint.
"""
import pytest

import auth
import database as db


@pytest.fixture
def app(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    auth._login_fails.clear()
    from app import create_app
    a = create_app()
    a.config["TESTING"] = True
    return a


def _client(app):
    c = app.test_client()
    c.post("/setup", data={"username": "admin", "password": "supersecret"})
    return c


# ---- DB layer ----

def test_upsert_and_resolution(tmp_db):
    nid, created = db.rule_note_upsert("5710", "", "rule-wide note", "admin")
    assert created
    nid2, created2 = db.rule_note_upsert("5710", "web01", "host note", "admin")
    assert created2 and nid2 != nid
    # Agent-specific wins over rule-wide.
    assert db.rule_note_for("5710", "web01")["note"] == "host note"
    # An agent with no specific note falls back to the rule-wide one.
    assert db.rule_note_for("5710", "db01")["note"] == "rule-wide note"
    # Unknown rule → None.
    assert db.rule_note_for("9999", "web01") is None


def test_upsert_replaces_in_place(tmp_db):
    nid, created = db.rule_note_upsert("100", "", "first", "admin")
    nid2, created2 = db.rule_note_upsert("100", "", "second", "admin")
    assert not created2 and nid2 == nid
    assert db.rule_note_for("100", None)["note"] == "second"
    assert len(db.rule_notes_list()) == 1


# ---- API layer ----

def test_api_crud(app):
    c = _client(app)
    r = c.post("/api/rule-notes", json={"rule_id": "5710", "note": "expected nightly"})
    assert r.status_code == 200 and r.get_json()["data"]["created"]
    nid = r.get_json()["data"]["id"]

    lk = c.get("/api/rule-notes/lookup?rule_id=5710")
    assert lk.get_json()["data"]["note"] == "expected nightly"

    lst = c.get("/api/rule-notes")
    assert len(lst.get_json()["data"]) == 1

    d = c.delete(f"/api/rule-notes/{nid}")
    assert d.status_code == 200
    assert c.get("/api/rule-notes/lookup?rule_id=5710").get_json()["data"] is None


def test_api_validation(app):
    c = _client(app)
    assert c.post("/api/rule-notes", json={"note": "x"}).status_code == 400
    assert c.post("/api/rule-notes", json={"rule_id": "5710"}).status_code == 400
    assert c.delete("/api/rule-notes/9999").status_code == 404


def test_note_surfaced_on_alert_detail(app):
    c = _client(app)
    db.insert_alert({
        "wazuh_id": "w-1", "timestamp": "2026-06-10T00:00:00",
        "agent_name": "web01", "agent_ip": "10.0.0.5", "rule_id": "5710",
        "rule_level": 5, "rule_description": "sshd", "rule_groups": [],
        "full_log": "x", "location": "/var/log/auth.log", "raw": {},
    })
    with db.conn() as conn:
        aid = conn.execute("SELECT id FROM alerts WHERE wazuh_id='w-1'").fetchone()["id"]
    c.post("/api/rule-notes", json={"rule_id": "5710", "agent_name": "web01",
                                    "note": "expected — backup job"})
    detail = c.get(f"/api/alerts/{aid}").get_json()["data"]
    assert detail["rule_note"]["note"] == "expected — backup job"


def test_note_audited(app):
    c = _client(app)
    c.post("/api/rule-notes", json={"rule_id": "5710", "note": "x"})
    rows = db.audit_list(limit=10, action="rule_note.save")
    assert any(r["action"] == "rule_note.save" for r in rows)
