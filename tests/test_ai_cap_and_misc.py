"""Regression tests for the hardening pass:
- interactive AI request cap (manual explain + chat) returns 429 over budget
- login-failure map sweeps stale buckets (no unbounded growth)
- notes-only action update no longer silently drops the notes
- pipeline/run is admin-gated
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


def _admin(app):
    c = app.test_client()
    c.post("/setup", data={"username": "admin", "password": "supersecret"})
    return c


def _analyst(app, admin):
    admin.post("/api/users", json={"username": "analyst", "password": "analystpass",
                                   "role": "user"})
    c = app.test_client()
    c.post("/login", data={"username": "analyst", "password": "analystpass"})
    return c


# ---- interactive AI cap ----

def _seed_alert():
    db.insert_alert({
        "wazuh_id": "w-cap", "timestamp": "2026-06-10T00:00:00",
        "agent_name": "h", "agent_ip": "10.0.0.5", "rule_id": "1",
        "rule_level": 12, "rule_description": "x", "rule_groups": [],
        "full_log": "x", "location": "loc", "raw": {"rule": {"level": 12}},
    })
    with db.conn() as c:
        return c.execute("SELECT id FROM alerts WHERE wazuh_id='w-cap'").fetchone()["id"]


def test_manual_explain_capped(app, monkeypatch):
    monkeypatch.setenv("SOC_AI_INTERACTIVE_CAP", "3")
    c = _admin(app)
    aid = _seed_alert()
    # Fill the budget with recorded runs (no real Claude call needed).
    for _ in range(3):
        db.ai_run_add(aid, "manual_explain", "m", 10, success=True)
    r = c.post(f"/api/alerts/{aid}/explain")
    assert r.status_code == 429
    assert "cap" in r.get_json()["error"].lower()


def test_chat_capped(app, monkeypatch):
    monkeypatch.setenv("SOC_AI_INTERACTIVE_CAP", "2")
    c = _admin(app)
    aid = _seed_alert()
    db.explanation_put(aid, "an explanation", "m")  # chat requires an explanation
    db.ai_run_add(aid, "manual_explain", "m", 10, success=True)
    db.ai_run_add(aid, "chat", "m", 10, success=True)
    r = c.post(f"/api/alerts/{aid}/chat", json={"message": "hi"})
    assert r.status_code == 429


# ---- login map sweep ----

def test_login_fails_sweep(monkeypatch):
    monkeypatch.setattr(auth, "_LOGIN_FAILS_SWEEP_AT", 5)
    monkeypatch.setattr(auth, "_LOGIN_WINDOW_S", 900)
    auth._login_fails.clear()
    import time
    old = time.monotonic() - 10_000      # older than the window
    # Seed several stale buckets directly.
    for i in range(10):
        auth._login_fails[f"user:stale{i}"] = [old]
    # A fresh failure trips the sweep (len >= 5) and clears all stale buckets.
    auth.login_record_failure("10.0.0.9", "freshuser")
    keys = set(auth._login_fails)
    assert not any(k.startswith("user:stale") for k in keys), keys
    assert "user:freshuser" in keys


# ---- notes-only action update ----

def test_action_notes_only_update(app):
    c = _admin(app)
    db.upsert_action("2026-06-10", "P1", "do the thing", "/b.md", "hash-1")
    with db.conn() as conn:
        aid = conn.execute("SELECT id FROM recommended_actions").fetchone()["id"]
    r = c.patch(f"/api/actions/{aid}", json={"notes": "looked into it"})
    assert r.status_code == 200
    with db.conn() as conn:
        row = conn.execute("SELECT status, resolution_notes FROM recommended_actions WHERE id=?",
                           (aid,)).fetchone()
    assert row["resolution_notes"] == "looked into it"
    assert row["status"] == "open"   # unchanged


def test_action_empty_update_rejected(app):
    c = _admin(app)
    db.upsert_action("2026-06-10", "P2", "thing", "/b.md", "hash-2")
    with db.conn() as conn:
        aid = conn.execute("SELECT id FROM recommended_actions").fetchone()["id"]
    assert c.patch(f"/api/actions/{aid}", json={}).status_code == 400


# ---- pipeline run is admin-only ----

def test_pipeline_run_admin_only(app):
    admin = _admin(app)
    analyst = _analyst(app, admin)
    assert analyst.post("/api/pipeline/run", json={"kind": "collect"}).status_code == 403


# ---- count_actions perf helper correctness ----

def test_count_actions(tmp_db):
    db.upsert_action("2026-06-10", "P1", "a", "/b.md", "h1")
    db.upsert_action("2026-06-10", "P1", "b", "/b.md", "h2")
    db.upsert_action("2026-06-10", "P2", "c", "/b.md", "h3")
    assert db.count_actions(("open", "in_progress"), priority="P1") == 2
    assert db.count_actions(("open",)) == 3
    assert db.count_actions(()) == 0
