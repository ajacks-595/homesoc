"""Retention/housekeeping prune functions + the run_retention job (F4)."""
from datetime import datetime, timezone, timedelta

import config
import database as db
import sync


def _ts(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


def test_notification_log_prune(tmp_db):
    wid = db.insert_webhook("w", "mattermost", config.encrypt("https://chat.example.com/x"),
                            0, True, 240)
    with db.conn() as c:
        c.execute("INSERT INTO notification_log(webhook_id,rule_id,agent_name,sent_at,success) "
                  "VALUES(?,?,?,?,1)", (wid, "5710", "h", _ts(40)))   # old
        c.execute("INSERT INTO notification_log(webhook_id,rule_id,agent_name,sent_at,success) "
                  "VALUES(?,?,?,?,1)", (wid, "5710", "h", _ts(1)))    # recent
    assert db.notification_log_prune(days=30) == 1
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM notification_log").fetchone()[0] == 1


def test_ai_runs_prune(tmp_db):
    with db.conn() as c:
        c.execute("INSERT INTO ai_runs(kind,model,created_at,success) VALUES('chat','m',?,1)", (_ts(10),))
        c.execute("INSERT INTO ai_runs(kind,model,created_at,success) VALUES('chat','m',?,1)", (_ts(1),))
    assert db.ai_runs_prune(days=7) == 1
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM ai_runs").fetchone()[0] == 1


def test_run_retention_returns_counts(tmp_db):
    res = sync.run_retention()
    assert set(res) == {"osint_expired", "notification_log", "ai_runs", "fts_backfill"}
    # The prune counters are ints; fts_backfill is a progress dict.
    assert all(isinstance(res[k], int) for k in ("osint_expired", "notification_log", "ai_runs"))
    assert isinstance(res["fts_backfill"], dict) and "done" in res["fts_backfill"]
