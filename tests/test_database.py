"""Smoke tests for database.py — migration idempotency, CRUD round-trips."""
import json


def test_init_db_idempotent(tmp_db):
    """Calling init_db twice should not raise."""
    import database
    database.init_db()
    database.init_db()


def test_alert_insert_and_query(tmp_db):
    import database as db
    alerts = [{
        "wazuh_id": "test-1", "timestamp": "2026-05-21T12:00:00",
        "agent_name": "host-a", "agent_ip": "10.0.0.1",
        "rule_id": "1234", "rule_level": 7,
        "rule_description": "Test alert", "rule_groups": ["test"],
        "full_log": "log line", "location": "/var/log/test", "raw": {},
    }]
    inserted = db.insert_alerts_bulk(alerts)
    assert inserted == 1
    rows, total = db.query_alerts()
    assert total == 1
    assert rows[0]["rule_id"] == "1234"


def test_alert_dedup_on_wazuh_id(tmp_db):
    import database as db
    alert = {
        "wazuh_id": "dup-1", "timestamp": "2026-05-21T12:00:00",
        "rule_id": "1", "rule_level": 5, "raw": {},
    }
    db.insert_alerts_bulk([alert])
    db.insert_alerts_bulk([alert])
    rows, total = db.query_alerts()
    assert total == 1


def test_status_workflow(tmp_db):
    import database as db
    db.insert_alerts_bulk([{
        "wazuh_id": "s-1", "timestamp": "2026-05-21T12:00:00",
        "rule_id": "1", "rule_level": 7, "raw": {},
    }])
    rows, _ = db.query_alerts()
    aid = rows[0]["id"]
    assert rows[0]["status"] == "open"

    db.set_alert_status(aid, "in_progress", "looking at it")
    assert db.get_alert(aid)["status"] == "in_progress"
    assert db.get_alert(aid)["ack_notes"] == "looking at it"

    db.set_alert_status(aid, "tp_remediated", "patched")
    assert db.get_alert(aid)["status"] == "tp_remediated"

    db.set_alert_status(aid, "open", None)
    assert db.get_alert(aid)["status"] == "open"


def test_query_filters_by_status(tmp_db):
    import database as db
    db.insert_alerts_bulk([
        {"wazuh_id": "a", "timestamp": "2026-05-21T12:00:00", "rule_id": "1", "rule_level": 7, "raw": {}},
        {"wazuh_id": "b", "timestamp": "2026-05-21T12:00:01", "rule_id": "1", "rule_level": 7, "raw": {}},
        {"wazuh_id": "c", "timestamp": "2026-05-21T12:00:02", "rule_id": "1", "rule_level": 7, "raw": {}},
    ])
    rows_all, _ = db.query_alerts()
    db.set_alert_status(rows_all[0]["id"], "false_positive", None)

    # Default = open only
    _, open_total = db.query_alerts(statuses=["open"])
    assert open_total == 2

    # statuses=None means everything
    _, total_all = db.query_alerts(statuses=None)
    assert total_all == 3

    _, fp_total = db.query_alerts(statuses=["false_positive"])
    assert fp_total == 1


def test_action_dedup_hash(tmp_db):
    """Same priority + similar description should dedup via the hash."""
    import database as db
    import parsers
    desc = "Investigate the suspicious login from 1.2.3.4 on host-a"
    h = parsers.action_hash("2026-05-21", "P1", desc)
    assert db.upsert_action("2026-05-21", "P1", desc, "/path/to/briefing.md", h) is True
    # Second insert is dedup'd
    assert db.upsert_action("2026-05-21", "P1", desc, "/path/to/briefing.md", h) is False


def test_webhook_crud(tmp_db):
    import database as db
    wid = db.insert_webhook("test", "mattermost", "encrypted_url",
                            severity_min=7, include_ai=True, dedup_minutes=240)
    assert wid > 0
    w = db.get_webhook(wid)
    assert w["name"] == "test"
    assert w["platform"] == "mattermost"

    db.update_webhook(wid, enabled=0)
    assert db.get_webhook(wid)["enabled"] == 0

    db.delete_webhook(wid)
    assert db.get_webhook(wid) is None


def test_user_crud(tmp_db):
    import database as db
    uid = db.insert_user("alex", "pbkdf2$200000$salt$hash", role="admin")
    assert uid > 0
    assert db.count_users() == 1

    u = db.get_user_by_username("alex")
    assert u["role"] == "admin"

    db.disable_user(uid)
    assert db.get_user(uid)["disabled"] == 1

    db.delete_user(uid)
    assert db.count_users() == 0


def test_audit_log(tmp_db):
    import database as db
    db.audit_add(1, "alex", "alert.status_change", "alert", "123",
                 details=json.dumps({"new_status": "false_positive"}),
                 ip_address="10.0.0.5")
    rows = db.audit_list()
    assert len(rows) == 1
    assert rows[0]["action"] == "alert.status_change"
    assert rows[0]["username"] == "alex"


def test_explanation_cache(tmp_db):
    import database as db
    db.insert_alerts_bulk([{
        "wazuh_id": "e-1", "timestamp": "2026-05-21T12:00:00",
        "rule_id": "1", "rule_level": 7, "raw": {},
    }])
    rows, _ = db.query_alerts()
    aid = rows[0]["id"]
    db.explanation_put(aid, "## test\nexplanation", "claude-sonnet-4-6")
    cached = db.explanation_get(aid)
    assert cached["content"] == "## test\nexplanation"
    assert cached["model"] == "claude-sonnet-4-6"
