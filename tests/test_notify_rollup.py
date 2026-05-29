"""Notification dedup roll-up: count suppressed-since-last-send and pass it to
the formatter, plus the suppress-within-window path (B6)."""
import config
import database as db
import notifications as nf


def test_suppressed_since_last_send_counts_correctly(tmp_db):
    wid = db.insert_webhook("w", "mattermost", config.encrypt("https://chat.example.com/x"),
                            0, True, 240)
    # last successful send, then 3 dedup-suppressed for the same rule/agent
    db.notification_log_add(wid, 1, "5710", "host-a", success=True, response="200")
    for i in range(3):
        db.notification_log_add(wid, 10 + i, "5710", "host-a", success=False,
                                response=None, skipped_reason="dedup")
    assert db.notification_suppressed_since_last_send(wid, "5710", "host-a") == 3
    # a fresh successful send resets the window
    db.notification_log_add(wid, 99, "5710", "host-a", success=True, response="200")
    assert db.notification_suppressed_since_last_send(wid, "5710", "host-a") == 0
    # different agent is independent
    assert db.notification_suppressed_since_last_send(wid, "5710", "host-b") == 0


def test_deliver_alert_passes_rollup_to_formatter(monkeypatch):
    fake = {"id": 1, "enabled": 1, "severity_min": 0, "dedup_minutes": 240, "include_ai": 1}
    monkeypatch.setattr(nf.db, "list_webhooks", lambda: [fake])
    monkeypatch.setattr(nf.db, "notification_recent", lambda *a, **k: 0)   # nothing recent → send
    monkeypatch.setattr(nf.db, "notification_suppressed_since_last_send", lambda *a, **k: 4)
    monkeypatch.setattr(nf.db, "notification_log_add", lambda *a, **k: None)
    monkeypatch.setattr(nf.db, "update_webhook", lambda *a, **k: None)
    captured = {}
    monkeypatch.setattr(nf, "send_to_webhook",
                        lambda w, alert, summary, dedup_count=0: (captured.update(dc=dedup_count), (True, "200"))[1])
    out = nf.deliver_alert({"id": 9, "rule_level": 12, "rule_id": "5710",
                            "agent_name": "host-a", "rule_description": "x", "timestamp": "t"})
    assert captured["dc"] == 4
    assert out[0]["sent"] is True and out[0]["rolled_up"] == 4


def test_deliver_alert_suppresses_within_window(monkeypatch):
    fake = {"id": 1, "enabled": 1, "severity_min": 0, "dedup_minutes": 240, "include_ai": 1}
    monkeypatch.setattr(nf.db, "list_webhooks", lambda: [fake])
    monkeypatch.setattr(nf.db, "notification_recent", lambda *a, **k: 1)   # recent send → suppress
    logged = []
    monkeypatch.setattr(nf.db, "notification_log_add",
                        lambda *a, **k: logged.append(k.get("skipped_reason")))
    sent = []
    monkeypatch.setattr(nf, "send_to_webhook", lambda *a, **k: (sent.append(1), (True, "x"))[1])
    out = nf.deliver_alert({"id": 9, "rule_level": 12, "rule_id": "5710", "agent_name": "host-a"})
    assert out[0]["skipped"] == "dedup"
    assert logged == ["dedup"]
    assert not sent
