"""Wazuh alert parsing hardening: surrogate dedup id (B1) + defensive level
coercion (B4)."""
import json

import parsers


def _alert(**over):
    base = {
        "id": None,
        "timestamp": "2026-05-29T10:00:00.123+0000",
        "rule": {"id": 5710, "level": 7, "description": "d"},
        "agent": {"name": "host-a", "ip": "10.0.0.1"},
        "full_log": "log line", "location": "/var/log/x",
    }
    base.update(over)
    if base.get("id") is None:
        base.pop("id")
    return json.dumps(base)


def test_uses_wazuh_id_when_present():
    p = parsers.parse_wazuh_alert_line(_alert(id="1654321"))
    assert p["wazuh_id"] == "1654321"


def test_synthesizes_stable_id_when_missing():
    line = _alert()  # no "id"
    p1 = parsers.parse_wazuh_alert_line(line)
    p2 = parsers.parse_wazuh_alert_line(line)
    assert p1["wazuh_id"].startswith("syn-")
    assert p1["wazuh_id"] == p2["wazuh_id"]   # stable across polls → dedups


def test_distinct_alerts_get_distinct_synthetic_ids():
    a = parsers.parse_wazuh_alert_line(_alert(full_log="A"))
    b = parsers.parse_wazuh_alert_line(_alert(full_log="B"))
    assert a["wazuh_id"] != b["wazuh_id"]


def test_malformed_rule_level_does_not_raise():
    p = parsers.parse_wazuh_alert_line(
        _alert(rule={"id": 5710, "level": "high", "description": "d"}))
    assert p is not None
    assert p["rule_level"] == 0       # bad level → 0, line still parsed
    assert p["rule_id"] == "5710"


def test_surrogate_id_dedups_in_db(tmp_db):
    import database as db
    p = parsers.parse_wazuh_alert_line(_alert())   # no id → synthetic
    db.insert_alerts_bulk([p])
    db.insert_alerts_bulk([p])                      # same alert, next poll
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
