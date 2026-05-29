"""The composite alerts(status, timestamp) index exists and is used by the
busiest queries (overview / query_alerts / latest_alerts), removing the full
table scan + filesort flagged in review."""
import database as db


def _seed(n=50):
    rows = []
    for i in range(n):
        rows.append({
            "wazuh_id": f"w{i}", "timestamp": f"2026-05-29T10:{i % 60:02d}:00",
            "agent_name": "host-a", "agent_ip": "10.0.0.1",
            "rule_id": "5710", "rule_level": 5 + (i % 8),
            "rule_description": "x", "rule_groups": "[]", "full_log": "l",
            "location": "loc", "raw_json": "{}",
            "status": "open" if i % 3 else "acknowledged",
        })
    db.insert_alerts_bulk(rows)


def test_status_index_exists(tmp_db):
    with db.conn() as c:
        names = [r["name"] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='alerts'")]
    assert "idx_alerts_status_ts" in names


def test_overview_query_uses_index_not_scan(tmp_db):
    _seed()
    with db.conn() as c:
        plan = c.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM alerts WHERE status IN ('open') "
            "ORDER BY timestamp DESC LIMIT 10").fetchall()
    text = " | ".join(" ".join(str(x) for x in tuple(r)) for r in plan)
    assert "idx_alerts_status_ts" in text, text
    assert "SCAN alerts" not in text, text   # no full table scan
