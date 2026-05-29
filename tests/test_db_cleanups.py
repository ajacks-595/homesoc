"""P5: single-UPDATE FP refresh, OSINT cache reaper, optional COUNT in query_alerts."""
import database as db


def _alert(wid, rule_id, agent, level=10, ts="2026-05-29T10:00:00"):
    return {"wazuh_id": wid, "timestamp": ts, "agent_name": agent, "agent_ip": "10.0.0.1",
            "rule_id": rule_id, "rule_level": level, "rule_description": "x",
            "rule_groups": "[]", "full_log": "l", "location": "loc", "raw_json": "{}",
            "status": "open"}


def test_refresh_fp_alert_counts_single_update(tmp_db):
    db.insert_alerts_bulk([
        _alert("a1", "5710", "host-a"), _alert("a2", "5710", "host-a"),
        _alert("a3", "5710", "host-b"), _alert("a4", "9999", "host-a"),
    ])
    fp_scoped = db.insert_fp("5710", "host-a", "noisy on host-a", "100001", "<snip>")
    fp_all = db.insert_fp("5710", None, "noisy everywhere", "100002", "<snip>")
    db.refresh_fp_alert_counts()
    counts = {r["id"]: r["alert_count"] for r in db.list_fps()}
    assert counts[fp_scoped] == 2   # host-a only
    assert counts[fp_all] == 3      # all agents for rule 5710


def test_osint_purge_expired(tmp_db):
    db.osint_put("1.2.3.4", "ipv4", "virustotal", {"x": 1}, ttl_days=7)    # fresh
    db.osint_put("5.6.7.8", "ipv4", "abuseipdb", {"y": 2}, ttl_days=-1)    # expired
    removed = db.osint_purge_expired()
    assert removed == 1
    assert db.osint_get("1.2.3.4", "virustotal") is not None
    assert db.osint_get("5.6.7.8", "abuseipdb") is None
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM osint_results").fetchone()[0] == 1


def test_query_alerts_with_total_flag(tmp_db):
    db.insert_alerts_bulk([_alert(f"w{i}", "5710", "host-a") for i in range(5)])
    rows, total = db.query_alerts(statuses=["open"], limit=2, with_total=True)
    assert len(rows) == 2 and total == 5
    rows, total = db.query_alerts(statuses=["open"], limit=2, with_total=False)
    assert len(rows) == 2 and total == 2   # len(rows), COUNT scan skipped
