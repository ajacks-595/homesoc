"""CVE asset tracker Phase 3: remediation workflow + dashboard stats."""
import json

import pytest

import database as db


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


def _seed_match(key="CVE-2026-1111", severity="critical", days_old=0,
                status="new") -> int:
    aid_row = db.assets_list()
    if not aid_row:
        aid = db.asset_insert("nginx", product="nginx",
                              exposure="internet", criticality="high")
    else:
        aid = aid_row[0]["id"]
    iid, _ = db.cve_item_upsert(key, title=f"{key} test", severity=severity,
                                cve_ids=json.dumps([key]))
    mid, _ = db.cve_match_upsert(iid, aid, "strong", "test", 36.0)
    with db.conn() as c:
        c.execute("UPDATE cve_matches SET status=?, "
                  "created_at=datetime('now', ?) WHERE id=?",
                  (status, f"-{days_old} days", mid))
    return mid


def test_workflow_status_and_audit(auth_client):
    mid = _seed_match()
    for status in ("investigating", "patching", "resolved"):
        r = auth_client.patch(f"/api/vulns/matches/{mid}",
                              json={"status": status, "notes": f"now {status}"})
        body = r.get_json()
        assert body["success"] and body["data"]["status"] == status
    row = db.cve_match_get(mid)
    assert row["status_by"] == "admin" and row["status_at"]
    assert row["notes"] == "now resolved"

    # every transition audited
    with db.conn() as c:
        n = c.execute("SELECT COUNT(*) FROM audit_log "
                      "WHERE action='vulns.match_status'").fetchone()[0]
    assert n == 3


def test_notes_preserved_when_omitted(auth_client):
    mid = _seed_match()
    auth_client.patch(f"/api/vulns/matches/{mid}",
                      json={"status": "investigating", "notes": "keep me"})
    auth_client.patch(f"/api/vulns/matches/{mid}", json={"status": "patching"})
    assert db.cve_match_get(mid)["notes"] == "keep me"


def test_dashboard_stats(auth_client):
    m_new = _seed_match("CVE-2026-2222", "critical", days_old=0)
    m_late = _seed_match("CVE-2026-3333", "critical", days_old=10)   # SLA 7d → overdue
    m_ok = _seed_match("CVE-2026-4444", "low", days_old=10)          # SLA 90d → fine
    m_done = _seed_match("CVE-2026-5555", "high", days_old=3)
    auth_client.patch(f"/api/vulns/matches/{m_done}",
                      json={"status": "resolved", "notes": "patched today"})

    d = auth_client.get("/api/vulns/dashboard").get_json()["data"]
    assert d["open_total"] == 3
    assert d["crit_high_open"] == 2          # two critical open, the high resolved
    assert d["open_by_severity"]["critical"]["open"] == 2
    assert [o["item_key"] for o in d["overdue"]] == ["CVE-2026-3333"]
    assert d["overdue"][0]["age_days"] >= 10
    assert d["resolved_14d"] == 1
    assert d["recently_resolved"][0]["item_key"] == "CVE-2026-5555"
    assert d["recently_resolved"][0]["status_by"] == "admin"
    assert {m_new, m_ok} and d["sla_days"]["critical"] == 7
