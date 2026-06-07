"""CVE asset tracker Phase 4: proactive alerting through the webhook channels."""
import json
from pathlib import Path

import pytest

import database as db
import notifications

CURRENT = (Path(__file__).parent / "fixtures" / "cve-briefing-current.md").read_text()


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


def _add_webhook(severity_min=0) -> int:
    import config
    return db.insert_webhook("mm", "mattermost",
                             config.encrypt("https://chat.example.com/hooks/abc"),
                             severity_min=severity_min, dedup_minutes=60,
                             include_ai=False)


@pytest.fixture
def allow_webhook_dns(monkeypatch):
    """The SSRF guard live-resolves DNS; the test host can't. The guard has its
    own dedicated suite (test_ssrf.py) — bypass it here."""
    monkeypatch.setattr(notifications, "validate_webhook_url",
                        lambda url: (True, ""))


_SAMPLE = {
    "item_key": "CVE-2026-42945", "title": "nginx Rift heap overflow",
    "severity": "critical", "cvss_score": 9.2,
    "asset_name": "nginx (proxy)", "exposure": "internet", "criticality": "high",
    "priority": 54.0, "confidence": "cpe",
    "match_reason": "CPE product 'nginx' in affected text",
    "action": "apt upgrade nginx", "exploited": True, "kev": False,
    "bookstack_url": "https://bs.example.com/books/cve-deep-dives/page/x",
}


def test_vuln_formatters_shape():
    mm = notifications._format_vuln_for_mattermost(_SAMPLE)
    assert "CVE-2026-42945" in mm["text"] and "nginx (proxy)" in mm["text"]
    assert "CRITICAL 9.2" in mm["text"].replace("**", "") or "CRITICAL" in mm["text"]
    assert "actively exploited" in mm["text"]
    assert "⚡ apt upgrade nginx" in mm["text"]
    assert "Deep dive" in mm["text"]

    dc = notifications._format_vuln_for_discord(_SAMPLE)
    assert dc["embeds"][0]["url"] == _SAMPLE["bookstack_url"]
    assert "cpe" in dc["embeds"][0]["description"]

    gen = notifications._format_vuln_for_generic(_SAMPLE)
    assert gen["type"] == "cve_match" and gen["match"]["item_key"] == "CVE-2026-42945"


def test_deliver_respects_webhook_threshold_and_dedup(tmp_db, allow_webhook_dns, monkeypatch):
    sent_payloads = []

    class FakeResp:
        status_code = 200
        text = "ok"

    monkeypatch.setattr(notifications.requests, "post",
                        lambda url, **kw: sent_payloads.append(kw["json"]) or FakeResp())

    _add_webhook(severity_min=0)
    _add_webhook(severity_min=12)     # only critical (13) clears this

    high = dict(_SAMPLE, severity="high")           # maps to level 10
    out = notifications.deliver_vuln_match(high)
    assert [o.get("skipped") for o in out].count("below_threshold") == 1
    assert sum(1 for o in out if o.get("sent")) == 1

    # second send inside the dedup window is suppressed
    out2 = notifications.deliver_vuln_match(high)
    assert any(o.get("skipped") == "dedup" for o in out2)
    assert len(sent_payloads) == 1


def test_threshold_config_filtering(tmp_db):
    import vulntrack
    cfg = {"alert_enabled": True, "alert_min_severity": "high",
           "alert_exposures": ["internet"]}
    mk = lambda sev, expo: {"severity": sev, "exposure": expo}
    assert vulntrack._meets_alert_threshold(mk("critical", "internet"), cfg)
    assert vulntrack._meets_alert_threshold(mk("high", "internet"), cfg)
    assert not vulntrack._meets_alert_threshold(mk("medium", "internet"), cfg)
    assert not vulntrack._meets_alert_threshold(mk("critical", "lan"), cfg)
    assert not vulntrack._meets_alert_threshold(
        mk("critical", "internet"), dict(cfg, alert_enabled=False))


def test_sync_fires_alert_once(auth_client, allow_webhook_dns, monkeypatch):
    """End-to-end: briefing ingest → match → webhook fires exactly once."""
    import vulntrack

    db.asset_insert("nginx (proxy)", product="nginx", version="1.27.0",
                    exposure="internet", criticality="high")
    _add_webhook(severity_min=0)
    delivered = []

    class FakeResp:
        status_code = 200
        text = "ok"

    monkeypatch.setattr(notifications.requests, "post",
                        lambda url, **kw: delivered.append(kw["json"]) or FakeResp())

    def fake_pages():
        return ({"slug": "cve-deep-dives"},
                [{"id": 326, "type": "page", "name": "CVE Briefing",
                  "updated_at": "2026-06-07T06:00:00Z"}])

    monkeypatch.setattr(vulntrack, "fetch_cve_pages", fake_pages)
    monkeypatch.setattr(vulntrack, "fetch_page", lambda pid: {
        "id": pid, "slug": "p", "name": "CVE Briefing", "markdown": CURRENT,
        "created_at": "2026-06-07T05:50:00Z"})
    vulntrack.set_config({
        "bookstack_url": "https://bs.example.com", "bookstack_token_id": "t",
        "bookstack_token_secret": "s", "alert_enabled": True,
        "alert_min_severity": "high", "alert_exposures": ["internet", "lan"]})

    res = vulntrack.sync_cve_briefings()
    assert res["alerts_sent"] >= 1
    assert any("nginx (proxy)" in json.dumps(p) for p in delivered)

    # nothing new on re-sync → no replay (notified_at + page watermark)
    n_before = len(delivered)
    res2 = vulntrack.sync_cve_briefings()
    assert res2["alerts_sent"] == 0 and len(delivered) == n_before


def test_below_threshold_marked_considered(auth_client, monkeypatch):
    """Threshold-failing matches are marked notified — raising thresholds later
    must not replay old history."""
    import vulntrack

    db.asset_insert("Jellyfin", product="Jellyfin",
                    exposure="isolated", criticality="low")
    iid, _ = db.cve_item_upsert("CVE-2026-7777", title="Jellyfin bug",
                                severity="critical", cve_ids='["CVE-2026-7777"]')
    db.cve_match_upsert(iid, db.assets_list()[0]["id"], "strong", "test", 12.0)

    vulntrack.set_config({"alert_enabled": True, "alert_min_severity": "high",
                          "alert_exposures": ["internet"]})     # isolated excluded
    res = vulntrack.notify_new_matches()
    assert res == {"alerts_sent": 0, "alerts_below_threshold": 1}
    assert db.cve_matches_unnotified() == []

    # widening the config later does not resurrect it
    vulntrack.set_config({"alert_exposures": ["internet", "lan", "isolated"]})
    assert vulntrack.notify_new_matches()["alerts_sent"] == 0


def test_alert_test_endpoint(auth_client, allow_webhook_dns, monkeypatch):
    _add_webhook(severity_min=0)

    class FakeResp:
        status_code = 200
        text = "ok"

    sent = []
    monkeypatch.setattr(notifications.requests, "post",
                        lambda url, **kw: sent.append(kw["json"]) or FakeResp())
    r = auth_client.post("/api/vulns/alert-test")
    body = r.get_json()
    assert body["success"]
    assert any(x.get("sent") for x in body["data"]["results"])
    assert "CVE-0000-TEST" in json.dumps(sent)
