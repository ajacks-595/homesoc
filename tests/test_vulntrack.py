"""CVE asset tracker Phase 2: briefing parser, matcher, sync orchestration."""
import json
from pathlib import Path

import pytest

import database as db
from parsers import parse_cve_briefing

FIXTURES = Path(__file__).parent / "fixtures"
CURRENT = (FIXTURES / "cve-briefing-current.md").read_text()
LEGACY = (FIXTURES / "cve-briefing-legacy.md").read_text()


# ---- parser -----------------------------------------------------------------

def test_parse_current_template():
    r = parse_cve_briefing(CURRENT)
    assert len(r["items"]) == 6 and not r["warnings"]
    by_key = {i["item_key"]: i for i in r["items"]}

    unifi = by_key["CVE-2026-34908"]            # multi-CVE cluster
    assert len(unifi["cve_ids"]) == 3
    assert unifi["severity"] == "critical" and unifi["cvss_score"] == 10.0
    assert unifi["stack_flag"] == "yes"
    assert "5.1.12" in unifi["action"]

    kernel = by_key["CVE-2026-31431"]
    assert kernel["exploited"] and kernel["kev"]

    miasma = by_key["miasma"]                   # non-CVE item → slug key
    assert miasma["stack_flag"] == "check"
    assert miasma["exploited"]                  # "Active Campaign"


def test_parse_legacy_template():
    # Pre-2026-05-28 pages use '**Key:** value' paragraphs, not field tables.
    r = parse_cve_briefing(LEGACY)
    assert len(r["items"]) == 5
    assert all(i["parse_ok"] for i in r["items"])
    by_key = {i["item_key"]: i for i in r["items"]}
    assert by_key["CVE-2026-31431"]["severity"] == "high"
    assert by_key["CVE-2026-31431"]["kev"]
    assert by_key["trapdoor"]["stack_flag"] == "check"


def test_parse_garbage_degrades_not_raises():
    r = parse_cve_briefing("# nothing here\n\njust prose, no structure")
    assert r["items"] == []
    r = parse_cve_briefing("## Deep Dives\n### 1. CVE-2026-1 — Mystery\nno fields")
    assert len(r["items"]) == 1
    assert not r["items"][0]["parse_ok"]        # surfaced for manual review


def test_slug_stability_across_title_drift():
    from parsers import _cve_slugify
    # Same campaign, different day-to-day titles → same key
    assert _cve_slugify("Miasma — Red Hat npm Supply Chain Attack") == \
           _cve_slugify("Miasma — Red Hat @redhat-cloud-services npm Compromise")
    assert _cve_slugify("Supply Chain: TrapDoor — npm/PyPI Credential Theft") == "trapdoor"


# ---- matcher ----------------------------------------------------------------

def _mk_assets(tmp_db):
    db.asset_insert("UniFi Gateway", vendor="Ubiquiti", product="UniFi OS",
                    version="5.1.10", category="network_device",
                    exposure="internet", criticality="high")
    db.asset_insert("nginx (proxy)", vendor="nginx", product="nginx",
                    version="1.27.3", exposure="internet", criticality="high",
                    cpe="cpe:2.3:a:nginx:nginx:1.27.3")
    db.asset_insert("Proxmox host", vendor="Proxmox", product="Proxmox VE",
                    version="8.3", category="hypervisor",
                    exposure="lan", criticality="high")
    db.asset_insert("Jellyfin", product="Jellyfin", exposure="lan", criticality="low")
    db.asset_insert("Mystery box")              # draft: no product/cpe


def test_matching_confidence_tiers(tmp_db):
    import vulntrack
    _mk_assets(tmp_db)
    assets = db.assets_list()
    items = {i["item_key"]: i for i in parse_cve_briefing(CURRENT)["items"]}

    # strong: product name in affected text
    got = vulntrack.match_item_to_assets(items["CVE-2026-34908"], assets)
    by_name = {a["name"]: (c, r) for a, c, r in got}
    assert by_name["UniFi Gateway"][0] == "strong"
    assert "UniFi OS" in by_name["UniFi Gateway"][1]
    assert "Jellyfin" not in by_name and "Mystery box" not in by_name

    # cpe: anchored on the CPE product field
    got = vulntrack.match_item_to_assets(items["CVE-2026-42945"], assets)
    by_name = {a["name"]: (c, r) for a, c, r in got}
    assert by_name["nginx (proxy)"][0] == "cpe"

    # fuzzy alias: kernel LPE → Proxmox via the distro alias (when the text
    # doesn't name Proxmox, the alias still catches it; here the text DOES
    # name Proxmox so it may be strong — accept either, but it must match)
    got = vulntrack.match_item_to_assets(items["CVE-2026-31431"], assets)
    names = {a["name"] for a, _, _ in got}
    assert "Proxmox host" in names


def test_fuzzy_ignores_generic_infra_tokens(tmp_db):
    # Live E2E finding: a PAN-OS GlobalProtect item fuzzy-matched "UniFi Cloud
    # Gateway" purely on the token 'gateway' — and outranked every real match.
    # Generic infra nouns must not be enough for a fuzzy match on their own.
    import vulntrack
    db.asset_insert("UniFi Cloud Gateway", vendor="Ubiquiti", product="UniFi OS",
                    exposure="internet", criticality="high")
    pan_os = {"title": "CVE-2026-0257 — PAN-OS GlobalProtect Authentication Bypass",
              "affects": "Palo Alto PAN-OS GlobalProtect gateway and portal",
              "affected_detail": "PAN-OS 11.x with GlobalProtect gateway enabled"}
    assert vulntrack.match_item_to_assets(pan_os, db.assets_list()) == []
    # ...while the real UniFi item still matches via the product name
    unifi = {"title": "UniFi OS RCE", "affects": "UniFi OS (Cloud GW)",
             "affected_detail": "UniFi OS prior to 5.1.12"}
    got = vulntrack.match_item_to_assets(unifi, db.assets_list())
    assert got and got[0][1] == "strong"


def test_matching_version_note(tmp_db):
    import vulntrack
    db.asset_insert("n8n", product="n8n", version="1.121.0",
                    exposure="lan", criticality="medium")
    items = {i["item_key"]: i for i in parse_cve_briefing(CURRENT)["items"]}
    got = vulntrack.match_item_to_assets(items["CVE-2026-21858"], db.assets_list())
    assert len(got) == 1
    _, conf, reason = got[0]
    assert conf == "strong"
    assert "may already be patched" in reason   # 1.121.0 >= fix 1.121.0


def test_priority_ordering(tmp_db):
    import vulntrack
    crit_item = {"severity": "critical", "exploited": True, "kev": True}
    low_item = {"severity": "low", "exploited": False, "kev": False}
    inet_high = {"exposure": "internet", "criticality": "high"}
    iso_low = {"exposure": "isolated", "criticality": "low"}
    assert vulntrack.priority_for(crit_item, inet_high) == 64.8   # 4*3*3*1.5*1.2
    assert vulntrack.priority_for(low_item, iso_low) == 1.0
    assert (vulntrack.priority_for(crit_item, inet_high)
            > vulntrack.priority_for(crit_item, iso_low))


# ---- sync orchestration (BookStack mocked) -----------------------------------

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


def _mock_bookstack(monkeypatch, pages_md: dict[int, str], updated="2026-06-07T06:00:00Z"):
    import vulntrack

    def fake_fetch_cve_pages():
        return ({"slug": "cve-deep-dives"},
                [{"id": pid, "type": "page", "name": f"CVE Briefing {pid}",
                  "updated_at": updated} for pid in pages_md])

    def fake_fetch_page(pid):
        return {"id": pid, "slug": f"page-{pid}", "name": f"CVE Briefing {pid}",
                "markdown": pages_md[pid], "created_at": "2026-06-07T05:50:00Z"}

    monkeypatch.setattr(vulntrack, "fetch_cve_pages", fake_fetch_cve_pages)
    monkeypatch.setattr(vulntrack, "fetch_page", fake_fetch_page)
    vulntrack.set_config({"bookstack_url": "https://bs.example.com",
                          "bookstack_token_id": "t", "bookstack_token_secret": "s"})


def test_sync_end_to_end(auth_client, monkeypatch):
    import vulntrack
    _mk_assets(None)
    _mock_bookstack(monkeypatch, {326: CURRENT})

    res = vulntrack.sync_cve_briefings()
    assert res["pages_processed"] == 1
    assert res["items_new"] == 6
    assert res["matches_new"] >= 3              # UniFi, nginx, Proxmox at least

    # idempotent: unchanged page is skipped, matches refresh not duplicate
    res2 = vulntrack.sync_cve_briefings()
    assert res2["pages_processed"] == 0
    assert res2["matches_new"] == 0

    # matches API serves them, priority-sorted
    r = auth_client.get("/api/vulns/matches?statuses=")
    rows = r.get_json()["data"]
    assert rows and rows[0]["priority"] == max(m["priority"] for m in rows)
    assert all(m["match_reason"] for m in rows)
    # the briefing's UniFi cluster carries its BookStack deep-dive link
    uni = next(m for m in rows if m["item_key"] == "CVE-2026-34908")
    assert "books/cve-deep-dives/page/page-326" in uni["bookstack_url"]


def test_sync_updates_do_not_reopen_resolved(auth_client, monkeypatch):
    import vulntrack
    _mk_assets(None)
    _mock_bookstack(monkeypatch, {326: CURRENT})
    vulntrack.sync_cve_briefings()

    r = auth_client.get("/api/vulns/matches?statuses=")
    mid = r.get_json()["data"][0]["id"]
    r = auth_client.patch(f"/api/vulns/matches/{mid}",
                          json={"status": "resolved", "notes": "patched"})
    assert r.get_json()["data"]["status"] == "resolved"

    # page updated next day → items refresh, match status must survive
    _mock_bookstack(monkeypatch, {326: CURRENT}, updated="2026-06-08T06:00:00Z")
    vulntrack.sync_cve_briefings()
    row = db.cve_match_get(mid)
    assert row["status"] == "resolved" and row["notes"] == "patched"


def test_rematch_picks_up_new_assets(auth_client, monkeypatch):
    import vulntrack
    _mock_bookstack(monkeypatch, {326: CURRENT})
    vulntrack.sync_cve_briefings()              # no assets yet → no matches
    assert db.cve_matches_list(statuses=None) == []

    db.asset_insert("nginx", product="nginx", version="1.27.0",
                    exposure="internet", criticality="high")
    res = vulntrack.rematch_all()               # asset added later still matches
    assert res["matches_new"] >= 1


def test_rematch_prunes_retracted_but_not_touched(tmp_db):
    import vulntrack
    # neutral asset name: only `product` should drive the match, so editing
    # product genuinely retracts it (a name like "nginx" would keep fuzzy-matching)
    aid = db.asset_insert("ingress box", product="nginx",
                          exposure="internet", criticality="high")
    iid, _ = db.cve_item_upsert("CVE-2026-9999", title="nginx bug",
                                severity="high", affects="nginx all versions",
                                cve_ids='["CVE-2026-9999"]')
    vulntrack.rematch_all()
    assert len(db.cve_matches_list(statuses=None)) == 1
    mid = db.cve_matches_list(statuses=None)[0]["id"]

    # asset edited so it no longer matches → untouched 'new' match is pruned
    db.update_asset_fields(aid, product="apache httpd")
    res = vulntrack.rematch_all()
    assert res["matches_pruned"] == 1
    assert db.cve_matches_list(statuses=None) == []

    # but a match the analyst touched survives retraction
    db.update_asset_fields(aid, product="nginx")
    vulntrack.rematch_all()
    mid = db.cve_matches_list(statuses=None)[0]["id"]
    db.cve_match_set_status(mid, "investigating", "looking into it", "alex")
    db.update_asset_fields(aid, product="apache httpd")
    res = vulntrack.rematch_all()
    assert res["matches_pruned"] == 0
    assert db.cve_match_get(mid)["status"] == "investigating"


def test_cross_page_stub_dedup(auth_client, monkeypatch):
    """Live prod finding: campaign names drift across daily summary tables
    ("Mini Shai-Hulud" landed under 4 slug variants). A later page's
    summary-only stub must not fork a new item when its slug overlaps a
    known item's key or title-slug."""
    import vulntrack
    day1 = (
        "## 📋 Summary\n"
        "| # | CVE/Item | Severity | Affects | Status | Stack |\n|---|---|---|---|---|---|\n"
        "| 1 | Mini Shai-Hulud — npm worm | CRITICAL 9.6 | npm | 🔴 Active | ⚠️ |\n\n"
        "## 🔍 Deep Dives\n"
        "### 1. Supply Chain: Mini Shai-Hulud — TeamPCP npm Worm\n"
        "| | |\n|---|---|\n"
        "| **CVE** | — |\n| **Severity** | 🔴 CRITICAL — CVSS 9.6 |\n"
        "| **Affected** | 170+ npm packages |\n| **Status** | 🔴 Active campaign |\n")
    day2 = (
        "## 📋 Summary\n"
        "| # | CVE/Item | Severity | Affects | Status | Stack |\n|---|---|---|---|---|---|\n"
        "| 1 | Mini Shai-Hulud Worm (TeamPCP) | CRITICAL | npm | 🔴 Active | ⚠️ |\n\n"
        "## 🔍 Deep Dives\n")
    _mock_bookstack(monkeypatch, {1: day1, 2: day2})
    res = vulntrack.sync_cve_briefings()
    assert res["stubs_skipped"] == 1
    keys = [r["item_key"] for r in db.cve_items_list()]
    assert keys == ["mini-shai-hulud"]          # one item, not two


def test_sync_unconfigured_skips(tmp_db):
    import vulntrack
    assert vulntrack.sync_cve_briefings()["skipped"] == "bookstack not configured"


def test_match_status_validation(auth_client, monkeypatch):
    import vulntrack
    _mk_assets(None)
    _mock_bookstack(monkeypatch, {326: CURRENT})
    vulntrack.sync_cve_briefings()
    mid = db.cve_matches_list(statuses=None)[0]["id"]
    r = auth_client.patch(f"/api/vulns/matches/{mid}", json={"status": "fixed!!"})
    assert not r.get_json()["success"]
    r = auth_client.patch("/api/vulns/matches/99999", json={"status": "resolved"})
    assert r.status_code == 404 or not r.get_json()["success"]
