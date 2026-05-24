"""Tests for the MCP triage server (mcp_server.py).

Exercises tools through the real MCP path (mcp.call_tool), so argument
validation + serialization are covered too. Read tools run against a seeded
temp DB; the Wazuh suppression flow is tested with wazuh.py monkeypatched so
no SSH is required.

Security contract under test:
  - read tools always work
  - mutating tools refuse unless SOC_MCP_ALLOW_MUTATIONS=1
  - every mutation lands in the audit log stamped via=mcp, operator=mcp
"""
from __future__ import annotations

import pytest

# The MCP server is an optional add-on (requirements-mcp.txt). Skip the whole
# module cleanly if the `mcp` SDK isn't installed, so core CI stays green.
pytest.importorskip("mcp")

import asyncio
import json

import mcp_server
import database as db


def call(name: str, **arguments):
    """Invoke an MCP tool and return its parsed {ok, data|error} payload."""
    content, _structured = asyncio.run(mcp_server.mcp.call_tool(name, arguments))
    return json.loads(content[0].text)


def _seed_alert(rule_id="5710", level=7, status="open", agent="host-a",
                desc="sshd failed login", wazuh_id=None, raw=None):
    with db.conn() as c:
        cur = c.execute(
            """INSERT INTO alerts
               (wazuh_id, timestamp, agent_name, agent_ip, rule_id, rule_level,
                rule_description, rule_groups, full_log, location, raw_json, status)
               VALUES (?, datetime('now'), ?, '10.0.0.9', ?, ?, ?, ?, 'log', '/var/log', ?, ?)""",
            (wazuh_id, agent, rule_id, level, desc, '["authentication_failed"]',
             json.dumps(raw or {"rule": {"id": rule_id, "level": level}}), status),
        )
        return int(cur.lastrowid)


# ---------- read tools ----------------------------------------------------

def test_status_reports_counts_and_mutation_flag(tmp_db, monkeypatch):
    monkeypatch.delenv("SOC_MCP_ALLOW_MUTATIONS", raising=False)
    _seed_alert(status="open")
    _seed_alert(status="acknowledged")
    r = call("status")
    assert r["ok"] is True
    assert r["data"]["mutations_enabled"] is False
    assert r["data"]["open_alerts"] == 1
    assert r["data"]["total_alerts"] == 2


def test_list_alerts_filters_open_and_level(tmp_db):
    _seed_alert(rule_id="100", level=12, status="open")
    _seed_alert(rule_id="101", level=3, status="open")      # below min_level
    _seed_alert(rule_id="102", level=12, status="acknowledged")  # not open
    r = call("list_alerts", min_level=7, only_open=True)
    assert r["ok"] is True
    rule_ids = {a["rule_id"] for a in r["data"]}
    assert rule_ids == {"100"}


def test_search_alerts_returns_total_and_matches(tmp_db):
    _seed_alert(rule_id="200", desc="brute force ssh")
    _seed_alert(rule_id="201", desc="package updated")
    r = call("search_alerts", search="brute")
    assert r["ok"] is True
    assert r["data"]["total"] == 1
    assert r["data"]["alerts"][0]["rule_id"] == "200"


def test_get_alert_includes_raw_and_missing_is_error(tmp_db):
    aid = _seed_alert(raw={"rule": {"id": "300"}, "data": {"srcip": "1.2.3.4"}})
    r = call("get_alert", alert_id=aid)
    assert r["ok"] is True
    assert r["data"]["raw"]["data"]["srcip"] == "1.2.3.4"
    assert "raw_json" not in r["data"]      # replaced by parsed `raw`
    assert call("get_alert", alert_id=999999)["ok"] is False


def test_list_fp_candidates_groups_and_excludes_suppressed(tmp_db):
    for _ in range(4):
        _seed_alert(rule_id="5710", status="open")     # noisy -> candidate
    for _ in range(2):
        _seed_alert(rule_id="5711", status="open")     # below min_count=3
    # 5712 is noisy but already suppressed -> excluded
    for _ in range(5):
        _seed_alert(rule_id="5712", status="open")
    db.insert_fp("5712", None, "already handled", "100000", "<rule/>")

    r = call("list_fp_candidates", min_count=3)
    assert r["ok"] is True
    ids = {row["rule_id"] for row in r["data"]}
    assert ids == {"5710"}
    assert r["data"][0]["open_count"] == 4


def test_get_suppressions_db_only(tmp_db):
    db.insert_fp("5710", "host-a", "noisy ssh", "100000", "<rule/>")
    r = call("get_suppressions", include_live=False)
    assert r["ok"] is True
    assert r["data"]["live"] is None
    assert len(r["data"]["db"]) == 1
    assert r["data"]["db"][0]["rule_id"] == "5710"


# ---------- mutation gate -------------------------------------------------

def test_mutations_disabled_by_default(tmp_db, monkeypatch):
    monkeypatch.delenv("SOC_MCP_ALLOW_MUTATIONS", raising=False)
    aid = _seed_alert()
    for name, args in [
        ("resolve_alert", {"alert_id": aid, "status": "false_positive"}),
        ("bulk_resolve", {"alert_ids": [aid], "status": "false_positive"}),
        ("add_suppression", {"rule_id": "5710", "description": "x"}),
        ("delete_suppression", {"fp_id": 1}),
    ]:
        r = call(name, **args)
        assert r["ok"] is False, f"{name} should be blocked"
        assert "disabled" in r["error"].lower()
    # and the alert was NOT modified
    assert db.get_alert(aid)["status"] == "open"


# ---------- mutating tools (enabled) --------------------------------------

def test_resolve_alert_changes_status_and_audits(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_MCP_ALLOW_MUTATIONS", "1")
    aid = _seed_alert()
    r = call("resolve_alert", alert_id=aid, status="false_positive", notes="benign")
    assert r["ok"] is True
    assert db.get_alert(aid)["status"] == "false_positive"
    assert db.get_alert(aid)["ack_notes"] == "benign"
    audit = db.audit_list(action="alert.status_change")
    assert len(audit) == 1
    assert audit[0]["username"] == "mcp"
    assert json.loads(audit[0]["details"])["via"] == "mcp"


def test_resolve_alert_rejects_bad_status(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_MCP_ALLOW_MUTATIONS", "1")
    aid = _seed_alert()
    r = call("resolve_alert", alert_id=aid, status="bogus")
    assert r["ok"] is False
    assert "invalid status" in r["error"].lower()


def test_bulk_resolve_reports_updated_and_missing(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_MCP_ALLOW_MUTATIONS", "1")
    a1, a2 = _seed_alert(), _seed_alert()
    r = call("bulk_resolve", alert_ids=[a1, a2, 999999], status="acknowledged")
    assert r["ok"] is True
    assert set(r["data"]["updated"]) == {a1, a2}
    assert r["data"]["missing"] == [999999]
    assert db.get_alert(a1)["status"] == "acknowledged"


def test_add_suppression_orchestrates_and_audits(tmp_db, monkeypatch):
    """add_suppression should write+verify+restart (mocked) then persist the
    FP row and audit it via=mcp."""
    monkeypatch.setenv("SOC_MCP_ALLOW_MUTATIONS", "1")
    written = {}
    monkeypatch.setattr(mcp_server.wazuh, "read_local_rules",
                        lambda: '<group name="local,">\n</group>\n')
    monkeypatch.setattr(mcp_server.wazuh, "write_local_rules",
                        lambda xml: written.update(xml=xml))
    monkeypatch.setattr(mcp_server.wazuh, "verify_config", lambda: (True, "ok"))
    monkeypatch.setattr(mcp_server.wazuh, "restart_manager", lambda: (True, "restarted"))

    r = call("add_suppression", rule_id="5710", description="noisy ssh", agent_name="host-a")
    assert r["ok"] is True
    assert r["data"]["new_rule_id"] == "100000"
    assert "5710" in written["xml"]                  # snippet was written
    fps = db.list_fps()
    assert len(fps) == 1 and fps[0]["rule_id"] == "5710"
    audit = db.audit_list(action="fp.add")
    assert len(audit) == 1
    assert json.loads(audit[0]["details"])["via"] == "mcp"


def test_add_suppression_rolls_back_on_verify_failure(tmp_db, monkeypatch):
    """If wazuh-analysisd -t rejects the new XML, the original must be
    rewritten and no FP row persisted."""
    monkeypatch.setenv("SOC_MCP_ALLOW_MUTATIONS", "1")
    writes = []
    monkeypatch.setattr(mcp_server.wazuh, "read_local_rules",
                        lambda: '<group name="local,">\nORIGINAL\n</group>\n')
    monkeypatch.setattr(mcp_server.wazuh, "write_local_rules",
                        lambda xml: writes.append(xml))
    monkeypatch.setattr(mcp_server.wazuh, "verify_config", lambda: (False, "syntax error"))
    monkeypatch.setattr(mcp_server.wazuh, "restart_manager",
                        lambda: pytest.fail("must not restart after failed verify"))

    r = call("add_suppression", rule_id="5710", description="x")
    assert r["ok"] is False
    assert "rolled back" in r["error"].lower()
    assert "ORIGINAL" in writes[-1]            # last write restored the original
    assert db.list_fps() == []
