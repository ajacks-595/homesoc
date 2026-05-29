"""HomeSOC MCP server — interactive triage surface for Claude Code.

This exposes the dashboard's own data + actions as Model Context Protocol
tools so an interactive Claude Code session can read alerts, run OSINT,
ask for AI explanations, and (optionally) resolve alerts / manage Wazuh
false-positive suppressions — all against the same SQLite DB and the same
SSH-backed Wazuh helpers the web UI uses.

Transport
---------
stdio. Intended to be spawned over SSH from a dev workstation, e.g. an
`.mcp.json` entry that runs:

    ssh wazuh@<wazuh-vm> /opt/dashboard/venv/bin/python -m mcp_server

Whoever can spawn this already has shell access to the dashboard host, so
SSH *is* the authentication boundary. As defence-in-depth the mutating
tools are disabled unless SOC_MCP_ALLOW_MUTATIONS=1 is set in the spawned
environment, mirroring the read-only-by-default posture of the /api/home
consumer API.

Security model
--------------
- Read tools (list/search/get/osint/explain/briefing/suppressions) are
  always available.
- State-changing tools (resolve_alert, bulk_resolve, add_suppression,
  delete_suppression) return an error unless SOC_MCP_ALLOW_MUTATIONS=1.
- Every mutation is written to the audit log with username SOC_MCP_OPERATOR
  (default "mcp") and a details payload stamped {"via": "mcp", ...}, so MCP
  actions are distinguishable from web-UI actions after the fact.
- The Wazuh suppression flow reuses wazuh.py verbatim: write -> verify with
  `wazuh-analysisd -t` -> roll back on failure -> restart manager. Callers
  can never inject arbitrary XML or shell.

Output
------
Every tool returns a JSON string (pretty-printed). Errors come back as
`{"ok": false, "error": "..."}` rather than raising, so the model gets a
readable message instead of a transport-level fault.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

import ai
import database as db
import osint
import wazuh

# stdout is reserved for the MCP JSON-RPC stream; all logging must go to stderr.
logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s mcp_server %(levelname)s %(message)s")
log = logging.getLogger("mcp_server")

mcp = FastMCP("homesoc")

_OPERATOR = os.environ.get("SOC_MCP_OPERATOR", "mcp")


def _mutations_enabled() -> bool:
    return os.environ.get("SOC_MCP_ALLOW_MUTATIONS", "0") == "1"


# ---------- output helpers ------------------------------------------------

def _dump(obj: Any) -> str:
    return json.dumps(obj, default=str, indent=2)


def _ok(data: Any) -> str:
    return _dump({"ok": True, "data": data})


def _error(msg: str) -> str:
    return _dump({"ok": False, "error": msg})


def _mutation_disabled() -> str:
    return _error(
        "mutations are disabled on this MCP server. Set "
        "SOC_MCP_ALLOW_MUTATIONS=1 in the server's environment to allow "
        "state-changing tools."
    )


def _audit(action: str, target_type: str | None = None,
           target_id: str | int | None = None, details: dict | None = None) -> None:
    """Record an MCP-originated mutation. No Flask request context here, so we
    call db.audit_add directly (auth.audit() needs `request`/`current_user`)."""
    payload: dict[str, Any] = {"via": "mcp"}
    if details:
        payload.update(details)
    db.audit_add(
        user_id=None,
        username=_OPERATOR,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=json.dumps(payload),
        ip_address=None,
    )


def _alert_summary(row: Any) -> dict[str, Any]:
    """Compact view of an alert row — omits full_log/raw_json (see get_alert)."""
    d = dict(row)
    groups = d.get("rule_groups")
    if groups:
        try:
            groups = json.loads(groups)
        except (ValueError, TypeError):
            pass
    return {
        "id": d.get("id"),
        "timestamp": d.get("timestamp"),
        "agent_name": d.get("agent_name"),
        "agent_ip": d.get("agent_ip"),
        "rule_id": d.get("rule_id"),
        "rule_level": d.get("rule_level"),
        "rule_description": d.get("rule_description"),
        "rule_groups": groups,
        "status": d.get("status"),
        "location": d.get("location"),
    }


# ---------- read tools ----------------------------------------------------

@mcp.tool()
def status() -> str:
    """Server + queue overview: whether mutations are enabled, the audit
    operator name, and counts of open alerts / total alerts / suppressions.
    Cheap — no SSH, no external calls. Call this first to orient."""
    with db.conn() as c:
        open_n = c.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        total_n = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        fp_n = c.execute("SELECT COUNT(*) FROM false_positives").fetchone()[0]
    return _ok({
        "mutations_enabled": _mutations_enabled(),
        "audit_operator": _OPERATOR,
        "open_alerts": int(open_n),
        "total_alerts": int(total_n),
        "suppressions": int(fp_n),
        "alert_statuses": list(db.ALERT_STATUSES),
    })


@mcp.tool()
def list_alerts(min_level: int = 7, limit: int = 20, only_open: bool = True) -> str:
    """List recent alerts at or above min_level, newest first. By default
    only `open` alerts (still on the triage queue). Set only_open=False to
    include resolved/acknowledged. Returns compact summaries — use get_alert
    for the full record."""
    rows = db.latest_alerts(min_level=min_level, limit=limit, only_open=only_open)
    return _ok([_alert_summary(r) for r in rows])


@mcp.tool()
def search_alerts(search: str | None = None, agent: str | None = None,
                  rule_id: str | None = None, min_level: int | None = None,
                  group: str | None = None, status: str | None = None,
                  date_from: str | None = None, date_to: str | None = None,
                  limit: int = 50, offset: int = 0) -> str:
    """Filtered alert search. `search` matches full_log/description/agent.
    `status` is one of open/in_progress/tp_remediated/false_positive/
    acknowledged. Dates are ISO strings matched against the alert timestamp.
    Returns {total, count, alerts:[summaries]} — total is the unpaged match
    count for paging with limit/offset."""
    statuses = [status] if status else None
    rows, total = db.query_alerts(
        date_from=date_from, date_to=date_to, agent=agent, rule_id=rule_id,
        min_level=min_level, group=group, search=search, statuses=statuses,
        limit=limit, offset=offset,
    )
    return _ok({
        "total": int(total),
        "count": len(rows),
        "alerts": [_alert_summary(r) for r in rows],
    })


@mcp.tool()
def get_alert(alert_id: int) -> str:
    """Full record for one alert, including the parsed raw Wazuh JSON and the
    cached AI explanation if one exists. Use this after list/search to inspect
    a specific alert before deciding how to resolve it."""
    row = db.get_alert(alert_id)
    if not row:
        return _error(f"alert {alert_id} not found")
    d = dict(row)
    raw = d.get("raw_json")
    if raw:
        try:
            d["raw"] = json.loads(raw)
        except (ValueError, TypeError):
            d["raw"] = None
    d.pop("raw_json", None)
    expl = db.explanation_get(alert_id)
    if expl:
        e = dict(expl)
        d["explanation"] = {"content": e.get("content"), "model": e.get("model"),
                            "created_at": e.get("created_at")}
    return _ok(d)


@mcp.tool()
def list_fp_candidates(limit: int = 20, min_count: int = 3) -> str:
    """Surface false-positive candidates: rules that fire frequently and are
    still open, excluding rules already suppressed. Returns rules ordered by
    open-alert count (only those with >= min_count). These are the rules worth
    reviewing for an add_suppression."""
    with db.conn() as c:
        rows = c.execute(
            """SELECT rule_id,
                      MAX(rule_description) AS rule_description,
                      MAX(rule_level)       AS rule_level,
                      COUNT(*)              AS open_count,
                      MAX(timestamp)        AS last_seen
               FROM alerts
               WHERE status='open'
                 AND rule_id NOT IN (SELECT rule_id FROM false_positives)
               GROUP BY rule_id
               HAVING open_count >= ?
               ORDER BY open_count DESC
               LIMIT ?""",
            (min_count, limit),
        ).fetchall()
    return _ok([dict(r) for r in rows])


@mcp.tool()
def get_suppressions(include_live: bool = False) -> str:
    """List configured Wazuh false-positive suppressions from the dashboard
    DB. With include_live=True, also reads local_rules.xml over SSH and returns
    the rules actually present on the manager (slower — one SSH round-trip)."""
    fps = [dict(r) for r in db.list_fps()]
    result: dict[str, Any] = {"db": fps, "live": None}
    if include_live:
        try:
            xml = wazuh.read_local_rules()
            result["live"] = wazuh.parse_existing_suppressions(xml)
        except Exception as e:  # noqa: BLE001
            result["live_error"] = str(e)
    return _ok(result)


@mcp.tool()
def list_actions(status: str | None = None, priority: str | None = None) -> str:
    """List recommended actions parsed from briefings (the P1/P2/P3 kanban).
    Filter by status (open/in_progress/resolved) and/or priority (P1/P2/P3)."""
    rows = db.list_actions(status=status, priority=priority)
    return _ok([dict(r) for r in rows])


@mcp.tool()
def get_briefing(date: str | None = None, btype: str = "daily") -> str:
    """Fetch a briefing's full markdown. With no date, returns the latest of
    the given type (btype = daily | weekly). With a date (YYYY-MM-DD), returns
    that day's briefing."""
    row = db.get_briefing_by_date(date, btype) if date else db.latest_briefing(btype)
    if not row:
        return _error(f"no {btype} briefing found" + (f" for {date}" if date else ""))
    return _ok(dict(row))


@mcp.tool()
def osint_lookup(ioc: str, force_refresh: bool = False) -> str:
    """Run an IOC (IP / domain / URL / hash) through VirusTotal, AbuseIPDB
    (IPs only) and URLScan, using the dashboard's configured API keys and 7-day
    cache. force_refresh=True bypasses the cache. NOTE: this calls external
    services and consumes provider quota."""
    if not ioc or not ioc.strip():
        return _error("ioc is required")
    return _ok(osint.run_all(ioc.strip(), force_refresh=force_refresh))


@mcp.tool()
def explain_alert(alert_id: int, refresh: bool = False) -> str:
    """Get an AI explanation of an alert, cross-correlated with other recent
    Wazuh alerts and DNS activity. Returns the cached explanation if one exists
    unless refresh=True. NOTE: a fresh explanation invokes the Claude CLI
    (cost + latency, ~10-40s) and is recorded in ai_runs as kind='explain_mcp'.
    Unlike the dashboard auto-explainer this is not subject to the 20/24h cap —
    it is analyst-initiated."""
    row = db.get_alert(alert_id)
    if not row:
        return _error(f"alert {alert_id} not found")
    if not refresh:
        cached = db.explanation_get(alert_id)
        if cached:
            e = dict(cached)
            return _ok({"alert_id": alert_id, "cached": True,
                        "model": e.get("model"), "content": e.get("content")})
    try:
        raw = json.loads(row["raw_json"] or "{}")
    except (ValueError, TypeError):
        raw = {}
    t0 = time.monotonic()
    try:
        content, model = ai.explain_with_enrichment(raw, alert_id)
    except Exception as e:  # noqa: BLE001
        elapsed = int((time.monotonic() - t0) * 1000)
        db.ai_run_add(alert_id, "explain_mcp", "unknown", elapsed, success=False)
        return _error(f"AI explanation failed: {e}")
    elapsed = int((time.monotonic() - t0) * 1000)
    db.explanation_put(alert_id, content, model)
    db.ai_run_add(alert_id, "explain_mcp", model, elapsed, success=True)
    return _ok({"alert_id": alert_id, "cached": False, "model": model,
                "elapsed_ms": elapsed, "content": content})


# ---------- mutating tools (gated) ----------------------------------------

@mcp.tool()
def resolve_alert(alert_id: int, status: str, notes: str | None = None) -> str:
    """Set an alert's resolution status. status is one of: open, in_progress,
    tp_remediated, false_positive, acknowledged. `notes` are stored as
    ack_notes. Audited as alert.status_change (via=mcp). Requires mutations
    to be enabled."""
    if not _mutations_enabled():
        return _mutation_disabled()
    if status not in db.ALERT_STATUSES:
        return _error(f"invalid status '{status}'; valid: {list(db.ALERT_STATUSES)}")
    if not db.get_alert(alert_id):
        return _error(f"alert {alert_id} not found")
    db.set_alert_status(alert_id, status, notes)
    _audit("alert.status_change", "alert", alert_id, {"status": status, "notes": notes})
    return _ok({"alert_id": alert_id, "status": status})


@mcp.tool()
def bulk_resolve(alert_ids: list[int], status: str, notes: str | None = None) -> str:
    """Set the same resolution status on many alerts at once — useful after
    triaging a noisy rule. Returns per-id results. Audited once as
    alert.bulk_status_change (via=mcp). Requires mutations to be enabled."""
    if not _mutations_enabled():
        return _mutation_disabled()
    if status not in db.ALERT_STATUSES:
        return _error(f"invalid status '{status}'; valid: {list(db.ALERT_STATUSES)}")
    if not alert_ids:
        return _error("alert_ids is empty")
    updated, missing = [], []
    for aid in alert_ids:
        if db.get_alert(aid):
            db.set_alert_status(aid, status, notes)
            updated.append(aid)
        else:
            missing.append(aid)
    _audit("alert.bulk_status_change", "alert", None,
           {"status": status, "notes": notes, "updated": updated, "missing": missing})
    return _ok({"status": status, "updated": updated, "missing": missing,
                "updated_count": len(updated)})


@mcp.tool()
def add_suppression(rule_id: str, description: str, agent_name: str | None = None) -> str:
    """Add a Wazuh false-positive suppression for a rule (optionally scoped to
    one agent). This writes local_rules.xml on the manager, validates with
    `wazuh-analysisd -t`, rolls back automatically if validation fails, and
    restarts the manager on success — identical to the dashboard's /fp/add.
    Audited as fp.add (via=mcp). Requires mutations to be enabled."""
    if not _mutations_enabled():
        return _mutation_disabled()
    rid = (rule_id or "").strip()
    desc = (description or "").strip()
    agent = (agent_name or "").strip() or None
    if not rid or not desc:
        return _error("rule_id and description are required")
    if not rid.isdigit():
        return _error("rule_id must be numeric")

    try:
        original = wazuh.read_local_rules()
    except Exception as e:  # noqa: BLE001
        return _error(f"cannot read local_rules.xml: {e}")

    new_rid = wazuh.next_local_rule_id(original)
    snippet = wazuh.build_suppression(rid, agent, desc, new_rid)
    updated = wazuh.insert_into_group(original, snippet)

    try:
        wazuh.write_local_rules(updated)
    except Exception as e:  # noqa: BLE001
        return _error(f"write failed: {e}")

    ok_verify, verify_out = wazuh.verify_config()
    if not ok_verify:
        try:
            wazuh.write_local_rules(original)  # roll back
        except Exception:  # noqa: BLE001
            log.exception("rollback after failed verify also failed")
        return _error(f"verifyconf failed (rolled back): {verify_out[-500:]}")

    ok_restart, restart_out = wazuh.restart_manager()
    if not ok_restart:
        return _error(f"manager restart failed: {restart_out[-500:]}")

    db.insert_fp(rid, agent, desc, new_rid, snippet)
    db.refresh_fp_alert_counts()
    _audit("fp.add", "wazuh_rule", new_rid,
           {"suppresses": rid, "agent": agent, "description": desc})
    return _ok({"new_rule_id": new_rid, "suppresses": rid, "agent": agent,
                "verify": verify_out[-500:], "restart": restart_out[-200:]})


@mcp.tool()
def delete_suppression(fp_id: int) -> str:
    """Remove a false-positive suppression by its DB id (see get_suppressions).
    Rewrites local_rules.xml, validates + rolls back on failure, restarts the
    manager. Audited as fp.delete (via=mcp). Requires mutations to be enabled."""
    if not _mutations_enabled():
        return _mutation_disabled()
    with db.conn() as c:
        row = c.execute("SELECT * FROM false_positives WHERE id=?", (fp_id,)).fetchone()
    if not row:
        return _error(f"suppression {fp_id} not found")

    try:
        original = wazuh.read_local_rules()
    except Exception as e:  # noqa: BLE001
        return _error(str(e))

    updated = wazuh.remove_rule_from_xml(original, row["wazuh_rule_id"])
    try:
        wazuh.write_local_rules(updated)
    except Exception as e:  # noqa: BLE001
        return _error(f"write failed: {e}")

    ok_verify, verify_out = wazuh.verify_config()
    if not ok_verify:
        try:
            wazuh.write_local_rules(original)  # roll back
        except Exception:  # noqa: BLE001
            log.exception("rollback after failed verify also failed")
        return _error(f"verifyconf failed (rolled back): {verify_out[-500:]}")

    wazuh.restart_manager()
    db.delete_fp(fp_id)
    _audit("fp.delete", "wazuh_rule", row["wazuh_rule_id"],
           {"suppressed_rule": row["rule_id"]})
    return _ok({"deleted": fp_id, "removed_rule_id": row["wazuh_rule_id"]})


def main() -> None:
    db.init_db()  # idempotent — ensures schema exists in dev/fresh setups
    log.info("HomeSOC MCP server starting (mutations=%s, operator=%s)",
             _mutations_enabled(), _OPERATOR)
    mcp.run()


if __name__ == "__main__":
    main()
