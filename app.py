"""Flask application — routes, blueprints, JSON API."""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import threading
from datetime import datetime, timedelta, timezone

import markdown as md_lib
import nh3
import requests
from flask import (
    Blueprint, Flask, g, jsonify, render_template, request, send_file,
)

import ai
import auth
import backup
import config
import database as db
import notifications
import osint
import parsers
import sync
import vulntrack
import wazuh


# ---------- logging --------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_PATH),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("soc.app")


# ---------- helpers --------------------------------------------------------

def ok(data=None, **extra):
    return jsonify({"success": True, "data": data, "error": None, **extra})


def err(message: str, code: int = 400, **extra):
    return jsonify({"success": False, "data": None, "error": message, **extra}), code


class BadParam(ValueError):
    """A request parameter failed to parse — surfaced as a 400 JSON error
    (via an errorhandler) instead of a bare int() ValueError → 500."""


def int_arg(name: str, default: int | None = None, *,
            minimum: int | None = None, maximum: int | None = None) -> int | None:
    """Parse an integer query-string arg. Missing/empty → default. Raises
    BadParam on a non-integer value; clamps to [minimum, maximum] if given."""
    raw = request.args.get(name)
    if raw is None or raw == "":
        if default is None:
            return None
        raw = str(default)
    try:
        v = int(raw)
    except (TypeError, ValueError):
        raise BadParam(f"{name} must be an integer")
    if minimum is not None:
        v = max(v, minimum)
    if maximum is not None:
        v = min(v, maximum)
    return v


def int_field(data: dict, name: str, default: int) -> int:
    """Parse an integer from a JSON body field. Missing/None → default. Raises
    BadParam on a non-integer value."""
    if name not in data or data[name] is None:
        return default
    try:
        return int(data[name])
    except (TypeError, ValueError):
        raise BadParam(f"{name} must be an integer")


def _csv_safe(value) -> str:
    """Neutralise CSV/formula injection (CWE-1236). Spreadsheet apps execute a
    cell whose text starts with = + - @ (or a leading tab/CR), and alert fields
    like full_log are attacker-influenced. Prefix any such cell with a single
    quote so it's treated as text, not a formula."""
    s = "" if value is None else str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def row_to_dict(row) -> dict:
    if row is None:
        return {}
    d = dict(row)
    # decode JSON-stored columns
    for k in ("rule_groups", "raw_json"):
        if k in d and isinstance(d[k], str) and d[k]:
            try:
                d[k] = json.loads(d[k])
            except json.JSONDecodeError:
                pass
    return d


# Tags/attributes permitted in rendered markdown (briefings, AI explanations,
# follow-up chat, exec summary). The rendered HTML is injected into the DOM via
# innerHTML on the client, and the source can include AI/Claude output (which
# runs with WebSearch/WebFetch), so raw HTML is NOT trusted. nh3 strips
# <script>, on* event handlers, and dangerous URL schemes (javascript:, data:)
# while preserving formatting — the root-cause fix for the stored-XSS surface.
_MD_ALLOWED_TAGS = {
    "a", "p", "br", "hr", "span", "div",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "dl", "dt", "dd",
    "strong", "em", "b", "i", "u", "s", "del", "ins", "sup", "sub", "mark",
    "code", "pre", "kbd", "samp", "var",
    "blockquote", "q", "abbr", "cite",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td",
    "caption", "col", "colgroup",
    "img",
}
_MD_ALLOWED_ATTRS = {
    "a":        {"href", "title"},
    "img":      {"src", "alt", "title"},
    "td":       {"align"},
    "th":       {"align", "scope"},
    "col":      {"span"},
    "colgroup": {"span"},
    "ol":       {"start"},
}
_MD_URL_SCHEMES = {"http", "https", "mailto"}


def render_md(text: str) -> str:
    """Render markdown to HTML, then sanitize against an allowlist.

    Output is trusted by the client (injected via innerHTML), but the input can
    contain attacker-influenced content (AI web-fetched threat intel, briefing
    bodies). nh3 enforces the tag/attribute/URL-scheme allowlist below."""
    raw = md_lib.markdown(
        text or "",
        extensions=["fenced_code", "tables", "sane_lists", "nl2br"],
        output_format="html5",
    )
    return nh3.clean(
        raw,
        tags=_MD_ALLOWED_TAGS,
        attributes=_MD_ALLOWED_ATTRS,
        url_schemes=_MD_URL_SCHEMES,
        link_rel="noopener noreferrer nofollow",
    )


# ---------- pages blueprint -----------------------------------------------

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def dashboard_page():
    return render_template("dashboard.html", theme=config.DEFAULT_THEME)


@pages_bp.route("/briefings")
def briefings_page():
    return render_template("briefings.html", theme=config.DEFAULT_THEME)


@pages_bp.route("/alerts")
def alerts_page():
    return render_template("alerts.html", theme=config.DEFAULT_THEME)


@pages_bp.route("/osint")
def osint_page():
    ioc = request.args.get("ioc", "")
    return render_template("osint.html", theme=config.DEFAULT_THEME, ioc=ioc)


@pages_bp.route("/fp-manager")
def fp_page():
    return render_template("fp_manager.html", theme=config.DEFAULT_THEME)


@pages_bp.route("/actions")
def actions_page():
    return render_template("actions.html", theme=config.DEFAULT_THEME)


@pages_bp.route("/hosts")
def hosts_page():
    return render_template("hosts.html", theme=config.DEFAULT_THEME)


@pages_bp.route("/threat-intel")
def ti_page():
    tab = request.args.get("tab", "dns")
    return render_template("threat_intel.html", theme=config.DEFAULT_THEME, tab=tab)


@pages_bp.route("/vulns")
def vulns_page():
    tab = request.args.get("tab", "dashboard")
    return render_template("vulns.html", theme=config.DEFAULT_THEME, tab=tab)


@pages_bp.route("/settings")
def settings_page():
    return render_template("settings.html", theme=config.DEFAULT_THEME,
                           themes=config.THEMES)


# ---------- dashboard API -------------------------------------------------

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/dashboard/metrics")
def metrics():
    alerts_today = db.alerts_today_count()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dns = db.dns_get_daily(today) or {"total_queries": 0, "blocked_queries": 0}
    block_rate = (
        round(100.0 * dns["blocked_queries"] / dns["total_queries"], 1)
        if dns["total_queries"] else 0.0
    )
    open_p1 = len(db.list_actions(status="open", priority="P1"))
    open_p1 += len(db.list_actions(status="in_progress", priority="P1"))
    active_agents = sum(1 for h in db.list_hosts() if h["agent_status"] == "active")

    # Level-10+ open alerts in last 24h — surfaced as a banner on the dashboard.
    # Any alert that's been triaged (in_progress / resolved / fp / acked) is
    # off the queue and shouldn't re-appear here.
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    with db.conn() as c:
        crit_rows = c.execute(
            """SELECT id, timestamp, agent_name, rule_id, rule_level, rule_description
               FROM alerts
               WHERE rule_level >= 10 AND timestamp >= ? AND status = 'open'
               ORDER BY timestamp DESC LIMIT 10""",
            (cutoff,),
        ).fetchall()
    critical = [dict(r) for r in crit_rows]

    return ok({
        "alerts_today":  alerts_today,
        "block_rate":    block_rate,
        "active_agents": active_agents,
        "open_p1":       open_p1,
        "dns_total":     dns["total_queries"],
        "dns_blocked":   dns["blocked_queries"],
        "critical_24h":  critical,
        "critical_count": len(critical),
    })


@api_bp.route("/dashboard/summary")
def todays_summary():
    """Executive summary section pulled from today's briefing (or latest)."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    row = db.get_briefing_by_date(today, "daily") or db.latest_briefing("daily")
    if not row:
        return ok({"html": "<p><em>No briefing available yet.</em></p>",
                   "date": None})
    content = row["content"]
    # Extract "## Executive Summary" through next ## or end
    m = re.search(r"^##\s*Executive Summary.*?(?=^##\s|\Z)",
                  content, re.MULTILINE | re.DOTALL)
    section = m.group(0) if m else content[:2000]
    return ok({"html": render_md(section), "date": row["date"]})


@api_bp.route("/dashboard/stats")
def dashboard_stats():
    s = db.alert_stats_7d()
    dns_trend = db.dns_last_n_days(7)
    return ok({
        "alerts_by_day":     s["by_day"],
        "alerts_by_severity": s["by_severity"],
        "alerts_top_rules":  s["top_rules"],
        "dns_trend":         dns_trend,
    })


# ---------- alerts API ----------------------------------------------------

@api_bp.route("/alerts")
def alerts_query():
    page = int_arg("page", 1, minimum=1)
    per_page = int_arg("per_page", 50, minimum=1, maximum=200)
    # statuses: comma-separated list, or empty → all (no filter)
    # default: 'open' only — matches the typical "what's on my queue" mental model.
    raw_statuses = request.args.get("statuses")
    if raw_statuses is None:
        statuses: list[str] | None = ["open"]
    elif raw_statuses == "":
        statuses = None     # explicit "show everything"
    else:
        statuses = [s for s in raw_statuses.split(",") if s in db.ALERT_STATUSES]
    rows, total = db.query_alerts(
        date_from=request.args.get("date_from"),
        date_to=request.args.get("date_to"),
        agent=request.args.get("agent"),
        rule_id=request.args.get("rule_id"),
        min_level=int_arg("min_level", minimum=0, maximum=16),
        group=request.args.get("group"),
        search=request.args.get("q"),
        mitre=request.args.get("mitre"),
        statuses=statuses,
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    return ok({
        "rows":   [row_to_dict(r) for r in rows],
        "total":  total,
        "page":   page,
        "per_page": per_page,
    })


@api_bp.route("/alerts/<int:aid>/explain", methods=["GET", "POST"])
def alerts_explain(aid: int):
    """Get or generate an AI explanation for this alert.

    GET returns the cached explanation if present, else generates one.
    POST always regenerates (used by the "refresh" button)."""
    row = db.get_alert(aid)
    if not row:
        return err("alert not found", 404)

    force = request.method == "POST" or request.args.get("refresh") == "1"
    if not force:
        cached = db.explanation_get(aid)
        if cached:
            return ok({
                "content":    cached["content"],
                "html":       render_md(cached["content"]),
                "model":      cached["model"],
                "created_at": cached["created_at"],
                "from_cache": True,
            })

    # GET with no cache: do NOT auto-generate — the user must POST to opt in.
    # Avoids burning Claude calls on every accidental row-expansion.
    if request.method == "GET":
        return ok({"content": None, "html": None, "from_cache": False,
                   "not_generated": True})

    try:
        raw = json.loads(row["raw_json"]) if row["raw_json"] else {}
    except json.JSONDecodeError:
        raw = {}

    try:
        import time as _t
        t0 = _t.time()
        content, model_used = ai.explain(raw, alert_id=aid)
        elapsed_ms = int((_t.time() - t0) * 1000)
        db.ai_run_add(aid, "manual_explain", model_used, elapsed_ms, success=True)
    except Exception as e:  # noqa: BLE001
        db.ai_run_add(aid, "manual_explain", "(failed)", 0, success=False)
        log.exception("AI explain failed for alert %s", aid)
        return err(f"AI explanation failed: {e}", 500)

    db.explanation_put(aid, content, model_used)
    return ok({
        "content":    content,
        "html":       render_md(content),
        "model":      model_used,
        "created_at": None,
        "from_cache": False,
    })


@api_bp.route("/alerts/<int:aid>/explain", methods=["DELETE"])
def alerts_explain_clear(aid: int):
    db.explanation_delete(aid)
    db.chat_clear(aid)        # follow-ups only make sense with an explanation
    return ok({"cleared": aid})


def _chat_msg_html(msg: dict) -> dict:
    """Render a chat message's content as HTML for client consumption."""
    return {
        "role":       msg["role"],
        "content":    msg["content"],
        "html":       render_md(msg["content"]),
        "created_at": msg.get("created_at"),
    }


@api_bp.route("/alerts/<int:aid>/chat", methods=["GET"])
def alerts_chat_list(aid: int):
    if not db.get_alert(aid):
        return err("alert not found", 404)
    history = db.chat_history(aid)
    return ok({"history": [_chat_msg_html(m) for m in history]})


@api_bp.route("/alerts/<int:aid>/chat", methods=["POST"])
def alerts_chat_send(aid: int):
    row = db.get_alert(aid)
    if not row:
        return err("alert not found", 404)
    p = request.get_json(silent=True) or {}
    msg = (p.get("message") or "").strip()
    if not msg:
        return err("message required")

    explanation_row = db.explanation_get(aid)
    if not explanation_row:
        return err("generate an AI explanation first")

    try:
        raw = json.loads(row["raw_json"]) if row["raw_json"] else {}
    except json.JSONDecodeError:
        raw = {}

    history = db.chat_history(aid)

    try:
        import time as _t
        t0 = _t.time()
        reply, model_used = ai.chat(
            alert_raw=raw,
            explanation=explanation_row["content"],
            history=history,
            user_message=msg,
        )
        elapsed_ms = int((_t.time() - t0) * 1000)
        db.ai_run_add(aid, "chat", model_used, elapsed_ms, success=True)
    except Exception as e:  # noqa: BLE001
        db.ai_run_add(aid, "chat", "(failed)", 0, success=False)
        log.exception("AI chat failed for alert %s", aid)
        return err(f"AI chat failed: {e}", 500)

    db.chat_append(aid, "user", msg)
    db.chat_append(aid, "assistant", reply)

    full_history = db.chat_history(aid)
    return ok({
        "history": [_chat_msg_html(m) for m in full_history],
        "model":   model_used,
    })


@api_bp.route("/alerts/<int:aid>/chat", methods=["DELETE"])
def alerts_chat_clear(aid: int):
    db.chat_clear(aid)
    return ok({"cleared": aid})


@api_bp.route("/alerts/<int:aid>", methods=["PATCH"])
def alerts_ack(aid: int):
    p = request.get_json(silent=True) or {}
    status = p.get("status")
    if status not in db.ALERT_STATUSES:
        return err(f"status must be one of: {', '.join(db.ALERT_STATUSES)}")
    try:
        db.set_alert_status(aid, status, p.get("notes"))
    except ValueError as e:
        return err(str(e))
    row = db.get_alert(aid)
    if not row:
        return err("not found", 404)
    auth.audit("alert.status_change", "alert", aid,
               {"new_status": status, "notes": p.get("notes")})
    return ok(row_to_dict(row))


@api_bp.route("/alerts/latest")
def alerts_latest():
    rows = db.latest_alerts(min_level=int_arg("min_level", 7, minimum=0, maximum=16),
                            limit=int_arg("limit", 10, minimum=1, maximum=200))
    return ok([row_to_dict(r) for r in rows])


@api_bp.route("/alerts/<int:aid>")
def alert_detail(aid: int):
    row = db.get_alert(aid)
    if not row:
        return err("not found", 404)
    return ok(row_to_dict(row))


@api_bp.route("/alerts/<int:aid>/related")
def alert_related(aid: int):
    """IOC cross-correlation for this alert (other alerts + today's DNS in the
    last 24h) — computed from the DB, no AI call."""
    row = db.get_alert(aid)
    if not row:
        return err("not found", 404)
    try:
        raw = json.loads(row["raw_json"]) if row["raw_json"] else {}
    except json.JSONDecodeError:
        raw = {}
    return ok(ai.related_observations(aid, raw))


@api_bp.route("/mitre/summary")
def mitre_overview():
    """MITRE ATT&CK tactic/technique counts over the last N days (default 7)."""
    return ok(db.mitre_summary(days=int_arg("days", 7, minimum=1, maximum=365)))


@api_bp.route("/metrics/soc")
def soc_metrics_overview():
    """Analyst performance metrics (MTTR, FP rate, triage volume) over N days."""
    return ok(db.soc_metrics(days=int_arg("days", 7, minimum=1, maximum=365)))


@api_bp.route("/alerts/export")
def alerts_export():
    rows, _ = db.query_alerts(
        date_from=request.args.get("date_from"),
        date_to=request.args.get("date_to"),
        agent=request.args.get("agent"),
        rule_id=request.args.get("rule_id"),
        min_level=int_arg("min_level", minimum=0, maximum=16),
        group=request.args.get("group"),
        search=request.args.get("q"),
        mitre=request.args.get("mitre"),
        limit=10000,
        with_total=False,   # CSV export discards the total → skip the COUNT scan
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "agent_name", "agent_ip", "rule_id", "rule_level",
                "rule_description", "rule_groups", "location", "full_log"])
    for r in rows:
        w.writerow([_csv_safe(c) for c in (
            r["timestamp"], r["agent_name"], r["agent_ip"],
            r["rule_id"], r["rule_level"], r["rule_description"],
            r["rule_groups"], r["location"], r["full_log"])])
    data = buf.getvalue().encode("utf-8")
    return send_file(
        io.BytesIO(data), mimetype="text/csv",
        as_attachment=True,
        download_name=f"alerts-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.csv",
    )


@api_bp.route("/alerts/sync", methods=["POST"])
def alerts_sync():
    return ok(sync.sync_recent_alerts())


# ---------- briefings API -------------------------------------------------

@api_bp.route("/briefings")
def briefings_list():
    btype = request.args.get("type")
    search = request.args.get("q")
    rows = db.list_briefings(btype=btype, search=search)
    return ok([{
        "id": r["id"], "date": r["date"], "type": r["type"],
        "assessment": r["assessment"], "size": r["size"],
        "file_path": r["file_path"], "word_count":
            parsers.briefing_word_count(r["content"]),
    } for r in rows])


@api_bp.route("/briefings/<int:bid>")
def briefing_detail(bid: int):
    row = db.get_briefing(bid)
    if not row:
        return err("not found", 404)
    actions = parsers.extract_recommended_actions(row["content"])
    return ok({
        "id": row["id"], "date": row["date"], "type": row["type"],
        "assessment": row["assessment"], "file_path": row["file_path"],
        "html": render_md(row["content"]),
        "word_count": parsers.briefing_word_count(row["content"]),
        "actions": actions,
    })


def _briefing_html_doc(btype: str, date: str, body_html: str) -> str:
    """Wrap sanitized briefing HTML in a self-contained, printable document
    (no external assets, so it works offline and 'Print → Save as PDF')."""
    import html as _html
    title = f"{(btype or 'daily').capitalize()} briefing — {date}"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_html.escape(title)}</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:820px;"
        "margin:2rem auto;padding:0 1rem;line-height:1.55;color:#1a1a1a}"
        "h1,h2,h3{line-height:1.25}code,pre{font-family:ui-monospace,monospace}"
        "pre{background:#f4f4f4;padding:.75rem;overflow:auto;border-radius:6px}"
        "table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:4px 8px}"
        "blockquote{border-left:3px solid #ccc;margin:0;padding-left:1rem;color:#555}</style>"
        f"</head><body><h1>{_html.escape(title)}</h1>{body_html}</body></html>"
    )


@api_bp.route("/briefings/<int:bid>/export")
def briefing_export(bid: int):
    """Download a briefing as a self-contained HTML doc or raw markdown."""
    row = db.get_briefing(bid)
    if not row:
        return err("not found", 404)
    fmt = (request.args.get("format") or "html").lower()
    name = f"briefing-{row['type']}-{row['date']}"
    if fmt == "md":
        data = (row["content"] or "").encode("utf-8")
        return send_file(io.BytesIO(data), mimetype="text/markdown",
                         as_attachment=True, download_name=f"{name}.md")
    if fmt == "html":
        doc = _briefing_html_doc(row["type"], row["date"], render_md(row["content"]))
        return send_file(io.BytesIO(doc.encode("utf-8")), mimetype="text/html",
                         as_attachment=True, download_name=f"{name}.html")
    return err("format must be 'html' or 'md'")


@api_bp.route("/briefings/sync", methods=["POST"])
def briefings_sync():
    res = sync.sync_briefings()
    return ok(res)


# ---------- OSINT API -----------------------------------------------------

@api_bp.route("/osint/<source>")
def osint_lookup(source: str):
    ioc = (request.args.get("ioc") or "").strip()
    if not ioc:
        return err("missing ioc")
    force = request.args.get("force") == "1"
    fn = {"virustotal": osint.virustotal,
          "abuseipdb":  osint.abuseipdb,
          "urlscan":    osint.urlscan}.get(source)
    if not fn:
        return err(f"unknown source: {source}", 404)
    result = fn(ioc, force_refresh=force)
    return jsonify(result)


@api_bp.route("/osint/all")
def osint_all():
    ioc = (request.args.get("ioc") or "").strip()
    if not ioc:
        return err("missing ioc")
    force = request.args.get("force") == "1"
    return ok({"ioc": ioc, "type": parsers.detect_ioc_type(ioc),
               "results": osint.run_all(ioc, force_refresh=force)})


@api_bp.route("/osint/references")
def osint_refs():
    ioc = (request.args.get("ioc") or "").strip()
    if not ioc:
        return err("missing ioc")
    return ok(db.osint_references(ioc))


@api_bp.route("/osint/detect")
def osint_detect():
    ioc = (request.args.get("ioc") or "").strip()
    return ok({"ioc": ioc, "type": parsers.detect_ioc_type(ioc)})


# ---------- FP manager API ------------------------------------------------

@api_bp.route("/fp/list")
def fp_list():
    rows = db.list_fps()
    return ok([row_to_dict(r) for r in rows])


@api_bp.route("/fp/noisy-rules")
def fp_noisy_rules():
    """Noisiest rules over the window — FP-suppression candidates."""
    return ok(db.noisy_rules(days=int_arg("days", 7, minimum=1, maximum=365),
                             limit=int_arg("limit", 20, minimum=1, maximum=200)))


@api_bp.route("/fp/rules-xml")
def fp_rules_xml():
    try:
        xml = wazuh.read_local_rules()
    except Exception as e:  # noqa: BLE001
        return err(str(e), 500)
    return ok({"xml": xml,
               "parsed": wazuh.parse_existing_suppressions(xml)})


@api_bp.route("/fp/rule-lookup")
def fp_rule_lookup():
    rid = (request.args.get("rule_id") or "").strip()
    if not rid:
        return err("missing rule_id")
    # Best-effort: find an alert in our DB that matches this rule id.
    with db.conn() as c:
        row = c.execute(
            "SELECT rule_id, rule_description, rule_level, rule_groups FROM alerts WHERE rule_id=? LIMIT 1",
            (rid,),
        ).fetchone()
    if not row:
        return ok({"rule_id": rid, "description": None, "level": None, "groups": []})
    groups = []
    try:
        groups = json.loads(row["rule_groups"] or "[]")
    except json.JSONDecodeError:
        pass
    return ok({"rule_id": rid, "description": row["rule_description"],
               "level": row["rule_level"], "groups": groups})


@api_bp.route("/fp/preview", methods=["POST"])
def fp_preview():
    p = request.get_json(silent=True) or {}
    rid = (p.get("rule_id") or "").strip()
    agent = (p.get("agent_name") or "").strip() or None
    desc = (p.get("description") or "").strip()
    if not rid or not desc:
        return err("rule_id and description required")
    if not rid.isdigit():
        return err("rule_id must be numeric")
    try:
        xml = wazuh.read_local_rules()
    except Exception as e:  # noqa: BLE001
        return err(str(e), 500)
    new_rid = wazuh.next_local_rule_id(xml)
    snippet = wazuh.build_suppression(rid, agent, desc, new_rid)
    return ok({"new_rule_id": new_rid, "snippet": snippet})


@api_bp.route("/fp/add", methods=["POST"])
def fp_add():
    p = request.get_json(silent=True) or {}
    rid = (p.get("rule_id") or "").strip()
    agent = (p.get("agent_name") or "").strip() or None
    desc = (p.get("description") or "").strip()
    if not rid or not desc:
        return err("rule_id and description required")
    if not rid.isdigit():
        return err("rule_id must be numeric")

    # Serialise the whole read→write→verify→restart cycle so concurrent adds
    # can't allocate the same new rule id or interleave writes (L5).
    with wazuh.LOCAL_RULES_LOCK:
        try:
            original = wazuh.read_local_rules()
        except Exception as e:  # noqa: BLE001
            return err(f"cannot read local_rules.xml: {e}", 500)

        new_rid = wazuh.next_local_rule_id(original)
        snippet = wazuh.build_suppression(rid, agent, desc, new_rid)
        updated = wazuh.insert_into_group(original, snippet)

        try:
            wazuh.write_local_rules(updated)
        except Exception as e:  # noqa: BLE001
            return err(f"write failed: {e}", 500)

        ok_verify, verify_out = wazuh.verify_config()
        if not ok_verify:
            # Roll back
            try:
                wazuh.write_local_rules(original)
            except Exception:  # noqa: BLE001
                log.exception("rollback also failed")
            return err(f"verifyconf failed (rolled back): {verify_out[-500:]}", 400)

        ok_restart, restart_out = wazuh.restart_manager()
        if not ok_restart:
            return err(f"manager restart failed: {restart_out[-500:]}", 500)

        db.insert_fp(rid, agent, desc, new_rid, snippet)
        db.refresh_fp_alert_counts()
    auth.audit("fp.add", "wazuh_rule", new_rid,
               {"suppresses": rid, "agent": agent, "description": desc})
    return ok({"new_rule_id": new_rid, "verify": verify_out,
               "restart": restart_out})


@api_bp.route("/fp/<int:fp_id>", methods=["DELETE"])
def fp_delete(fp_id: int):
    with db.conn() as c:
        row = c.execute("SELECT * FROM false_positives WHERE id=?", (fp_id,)).fetchone()
    if not row:
        return err("not found", 404)
    with wazuh.LOCAL_RULES_LOCK:
        try:
            original = wazuh.read_local_rules()
        except Exception as e:  # noqa: BLE001
            return err(str(e), 500)
        updated = wazuh.remove_rule_from_xml(original, row["wazuh_rule_id"])
        try:
            wazuh.write_local_rules(updated)
        except Exception as e:  # noqa: BLE001
            return err(f"write failed: {e}", 500)
        ok_verify, verify_out = wazuh.verify_config()
        if not ok_verify:
            wazuh.write_local_rules(original)
            return err(f"verifyconf failed (rolled back): {verify_out[-500:]}", 400)
        wazuh.restart_manager()
        db.delete_fp(fp_id)
    auth.audit("fp.delete", "wazuh_rule", row["wazuh_rule_id"],
               {"suppressed_rule": row["rule_id"]})
    return ok({"deleted": fp_id})


# ---------- actions API ---------------------------------------------------

@api_bp.route("/actions")
def actions_list():
    rows = db.list_actions(
        status=request.args.get("status"),
        priority=request.args.get("priority"),
        date_from=request.args.get("date_from"),
        date_to=request.args.get("date_to"),
    )
    return ok([dict(r) for r in rows])


@api_bp.route("/actions/stats")
def actions_stats():
    return ok(db.action_stats())


@api_bp.route("/actions/<int:aid>", methods=["PATCH"])
def actions_update(aid: int):
    p = request.get_json(silent=True) or {}
    status = p.get("status")
    notes = p.get("notes")
    if status not in (None, "open", "in_progress", "resolved"):
        return err("invalid status")
    if status:
        db.update_action_status(aid, status, notes)
    return ok({"id": aid})


# ---------- hosts API -----------------------------------------------------

@api_bp.route("/hosts")
def hosts_list():
    return ok([dict(r) for r in db.list_hosts()])


@api_bp.route("/hosts/<int:hid>", methods=["PATCH"])
def hosts_update(hid: int):
    p = request.get_json(silent=True) or {}
    fields = {k: v for k, v in p.items() if k in {"hostname", "role", "notes"}}
    if not fields:
        return err("nothing to update")
    db.update_host_fields(hid, **fields)
    return ok(dict(db.get_host(hid) or {}))


@api_bp.route("/hosts/<int:hid>", methods=["DELETE"])
def hosts_delete(hid: int):
    db.delete_host(hid)
    return ok({"deleted": hid})


@api_bp.route("/hosts", methods=["POST"])
def hosts_add():
    p = request.get_json(silent=True) or {}
    ip = (p.get("ip") or "").strip()
    if not ip:
        return err("ip required")
    db.upsert_host(ip, p.get("hostname"), p.get("role"), p.get("notes"))
    return ok(dict(db.get_host_by_ip(ip) or {}))


@api_bp.route("/hosts/<int:hid>/alerts")
def hosts_alerts(hid: int):
    h = db.get_host(hid)
    if not h:
        return err("not found", 404)
    rows = db.alerts_for_host(h["ip"], limit=20)
    if not rows and h["hostname"]:
        rows = db.alerts_for_host(h["hostname"], limit=20)
    return ok([row_to_dict(r) for r in rows])


@api_bp.route("/hosts/refresh", methods=["POST"])
def hosts_refresh():
    n = sync.sync_agent_status()
    return ok({"updated": n})


# ---------- CVE asset tracker API ------------------------------------------

@api_bp.route("/assets")
def assets_list_api():
    return ok([dict(r) for r in db.assets_list()])


@api_bp.route("/assets", methods=["POST"])
def assets_add():
    p = request.get_json(silent=True) or {}
    name = (p.get("name") or "").strip()
    if not name:
        return err("name required")
    fields = _asset_fields_from(p)
    if isinstance(fields, tuple):           # (error response)
        return fields[0]
    try:
        aid = db.asset_insert(name, **fields)
    except Exception:
        return err("an asset with that name already exists")
    auth.audit("asset.create", "asset", aid, {"name": name})
    return ok(dict(db.asset_get(aid) or {}))


@api_bp.route("/assets/<int:aid>", methods=["PATCH"])
def assets_update(aid: int):
    if not db.asset_get(aid):
        return err("not found", 404)
    p = request.get_json(silent=True) or {}
    fields = _asset_fields_from(p, allow_name=True)
    if isinstance(fields, tuple):
        return fields[0]
    if not fields:
        return err("nothing to update")
    db.update_asset_fields(aid, **fields)
    auth.audit("asset.update", "asset", aid, {k: v for k, v in fields.items()})
    return ok(dict(db.asset_get(aid) or {}))


@api_bp.route("/assets/<int:aid>", methods=["DELETE"])
def assets_delete(aid: int):
    row = db.asset_get(aid)
    if not row:
        return err("not found", 404)
    db.asset_delete(aid)
    auth.audit("asset.delete", "asset", aid, {"name": row["name"]})
    return ok({"deleted": aid})


def _asset_fields_from(p: dict, allow_name: bool = False):
    """Validate + collect asset fields from a request payload. Returns a dict,
    or a 1-tuple wrapping an error response when validation fails."""
    fields: dict = {}
    if allow_name and "name" in p:
        name = (p.get("name") or "").strip()
        if not name:
            return (err("name cannot be empty"),)
        fields["name"] = name
    for k in ("vendor", "product", "version", "cpe", "notes"):
        if k in p:
            fields[k] = (p.get(k) or "").strip() or None
    if "category" in p:
        if p["category"] not in db.ASSET_CATEGORIES:
            return (err(f"category must be one of: {', '.join(db.ASSET_CATEGORIES)}"),)
        fields["category"] = p["category"]
    if "exposure" in p:
        if p["exposure"] not in db.ASSET_EXPOSURES:
            return (err(f"exposure must be one of: {', '.join(db.ASSET_EXPOSURES)}"),)
        fields["exposure"] = p["exposure"]
    if "criticality" in p:
        if p["criticality"] not in db.ASSET_CRITICALITIES:
            return (err(f"criticality must be one of: {', '.join(db.ASSET_CRITICALITIES)}"),)
        fields["criticality"] = p["criticality"]
    return fields


@api_bp.route("/assets/import-vigil", methods=["POST"])
def assets_import_vigil():
    try:
        res = vulntrack.import_assets_from_vigil()
    except RuntimeError as e:
        return err(str(e))
    except requests.RequestException as e:
        return err(f"Vigil unreachable: {e}")
    auth.audit("asset.import_vigil", "asset", None, res)
    return ok(res)


@api_bp.route("/vulns/sync", methods=["POST"])
def vulns_sync():
    try:
        res = vulntrack.sync_cve_briefings()
    except RuntimeError as e:
        return err(str(e))
    except requests.RequestException as e:
        return err(f"BookStack unreachable: {e}")
    if res.get("skipped"):
        return err(f"sync skipped: {res['skipped']}")
    auth.audit("vulns.sync", "cve_sync", None,
               {k: v for k, v in res.items() if k != "warnings"})
    return ok(res)


@api_bp.route("/vulns/matches")
def vulns_matches():
    raw_statuses = request.args.get("statuses")
    if raw_statuses is None or raw_statuses == "open":
        statuses: list[str] | None = list(db.CVE_OPEN_STATUSES)
    elif raw_statuses == "":
        statuses = None
    else:
        statuses = [s for s in raw_statuses.split(",") if s in db.CVE_MATCH_STATUSES]
    rows = db.cve_matches_list(
        statuses=statuses,
        min_severity=request.args.get("min_severity") or None,
        search=request.args.get("q") or None,
        limit=int_arg("limit", 500, minimum=1, maximum=2000),
    )
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["cve_ids"] = json.loads(d.get("cve_ids") or "[]")
        except json.JSONDecodeError:
            d["cve_ids"] = []
        out.append(d)
    return ok(out)


@api_bp.route("/vulns/matches/<int:mid>", methods=["PATCH"])
def vulns_match_update(mid: int):
    row = db.cve_match_get(mid)
    if not row:
        return err("not found", 404)
    p = request.get_json(silent=True) or {}
    status = p.get("status")
    if status not in db.CVE_MATCH_STATUSES:
        return err(f"status must be one of: {', '.join(db.CVE_MATCH_STATUSES)}")
    notes = (p.get("notes") or "").strip() or None
    user = auth.current_user()
    db.cve_match_set_status(mid, status, notes, user["username"] if user else None)
    auth.audit("vulns.match_status", "cve_match", mid,
               {"item": row["item_key"], "asset": row["asset_name"],
                "from": row["status"], "to": status})
    return ok(dict(db.cve_match_get(mid)))


@api_bp.route("/vulns/items/<int:iid>")
def vulns_item_get(iid: int):
    row = db.cve_item_get(iid)
    if not row:
        return err("not found", 404)
    d = dict(row)
    try:
        d["cve_ids"] = json.loads(d.get("cve_ids") or "[]")
    except json.JSONDecodeError:
        d["cve_ids"] = []
    d["section_html"] = render_md(d.get("section_md") or "")
    return ok(d)


@api_bp.route("/vulns/dashboard")
def vulns_dashboard():
    return ok(db.cve_dashboard_stats())


@api_bp.route("/vulns/alert-test", methods=["POST"])
def vulns_alert_test():
    """Fire a synthetic CVE-match notification at every enabled webhook so the
    end-to-end path can be verified without waiting for a real match."""
    if (resp := auth.require_admin()): return resp
    sample = {
        "item_key": "CVE-0000-TEST",
        "title": "Synthetic CVE-match notification — configuration check",
        "severity": "critical", "cvss_score": 9.9,
        "asset_name": "test-asset", "exposure": "internet", "criticality": "high",
        "priority": 54.0, "confidence": "strong",
        "match_reason": "synthetic test fired from the CVE Tracker",
        "action": "No action — this is a test.",
        "exploited": True, "kev": False,
        "bookstack_url": None,
    }
    results = notifications.deliver_vuln_match(sample)
    auth.audit("vulns.alert_test", "webhook", None,
               {"results": [{k: v for k, v in r.items() if k != "response"}
                            for r in results]})
    return ok({"results": results})


@api_bp.route("/vulns/config")
def vulns_config_get():
    if (resp := auth.require_admin()): return resp
    return ok(vulntrack.config_public())


@api_bp.route("/vulns/config", methods=["POST"])
def vulns_config_set():
    if (resp := auth.require_admin()): return resp
    p = request.get_json(silent=True) or {}
    vulntrack.set_config(p)
    auth.audit("vulns.config_update", "vuln_config", None,
               {k: ("***" if k in vulntrack._SECRET_FIELDS else v)
                for k, v in p.items()})
    return ok(vulntrack.config_public())


# ---------- DNS / Threat Intel API ---------------------------------------

@api_bp.route("/dns/today")
def dns_today():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    data = db.dns_get_daily(today)
    if data:
        return ok(data)
    return ok({"date": today, "total_queries": 0, "blocked_queries": 0,
               "top_queried": [], "top_blocked": [],
               "per_client": [], "hourly": []})


@api_bp.route("/dns/trend")
def dns_trend():
    return ok(db.dns_last_n_days(7))


@api_bp.route("/dns/sync", methods=["POST"])
def dns_sync():
    # Cap days: each extra day is another in-memory bucket of Counters over a
    # multi-hundred-MB tail, so an unbounded value is a self-inflicted OOM.
    n = int_arg("days", 1, minimum=1, maximum=90)
    if n <= 1:
        return ok(sync.sync_dns_today())
    return ok({"days": sync.sync_dns_last_n(n)})


@api_bp.route("/unifi/recent")
def unifi_recent():
    """UniFi events: alerts whose rule_groups or location indicate unifi."""
    with db.conn() as c:
        rows = c.execute(
            """SELECT * FROM alerts
               WHERE rule_groups LIKE '%unifi%' OR location LIKE '%unifi%'
                  OR rule_description LIKE '%UniFi%'
               ORDER BY timestamp DESC LIMIT 200"""
        ).fetchall()
    return ok([row_to_dict(r) for r in rows])


@api_bp.route("/unifi/top-sources")
def unifi_top_sources():
    """Try to extract source IPs from full_log for the past 7 days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    src_re = re.compile(r"\bsrc=([0-9]{1,3}(?:\.[0-9]{1,3}){3})|\bSRC=([0-9.]+)|"
                        r"\bfrom\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
    counts: dict[str, int] = {}
    with db.conn() as c:
        rows = c.execute(
            """SELECT full_log FROM alerts
               WHERE (rule_groups LIKE '%unifi%' OR location LIKE '%unifi%')
                 AND timestamp >= ?""", (cutoff,)).fetchall()
    for r in rows:
        log_line = r["full_log"] or ""
        m = src_re.search(log_line)
        if not m:
            continue
        ip = next((g for g in m.groups() if g), None)
        if ip and not ip.startswith(("10.", "192.168.", "172.")):
            counts[ip] = counts.get(ip, 0) + 1
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return ok([{"ip": ip, "count": n} for ip, n in top])


# ---------- settings API --------------------------------------------------

@api_bp.route("/settings/keys")
def settings_keys():
    return ok(osint.key_status())


@api_bp.route("/settings/keys/<service>", methods=["POST"])
def settings_set_key(service: str):
    if (resp := auth.require_admin()): return resp
    if service not in ("virustotal", "abuseipdb", "urlscan"):
        return err("unknown service", 404)
    p = request.get_json(silent=True) or {}
    key = (p.get("key") or "").strip()
    if not key:
        return err("key required")
    osint.set_key(service, key)
    auth.audit("settings.api_key_set", "api_key", service)
    return ok(osint.key_status())


@api_bp.route("/settings/keys/<service>", methods=["DELETE"])
def settings_clear_key(service: str):
    if (resp := auth.require_admin()): return resp
    if service not in ("virustotal", "abuseipdb", "urlscan"):
        return err("unknown service", 404)
    osint.clear_key(service)
    auth.audit("settings.api_key_clear", "api_key", service)
    return ok(osint.key_status())


@api_bp.route("/settings/keys/<service>/test", methods=["POST"])
def settings_test_key(service: str):
    if (resp := auth.require_admin()): return resp
    return jsonify(osint.test_key(service))


@api_bp.route("/settings/theme", methods=["POST"])
def settings_theme():
    """Persist preferred theme (client mirrors in localStorage)."""
    p = request.get_json(silent=True) or {}
    theme = p.get("theme")
    if theme not in config.THEMES:
        return err("invalid theme")
    db.setting_set("theme", theme)
    return ok({"theme": theme})


# ---------- pipeline API --------------------------------------------------

@api_bp.route("/pipeline/status")
def pipeline_status():
    def serialise(row):
        if not row:
            return None
        return dict(row)
    return ok({
        "collect": serialise(db.pipeline_last("collect")),
        "analyse": serialise(db.pipeline_last("analyse")),
        "next_collect": "05:50",
        "next_analyse": "06:00",
    })


@api_bp.route("/pipeline/run", methods=["POST"])
def pipeline_run():
    p = request.get_json(silent=True) or {}
    kind = p.get("kind")
    if kind not in ("collect", "analyse", "weekly"):
        return err("invalid kind")
    return ok(sync.trigger_pipeline_script(kind))


# ---------- home dashboard API -------------------------------------------
#
# Read-only endpoints consumed by the jacknet-home dashboard
# (http://10.0.0.188:8090). LAN-only — no session auth.

def _home_extract_summary(content: str) -> str:
    """Pull the Executive Summary section out of a briefing markdown body,
    strip markdown formatting, and trim. Falls back to the first 400 chars."""
    if not content:
        return ""
    m = re.search(r"^##\s*Executive Summary\s*\n(.*?)(?=^##\s|\Z)",
                  content, re.MULTILINE | re.DOTALL)
    text = m.group(1) if m else content
    # Cheap markdown strip — good enough for a 200-char preview.
    text = re.sub(r"^#+\s*", "", text, flags=re.MULTILINE)   # headings
    text = re.sub(r"[*_`]+", "", text)                       # emphasis / code
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)     # links → label
    text = re.sub(r"\s+", " ", text).strip()
    return text[:400]


@api_bp.route("/home/alerts")
def home_alerts():
    """Open-alert counts bucketed into P1/P2/P3 by Wazuh rule level.
    P1 = level >= 12, P2 = level 10-11, P3 = level 7-9."""
    with db.conn() as c:
        row = c.execute(
            """SELECT
                 SUM(CASE WHEN rule_level >= 12 THEN 1 ELSE 0 END) AS p1,
                 SUM(CASE WHEN rule_level BETWEEN 10 AND 11 THEN 1 ELSE 0 END) AS p2,
                 SUM(CASE WHEN rule_level BETWEEN 7 AND 9 THEN 1 ELSE 0 END) AS p3,
                 COUNT(*) AS open
               FROM alerts
               WHERE status = 'open'"""
        ).fetchone()
    return ok({
        "open": int(row["open"] or 0),
        "p1":   int(row["p1"]   or 0),
        "p2":   int(row["p2"]   or 0),
        "p3":   int(row["p3"]   or 0),
    })


@api_bp.route("/home/agents")
def home_agents():
    """Wazuh agent state, one row per configured host."""
    out = []
    for h in db.list_hosts():
        status = (h["agent_status"] or "").lower()
        out.append({
            "name":   h["hostname"] or h["ip"],
            "ip":     h["ip"],
            "status": "online" if status in ("active", "connected", "online") else "offline",
        })
    return ok(out)


@api_bp.route("/home/briefing")
def home_briefing():
    """Most recent daily briefing — date, severity, assessment preview."""
    row = db.latest_briefing("daily")
    if not row:
        return ok(None)
    return ok({
        "date":          row["date"],
        "assessment":    _home_extract_summary(row["content"]),
        "severity":      row["assessment"],
        "bookstack_url": "",  # populated once briefings are wired to BookStack
    })


@api_bp.route("/home/pipeline")
def home_pipeline():
    """Latest run of each requested pipeline kind. The home dashboard
    drives the kind list and the labels — we just report what's in the
    database. ?kinds=collect,analyse,weekly (defaults to the known set)."""
    req = request.args.get("kinds")
    if req:
        kinds = [k.strip() for k in req.split(",") if k.strip()]
    else:
        kinds = list(config.SIEM_SCRIPTS.keys())

    out = []
    for kind in kinds:
        r = db.pipeline_last(kind)
        if not r:
            out.append({"kind": kind, "name": kind,
                        "status": "fail", "ran_at": None})
        else:
            out.append({
                "kind":   kind,
                "name":   kind,   # caller overrides with its own label
                "status": "ok" if r["success"] else "fail",
                "ran_at": r["finished_at"] or r["started_at"],
            })
    return ok(out)


# Cap on concurrent SSE streams. Each stream is an infinite generator that pins
# a waitress worker thread for its lifetime, so without a cap a few clients (or
# stale browser tabs) could exhaust the pool and stall every other request.
# Keep it below SOC_THREADS (default 8) so normal requests always have headroom.
_sse_slots = threading.BoundedSemaphore(int(os.environ.get("SOC_SSE_MAX", "4")))


@api_bp.route("/home/events")
def home_events():
    """SSE feed for the home dashboard.

    Polls the alerts / actions / pipeline tables once a second and emits
    typed events when state changes. Heartbeat every 25s so reverse
    proxies don't idle-close the connection.

    Events:
      alert_new       — new high-severity (>=10) open alert appears
      alert_p1_open   — count of open P1 (level>=12) alerts changes
      action_added    — new recommended action appears
      action_resolved — an action transitions to status=resolved
      pipeline_run    — any pipeline kind completes (success or fail)
      briefing_new    — a new daily briefing lands
      heartbeat       — every 25s, keeps connection alive
    """
    import time as _t
    from datetime import datetime as _dt
    from flask import Response as _Response, stream_with_context as _swc

    def _stream():
        # Snapshot baseline state on connect — we emit events for *changes*
        # relative to this. Avoids dumping the whole history at every
        # client reconnect.
        with db.conn() as c:
            seen_alerts = set(r["id"] for r in c.execute(
                "SELECT id FROM alerts WHERE rule_level >= 10 AND status='open' "
                "ORDER BY id DESC LIMIT 200").fetchall())
            last_actions = {r["id"]: r["status"] for r in c.execute(
                "SELECT id, status FROM recommended_actions ORDER BY id DESC LIMIT 200"
            ).fetchall()}
            last_pipeline = {}
            for kind in config.SIEM_SCRIPTS.keys():
                r = db.pipeline_last(kind)
                last_pipeline[kind] = (r["id"], r["success"]) if r else (None, None)
            latest_brief = db.latest_briefing("daily")
            last_brief_id = latest_brief["id"] if latest_brief else None
            p1_count = sum(1 for x in c.execute(
                "SELECT id FROM alerts WHERE rule_level >= 12 AND status='open'"
            ))

        yield f"event: hello\ndata: {{\"as_of\": \"{_dt.now(timezone.utc).isoformat()}\"}}\n\n"
        last_heartbeat = _t.monotonic()

        while True:
            try:
                with db.conn() as c:
                    # Alerts (rule_level>=10 = "interesting")
                    rows = c.execute(
                        "SELECT id, timestamp, agent_name, rule_id, rule_level, "
                        "       rule_description "
                        "FROM alerts "
                        "WHERE rule_level >= 10 AND status='open' "
                        "ORDER BY id DESC LIMIT 100"
                    ).fetchall()
                    for r in rows:
                        if r["id"] in seen_alerts:
                            continue
                        seen_alerts.add(r["id"])
                        payload = {
                            "id": r["id"], "timestamp": r["timestamp"],
                            "agent": r["agent_name"], "rule_id": r["rule_id"],
                            "rule_level": r["rule_level"],
                            "description": r["rule_description"],
                        }
                        yield f"event: alert_new\ndata: {json.dumps(payload)}\n\n"

                    # P1 count change
                    new_p1 = sum(1 for _ in c.execute(
                        "SELECT id FROM alerts WHERE rule_level >= 12 AND status='open'"))
                    if new_p1 != p1_count:
                        p1_count = new_p1
                        yield f"event: alert_p1_open\ndata: {{\"count\": {new_p1}}}\n\n"

                    # Actions
                    arows = c.execute(
                        "SELECT id, status, priority, description "
                        "FROM recommended_actions ORDER BY id DESC LIMIT 200"
                    ).fetchall()
                    new_actions = {r["id"]: r["status"] for r in arows}
                    for a in arows:
                        prev = last_actions.get(a["id"])
                        if prev is None:
                            yield ("event: action_added\n"
                                   f"data: {json.dumps(dict(a))}\n\n")
                        elif prev != a["status"] and a["status"] == "resolved":
                            yield ("event: action_resolved\n"
                                   f"data: {json.dumps({'id': a['id']})}\n\n")
                    last_actions = new_actions

                    # Pipelines
                    for kind in config.SIEM_SCRIPTS.keys():
                        p = db.pipeline_last(kind)
                        if not p:
                            continue
                        prev_id, prev_ok = last_pipeline.get(kind, (None, None))
                        if p["id"] != prev_id:
                            last_pipeline[kind] = (p["id"], p["success"])
                            data = {
                                "kind": kind,
                                "success": bool(p["success"]),
                                "started_at": p["started_at"],
                                "finished_at": p["finished_at"],
                            }
                            yield f"event: pipeline_run\ndata: {json.dumps(data)}\n\n"

                    # Briefings
                    b = db.latest_briefing("daily")
                    if b and b["id"] != last_brief_id:
                        last_brief_id = b["id"]
                        data = {"date": b["date"], "assessment": b["assessment"]}
                        yield f"event: briefing_new\ndata: {json.dumps(data)}\n\n"

                # Heartbeat
                if _t.monotonic() - last_heartbeat > 25:
                    yield f"event: heartbeat\ndata: {{\"as_of\": \"{_dt.now(timezone.utc).isoformat()}\"}}\n\n"
                    last_heartbeat = _t.monotonic()
            except GeneratorExit:
                return
            except Exception:  # noqa: BLE001
                log.exception("home_events tick failed")
            _t.sleep(1.0)

    # Refuse once the concurrent-stream cap is hit (returns immediately, no
    # stream), so SSE clients can't starve the worker pool.
    if not _sse_slots.acquire(blocking=False):
        return err("too many concurrent event streams; retry shortly", 503)

    def gen():
        try:
            yield from _stream()
        finally:
            _sse_slots.release()

    return _Response(_swc(gen()), mimetype="text/event-stream",
                     headers={
                         "Cache-Control": "no-cache",
                         "X-Accel-Buffering": "no",  # nginx: disable response buffering
                     })


@api_bp.route("/home/pipeline/run", methods=["POST"])
def home_pipeline_run():
    """Token-gated trigger for a pipeline script. Reaches this handler only
    if the home token is valid AND mutations are enabled (enforced in
    auth.login_required_globally). Kind is validated against SIEM_SCRIPTS so
    callers can't run arbitrary commands."""
    # Token-gated consumer (bearer token, not cookie auth → not CSRF-exposed);
    # keep force=True so the consumer needn't set Content-Type: application/json.
    p = request.get_json(force=True, silent=True) or {}
    kind = p.get("kind")
    if kind not in config.SIEM_SCRIPTS:
        return err("invalid kind")
    auth.audit("home_api.pipeline_run", "pipeline", kind,
               {"via": "home_api", "remote_addr": request.remote_addr})
    return ok(sync.trigger_pipeline_script(kind))


@api_bp.route("/home/actions")
def home_actions():
    """Counts of recommended actions, grouped by status."""
    with db.conn() as c:
        rows = c.execute(
            "SELECT status, COUNT(*) AS n FROM recommended_actions GROUP BY status"
        ).fetchall()
    counts = {"open": 0, "in_progress": 0, "resolved": 0}
    for r in rows:
        if r["status"] in counts:
            counts[r["status"]] = int(r["n"])
    return ok(counts)


# ---------- wazuh status -------------------------------------------------

@api_bp.route("/wazuh/status")
def wazuh_status():
    return ok(wazuh.connection_status())


@api_bp.route("/pollers/status")
def pollers_status():
    return ok(sync.poller_status())


@api_bp.route("/backup/download/<kind>")
def backup_download(kind: str):
    if (resp := auth.require_admin()): return resp
    if kind not in ("config", "full", "data"):
        return err("kind must be config|full|data")
    try:
        data, filename, _size = backup.stream_to_browser(kind)
    except Exception as e:  # noqa: BLE001
        return err(str(e), 500)
    return send_file(
        io.BytesIO(data), mimetype="application/octet-stream",
        as_attachment=True, download_name=filename,
    )


@api_bp.route("/backup/nas/config", methods=["GET"])
def backup_nas_get():
    if (resp := auth.require_admin()): return resp
    cfg = backup.nas_config_get()
    return ok(cfg or {})


@api_bp.route("/backup/nas/config", methods=["POST"])
def backup_nas_set():
    if (resp := auth.require_admin()): return resp
    p = request.get_json(silent=True) or {}
    host = (p.get("host") or "").strip()
    user = (p.get("user") or "").strip()
    path = (p.get("remote_path") or "").strip()
    if not host or not user or not path:
        return err("host, user, remote_path all required")
    backup.nas_config_set(host, user, path)
    return ok({"saved": True})


@api_bp.route("/backup/nas/config", methods=["DELETE"])
def backup_nas_clear():
    if (resp := auth.require_admin()): return resp
    backup.nas_config_clear()
    return ok({"cleared": True})


@api_bp.route("/backup/nas/push", methods=["POST"])
def backup_nas_push():
    if (resp := auth.require_admin()): return resp
    p = request.get_json(silent=True) or {}
    kind = p.get("kind", "config")
    if kind not in ("config", "full"):
        return err("kind must be config|full")
    cfg = backup.nas_config_get()
    if not cfg:
        return err("NAS backup target not configured")
    try:
        res = backup.push_to_nas(kind, cfg["host"], cfg["user"], cfg["remote_path"])
    except Exception as e:  # noqa: BLE001
        return err(str(e), 500)
    return ok(res)


@api_bp.route("/backup/history")
def backup_history_get():
    if (resp := auth.require_admin()): return resp
    rows = db.backup_list(50)
    return ok([dict(r) for r in rows])


@api_bp.route("/settings/home-api", methods=["GET"])
def home_api_status():
    if (resp := auth.require_admin()): return resp
    token = auth.home_api_token_get()
    return ok({
        "configured":        bool(token),
        "last4":             token[-4:] if token else None,
        "mutations_enabled": auth.home_api_mutations_enabled(),
    })


@api_bp.route("/settings/home-api/token", methods=["POST"])
def home_api_generate():
    """Generate a fresh token. Returned ONCE here so the operator can copy it
    into the consumer (jacknet-home). Not retrievable afterwards."""
    if (resp := auth.require_admin()): return resp
    token = auth.home_api_generate_token()
    auth.audit("settings.home_api_token_generate", "home_api", None)
    return ok({"token": token})


@api_bp.route("/settings/home-api/token", methods=["DELETE"])
def home_api_clear():
    if (resp := auth.require_admin()): return resp
    auth.home_api_token_clear()
    auth.audit("settings.home_api_token_clear", "home_api", None)
    return ok({"cleared": True})


@api_bp.route("/settings/home-api/mutations", methods=["POST"])
def home_api_mutations():
    if (resp := auth.require_admin()): return resp
    p = request.get_json(silent=True) or {}
    enabled = bool(p.get("enabled"))
    auth.home_api_set_mutations(enabled)
    auth.audit("settings.home_api_mutations", "home_api", None, {"enabled": enabled})
    return ok({"mutations_enabled": enabled})


@api_bp.route("/host-config", methods=["GET"])
def host_config_get():
    cfg = config.host_config()
    # Never return the SSH private-key path's contents — just the path string.
    return ok({
        "wazuh_host":             cfg.get("wazuh_host", ""),
        "wazuh_user":             cfg.get("wazuh_user", "wazuh"),
        "claudedev_host":         cfg.get("claudedev_host", ""),
        "claudedev_user":         cfg.get("claudedev_user", "dev"),
        "adguard_host":           cfg.get("adguard_host", ""),
        "adguard_user":           cfg.get("adguard_user", ""),
        "adguard_querylog_path":  cfg.get("adguard_querylog_path", ""),
        "ssh_key_path":           cfg.get("ssh_key_path", ""),
        "siem_scripts_dir":       cfg.get("siem_scripts_dir", ""),
        "claude_cli_path":        cfg.get("claude_cli_path", ""),
        "is_prod":                config.IS_PROD,
    })


@api_bp.route("/host-config", methods=["POST"])
def host_config_set():
    if (resp := auth.require_admin()): return resp
    p = request.get_json(silent=True) or {}
    allowed = {"wazuh_host", "wazuh_user", "claudedev_host", "claudedev_user",
               "adguard_host", "adguard_user", "adguard_querylog_path",
               "ssh_key_path", "siem_scripts_dir", "claude_cli_path"}
    updates = {k: (v or "").strip() if isinstance(v, str) else v
               for k, v in p.items() if k in allowed}
    try:
        config.host_config_set(updates)
    except ValueError as e:
        return err(f"invalid host config: {e}")
    auth.audit("settings.host_config_update", "host_config", None,
               {"updated_keys": list(updates.keys())})
    return ok({"updated": list(updates.keys())})


@api_bp.route("/host-config/test", methods=["POST"])
def host_config_test():
    """Run quick reachability checks against each configured host."""
    if (resp := auth.require_admin()): return resp
    results: dict[str, dict] = {}

    cfg = config.host_config()
    key = cfg.get("ssh_key_path")

    def probe(name: str, host: str, user: str, key: str | None,
              cmd: list[str] | None = None) -> dict:
        if not host:
            return {"configured": False, "reachable": False}
        # Same argument-injection guard the real SSH paths use: host_config is
        # operator-set but must never be parseable as an ssh option such as
        # -oProxyCommand=... (this probe previously bypassed assert_safe_ssh).
        try:
            wazuh.assert_safe_ssh(host, user, key or config.SSH_KEY)
        except ValueError as e:
            return {"configured": True, "reachable": False,
                    "stderr": ("refused unsafe SSH config: " + str(e))[:200]}
        import subprocess
        argv = ["ssh"]
        if key:
            argv += ["-i", key]
        argv += ["-o", "BatchMode=yes",
                 "-o", "StrictHostKeyChecking=accept-new",
                 "-o", "ConnectTimeout=5",
                 f"{user}@{host}", "--"]
        argv += cmd or ["true"]
        try:
            cp = subprocess.run(argv, capture_output=True, timeout=10, check=False)
            return {
                "configured": True,
                "reachable": cp.returncode == 0,
                "stderr": cp.stderr.decode(errors="replace")[:200],
            }
        except Exception as e:  # noqa: BLE001
            return {"configured": True, "reachable": False, "stderr": str(e)[:200]}

    results["wazuh"] = probe("wazuh", cfg.get("wazuh_host", ""),
                             cfg.get("wazuh_user", "wazuh"), key)
    results["claudedev"] = probe("claudedev", cfg.get("claudedev_host", ""),
                                 cfg.get("claudedev_user", "dev"), key)
    results["adguard"] = probe("adguard", cfg.get("adguard_host", ""),
                               cfg.get("adguard_user", ""), key)
    return ok(results)


@api_bp.route("/users")
def users_list():
    if (resp := auth.require_admin()): return resp
    rows = db.list_users()
    return ok([{"id": r["id"], "username": r["username"], "role": r["role"],
                "created_at": r["created_at"], "last_login_at": r["last_login_at"],
                "disabled": bool(r["disabled"])} for r in rows])


@api_bp.route("/users", methods=["POST"])
def users_create():
    if (resp := auth.require_admin()): return resp
    p = request.get_json(silent=True) or {}
    username = (p.get("username") or "").strip()
    password = p.get("password") or ""
    if not username or len(password) < 8:
        return err("username and 8+ char password required")
    role = (p.get("role") or "user").strip().lower()
    if role not in ("admin", "user"):
        return err("role must be 'admin' or 'user'")
    if db.get_user_by_username(username):
        return err("username taken")
    uid = db.insert_user(username, auth.hash_password(password), role=role)
    auth.audit("user.create", "user", uid, {"username": username, "role": role})
    return ok({"id": uid})


@api_bp.route("/users/<int:uid>", methods=["PATCH"])
def users_update(uid: int):
    if (resp := auth.require_admin()): return resp
    p = request.get_json(silent=True) or {}
    if p.get("password"):
        if len(p["password"]) < 8:
            return err("password too short")
        db.update_user_password(uid, auth.hash_password(p["password"]))
        auth.audit("user.password_change", "user", uid)
    if "disabled" in p:
        db.disable_user(uid, bool(p["disabled"]))
        auth.audit("user.disable" if p["disabled"] else "user.enable", "user", uid)
    return ok({"id": uid})


@api_bp.route("/users/<int:uid>", methods=["DELETE"])
def users_delete(uid: int):
    if (resp := auth.require_admin()): return resp
    me = auth.current_user()
    if me and me["id"] == uid:
        return err("cannot delete yourself")
    db.delete_user(uid)
    auth.audit("user.delete", "user", uid)
    return ok({"deleted": uid})


@api_bp.route("/audit-log")
def audit_get():
    if (resp := auth.require_admin()): return resp
    rows = db.audit_list(
        limit=int_arg("limit", 200, minimum=1, maximum=1000),
        action=request.args.get("action"),
        target_type=request.args.get("target_type"),
    )
    return ok([dict(r) for r in rows])


@api_bp.route("/me")
def me():
    u = auth.current_user()
    if not u:
        return err("not authenticated", 401)
    return ok({"id": u["id"], "username": u["username"], "role": u["role"],
               "totp_enabled": bool(u.get("totp_enabled"))})


# ---------- 2FA (TOTP) ----------------------------------------------------

@api_bp.route("/2fa/status")
def twofa_status():
    u = auth.current_user()
    return ok({"enabled": bool(u and u.get("totp_enabled"))})


@api_bp.route("/2fa/enroll", methods=["POST"])
def twofa_enroll():
    """Start enrollment: returns the secret + otpauth URI (2FA stays disabled
    until a code is confirmed). Re-enroll overwrites any pending secret."""
    u = auth.current_user()
    if not u:
        return err("not authenticated", 401)
    data = auth.totp_begin_enroll(u)
    auth.audit("user.2fa_enroll_start", "user", u["id"])
    return ok(data)


@api_bp.route("/2fa/confirm", methods=["POST"])
def twofa_confirm():
    u = auth.current_user()
    if not u:
        return err("not authenticated", 401)
    p = request.get_json(silent=True) or {}
    if auth.totp_confirm_enroll(u["id"], p.get("code") or ""):
        auth.audit("user.2fa_enabled", "user", u["id"])
        return ok({"enabled": True})
    return err("invalid code — check your authenticator and try again")


@api_bp.route("/2fa/disable", methods=["POST"])
def twofa_disable():
    u = auth.current_user()
    if not u:
        return err("not authenticated", 401)
    p = request.get_json(silent=True) or {}
    if auth.totp_disable(u["id"], p.get("code") or ""):
        auth.audit("user.2fa_disabled", "user", u["id"])
        return ok({"enabled": False})
    return err("invalid code — a current code is required to disable 2FA")


@api_bp.route("/ai/usage")
def ai_usage():
    """Recent AI invocation counts for the settings page meter."""
    return ok({
        "auto_explain_24h":   db.ai_runs_count("auto_explain", 24),
        "manual_explain_24h": db.ai_runs_count("manual_explain", 24),
        "chat_24h":           db.ai_runs_count("chat", 24),
        "daily_cap":          int(os.environ.get("SOC_AI_DAILY_CAP", "20")),
    })


# ---------- webhooks API --------------------------------------------------

def _webhook_url_hint(enc: str) -> str:
    """Non-secret hint for the UI: the host only. Webhook URLs embed their
    secret in the path/query (Slack/Discord/Mattermost tokens), so we must not
    return any of the path — not even the last few characters."""
    from urllib.parse import urlparse
    url = config.decrypt(enc)
    if url is None:
        return "configured · (undecryptable on this host)"
    host = ""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        host = ""
    return f"configured · {host}" if host else "configured"


def _webhook_row_to_dict(w) -> dict:
    return {
        "id":            w["id"],
        "name":          w["name"],
        "platform":      w["platform"],
        # Host only — never any of the URL path/query (that's where the secret is)
        "url_hint":      _webhook_url_hint(w["url_encrypted"]),
        "severity_min":  w["severity_min"],
        "include_ai":    bool(w["include_ai"]),
        "enabled":       bool(w["enabled"]),
        "dedup_minutes": w["dedup_minutes"],
        "created_at":    w["created_at"],
        "last_used_at":  w["last_used_at"],
        "last_error":    w["last_error"],
    }


@api_bp.route("/webhooks")
def webhooks_list():
    return ok([_webhook_row_to_dict(w) for w in db.list_webhooks()])


@api_bp.route("/webhooks", methods=["POST"])
def webhooks_create():
    p = request.get_json(silent=True) or {}
    name = (p.get("name") or "").strip()
    platform = (p.get("platform") or "").strip().lower()
    url = (p.get("url") or "").strip()
    if not name:
        return err("name required")
    if platform not in notifications.SUPPORTED_PLATFORMS:
        return err(f"platform must be one of: {', '.join(notifications.SUPPORTED_PLATFORMS)}")
    ok_url, why = notifications.validate_webhook_url(url)
    if not ok_url:
        return err(f"invalid webhook URL: {why}")
    sev = int_field(p, "severity_min", 7)
    include_ai = bool(p.get("include_ai", True))
    dedup_minutes = int_field(p, "dedup_minutes", 240)
    wid = db.insert_webhook(name, platform, config.encrypt(url),
                            sev, include_ai, dedup_minutes)
    return ok({"id": wid})


@api_bp.route("/webhooks/<int:wid>", methods=["PATCH"])
def webhooks_update(wid: int):
    p = request.get_json(silent=True) or {}
    updates: dict = {}
    if "name" in p: updates["name"] = str(p["name"]).strip()
    if "platform" in p:
        if p["platform"] not in notifications.SUPPORTED_PLATFORMS:
            return err("invalid platform")
        updates["platform"] = p["platform"]
    if "url" in p and p["url"]:
        ok_url, why = notifications.validate_webhook_url(str(p["url"]))
        if not ok_url:
            return err(f"invalid webhook URL: {why}")
        updates["url_encrypted"] = config.encrypt(p["url"])
    if "severity_min" in p: updates["severity_min"] = int_field(p, "severity_min", 7)
    if "include_ai"   in p: updates["include_ai"]   = 1 if p["include_ai"] else 0
    if "enabled"      in p: updates["enabled"]      = 1 if p["enabled"] else 0
    if "dedup_minutes" in p: updates["dedup_minutes"] = int_field(p, "dedup_minutes", 240)
    if not updates:
        return err("nothing to update")
    db.update_webhook(wid, **updates)
    return ok({"id": wid})


@api_bp.route("/webhooks/<int:wid>", methods=["DELETE"])
def webhooks_delete(wid: int):
    db.delete_webhook(wid)
    return ok({"deleted": wid})


@api_bp.route("/webhooks/<int:wid>/test", methods=["POST"])
def webhooks_test(wid: int):
    w = db.get_webhook(wid)
    if not w:
        return err("not found", 404)
    success, resp = notifications.test_webhook(w)
    return ok({"success": success, "response": resp})


# ---------- factory -------------------------------------------------------

def create_app() -> Flask:
    config.ensure_dirs()
    db.init_db()
    # Idempotent bootstrap on every start — fast if everything's already there.
    try:
        sync.first_run_bootstrap()
    except Exception:  # noqa: BLE001
        log.exception("first_run_bootstrap failed")

    # Background pollers: only if NOT running under systemd-timer mode.
    # When `SOC_POLLERS=systemd` the timer units handle scheduling, so the
    # in-process pollers stay dormant.
    poller_mode = os.environ.get("SOC_POLLERS", "inprocess")
    if poller_mode == "inprocess":
        if not os.environ.get("WERKZEUG_RUN_MAIN") or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            try:
                sync.start_background_pollers()
            except Exception:  # noqa: BLE001
                log.exception("start_background_pollers failed")
    else:
        log.info("In-process pollers disabled (SOC_POLLERS=%s)", poller_mode)

    app = Flask(__name__,
                static_folder="static",
                template_folder="templates")

    # Behind a reverse proxy, request.remote_addr is the proxy's IP — which would
    # collapse the per-IP login throttle to a single global bucket (one client
    # could lock out everyone) and poison audit-log attribution. Only trust
    # X-Forwarded-For when an operator explicitly declares how many proxy hops
    # are in front (SOC_TRUST_PROXY=N); default 0 = trust nothing (direct LAN).
    trust_proxy = int(os.environ.get("SOC_TRUST_PROXY", "0"))
    if trust_proxy > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trust_proxy, x_proto=trust_proxy,
                                x_host=trust_proxy, x_port=trust_proxy)
        log.info("ProxyFix enabled — trusting %d proxy hop(s) for X-Forwarded-* "
                 "(remote_addr now reflects the real client)", trust_proxy)

    app.secret_key = auth.get_or_create_secret_key()
    # Session cookies: 30 days, secure if behind HTTPS (set via env)
    from datetime import timedelta as _td
    app.permanent_session_lifetime = _td(days=30)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SOC_COOKIE_SECURE", "0") == "1",
    )

    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp)

    @app.before_request
    def _csp_nonce():
        # Per-request nonce for inline <script> blocks, so the CSP can drop
        # 'unsafe-inline' from script-src (a real XSS backstop). Set before the
        # auth middleware so it's available even on redirect/error responses.
        import secrets as _secrets
        g.csp_nonce = _secrets.token_urlsafe(16)

    @app.before_request
    def _enforce_auth():
        # Make every session permanent so the 30-day lifetime applies
        from flask import session as _s
        _s.permanent = True
        return auth.login_required_globally()

    # Security response headers on every response (defence-in-depth).
    # HSTS is intentionally omitted until the dashboard is served over HTTPS
    # (sending it over plain HTTP is meaningless and can lock out the host).
    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=()")
        # CSP: inline <script> is nonce-gated (no 'unsafe-inline' for scripts),
        # which makes the policy a genuine XSS backstop. style-src keeps
        # 'unsafe-inline' because the templates use inline style="" attributes
        # (which CSP nonces cannot cover and which can't execute script anyway).
        nonce = getattr(g, "csp_nonce", "")
        script_src = f"script-src 'self' 'nonce-{nonce}'" if nonce else "script-src 'self'"
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            + script_src + "; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'")
        # Dynamic HTML embeds a PER-REQUEST CSP nonce, so it must never be
        # cached: a browser/proxy that reuses a stale HTML body (old nonce)
        # under a freshly-issued CSP header (new nonce) gets its inline
        # <script> blocked, silently breaking page init — observed on
        # /settings (audit log / users widgets blank, zero /api calls fired,
        # 2026-06-07). Static assets (/static/*) keep their own long cache;
        # only text/html is force-uncached here.
        if (resp.content_type or "").startswith("text/html"):
            resp.headers["Cache-Control"] = "no-store"
        if os.environ.get("SOC_COOKIE_SECURE", "0") == "1":
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    # Expose current user + CSP nonce to all templates.
    @app.context_processor
    def _inject_user():
        return {"current_user": auth.current_user(),
                "csp_nonce": getattr(g, "csp_nonce", "")}

    @app.errorhandler(BadParam)
    def _bad_param(e):
        return err(str(e), 400)

    @app.errorhandler(404)
    def not_found(_e):
        if request.path.startswith("/api/"):
            return err("not found", 404)
        return render_template("base.html",
                               theme=config.DEFAULT_THEME,
                               body="<div class='card'><h1>404</h1><p>Not found.</p></div>"), 404

    return app


def _cli_run_oneshot(kind: str) -> int:
    """One-shot poller mode for systemd timers (no Flask server)."""
    config.ensure_dirs()
    db.init_db()
    if kind == "alerts":
        result = sync.sync_recent_alerts()
    elif kind == "dns":
        result = sync.sync_dns_today()
    elif kind == "agents":
        result = sync.sync_agent_status()
    elif kind == "briefings":
        result = sync.sync_briefings()
    elif kind == "retention":
        result = sync.run_retention()
    elif kind == "cve":
        result = sync.sync_cve_briefings()
    elif kind == "bootstrap":
        result = sync.first_run_bootstrap()
    else:
        print(f"unknown kind: {kind}", flush=True)
        return 2
    print(f"[{kind}] {result}", flush=True)
    return 0


if __name__ == "__main__":
    import sys
    # systemd-timer one-shot mode: `python app.py --run alerts`
    if len(sys.argv) >= 3 and sys.argv[1] == "--run":
        sys.exit(_cli_run_oneshot(sys.argv[2]))

    # Normal server mode. In-process pollers are started inside create_app()
    # unless SOC_POLLERS=systemd.
    app = create_app()
    host, port = config.LISTEN_HOST, config.LISTEN_PORT

    # Prefer the waitress production WSGI server. It's a single process with a
    # thread pool, so the in-process pollers (daemon threads) still start
    # exactly once — unlike a multi-worker gunicorn, which would run N copies.
    # Fall back to the Werkzeug dev server only if waitress is unavailable, or
    # if SOC_DEV_SERVER=1 (handy for the auto-reloader during local dev).
    if os.environ.get("SOC_DEV_SERVER") == "1":
        log.warning("SOC_DEV_SERVER=1 → Werkzeug dev server (do not use in production)")
        app.run(host=host, port=port, debug=False)
    else:
        try:
            from waitress import serve
        except ImportError:
            log.warning("waitress not installed → Werkzeug dev server; "
                        "`pip install waitress` for production")
            app.run(host=host, port=port, debug=False)
        else:
            threads = int(os.environ.get("SOC_THREADS", "8"))
            log.info("HomeSOC serving on http://%s:%s via waitress (threads=%d)",
                     host, port, threads)
            serve(app, host=host, port=port, threads=threads, ident="HomeSOC")
