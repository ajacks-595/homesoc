"""Outbound webhook notifications for alerts.

Supports Mattermost, Slack, Discord, and a generic JSON sink. Each webhook
in the `webhooks` table is configured with a platform + URL + filters; this
module formats and delivers a payload appropriate for that platform.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import requests

import config
import database as db

log = logging.getLogger("soc.notify")

_TIMEOUT = 15


# ---------- formatters ----------------------------------------------------

def _sev_emoji(level: int) -> str:
    if level >= 12: return ":rotating_light:"
    if level >= 10: return ":warning:"
    if level >= 7:  return ":eyes:"
    return ":small_blue_diamond:"


def _truncate(s: str, n: int) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


def _alert_url(alert_id: int) -> str:
    """Public link to the alert in the dashboard."""
    base = config.PUBLIC_BASE_URL.rstrip("/") if hasattr(config, "PUBLIC_BASE_URL") else f"http://{config.LISTEN_HOST}:{config.LISTEN_PORT}"
    return f"{base}/alerts?focus={alert_id}"


def _format_for_mattermost(alert: dict, ai_summary: str | None,
                           dedup_count: int) -> dict:
    level = alert.get("rule_level", 0)
    title = f"{_sev_emoji(level)} **L{level} alert — {alert.get('rule_description','')[:120]}**"

    fields = [
        f"**Agent:** `{alert.get('agent_name','—')}`",
        f"**Rule:** `{alert.get('rule_id')}` · level {level}",
        f"**Time:** {alert.get('timestamp','')}",
    ]
    if alert.get("location"):
        fields.append(f"**Source:** `{alert['location']}`")
    if dedup_count > 0:
        fields.append(f"_(rolled-up: this rule fired {dedup_count} more times in the dedup window)_")

    text = "\n".join([title, "", " · ".join(fields[:3]), *fields[3:]])

    if ai_summary:
        text += f"\n\n---\n{_truncate(ai_summary, 3500)}"

    text += f"\n\n[Open in dashboard]({_alert_url(alert['id'])})"
    return {"text": text, "username": "HomeSOC", "icon_emoji": ":shield:"}


def _format_for_slack(alert: dict, ai_summary: str | None,
                      dedup_count: int) -> dict:
    # Slack accepts the same simple text payload as Mattermost for incoming webhooks
    return _format_for_mattermost(alert, ai_summary, dedup_count)


def _format_for_discord(alert: dict, ai_summary: str | None,
                        dedup_count: int) -> dict:
    level = alert.get("rule_level", 0)
    color = 0xF85149 if level >= 10 else 0xD29922 if level >= 7 else 0x58A6FF

    desc_lines = [
        f"**Rule:** `{alert.get('rule_id')}` · L{level}",
        f"**Agent:** `{alert.get('agent_name','—')}`",
        f"**Time:** {alert.get('timestamp','')}",
    ]
    if alert.get("location"):
        desc_lines.append(f"**Source:** `{alert['location']}`")
    if dedup_count > 0:
        desc_lines.append(f"_Rolled-up: rule fired {dedup_count} more times_")

    embed: dict[str, Any] = {
        "title": _truncate(alert.get("rule_description", "(no description)"), 250),
        "description": "\n".join(desc_lines),
        "color": color,
        "url": _alert_url(alert["id"]),
    }
    if ai_summary:
        embed["fields"] = [{
            "name": "AI Analysis",
            "value": _truncate(ai_summary, 1024),
            "inline": False,
        }]
    return {"embeds": [embed], "username": "HomeSOC"}


def _format_for_generic(alert: dict, ai_summary: str | None,
                        dedup_count: int) -> dict:
    """Plain JSON for users wiring up custom integrations."""
    return {
        "alert": alert,
        "ai_summary": ai_summary,
        "dedup_count": dedup_count,
        "dashboard_url": _alert_url(alert["id"]),
    }


_FORMATTERS = {
    "mattermost": _format_for_mattermost,
    "slack":      _format_for_slack,
    "discord":    _format_for_discord,
    "generic":    _format_for_generic,
}

SUPPORTED_PLATFORMS = tuple(_FORMATTERS.keys())


# ---------- delivery ------------------------------------------------------

def _decrypt_url(enc: str) -> str | None:
    return config.decrypt(enc)


def send_to_webhook(webhook_row, alert: dict[str, Any],
                    ai_summary: str | None = None,
                    dedup_count: int = 0) -> tuple[bool, str]:
    """Format + POST to a webhook. Returns (success, response_snippet)."""
    url = _decrypt_url(webhook_row["url_encrypted"])
    if not url:
        return False, "url decrypt failed (wrong machine?)"

    formatter = _FORMATTERS.get(webhook_row["platform"])
    if not formatter:
        return False, f"unknown platform: {webhook_row['platform']}"

    payload = formatter(alert, ai_summary, dedup_count)

    try:
        r = requests.post(url, json=payload, timeout=_TIMEOUT)
    except requests.RequestException as e:
        return False, f"network error: {e}"

    ok = r.status_code in (200, 201, 202, 204)
    snippet = f"{r.status_code} {r.text[:200]}"
    return ok, snippet


def deliver_alert(alert: dict[str, Any],
                  ai_summary: str | None = None) -> list[dict[str, Any]]:
    """Iterate all enabled webhooks and deliver `alert` to those whose
    severity threshold matches. Honour per-webhook dedup windows.

    Returns a list of delivery outcomes for logging/inspection.
    """
    out: list[dict[str, Any]] = []
    level = alert.get("rule_level", 0)
    rule_id = alert.get("rule_id")
    agent = alert.get("agent_name")

    for w in db.list_webhooks():
        wid = w["id"]
        if not w["enabled"]:
            out.append({"webhook": wid, "skipped": "disabled"})
            continue
        if level < w["severity_min"]:
            out.append({"webhook": wid, "skipped": "below_threshold"})
            continue

        # Dedup
        dedup_count_seen = db.notification_recent(
            wid, rule_id, agent, w["dedup_minutes"])
        if dedup_count_seen > 0:
            db.notification_log_add(
                wid, alert.get("id"), rule_id, agent, success=False,
                response=None, skipped_reason="dedup")
            out.append({"webhook": wid, "skipped": "dedup",
                        "previous_in_window": dedup_count_seen})
            continue

        summary = ai_summary if w["include_ai"] else None
        ok, resp = send_to_webhook(w, alert, summary, dedup_count=0)
        db.notification_log_add(
            wid, alert.get("id"), rule_id, agent,
            success=ok, response=resp)
        db.update_webhook(
            wid, last_used_at=__import__("datetime").datetime.utcnow().isoformat(timespec="seconds"),
            last_error=None if ok else resp[:500])
        out.append({"webhook": wid, "sent": ok, "response": resp})

    return out


def test_webhook(webhook_row) -> tuple[bool, str]:
    """Send a synthetic test notification."""
    sample = {
        "id": 0,
        "rule_id": "0",
        "rule_level": 10,
        "rule_description": "Test alert from HomeSOC — webhook configuration check",
        "agent_name": "soc-dashboard",
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(timespec="seconds"),
        "location": "test",
    }
    return send_to_webhook(webhook_row, sample,
                           ai_summary="This is a test message. If you see this in your channel, the webhook is wired up correctly.",
                           dedup_count=0)
