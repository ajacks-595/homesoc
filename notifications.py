"""Outbound webhook notifications for alerts.

Supports Mattermost, Slack, Discord, and a generic JSON sink. Each webhook
in the `webhooks` table is configured with a platform + URL + filters; this
module formats and delivers a payload appropriate for that platform.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests

import config
import database as db

log = logging.getLogger("soc.notify")

_TIMEOUT = 15

# SSRF guard. Loopback / link-local (incl. 169.254.169.254 cloud metadata) /
# multicast / reserved / unspecified are ALWAYS rejected. Private LAN ranges
# (10/8, 172.16/12, 192.168/16, fc00::/7) are permitted by default because
# HomeSOC commonly posts to a self-hosted Mattermost on the LAN; set
# SOC_WEBHOOK_ALLOW_PRIVATE=0 to block them too (e.g. once the dashboard is
# exposed through a public reverse proxy).
_ALLOW_PRIVATE = os.environ.get("SOC_WEBHOOK_ALLOW_PRIVATE", "1") == "1"


def _ip_is_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → block
    if (ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return True
    if ip.is_private and not _ALLOW_PRIVATE:
        return True
    return False


def validate_webhook_url(url: str) -> tuple[bool, str]:
    """SSRF guard for outbound webhook POSTs. Returns (ok, reason).

    Enforces http(s) and resolves the host, rejecting if ANY resolved address
    is loopback/link-local/metadata/multicast/reserved/unspecified (or private
    when SOC_WEBHOOK_ALLOW_PRIVATE=0). Note: a determined DNS-rebinding attacker
    could still race the resolve vs. the connect; full mitigation would pin the
    resolved IP. This closes the "no validation at all" gap for a LAN tool."""
    try:
        u = urlparse(url or "")
    except ValueError:
        return False, "unparseable URL"
    if u.scheme not in ("http", "https"):
        return False, f"scheme must be http or https (got {u.scheme or 'none'!r})"
    host = u.hostname
    if not host:
        return False, "missing host"
    try:
        infos = socket.getaddrinfo(
            host, u.port or (443 if u.scheme == "https" else 80),
            proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False, "no addresses resolved"
    for a in addrs:
        if _ip_is_blocked(a):
            return False, f"host resolves to a blocked address ({a})"
    return True, "ok"


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
    if url is None:
        return False, "url decrypt failed (wrong machine?)"
    if not url:
        return False, "webhook URL is empty"

    ok_url, why = validate_webhook_url(url)
    if not ok_url:
        return False, f"refusing webhook URL: {why}"

    formatter = _FORMATTERS.get(webhook_row["platform"])
    if not formatter:
        return False, f"unknown platform: {webhook_row['platform']}"

    payload = formatter(alert, ai_summary, dedup_count)

    try:
        # allow_redirects=False: a permitted host must not be able to 302 the
        # POST onward to an internal address (SSRF bypass).
        r = requests.post(url, json=payload, timeout=_TIMEOUT, allow_redirects=False)
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

        # Roll up how many times this rule fired (and was suppressed) since we
        # last actually notified this webhook — makes the formatters' "fired N
        # more times" line accurate instead of always 0.
        rollup = db.notification_suppressed_since_last_send(wid, rule_id, agent)
        summary = ai_summary if w["include_ai"] else None
        ok, resp = send_to_webhook(w, alert, summary, dedup_count=rollup)
        db.notification_log_add(
            wid, alert.get("id"), rule_id, agent,
            success=ok, response=resp)
        db.update_webhook(
            wid, last_used_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            last_error=None if ok else resp[:500])
        out.append({"webhook": wid, "sent": ok, "response": resp,
                    "rolled_up": rollup})

    return out


def test_webhook(webhook_row) -> tuple[bool, str]:
    """Send a synthetic test notification."""
    sample = {
        "id": 0,
        "rule_id": "0",
        "rule_level": 10,
        "rule_description": "Test alert from HomeSOC — webhook configuration check",
        "agent_name": "soc-dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "location": "test",
    }
    return send_to_webhook(webhook_row, sample,
                           ai_summary="This is a test message. If you see this in your channel, the webhook is wired up correctly.",
                           dedup_count=0)
