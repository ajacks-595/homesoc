"""AI-powered alert explanations via the Claude CLI on claude-dev.

The Claude CLI is installed on claude-dev (where the SIEM pipeline runs).
The dashboard runs on wazuh-vm, so we shell out over SSH to claude-dev
and run the CLI there. Uses the same reverse-SSH key we already set up.
"""
from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

import config
import database as db
import parsers
import wazuh

log = logging.getLogger("soc.ai")

# Cheaper + faster than Opus for ~3KB of alert JSON. Sonnet has plenty of
# headroom for a single-alert analysis and the round-trip latency feels
# better in the UI.
DEFAULT_MODEL = "claude-sonnet-4-6"

_SYSTEM_PREAMBLE = """You are a senior SOC analyst explaining a Wazuh alert
to a teammate on a home network. Write terse, signal-rich markdown. No
fluff, no over-cautious hedging.

You have WebSearch and WebFetch tools available. USE THEM for any CVE,
threat actor, IOC, or current-events question — don't fall back on
"my knowledge cutoff" when you can simply look it up. Cite sources inline
as bullet links at the end of the relevant section.
"""

_PROMPT_TEMPLATE = """{system}

Format your response as markdown with EXACTLY these section headers and
nothing else. Total under 400 words.

## What it is
One short paragraph: plain-English what this alert is actually flagging.

## How Wazuh detected this
The specific decoder, rule, and Wazuh module (e.g. vulnerability-detector,
rootcheck, syscheck, sshd decoder) that produced this alert. Be precise
about the mechanism.

## Exploitation context
For CVE alerts: vulnerability mechanism, attack surface, prerequisites,
PoCs, active exploitation, threat-actor use. WebSearch this — don't guess.
For other alerts: typical adversary use of this signal, current campaigns.

## Recommended action
ONE concrete next step tailored to THIS alert (host, IP, file, package).
Not generic boilerplate.

=== NETWORK CONTEXT (excerpt) ===
{context}

=== ALERT ===
{alert_json}
"""

_ALLOWED_TOOLS = "WebSearch WebFetch"


def _context_excerpt(max_chars: int = 1500) -> str:
    """Pull a short network-context excerpt for the prompt."""
    try:
        text = config.CONTEXT_MD.read_text(encoding="utf-8")
    except OSError:
        return "(network context unavailable)"
    # Take just the infrastructure/servers table — that's what's useful here
    end = text.find("## User Devices")
    if end == -1:
        end = max_chars
    return text[:min(end, max_chars)]


def _run_claude(prompt: str, model: str, timeout: int = 180) -> str:
    """Run the Claude CLI (local or via reverse-SSH) with web tools enabled."""
    cli = config.CLAUDE_CLI    # GUI-configurable; defaults to /usr/local/bin/claude
    cmd = [cli, "--model", model, "--allowedTools", _ALLOWED_TOOLS, "-p", "-"]

    if config.CLAUDEDEV_IS_LOCAL:
        cp = subprocess.run(
            cmd, input=prompt.encode(), capture_output=True, timeout=timeout, check=False,
        )
    else:
        if not config.CLAUDE_DEV_HOST:
            raise wazuh.NotConfigured("Claude CLI host is not configured")
        # Reuse wazuh._ssh_argv so the host/user/key injection guard applies here too.
        argv = wazuh._ssh_argv(config.CLAUDE_DEV_HOST, config.CLAUDE_DEV_USER, cmd)
        cp = subprocess.run(
            argv, input=prompt.encode(), capture_output=True, timeout=timeout, check=False,
        )

    if cp.returncode != 0:
        err = cp.stderr.decode("utf-8", errors="replace").strip()
        out = cp.stdout.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"claude CLI failed ({cp.returncode}): {err or out}")

    out = cp.stdout.decode("utf-8", errors="replace").strip()
    if not out:
        raise RuntimeError("claude CLI returned empty output")
    return out


def _extract_iocs(alert_raw: dict[str, Any]) -> dict[str, set[str]]:
    """Pull IOCs (IPs, domains, hashes) out of an alert for cross-correlation."""
    iocs: dict[str, set[str]] = {"ipv4": set(), "domain": set(), "hash": set()}
    # Walk the JSON looking for string values that look like IOCs.
    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str):
            # Quick cheap regex first to find candidates
            import re
            for tok in re.findall(r"\b[\w.:-]{3,64}\b", o):
                t = parsers.detect_ioc_type(tok)
                if t == "ipv4":
                    # Skip RFC1918 — internal IPs aren't IOCs in this context
                    if not (tok.startswith("10.") or tok.startswith("192.168.")
                            or tok.startswith("172.")):
                        iocs["ipv4"].add(tok)
                elif t == "domain":
                    iocs["domain"].add(tok)
                elif t in ("md5", "sha1", "sha256"):
                    iocs["hash"].add(tok)
    walk(alert_raw)
    return iocs


def _related_observations(alert_id: int, alert_raw: dict[str, Any],
                          max_items: int = 30) -> str:
    """Pre-correlate this alert against our own DB and return a markdown
    snippet to embed in the prompt. Looks for:
    - Other Wazuh alerts referencing the same IPs/domains (last 24h)
    - DNS activity from/to the same IPs/domains (top-N from per-client + top-domains)
    - UniFi events for the same source IP
    """
    iocs = _extract_iocs(alert_raw)
    flat_iocs = iocs["ipv4"] | iocs["domain"] | iocs["hash"]
    if not flat_iocs:
        return ""

    lines: list[str] = []
    seen = 0
    with db.conn() as c:
        # Other Wazuh alerts referencing these IOCs (last 24h)
        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        cutoff = (_dt.now(_tz.utc) - _td(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
        for ioc in list(flat_iocs)[:10]:    # cap how many IOCs we probe
            if seen >= max_items:
                break
            rows = c.execute(
                """SELECT timestamp, agent_name, rule_id, rule_level, rule_description, location
                   FROM alerts
                   WHERE id != ? AND timestamp >= ?
                     AND (raw_json LIKE ? OR full_log LIKE ?)
                   ORDER BY timestamp DESC LIMIT 5""",
                (alert_id, cutoff, f"%{ioc}%", f"%{ioc}%"),
            ).fetchall()
            for r in rows:
                if seen >= max_items:
                    break
                lines.append(
                    f"- `{ioc}` → Wazuh alert {r['timestamp']} agent=`{r['agent_name']}` "
                    f"rule={r['rule_id']} (L{r['rule_level']}): {r['rule_description']}"
                )
                seen += 1

    # DNS activity from today's snapshot
    today = _dt.now(_tz.utc).strftime("%Y-%m-%d")
    dns = db.dns_get_daily(today) or {}
    top_blocked = {d["domain"]: d["count"] for d in dns.get("top_blocked", [])}
    top_queried = {d["domain"]: d["count"] for d in dns.get("top_queried", [])}
    for domain in list(iocs["domain"])[:5]:
        if domain in top_blocked:
            lines.append(f"- `{domain}` → AdGuard BLOCKED {top_blocked[domain]} times today")
            seen += 1
        elif domain in top_queried:
            lines.append(f"- `{domain}` → AdGuard queried {top_queried[domain]} times today (not blocked)")
            seen += 1
        if seen >= max_items:
            break

    if not lines:
        return ""
    return "\n=== RELATED OBSERVATIONS (from your network, last 24h) ===\n" + "\n".join(lines)


def related_observations(alert_id: int, alert_raw: dict[str, Any],
                         max_items: int = 30) -> dict[str, Any]:
    """Structured cross-correlation for the UI 'Related activity' panel — the
    same IOC overlap _related_observations summarizes for the AI prompt, but
    returned as data and WITHOUT any Claude call, so it's cheap to show on every
    alert expand. Returns {iocs, alerts:[{ioc,...}], dns:[{domain,status,count}]}."""
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    iocs = _extract_iocs(alert_raw)
    flat = sorted(iocs["ipv4"] | iocs["domain"] | iocs["hash"])
    out: dict[str, Any] = {"iocs": flat, "alerts": [], "dns": []}
    if not flat:
        return out

    cutoff = (_dt.now(_tz.utc) - _td(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    with db.conn() as c:
        for ioc in flat[:10]:
            if len(out["alerts"]) >= max_items:
                break
            rows = c.execute(
                """SELECT id, timestamp, agent_name, rule_id, rule_level, rule_description
                   FROM alerts
                   WHERE id != ? AND timestamp >= ?
                     AND (raw_json LIKE ? OR full_log LIKE ?)
                   ORDER BY timestamp DESC LIMIT 5""",
                (alert_id, cutoff, f"%{ioc}%", f"%{ioc}%"),
            ).fetchall()
            for r in rows:
                if len(out["alerts"]) >= max_items:
                    break
                out["alerts"].append({"ioc": ioc, **dict(r)})

    today = _dt.now(_tz.utc).strftime("%Y-%m-%d")
    dns = db.dns_get_daily(today) or {}
    top_blocked = {d["domain"]: d["count"] for d in dns.get("top_blocked", [])}
    top_queried = {d["domain"]: d["count"] for d in dns.get("top_queried", [])}
    for domain in sorted(iocs["domain"])[:5]:
        if domain in top_blocked:
            out["dns"].append({"domain": domain, "status": "blocked", "count": top_blocked[domain]})
        elif domain in top_queried:
            out["dns"].append({"domain": domain, "status": "queried", "count": top_queried[domain]})
    return out


def explain(alert_raw: dict[str, Any], model: str = DEFAULT_MODEL,
            alert_id: int | None = None) -> tuple[str, str]:
    """Generate an AI explanation of the alert. Returns (content, model_used)."""
    related = _related_observations(alert_id or 0, alert_raw) if alert_id else ""
    prompt = _PROMPT_TEMPLATE.format(
        system=_SYSTEM_PREAMBLE,
        context=_context_excerpt(),
        alert_json=json.dumps(alert_raw, indent=2)[:60_000],
    )
    if related:
        prompt += "\n" + related
    return _run_claude(prompt, model), model


def explain_with_enrichment(alert_raw: dict[str, Any], alert_id: int,
                            model: str = DEFAULT_MODEL) -> tuple[str, str]:
    """Convenience: same as explain() but always pre-correlates."""
    return explain(alert_raw, model=model, alert_id=alert_id)


def chat(alert_raw: dict[str, Any], explanation: str,
         history: list[dict[str, str]], user_message: str,
         model: str = DEFAULT_MODEL) -> tuple[str, str]:
    """Continue a follow-up conversation about a specific alert.

    history: list of {"role": "user"|"assistant", "content": str}
    user_message: the new message to send
    Returns (assistant_reply, model_used).
    """
    # Build a single prompt that includes the original explanation + chat history.
    # The CLI doesn't expose multi-turn natively in -p mode for OAuth users,
    # so we serialise the conversation into one prompt. Claude handles this fine.
    convo = []
    for msg in history:
        speaker = "User" if msg["role"] == "user" else "Assistant"
        convo.append(f"### {speaker}\n{msg['content']}")
    convo.append(f"### User\n{user_message}")
    convo_text = "\n\n".join(convo)

    prompt = f"""{_SYSTEM_PREAMBLE}

You previously explained this Wazuh alert to a teammate (below). The
teammate now has follow-up questions. Use WebSearch and WebFetch as
needed for any current threat-intel question. Answer ONLY the most
recent user message. Be terse and signal-rich. Markdown OK.

=== NETWORK CONTEXT (excerpt) ===
{_context_excerpt()}

=== ALERT JSON ===
{json.dumps(alert_raw, indent=2)[:30_000]}

=== ORIGINAL EXPLANATION ===
{explanation}

=== CONVERSATION SO FAR ===
{convo_text}

### Assistant
"""
    return _run_claude(prompt, model), model
