"""Parse briefings, Wazuh alerts, AdGuard querylog, and network context."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


# ---------- briefings -------------------------------------------------------

# Match "**P1**", "**P2 — Open / carry-forward**", "**P3 — Backlog**", etc.
_P_HEADER = re.compile(r"^\*\*(P[123])(?:\s+[^*]*)?\*\*\s*$", re.MULTILINE)
# Match "## Recommended Actions" or "## Recommended Actions — Weekly Review"
_RECS_HEADER = re.compile(r"^##\s+Recommended Actions.*$", re.MULTILINE | re.IGNORECASE)
# Any other ## section
_NEXT_HEADER = re.compile(r"^##\s+", re.MULTILINE)
# Bullet/checkbox line
_BULLET = re.compile(r"^\s*[-*]\s+(?:\[[ x]\]\s+)?(.+)$")


def _strip_md(text: str) -> str:
    """Strip leading "**(Open since X)** " and similar bold preambles, normalise whitespace."""
    text = text.strip()
    # Drop leading "**(...)** " note prefixes that exist in weekly briefings
    text = re.sub(r"^\*\*\([^)]+\)\*\*\s*", "", text)
    # Collapse internal whitespace
    return re.sub(r"\s+", " ", text)


def extract_recommended_actions(content: str) -> list[dict[str, str]]:
    """Return list of {priority, description} for every P1/P2/P3 bullet."""
    m = _RECS_HEADER.search(content)
    if not m:
        return []
    section = content[m.end():]
    end = _NEXT_HEADER.search(section)
    if end:
        section = section[:end.start()]

    out: list[dict[str, str]] = []
    pos = 0
    headers = list(_P_HEADER.finditer(section))
    for i, hm in enumerate(headers):
        priority = hm.group(1)
        body_start = hm.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(section)
        body = section[body_start:body_end]
        # An action item may span multiple wrapped lines until the next bullet
        current: list[str] = []
        for line in body.splitlines():
            if not line.strip():
                if current:
                    out.append({"priority": priority,
                                "description": _strip_md(" ".join(current))})
                    current = []
                continue
            bm = _BULLET.match(line)
            if bm:
                if current:
                    out.append({"priority": priority,
                                "description": _strip_md(" ".join(current))})
                current = [bm.group(1)]
            elif current and line.startswith(" "):
                # continuation of previous bullet (indented wrap)
                current.append(line.strip())
            # else: stray non-bullet line — ignore
        if current:
            out.append({"priority": priority,
                        "description": _strip_md(" ".join(current))})
    return out


def assess_briefing(actions: list[dict[str, str]]) -> str:
    """clean / notable / action_required based on the highest priority present."""
    priorities = {a["priority"] for a in actions}
    if "P1" in priorities:
        return "action_required"
    if "P2" in priorities:
        return "notable"
    return "clean"


def briefing_date_from_filename(path: Path) -> tuple[str, str]:
    """Return (date_iso, type)."""
    name = path.stem  # e.g. "2026-05-21" or "weekly-2026-05-21"
    if name.startswith("weekly-"):
        return name[len("weekly-"):], "weekly"
    return name, "daily"


def action_hash(briefing_date: str, priority: str, description: str) -> str:
    """Hash used to dedupe actions across briefings.

    We hash priority + a normalised description prefix so that the *same* P1
    appearing in a daily and then in the weekly is only stored once. Keep the
    date out so carry-forwards don't multiply.
    """
    # Take first 80 chars, lowercased, alphanumerics only — robust to formatting drift
    norm = re.sub(r"[^a-z0-9 ]", " ", description.lower())
    norm = re.sub(r"\s+", " ", norm).strip()[:120]
    return hashlib.sha256(f"{priority}|{norm}".encode()).hexdigest()


# ---------- wazuh alerts ----------------------------------------------------

def parse_wazuh_alert_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        a = json.loads(line)
    except json.JSONDecodeError:
        return None
    rule = a.get("rule") or {}
    agent = a.get("agent") or {}
    # Normalise timestamp to "YYYY-MM-DDTHH:MM:SS" so it sorts as text.
    ts = a.get("timestamp") or ""
    if ts:
        # Wazuh emits "2026-05-21T00:00:39.057+0000" — slice to seconds.
        ts = ts[:19]
    return {
        "wazuh_id":         a.get("id"),
        "timestamp":        ts,
        "agent_name":       agent.get("name"),
        "agent_ip":         agent.get("ip"),
        "rule_id":          str(rule.get("id") or ""),
        "rule_level":       int(rule.get("level") or 0),
        "rule_description": rule.get("description"),
        "rule_groups":      rule.get("groups") or [],
        "full_log":         a.get("full_log"),
        "location":         a.get("location"),
        "raw":              a,
    }


def parse_wazuh_alerts_stream(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        p = parse_wazuh_alert_line(line)
        if p:
            out.append(p)
    return out


# ---------- adguard querylog -----------------------------------------------

def parse_adguard_lines(lines: Iterable[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            q = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = q.get("Result") or {}
        out.append({
            "ts": q.get("T", "")[:19],
            "qh": q.get("QH"),
            "qt": q.get("QT"),
            "client": q.get("IP"),
            "blocked": bool(result.get("IsFiltered")),
            "elapsed_us": (q.get("Elapsed") or 0) // 1000,
        })
    return out


def summarise_dns(queries: list[dict[str, Any]],
                  day: str,
                  hostname_lookup: dict[str, str] | None = None) -> dict[str, Any]:
    """Build a DNS daily summary from parsed querylog entries."""
    same_day = [q for q in queries if q["ts"].startswith(day)]
    total = len(same_day)
    blocked = sum(1 for q in same_day if q["blocked"])

    top_q = Counter(q["qh"] for q in same_day if q["qh"])
    top_b = Counter(q["qh"] for q in same_day if q["blocked"] and q["qh"])
    per_client_counter: Counter[str] = Counter()
    per_client_blocked: Counter[str] = Counter()
    for q in same_day:
        if not q["client"]:
            continue
        per_client_counter[q["client"]] += 1
        if q["blocked"]:
            per_client_blocked[q["client"]] += 1

    per_client = []
    for client, n in per_client_counter.most_common(50):
        per_client.append({
            "client": client,
            "hostname": (hostname_lookup or {}).get(client, ""),
            "queries": n,
            "blocked": per_client_blocked[client],
        })

    hourly: dict[int, dict[str, int]] = defaultdict(lambda: {"queries": 0, "blocked": 0})
    for q in same_day:
        ts = q["ts"]
        if len(ts) >= 13:
            try:
                hour = int(ts[11:13])
            except ValueError:
                continue
            hourly[hour]["queries"] += 1
            if q["blocked"]:
                hourly[hour]["blocked"] += 1
    hourly_list = [{"hour": h, **hourly[h]} for h in sorted(hourly)]

    return {
        "total_queries":   total,
        "blocked_queries": blocked,
        "top_queried":     [{"domain": d, "count": n} for d, n in top_q.most_common(20)],
        "top_blocked":     [{"domain": d, "count": n} for d, n in top_b.most_common(20)],
        "per_client":      per_client,
        "hourly":          hourly_list,
    }


# ---------- network context (context.md → hosts) ---------------------------

_TABLE_ROW = re.compile(r"^\s*\|\s*(?P<ip>10\.0\.0\.\d+)\s*\|\s*(?P<hostname>[^|]+?)\s*\|\s*(?P<role>[^|]+?)\s*\|\s*(?P<notes>[^|]*)\|")


def parse_context_md(text: str) -> list[dict[str, str]]:
    """Return [{ip, hostname, role, notes}] for every table row that begins with an IP."""
    hosts: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        m = _TABLE_ROW.match(line)
        if not m:
            continue
        ip = m.group("ip").strip()
        if ip in seen:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        seen.add(ip)
        hosts.append({
            "ip":       ip,
            "hostname": m.group("hostname").strip(),
            "role":     m.group("role").strip(),
            "notes":    m.group("notes").strip(),
        })
    return hosts


# ---------- IOC detection ---------------------------------------------------

_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6 = re.compile(r"^[0-9a-fA-F:]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_-]{1,63}\.)+[a-zA-Z]{2,63}$")
_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_URL    = re.compile(r"^https?://", re.IGNORECASE)


def detect_ioc_type(value: str) -> str:
    v = value.strip()
    if _URL.match(v):
        return "url"
    if _IPV4.match(v):
        try:
            ipaddress.IPv4Address(v)
            return "ipv4"
        except ValueError:
            pass
    if ":" in v and _IPV6.match(v):
        try:
            ipaddress.IPv6Address(v)
            return "ipv6"
        except ValueError:
            pass
    if _MD5.match(v):    return "md5"
    if _SHA1.match(v):   return "sha1"
    if _SHA256.match(v): return "sha256"
    if _DOMAIN.match(v): return "domain"
    return "unknown"


def briefing_word_count(content: str) -> int:
    return len(re.findall(r"\b\w+\b", content))
