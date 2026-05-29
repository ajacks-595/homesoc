"""VirusTotal / AbuseIPDB / URLScan integration with 7-day SQLite cache."""
from __future__ import annotations

import base64
import json
import logging
from datetime import datetime
from typing import Any

import requests

import config
import database as db
from parsers import detect_ioc_type

log = logging.getLogger("soc.osint")

_TIMEOUT = 20


# ---------- key helpers ---------------------------------------------------

def _key(service: str) -> str | None:
    enc = db.api_key_get(service)
    if not enc:
        return None
    return config.decrypt(enc)


def set_key(service: str, plaintext: str) -> None:
    db.api_key_set(service, config.encrypt(plaintext))


def clear_key(service: str) -> None:
    db.api_key_delete(service)


def key_status() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for svc in ("virustotal", "abuseipdb", "urlscan"):
        pt = _key(svc)
        out[svc] = {
            "configured": bool(pt),
            "last4": (pt[-4:] if pt and len(pt) >= 4 else None),
        }
    return out


# ---------- cache helpers ------------------------------------------------

def _from_cache(ioc: str, source: str) -> dict[str, Any] | None:
    row = db.osint_get(ioc, source)
    if not row:
        return None
    res = json.loads(row["result_json"])
    return {
        "success": True,
        "from_cache": True,
        "cached_at": row["created_at"],
        "expires_at": row["expires_at"],
        "data": res,
    }


def _store(ioc: str, ioc_type: str, source: str, data: dict[str, Any]) -> None:
    db.osint_put(ioc, ioc_type, source, data, ttl_days=config.OSINT_CACHE_DAYS)


def _parse_json(r, provider: str):
    """Return (body, None) on success, or (None, error_dict) when a 200 body
    isn't valid JSON (providers sometimes return WAF/captcha/gateway HTML).
    requests.JSONDecodeError subclasses ValueError, so this catches both."""
    try:
        return r.json(), None
    except ValueError:
        return None, {"success": False,
                      "error": f"invalid JSON from {provider} (HTTP {r.status_code})"}


# ---------- VirusTotal ---------------------------------------------------

def virustotal(ioc: str, *, force_refresh: bool = False) -> dict[str, Any]:
    ioc_type = detect_ioc_type(ioc)
    if not force_refresh:
        c = _from_cache(ioc, "virustotal")
        if c:
            return c
    key = _key("virustotal")
    if not key:
        return {"success": False, "error": "API key not configured"}

    if ioc_type in ("ipv4", "ipv6"):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type in ("md5", "sha1", "sha256"):
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "url":
        b = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{b}"
    else:
        return {"success": False, "error": f"unsupported IOC type: {ioc_type}"}

    try:
        r = requests.get(url, headers={"x-apikey": key}, timeout=_TIMEOUT)
    except requests.RequestException as e:
        return {"success": False, "error": f"network error: {e}"}
    if r.status_code == 404:
        # VT has no record — store empty result so we don't hammer it
        data = {"not_found": True}
        _store(ioc, ioc_type, "virustotal", data)
        return {"success": True, "from_cache": False, "data": data}
    if r.status_code != 200:
        return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:300]}"}

    body, jerr = _parse_json(r, "virustotal")
    if jerr:
        return jerr
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    summary = {
        "malicious":   stats.get("malicious", 0),
        "suspicious":  stats.get("suspicious", 0),
        "harmless":    stats.get("harmless", 0),
        "undetected":  stats.get("undetected", 0),
        "engines":     sum(stats.values()) if stats else 0,
        "detection":   f"{stats.get('malicious', 0)}/{sum(stats.values()) if stats else 0}",
        "categories":  list((attrs.get("categories") or {}).values()),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "report_url":  f"https://www.virustotal.com/gui/search/{ioc}",
        "reputation":  attrs.get("reputation"),
        "country":     attrs.get("country"),
        "as_owner":    attrs.get("as_owner"),
    }
    _store(ioc, ioc_type, "virustotal", summary)
    return {"success": True, "from_cache": False, "data": summary}


# ---------- AbuseIPDB ----------------------------------------------------

def abuseipdb(ioc: str, *, force_refresh: bool = False) -> dict[str, Any]:
    ioc_type = detect_ioc_type(ioc)
    if ioc_type not in ("ipv4", "ipv6"):
        return {"success": False, "error": "AbuseIPDB only accepts IPs"}
    if not force_refresh:
        c = _from_cache(ioc, "abuseipdb")
        if c:
            return c
    key = _key("abuseipdb")
    if not key:
        return {"success": False, "error": "API key not configured"}

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""},
            timeout=_TIMEOUT,
        )
    except requests.RequestException as e:
        return {"success": False, "error": f"network error: {e}"}
    if r.status_code != 200:
        return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:300]}"}

    body, jerr = _parse_json(r, "abuseipdb")
    if jerr:
        return jerr
    d = (body.get("data") or {})
    summary = {
        "abuse_confidence":    d.get("abuseConfidenceScore", 0),
        "country_code":        d.get("countryCode"),
        "country_name":        d.get("countryName"),
        "isp":                 d.get("isp"),
        "domain":              d.get("domain"),
        "usage_type":          d.get("usageType"),
        "total_reports":       d.get("totalReports", 0),
        "num_distinct_users":  d.get("numDistinctUsers", 0),
        "last_reported_at":    d.get("lastReportedAt"),
        "is_whitelisted":      d.get("isWhitelisted", False),
        "is_tor":              d.get("isTor", False),
        "report_url":          f"https://www.abuseipdb.com/check/{ioc}",
    }
    _store(ioc, ioc_type, "abuseipdb", summary)
    return {"success": True, "from_cache": False, "data": summary}


# ---------- URLScan -------------------------------------------------------

def urlscan(ioc: str, *, force_refresh: bool = False) -> dict[str, Any]:
    ioc_type = detect_ioc_type(ioc)
    if not force_refresh:
        c = _from_cache(ioc, "urlscan")
        if c:
            return c
    key = _key("urlscan")
    if not key:
        return {"success": False, "error": "API key not configured"}

    # URLScan supports search by domain/ip/url
    try:
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            headers={"API-Key": key},
            params={"q": ioc, "size": 5},
            timeout=_TIMEOUT,
        )
    except requests.RequestException as e:
        return {"success": False, "error": f"network error: {e}"}
    if r.status_code != 200:
        return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:300]}"}

    body, jerr = _parse_json(r, "urlscan")
    if jerr:
        return jerr
    results = body.get("results", []) or []
    latest = results[0] if results else {}
    page = latest.get("page", {}) if latest else {}
    task = latest.get("task", {}) if latest else {}
    verdicts = latest.get("verdicts", {}).get("overall", {}) if latest else {}
    summary = {
        "found":         bool(results),
        "result_count":  body.get("total", 0),
        "verdict":       verdicts.get("malicious", False) and "malicious" or "clean",
        "score":         verdicts.get("score"),
        "categories":    verdicts.get("categories", []),
        "scan_date":     task.get("time"),
        "scan_url":      latest.get("result"),
        "screenshot":    latest.get("screenshot"),
        "page_url":      page.get("url"),
        "page_domain":   page.get("domain"),
        "page_ip":       page.get("ip"),
    }
    _store(ioc, ioc_type, "urlscan", summary)
    return {"success": True, "from_cache": False, "data": summary}


# ---------- run-all -------------------------------------------------------

def run_all(ioc: str, *, force_refresh: bool = False) -> dict[str, Any]:
    return {
        "virustotal": virustotal(ioc, force_refresh=force_refresh),
        "abuseipdb":  abuseipdb(ioc, force_refresh=force_refresh)
                       if detect_ioc_type(ioc) in ("ipv4", "ipv6") else
                       {"success": False, "error": "AbuseIPDB only accepts IPs"},
        "urlscan":    urlscan(ioc, force_refresh=force_refresh),
    }


# ---------- key test ------------------------------------------------------

def test_key(service: str) -> dict[str, Any]:
    """Validate that the stored key is accepted by the upstream service."""
    key = _key(service)
    if not key:
        return {"success": False, "error": "no key configured"}
    try:
        if service == "virustotal":
            r = requests.get(
                "https://www.virustotal.com/api/v3/users/current",
                headers={"x-apikey": key}, timeout=_TIMEOUT)
        elif service == "abuseipdb":
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": "8.8.8.8"}, timeout=_TIMEOUT)
        elif service == "urlscan":
            r = requests.get(
                "https://urlscan.io/user/quotas/",
                headers={"API-Key": key}, timeout=_TIMEOUT)
        else:
            return {"success": False, "error": f"unknown service: {service}"}
    except requests.RequestException as e:
        return {"success": False, "error": str(e)}
    return {"success": r.status_code in (200, 201),
            "status_code": r.status_code,
            "snippet": r.text[:200]}
