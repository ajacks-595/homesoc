"""CVE Asset Tracker: config, Vigil asset import, BookStack CVE ingestion,
and CVE→asset matching.

Data source is the existing "CVE News" remote routine, which researches CVEs
daily and publishes a structured briefing page into BookStack (book
"CVE Deep Dives"). This module *consumes* that flow — it never fetches CVE
intelligence itself. Matching is pragmatic homelab-grade (CPE-anchored where
available, token/name matching otherwise) and always records confidence + a
human-readable reason rather than pretending to be a scanner.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import requests

import config
import database as db

log = logging.getLogger("soc.vulntrack")

_TIMEOUT = 15

# ---------- configuration ---------------------------------------------------
# One Fernet-encrypted settings blob holds everything: Vigil (asset import),
# BookStack (CVE briefing source), and alert thresholds. Secrets never leave
# the server — config_public() masks them to presence booleans for the UI.

_CONFIG_KEY = "vuln_config"

_DEFAULTS: dict[str, Any] = {
    # Vigil (optional asset-import convenience)
    "vigil_url": "",
    "vigil_api_key": "",
    # BookStack CVE briefing source
    "bookstack_url": "",
    "bookstack_token_id": "",
    "bookstack_token_secret": "",
    "cf_client_id": "",          # Cloudflare Access service token (optional)
    "cf_client_secret": "",
    "book_id": 247,
    # Phase 4: alerting thresholds
    "alert_enabled": False,
    "alert_min_severity": "high",        # critical / high / medium / low
    "alert_exposures": ["internet", "lan", "isolated"],
}

_SECRET_FIELDS = ("vigil_api_key", "bookstack_token_secret", "cf_client_secret")


def get_config() -> dict[str, Any]:
    raw = db.setting_get(_CONFIG_KEY)
    cfg = dict(_DEFAULTS)
    if raw:
        dec = config.decrypt(raw)
        if dec:
            try:
                cfg.update(json.loads(dec))
            except json.JSONDecodeError:
                log.warning("vuln_config is corrupt JSON — using defaults")
    return cfg


def set_config(updates: dict[str, Any]) -> dict[str, Any]:
    cfg = get_config()
    for k, v in updates.items():
        if k not in _DEFAULTS:
            continue
        # Empty-string secrets mean "keep existing" so the UI never needs to
        # echo them back; clear explicitly with None.
        if k in _SECRET_FIELDS and v == "":
            continue
        if k in _SECRET_FIELDS and v is None:
            v = ""
        cfg[k] = v
    db.setting_set(_CONFIG_KEY, config.encrypt(json.dumps(cfg)))
    return cfg


def config_public() -> dict[str, Any]:
    """Config view safe to return to the browser: secrets become booleans."""
    cfg = get_config()
    out = {k: v for k, v in cfg.items() if k not in _SECRET_FIELDS}
    for k in _SECRET_FIELDS:
        out[f"{k}_set"] = bool(cfg.get(k))
    return out


# ---------- Vigil asset import ----------------------------------------------
# Vigil's /api/v1/status returns monitored integrations as {id, name, type,
# health, summary} — names and types only, no vendor/product/version. Imported
# rows are therefore *drafts*: the matcher ignores assets until product (or
# CPE) is filled in, and the UI flags them.

_VIGIL_TYPE_CATEGORY = {
    "proxmox":     "hypervisor",
    "synology":    "os",
    "cloudron":    "container_app",
    "unifi":       "network_device",
    "uptime_kuma": "service",
    "ping":        "service",
    "http":        "service",
    "ssl":         "service",
}


def vigil_fetch_integrations() -> list[dict[str, Any]]:
    cfg = get_config()
    url = (cfg["vigil_url"] or "").rstrip("/")
    key = cfg["vigil_api_key"]
    if not url or not key:
        raise RuntimeError("Vigil URL / API key not configured (Settings → CVE Tracker)")
    r = requests.get(f"{url}/api/v1/status", headers={"X-API-Key": key},
                     timeout=_TIMEOUT)
    r.raise_for_status()
    return (r.json() or {}).get("integrations") or []


def import_assets_from_vigil() -> dict[str, Any]:
    """Seed draft assets from Vigil's integration list. Existing assets
    (by case-insensitive name) are never touched. Returns counts + names."""
    integrations = vigil_fetch_integrations()
    existing = {(a["name"] or "").strip().lower() for a in db.assets_list()}
    imported: list[str] = []
    skipped: list[str] = []
    for it in integrations:
        name = (it.get("name") or "").strip()
        if not name:
            continue
        if name.lower() in existing:
            skipped.append(name)
            continue
        db.asset_insert(
            name,
            category=_VIGIL_TYPE_CATEGORY.get(it.get("type") or "", "service"),
            notes=f"Imported from Vigil ({it.get('type')}) — set vendor/product/version "
                  f"to enable CVE matching. Vigil summary: {it.get('summary') or '—'}",
            source="vigil",
        )
        existing.add(name.lower())
        imported.append(name)
    return {"imported": len(imported), "skipped": len(skipped),
            "imported_names": imported}
