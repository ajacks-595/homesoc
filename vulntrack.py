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
import re
from typing import Any

import requests

import config
import database as db
import parsers

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


# ---------- BookStack client -------------------------------------------------

def _bs_headers(cfg: dict[str, Any]) -> dict[str, str]:
    h = {"Authorization":
         f"Token {cfg['bookstack_token_id']}:{cfg['bookstack_token_secret']}"}
    if cfg["cf_client_id"]:
        h["CF-Access-Client-Id"] = cfg["cf_client_id"]
        h["CF-Access-Client-Secret"] = cfg["cf_client_secret"]
    return h


def _bs_get(cfg: dict[str, Any], path: str) -> dict[str, Any]:
    url = cfg["bookstack_url"].rstrip("/") + path
    r = requests.get(url, headers=_bs_headers(cfg), timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


def fetch_cve_pages() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return (book_json, flat page list) for the configured CVE book."""
    cfg = get_config()
    if not cfg["bookstack_url"] or not cfg["bookstack_token_id"]:
        raise RuntimeError("BookStack not configured (⚙ on the CVE Tracker page)")
    book = _bs_get(cfg, f"/api/books/{int(cfg['book_id'])}")
    pages: list[dict[str, Any]] = []
    for entry in book.get("contents") or []:
        if entry.get("type") == "page":
            pages.append(entry)
        else:                                   # chapter → nested pages
            pages.extend(entry.get("pages") or [])
    return book, pages


def fetch_page(page_id: int) -> dict[str, Any]:
    return _bs_get(get_config(), f"/api/pages/{int(page_id)}")


# ---------- CVE → asset matching ---------------------------------------------
# Pragmatic homelab matching, not a scanner. Three confidence tiers, each
# recorded with a human-readable reason so the analyst can judge the call:
#   cpe    — the asset's CPE vendor/product appears in the item's affected text
#   strong — the asset's product name appears in the affected text
#   fuzzy  — distinctive token overlap, or a built-in distro→kernel alias
# Drafts (no product and no CPE) are never matched.

_STOPWORDS = {"server", "service", "services", "app", "apps", "os", "home",
              "cloud", "all", "and", "the", "for", "with", "via", "open",
              "source", "edition", "version", "versions"}

# Distro/platform aliases: a "Linux kernel" item affects Ubuntu/Proxmox/Debian
# hosts even when the text never names them. Deliberately small + visible.
_ALIASES: dict[str, tuple[str, ...]] = {
    "ubuntu":  ("linux kernel", "linux"),
    "debian":  ("linux kernel", "linux"),
    "proxmox": ("linux kernel", "linux"),     # PVE is Debian-based
}

_SEV_W = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "unknown": 2.0}
_EXPO_W = {"internet": 3.0, "lan": 2.0, "isolated": 1.0}
_CRIT_W = {"high": 3.0, "medium": 2.0, "low": 1.0}


def _norm(s: str | None) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9. ]", " ", (s or "").lower())).strip()


def _tokens(s: str | None) -> set[str]:
    return {t for t in _norm(s).split()
            if len(t) >= 3 and t not in _STOPWORDS and not t.replace(".", "").isdigit()}


def _cpe_parts(cpe: str | None) -> tuple[str, str] | None:
    """cpe:2.3:a:nginx:nginx:1.27.3:... → ('nginx', 'nginx'); underscores
    become spaces per CPE convention."""
    if not cpe:
        return None
    p = cpe.strip().split(":")
    if len(p) >= 5 and p[0] == "cpe":
        vendor, product = p[3], p[4]
        if product and product != "*":
            return vendor.replace("_", " "), product.replace("_", " ")
    return None


def _phrase_in(phrase: str, text: str) -> bool:
    phrase = _norm(phrase)
    return bool(phrase) and bool(re.search(rf"\b{re.escape(phrase)}\b", text))


def _version_note(item_text: str, asset_version: str | None) -> str:
    """Best-effort version-range commentary for the match reason. We don't
    suppress matches on version logic — prose ranges are too unreliable —
    we surface the evidence and let the analyst decide."""
    if not asset_version:
        return ""
    m = re.search(r"(?:fixed in|patch(?:ed)? (?:in|to)|update to|≥|>=)\s*\**v?(\d[\w.]*)",
                  item_text, re.IGNORECASE)
    if not m:
        return ""
    fixed = m.group(1).rstrip(".")
    try:
        def vt(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in re.findall(r"\d+", v)[:4])
        if vt(asset_version) >= vt(fixed):
            return f" · asset is on {asset_version}, fix is {fixed} — may already be patched"
        return f" · asset on {asset_version}, fix is {fixed}"
    except Exception:  # noqa: BLE001
        return ""


def match_item_to_assets(item: dict[str, Any],
                         assets: list[Any]) -> list[tuple[Any, str, str]]:
    """Returns [(asset_row, confidence, reason)] — best confidence per asset."""
    text = _norm(" ".join(filter(None, (
        item.get("title"), item.get("affects"), item.get("affected_detail")))))
    if not text:
        return []
    text_tokens = set(text.split())
    out: list[tuple[Any, str, str]] = []
    for a in assets:
        if not a["product"] and not a["cpe"]:
            continue                              # draft — excluded by design
        vnote = _version_note(text, a["version"])

        cpe = _cpe_parts(a["cpe"])
        if cpe and (_phrase_in(cpe[1], text) or
                    (cpe[0] and _phrase_in(f"{cpe[0]} {cpe[1]}", text))):
            out.append((a, "cpe",
                        f"CPE product '{cpe[1]}' in affected text{vnote}"))
            continue
        if a["product"] and _phrase_in(a["product"], text):
            reason = f"product '{a['product']}' in affected text"
            if a["vendor"] and _phrase_in(a["vendor"], text):
                reason = f"vendor+{reason}"
            out.append((a, "strong", reason + vnote))
            continue
        # fuzzy: alias hit, or distinctive-token overlap
        basis = " ".join(filter(None, (a["product"], a["name"], a["vendor"])))
        alias_hit = None
        for tok in _tokens(basis):
            for alias in _ALIASES.get(tok, ()):
                if _phrase_in(alias, text):
                    alias_hit = (tok, alias)
                    break
            if alias_hit:
                break
        if alias_hit:
            out.append((a, "fuzzy",
                        f"alias: '{alias_hit[0]}' is {alias_hit[1]}-based and item "
                        f"affects '{alias_hit[1]}'{vnote}"))
            continue
        overlap = _tokens(basis) & text_tokens
        if overlap:
            out.append((a, "fuzzy",
                        f"name tokens {sorted(overlap)} appear in affected text{vnote}"))
    return out


def priority_for(item: dict[str, Any], asset: Any) -> float:
    """severity × exposure × criticality, ×1.5 if actively exploited,
    ×1.2 if CISA-KEV listed. Range ≈ 1–65; sorts the queue, isn't a CVSS."""
    score = (_SEV_W.get(item.get("severity") or "unknown", 2.0)
             * _EXPO_W.get(asset["exposure"], 2.0)
             * _CRIT_W.get(asset["criticality"], 2.0))
    if item.get("exploited"):
        score *= 1.5
    if item.get("kev"):
        score *= 1.2
    return round(score, 1)


# ---------- sync orchestration -------------------------------------------------

def _item_record(item: dict[str, Any], page: dict[str, Any],
                 page_url: str, briefing_date: str) -> dict[str, Any]:
    return {
        "cve_ids": json.dumps(item["cve_ids"]),
        "title": item["title"],
        "severity": item["severity"],
        "cvss_score": item["cvss_score"],
        "cvss_vector": item["cvss_vector"],
        "status_label": item["status_label"],
        "exploited": int(item["exploited"]),
        "kev": int(item["kev"]),
        "stack_flag": item["stack_flag"],
        "affects": item.get("affects"),
        "affected_detail": item.get("affected_detail"),
        "action": item.get("action"),
        "patch": item.get("patch"),
        "section_md": item.get("section_md"),
        "bookstack_page_id": page["id"],
        "bookstack_url": page_url,
        "briefing_date": briefing_date,
        "parse_ok": int(item.get("parse_ok", True)),
    }


def rematch_all() -> dict[str, int]:
    """Re-run matching for every stored item × current assets. Cheap (tens of
    items × tens of assets); called after every sync so asset edits take
    effect without waiting for a new briefing. Never touches workflow status."""
    assets = db.assets_list()
    new = updated = 0
    for row in db.cve_items_list():
        item = dict(row)
        item["exploited"], item["kev"] = bool(row["exploited"]), bool(row["kev"])
        for asset, confidence, reason in match_item_to_assets(item, assets):
            _, created = db.cve_match_upsert(
                row["id"], asset["id"], confidence, reason,
                priority_for(item, asset))
            new += created
            updated += not created
    return {"matches_new": new, "matches_refreshed": updated}


def sync_cve_briefings() -> dict[str, Any]:
    """Poll the BookStack CVE book for new/updated briefing pages, parse them
    into cve_items, and (re)match against the asset register. Idempotent —
    page watermarks skip anything unchanged."""
    cfg = get_config()
    if not cfg["bookstack_url"] or not cfg["bookstack_token_id"]:
        return {"skipped": "bookstack not configured"}

    book, pages = fetch_cve_pages()
    book_slug = book.get("slug") or "cve-deep-dives"
    stats = {"pages_seen": len(pages), "pages_processed": 0,
             "items_new": 0, "items_updated": 0, "warnings": []}

    for p in sorted(pages, key=lambda x: x.get("id") or 0):
        seen = db.cve_page_get(p["id"])
        if seen and seen["updated_at"] == (p.get("updated_at") or ""):
            continue
        try:
            page = fetch_page(p["id"])
        except requests.RequestException as e:
            stats["warnings"].append(f"page {p['id']}: fetch failed: {e}")
            continue
        md = page.get("markdown") or ""
        parsed = parsers.parse_cve_briefing(md)
        stats["warnings"].extend(parsed["warnings"])
        page_url = (f"{cfg['bookstack_url'].rstrip('/')}/books/{book_slug}"
                    f"/page/{page.get('slug')}")
        briefing_date = (page.get("created_at") or "")[:10]
        for item in parsed["items"]:
            _, created = db.cve_item_upsert(
                item["item_key"], **_item_record(item, page, page_url, briefing_date))
            stats["items_new"] += created
            stats["items_updated"] += not created
        db.cve_page_mark(p["id"], page.get("name") or "",
                         p.get("updated_at") or "", len(parsed["items"]))
        stats["pages_processed"] += 1

    stats.update(rematch_all())
    stats.update(notify_new_matches())
    if stats["pages_processed"] or stats["matches_new"]:
        log.info("CVE sync: %s", {k: v for k, v in stats.items() if k != "warnings"})
    return stats


# ---------- proactive alerting (Phase 4) --------------------------------------
# When a sync creates a NEW match above the configured thresholds, announce it
# through the existing webhook channels. notified_at makes this once-per-match;
# notifications.deliver_vuln_match adds the per-webhook dedup window on top.

_SEV_ORDER = ("critical", "high", "medium", "low")


def _meets_alert_threshold(m: Any, cfg: dict[str, Any]) -> bool:
    if not cfg.get("alert_enabled"):
        return False
    min_sev = cfg.get("alert_min_severity") or "high"
    sev = m["severity"] if m["severity"] in _SEV_ORDER else "medium"  # unknown → medium
    if min_sev in _SEV_ORDER and _SEV_ORDER.index(sev) > _SEV_ORDER.index(min_sev):
        return False
    exposures = cfg.get("alert_exposures") or []
    return m["exposure"] in exposures


def notify_new_matches() -> dict[str, int]:
    """Announce unnotified new matches that clear the configured thresholds.
    Below-threshold matches are marked notified too — they were *considered*;
    raising the threshold later shouldn't replay history."""
    import notifications
    cfg = get_config()
    sent = skipped = 0
    for m in db.cve_matches_unnotified():
        if _meets_alert_threshold(m, cfg):
            results = notifications.deliver_vuln_match(dict(m))
            delivered = any(r.get("sent") for r in results)
            log.info("CVE alert %s × %s: %s", m["item_key"], m["asset_name"],
                     [r for r in results if "skipped" not in r] or "all skipped")
            sent += delivered
        else:
            skipped += 1
        db.cve_match_mark_notified(m["id"])
    return {"alerts_sent": sent, "alerts_below_threshold": skipped}
