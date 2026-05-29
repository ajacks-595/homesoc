"""High-level sync jobs: briefings → DB, Wazuh alerts → DB, AdGuard → DB."""
from __future__ import annotations

import copy
import json
import logging
import os as _os
import queue
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import config
import database as db
import parsers
import wazuh

log = logging.getLogger("soc.sync")


# ---------- briefings ------------------------------------------------------

def pull_data_from_claudedev() -> dict[str, object]:
    """In prod: rsync /opt/siem/{briefings,logs/staging,context.md} from claude-dev
    into SIEM_BASE. In dev: no-op (data is already local)."""
    if config.IS_DEV:
        return {"skipped": "dev"}
    config.SIEM_BASE.mkdir(parents=True, exist_ok=True)
    (config.SIEM_BASE / "logs").mkdir(parents=True, exist_ok=True)
    cp = subprocess_run([
        "rsync", "-az", "--delete",
        "-e", f"ssh -i {config.SSH_KEY} -o BatchMode=yes -o StrictHostKeyChecking=accept-new",
        f"{config.CLAUDE_DEV_USER}@{config.CLAUDE_DEV_HOST}:/opt/siem/briefings/",
        str(config.BRIEFINGS_DIR) + "/",
    ])
    cp2 = subprocess_run([
        "rsync", "-az",
        "-e", f"ssh -i {config.SSH_KEY} -o BatchMode=yes -o StrictHostKeyChecking=accept-new",
        f"{config.CLAUDE_DEV_USER}@{config.CLAUDE_DEV_HOST}:/opt/siem/context.md",
        str(config.CONTEXT_MD),
    ])
    return {
        "briefings_rc": cp.returncode,
        "context_rc": cp2.returncode,
        "errors": (cp.stderr + cp2.stderr).decode("utf-8", errors="replace")[:500],
    }


def subprocess_run(argv):
    import subprocess
    return subprocess.run(argv, capture_output=True, timeout=120, check=False)


def sync_briefings() -> dict[str, int]:
    """Import all briefings from BRIEFINGS_DIR. Idempotent (upserts by date)."""
    if config.IS_PROD:
        pull_data_from_claudedev()
    n_briefings = 0
    n_actions = 0
    if not config.BRIEFINGS_DIR.exists():
        log.warning("briefings dir not found: %s", config.BRIEFINGS_DIR)
        return {"briefings": 0, "actions": 0}

    for path in sorted(config.BRIEFINGS_DIR.glob("*.md")):
        date_str, btype = parsers.briefing_date_from_filename(path)
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            log.warning("cannot read %s: %s", path, e)
            continue
        actions = parsers.extract_recommended_actions(content)
        assessment = parsers.assess_briefing(actions)
        db.upsert_briefing(date_str, btype, content, str(path), assessment)
        n_briefings += 1
        for a in actions:
            h = parsers.action_hash(date_str, a["priority"], a["description"])
            if db.upsert_action(date_str, a["priority"], a["description"],
                                str(path), h):
                n_actions += 1
    return {"briefings": n_briefings, "actions": n_actions}


# ---------- hosts ----------------------------------------------------------

def sync_hosts_from_context() -> int:
    n = 0
    if not config.CONTEXT_MD.exists():
        log.warning("context.md not found: %s", config.CONTEXT_MD)
        return 0
    text = config.CONTEXT_MD.read_text(encoding="utf-8")
    for h in parsers.parse_context_md(text):
        db.upsert_host(h["ip"], h["hostname"], h["role"], h["notes"])
        n += 1
    return n


# ---------- alerts ---------------------------------------------------------

def sync_recent_alerts(max_bytes: int = 8 * 1024 * 1024,
                       dispatch_notifications: bool = True) -> dict[str, int]:
    try:
        text = wazuh.fetch_alerts_tail(max_bytes=max_bytes)
    except wazuh.NotConfigured as e:
        return {"fetched": 0, "inserted": 0, "skipped": str(e)}
    except Exception as e:  # noqa: BLE001
        log.warning("cannot fetch alerts: %s", e)
        return {"fetched": 0, "inserted": 0, "error": str(e)}
    parsed = parsers.parse_wazuh_alerts_stream(text)
    # Track which wazuh_ids are new (vs already in the DB) so we know which
    # alerts to enrich + dispatch. INSERT OR IGNORE means we can't tell from
    # rowcount alone, so snapshot before/after.
    new_wazuh_ids = set()
    if dispatch_notifications and parsed:
        with db.conn() as c:
            existing = c.execute(
                "SELECT wazuh_id FROM alerts WHERE wazuh_id IN (" +
                ",".join("?" * len(parsed)) + ")",
                [a["wazuh_id"] for a in parsed if a.get("wazuh_id")],
            ).fetchall()
        existing_ids = {r["wazuh_id"] for r in existing}
        new_wazuh_ids = {a["wazuh_id"] for a in parsed
                         if a.get("wazuh_id") and a["wazuh_id"] not in existing_ids}

    n = db.insert_alerts_bulk(parsed)

    if dispatch_notifications and new_wazuh_ids:
        _enqueue_dispatch(new_wazuh_ids)

    return {"fetched": len(parsed), "inserted": n,
            "dispatched": len(new_wazuh_ids) if dispatch_notifications else 0}


def _dispatch_new_alerts(new_wazuh_ids: set[str]) -> None:
    """For each freshly-inserted alert, run AI enrichment (if eligible) and
    deliver webhook notifications. Imported lazily to avoid circular imports."""
    import ai
    import notifications

    if not new_wazuh_ids:
        return

    # Fetch the inserted rows so we can build full dispatch payloads
    with db.conn() as c:
        placeholders = ",".join("?" * len(new_wazuh_ids))
        rows = c.execute(
            f"SELECT * FROM alerts WHERE wazuh_id IN ({placeholders}) AND status='open'",
            list(new_wazuh_ids),
        ).fetchall()

    AI_DAILY_CAP = int(_os.environ.get("SOC_AI_DAILY_CAP", "20"))

    for r in rows:
        alert = dict(r)
        try:
            alert["raw_json"] = json.loads(alert["raw_json"]) if alert.get("raw_json") else {}
        except json.JSONDecodeError:
            alert["raw_json"] = {}

        ai_summary = None

        # Auto-explain ONLY for Level 10+ alerts, subject to the rolling 24h cap.
        if alert["rule_level"] >= 10:
            used_today = db.ai_runs_count("auto_explain", 24)
            if used_today < AI_DAILY_CAP:
                try:
                    import time as _t
                    t0 = _t.time()
                    content, model = ai.explain_with_enrichment(alert["raw_json"], alert["id"])
                    elapsed_ms = int((_t.time() - t0) * 1000)
                    db.explanation_put(alert["id"], content, model)
                    db.ai_run_add(alert["id"], "auto_explain", model, elapsed_ms, success=True)
                    ai_summary = content
                except Exception as e:  # noqa: BLE001
                    log.warning("auto-explain failed for alert %s: %s", alert["id"], e)
                    db.ai_run_add(alert["id"], "auto_explain", "(failed)", 0, success=False)
            else:
                log.info("AI daily cap reached (%d/%d); skipping auto-explain for alert %s",
                         used_today, AI_DAILY_CAP, alert["id"])

        # Webhook delivery (always; per-webhook severity filtering inside)
        try:
            notifications.deliver_alert(alert, ai_summary=ai_summary)
        except Exception as e:  # noqa: BLE001
            log.exception("notification delivery failed for alert %s: %s",
                          alert["id"], e)


# ---------- dispatch worker -----------------------------------------------
# AI enrichment is a ~30-60s Claude call per Level-10+ alert (up to the daily
# cap). Running that inline in the alerts poller would block ingestion + webhook
# delivery for minutes during a burst. Instead the poller hands new-alert ids to
# this single background worker and returns immediately.

_dispatch_q: "queue.Queue" = queue.Queue()
_dispatch_worker_thread: threading.Thread | None = None


def _dispatch_worker_loop() -> None:
    while True:
        ids = _dispatch_q.get()
        try:
            if ids is None:           # sentinel → stop (used by tests)
                return
            _dispatch_new_alerts(ids)
        except Exception:  # noqa: BLE001
            log.exception("dispatch worker failed for batch")
        finally:
            _dispatch_q.task_done()


def _start_dispatch_worker() -> None:
    """Start the background dispatch worker (idempotent)."""
    global _dispatch_worker_thread
    if _dispatch_worker_thread and _dispatch_worker_thread.is_alive():
        return
    _dispatch_worker_thread = threading.Thread(
        target=_dispatch_worker_loop, daemon=True, name="dispatch-worker")
    _dispatch_worker_thread.start()


def _enqueue_dispatch(new_wazuh_ids: set[str]) -> None:
    """Hand new-alert enrichment + webhook delivery to the background worker so
    the caller (alerts poller / sync route) returns immediately. Falls back to
    synchronous dispatch when no worker is running — e.g. the systemd one-shot
    mode, a short-lived process where a background thread would never run."""
    if not new_wazuh_ids:
        return
    if _dispatch_worker_thread and _dispatch_worker_thread.is_alive():
        _dispatch_q.put(set(new_wazuh_ids))
    else:
        _dispatch_new_alerts(new_wazuh_ids)


def sync_agent_status() -> int:
    try:
        agents = wazuh.list_agents()
    except wazuh.NotConfigured:
        return 0
    n = 0
    all_hosts = {h["hostname"]: h for h in db.list_hosts() if h["hostname"]}
    for a in agents:
        ip = a.get("ip") or ""
        name = a.get("name") or ""
        # If the agent reports a real IP we match the host by IP.
        # If it reports "any" / "127.0.0.1" (typical) we match by hostname.
        if ip and ip not in ("any", "127.0.0.1"):
            db.update_host_agent(ip, a["id"], a["status"], a.get("last_seen"))
            n += 1
            continue
        # Hostname match — fuzzy (case-insensitive, strip trailing ".local")
        nname = name.lower().rstrip(".").removesuffix(".local")
        for hname, host in all_hosts.items():
            hh = (hname or "").lower().rstrip(".").removesuffix(".local")
            if hh == nname or hname.lower() == name.lower():
                db.update_host_agent(host["ip"], a["id"], a["status"], a.get("last_seen"))
                n += 1
                break
    db.refresh_host_alert_counts()
    return n


# ---------- adguard --------------------------------------------------------

def _adguard_configured() -> bool:
    return bool(config.RUNTIPI_HOST and config.ADGUARD_QUERYLOG)


def _iter_lines(raw: str):
    """Yield lines from a large string one at a time, without building a full
    splitlines() list (the AdGuard tail can be hundreds of MB)."""
    start, n = 0, len(raw)
    while start < n:
        nl = raw.find("\n", start)
        if nl == -1:
            yield raw[start:]
            return
        yield raw[start:nl]
        start = nl + 1


def _fetch_adguard_tail(max_bytes: int = 60 * 1024 * 1024) -> str:
    """Return the recent tail of AdGuard's querylog.json from runtipi.

    The file is millions of lines; we cap to the last ~60 MB which is plenty
    for the most recent day or two of queries.
    """
    if config.IS_DEV:
        # In dev we can SSH to runtipi directly using collector_key.
        cp = wazuh.run_on_runtipi(
            ["sudo", "-n", "/usr/bin/cat", config.ADGUARD_QUERYLOG],
            timeout=60,
        )
    else:
        cp = wazuh.run_on_runtipi(
            ["sudo", "-n", "/usr/bin/cat", config.ADGUARD_QUERYLOG],
            timeout=60,
        )
    if cp.returncode != 0:
        raise RuntimeError(
            f"adguard cat failed: {cp.stderr.decode(errors='replace')[:300]}")
    data = cp.stdout
    if len(data) > max_bytes:
        data = data[-max_bytes:]
        nl = data.find(b"\n")
        if nl >= 0:
            data = data[nl + 1:]
    return data.decode("utf-8", errors="replace")


def sync_dns_today(day: str | None = None) -> dict[str, object]:
    day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if not _adguard_configured():
        return {"skipped": "AdGuard host not configured"}
    try:
        raw = _fetch_adguard_tail()
    except wazuh.NotConfigured as e:
        return {"skipped": str(e)}
    except Exception as e:  # noqa: BLE001
        log.warning("dns sync failed: %s", e)
        return {"error": str(e)}
    hostname_lookup = {h["ip"]: h["hostname"] or "" for h in db.list_hosts()}
    entries = parsers.iter_adguard_lines(_iter_lines(raw))
    stats = parsers.summarise_dns_days(entries, [day], hostname_lookup)[day]
    db.dns_save_daily(day, stats)
    return {"day": day, "queries": stats["total_queries"],
            "blocked": stats["blocked_queries"]}


def sync_dns_last_n(n: int = 7) -> list[dict[str, object]]:
    """Build DNS daily stats for the past N days (one fetch, sliced by day)."""
    if not _adguard_configured():
        return [{"skipped": "AdGuard host not configured"}]
    try:
        raw = _fetch_adguard_tail(max_bytes=200 * 1024 * 1024)
    except wazuh.NotConfigured as e:
        return [{"skipped": str(e)}]
    except Exception as e:  # noqa: BLE001
        log.warning("dns sync failed: %s", e)
        return [{"error": str(e)}]
    hostname_lookup = {h["ip"]: h["hostname"] or "" for h in db.list_hosts()}
    today = datetime.now(timezone.utc).date()
    days = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(n)]
    # Single pass over the (streamed) tail, bucketed into all N days at once —
    # was N full re-scans of a fully-materialized list.
    by_day = parsers.summarise_dns_days(
        parsers.iter_adguard_lines(_iter_lines(raw)), days, hostname_lookup)
    out: list[dict[str, object]] = []
    for d in days:
        stats = by_day[d]
        db.dns_save_daily(d, stats)
        out.append({"day": d, "queries": stats["total_queries"],
                    "blocked": stats["blocked_queries"]})
    return out


# ---------- first-run bootstrap -------------------------------------------

def first_run_bootstrap() -> dict[str, object]:
    """Idempotent: safe to call on every startup."""
    db.init_db()
    config.ensure_dirs()
    out: dict[str, object] = {}
    out["hosts"] = sync_hosts_from_context()
    out["briefings"] = sync_briefings()
    try:
        # Bootstrap pulls a backlog — never dispatch webhooks/AI for it.
        # Real-time dispatch fires from the alerts poller's runs.
        out["alerts"] = sync_recent_alerts(dispatch_notifications=False)
    except Exception as e:  # noqa: BLE001
        out["alerts"] = {"error": str(e)}
    db.refresh_fp_alert_counts()
    db.refresh_host_alert_counts()
    return out


# ---------- pipeline triggers ---------------------------------------------

# ---------- background pollers --------------------------------------------

# Intervals in seconds. Override with env vars for tuning.
import os as _os
_POLL_ALERTS_S    = int(_os.environ.get("SOC_POLL_ALERTS_S",    "300"))    # 5 min
_POLL_DNS_S       = int(_os.environ.get("SOC_POLL_DNS_S",       "3600"))   # 1 hour
_POLL_AGENTS_S    = int(_os.environ.get("SOC_POLL_AGENTS_S",    "900"))    # 15 min
_POLL_BRIEFINGS_S = int(_os.environ.get("SOC_POLL_BRIEFINGS_S", "3600"))   # 1 hour

_pollers_started = False
# Guards _poller_state (written by 4 poller threads, read by the Flask
# /pollers/status handler) and the _pollers_started check-and-set.
_poller_lock = threading.Lock()
_poller_state: dict[str, dict[str, object]] = {
    "alerts":    {"last_run": None, "last_result": None, "last_error": None},
    "dns":       {"last_run": None, "last_result": None, "last_error": None},
    "agents":    {"last_run": None, "last_result": None, "last_error": None},
    "briefings": {"last_run": None, "last_result": None, "last_error": None},
}


def _poller_loop(name: str, interval_s: int, fn) -> None:
    log.info("background poller starting: %s every %ds", name, interval_s)
    while True:
        try:
            res = fn()
            with _poller_lock:
                _poller_state[name]["last_result"] = res
                _poller_state[name]["last_error"] = None
        except Exception as e:  # noqa: BLE001
            log.exception("poller %s failed", name)
            with _poller_lock:
                _poller_state[name]["last_error"] = str(e)
        with _poller_lock:
            _poller_state[name]["last_run"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        time.sleep(interval_s)


def start_background_pollers() -> None:
    """Idempotent: kick off background polling threads. Safe to call once at app start."""
    global _pollers_started
    with _poller_lock:
        if _pollers_started:
            return
        _pollers_started = True

    # Background worker that drains AI-enrichment + delivery off the poller path.
    _start_dispatch_worker()

    # Stagger initial fires by a few seconds so we don't hammer the network at boot.
    def delayed(delay_s: int, name: str, interval_s: int, fn):
        def go():
            time.sleep(delay_s)
            _poller_loop(name, interval_s, fn)
        threading.Thread(target=go, daemon=True, name=f"poll-{name}").start()

    delayed(10, "alerts",    _POLL_ALERTS_S,    sync_recent_alerts)
    delayed(30, "dns",       _POLL_DNS_S,       sync_dns_today)
    delayed(20, "agents",    _POLL_AGENTS_S,    sync_agent_status)
    delayed(40, "briefings", _POLL_BRIEFINGS_S, sync_briefings)
    log.info("background pollers scheduled (alerts %ds, dns %ds, agents %ds, briefings %ds)",
             _POLL_ALERTS_S, _POLL_DNS_S, _POLL_AGENTS_S, _POLL_BRIEFINGS_S)


def poller_status() -> dict[str, object]:
    with _poller_lock:
        state = copy.deepcopy(_poller_state)
    return {
        "running":    _pollers_started,
        "intervals":  {"alerts_s":    _POLL_ALERTS_S,
                       "dns_s":       _POLL_DNS_S,
                       "agents_s":    _POLL_AGENTS_S,
                       "briefings_s": _POLL_BRIEFINGS_S},
        "state":      state,
    }


def trigger_pipeline_script(kind: str) -> dict[str, object]:
    """Run /opt/siem/scripts/{kind}.sh on claude-dev (local exec in dev)."""
    script = config.SIEM_SCRIPTS.get(kind)
    if not script:
        return {"success": False, "error": f"unknown kind: {kind}"}
    run_id = db.pipeline_start(kind)
    # Run as `dev` (not root) so the script can use dev's Claude CLI auth,
    # SSH keys, etc.
    cp = wazuh.run_on_claude_dev(["sudo", "-n", "-u", "dev", script], timeout=600)
    output = (cp.stdout + cp.stderr).decode("utf-8", errors="replace")
    success = cp.returncode == 0
    briefing_size = None
    if kind == "analyse":
        latest = db.latest_briefing("daily")
        briefing_size = len(latest["content"]) if latest else None
    db.pipeline_finish(run_id, success, output, briefing_size)
    return {"success": success, "output": output[-2000:], "run_id": run_id}
