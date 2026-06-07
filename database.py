"""SQLite schema + CRUD helpers for the SOC dashboard."""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from config import DB_PATH

log = logging.getLogger("soc.database")


SCHEMA = """
CREATE TABLE IF NOT EXISTS briefings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    date          TEXT    NOT NULL,
    type          TEXT    NOT NULL CHECK (type IN ('daily','weekly')),
    content       TEXT    NOT NULL,
    file_path     TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assessment    TEXT    NOT NULL DEFAULT 'clean'
        CHECK (assessment IN ('clean','notable','action_required')),
    UNIQUE(date, type)
);
CREATE INDEX IF NOT EXISTS idx_briefings_date ON briefings(date DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    wazuh_id          TEXT    UNIQUE,
    timestamp         TEXT    NOT NULL,
    agent_name        TEXT,
    agent_ip          TEXT,
    rule_id           TEXT    NOT NULL,
    rule_level        INTEGER NOT NULL,
    rule_description  TEXT,
    rule_groups       TEXT,    -- json array
    full_log          TEXT,
    location          TEXT,
    raw_json          TEXT,    -- full alert json for expansion view
    created_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status            TEXT    NOT NULL DEFAULT 'open',  -- open / acked
    ack_notes         TEXT,
    acked_at          TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_name);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(rule_level);

-- MITRE ATT&CK mapping denormalised out of alerts.raw_json (rule.mitre).
-- One row per (alert, technique, tactic) pair; a single all-empty sentinel
-- row marks an alert as processed-but-unmapped so the populate pass never
-- re-parses it. Empty strings (not NULL) so the PK dedupes INSERT OR IGNORE.
CREATE TABLE IF NOT EXISTS alert_mitre (
    alert_id      INTEGER NOT NULL,
    technique_id  TEXT    NOT NULL DEFAULT '',   -- e.g. T1110
    technique     TEXT    NOT NULL DEFAULT '',   -- e.g. Brute Force
    tactic        TEXT    NOT NULL DEFAULT '',   -- e.g. Credential Access
    PRIMARY KEY (alert_id, technique_id, technique, tactic),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alert_mitre_tech ON alert_mitre(technique_id);
CREATE INDEX IF NOT EXISTS idx_alert_mitre_tactic ON alert_mitre(tactic);

CREATE TABLE IF NOT EXISTS false_positives (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id           TEXT    NOT NULL,     -- wazuh rule id being suppressed
    agent_name        TEXT,                 -- null = all agents
    description       TEXT    NOT NULL,
    wazuh_rule_id     TEXT    NOT NULL,     -- our new 1xxxxx id
    suppression_xml   TEXT    NOT NULL,
    created_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    alert_count       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fp_rule ON false_positives(rule_id);

CREATE TABLE IF NOT EXISTS recommended_actions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    briefing_date     TEXT    NOT NULL,
    priority          TEXT    NOT NULL CHECK (priority IN ('P1','P2','P3')),
    description       TEXT    NOT NULL,
    status            TEXT    NOT NULL DEFAULT 'open'
                       CHECK (status IN ('open','in_progress','resolved')),
    created_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at       TEXT,
    resolution_notes  TEXT,
    source_briefing   TEXT    NOT NULL,         -- file path
    description_hash  TEXT    NOT NULL,         -- for dedupe
    UNIQUE(description_hash)
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON recommended_actions(status);
CREATE INDEX IF NOT EXISTS idx_actions_priority ON recommended_actions(priority);

CREATE TABLE IF NOT EXISTS osint_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value    TEXT NOT NULL,
    ioc_type     TEXT NOT NULL,
    source       TEXT NOT NULL,        -- virustotal / abuseipdb / urlscan
    result_json  TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   TEXT NOT NULL,
    UNIQUE(ioc_value, source)
);
CREATE INDEX IF NOT EXISTS idx_osint_lookup ON osint_results(ioc_value, source);

-- CVE Asset Tracker: the software/product register CVEs are matched against.
-- Distinct from `hosts` (live machines w/ Wazuh agents) — an asset is a
-- product+version you run (nginx, UniFi OS, Proxmox VE), wherever it lives.
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    vendor      TEXT,
    product     TEXT,
    version     TEXT,
    category    TEXT    NOT NULL DEFAULT 'service'
        CHECK (category IN ('os','hypervisor','container_app','network_device','service')),
    exposure    TEXT    NOT NULL DEFAULT 'lan'
        CHECK (exposure IN ('internet','lan','isolated')),
    criticality TEXT    NOT NULL DEFAULT 'medium'
        CHECK (criticality IN ('low','medium','high')),
    cpe         TEXT,                -- optional cpe:2.3:... string for precise matching
    notes       TEXT,
    source      TEXT    NOT NULL DEFAULT 'manual',   -- manual / vigil
    created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL UNIQUE,
    hostname        TEXT,
    role            TEXT,
    agent_id        TEXT,
    agent_status    TEXT,
    last_seen       TEXT,
    notes           TEXT,
    alert_count_7d  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);

CREATE TABLE IF NOT EXISTS settings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    key            TEXT NOT NULL UNIQUE,
    value_encrypted TEXT,
    created_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    service       TEXT NOT NULL UNIQUE,
    key_encrypted TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_daily_stats (
    date              TEXT PRIMARY KEY,
    total_queries     INTEGER NOT NULL DEFAULT 0,
    blocked_queries   INTEGER NOT NULL DEFAULT 0,
    top_queried_json  TEXT,
    top_blocked_json  TEXT,
    per_client_json   TEXT,
    hourly_json       TEXT,
    updated_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_explanations (
    alert_id    INTEGER PRIMARY KEY,
    content     TEXT NOT NULL,
    model       TEXT,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webhooks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    platform        TEXT NOT NULL,        -- mattermost / slack / discord / generic
    url_encrypted   TEXT NOT NULL,         -- Fernet-encrypted webhook URL
    severity_min    INTEGER NOT NULL DEFAULT 7,   -- minimum rule_level to fire
    include_ai      INTEGER NOT NULL DEFAULT 1,   -- 1=include AI explanation when available
    enabled         INTEGER NOT NULL DEFAULT 1,
    dedup_minutes   INTEGER NOT NULL DEFAULT 240, -- per (rule_id, agent) window
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at    TEXT,
    last_error      TEXT
);

CREATE TABLE IF NOT EXISTS notification_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id      INTEGER NOT NULL,
    alert_id        INTEGER,
    rule_id         TEXT,
    agent_name      TEXT,
    sent_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success         INTEGER NOT NULL,
    response_snippet TEXT,
    skipped_reason  TEXT,             -- "dedup", "below_threshold", "disabled" etc.
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_notif_dedup ON notification_log(webhook_id, rule_id, agent_name, sent_at DESC);

CREATE TABLE IF NOT EXISTS ai_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER,
    kind        TEXT NOT NULL,         -- "auto_explain" | "manual_explain" | "chat"
    model       TEXT,
    tokens_in   INTEGER,
    tokens_out  INTEGER,
    elapsed_ms  INTEGER,
    success     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ai_runs_kind_ts ON ai_runs(kind, created_at DESC);

CREATE TABLE IF NOT EXISTS backup_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,    -- "config" | "data" | "full"
    destination   TEXT NOT NULL,    -- "download" | "nas:<path>"
    size_bytes    INTEGER,
    success       INTEGER NOT NULL,
    error         TEXT,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user',
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    username    TEXT,             -- denormalised so it survives user deletion
    action      TEXT NOT NULL,    -- e.g. "alert.ack", "fp.add", "settings.key_set"
    target_type TEXT,             -- "alert" / "host" / "webhook" etc.
    target_id   TEXT,
    details     TEXT,             -- json blob with extra context
    ip_address  TEXT,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);

CREATE TABLE IF NOT EXISTS alert_chat (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER NOT NULL,
    role        TEXT    NOT NULL CHECK (role IN ('user','assistant')),
    content     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_chat_alert ON alert_chat(alert_id, id);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,         -- collect / analyse
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    success     INTEGER,
    output      TEXT,
    briefing_size INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pipeline_kind_ts ON pipeline_runs(kind, started_at DESC);
"""


@contextmanager
def conn() -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection (WAL mode) and always close it.

    NOTE: isolation_level=None means each statement autocommits immediately —
    there is NO implicit transaction or rollback. Multi-statement helpers are
    therefore not atomic; if a sequence must be all-or-nothing, wrap it in an
    explicit BEGIN/COMMIT/ROLLBACK yourself."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA journal_mode = WAL")
    try:
        yield c
    finally:
        c.close()


_MIGRATIONS = [
    # column adds — only applied if missing. Run with pragma_table_info to
    # check existence so this is idempotent across versions.
    ("alerts", "status",    "TEXT NOT NULL DEFAULT 'open'"),
    ("alerts", "ack_notes", "TEXT"),
    ("alerts", "acked_at",  "TEXT"),
    ("users",  "totp_secret",  "TEXT"),                       # Fernet-encrypted
    ("users",  "totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
]


def _apply_migrations(c: sqlite3.Connection) -> None:
    for table, column, ddl in _MIGRATIONS:
        cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]
        if column not in cols:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def _seed_host_config_for_upgrade(c: sqlite3.Connection) -> None:
    """One-shot migration for users upgrading from a version that had
    hard-coded host config. If they already have data (alerts, users) but
    no host_config setting yet, seed it from environment variables so
    their deployment keeps working."""
    has_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
    has_alerts = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] > 0
    has_host_config = c.execute(
        "SELECT 1 FROM settings WHERE key='host_config'"
    ).fetchone() is not None

    if not (has_users or has_alerts):
        return       # fresh install, no need to seed
    if has_host_config:
        return       # already configured

    # Pull from env vars only (no Jacknet IPs in code). User can refine
    # via /settings → Hosts after the upgrade.
    import os
    import json
    from config import encrypt
    seeded = {
        k: v for k, v in {
            "wazuh_host":             os.environ.get("SOC_WAZUH_HOST", ""),
            "wazuh_user":             os.environ.get("SOC_WAZUH_USER", "wazuh"),
            "claudedev_host":         os.environ.get("SOC_CLAUDEDEV_HOST", ""),
            "claudedev_user":         os.environ.get("SOC_CLAUDEDEV_USER", "dev"),
            "adguard_host":           os.environ.get("SOC_ADGUARD_HOST", ""),
            "adguard_user":           os.environ.get("SOC_ADGUARD_USER", ""),
            "adguard_querylog_path":  os.environ.get("SOC_ADGUARD_QUERYLOG", ""),
            "ssh_key_path":           os.environ.get("SOC_SSH_KEY", ""),
            "siem_scripts_dir":       os.environ.get("SOC_SIEM_SCRIPTS_DIR", ""),
            "claude_cli_path":        os.environ.get("SOC_CLAUDE_CLI", ""),
        }.items() if v
    }
    if seeded:
        try:
            c.execute(
                """INSERT INTO settings(key, value_encrypted)
                   VALUES('host_config', ?)
                   ON CONFLICT(key) DO UPDATE SET value_encrypted=excluded.value_encrypted""",
                (encrypt(json.dumps(seeded)),),
            )
        except Exception:  # noqa: BLE001 — never let an upgrade-seed hiccup abort startup
            log.warning("host_config upgrade-seed skipped (encrypt/machine-id issue?)",
                        exc_info=True)


def init_db() -> None:
    with conn() as c:
        c.executescript(SCHEMA)
        _apply_migrations(c)
        # Composite index for the dominant access path: status filter + recency
        # ordering (overview, query_alerts, latest_alerts, /api/home/*). Created
        # AFTER migrations because `status` is a migration-added column on DBs
        # that predate it, so it may not exist at executescript time.
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status_ts "
                  "ON alerts(status, timestamp DESC)")
        _seed_host_config_for_upgrade(c)
        # One-time backfill of alert_mitre from existing raw_json (then a
        # cheap no-op — every processed alert has at least a sentinel row).
        n = _populate_alert_mitre(c)
        if n:
            log.info("alert_mitre: extracted ATT&CK mappings for %d alerts", n)
    # The DB holds Fernet-encrypted secrets + the signed-session key. Its key
    # material (/etc/machine-id) is world-readable, so a local user able to read
    # the DB file could derive those keys — keep the file (and WAL/SHM) owner-only.
    for p in (DB_PATH, f"{DB_PATH}-wal", f"{DB_PATH}-shm"):
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


# ---------- briefings ----------

def upsert_briefing(date: str, btype: str, content: str, file_path: str,
                    assessment: str) -> int:
    with conn() as c:
        cur = c.execute(
            """INSERT INTO briefings(date,type,content,file_path,assessment)
               VALUES(?,?,?,?,?)
               ON CONFLICT(date,type) DO UPDATE SET
                 content=excluded.content,
                 file_path=excluded.file_path,
                 assessment=excluded.assessment""",
            (date, btype, content, file_path, assessment),
        )
        cur = c.execute(
            "SELECT id FROM briefings WHERE date=? AND type=?", (date, btype))
        row = cur.fetchone()
        return int(row["id"]) if row else 0


def get_briefing(briefing_id: int) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute("SELECT * FROM briefings WHERE id=?", (briefing_id,)).fetchone()


def get_briefing_by_date(date: str, btype: str = "daily") -> sqlite3.Row | None:
    with conn() as c:
        return c.execute(
            "SELECT * FROM briefings WHERE date=? AND type=?", (date, btype)
        ).fetchone()


def list_briefings(btype: str | None = None, search: str | None = None) -> list[sqlite3.Row]:
    q = "SELECT id,date,type,assessment,file_path,created_at,length(content) as size,content FROM briefings WHERE 1=1"
    params: list[Any] = []
    if btype:
        q += " AND type=?"
        params.append(btype)
    if search:
        q += " AND content LIKE ?"
        params.append(f"%{search}%")
    q += " ORDER BY date DESC"
    with conn() as c:
        return list(c.execute(q, params).fetchall())


def latest_briefing(btype: str = "daily") -> sqlite3.Row | None:
    with conn() as c:
        return c.execute(
            "SELECT * FROM briefings WHERE type=? ORDER BY date DESC LIMIT 1", (btype,)
        ).fetchone()


# ---------- alerts ----------

def _populate_alert_mitre(c: sqlite3.Connection, batch: int = 5000) -> int:
    """Denormalise rule.mitre out of raw_json into alert_mitre for every alert
    that has no rows there yet. Every processed alert gets at least one row
    (an all-empty sentinel when the rule carries no MITRE metadata), so each
    call only touches alerts inserted since the last one — making this both
    the one-time backfill (init_db) and the per-poll incremental hook.

    Works in id-ordered batches inside explicit transactions: the connection
    is autocommit (isolation_level=None), so an unwrapped executemany would
    fsync per row — on a multi-hundred-MB prod DB that ground the disk for
    minutes with the service unbound (deploy 2026-06-05). Batching also caps
    memory at ~one batch of raw_json instead of fetchall()ing the table.
    Each committed batch is durable progress: a restart mid-backfill resumes
    where it left off (INSERT OR IGNORE + the NOT IN pending check)."""
    from parsers import extract_mitre
    total = 0
    last_id = 0
    while True:
        pending = c.execute(
            "SELECT id, raw_json FROM alerts "
            "WHERE id > ? AND id NOT IN (SELECT alert_id FROM alert_mitre) "
            "ORDER BY id LIMIT ?", (last_id, batch)).fetchall()
        if not pending:
            return total
        last_id = pending[-1]["id"]
        rows: list[tuple[int, str, str, str]] = []
        for r in pending:
            try:
                raw = json.loads(r["raw_json"] or "{}")
            except json.JSONDecodeError:
                raw = {}
            tuples = extract_mitre(raw) if isinstance(raw, dict) else []
            if tuples:
                rows.extend((r["id"], tid, tname, tac) for tid, tname, tac in tuples)
            else:
                rows.append((r["id"], "", "", ""))   # processed-but-unmapped sentinel
        c.execute("BEGIN IMMEDIATE")
        try:
            c.executemany(
                "INSERT OR IGNORE INTO alert_mitre(alert_id,technique_id,technique,tactic) "
                "VALUES(?,?,?,?)", rows)
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise
        total += len(pending)
        if total > batch:   # only a real backfill is worth narrating, not pollers
            log.info("alert_mitre backfill: %d alerts processed…", total)


def insert_alert(a: dict[str, Any]) -> None:
    with conn() as c:
        c.execute(
            """INSERT OR IGNORE INTO alerts
               (wazuh_id,timestamp,agent_name,agent_ip,rule_id,rule_level,
                rule_description,rule_groups,full_log,location,raw_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                a.get("wazuh_id"), a["timestamp"], a.get("agent_name"),
                a.get("agent_ip"), a["rule_id"], a["rule_level"],
                a.get("rule_description"), json.dumps(a.get("rule_groups") or []),
                a.get("full_log"), a.get("location"),
                json.dumps(a.get("raw") or {}),
            ),
        )
        _populate_alert_mitre(c)


def insert_alerts_bulk(items: Iterable[dict[str, Any]]) -> int:
    rows = [
        (
            a.get("wazuh_id"), a["timestamp"], a.get("agent_name"),
            a.get("agent_ip"), a["rule_id"], a["rule_level"],
            a.get("rule_description"), json.dumps(a.get("rule_groups") or []),
            a.get("full_log"), a.get("location"),
            json.dumps(a.get("raw") or {}),
        )
        for a in items
    ]
    if not rows:
        return 0
    with conn() as c:
        cur = c.executemany(
            """INSERT OR IGNORE INTO alerts
               (wazuh_id,timestamp,agent_name,agent_ip,rule_id,rule_level,
                rule_description,rule_groups,full_log,location,raw_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        _populate_alert_mitre(c)
        return cur.rowcount or 0


def query_alerts(*, date_from: str | None = None, date_to: str | None = None,
                 agent: str | None = None, rule_id: str | None = None,
                 min_level: int | None = None, group: str | None = None,
                 search: str | None = None,
                 mitre: str | None = None,
                 statuses: list[str] | None = None,
                 limit: int = 50,
                 offset: int = 0,
                 with_total: bool = True) -> tuple[list[sqlite3.Row], int]:
    q = "FROM alerts WHERE 1=1"
    params: list[Any] = []
    if statuses:
        placeholders = ",".join("?" * len(statuses))
        q += f" AND status IN ({placeholders})"
        params.extend(statuses)
    if date_from:
        q += " AND timestamp >= ?"
        params.append(date_from)
    if date_to:
        q += " AND timestamp <= ?"
        params.append(date_to)
    if agent:
        q += " AND agent_name = ?"
        params.append(agent)
    if rule_id:
        q += " AND rule_id = ?"
        params.append(rule_id)
    if min_level is not None:
        q += " AND rule_level >= ?"
        params.append(min_level)
    if group:
        q += " AND rule_groups LIKE ?"
        params.append(f"%\"{group}\"%")
    if mitre:
        # Exact (case-insensitive) match on technique id, technique name, or
        # tactic via the denormalised alert_mitre table — no raw_json LIKE, so
        # log content that merely mentions "T1110" can't false-positive.
        q += (" AND id IN (SELECT alert_id FROM alert_mitre"
              " WHERE technique_id = ? COLLATE NOCASE"
              " OR technique = ? COLLATE NOCASE"
              " OR tactic = ? COLLATE NOCASE)")
        params.extend([mitre, mitre, mitre])
    if search:
        q += " AND (full_log LIKE ? OR rule_description LIKE ? OR agent_name LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like])
    with conn() as c:
        # Skip the extra full-predicate COUNT pass when the caller discards the
        # total (e.g. CSV export) — with the leading-% LIKE search that COUNT is
        # an unindexable second scan.
        total = c.execute("SELECT COUNT(*) " + q, params).fetchone()[0] if with_total else None
        rows = c.execute(
            "SELECT * " + q + " ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    rows = list(rows)
    return rows, (int(total) if with_total else len(rows))


def mitre_summary(days: int = 7) -> dict[str, Any]:
    """Aggregate MITRE ATT&CK tactic/technique counts over the window from the
    denormalised alert_mitre table (pure SQL — no raw_json re-parsing).

    `matrix` groups techniques under each tactic for the heatmap view; the
    flat `tactics` / `techniques` / `ids` lists are kept for API compat with
    the pre-matrix summary shape. Counts are distinct alerts, so a
    multi-tactic technique (T1078 → 4 tactics) counts once per cell but its
    alert still counts once in `alerts_with_mitre`."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    base = ("FROM alert_mitre m JOIN alerts a ON a.id = m.alert_id "
            "WHERE a.timestamp >= ? AND (m.technique_id != '' OR m.technique != '' OR m.tactic != '')")
    with conn() as c:
        n = c.execute(f"SELECT COUNT(DISTINCT m.alert_id) {base}", (cutoff,)).fetchone()[0]
        tactic_rows = c.execute(
            f"SELECT m.tactic, COUNT(DISTINCT m.alert_id) AS n {base} AND m.tactic != '' "
            "GROUP BY m.tactic ORDER BY n DESC", (cutoff,)).fetchall()
        tech_rows = c.execute(
            f"SELECT m.technique_id, m.technique, COUNT(DISTINCT m.alert_id) AS n {base} "
            "AND (m.technique_id != '' OR m.technique != '') "
            "GROUP BY m.technique_id, m.technique ORDER BY n DESC", (cutoff,)).fetchall()
        cell_rows = c.execute(
            f"SELECT m.tactic, m.technique_id, m.technique, COUNT(DISTINCT m.alert_id) AS n {base} "
            "GROUP BY m.tactic, m.technique_id, m.technique ORDER BY n DESC", (cutoff,)).fetchall()
    matrix: dict[str, list[dict[str, Any]]] = {}
    for r in cell_rows:
        matrix.setdefault(r["tactic"], []).append(
            {"id": r["technique_id"], "name": r["technique"], "count": r["n"]})
    return {
        "days": days,
        "alerts_with_mitre": n,
        "tactics":    [{"name": r["tactic"], "count": r["n"]} for r in tactic_rows],
        "techniques": [{"id": r["technique_id"], "name": r["technique"], "count": r["n"]}
                       for r in tech_rows[:20]],
        "ids":        [{"id": r["technique_id"], "count": r["n"]}
                       for r in tech_rows if r["technique_id"]][:30],
        "matrix":     matrix,
    }


def noisy_rules(days: int = 7, limit: int = 20) -> list[dict[str, Any]]:
    """Top alert-generating rules over the window — candidates for FP
    suppression. Each row is flagged if it's already suppressed."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    with conn() as c:
        suppressed = {row["rule_id"] for row in
                      c.execute("SELECT rule_id FROM false_positives").fetchall()}
        rows = c.execute(
            """SELECT rule_id,
                      COUNT(*)              AS cnt,
                      MAX(rule_level)       AS level,
                      MAX(rule_description) AS description
               FROM alerts
               WHERE timestamp >= ? AND rule_id != ''
               GROUP BY rule_id
               ORDER BY cnt DESC
               LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
    return [{
        "rule_id":     r["rule_id"],
        "count":       int(r["cnt"]),
        "level":       r["level"],
        "description": r["description"],
        "suppressed":  r["rule_id"] in suppressed,
    } for r in rows]


def _parse_ts(s: Any) -> "datetime | None":
    """Best-effort parse of a stored timestamp (handles both the 'T' and space
    separators and any trailing offset) to a naive datetime for arithmetic."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).strip().replace(" ", "T")[:19])
    except ValueError:
        return None


def soc_metrics(days: int = 7) -> dict[str, Any]:
    """Analyst performance over the window: open backlog, triage volume,
    mean-time-to-respond (alert timestamp → acked_at), false-positive rate, and
    a per-day closed count. Derived from the alerts table (status + acked_at)."""
    from collections import Counter
    cutoff_sp = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    status_counts: Counter = Counter()
    per_day: Counter = Counter()
    durations: list[float] = []
    with conn() as c:
        open_count = c.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        triaged = c.execute(
            "SELECT status, timestamp, acked_at FROM alerts "
            "WHERE acked_at IS NOT NULL AND acked_at >= ?", (cutoff_sp,)).fetchall()
    for r in triaged:
        status_counts[r["status"]] += 1
        per_day[(r["acked_at"] or "")[:10]] += 1
        ack, ts = _parse_ts(r["acked_at"]), _parse_ts(r["timestamp"])
        if ack and ts:
            h = (ack - ts).total_seconds() / 3600.0
            if h >= 0:
                durations.append(h)
    total = sum(status_counts.values())
    fp = status_counts.get("false_positive", 0)
    return {
        "days": days,
        "open_alerts": int(open_count),
        "triaged": total,
        "by_status": dict(status_counts),
        "false_positive_rate": round(100.0 * fp / total, 1) if total else 0.0,
        "mttr_hours": round(sum(durations) / len(durations), 2) if durations else None,
        "closed_per_day": [{"day": d, "count": per_day[d]} for d in sorted(per_day) if d],
    }


def latest_alerts(min_level: int = 7, limit: int = 10,
                  only_open: bool = True) -> list[sqlite3.Row]:
    with conn() as c:
        q = "SELECT * FROM alerts WHERE rule_level >= ?"
        params: list[Any] = [min_level]
        if only_open:
            q += " AND status = 'open'"
        q += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        return list(c.execute(q, params).fetchall())


def alerts_since(iso_ts: str) -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute(
            "SELECT * FROM alerts WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 200",
            (iso_ts,),
        ).fetchall())


def alerts_for_host(ip_or_name: str, limit: int = 20) -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute(
            """SELECT * FROM alerts
               WHERE agent_ip=? OR agent_name=?
               ORDER BY timestamp DESC LIMIT ?""",
            (ip_or_name, ip_or_name, limit),
        ).fetchall())


def alert_stats_7d() -> dict[str, Any]:
    """Daily counts, severity distribution, top rules — last 7 days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    with conn() as c:
        by_day = c.execute(
            """SELECT substr(timestamp,1,10) AS day, COUNT(*) AS n
               FROM alerts WHERE timestamp >= ?
               GROUP BY day ORDER BY day""", (cutoff,)).fetchall()
        by_sev = c.execute(
            """SELECT rule_level, COUNT(*) AS n FROM alerts
               WHERE timestamp >= ? GROUP BY rule_level ORDER BY rule_level""",
            (cutoff,)).fetchall()
        by_rule = c.execute(
            """SELECT rule_id, rule_description, COUNT(*) AS n FROM alerts
               WHERE timestamp >= ?
               GROUP BY rule_id ORDER BY n DESC LIMIT 10""", (cutoff,)).fetchall()
    return {
        "by_day": [dict(r) for r in by_day],
        "by_severity": [dict(r) for r in by_sev],
        "top_rules": [dict(r) for r in by_rule],
    }


def alerts_today_count() -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with conn() as c:
        return int(c.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp LIKE ?", (f"{today}%",)
        ).fetchone()[0])


def explanation_get(alert_id: int) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute(
            "SELECT * FROM alert_explanations WHERE alert_id=?", (alert_id,)
        ).fetchone()


def explanation_put(alert_id: int, content: str, model: str) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO alert_explanations(alert_id, content, model)
               VALUES (?,?,?)
               ON CONFLICT(alert_id) DO UPDATE SET
                 content=excluded.content,
                 model=excluded.model,
                 created_at=CURRENT_TIMESTAMP""",
            (alert_id, content, model),
        )


def explanation_delete(alert_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM alert_explanations WHERE alert_id=?", (alert_id,))


# ---------- webhooks -------------------------------------------------------

def list_webhooks() -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute("SELECT * FROM webhooks ORDER BY id").fetchall())


def get_webhook(wid: int) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone()


def insert_webhook(name: str, platform: str, url_encrypted: str,
                   severity_min: int, include_ai: bool,
                   dedup_minutes: int) -> int:
    with conn() as c:
        cur = c.execute(
            """INSERT INTO webhooks(name, platform, url_encrypted, severity_min,
                                    include_ai, dedup_minutes)
               VALUES(?,?,?,?,?,?)""",
            (name, platform, url_encrypted, severity_min,
             1 if include_ai else 0, dedup_minutes),
        )
        return int(cur.lastrowid or 0)


def update_webhook(wid: int, **fields: Any) -> None:
    allowed = {"name", "platform", "url_encrypted", "severity_min",
               "include_ai", "enabled", "dedup_minutes", "last_used_at",
               "last_error"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with conn() as c:
        c.execute(f"UPDATE webhooks SET {cols} WHERE id=?",
                  (*fields.values(), wid))


def delete_webhook(wid: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM webhooks WHERE id=?", (wid,))


def notification_recent(webhook_id: int, rule_id: str, agent_name: str | None,
                        within_minutes: int) -> int:
    """Count successful sends for (webhook, rule, agent) within window."""
    with conn() as c:
        params: list[Any] = [webhook_id, rule_id]
        q = """SELECT COUNT(*) FROM notification_log
               WHERE webhook_id=? AND rule_id=? AND success=1
                 AND sent_at >= datetime('now', ?)"""
        params.append(f"-{within_minutes} minutes")
        if agent_name:
            q += " AND agent_name=?"
            params.append(agent_name)
        else:
            q += " AND agent_name IS NULL"
        return int(c.execute(q, params).fetchone()[0])


def notification_suppressed_since_last_send(webhook_id: int, rule_id: str,
                                            agent_name: str | None) -> int:
    """How many notifications for (webhook, rule, agent) were dedup-suppressed
    since the last successful send. Used to roll that count into the next send
    ("this rule fired N more times"). Keyed on the monotonic row id, not sent_at
    (which is only second-resolution and would miss a same-second burst)."""
    agent_clause = "agent_name=?" if agent_name else "agent_name IS NULL"
    base: list[Any] = [webhook_id, rule_id]
    if agent_name:
        base.append(agent_name)
    with conn() as c:
        last_id = c.execute(
            f"""SELECT COALESCE(MAX(id), 0) FROM notification_log
                WHERE webhook_id=? AND rule_id=? AND {agent_clause} AND success=1""",
            base,
        ).fetchone()[0]
        return int(c.execute(
            f"""SELECT COUNT(*) FROM notification_log
                WHERE webhook_id=? AND rule_id=? AND {agent_clause}
                  AND skipped_reason='dedup' AND id > ?""",
            base + [last_id],
        ).fetchone()[0])


def notification_log_add(webhook_id: int, alert_id: int | None,
                         rule_id: str | None, agent_name: str | None,
                         success: bool, response: str | None,
                         skipped_reason: str | None = None) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO notification_log(webhook_id, alert_id, rule_id,
                  agent_name, success, response_snippet, skipped_reason)
               VALUES(?,?,?,?,?,?,?)""",
            (webhook_id, alert_id, rule_id, agent_name,
             1 if success else 0,
             (response or "")[:500] or None, skipped_reason),
        )


# ---------- ai run accounting ---------------------------------------------

def ai_run_add(alert_id: int | None, kind: str, model: str,
               elapsed_ms: int, success: bool = True) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO ai_runs(alert_id, kind, model, elapsed_ms, success)
               VALUES(?,?,?,?,?)""",
            (alert_id, kind, model, elapsed_ms, 1 if success else 0),
        )


def ai_runs_count(kind: str, hours: int) -> int:
    with conn() as c:
        return int(c.execute(
            """SELECT COUNT(*) FROM ai_runs
               WHERE kind=? AND created_at >= datetime('now', ?)""",
            (kind, f"-{hours} hours"),
        ).fetchone()[0])


# ---------- users (auth) --------------------------------------------------

def list_users() -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute("SELECT * FROM users ORDER BY id").fetchall())


def count_users() -> int:
    with conn() as c:
        return int(c.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def get_user(user_id: int) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def insert_user(username: str, password_hash: str, role: str = "user") -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO users(username, password_hash, role) VALUES(?,?,?)",
            (username, password_hash, role),
        )
        return int(cur.lastrowid or 0)


def update_user_password(user_id: int, password_hash: str) -> None:
    with conn() as c:
        c.execute("UPDATE users SET password_hash=? WHERE id=?",
                  (password_hash, user_id))


def set_user_totp(user_id: int, secret_encrypted: str | None, enabled: bool) -> None:
    """Store (or clear) a user's Fernet-encrypted TOTP secret + enabled flag."""
    with conn() as c:
        c.execute("UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?",
                  (secret_encrypted, 1 if enabled else 0, user_id))


def update_user_login(user_id: int) -> None:
    with conn() as c:
        c.execute("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?",
                  (user_id,))


def disable_user(user_id: int, disabled: bool = True) -> None:
    with conn() as c:
        c.execute("UPDATE users SET disabled=? WHERE id=?",
                  (1 if disabled else 0, user_id))


def delete_user(user_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM users WHERE id=?", (user_id,))


# ---------- audit log -----------------------------------------------------

def audit_add(user_id: int | None, username: str | None, action: str,
              target_type: str | None = None, target_id: str | None = None,
              details: str | None = None, ip_address: str | None = None) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO audit_log(user_id, username, action, target_type,
                  target_id, details, ip_address)
               VALUES(?,?,?,?,?,?,?)""",
            (user_id, username, action, target_type, target_id, details, ip_address),
        )


def audit_list(limit: int = 200, action: str | None = None,
               target_type: str | None = None) -> list[sqlite3.Row]:
    q = "SELECT * FROM audit_log WHERE 1=1"
    params: list[Any] = []
    if action:
        q += " AND action=?"
        params.append(action)
    if target_type:
        q += " AND target_type=?"
        params.append(target_type)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with conn() as c:
        return list(c.execute(q, params).fetchall())


# ---------- backup history ------------------------------------------------

def backup_log_add(kind: str, destination: str, size_bytes: int,
                   success: bool, error: str | None = None) -> int:
    with conn() as c:
        cur = c.execute(
            """INSERT INTO backup_history(kind, destination, size_bytes, success, error)
               VALUES(?,?,?,?,?)""",
            (kind, destination, size_bytes, 1 if success else 0, error),
        )
        return int(cur.lastrowid or 0)


def backup_list(limit: int = 50) -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute(
            "SELECT * FROM backup_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())


# ---------- (existing chat helper continues) ------------------------------

def chat_history(alert_id: int) -> list[dict[str, str]]:
    with conn() as c:
        rows = c.execute(
            "SELECT role, content, created_at FROM alert_chat WHERE alert_id=? ORDER BY id",
            (alert_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def chat_append(alert_id: int, role: str, content: str) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO alert_chat(alert_id, role, content) VALUES(?,?,?)",
            (alert_id, role, content),
        )


def chat_clear(alert_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM alert_chat WHERE alert_id=?", (alert_id,))


# Valid alert status values. "open" is the default; everything non-open is
# considered "off the queue" and hidden from the overview's critical banner.
# "in_progress" still hides from overview (it's actively being investigated).
ALERT_STATUSES = ("open", "in_progress", "tp_remediated", "false_positive", "acknowledged")


def set_alert_status(alert_id: int, status: str, notes: str | None) -> None:
    if status not in ALERT_STATUSES:
        raise ValueError(f"invalid status: {status}")
    with conn() as c:
        if status == "open":
            c.execute(
                "UPDATE alerts SET status=?, acked_at=NULL, ack_notes=NULL WHERE id=?",
                (status, alert_id),
            )
        else:
            c.execute(
                "UPDATE alerts SET status=?, acked_at=CURRENT_TIMESTAMP, ack_notes=? WHERE id=?",
                (status, notes, alert_id),
            )


# Back-compat shims for old call sites
def ack_alert(alert_id: int, notes: str | None) -> None:
    set_alert_status(alert_id, "acknowledged", notes)


def unack_alert(alert_id: int) -> None:
    set_alert_status(alert_id, "open", None)


def get_alert(alert_id: int) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()


def alerts_by_ip(ip: str) -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute(
            "SELECT * FROM alerts WHERE raw_json LIKE ? ORDER BY timestamp DESC LIMIT 50",
            (f"%{ip}%",)).fetchall())


# ---------- false positives ----------

def list_fps() -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute(
            "SELECT * FROM false_positives ORDER BY created_at DESC").fetchall())


def insert_fp(rule_id: str, agent_name: str | None, description: str,
              wazuh_rule_id: str, suppression_xml: str) -> int:
    with conn() as c:
        cur = c.execute(
            """INSERT INTO false_positives
               (rule_id,agent_name,description,wazuh_rule_id,suppression_xml)
               VALUES(?,?,?,?,?)""",
            (rule_id, agent_name, description, wazuh_rule_id, suppression_xml),
        )
        return int(cur.lastrowid or 0)


def delete_fp(fp_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM false_positives WHERE id=?", (fp_id,))


def refresh_fp_alert_counts() -> None:
    """Update alert_count for every FP from the alerts table in a single
    correlated UPDATE (was an N+1 loop of COUNT + UPDATE per FP). A NULL
    agent_name on the FP means 'all agents'."""
    with conn() as c:
        c.execute(
            """UPDATE false_positives SET alert_count = (
                 SELECT COUNT(*) FROM alerts
                 WHERE alerts.rule_id = false_positives.rule_id
                   AND (false_positives.agent_name IS NULL
                        OR alerts.agent_name = false_positives.agent_name)
               )""")


# ---------- recommended actions ----------

def upsert_action(briefing_date: str, priority: str, description: str,
                  source_briefing: str, description_hash: str) -> bool:
    """Return True if newly inserted."""
    with conn() as c:
        cur = c.execute(
            """INSERT OR IGNORE INTO recommended_actions
               (briefing_date,priority,description,source_briefing,description_hash)
               VALUES(?,?,?,?,?)""",
            (briefing_date, priority, description, source_briefing, description_hash),
        )
        return (cur.rowcount or 0) > 0


def list_actions(status: str | None = None, priority: str | None = None,
                 date_from: str | None = None, date_to: str | None = None) -> list[sqlite3.Row]:
    q = "SELECT * FROM recommended_actions WHERE 1=1"
    params: list[Any] = []
    if status:
        q += " AND status=?"
        params.append(status)
    if priority:
        q += " AND priority=?"
        params.append(priority)
    if date_from:
        q += " AND briefing_date >= ?"
        params.append(date_from)
    if date_to:
        q += " AND briefing_date <= ?"
        params.append(date_to)
    q += " ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END, briefing_date DESC"
    with conn() as c:
        return list(c.execute(q, params).fetchall())


def update_action_status(action_id: int, status: str, notes: str | None = None) -> None:
    with conn() as c:
        if status == "resolved":
            c.execute(
                "UPDATE recommended_actions SET status=?, resolved_at=CURRENT_TIMESTAMP, resolution_notes=? WHERE id=?",
                (status, notes, action_id))
        else:
            c.execute(
                "UPDATE recommended_actions SET status=?, resolution_notes=COALESCE(?, resolution_notes) WHERE id=?",
                (status, notes, action_id))


def action_stats() -> dict[str, Any]:
    with conn() as c:
        counts = c.execute(
            """SELECT priority, status, COUNT(*) AS n
               FROM recommended_actions GROUP BY priority, status"""
        ).fetchall()
        avg = c.execute(
            """SELECT priority,
                   AVG((julianday(resolved_at) - julianday(created_at)) * 24) AS avg_hours
               FROM recommended_actions
               WHERE resolved_at IS NOT NULL
               GROUP BY priority"""
        ).fetchall()
        wk = c.execute(
            """SELECT status, COUNT(*) AS n FROM recommended_actions
               WHERE created_at >= date('now','-7 days')
               GROUP BY status"""
        ).fetchall()
    return {
        "counts": [dict(r) for r in counts],
        "avg_resolution_hours": [dict(r) for r in avg],
        "this_week": [dict(r) for r in wk],
    }


# ---------- osint cache ----------

def osint_get(ioc_value: str, source: str) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute(
            "SELECT * FROM osint_results WHERE ioc_value=? AND source=? AND expires_at > CURRENT_TIMESTAMP",
            (ioc_value, source),
        ).fetchone()


def osint_put(ioc_value: str, ioc_type: str, source: str, result: dict[str, Any],
              ttl_days: int = 7) -> None:
    expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).strftime("%Y-%m-%d %H:%M:%S")
    with conn() as c:
        c.execute(
            """INSERT INTO osint_results(ioc_value,ioc_type,source,result_json,expires_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(ioc_value,source) DO UPDATE SET
                 result_json=excluded.result_json,
                 ioc_type=excluded.ioc_type,
                 created_at=CURRENT_TIMESTAMP,
                 expires_at=excluded.expires_at""",
            (ioc_value, ioc_type, source, json.dumps(result), expires),
        )


def osint_purge_expired() -> int:
    """Delete OSINT cache rows past their TTL. Returns the number removed.
    osint_get already filters expired rows out of reads, but without this they
    accumulate forever (and bloat idx_osint_lookup). Called by the retention
    poller."""
    with conn() as c:
        cur = c.execute("DELETE FROM osint_results WHERE expires_at <= CURRENT_TIMESTAMP")
        return cur.rowcount


def notification_log_prune(days: int = 30) -> int:
    """Delete notification_log rows older than `days`. Returns rows removed."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with conn() as c:
        return c.execute("DELETE FROM notification_log WHERE sent_at < ?", (cutoff,)).rowcount


def ai_runs_prune(days: int = 7) -> int:
    """Delete ai_runs accounting rows older than `days` (the usage meter only
    needs the last 24h). Returns rows removed."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with conn() as c:
        return c.execute("DELETE FROM ai_runs WHERE created_at < ?", (cutoff,)).rowcount


def osint_references(ioc_value: str) -> dict[str, list[Any]]:
    """Find alerts/briefings that reference this IOC."""
    with conn() as c:
        alerts = c.execute(
            "SELECT id,timestamp,agent_name,rule_id,rule_description FROM alerts WHERE raw_json LIKE ? ORDER BY timestamp DESC LIMIT 20",
            (f"%{ioc_value}%",),
        ).fetchall()
        briefings = c.execute(
            "SELECT id,date,type FROM briefings WHERE content LIKE ? ORDER BY date DESC LIMIT 20",
            (f"%{ioc_value}%",),
        ).fetchall()
    return {
        "alerts": [dict(r) for r in alerts],
        "briefings": [dict(r) for r in briefings],
    }


# ---------- hosts ----------

def upsert_host(ip: str, hostname: str | None = None, role: str | None = None,
                notes: str | None = None) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO hosts(ip,hostname,role,notes) VALUES(?,?,?,?)
               ON CONFLICT(ip) DO UPDATE SET
                 hostname=COALESCE(excluded.hostname, hosts.hostname),
                 role=COALESCE(excluded.role, hosts.role),
                 notes=COALESCE(excluded.notes, hosts.notes)""",
            (ip, hostname, role, notes),
        )


def update_host_fields(host_id: int, **fields: Any) -> None:
    # Allowlist the column names interpolated into the UPDATE so the helper is
    # injection-safe regardless of caller (values are already parameterised).
    allowed = {"hostname", "role", "notes"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with conn() as c:
        c.execute(f"UPDATE hosts SET {cols} WHERE id=?",
                  (*fields.values(), host_id))


def update_host_agent(ip: str, agent_id: str | None, status: str | None,
                      last_seen: str | None) -> None:
    with conn() as c:
        c.execute(
            "UPDATE hosts SET agent_id=?, agent_status=?, last_seen=? WHERE ip=?",
            (agent_id, status, last_seen, ip),
        )


# ---------- CVE asset tracker: assets --------------------------------------

ASSET_CATEGORIES = ("os", "hypervisor", "container_app", "network_device", "service")
ASSET_EXPOSURES = ("internet", "lan", "isolated")
ASSET_CRITICALITIES = ("low", "medium", "high")


def assets_list() -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute(
            "SELECT * FROM assets ORDER BY "
            "CASE exposure WHEN 'internet' THEN 0 WHEN 'lan' THEN 1 ELSE 2 END, "
            "CASE criticality WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, "
            "name COLLATE NOCASE").fetchall())


def asset_get(asset_id: int) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()


def asset_insert(name: str, **fields: Any) -> int:
    allowed = {"vendor", "product", "version", "category", "exposure",
               "criticality", "cpe", "notes", "source"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    cols = ", ".join(["name", *fields])
    marks = ", ".join("?" * (1 + len(fields)))
    with conn() as c:
        cur = c.execute(f"INSERT INTO assets({cols}) VALUES({marks})",
                        (name, *fields.values()))
        return int(cur.lastrowid or 0)


def update_asset_fields(asset_id: int, **fields: Any) -> None:
    # Same allowlist-the-columns pattern as update_host_fields — values are
    # parameterised, names are interpolated so they must be vetted here.
    allowed = {"name", "vendor", "product", "version", "category", "exposure",
               "criticality", "cpe", "notes"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with conn() as c:
        c.execute(f"UPDATE assets SET {cols}, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                  (*fields.values(), asset_id))


def asset_delete(asset_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM assets WHERE id=?", (asset_id,))


def refresh_host_alert_counts() -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    with conn() as c:
        c.execute(
            """UPDATE hosts SET alert_count_7d = (
                 SELECT COUNT(*) FROM alerts
                 WHERE (alerts.agent_ip = hosts.ip OR alerts.agent_name = hosts.hostname)
                   AND alerts.timestamp >= ?
               )""", (cutoff,))


def list_hosts() -> list[sqlite3.Row]:
    with conn() as c:
        return list(c.execute("SELECT * FROM hosts ORDER BY ip").fetchall())


def get_host(host_id: int) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()


def get_host_by_ip(ip: str) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()


def delete_host(host_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM hosts WHERE id=?", (host_id,))


# ---------- settings / api keys ----------

def setting_get(key: str) -> str | None:
    with conn() as c:
        row = c.execute("SELECT value_encrypted FROM settings WHERE key=?", (key,)).fetchone()
    return row["value_encrypted"] if row else None


def setting_set(key: str, value_encrypted: str | None) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO settings(key,value_encrypted) VALUES(?,?)
               ON CONFLICT(key) DO UPDATE SET value_encrypted=excluded.value_encrypted,
                                              updated_at=CURRENT_TIMESTAMP""",
            (key, value_encrypted),
        )


def api_key_get(service: str) -> str | None:
    with conn() as c:
        row = c.execute("SELECT key_encrypted FROM api_keys WHERE service=?", (service,)).fetchone()
    return row["key_encrypted"] if row else None


def api_key_set(service: str, key_encrypted: str) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO api_keys(service,key_encrypted) VALUES(?,?)
               ON CONFLICT(service) DO UPDATE SET key_encrypted=excluded.key_encrypted,
                                                  created_at=CURRENT_TIMESTAMP""",
            (service, key_encrypted),
        )


def api_key_delete(service: str) -> None:
    with conn() as c:
        c.execute("DELETE FROM api_keys WHERE service=?", (service,))


# ---------- dns daily stats ----------

def dns_save_daily(date: str, stats: dict[str, Any]) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO dns_daily_stats(date,total_queries,blocked_queries,
                  top_queried_json,top_blocked_json,per_client_json,hourly_json,updated_at)
               VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
               ON CONFLICT(date) DO UPDATE SET
                 total_queries=excluded.total_queries,
                 blocked_queries=excluded.blocked_queries,
                 top_queried_json=excluded.top_queried_json,
                 top_blocked_json=excluded.top_blocked_json,
                 per_client_json=excluded.per_client_json,
                 hourly_json=excluded.hourly_json,
                 updated_at=CURRENT_TIMESTAMP""",
            (
                date,
                stats.get("total_queries", 0),
                stats.get("blocked_queries", 0),
                json.dumps(stats.get("top_queried", [])),
                json.dumps(stats.get("top_blocked", [])),
                json.dumps(stats.get("per_client", [])),
                json.dumps(stats.get("hourly", [])),
            ),
        )


def dns_get_daily(date: str) -> dict[str, Any] | None:
    with conn() as c:
        row = c.execute("SELECT * FROM dns_daily_stats WHERE date=?", (date,)).fetchone()
    if not row:
        return None
    return {
        "date": row["date"],
        "total_queries": row["total_queries"],
        "blocked_queries": row["blocked_queries"],
        "top_queried": json.loads(row["top_queried_json"] or "[]"),
        "top_blocked": json.loads(row["top_blocked_json"] or "[]"),
        "per_client": json.loads(row["per_client_json"] or "[]"),
        "hourly": json.loads(row["hourly_json"] or "[]"),
        "updated_at": row["updated_at"],
    }


def dns_last_n_days(n: int = 7) -> list[dict[str, Any]]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%d")
    with conn() as c:
        rows = c.execute(
            "SELECT date,total_queries,blocked_queries FROM dns_daily_stats WHERE date >= ? ORDER BY date",
            (cutoff,)).fetchall()
    return [dict(r) for r in rows]


# ---------- pipeline runs ----------

def pipeline_start(kind: str) -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO pipeline_runs(kind,started_at) VALUES(?,?)",
            (kind, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        return int(cur.lastrowid or 0)


def pipeline_finish(run_id: int, success: bool, output: str,
                    briefing_size: int | None = None) -> None:
    with conn() as c:
        c.execute(
            "UPDATE pipeline_runs SET finished_at=?, success=?, output=?, briefing_size=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             1 if success else 0, output[-8000:] if output else None,
             briefing_size, run_id),
        )


def pipeline_last(kind: str) -> sqlite3.Row | None:
    with conn() as c:
        return c.execute(
            "SELECT * FROM pipeline_runs WHERE kind=? AND finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 1",
            (kind,)).fetchone()
