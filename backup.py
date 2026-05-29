"""Database backup: snapshot SQLite safely, with config-only or full options.

A "config" backup includes user-curated state and credentials:
  - settings, api_keys (encrypted), hosts, false_positives, webhooks, users
A "full" backup is the entire DB including alerts, briefings, OSINT cache, etc.

Backups can be streamed to the browser or pushed via SCP to a configured
destination (e.g. Synology NAS).
"""
from __future__ import annotations

import io
import logging
import os
import shutil
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import config
import database as db
import wazuh

log = logging.getLogger("soc.backup")


# Tables grouped by category. Used for "config-only" backup.
CONFIG_TABLES = (
    "settings", "api_keys", "hosts", "false_positives",
    "webhooks", "users", "recommended_actions",
)
DATA_TABLES_OMIT_FROM_CONFIG = (
    "alerts", "briefings", "osint_results", "dns_daily_stats",
    "pipeline_runs", "alert_explanations", "alert_chat",
    "ai_runs", "notification_log", "backup_history", "audit_log",
    "sqlite_sequence",
)


def snapshot_full(dest_path: str) -> int:
    """Use SQLite's online-backup API to copy the live DB safely."""
    src = sqlite3.connect(config.DB_PATH)
    try:
        dst = sqlite3.connect(dest_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    return Path(dest_path).stat().st_size


def snapshot_config(dest_path: str) -> int:
    """Create a config-only SQLite that contains the schema + the curated
    tables, omitting alert/briefing/OSINT data."""
    # First snapshot the full DB to a temp file (so we capture the live state),
    # then drop the data tables in the copy.
    snapshot_full(dest_path)
    # isolation_level=None → autocommit; VACUUM cannot run inside an
    # implicit transaction.
    c = sqlite3.connect(dest_path, isolation_level=None)
    try:
        for t in DATA_TABLES_OMIT_FROM_CONFIG:
            try:
                c.execute(f"DELETE FROM {t}")
            except sqlite3.OperationalError:
                pass     # table doesn't exist — fine
        c.execute("VACUUM")
    finally:
        c.close()
    return Path(dest_path).stat().st_size


def make_filename(kind: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"soc-dashboard-{kind}-{stamp}.sqlite"


def _secure_tmp() -> Path:
    """A 0600 temp path for an on-disk snapshot. The snapshot is a full copy of
    the DB (Fernet-encrypted secrets + session key), so it must not be written
    to a predictable, world-readable temp name. mkstemp creates it owner-only;
    sqlite reopens it by path."""
    fd, path = tempfile.mkstemp(prefix="socbackup-", suffix=".sqlite")
    os.close(fd)
    return Path(path)


def stream_to_browser(kind: str) -> tuple[bytes, str, int]:
    """Return (bytes, filename, size) ready for a Flask send_file response."""
    filename = make_filename(kind)
    tmp = _secure_tmp()
    try:
        if kind == "config":
            size = snapshot_config(str(tmp))
        elif kind in ("full", "data"):
            size = snapshot_full(str(tmp))
        else:
            raise ValueError(f"unknown kind: {kind}")
        data = tmp.read_bytes()
        db.backup_log_add(kind, "download", size, True)
        return data, filename, size
    except Exception as e:  # noqa: BLE001
        db.backup_log_add(kind, "download", 0, False, str(e))
        raise
    finally:
        try: tmp.unlink()
        except FileNotFoundError: pass


# ---------- NAS / remote destination via SCP ------------------------------

def push_to_nas(kind: str, host: str, user: str, remote_path: str,
                ssh_key: str | None = None) -> dict:
    """SCP a fresh snapshot to a remote host (e.g. Synology). Returns metadata."""
    filename = make_filename(kind)
    tmp = _secure_tmp()
    ssh_key = ssh_key or config.SSH_KEY
    # NAS host/user/key are GUI-editable → validate before they hit the scp argv
    # (same argument-injection guard as the ssh wrappers).
    wazuh.assert_safe_ssh(host, user, ssh_key)
    try:
        if kind == "config":
            size = snapshot_config(str(tmp))
        else:
            size = snapshot_full(str(tmp))

        remote_target = f"{user}@{host}:{remote_path.rstrip('/')}/{filename}"
        cp = subprocess.run(
            ["scp", "-i", ssh_key,
             "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=accept-new",
             "-o", "ConnectTimeout=15",
             str(tmp), remote_target],
            capture_output=True, timeout=120, check=False,
        )
        if cp.returncode != 0:
            err = cp.stderr.decode(errors="replace")[:500]
            db.backup_log_add(kind, f"nas:{remote_target}", size, False, err)
            raise RuntimeError(f"scp failed: {err}")
        db.backup_log_add(kind, f"nas:{remote_target}", size, True)
        return {"destination": remote_target, "size": size, "filename": filename}
    finally:
        try: tmp.unlink()
        except FileNotFoundError: pass


# ---------- settings helpers (NAS target config) --------------------------

NAS_SETTING_KEY = "backup_nas_config"


def nas_config_get() -> dict | None:
    """Return decrypted NAS backup target settings, or None if unconfigured."""
    enc = db.setting_get(NAS_SETTING_KEY)
    if not enc:
        return None
    raw = config.decrypt(enc)
    if not raw:
        return None
    import json
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def nas_config_set(host: str, user: str, remote_path: str) -> None:
    import json
    payload = json.dumps({"host": host, "user": user, "remote_path": remote_path})
    db.setting_set(NAS_SETTING_KEY, config.encrypt(payload))


def nas_config_clear() -> None:
    db.setting_set(NAS_SETTING_KEY, None)
