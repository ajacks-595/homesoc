"""Configuration, environment detection, and crypto setup.

All connection details (hosts, paths, users) are dynamic — they're read from:
  1. The `host_config` JSON blob in the `settings` table (set via the GUI)
  2. Environment variables (defaults when the DB has no entry)
  3. Hardcoded safe defaults (rarely useful — users almost always need to set them)

Existing code accesses these as `config.WAZUH_VM_HOST` (no parens). Module-level
`__getattr__` (PEP 562) resolves them on each access so updates via the GUI
take effect immediately without a restart.

Run-mode is auto-detected; override with `SOC_RUNTIME=prod|dev`.
"""
from __future__ import annotations

import base64
import json
import os
import socket
from hashlib import pbkdf2_hmac
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


# ---------- Crypto (per-machine Fernet) -----------------------------------

_FERNET_SALT_DEFAULT = b"soc-dashboard-v1-deployment-salt"
_FERNET_SALT = (os.environ.get("SOC_FERNET_SALT", "").encode()
                or _FERNET_SALT_DEFAULT)


def _machine_id() -> str:
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p) as f:
                v = f.read().strip()
                if v:
                    return v
        except OSError:
            pass
    return socket.gethostname() + "-no-machine-id"


def fernet() -> Fernet:
    raw = pbkdf2_hmac("sha256", _machine_id().encode(), _FERNET_SALT, 200_000, 32)
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt(plaintext: str) -> str:
    return fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str | None:
    try:
        return fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return None


# ---------- Run mode (static) ---------------------------------------------

HOSTNAME = socket.gethostname()

_runtime = os.environ.get("SOC_RUNTIME")
if _runtime == "prod":
    IS_PROD = True
elif _runtime == "dev":
    IS_PROD = False
else:
    # Auto-detect: if we're running from /opt/dashboard, assume prod.
    IS_PROD = Path(__file__).resolve().parent == Path("/opt/dashboard")
IS_DEV = not IS_PROD


# ---------- Paths (mostly static, some env-overridable) -------------------

if IS_PROD:
    APP_BASE = Path(os.environ.get("SOC_APP_BASE", "/opt/dashboard"))
    SIEM_BASE = Path(os.environ.get("SIEM_BASE", str(APP_BASE / "data" / "siem")))
else:
    APP_BASE = Path(__file__).resolve().parent
    SIEM_BASE = Path(os.environ.get("SIEM_BASE", str(APP_BASE / "data" / "siem")))

BRIEFINGS_DIR = Path(os.environ.get("SOC_BRIEFINGS_DIR", str(SIEM_BASE / "briefings")))
STAGING_DIR = Path(os.environ.get("SOC_STAGING_DIR", str(SIEM_BASE / "logs" / "staging")))
CONTEXT_MD = Path(os.environ.get("SOC_CONTEXT_MD", str(SIEM_BASE / "context.md")))

DATA_DIR = APP_BASE / "data"
DB_PATH = os.environ.get("SOC_DB_PATH", str(DATA_DIR / "dashboard.db"))
LOG_PATH = os.environ.get(
    "SOC_LOG_PATH",
    "/var/log/soc-dashboard.log" if IS_PROD else str(APP_BASE / "soc-dashboard.log"),
)


# ---------- Web (static) -------------------------------------------------

LISTEN_HOST = os.environ.get("SOC_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("SOC_PORT", "8080"))
PUBLIC_BASE_URL = os.environ.get(
    "SOC_PUBLIC_BASE_URL", f"http://localhost:{LISTEN_PORT}"
)

DEFAULT_THEME = os.environ.get("SOC_DEFAULT_THEME", "midnight")
THEMES = ("midnight", "terminal", "nordic", "light")

OSINT_CACHE_DAYS = int(os.environ.get("SOC_OSINT_CACHE_DAYS", "7"))
SSH_TIMEOUT = int(os.environ.get("SOC_SSH_TIMEOUT", "30"))


# ---------- Wazuh paths (env-overridable, rarely changed) -----------------

WAZUH_ALERTS_JSON = os.environ.get(
    "SOC_WAZUH_ALERTS_JSON", "/var/ossec/logs/alerts/alerts.json"
)
WAZUH_LOCAL_RULES = os.environ.get(
    "SOC_WAZUH_LOCAL_RULES", "/var/ossec/etc/rules/local_rules.xml"
)
WAZUH_AGENT_CONTROL = os.environ.get(
    "SOC_WAZUH_AGENT_CONTROL", "/var/ossec/bin/agent_control"
)
WAZUH_VERIFYCONF = os.environ.get(
    "SOC_WAZUH_VERIFYCONF", "/var/ossec/bin/wazuh-analysisd"
)
WAZUH_VERIFYCONF_ARGS = (os.environ.get("SOC_WAZUH_VERIFYCONF_ARGS", "-t") or "").split()


# ---------- GUI-configurable host settings --------------------------------

# Default values are intentionally empty/generic. Users configure via the
# Settings → Hosts panel on first run.
_HOST_DEFAULTS = {
    "wazuh_host":            os.environ.get("SOC_WAZUH_HOST", ""),
    "wazuh_user":            os.environ.get("SOC_WAZUH_USER", "wazuh"),
    "claudedev_host":        os.environ.get("SOC_CLAUDEDEV_HOST", ""),
    "claudedev_user":        os.environ.get("SOC_CLAUDEDEV_USER", "dev"),
    "adguard_host":          os.environ.get("SOC_ADGUARD_HOST", ""),
    "adguard_user":          os.environ.get("SOC_ADGUARD_USER", "root"),
    "adguard_querylog_path": os.environ.get("SOC_ADGUARD_QUERYLOG",
                                             "/opt/AdGuardHome/data/querylog.json"),
    "ssh_key_path":          os.environ.get("SOC_SSH_KEY",
                                             str(APP_BASE / ".ssh" / "id_ed25519")
                                             if IS_PROD else
                                             str(Path.home() / ".ssh" / "id_ed25519")),
    "siem_scripts_dir":      os.environ.get("SOC_SIEM_SCRIPTS_DIR", "/opt/siem/scripts"),
    "claude_cli_path":       os.environ.get("SOC_CLAUDE_CLI", "/usr/local/bin/claude"),
}

_host_config_cache: dict | None = None


def _read_host_config_from_db() -> dict:
    """Lazy import to avoid circular dep (database imports config)."""
    try:
        from database import setting_get
    except Exception:  # noqa: BLE001 — runs before DB initialised? fall through.
        return {}
    enc = setting_get("host_config")
    if not enc:
        return {}
    raw = decrypt(enc)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def host_config() -> dict:
    """Effective host config: DB-stored values override env-var defaults."""
    global _host_config_cache
    if _host_config_cache is None:
        try:
            stored = _read_host_config_from_db()
        except Exception:  # noqa: BLE001
            stored = {}
        _host_config_cache = {**_HOST_DEFAULTS, **{k: v for k, v in stored.items() if v}}
    return _host_config_cache


def host_config_set(values: dict) -> None:
    from database import setting_set
    # Lazy import: wazuh imports config, so this can't be a module-level import.
    from wazuh import assert_safe_host_config
    current = _read_host_config_from_db()
    current.update({k: v for k, v in values.items() if v is not None})
    # Validate the merged result so SSH-injection-unsafe host/user/key values
    # (e.g. -oProxyCommand=...) can never be persisted. Raises ValueError.
    assert_safe_host_config(current)
    setting_set("host_config", encrypt(json.dumps(current)))
    invalidate_host_config()


def invalidate_host_config() -> None:
    global _host_config_cache
    _host_config_cache = None


# ---------- PEP 562 module __getattr__ — dynamic attribute resolution -----

# These attribute names look like constants but resolve to the current
# host_config() value on each access. Existing code that does e.g.
# `config.WAZUH_VM_HOST` keeps working unchanged.
_DYNAMIC_HOST_ATTRS = {
    "WAZUH_VM_HOST":   lambda: host_config().get("wazuh_host", ""),
    "WAZUH_VM_USER":   lambda: host_config().get("wazuh_user", "wazuh"),
    "RUNTIPI_HOST":    lambda: host_config().get("adguard_host", ""),
    "RUNTIPI_USER":    lambda: host_config().get("adguard_user", "root"),
    "CLAUDE_DEV_HOST": lambda: host_config().get("claudedev_host", ""),
    "CLAUDE_DEV_USER": lambda: host_config().get("claudedev_user", "dev"),
    "SSH_KEY":         lambda: host_config().get("ssh_key_path", ""),
    "ADGUARD_QUERYLOG": lambda: host_config().get("adguard_querylog_path", ""),
    "CLAUDE_CLI":      lambda: host_config().get("claude_cli_path", "/usr/local/bin/claude"),
}


def _wazuh_is_local() -> bool:
    """Whether Wazuh manager runs on the same box as the dashboard.

    Prod default: True (typical co-located deploy on the Wazuh manager).
    Dev default: False unless the GUI explicitly points wazuh_host at this host.
    """
    h = host_config().get("wazuh_host", "")
    if IS_PROD:
        # In prod, default to co-located unless GUI says otherwise.
        return not h or h in ("localhost", "127.0.0.1", HOSTNAME)
    return h in ("localhost", "127.0.0.1", HOSTNAME)


def _claudedev_is_local() -> bool:
    """Whether the Claude CLI host (SIEM pipeline) is the same box.

    Dev default: True (typical: develop on the box that has the Claude CLI).
    Prod default: False unless GUI explicitly says so.
    """
    h = host_config().get("claudedev_host", "")
    if IS_DEV:
        return not h or h in ("localhost", "127.0.0.1", HOSTNAME)
    return h in ("localhost", "127.0.0.1", HOSTNAME)


def _siem_scripts() -> dict[str, str]:
    base = host_config().get("siem_scripts_dir", "/opt/siem/scripts")
    return {"collect": f"{base}/collect.sh",
            "analyse": f"{base}/analyse.sh",
            "weekly":  f"{base}/weekly.sh"}


_DYNAMIC_FLAG_ATTRS = {
    "WAZUH_IS_LOCAL":     _wazuh_is_local,
    "CLAUDEDEV_IS_LOCAL": _claudedev_is_local,
    "SIEM_SCRIPTS":       _siem_scripts,
}


def __getattr__(name: str):
    if name in _DYNAMIC_HOST_ATTRS:
        return _DYNAMIC_HOST_ATTRS[name]()
    if name in _DYNAMIC_FLAG_ATTRS:
        return _DYNAMIC_FLAG_ATTRS[name]()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------- Helpers -------------------------------------------------------

def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BRIEFINGS_DIR.mkdir(parents=True, exist_ok=True)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)


def is_host_configured(kind: str) -> bool:
    """Whether the user has set up SSH access to a given component.

    kind: "wazuh" | "claudedev" | "adguard"
    """
    cfg = host_config()
    if kind == "wazuh":
        return bool(cfg.get("wazuh_host")) or IS_PROD
    if kind == "claudedev":
        return bool(cfg.get("claudedev_host")) or IS_DEV
    if kind == "adguard":
        return bool(cfg.get("adguard_host"))
    return False
