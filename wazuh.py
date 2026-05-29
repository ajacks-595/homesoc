"""Wazuh integration over SSH (or local exec when running on wazuh-vm)."""
from __future__ import annotations

import logging
import re
import subprocess
from datetime import datetime, timezone
from typing import Any

import defusedxml.ElementTree as DET  # safe XML parsing (no entity expansion)

import config

log = logging.getLogger("soc.wazuh")


# ---------- shell helpers ---------------------------------------------------

# SSH host/user/key come from the GUI-editable host_config. They are placed in
# the ssh argv *before* "--", so a value beginning with "-" would be parsed by
# ssh as an option (e.g. -oProxyCommand=...) — argument injection / RCE. These
# patterns require a safe leading char and reject whitespace + shell metachars.
_SSH_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]*$")        # hostname or IP(v4/v6)
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*$")
_SSH_KEY_RE = re.compile(r"^[A-Za-z0-9/~][A-Za-z0-9._/~\-]*$")      # filesystem path


def _safe_ssh(value: str, what: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise ValueError(
            f"refusing unsafe SSH {what} {value!r}: must match {pattern.pattern} "
            "(guards against argument injection such as -oProxyCommand=...)"
        )
    return value


def assert_safe_ssh(host: str, user: str, key: str) -> None:
    """Validate SSH connection components before they hit an ssh/scp argv.
    Raises ValueError on anything that could be parsed as an ssh option.
    Reused by wazuh, ai (via _ssh_argv) and backup (scp to NAS)."""
    _safe_ssh(host, "host", _SSH_HOST_RE)
    _safe_ssh(user, "user", _SSH_USER_RE)
    _safe_ssh(key, "key path", _SSH_KEY_RE)


# host_config field name -> validating pattern, for the SSH-relevant fields that
# end up as host/user/key in an ssh/scp argv. The command-path fields
# (siem_scripts_dir, claude_cli_path, adguard_querylog_path) are remote command
# tokens placed after "--", not ssh options, so they aren't argument-injection
# vectors and are intentionally not pattern-checked here.
_HOST_CONFIG_SSH_FIELDS = {
    "wazuh_host":     _SSH_HOST_RE,
    "claudedev_host": _SSH_HOST_RE,
    "adguard_host":   _SSH_HOST_RE,
    "wazuh_user":     _SSH_USER_RE,
    "claudedev_user": _SSH_USER_RE,
    "adguard_user":   _SSH_USER_RE,
    "ssh_key_path":   _SSH_KEY_RE,
}


def assert_safe_host_config(cfg: dict) -> None:
    """Validate the SSH-relevant fields of a host_config blob so injection-unsafe
    values (e.g. a host of '-oProxyCommand=...') can never be stored. Empty
    values are allowed (they mean 'unset / use default'). Raises ValueError."""
    for field, pattern in _HOST_CONFIG_SSH_FIELDS.items():
        val = cfg.get(field)
        if val:   # only non-empty values are constrained
            _safe_ssh(val, field, pattern)


def _ssh_argv(host: str, user: str, remote_cmd: list[str], *,
              key: str | None = None) -> list[str]:
    key = key or config.SSH_KEY
    assert_safe_ssh(host, user, key)
    return [
        "ssh", "-i", key,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={min(config.SSH_TIMEOUT, 10)}",
        f"{user}@{host}",
        "--",
        *remote_cmd,
    ]


def _run_local(argv: list[str], *, input_: bytes | None = None,
               timeout: int | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv, input=input_, capture_output=True,
        timeout=timeout or config.SSH_TIMEOUT, check=False,
    )


class NotConfigured(Exception):
    """Raised when a component the dashboard wants to talk to has no host configured."""


def run_on_wazuh_vm(remote_cmd: list[str], *, input_: bytes | None = None,
                    timeout: int | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run remote_cmd on the Wazuh manager. Local exec if we ARE the Wazuh manager."""
    if config.WAZUH_IS_LOCAL:
        return _run_local(remote_cmd, input_=input_, timeout=timeout)
    if not config.WAZUH_VM_HOST:
        raise NotConfigured("Wazuh manager not configured — set up in Settings → Hosts")
    argv = _ssh_argv(config.WAZUH_VM_HOST, config.WAZUH_VM_USER, remote_cmd)
    return _run_local(argv, input_=input_, timeout=timeout)


def run_on_claude_dev(remote_cmd: list[str], *,
                      timeout: int | None = None) -> subprocess.CompletedProcess[bytes]:
    if config.CLAUDEDEV_IS_LOCAL:
        return _run_local(remote_cmd, timeout=timeout)
    if not config.CLAUDE_DEV_HOST:
        raise NotConfigured("Claude CLI / SIEM host is not configured")
    argv = _ssh_argv(config.CLAUDE_DEV_HOST, config.CLAUDE_DEV_USER, remote_cmd)
    return _run_local(argv, timeout=timeout)


def run_on_runtipi(remote_cmd: list[str], *,
                   timeout: int | None = None) -> subprocess.CompletedProcess[bytes]:
    if not config.RUNTIPI_HOST:
        raise NotConfigured("AdGuard host is not configured")
    argv = _ssh_argv(config.RUNTIPI_HOST, config.RUNTIPI_USER, remote_cmd)
    return _run_local(argv, timeout=timeout)


# ---------- connection test ------------------------------------------------

def connection_status() -> dict[str, Any]:
    out: dict[str, Any] = {"connected": False, "version": None, "agent_count": None,
                           "error": None, "configured": True}
    if not config.WAZUH_IS_LOCAL and not config.WAZUH_VM_HOST:
        out["configured"] = False
        out["error"] = "Wazuh host not configured — see Settings → Hosts"
        return out
    try:
        cp = run_on_wazuh_vm(["sudo", "-n", "/var/ossec/bin/wazuh-control", "info"])
        if cp.returncode == 0:
            out["connected"] = True
            txt = cp.stdout.decode(errors="replace")
            m = re.search(r"WAZUH_VERSION=\"?([^\"\n]+)", txt)
            if m:
                out["version"] = m.group(1).strip()
        else:
            # Fall back: at minimum we can ssh in
            cp2 = run_on_wazuh_vm(["hostname"], timeout=5)
            if cp2.returncode == 0:
                out["connected"] = True
                out["error"] = "ssh ok, wazuh-control denied (sudoers needed)"
            else:
                out["error"] = cp2.stderr.decode(errors="replace").strip() or "ssh failed"
    except subprocess.TimeoutExpired:
        out["error"] = "ssh timeout"
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    try:
        agents = list_agents()
        out["agent_count"] = sum(1 for a in agents if a["status"] != "no_agent")
    except Exception as e:  # noqa: BLE001 - agent count is best-effort
        log.warning("agent count unavailable: %s", e)
    return out


# ---------- alerts ---------------------------------------------------------

def fetch_alerts_tail(max_bytes: int = 8 * 1024 * 1024) -> str:
    """Return the recent tail of /var/ossec/logs/alerts/alerts.json (text)."""
    # Use tail -c so we don't ship the entire file every poll.
    cp = run_on_wazuh_vm(
        ["sudo", "-n", "/usr/bin/cat", config.WAZUH_ALERTS_JSON],
        timeout=30,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"cat alerts.json failed: {cp.stderr.decode(errors='replace')[:300]}")
    data = cp.stdout
    if len(data) > max_bytes:
        data = data[-max_bytes:]
        # Trim partial leading line
        nl = data.find(b"\n")
        if nl >= 0:
            data = data[nl + 1:]
    return data.decode("utf-8", errors="replace")


# ---------- agents ---------------------------------------------------------

# /var/ossec/bin/agent_control -l output example:
# Wazuh agent_control. List of available agents:
#    ID: 000, Name: wazuh (server), IP: 127.0.0.1, Active/Local
#    ID: 002, Name: cloudron, IP: any, Active
_AGENT_LINE = re.compile(
    r"^\s*ID:\s*(?P<id>\d+),\s*Name:\s*(?P<name>[^,]+?),\s*IP:\s*(?P<ip>[^,]+?),\s*(?P<status>.+?)\s*$"
)


def list_agents() -> list[dict[str, Any]]:
    cp = run_on_wazuh_vm(["sudo", "-n", config.WAZUH_AGENT_CONTROL, "-l"], timeout=20)
    if cp.returncode != 0:
        log.warning("agent_control failed: %s", cp.stderr.decode(errors="replace")[:200])
        return []
    out: list[dict[str, Any]] = []
    text = cp.stdout.decode("utf-8", errors="replace")
    for line in text.splitlines():
        m = _AGENT_LINE.match(line)
        if not m:
            continue
        status = m.group("status").strip().lower()
        norm = "active" if "active" in status else (
            "disconnected" if "disconnected" in status else
            ("never" if "never" in status else "no_agent")
        )
        out.append({
            "id":     m.group("id"),
            "name":   m.group("name").strip().replace(" (server)", ""),
            "ip":     m.group("ip").strip(),
            "status": norm,
            "raw_status": status,
            "last_seen": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
    return out


# ---------- local_rules.xml -----------------------------------------------

def read_local_rules() -> str:
    cp = run_on_wazuh_vm(["sudo", "-n", "/usr/bin/cat", config.WAZUH_LOCAL_RULES], timeout=20)
    if cp.returncode != 0:
        # If the file doesn't exist yet, treat as empty groups skeleton.
        msg = cp.stderr.decode(errors="replace")
        if "No such file" in msg:
            return '<group name="local,syscheck,">\n</group>\n'
        raise RuntimeError(f"read local_rules.xml failed: {msg[:300]}")
    return cp.stdout.decode("utf-8", errors="replace")


def write_local_rules(content: str) -> None:
    """Write via `sudo tee` so we can avoid sh redirection."""
    cp = run_on_wazuh_vm(
        ["sudo", "-n", "/usr/bin/tee", config.WAZUH_LOCAL_RULES],
        input_=content.encode("utf-8"), timeout=20,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"write local_rules.xml failed: {cp.stderr.decode(errors='replace')[:300]}")


def verify_config() -> tuple[bool, str]:
    cp = run_on_wazuh_vm(
        ["sudo", "-n", config.WAZUH_VERIFYCONF, *config.WAZUH_VERIFYCONF_ARGS],
        timeout=30,
    )
    out = (cp.stdout + cp.stderr).decode("utf-8", errors="replace")
    return cp.returncode == 0, out


def restart_manager() -> tuple[bool, str]:
    cp = run_on_wazuh_vm(
        ["sudo", "-n", "/usr/bin/systemctl", "restart", "wazuh-manager"],
        timeout=60,
    )
    out = (cp.stdout + cp.stderr).decode("utf-8", errors="replace")
    return cp.returncode == 0, out


# ---------- suppression xml ----------------------------------------------

_NEXT_LOCAL_RID_MIN = 100000


def next_local_rule_id(existing_xml: str) -> str:
    rids = [int(m) for m in re.findall(r'rule id="(\d+)"', existing_xml)]
    candidates = [r for r in rids if 100000 <= r < 200000]
    return str(max(candidates) + 1) if candidates else str(_NEXT_LOCAL_RID_MIN)


def build_suppression(parent_rule_id: str, agent_name: str | None,
                      description: str, new_rule_id: str) -> str:
    """Return an XML snippet that suppresses parent_rule_id (optionally scoped to agent)."""
    # parent_rule_id and new_rule_id are interpolated into the XML unescaped, so
    # they MUST be plain integers (a Wazuh <if_sid>/rule id always is). This is
    # the hard guard against XML injection through a crafted rule_id; callers
    # should also validate up front for a friendlier error.
    if not str(parent_rule_id or "").isdigit():
        raise ValueError(f"parent_rule_id must be numeric, got {parent_rule_id!r}")
    if not str(new_rule_id or "").isdigit():
        raise ValueError(f"new_rule_id must be numeric, got {new_rule_id!r}")
    safe_desc = (description or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if agent_name:
        safe_agent = agent_name.replace('"', "&quot;")
        return (
            f'  <rule id="{new_rule_id}" level="0">\n'
            f'    <if_sid>{parent_rule_id}</if_sid>\n'
            f'    <field name="agent.name">{safe_agent}</field>\n'
            f'    <description>FP suppression ({safe_desc})</description>\n'
            f'  </rule>\n'
        )
    return (
        f'  <rule id="{new_rule_id}" level="0">\n'
        f'    <if_sid>{parent_rule_id}</if_sid>\n'
        f'    <description>FP suppression ({safe_desc})</description>\n'
        f'  </rule>\n'
    )


def insert_into_group(existing_xml: str, snippet: str) -> str:
    """Append a rule snippet inside the last <group>, separated from its
    neighbours by exactly one blank line.

    Whitespace-normalising: the snippet "owns" one leading blank-line
    separator, which is precisely what remove_rule_from_xml() strips back out.
    That makes an insert followed by a remove of the same rule a byte-exact
    inverse, so add/delete cycles in the FP manager don't drift the file."""
    rule = snippet.strip("\n")
    if "<group" not in existing_xml:
        return f'<group name="local,fp,">\n\n{rule}\n\n</group>\n'

    idx = existing_xml.rfind("</group>")
    if idx == -1:                       # malformed: <group> with no close
        return f"{existing_xml.rstrip()}\n\n{rule}\n"
    head = existing_xml[:idx].rstrip()  # content before </group>, trailing ws dropped
    tail = existing_xml[idx:]           # "</group>" + anything after it
    return f"{head}\n\n{rule}\n\n{tail}"


def remove_rule_from_xml(existing_xml: str, rule_id: str) -> str:
    """Remove `<rule id="rule_id" ...>...</rule>` and the single blank-line
    separator preceding it — the exact inverse of insert_into_group(), so an
    add/remove round-trip restores the file byte-for-byte. The trailing
    separator is left intact (it belongs to the next element / the group close)."""
    pattern = re.compile(
        r"\n*[ \t]*<rule\s+id=\"" + re.escape(rule_id) + r"\".*?</rule>",
        re.DOTALL,
    )
    return pattern.sub("", existing_xml)


def parse_existing_suppressions(xml_text: str) -> list[dict[str, Any]]:
    """Parse rules with level=0 and an if_sid — those are our suppression style."""
    out: list[dict[str, Any]] = []
    try:
        # Wrap in synthetic root so multiple top-level <group>s parse cleanly.
        # defusedxml rejects entity-expansion / external-entity payloads.
        root = DET.fromstring(f"<root>{xml_text}</root>")
    except Exception as e:  # noqa: BLE001 - ParseError or any defuse rejection -> skip
        log.warning("local_rules.xml parse failed: %s", e)
        return out
    for rule in root.iter("rule"):
        level = rule.get("level")
        rid = rule.get("id")
        if level != "0" or not rid:
            continue
        if_sid = rule.findtext("if_sid")
        if not if_sid:
            continue
        agent = None
        for field in rule.findall("field"):
            if field.get("name") == "agent.name":
                agent = field.text
                break
        desc = rule.findtext("description") or ""
        out.append({
            "wazuh_rule_id": rid,
            "rule_id": if_sid.strip(),
            "agent_name": agent,
            "description": desc,
        })
    return out
