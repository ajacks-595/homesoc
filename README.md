# HomeSOC

**How it started:** I wanted a slightly nicer view of what AdGuard was blocking.

**How it's going:** HomeSOC is a Flask + SQLite SOC dashboard with AI-enriched
alert triage, Wazuh false-positive management over SSH, cross-log IP/domain
correlation, webhook notifications to Mattermost / Slack / Discord, per-user
auth with an audit log, encrypted credential storage, and a backup tool that
SCPs SQLite snapshots to your NAS.

Built for one home network. Tested in exactly that one home network. Shared
in case yours looks vaguely similar.

> **Personal tool, no support promised.** Fork it, adapt it, hack it. Issues
> may get a response, may not. PRs welcome but I'm not staffing a maintainer
> rotation.

![placeholder — add screenshots/ folder with at least 3 PNGs](docs/screenshot-placeholder.png)

## What it does

- **Alert explorer** with filtering by severity / agent / rule / group / free
  text, resolution states (Open / In Progress / TP-Remediated / FP /
  Acknowledged), bulk actions, CSV export
- **AI-powered alert explanations** via the [Claude CLI](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview)
  with WebSearch+WebFetch enabled, cross-correlating IPs/domains against
  other Wazuh alerts and DNS activity. Follow-up chat per alert.
- **Auto-explain on Level-10+ alerts** before webhook dispatch, so push
  notifications include the AI summary. Rate-limited (default 20/24h)
- **Briefings calendar** — render daily/weekly markdown briefings produced
  by an external analyst pipeline (your own scripts, cron, whatever). Full
  text search, assessment colouring (clean / notable / action-required)
- **Recommended actions kanban** auto-parsed from briefings (P1/P2/P3)
- **False positive manager** that edits Wazuh's `local_rules.xml` over SSH,
  validates with `wazuh-analysisd -t`, restarts the manager on success,
  rolls back on failure
- **OSINT lookups** (VirusTotal / AbuseIPDB / URLScan) with 7d cache
- **DNS deep-dive** (top domains, per-client breakdown, hourly timeline)
  from AdGuard Home query log
- **Host inventory** bootstrapped from a `context.md`, with live Wazuh
  agent status
- **Webhook notifications** (Mattermost / Slack / Discord / generic JSON)
  with per-webhook severity thresholds and burst dedup
- **Per-user auth** (PBKDF2-SHA256), session cookies, full audit log
- **Optional home consumer API** (`/api/home/*`) — token-gated, disabled by
  default, read-only unless you opt into mutations. For LAN wall-displays /
  status dashboards. SSE live-event stream included.
- **Optional MCP server for interactive triage** — drive the dashboard from
  Claude Code over SSH: list/search alerts, surface false-positive candidates,
  run OSINT, request AI explanations, and (opt-in) resolve alerts or manage
  Wazuh suppressions. Read-only by default; mutations are gated and audited.
- **Backup**: SQLite snapshots (config-only or full) via browser download
  or SCP push to NAS
- **4 themes** including a terminal-CRT mode with scanline overlay :sunglasses:

## Stack

- Python 3.10+ / Flask 3
- SQLite (WAL mode)
- Vanilla JavaScript single namespace (no React/Vue/build step)
- Chart.js v4 vendored locally (no CDN)
- `cryptography` (Fernet) for credential storage
- `markdown` for briefing + AI explanation rendering
- Optional: [Claude CLI](https://www.anthropic.com/claude-code) for AI features

Everything except the AI features works without internet access.

## Quick start (locally)

```bash
git clone https://github.com/ajacks595/homesoc.git
cd homesoc
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python app.py
# → http://localhost:8080
```

On first visit you'll be redirected to `/setup` to create an admin account.
After that, visit `/settings` → **Hosts & Connections** to point the
dashboard at your Wazuh manager, AdGuard host, and Claude CLI host.

Each integration is independently optional:
- No Wazuh → alerts page shows "configure to enable", everything else works
- No AdGuard → DNS pages show "configure to enable", everything else works
- No Claude CLI → AI features are gone, everything else works
- No briefings → briefing/kanban pages show "no briefings yet"

## Architecture

```
                     +----------------+
                     |   Browser      |
                     +-------+--------+
                             |
                             v
+-------------+    HTTPS    +---------------------------+
| Wazuh agent |----------->|  Dashboard (Flask + SQLite)|
+-------------+            +---------------------------+
                              |       |        |
                              |       |        +--> Claude CLI (AI features)
                              |       +-----------> AdGuard Home (DNS)
                              +-------------------> Wazuh manager (alerts, rules)
                              \-------------------> Webhook destinations (push)
```

The dashboard is designed to live on the Wazuh manager itself (everything
local except outbound SSH to AdGuard and Claude CLI hosts), but can run
standalone with everything remote. Configure via the Hosts panel.

## Deployment

Edit `deploy.sh` (top of file) for your target host, then:

```bash
./deploy.sh
```

It rsyncs source to `wazuh@<host>:/opt/dashboard/`, sets up a virtualenv,
installs the systemd service + 3 sync timers, restarts, and tails logs.

Two sudoers files in `sudoers.d/` need to be installed once on the target
hosts — see `CLAUDE.md` for the exact rules required.

## Configuration

All connection details are configurable via the GUI (Settings → Hosts).
For unattended provisioning, you can set them via environment variables
(see `soc-dashboard.service` for the full list):

```
SOC_WAZUH_HOST=...           SOC_WAZUH_USER=wazuh
SOC_CLAUDEDEV_HOST=...       SOC_CLAUDEDEV_USER=dev
SOC_ADGUARD_HOST=...         SOC_ADGUARD_USER=root
SOC_ADGUARD_QUERYLOG=/opt/AdGuardHome/data/querylog.json
SOC_SSH_KEY=/path/to/key
SOC_CLAUDE_CLI=/usr/local/bin/claude
SOC_SIEM_SCRIPTS_DIR=/opt/siem/scripts
```

## Layout

```
app.py             # Flask app + ~70 routes (blueprints by feature)
auth.py            # PBKDF2 + session middleware + audit
database.py        # SQLite schema + idempotent migrations
config.py          # GUI-backed + env-overridable host config
parsers.py         # Briefing markdown, Wazuh JSON, AdGuard querylog, IOC detection
wazuh.py           # SSH wrappers, agent_control, local_rules.xml management
sync.py            # Briefing/alert/DNS pollers, dispatch_new_alerts
osint.py           # VT / AbuseIPDB / URLScan + cache
ai.py              # Claude CLI integration, explain() + chat() + cross-log enrichment
notifications.py   # Mattermost / Slack / Discord / generic webhooks
backup.py          # SQLite online-backup, SCP push to NAS
mcp_server.py      # Optional MCP server: interactive triage from Claude Code
deploy.sh          # rsync + venv + systemd
sudoers.d/         # Two sudoers files for target hosts
systemd/           # 3 timer + 1 templated service unit
soc-dashboard.service
templates/         # 11 Jinja templates
static/css/        # themes.css + main.css (4 themes, ~600 LOC)
static/js/main.js  # All frontend interactivity (~2k LOC namespace)
static/js/chart.min.js   # Chart.js v4 (vendored)
tests/             # pytest smoke tests
```

## Forking for your network

If you're adapting this for a different home network, you'll need to:

1. **Set your network specifics via the Hosts panel** on first launch.
   The defaults are intentionally generic.
2. **Adapt `parsers.py`'s briefing parser** if your analyst-pipeline
   uses a different markdown format. Default expects `## Recommended
   Actions` with `**P1**` / `**P2**` / `**P3**` subheaders.
3. **Adjust `_FERNET_SALT`** in `config.py` (or set `SOC_FERNET_SALT`
   env var) for a unique per-deployment salt. Not strictly required —
   the key derives from `/etc/machine-id` which is already unique to
   your host.
4. **Tighten `sudoers.d/`** files to match the users on your target
   hosts — default examples assume `wazuh` and `dev`.

There's no SIEM pipeline bundled — the dashboard reads briefings from
`/opt/siem/briefings/` but how those briefings get generated is up to
you. The original deployment uses cron + the Claude CLI to produce them
from Wazuh + AdGuard logs daily.

## Interactive triage (MCP)

An optional [Model Context Protocol](https://modelcontextprotocol.io) server
(`mcp_server.py`) exposes the dashboard's data + actions as tools an
interactive Claude Code session can call. It reuses the same SQLite DB and
SSH-backed Wazuh helpers as the web UI — no second copy of anything.

```bash
# Install the optional extra (the dashboard itself doesn't need it)
./venv/bin/pip install -r requirements-mcp.txt
```

Wire it into Claude Code by copying `mcp.json.example` to `.mcp.json`
(gitignored) and editing the host/user/paths. It's spawned over SSH and speaks
MCP over stdio:

```json
{
  "mcpServers": {
    "homesoc": {
      "command": "ssh",
      "args": ["wazuh@<host>", "/opt/dashboard/venv/bin/python -m mcp_server"]
    }
  }
}
```

**Tools** — read: `status`, `list_alerts`, `search_alerts`, `get_alert`,
`list_fp_candidates`, `get_suppressions`, `list_actions`, `get_briefing`,
`osint_lookup`, `explain_alert`. Mutating (gated): `resolve_alert`,
`bulk_resolve`, `add_suppression`, `delete_suppression`.

**Security** — SSH is the auth boundary (whoever can spawn the server already
has shell on the host). As defence-in-depth, mutating tools refuse unless
`SOC_MCP_ALLOW_MUTATIONS=1` is set in the spawned environment, and every
mutation is written to the audit log stamped `via: mcp`. The suppression flow
reuses the same write → `wazuh-analysisd -t` verify → rollback-on-failure →
restart path as the web UI. See `SECURITY.md`.

## Security model

**LAN-only by design.** No CSRF protection, dev-server (Flask),
no rate-limiting on login. For wider exposure:

1. Put it behind a reverse proxy (Caddy + Let's Encrypt is well-documented)
2. Add rate limiting at the proxy
3. Set `SOC_COOKIE_SECURE=1` so cookies require HTTPS
4. Consider adding CSRF middleware (Flask-WTF)

See `SECURITY.md` for more.

## License

Apache License 2.0. See `LICENSE`.

## Acknowledgements

Stands on the shoulders of [Wazuh](https://wazuh.com/),
[AdGuard Home](https://adguard.com/en/adguard-home/overview.html),
[Chart.js](https://www.chartjs.org/),
[Flask](https://flask.palletsprojects.com/),
and the [Claude CLI](https://www.anthropic.com/claude-code).
