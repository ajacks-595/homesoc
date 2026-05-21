# HomeSOC — Project Overview

> **Forks: the IPs / hostnames / paths in this document describe the original
> deployment (a home network called "Jacknet"). They are examples — substitute
> your own values. All connection details are configurable via the dashboard's
> Settings → Hosts panel at runtime, no code edits required.**

A Flask-based home-network SOC dashboard. Original deployment: built on
**claude-dev** (10.0.0.155 in the original network), deployed to **wazuh-vm**
(10.0.0.213). Live at http://10.0.0.213:8080 in that deployment — auth
required after first-run setup.

This document is the single source of truth for the project. Read it in full
before making non-trivial changes.

## What it does

A single pane of glass over a self-hosted Wazuh + AdGuard Home + custom-pipeline
SIEM stack. Built for a senior security analyst running their own home SOC.

- Aggregates Wazuh alerts (live + archived) and presents them with filtering,
  resolution states, AI-explanation, and follow-up chat
- Surfaces daily/weekly markdown briefings produced by a separate analysis
  pipeline, with calendar view and full-text search
- Tracks recommended-action items parsed from briefings as a kanban
  (Open / In Progress / Resolved-TP / Resolved-FP / Acknowledged)
- OSINT investigation panel (VirusTotal / AbuseIPDB / URLScan) with caching
- False-positive suppression manager that writes Wazuh `local_rules.xml`
  over SSH, validates with `wazuh-analysisd -t`, and restarts the manager
- DNS deep-dive (top domains, per-client breakdown, hourly timeline) from
  AdGuard Home query log
- UniFi firewall events extracted from Wazuh alerts
- Host inventory bootstrapped from a network context.md, with live agent
  status from `agent_control -l`
- Per-user authentication (PBKDF2-SHA256), session cookies, audit log
- Webhook notifications (Mattermost / Slack / Discord / generic) with
  severity thresholds and 4h dedup
- Auto AI-explanations for new Level-10+ alerts, cross-correlated with
  other Wazuh events and DNS activity, capped at 20/24h
- Backups: config-only or full SQLite snapshots, browser download or
  SCP-push to NAS

## Architecture

### Hosts and roles

| Host | IP | Role | Auth into it |
|---|---|---|---|
| **claude-dev** | 10.0.0.155 | dev VM. Hosts `/opt/siem/{briefings,scripts,context.md,logs/staging}`. SIEM pipeline runs here (cron). Where new dashboard code is written. | local user `dev`, plus reverse-SSH from wazuh-vm |
| **wazuh-vm** | 10.0.0.213 | Wazuh manager v4.14.5. Runs the deployed dashboard as user `wazuh`. SQLite DB at `/opt/dashboard/data/dashboard.db`. | SSH `wazuh@` via `/home/dev/.ssh/collector_key` from claude-dev; full sudo (interactive password) + NOPASSWD list — see Sudoers section |
| **runtipi** | 10.0.0.188 | AdGuard Home host. Querylog at `/home/runtipi/runtipi/app-data/migrated/adguard/data/work/data/querylog.json` (~2.7M lines). | SSH `runtipi@` via collector_key; NOPASSWD `cat` of that querylog only |

### SSH topology

```
                 collector_key (dev's key)
  claude-dev ─────────────────────────────► wazuh-vm   (as wazuh)
       ▲                                       │
       │   /opt/dashboard/.ssh/id_ed25519      │
       │   (generated during deploy)           │
       └───────────────────────────────────────┘
                                               │
                                               │   same key
                                               ▼
                                            runtipi     (as runtipi)
```

wazuh-vm's `/opt/dashboard/.ssh/id_ed25519.pub` is registered in:
- `dev@claude-dev:~/.ssh/authorized_keys` — for pipeline triggers + briefing rsync
- `runtipi@10.0.0.188:~/.ssh/authorized_keys` — for AdGuard querylog read

### Environment detection

`config.py` switches behaviour off `socket.gethostname()`:
- `hostname == "wazuh"` → IS_PROD, paths point to `/opt/dashboard/data/siem`,
  SSH key is `/opt/dashboard/.ssh/id_ed25519`
- Anything else → IS_DEV, paths point to `/opt/siem`, SSH key is
  `/home/dev/.ssh/collector_key`, "SSH to claude-dev" becomes local exec,
  "SSH to wazuh-vm" goes via the network

This means **the same code runs in both places**. Develop locally on
claude-dev with full data access (no SSH needed), deploy to wazuh-vm and
it transparently switches.

### Data flow

- **Briefings, context.md**: `/opt/siem/` on claude-dev → rsync to
  `/opt/dashboard/data/siem/` on wazuh-vm. `deploy.sh` does the initial
  seed; subsequent runs use `sync.pull_data_from_claudedev()`
- **Wazuh alerts**: read locally via `sudo cat /var/ossec/logs/alerts/alerts.json`
  on wazuh-vm. Tail-bounded to last 8 MB per poll.
- **AdGuard querylog**: SSH to runtipi, `sudo cat` the (huge) JSON-per-line
  file, tail to last 60 MB, parse and aggregate. Cached in `dns_daily_stats`.
- **SIEM pipeline scripts** (collect/analyse/weekly): triggered via reverse-SSH
  wazuh-vm → claude-dev as `dev` user (NOT root — see Gotchas)
- **Webhook deliveries**: outbound HTTPS POST from wazuh-vm directly to
  the platform endpoint (no Cloudflare intermediary)

## Tech stack

- Python 3.10+ / Flask 3
- SQLite in WAL mode for concurrency
- Vanilla JavaScript single namespace (`SOC`) — no framework. ~2,500 LOC
- Chart.js v4 vendored locally at `static/js/chart.min.js`
- `cryptography` (Fernet) for credential storage
- `markdown` (python-markdown) for briefing + AI explanation rendering
- `requests` for OSINT providers and webhook delivery
- **Claude CLI** (`/home/dev/.npm-global/bin/claude`) for AI features —
  invoked on claude-dev via reverse-SSH from wazuh-vm. Uses Sonnet 4.6
  (fast, cheap) with `--allowedTools "WebSearch WebFetch"` for current
  threat-intel research

## Codebase layout

```
/home/dev/projects/soc-dashboard/
├── app.py                  # Flask app + ~60 routes; auth middleware + blueprints
├── auth.py                 # PBKDF2 hashing, session middleware, login/setup blueprint, audit()
├── database.py             # SQLite schema, CRUD helpers, idempotent migrations
├── config.py               # Paths, env detection, Fernet key derivation
├── parsers.py              # Briefing markdown, Wazuh JSON, AdGuard querylog, IOC detection
├── wazuh.py                # SSH wrappers, agent_control parser, local_rules.xml mgmt
├── sync.py                 # Briefings, alerts, DNS, agent pollers, dispatch_new_alerts
├── osint.py                # VT / AbuseIPDB / URLScan + 7d cache
├── ai.py                   # explain(), chat(), cross-log enrichment, Sonnet via CLI
├── notifications.py        # Mattermost/Slack/Discord/Generic formatters + dedup
├── backup.py               # SQLite online-backup, config-only filter, SCP push
├── requirements.txt
├── deploy.sh               # From-claude-dev rsync + venv + systemd install
├── soc-dashboard.service   # Main service unit
├── systemd/                # Timer units for the 3 pollers
├── sudoers.d/              # Canonical sudoers files (install on target hosts)
├── templates/              # 11 Jinja templates (login, setup, base, dashboard,
│                           #  briefings, alerts, osint, fp_manager, actions,
│                           #  hosts, threat_intel, settings)
├── static/
│   ├── css/themes.css      # 4 themes as CSS custom properties
│   ├── css/main.css        # ~600 LOC layout + components
│   └── js/main.js          # ~2k LOC SOC namespace
│   └── js/chart.min.js     # Vendored Chart.js v4
├── data/                   # SQLite DB lives here in dev (gitignored)
├── CLAUDE.md               # This file
├── README.md               # User-facing feature list + fork guide
├── ROADMAP.md              # TODOs + GitHub-readiness checklist
└── .gitignore
```

## Database schema (~20 tables)

Idempotent CREATE TABLE IF NOT EXISTS at startup + a small `_MIGRATIONS`
list in `database.py` for ALTER TABLE column adds.

**Core data:**
- `alerts` — Wazuh alerts with status (`open` / `in_progress` /
  `tp_remediated` / `false_positive` / `acknowledged`), ack_notes,
  acked_at
- `briefings` — daily + weekly markdown briefings with assessment
- `recommended_actions` — parsed P1/P2/P3 items, kanban-tracked
- `false_positives` — Wazuh rule suppressions written to local_rules.xml
- `hosts` — network inventory + live Wazuh agent status
- `osint_results` — VT/AbuseIPDB/URLScan cache (7d TTL)
- `dns_daily_stats` — AdGuard aggregations per day
- `pipeline_runs` — collect/analyse script execution log

**AI:**
- `alert_explanations` — cached per-alert AI explanations
- `alert_chat` — multi-turn follow-up conversations
- `ai_runs` — per-invocation accounting for rate limit + usage meter

**Notifications:**
- `webhooks` — configured destinations (URL Fernet-encrypted)
- `notification_log` — delivery history + dedup window source-of-truth

**Auth / audit:**
- `users` — PBKDF2-SHA256 hashed passwords
- `audit_log` — denormalised user + action + target tuples
- `settings` — kv store (Flask secret key, NAS backup config, etc.)
- `api_keys` — encrypted OSINT keys

**Backup:**
- `backup_history` — snapshot log

## Sudoers (CRITICAL — must be installed)

### On wazuh-vm — `/etc/sudoers.d/soc-dashboard-wazuh`
```
wazuh ALL=(ALL) NOPASSWD: /usr/bin/tail -f /var/ossec/logs/alerts/alerts.json
wazuh ALL=(ALL) NOPASSWD: /usr/bin/cat  /var/ossec/logs/alerts/alerts.json
wazuh ALL=(ALL) NOPASSWD: /usr/bin/cat  /var/ossec/etc/rules/local_rules.xml
wazuh ALL=(ALL) NOPASSWD: /usr/bin/tee  /var/ossec/etc/rules/local_rules.xml
wazuh ALL=(ALL) NOPASSWD: /var/ossec/bin/wazuh-analysisd -t        # NOT wazuh-verifyconf
wazuh ALL=(ALL) NOPASSWD: /var/ossec/bin/agent_control -l
wazuh ALL=(ALL) NOPASSWD: /var/ossec/bin/wazuh-control info
wazuh ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart wazuh-manager
wazuh ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart soc-dashboard.service
```

### On claude-dev — `/etc/sudoers.d/soc-dashboard-claudedev`
```
dev ALL=(dev) NOPASSWD: /opt/siem/scripts/collect.sh
dev ALL=(dev) NOPASSWD: /opt/siem/scripts/analyse.sh
dev ALL=(dev) NOPASSWD: /opt/siem/scripts/weekly.sh
```

**Note the `(dev)` target** — these run AS dev, not root (so the Claude
CLI has access to dev's OAuth tokens).

## Conventions

- **JSON API shape**: every `/api/*` endpoint returns
  `{success: bool, data: ..., error: str|null}`. Use `ok(data)` and
  `err(msg, code)` helpers in app.py.
- **DB connections**: always via the `db.conn()` context manager. WAL
  mode + autocommit (`isolation_level=None`) — never leave open.
- **Per-machine crypto**: API keys, webhook URLs, NAS backup config are
  all Fernet-encrypted with a key derived from `/etc/machine-id` + a
  fixed salt via PBKDF2. They will not decrypt on a different host —
  re-enter after a VM rebuild.
- **No CDN dependencies**: Chart.js is vendored. Themes are local. No
  external font loads. Browser hits only the dashboard's own origin
  (and webhook targets for outbound).
- **Status semantics**: `open` alerts are on the queue. Everything else
  (`in_progress`, `tp_remediated`, `false_positive`, `acknowledged`) is
  off the queue and hidden from the overview's critical banner.
- **Pollers**: live inside the Flask process by default. Set
  `SOC_POLLERS=systemd` in the service unit (already done) to delegate
  to systemd timers — see Phase 5 below.
- **Auth**: every endpoint except `/login`, `/setup`, and `/static/*`
  requires a session cookie. API endpoints return 401 JSON on missing
  auth (no redirect). First-run with empty `users` table forces /setup.

## Recent additions (Phases 1–5, this build)

### Phase 1: Webhooks + notifications
- Settings page has a Notifications card — add/edit/delete/test webhooks
  for Mattermost, Slack, Discord, or any HTTPS JSON sink
- Each webhook has: name, platform, URL (encrypted), severity threshold,
  AI-include flag, enabled toggle, dedup window (minutes)
- `(rule_id, agent_name)` dedup over the configured window prevents
  scanner-burst spam
- Test button sends a synthetic alert through the formatter

### Phase 2: AI auto-explain + cross-log enrichment
- New Level-10+ alerts from the poller trigger `ai.explain_with_enrichment()`
  BEFORE webhook dispatch, so the notification payload includes the
  AI summary
- 20-per-24h cap via the `ai_runs` table (configurable via
  `SOC_AI_DAILY_CAP` env var)
- Cross-log enrichment walks the alert JSON for IPs/domains/hashes and
  embeds related observations from the last 24h: other Wazuh alerts
  referencing the same IOCs + AdGuard DNS activity
- AI usage meter on /settings shows auto / manual / chat counts vs cap

### Phase 3: Backup
- `backup.py` uses SQLite's `connection.backup()` for snapshot-safe copies
- Browser download via `/api/backup/download/{config|full|data}`
- Config-only backup excludes alerts/briefings/OSINT/AI/audit (keeps
  api_keys, hosts, false_positives, webhooks, users, recommended_actions,
  settings)
- NAS push via SCP to a configurable Synology target, key + path
  configured via GUI in settings
- `backup_history` table records every snapshot

### Phase 4: Auth + audit
- First-run setup at `/setup` creates the initial admin
- Login at `/login` with same-origin `next=` parameter
- PBKDF2-SHA256, 200k iterations, base64-encoded scheme stored as
  `pbkdf2$iters$salt_b64$hash_b64`
- Flask session cookie (HttpOnly, SameSite=Lax, 30-day lifetime,
  `Secure` flag flipped on by `SOC_COOKIE_SECURE=1` env var)
- Audit log entries on every mutating endpoint, stamped with user_id,
  username (denormalised), action, target_type, target_id, details
  (JSON), ip_address
- User management UI on /settings: add, disable, reset password, delete
- `current_user()` helper available in any Flask route + templates

### Phase 5: Systemd timer migration
- `soc-dashboard-sync@.service` is a templated oneshot service that
  invokes `python app.py --run <kind>` for one of: alerts / dns /
  agents / bootstrap
- Three timer units schedule them (5min / 1h / 15min). All
  `Persistent=true` so missed fires (e.g. during reboot) catch up
- `SOC_POLLERS=systemd` in the main service env disables the
  in-process pollers to avoid double-firing
- Falls back to in-process pollers if `SOC_POLLERS=inprocess` (default)

## Gotchas (paid for in blood — do not relearn these)

1. **`rsync --delete` wipes `/opt/dashboard/.ssh/` during deploy** if not
   excluded. Excludes for `.ssh/` and `data/` are in deploy.sh. Leave them.

2. **`wazuh-verifyconf` doesn't exist on Wazuh 4.14**. Use
   `wazuh-analysisd -t` instead. `config.WAZUH_VERIFYCONF` already points
   to the right binary.

3. **AdGuard querylog is huge** (2.7M+ lines, months of history). Always
   `tail -c` to a bounded byte window. Never load the whole file.

4. **`sudo` on remote SSH commands needs `ssh -t`** for the TTY, otherwise
   sudo refuses to prompt. `deploy.sh` uses `$SSH_T` for password-prompted
   steps and `$SSH` for the NOPASSWD ones.

5. **`/opt/siem/scripts/collect.sh` invokes outbound SSH as root** when
   triggered via sudoers (because sudoers target is `(dev)` for analyse
   but historical configs may differ — verify with `sudo -l`). Root's
   `/root/.ssh/known_hosts` needs the runtipi + wazuh-vm host keys, or
   set `StrictHostKeyChecking=accept-new` in `/root/.ssh/config`.

6. **Claude CLI in `-p` mode redirects errors to stdout when stdin is
   piped + stdout is redirected**. The "Prompt is too long" failure for
   analyse.sh was silent because the error went into the briefing file,
   not stderr.

7. **Claude CLI doesn't expose the 1M-context beta to OAuth users** —
   only API-key users can pass `--betas context-1m-2025-08-07`. Hence
   the filter_wazuh.py tightening to keep prompt under 200K.

8. **`filter_wazuh.py` HAD `2902` in ALWAYS_KEEP_RULES** which overrode
   any SUPPRESS_RULES entry. Removed during the tighten — keep an eye
   if you add more suppressions for kept-rules.

9. **AI auto-explain on bootstrap import is a footgun** — first-run
   import of 4000+ alerts would burn through the 20/24h cap immediately.
   `first_run_bootstrap()` calls `sync_recent_alerts(dispatch_notifications=False)`
   to suppress dispatch.

10. **Sudo NOPASSWD matches the EXACT command + args**. `/usr/bin/systemctl
    restart soc-dashboard.service` is NOT matched by `systemctl restart
    soc-dashboard` (missing `.service` + missing `/usr/bin/` prefix).

11. **VACUUM can't run inside an implicit transaction**. `backup.py`
    opens with `isolation_level=None` (autocommit) for that reason.

12. **rsync from claude-dev cd to project dir first** — otherwise the
    `-R` relative paths resolve to `/home/dev/static/js/main.js` etc.
    instead of `<project>/static/js/main.js`.

13. **NEVER use `rsync --delete-excluded`**. This flag is a destructive
    booby-trap: it DELETES files on the destination that match the
    `--exclude` patterns. Combined with `--exclude 'venv/'` `--exclude 'data/'`
    `--exclude '.ssh/'` it WIPES exactly the things you wanted to preserve.
    `deploy.sh` correctly uses `--delete` (which preserves excluded paths).
    Ad-hoc updates should use plain `rsync -az` without `--delete*` flags,
    or `--delete` if you genuinely want destination cleanup of removed files.

## Deployment

```bash
# From claude-dev, as user dev (not root):
cd /home/dev/projects/soc-dashboard
./deploy.sh
```

`deploy.sh` does:
1. SSH sanity check
2. Create `/opt/dashboard/` on wazuh-vm + chown to `wazuh`
3. Generate `/opt/dashboard/.ssh/id_ed25519` if missing, print pubkey
4. rsync source (excluding venv/data/.ssh)
5. rsync briefings + context.md initial seed
6. Create venv + pip install
7. Install systemd units (main service + 3 sync timers)
8. Restart service
9. Tail logs for 10s

You'll be prompted for the wazuh-vm sudo password for the dir-create,
systemd install, and restart steps. After deploy you need to:
- Add the printed pubkey to `dev@claude-dev:~/.ssh/authorized_keys`
- Same pubkey to `runtipi@10.0.0.188:~/.ssh/authorized_keys`
- Install `sudoers.d/soc-dashboard-claudedev` on claude-dev
- Visit http://10.0.0.213:8080/setup to create the first admin

## Recovery

### DB wipe + rebuild
```
sudo systemctl stop soc-dashboard
sudo rm -f /opt/dashboard/data/dashboard.db
sudo systemctl start soc-dashboard
# Visit /setup to recreate admin
```

### Service-side debug
```
ssh -i /home/dev/.ssh/collector_key wazuh@10.0.0.213
sudo journalctl -u soc-dashboard -n 100 --no-pager
sudo tail -100 /var/log/soc-dashboard.log
systemctl list-timers | grep soc-dashboard    # confirm timers scheduled
```

### Code update without full redeploy
```bash
# From claude-dev, after editing local files:
cd /home/dev/projects/soc-dashboard
rsync -az -R -e 'ssh -i /home/dev/.ssh/collector_key' \
  <changed-files...> wazuh@10.0.0.213:/opt/dashboard/

# Restart if Python changed (CSS/JS picked up on next page load):
ssh -i /home/dev/.ssh/collector_key wazuh@10.0.0.213 \
  'sudo -n /usr/bin/systemctl restart soc-dashboard.service'
```

## How to extend safely

- **Add a new DB column**: append a `(table, column, ddl)` tuple to
  `_MIGRATIONS` in database.py. It runs on every service start
  (idempotent — checks `PRAGMA table_info`).
- **Add a new API route**: blueprint pattern — `pages_bp` for HTML,
  `api_bp` for JSON. Always wrap responses in `ok()` / `err()`.
- **Add a mutating route**: call `auth.audit("action.name", "type", id,
  {details})` at the end so it lands in the audit log.
- **Add a new JS page handler**: add `initX()` to the SOC namespace,
  expose it in the return object at the bottom, call it from the
  template's `{% block scripts %}`.
- **Add a new notification platform**: add a `_format_for_<x>()` in
  notifications.py and register it in `_FORMATTERS`. The CRUD UI picks
  it up automatically from `SUPPORTED_PLATFORMS`.
- **Add a new theme**: add a `body.theme-X { --bg-primary: ...; ... }`
  block in themes.css. The picker reads from `config.THEMES` — also
  add the slug there.

## Open items / future work

These are tracked in `ROADMAP.md` in more detail, but the headline items:

- **HTTPS / TLS** — being researched separately. Plan: Caddy reverse
  proxy with Let's Encrypt DNS-01 via Cloudflare, AdGuard split-horizon
  DNS so the hostname doesn't appear in public DNS at all
- **Roles** — schema supports it; only the flat single-role mode is
  currently used. Per-user RBAC (read-only vs admin) would be one
  middleware addition + a few endpoint annotations
- **CSRF** — not protected. Acceptable on LAN-only single-user; matters
  once exposed via reverse proxy
- **Background sync on first run** — `first_run_bootstrap()` runs
  synchronously; could be async if the alerts file is enormous
- **WSGI in front of Flask** — currently runs Flask's dev server.
  `waitress` or `gunicorn` would be more correct for "production"

## User profile / collaboration notes

- User is a senior security analyst running this for their own home SIEM
- Network has 30+ IoT devices on the same LAN — auth was non-negotiable
- Prefers terse, signal-rich communication. No fluff
- Comfortable with sudo/systemd/SSH plumbing — skip basic explanations
- Uses Mattermost for notifications (Cloudron-hosted at chat.jacknet595.com)
- Daily SIEM briefings (Opus 4.7) post to BookStack + Mattermost from
  cron at 06:00 on claude-dev — DO NOT touch that pipeline lightly,
  only the filter_wazuh.py tighten was explicitly authorised
- Plans to release on GitHub eventually — keep generic-fork notes in
  README.md current

## Quick reference

| Thing | Where |
|---|---|
| Dashboard URL | http://10.0.0.213:8080 |
| DB path (prod) | `/opt/dashboard/data/dashboard.db` |
| DB path (dev) | `/home/dev/projects/soc-dashboard/data/dashboard.db` |
| Logs | `/var/log/soc-dashboard.log` |
| Briefings (source) | `/opt/siem/briefings/*.md` on claude-dev |
| Wazuh alerts (source) | `/var/ossec/logs/alerts/alerts.json` on wazuh-vm |
| AdGuard querylog | `/home/runtipi/runtipi/app-data/migrated/adguard/data/work/data/querylog.json` |
| SSH key (claude-dev → wazuh-vm/runtipi) | `/home/dev/.ssh/collector_key` |
| SSH key (wazuh-vm → claude-dev/runtipi) | `/opt/dashboard/.ssh/id_ed25519` |
| Project dir | `/home/dev/projects/soc-dashboard/` |
