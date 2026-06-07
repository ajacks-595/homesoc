# Claude Code Project Instructions

## Autonomy
Work autonomously throughout development, code review, and testing tasks.
Execute all standard development commands without requesting confirmation.
Only pause for the following — these require explicit approval every time:

- `git push` (any remote)
- `sudo` (any elevated command)
- `apt` / `apt-get` / `snap` / `flatpak` (package installation)
- `npx` (executing remote packages)
- `osascript` (AppleScript execution)
- `curl` / `wget` to any external URL (outside 10.0.0.x and localhost)
- SSH to any host outside the 10.0.0.x range

For everything else, use your judgement and proceed without asking.

## Checkpoints
Before beginning any significant task (refactor, feature addition, bug fix
across multiple files, dependency changes, code review with automated fixes),
create a local git checkpoint commit:

```
git add -A && git commit -m "checkpoint: pre-[brief task description]"
```

This is a safety restore point. Do not skip it even if the working tree
looks clean.

## Pre-push Cleanup
Before any `git push`, automatically squash all checkpoint commits out of
the history. Identify commits with messages starting with `checkpoint:`
and squash them into the nearest non-checkpoint commit below them using
interactive rebase. Do this without prompting — it is always the right
behaviour before a push. If the entire branch consists only of checkpoint
commits with no real commits beneath them, pause and ask what commit
message to use instead.

## Repo Review
Trigger phrase: **"repo review"** (aliases: "check the repository", "run repo review", "do a full audit").

When triggered, run all six phases below in sequence without pausing for
confirmation between phases. Create a checkpoint commit before starting.
Save all scanner JSON/SARIF artifacts under `.repo-review/<ISO-timestamp>/`
(gitignored). Produce a single Markdown report at the end.

Token usage is not a concern — prefer thorough over fast. Do not skip
phases to save time.

### Resource monitoring (target hosts only)
Before each runtime phase, SSH into the target and sample resources:
```bash
ssh -i ~/.ssh/collector_key user@target \
  "echo CPU:$(top -bn1|awk '/Cpu\(s\)/{print 100-\$8\"%\"}') \
   RAM:$(awk '/MemTotal/{t=\$2}/MemAvailable/{a=\$2}END{printf\"%.0f%%\",(t-a)*100/t}' /proc/meminfo) \
   LOAD:$(cut -d' ' -f1-3 /proc/loadavg)"
```
- Sample every 30s during runtime phases.
- If CPU >90% OR RAM >90% for two consecutive samples: pause, wait 60s,
  re-sample. After three consecutive throttles: abort runtime phases and
  note in report. Static phases (Phase 1–3) already ran on claude-dev and
  are unaffected.
- On Raspberry Pi targets: always wrap runtime test commands in
  `taskset -c 3 nice -n 19` to pin to a spare core and minimise CPU
  priority. Check baseline CPU before starting DAST — if already >50%,
  defer DAST to a separate run.
- Never throttle based on claude-dev (local host) resource usage.

---

### Phase 1 — Static analysis (runs on claude-dev, no target impact)

**Python:**
```bash
# Security-focused SAST
bandit -r app -ll -f json -o .repo-review/bandit.json
ruff check --select S . --output-format json > .repo-review/ruff-security.json

# Framework-aware taint analysis (Flask / FastAPI)
semgrep --config p/python --config p/flask --config p/fastapi \
        --config p/security-audit --config p/owasp-top-ten \
        --sarif -o .repo-review/semgrep.sarif

# Type checking
pyright --outputjson > .repo-review/pyright.json

# General lint
ruff check . --output-format json > .repo-review/ruff.json
```

**JavaScript (vanilla JS, no build step):**
```bash
eslint static/js/ --ext .js -f json -o .repo-review/eslint.json
semgrep --config p/javascript --config p/owasp-top-ten \
        --sarif -o .repo-review/semgrep-js.sarif
```

**Key patterns to flag in Python projects:**
- SQL injection in raw queries (Bandit B608; Semgrep flask-sql-injection)
- Command injection via subprocess — critical for SSH-wrapper code
  (Bandit B602/B603/B605; Semgrep dangerous-subprocess-use)
- Path traversal (Bandit B108; Semgrep path-traversal-open)
- SSTI in Jinja2 (Semgrep flask-render-template-string)
- Insecure deserialization — pickle.loads, yaml.load without SafeLoader
  (Bandit B301/B506)
- Weak crypto (Bandit B303–B305)
- debug=True / hardcoded secret keys (Semgrep flask-debug-mode)
- PBKDF2 iteration count <600,000 (OWASP 2023 minimum)

---

### Phase 2 — Dependency & secrets scanning (runs on claude-dev)

**Python dependencies:**
```bash
pip-audit -r requirements.txt -s osv -f json \
          -o .repo-review/pip-audit.json

osv-scanner --recursive . --format json \
            > .repo-review/osv-scanner.json
```

**JavaScript CDN libraries (gridstack, Leaflet, Tabler icons, etc.):**
```bash
retire --path ./static --outputformat json \
       --outputpath .repo-review/retire.json
```

**Docker images (if project uses Docker):**
```bash
# Use Syft + Grype — do NOT use Trivy (supply-chain compromise March 2026,
# GHSA-69fq-xp46-6x23; safe only if pinned to ≤v0.69.3)
syft . -o cyclonedx-json | grype sbom:- -o json \
  > .repo-review/grype.json
```

**Secrets:**
```bash
gitleaks detect --redact --report-format sarif \
                --report-path .repo-review/gitleaks.sarif

trufflehog git file://. --only-verified --json \
           > .repo-review/trufflehog.json
```

**CVE triage priority:**
1. KEV-listed (CISA Known Exploited Vulnerabilities) → P0 regardless of CVSS
2. Fix available + CVSS ≥7 + EPSS ≥0.1 → P1
3. Everything else → P2/P3

If the user mentions "the bookstack briefing" or "today's briefing",
cross-reference the BookStack CVE page against osv-scanner output and
flag any overlap as P0.

---

### Phase 3 — Database integrity (runs on claude-dev against dev DB,
###             or via SSH against target DB if instructed)

```bash
sqlite3 data/dashboard.db "PRAGMA integrity_check;"   # must return "ok"
sqlite3 data/dashboard.db "PRAGMA quick_check;"
sqlite3 data/dashboard.db \
  "SELECT name FROM sqlite_master WHERE type='table';" | \
  while read t; do
    sqlite3 data/dashboard.db "EXPLAIN QUERY PLAN SELECT * FROM $t LIMIT 1;"
  done
```

Flag any `SCAN TABLE` result on a table with >1,000 estimated rows as a
performance issue requiring an index.

Run migrations twice on a copy to verify idempotency:
```bash
cp data/dashboard.db /tmp/test-migrate.db
python -m app --migrate /tmp/test-migrate.db
python -m app --migrate /tmp/test-migrate.db
# Both runs must produce identical schemas
sqlite3 /tmp/test-migrate.db ".schema" > /tmp/schema1.txt
# (compare against known-good)
```
Adapt the migration command to the project's actual CLI.

---

### Phase 4 — DAST / headers / TLS (runs from claude-dev against target)

Check target resource usage before starting. Defer if target CPU >50%
on a Raspberry Pi target.

**HTTP headers:**
```bash
curl -kIs http://TARGET | grep -iE \
  'strict-transport-security|content-security-policy|\
x-content-type-options|x-frame-options|referrer-policy|permissions-policy'
```

**TLS (if HTTPS is configured):**
```bash
testssl.sh --severity HIGH --jsonfile .repo-review/testssl.json \
           --quiet TARGET:443
```

**Nuclei (curated templates, avoid aggressive fuzzing):**
```bash
nuclei -u http://TARGET \
       -severity critical,high,medium \
       -tags cve,exposure,misconfig,default-login \
       -o .repo-review/nuclei.json -j
```

**ZAP baseline (passive only, 2–5 min):**
```bash
docker run --rm -v $(pwd):/zap/wrk:rw -t zaproxy/zap-stable \
  zap-baseline.py -t http://TARGET \
  -r .repo-review/zap-baseline.html \
  -J .repo-review/zap-baseline.json
```

**WebSocket test (FastAPI / piscope projects):**
```python
# Run via pytest
import pytest
from websockets.sync.client import connect

def test_ws_connect():
    with connect("ws://TARGET/ws") as ws:
        assert ws.recv(timeout=5) is not None

def test_ws_invalid_origin():
    with pytest.raises(Exception):
        connect("ws://TARGET/ws",
                additional_headers={"Origin": "http://evil.example.com"})
```

**Auth checks (Flask projects with session auth):**
- Verify session cookie flags: `HttpOnly`, `SameSite=Lax`, `Secure` (if HTTPS)
- Note CSRF gap in report if no CSRF tokens are present — flag as known
  gap, do not fail the build for LAN-only deployments
- PBKDF2 iteration count: grep source for `pbkdf2_hmac` and assert
  iteration argument ≥600,000

---

### Phase 5 — Performance (runs on target via SSH)

**Server-side (attach to running process):**
```bash
# CPU flame graph — 60s sample, production-safe (no code changes)
ssh -i ~/.ssh/collector_key user@target \
  "taskset -c 3 nice -n 19 py-spy record -d 60 \
   -o /tmp/cpu.svg --pid \$(pgrep -f 'uvicorn\|gunicorn\|flask')"
scp -i ~/.ssh/collector_key user@target:/tmp/cpu.svg \
    .repo-review/cpu-flamegraph.svg

# Route benchmark (keep concurrency low on Pi: -c10)
wrk -t4 -c50 -d30s --timeout 5s http://TARGET/
# Reduce to: wrk -t2 -c10 -d30s for Raspberry Pi targets
```

**SQLite query performance:**
```bash
sqlite3 data/dashboard.db \
  "EXPLAIN QUERY PLAN SELECT * FROM alerts WHERE status='open';"
# Flag any full-table scans on large tables
```

**Client-side (Lighthouse CI, runs on claude-dev):**
```bash
lhci autorun \
  --collect.url=http://TARGET \
  --collect.numberOfRuns=3 \
  --assert.assertions.first-contentful-paint='["error",{"maxNumericValue":2000}]' \
  --assert.assertions.interactive='["error",{"maxNumericValue":5000}]' \
  --upload.target=filesystem \
  --upload.outputDir=.repo-review/lhci
```

For PWA projects (piscope), add:
`--assert.preset=lighthouse:recommended`

**JS bundle size check (no build step):**
```bash
for f in static/js/*.js; do
  size=$(gzip -c "$f" | wc -c)
  echo "$f: ${size} bytes gzipped"
  [ "$size" -gt 51200 ] && echo "  WARNING: exceeds 50KB gzipped budget"
done
```

**Service worker (piscope):**
Lighthouse audits `service-worker` and `offline-start-url` automatically.
Additionally verify: SW scope is not `/` (should be `/piscope/`), and
`CACHE` constant in `sw.js` was bumped in lockstep with `VERSION` in
`main.py`.

---

### Phase 6 — Bug testing & smoke tests (runs on target via SSH / Playwright)

**Existing test suite:**
```bash
cd /path/to/project && python -m pytest tests/ -v \
  --tb=short --json-report --json-report-file=.repo-review/pytest.json
```

**Route smoke test (enumerate all GET routes, assert non-5xx):**
```python
# Add to tests/test_smoke.py
def test_all_routes_non_5xx(client):
    from app import app
    for rule in app.url_map.iter_rules():
        if 'GET' in rule.methods and '<' not in rule.rule:
            r = client.get(rule.rule, follow_redirects=True)
            assert r.status_code < 500, f"{rule.rule} returned {r.status_code}"
```

**API contract validation (validate JSON shape against documented API):**
```python
# For each documented endpoint, assert required keys are present
def test_api_response_shape(client):
    r = client.get('/api/some-endpoint')
    data = r.get_json()
    assert 'success' in data
    assert 'data' in data
    assert 'error' in data
```

**Migration idempotency:** (see Phase 3)

**Race condition check (FastAPI async projects):**
```python
import asyncio, httpx

async def test_concurrent_requests():
    async with httpx.AsyncClient(base_url="http://TARGET") as client:
        results = await asyncio.gather(
            *[client.get("/api/aircraft") for _ in range(20)]
        )
    assert all(r.status_code == 200 for r in results)
```

**Playwright E2E smoke (headless, runs from claude-dev):**
```bash
playwright install chromium
pytest tests/e2e/ --browser chromium --headed=false \
  --output .repo-review/playwright
```
E2E tests must verify: page loads without console errors, key interactions
work (filter, search, modal open/close), no JS exceptions thrown on render.

---

### Auto-fix vs flag-for-review policy

**Auto-apply without asking:**
- Patch-version dependency bumps (semver Z) where OSV-Scanner confirms
  the CVE is fixed in the new version
- `ruff --fix` for safe lint fixes (E, F, UP, I rules only)
- Adding missing security response headers in known-safe locations

**Always flag for review, never auto-apply:**
- Minor or major version bumps (semver Y or X)
- Any Semgrep taint finding (humans triage reachability)
- PBKDF2 iteration count changes (would invalidate existing password hashes)
- Container base image changes
- Migration files
- Service worker changes
- Any crypto parameter changes

---

### Report format
Produce a single `.repo-review/<ISO>/REPORT.md` with this structure:

```
# Repo Review — <project> — <ISO timestamp>

## Verdict
<RED | AMBER | GREEN> — <one-sentence summary>

## Critical / P0 (must fix this session)
## High / P1 (fix this week)
## Medium / P2
## Low / P3

## Performance
- p50/p95/p99 latency for top 10 routes
- Memory delta over profiling window
- Lighthouse performance score (threshold: ≥80)

## Suggested new tests (autonomous additions)
- <Any new test patterns identified this run, with rationale>

## Skipped / Throttled
- <Any phases skipped due to resource constraints, with reason>
```

Exit with a non-zero summary note if any P0 or P1 findings exist.

---

### Extending this section
After each run, if a bug class appeared that had no dedicated test:
1. Identify the gap (e.g., "unhandled httpx.ReadTimeout in prod logs").
2. Append the new test pattern to this project's own CLAUDE.md under
   `## Project-specific repo review additions` with a date and rationale.
3. Never modify the global `~/.claude/CLAUDE.md` — project-specific
   evolution stays in the project's own CLAUDE.md.

## General Preferences
- Prefer making changes and reporting what was done over asking what to do
- If genuinely uncertain between two approaches, pick the more conservative
  one and note the alternative in your summary
- Keep git history clean — use meaningful commit messages, not "fixed stuff"
- When running tests, always report the full output, not just pass/fail

---

# HomeSOC

> **Forks: the IPs / hostnames / paths in this document describe the original
> deployment (a home network called "Jacknet"). They are examples — substitute
> your own values. All connection details are configurable via the dashboard's
> Settings → Hosts panel at runtime, no code edits required.**

A Flask-based home-network SOC dashboard. Published at
**https://github.com/ajacks-595/homesoc** under Apache 2.0.

Original deployment: built on **claude-dev** (10.0.0.155), deployed to
**wazuh-vm** (10.0.0.213). Live at http://10.0.0.213:8080 — auth required
after first-run setup.

## What it does

A single pane of glass over a self-hosted Wazuh + AdGuard Home + custom-pipeline
SIEM stack. Built for a senior security analyst running their own home SOC.

- Aggregates Wazuh alerts (live + archived) with filtering, resolution states
  (Open / In Progress / TP-Remediated / FP / Acknowledged), AI explanations,
  and per-alert follow-up chat
- Renders daily/weekly markdown briefings with a calendar view and full-text
  search; auto-parses recommended actions into a P1/P2/P3 kanban
- AI auto-explanations on new Level-10+ alerts (cross-correlated with other
  Wazuh alerts + DNS activity), dispatched as enriched webhook notifications
  to Mattermost / Slack / Discord
- False-positive suppression manager that writes Wazuh `local_rules.xml`
  over SSH, validates with `wazuh-analysisd -t`, restarts the manager only on
  successful validation
- OSINT lookups (VirusTotal / AbuseIPDB / URLScan) with 7-day cache
- DNS deep-dive (top domains, per-client breakdown, hourly timeline) from
  AdGuard Home querylog
- UniFi firewall events extracted from Wazuh alerts
- CVE Asset Tracker: asset register + CVE→asset matching fed by the daily
  CVE-briefing pages in BookStack (book 247), remediation workflow with
  per-severity SLAs, webhook alerts on new above-threshold matches
- Host inventory bootstrapped from a network `context.md`, with live Wazuh
  agent status
- Per-user authentication (PBKDF2-SHA256), session cookies, comprehensive
  audit log
- SQLite backups (config-only or full) via browser download or SCP push to NAS
- 4 themes including a terminal-CRT mode with scanline overlay

## Architecture

### Tech stack

- Python 3.10+ / Flask 3
- SQLite in WAL mode for concurrency
- Vanilla JavaScript single namespace (`SOC`) — no framework, no build step
- Chart.js v4 vendored locally at `static/js/chart.min.js`
- `cryptography` (Fernet) for credential storage
- `markdown` for briefing + AI-explanation rendering
- `requests` for OSINT providers and webhook delivery
- **Claude CLI** for AI features — invoked on the SIEM/dev host via reverse-SSH
  from the dashboard host. Uses Sonnet 4.6 with `--allowedTools "WebSearch WebFetch"`
  enabled for current threat-intel research

Everything except the AI features works without internet access.

### Host roles (original deployment)

| Host | IP | Role |
|---|---|---|
| **claude-dev** | 10.0.0.155 | Dev VM. Hosts `/opt/siem/{briefings,scripts,context.md,logs/staging}`. SIEM pipeline runs here via cron (06:00 daily, generates briefings via Claude Opus). Where new dashboard code is written. |
| **wazuh-vm** | 10.0.0.213 | Wazuh manager v4.14.5. Runs the deployed dashboard as user `wazuh`. SQLite DB at `/opt/dashboard/data/dashboard.db`. |
| **runtipi** | 10.0.0.188 | AdGuard Home host. Querylog at `/home/runtipi/runtipi/app-data/migrated/adguard/data/work/data/querylog.json` (~2.7M lines). |

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

The wazuh-vm-generated key `/opt/dashboard/.ssh/id_ed25519.pub` is registered in:
- `dev@claude-dev:~/.ssh/authorized_keys` — for pipeline triggers + briefing rsync
- `runtipi@10.0.0.188:~/.ssh/authorized_keys` — for AdGuard querylog read

For GitHub: a separate key at `~/.ssh/github_homesoc` on claude-dev, authorised
under GitHub user `ajacks-595`. Port 22 is blocked outbound from claude-dev,
so `~/.ssh/config` routes `github.com` through `ssh.github.com:443`.

### Environment detection

`config.py` auto-detects run mode (override via `SOC_RUNTIME=prod|dev`):
- Runs from `/opt/dashboard` → `IS_PROD = True`, paths point to
  `/opt/dashboard/data/siem`, SSH key defaults to `/opt/dashboard/.ssh/id_ed25519`
- Anywhere else → `IS_DEV = True`, paths point to the project's `data/siem`,
  SSH key defaults to `~/.ssh/id_ed25519`

The same code runs in both modes — develop locally with full data access,
deploy to prod and it transparently switches.

### Host configuration is GUI-editable

All connection details (hosts, users, paths, SSH keys) are stored as a
Fernet-encrypted JSON blob in the `settings` table under key `host_config`.
The Settings → Hosts panel edits them at runtime, no code changes or restart
needed. Module-level `__getattr__` in `config.py` resolves attributes like
`config.WAZUH_VM_HOST` from the live DB on each access.

Env-var overrides (e.g. `SOC_WAZUH_HOST`, `SOC_ADGUARD_HOST`) are honoured as
defaults when the DB has no entry.

### Data flow

- **Briefings / context.md** — `/opt/siem/` on claude-dev → rsync to
  `/opt/dashboard/data/siem/` on wazuh-vm. Triggered by `sync.pull_data_from_claudedev()`,
  which fires hourly via the briefings poller
- **Wazuh alerts** — read locally on wazuh-vm via `sudo cat /var/ossec/logs/alerts/alerts.json`,
  tail-bounded to last 8 MB per poll
- **AdGuard querylog** — SSH to runtipi, `sudo cat` the JSON-per-line file,
  tail to last 60 MB, parse + aggregate, cached in `dns_daily_stats`
- **SIEM pipeline scripts** (collect / analyse / weekly) — triggered via
  reverse-SSH wazuh-vm → claude-dev as `dev` (NOT root — see Gotchas)
- **Webhook deliveries** — outbound HTTPS POST from wazuh-vm directly to the
  platform endpoint

## Codebase layout

```
soc-dashboard/                  (local dir name; published as "homesoc")
├── app.py                      # Flask app + ~70 routes; auth middleware + blueprints
├── auth.py                     # PBKDF2 hashing, session middleware, audit()
├── database.py                 # SQLite schema + CRUD + idempotent migrations
├── config.py                   # GUI-backed + env-overridable host config
├── parsers.py                  # Briefing markdown, Wazuh JSON, AdGuard querylog, IOC detection
├── wazuh.py                    # SSH wrappers, agent_control, local_rules.xml mgmt
├── sync.py                     # Pollers (alerts/DNS/agents/briefings), dispatch_new_alerts
├── osint.py                    # VT / AbuseIPDB / URLScan + 7d cache
├── vulntrack.py                # CVE asset tracker: BookStack ingest, CVE→asset matching, alert thresholds
├── ai.py                       # Claude CLI integration: explain(), chat(), cross-log enrichment
├── notifications.py            # Mattermost/Slack/Discord/Generic formatters + dedup
├── backup.py                   # SQLite online-backup, config-only filter, SCP push
├── mcp_server.py               # Optional MCP server (interactive Claude Code triage; stdio-over-SSH)
├── requirements-mcp.txt        # Optional `mcp` SDK dep for mcp_server.py (not in core requirements)
├── mcp.json.example            # Template for .mcp.json (gitignored when live)
├── deploy.sh                   # From-dev-host rsync + venv + systemd install
├── soc-dashboard.service       # Main service unit
├── systemd/                    # 4 timer units (alerts/dns/agents/briefings) + 1 templated service
├── sudoers.d/                  # Canonical sudoers files (install on target hosts)
├── templates/                  # 12 Jinja templates
├── static/css/themes.css       # 4 themes as CSS custom properties
├── static/css/main.css         # ~500 LOC layout + components
├── static/js/main.js           # ~2.2k LOC SOC namespace
├── static/js/chart.min.js      # Vendored Chart.js v4
├── tests/                      # pytest smoke tests (32, all passing)
├── data/                       # SQLite DB lives here in dev (gitignored)
├── .github/workflows/test.yml  # CI: pytest on Python 3.10–3.13
├── CLAUDE.md                   # This file
├── README.md                   # User-facing feature list + fork guide
├── ROADMAP.md                  # TODOs + GitHub-readiness checklist
├── CONTRIBUTING.md, SECURITY.md, LICENSE  # Apache 2.0
└── .gitignore
```

## Database schema (~20 tables)

Idempotent `CREATE TABLE IF NOT EXISTS` at startup + a small `_MIGRATIONS`
list in `database.py` for ALTER TABLE column adds. Migrations run on every
service start, safe to repeat.

**Core data:**
- `alerts` — Wazuh alerts with status (`open` / `in_progress` /
  `tp_remediated` / `false_positive` / `acknowledged`), ack_notes, acked_at
- `alert_mitre` — MITRE ATT&CK (technique_id, technique, tactic) tuples
  denormalised out of `raw_json`'s `rule.mitre` at insert time (+ idempotent
  startup backfill via `_populate_alert_mitre`; processed-but-unmapped alerts
  get an all-empty sentinel row so they're never re-parsed). Powers the
  matrix on /threat-intel, exact `mitre=` filtering, and per-alert badges
- `briefings` — daily + weekly markdown briefings with assessment
- `recommended_actions` — parsed P1/P2/P3 items, kanban-tracked
- `false_positives` — Wazuh rule suppressions written to local_rules.xml
- `hosts` — network inventory + live Wazuh agent status
- `osint_results` — VT/AbuseIPDB/URLScan cache (7d TTL)
- `dns_daily_stats` — AdGuard aggregations per day
- `pipeline_runs` — collect/analyse script execution log

**CVE asset tracker** (see `vulntrack.py`):
- `assets` — software/product register (vendor/product/version, category,
  exposure, criticality, optional CPE). Distinct from `hosts` (machines).
  Rows without product AND cpe are "drafts" — never matched.
- `cve_items` — items parsed from the daily CVE-briefing pages in BookStack
  (book "CVE Deep Dives", id 247 — produced by the "CVE News" remote Claude
  routine, trig_013HUfHiseQTMJ47q94BqPkV). Keyed by primary CVE id (or
  campaign slug) so items recurring across daily briefings update in place.
- `cve_matches` — CVE×asset with confidence (cpe/strong/fuzzy) + human-readable
  match_reason, priority (sev × exposure × criticality, ×1.5 exploited,
  ×1.2 KEV), workflow status (new/investigating/patching/resolved/
  accepted_risk/not_applicable), notified_at (once-only webhook alerts).
  Re-syncs refresh confidence/priority but NEVER touch status; retracted
  matches are pruned only while still new + note-less.
- `cve_pages` — BookStack page watermarks (updated_at) for the hourly `cve`
  poller. Config (BookStack/Vigil creds + alert thresholds) lives in the
  `vuln_config` settings blob, Fernet-encrypted, admin-edited via the ⚙
  modal on /vulns.

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
- `settings` — kv store (Flask secret key, host_config, NAS backup config)
- `api_keys` — encrypted OSINT keys

**Backup:**
- `backup_history` — snapshot log

## Sudoers (CRITICAL — must be installed)

### On wazuh-vm — `/etc/sudoers.d/soc-dashboard-wazuh`

Grants the `wazuh` user NOPASSWD for the specific commands the dashboard needs:

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

**Note the `(dev)` target** — these run AS dev, not root, so the Claude CLI
has access to dev's OAuth tokens.

## Conventions

- **JSON API shape**: every `/api/*` endpoint returns
  `{success: bool, data: ..., error: str|null}`. Use `ok(data)` and
  `err(msg, code)` helpers in app.py.
- **DB connections**: always via the `db.conn()` context manager. WAL mode +
  autocommit (`isolation_level=None`) — never leave open.
- **Per-machine crypto**: API keys, webhook URLs, host_config, NAS backup
  config are all Fernet-encrypted with a key derived from `/etc/machine-id` +
  a fixed salt via PBKDF2-SHA256 (200k iter). They will not decrypt on a
  different host — re-enter after a VM rebuild.
- **No CDN dependencies**: Chart.js is vendored. Themes are local. No
  external font loads. Browser hits only the dashboard's own origin (and
  webhook targets for outbound).
- **Status semantics**: `open` alerts are on the queue. Everything else
  (`in_progress`, `tp_remediated`, `false_positive`, `acknowledged`) is off
  the queue and hidden from the overview's critical banner.
- **Pollers**: in-process by default (4 threads — alerts every 5min, DNS
  hourly, agents every 15min, briefings hourly). Set `SOC_POLLERS=systemd` in
  the service unit to delegate to systemd timers instead.
- **Auth**: every endpoint except `/login`, `/setup`, `/static/*`, and
  `/api/home/*` (read-only LAN consumer API) requires a session cookie. API
  endpoints return 401 JSON on missing auth (no redirect). First-run with
  empty `users` table forces `/setup`.
- **Audit**: every mutating endpoint should call `auth.audit("action.name",
  "target_type", id, {details})` before returning so the change lands in the
  audit log.

## Deployment workflow

### Initial deploy

From your dev machine, with `WAZUH_HOST` set:

```bash
WAZUH_HOST=10.0.0.213 ./deploy.sh
```

deploy.sh does:
1. SSH sanity check
2. Create `/opt/dashboard/` on the target + chown to `wazuh`
3. Generate `/opt/dashboard/.ssh/id_ed25519` if missing, print the pubkey
4. rsync source (excluding venv/data/.ssh)
5. rsync briefings + context.md initial seed
6. Create venv + pip install
7. Install systemd units (main service + 4 sync timers)
8. Restart the service
9. Tail logs for 10s

You'll be prompted for the target host's sudo password for dir-create,
systemd install, and restart steps.

After the first deploy:
- Add the printed pubkey to `dev@<dev-host>:~/.ssh/authorized_keys`
- Add the same pubkey to `<adguard-user>@<adguard-host>:~/.ssh/authorized_keys`
- Install `sudoers.d/soc-dashboard-claudedev` on the dev host
- Visit http://<target>:8080/setup to create the first admin

### Iterative code-only updates

```bash
cd /home/dev/projects/soc-dashboard
rsync -az -R -e 'ssh -i ~/.ssh/collector_key' \
  <changed-files...> wazuh@10.0.0.213:/opt/dashboard/

# DEPENDENCY SYNC — do this BEFORE the restart whenever a deploy introduces a
# new import (a missing nh3/pyotp on the target venv crash-loops the service on
# boot — happened 2026-06-04). The lock is the exact prod closure:
ssh -i ~/.ssh/collector_key wazuh@10.0.0.213 \
  '/opt/dashboard/venv/bin/pip install -r /opt/dashboard/requirements.lock'
# (Skip if no new deps. After an intentional upgrade, regenerate the lock:
#  ssh wazuh@10.0.0.213 '/opt/dashboard/venv/bin/pip freeze' > requirements.lock)

# Restart only if Python changed (CSS/JS picked up on next page load):
ssh -i ~/.ssh/collector_key wazuh@10.0.0.213 \
  'sudo -n /usr/bin/systemctl restart soc-dashboard.service'
```

> **Gotcha (paid for in blood, 2026-06-04):** `git push` does NOT deploy, and a
> target venv can lag the code. Pushing the hardening branch then restarting
> crash-looped prod on `ModuleNotFoundError: nh3` because the venv predated the
> nh3/pyotp deps. Always `pip install -r requirements.lock` on the target before
> the restart. Also: never put tight upper-version pins in `requirements.txt` —
> a `cryptography<46` ceiling silently downgraded prod's working 48.0.0.

### Recovery

DB wipe + clean rebuild:
```bash
sudo systemctl stop soc-dashboard
sudo rm -f /opt/dashboard/data/dashboard.db
sudo systemctl start soc-dashboard
# Visit /setup to recreate admin
```

Service-side debug:
```bash
ssh -i ~/.ssh/collector_key wazuh@10.0.0.213
sudo journalctl -u soc-dashboard -n 100 --no-pager
sudo tail -100 /var/log/soc-dashboard.log
systemctl list-timers | grep soc-dashboard
```

## How to extend safely

- **Add a new DB column**: append a `(table, column, ddl)` tuple to
  `_MIGRATIONS` in database.py. Runs on every service start, idempotent
  via `PRAGMA table_info`.
- **Add a new API route**: blueprint pattern — `pages_bp` for HTML, `api_bp`
  for JSON. Always wrap responses in `ok()` / `err()`.
- **Add a mutating route**: call `auth.audit(...)` at the end.
- **Add a new JS page handler**: add `initX()` to the `SOC` namespace,
  expose it in the return object at the bottom of main.js, call it from the
  template's `{% block scripts %}`.
- **Add a new notification platform**: add a `_format_for_<x>()` in
  notifications.py and register in `_FORMATTERS`. The CRUD UI picks it up
  from `SUPPORTED_PLATFORMS` automatically.
- **Add a new theme**: add a `body.theme-X { --bg-primary: ...; ... }` block
  in themes.css. Add the slug to `config.THEMES`.
- **Add a new poller**: extend `_poller_state` + `delayed()` calls in
  `sync.start_background_pollers()` + add a `--run <kind>` branch in
  `app._cli_run_oneshot()` + (optionally) drop a `.timer` unit in `systemd/`.
- **Add an MCP tool**: add a `@mcp.tool()`-decorated function in
  `mcp_server.py` with a clear docstring (it becomes the tool description) and
  typed params (they become the JSON schema). Reuse `database.py` / `wazuh.py`
  / `osint.py` / `ai.py` — never reimplement queries. Return via the `_ok()` /
  `_error()` helpers. If it mutates state: guard with `if not
  _mutations_enabled(): return _mutation_disabled()` at the top, and call
  `_audit(...)` after the change. Do NOT call `auth.audit()` — there's no Flask
  request context in the MCP process; `_audit()` writes via `db.audit_add`
  directly with username `mcp` and `via: mcp`. Add a test to
  `tests/test_mcp_server.py` (monkeypatch `mcp_server.wazuh` for SSH-backed
  tools — see the existing add_suppression tests).

## MCP triage server

`mcp_server.py` is an optional Model Context Protocol server that lets an
interactive Claude Code session triage the SOC. Transport is stdio, spawned
over SSH (see `mcp.json.example`). It imports the dashboard's own modules and
runs against the same DB — it is **not** a second service and adds no network
listener.

- **Security**: SSH is the auth boundary. Mutating tools (`resolve_alert`,
  `bulk_resolve`, `add_suppression`, `delete_suppression`) are disabled unless
  `SOC_MCP_ALLOW_MUTATIONS=1` is in the spawned env. Every mutation is audited
  with `via: mcp`. Suppression tools reuse the web UI's verify→rollback→restart
  flow verbatim.
- **Dependency**: `mcp` SDK lives in `requirements-mcp.txt` (optional), pulled
  into `requirements-dev.txt` so CI exercises `tests/test_mcp_server.py`. The
  test module `pytest.importorskip("mcp")`s so core installs without the extra
  still pass.
- **Testing status**: unit-tested (read tools, mutation gate, suppression
  orchestration + rollback with `wazuh` mocked, 12 tests) and **verified
  against live prod on 2026-05-24** (wazuh-vm): read tools against the live
  DB, real SSH read of `local_rules.xml`, stdio-over-SSH handshake from
  claude-dev, `osint_lookup` (3/3 providers), `explain_alert` cached + a fresh
  ~59s generation through the real Claude CLI, and a full `add_suppression` →
  `delete_suppression` round-trip (real `wazuh-manager` restarts, audit rows
  stamped `via=mcp`, `local_rules.xml` left semantically identical + valid).
  `mcp_server.py` + `requirements-mcp.txt` are deployed and the `mcp` SDK is
  installed in the prod venv. Note: the round-trip leaves `local_rules.xml`
  whitespace-normalised (one blank line may shift) — a pre-existing quirk of
  `wazuh.remove_rule_from_xml`, shared with the web FP manager, harmless and
  verify-gated.

## Gotchas (paid for in blood — do not relearn these)

1. **NEVER use `rsync --delete-excluded`**. This flag DELETES files on the
   destination that match the `--exclude` patterns — the literal opposite of
   intuition. Combined with `--exclude 'venv/' --exclude 'data/' --exclude '.ssh/'`
   it WIPES exactly the things you wanted to preserve. `deploy.sh` correctly
   uses `--delete` (which preserves excluded paths). Ad-hoc updates should
   use plain `rsync -az` without any `--delete*` flags.

2. **`wazuh-verifyconf` doesn't exist on Wazuh 4.14**. Use `wazuh-analysisd -t`
   instead. `config.WAZUH_VERIFYCONF` already points to the right binary.

3. **AdGuard querylog is huge** (2.7M+ lines, months of history). Always
   `tail -c` to a bounded byte window. Never load the whole file.

4. **`sudo` on remote SSH commands needs `ssh -t`** for the TTY, otherwise
   sudo refuses to prompt. `deploy.sh` uses `$SSH_T` for password-prompted
   steps and `$SSH` for the NOPASSWD ones.

5. **Claude CLI in `-p` mode redirects errors to stdout when stdin is piped
   AND stdout is redirected**. The historical "Prompt is too long" failure
   for analyse.sh was silent because the error went into the briefing output
   file, not stderr.

6. **Claude CLI doesn't expose the 1M-context beta to OAuth users** — only
   API-key users can pass `--betas context-1m-2025-08-07`. If you hit "Prompt
   is too long", tighten `/opt/siem/scripts/filter_wazuh.py` rather than
   trying to switch context window.

7. **AI auto-explain on bootstrap import is a footgun**. First-run import of
   thousands of alerts would burn through the 20/24h cap immediately.
   `first_run_bootstrap()` calls `sync_recent_alerts(dispatch_notifications=False)`
   to suppress dispatch.

8. **Sudo NOPASSWD matches the EXACT command + args**. `/usr/bin/systemctl
   restart soc-dashboard.service` is NOT matched by `systemctl restart
   soc-dashboard` (missing `/usr/bin/` prefix and `.service` suffix).

9. **VACUUM can't run inside an implicit transaction**. `backup.py` opens
   with `isolation_level=None` (autocommit) for that reason.

10. **rsync from claude-dev: `cd` to project dir first**. Otherwise the `-R`
    relative paths resolve to `/home/dev/static/js/main.js` etc. instead of
    `<project>/static/js/main.js`.

11. **Port 22 outbound is blocked from claude-dev**. Use GitHub's port-443
    SSH endpoint — see `~/.ssh/config` for the `Host github.com` → `ssh.github.com:443`
    routing.

12. **Wazuh agents report `IP=any`** in `agent_control -l` output. Matching
    by IP fails; `sync_agent_status()` falls back to hostname matching
    (case-insensitive, strips trailing `.local`). If a host's hostname in
    your inventory doesn't match the Wazuh agent name, agent status won't
    populate — edit the hostname in `/hosts`.

13. **Encryption keys bind to /etc/machine-id**. If wazuh-vm is rebuilt,
    all stored API keys / webhook URLs / NAS config become un-decryptable
    and must be re-entered.

14. **`db.conn()` is autocommit — bulk writes need an explicit transaction**
    (2026-06-05). With `isolation_level=None`, a bare `executemany` commits
    (and fsyncs) PER ROW. The alert_mitre backfill did this against prod's
    219k-alert / 449MB table: ~775 fsyncs/s, disk at 91%, service unbound
    for minutes, 2.6GB written. Wrap any multi-row write in
    `BEGIN IMMEDIATE … COMMIT`, process in bounded batches (no `fetchall()`
    of a whole table — dev's DB is 60× smaller than prod's, so "fast
    locally" proves nothing), and make each batch durable/resumable so a
    restart mid-run continues instead of starting over. See
    `database._populate_alert_mitre` for the pattern.
    **Read-side corollary (2026-06-07):** a per-poll pending-check like
    `WHERE id NOT IN (SELECT … )` re-scans the whole table every call —
    `LIMIT` bounds results, not the scan. On prod's 710MB alerts table that
    was ~1.6GB of reads per service start (23 min to bind) and constant
    "database is locked" poller noise. Track incremental work with a
    high-water mark (`MAX(id)` over a table that's guaranteed a row per
    processed unit), never a set-difference against the full table.

15. **The iterative rsync deploy (explicit file list) silently drifts
    templates** (found 2026-06-07). The CSP hardening pass nonce-gated
    `script-src` in `app.py` AND added `nonce="{{ csp_nonce }}"` + `data-act`
    delegation to every template — but ad-hoc deploys only rsync'd the files
    named in each change, so `app.py`'s nonce-CSP shipped while 8 templates
    stayed on their pre-hardening versions (inline `onclick=`/nonce-less
    `<script>`). Effect: those pages' inline init scripts were CSP-blocked on
    prod — page data never loaded (Overview stats, Settings audit/users/
    backups blank, zero `/api` calls) while the server was provably correct
    (header nonce == body nonce in a fresh response). A browser acceptance
    test caught it; the static `tests/test_csp.py` per-page nonce check
    passes locally because LOCAL templates were fine — only prod had drifted.
    Lessons: (a) after any CSP/template hardening, `rsync templates/`
    wholesale, not file-by-file; (b) dynamic HTML carries a per-request nonce
    so it MUST be `Cache-Control: no-store` (a cached body's stale nonce gets
    blocked under a fresh header — now enforced in `_security_headers`);
    (c) restart after template changes — Jinja caches compiled templates when
    `debug=False`. Verify prod parity with
    `for t in templates/*; do ssh … "cat /opt/dashboard/$t" | diff - $t; done`.

## Project-specific repo review additions

(Populated by `repo review` runs — additions appear here over time, with
date + rationale.)

### 2026-06-04 — code review of the Codex-authored tree (M1–M4 + L1–L12)

Bug classes found that had no dedicated test, now covered:

- **Open redirect via `next=` (M1).** A leading-slash-then-backslash
  (`next=/\evil.com`) folds to `//evil.com` in the browser and bypassed the
  naive `startswith('//')` guard. Fix: `auth.safe_next_path()` rejects scheme,
  netloc, backslashes, and `//`. Test: `tests/test_open_redirect.py`.
  → When reflecting any user-controlled redirect target, validate with a real
  URL split, not string prefixes.
- **CSV/formula injection in the alert export (M2, CWE-1236).** `full_log` is
  attacker-influenced; cells starting with `= + - @` execute in spreadsheet
  apps. Fix: `app._csv_safe()`. Test: `tests/test_csv_injection.py`.
  → Any future CSV/TSV export must run cells through `_csv_safe`.
- **Login username-enumeration timing oracle (M4).** No-such-user returned
  before hashing. Fix: verify against `auth._DUMMY_PASSWORD_HASH` on the
  no-user path. Test: `tests/test_login_timing.py`.
- **`remote_addr` trusted with no proxy awareness (M3).** Throttle + audit IP
  collapse to the proxy IP behind a reverse proxy. Fix: opt-in `ProxyFix` via
  `SOC_TRUST_PROXY=<hops>` (default 0). Re-check when the Caddy/HTTPS work lands.
- **Admin endpoints had no authorization (L7).** The `role` column was stored
  but never enforced — any logged-in `user` had full admin. Fix:
  `auth.require_admin()` on user mgmt / host-config writes / home-API token /
  backups / audit log / API keys. Test: `tests/test_admin_required.py`.
  → New admin-only endpoints MUST start with `if (resp := auth.require_admin()): return resp`.
- **Webhook secret partial-leak (L1).** List view returned the last 6 chars of
  the decrypted URL. Fix: `_webhook_url_hint()` returns host only. Test:
  `tests/test_webhook_secret.py`.
- **Unbounded integer query params (L3).** `int_arg` without `maximum=` allowed
  self-inflicted OOM (`/api/dns/sync?days=1e8`, audit `limit`, etc.). Fix:
  `maximum=` on all such calls. Test: `tests/test_int_clamp.py`.
  → Always pass `maximum=` to `int_arg` for any value that sizes a query/loop.
- **Concurrency (L5/L6).** `wazuh.LOCAL_RULES_LOCK` serialises the FP
  read→write→verify→restart cycle (web + MCP); `sync._sync_alerts_lock`
  serialises alert classify→insert→dispatch so a manual sync + the poller can't
  double-dispatch.

Other low-risk cleanups this pass: `/2fa/*` handlers now None-guard
`current_user()`; `requirements.txt` got major-version upper bounds; 15 unused
imports removed (`ruff --fix`, F401/E401 only).

## Open items / future work

Tracked in `ROADMAP.md`. Headline items:

- **HTTPS / TLS** — being researched separately (Caddy reverse proxy with
  Let's Encrypt DNS-01 via Cloudflare API, AdGuard split-horizon DNS so the
  hostname doesn't appear in public DNS at all)
- **Roles** — `admin` vs `user` is now ENFORCED on the administrative surface
  (user mgmt, host-config writes, home-API token, backups, audit log, API keys)
  via `auth.require_admin()`. First account (`/setup`) is admin; later accounts
  default to `user`. Remaining work: finer-grained per-endpoint RBAC (e.g.
  read-only analysts who can't resolve alerts) and UI gating so non-admins don't
  see admin controls that 403 (backend is the enforced boundary today)
- **CSRF protection** — no tokens. Mitigated in practice by `SameSite=Lax`
  session cookies + JSON-only `fetch`; add Flask-WTF before exposing via a
  reverse proxy to multiple users
- **Screenshots** — README references `docs/screenshot-placeholder.png` which
  doesn't exist. Adding them is a 5-minute polish item but currently shows a
  broken image on the GitHub repo page
- **Incident records / case grouping** — flagged as the most differentiating
  next feature; would group multiple related alerts into a tracked
  investigation with an AI summary. (A non-AI per-alert IOC correlation panel
  now exists — see `ai.related_observations` / `/api/alerts/<id>/related`.)
- **Per-(rule, agent) "expected behaviour" notes** — analyst quality-of-life
  win: persistent notes attached to a rule+agent pair shown inline next to
  matching alerts

### Resolved during the review/hardening pass
- **WSGI** — served via `waitress` (auto-selected in `app.py`; `SOC_DEV_SERVER=1`
  forces the Werkzeug reloader for local dev).
- **PBKDF2** — raised to 600k (OWASP-2023) with transparent rehash-on-login, so
  no existing hashes were invalidated (`auth.needs_rehash`).
- **2FA** — optional per-user TOTP (`pyotp`); two-step login + Settings enrollment.
- **CSP** — `script-src` is nonce-gated (no `'unsafe-inline'`); inline handlers
  moved to a `data-act` delegation. Rendered markdown is nh3-sanitized.
- **SSRF / SSH-injection / XML-injection** guards added on webhook delivery,
  host_config test, and FP rule_id respectively. Login is rate-limited.
- **Perf** — `idx_alerts_status_ts`, cached Fernet key, SSE concurrency cap,
  streamed single-pass AdGuard aggregation, retention/housekeeping poller.

## Quick reference

| Thing | Where |
|---|---|
| Dashboard URL | http://10.0.0.213:8080 |
| GitHub repo | https://github.com/ajacks-595/homesoc |
| DB path (prod) | `/opt/dashboard/data/dashboard.db` |
| DB path (dev) | `/home/dev/projects/soc-dashboard/data/dashboard.db` |
| Logs | `/var/log/soc-dashboard.log` |
| Briefings (source) | `/opt/siem/briefings/*.md` on claude-dev |
| Wazuh alerts (source) | `/var/ossec/logs/alerts/alerts.json` on wazuh-vm |
| AdGuard querylog | `/home/runtipi/runtipi/app-data/migrated/adguard/data/work/data/querylog.json` |
| SSH key (claude-dev → wazuh-vm/runtipi) | `/home/dev/.ssh/collector_key` |
| SSH key (wazuh-vm → claude-dev/runtipi) | `/opt/dashboard/.ssh/id_ed25519` |
| SSH key (claude-dev → GitHub) | `/home/dev/.ssh/github_homesoc` |
| Project dir | `/home/dev/projects/soc-dashboard/` |
