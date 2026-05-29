# Roadmap / known TODOs

Nothing here is blocking — the app works as built. These are tracked for the
next dev session.

## Recently shipped (review / hardening pass)
- Security: server-side HTML sanitization (nh3) + attribute-safe client
  escaping + URL-scheme allowlisting; SSRF guard on webhook delivery;
  host_config SSH argument-injection guard; numeric rule_id (XML-injection)
  guard; login rate-limiting + audit; PBKDF2 → 600k with rehash-on-login;
  optional per-user TOTP 2FA; CSP `script-src` nonce-gated (no `unsafe-inline`);
  0600 DB + secure backup tempfiles.
- Performance: `alerts(status, timestamp)` index; cached Fernet key; SSE
  concurrency cap; streamed single-pass AdGuard aggregation; N+1 → single
  UPDATE; OSINT-cache reaper.
- Features: related-activity panel, MITRE ATT&CK summary + filter, noisy-rule
  detector, retention poller, SOC performance (MTTR/FP) tile, briefing export.

## Quick wins
- [ ] First-run bootstrap doesn't call `sync_agent_status()`, so the Hosts
      page shows "Active Agents: 0" until you click "Refresh agent status"
      once. Fix: add `sync.sync_agent_status()` to `sync.first_run_bootstrap()`.
- [ ] First-run bootstrap doesn't seed DNS data either; same fix — call
      `sync.sync_dns_today()` (catch and log on failure).
- [ ] Add `soc-dashboard.service` to the wazuh-vm sudoers so a code-update
      deploy can run unattended:
      `wazuh ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart soc-dashboard.service`
- [ ] Briefing reader on `/briefings#<id>` should auto-scroll/select that
      briefing on load. Currently the fragment is set but not consumed.

## Medium
- [ ] Move hard-coded IPs/paths from `config.py` into a settings table so the
      app is configurable from `/settings` rather than requiring a code edit.
- [x] Replace Flask's dev server with `waitress` for prod (single process +
      thread pool, so in-process pollers still start once). `app.py` prefers
      waitress automatically; no `ExecStart` change needed. `SOC_DEV_SERVER=1`
      forces the Werkzeug reloader for local dev.
- [x] Background pollers (alerts 5min / DNS hourly / agents 15min / briefings
      hourly / retention daily) run in-process, or via systemd timers with
      `SOC_POLLERS=systemd`. AI enrichment is off the poller's critical path
      (a background dispatch worker).
- [x] The alert-detail linkify no longer round-trips innerHTML —
      `linkifyIpsInEl` walks text nodes (added with the XSS hardening). A
      syntax-highlighted JSON viewer would still be a nice upgrade.
- [ ] DNS sync still pipes the querylog tail over SSH (the slow part). The
      parse/aggregate is now single-pass + streamed; a remote `tail -c +<offset>`
      (needs a runtipi sudoers entry) would cut the transfer.

## Bigger
- [x] **Auth layer** — per-user PBKDF2 (600k) login with sessions, brute-force
      throttling, optional TOTP 2FA, and a full audit log. Rule changes are
      authenticated + audited.
- [ ] **CSRF tokens** on mutating endpoints. Mitigated in practice today by
      `SameSite=Lax` cookies + JSON-only `fetch`; add Flask-WTF before exposing
      to multiple users / a public origin.
- [ ] **Multi-host hosts page** — current schema assumes one Wazuh manager.
      Generalise.
- [ ] **Briefing actions** would benefit from being editable in the UI
      (mark P2 → P1, edit description). Currently they're write-once from
      parser output.
- [ ] **Notifications** — push to ntfy when a P1 action appears or a
      Level 12+ alert fires. The ntfy server is already running on
      claude-dev.

## GitHub-readiness checklist (before publishing)
- [ ] Choose a license (MIT? Apache 2.0?) and add `LICENSE`
- [ ] Add `CONTRIBUTING.md` with PR/issue conventions
- [ ] Move all hard-coded `10.0.0.x` IPs to env vars or example config
- [ ] Move `_FERNET_SALT` to a per-deployment value
- [ ] Sanitise the example briefings (the parsed actions reference your real
      network: MacBook port 55555, claude-dev tooling drift, etc.)
- [ ] Remove or sanitise `CLAUDE.md` (contains your IPs)
- [ ] Sanitise `sudoers.d/` files (currently reference your `wazuh` and
      `dev` system users by name)
- [ ] Add a real screenshot to `docs/screenshot.png` (referenced in README)
- [ ] Pin dependency versions in `requirements.txt` (currently `>=` ranges)
- [ ] Add a GitHub Actions workflow that at least runs `python -c "import app"`
      to catch import errors on PR

## Things deliberately *not* on this list

- Database migrations (Alembic etc.). Schema is small enough to recreate;
  `init_db()` is `CREATE TABLE IF NOT EXISTS`, so column additions can be
  hand-applied via `ALTER TABLE`.
- ORM. Raw SQL is fine for this size.
- Frontend build step. Vanilla JS is the explicit choice.
- Docker. Could come later for the GitHub release but not needed for
  single-deployment use.
