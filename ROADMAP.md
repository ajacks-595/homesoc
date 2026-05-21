# Roadmap / known TODOs

Nothing here is blocking — the app works as built. These are tracked for the
next dev session.

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
- [ ] Replace Flask's dev server (which is what `app.py` currently starts)
      with `waitress` or `gunicorn` for prod. Update the systemd `ExecStart`.
- [ ] Schedule a periodic background sync (alerts every 30s, DNS hourly,
      agent status every 5min) using `apscheduler` or a simple thread. Right
      now everything is poll-on-request.
- [ ] The alert detail expand row builds raw_json HTML via `JSON.stringify`
      then `linkifyIps` runs on the resulting HTML — works but means we
      linkify inside quoted strings too. Switch to a real syntax-highlighted
      JSON viewer (e.g. a tiny ~50-line recursive renderer).
- [ ] DNS sync on prod takes ~7s because we pipe 60MB of querylog over SSH.
      Cache the last-known offset and `tail -c +<offset>` for incremental.

## Bigger
- [ ] **Auth layer** — even just a single shared password via a reverse proxy.
      Right now anyone on the LAN can change Wazuh rules.
- [ ] **CSRF protection** on mutating POST/PATCH/DELETE endpoints. Flask
      doesn't add this by default and we don't have it. Acceptable on a
      single-user LAN box, not acceptable for any wider deployment.
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
