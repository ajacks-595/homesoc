# Contributing

This project is primarily a personal SOC tool. Contributions are welcome but
this isn't a maintained product — expect "no support promised, fork freely"
energy.

## Quick orientation

Read `CLAUDE.md` first — it's the canonical architecture/conventions doc.

## Setting up locally

```bash
git clone <fork-url>
cd soc-dashboard
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/pip install pytest    # for the test suite
./venv/bin/python -m pytest tests/    # confirm tests pass
./venv/bin/python app.py    # listens on 0.0.0.0:8080
```

On first visit to http://localhost:8080 you'll be redirected to `/setup`
to create an admin account. After that, visit `/settings` → "Hosts &
Connections" to point the dashboard at your Wazuh manager, AdGuard host,
and Claude CLI host (if you have one).

## Code conventions

- Python: stdlib + Flask + cryptography + requests + markdown. No heavy
  deps without strong justification.
- Vanilla JS in a single `SOC` namespace. No build step. No bundler.
- SQLite migrations append to `_MIGRATIONS` in `database.py` — never
  drop or rename existing columns.
- Every JSON API endpoint returns `{success, data, error}`. Use the
  `ok()` / `err()` helpers in `app.py`.
- Every mutating endpoint calls `auth.audit(...)` before returning.

## PR checklist

- [ ] Tests pass: `pytest tests/`
- [ ] No hardcoded IPs/hostnames/paths — use config/env
- [ ] If adding a new dependency: justify it in the PR description
- [ ] If adding a new schema column: append to `_MIGRATIONS`, don't edit `SCHEMA` mid-file
- [ ] If changing an API response shape: bump a notional version + update the JS

## Things I won't merge (probably)

- Major framework rewrites (React/Vue/etc) — keeping vanilla JS is intentional
- Heavyweight deps for things stdlib can do
- "Improvements" to the AI prompt that haven't been A/B tested against real alerts
- Anything that adds CDN runtime dependencies
- Auth schemes that require external IdPs without making them optional

## Security

If you find a vuln, please don't open a public issue. Email is fine
(see profile) or use GitHub's private security advisory feature.
