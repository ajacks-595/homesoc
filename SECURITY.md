# Security Policy

## Supported versions

This is a personal project shared for reference. Only `main` gets security
fixes. Forks are on their own.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs.

Use GitHub's private vulnerability reporting feature, or email the maintainer
directly (see profile).

Expect a reply within ~1 week for serious issues. Less serious things might
take longer — this is a personal project, not a funded one.

## Security model

**This dashboard is LAN-only by design.** Do not expose it to the public
internet without putting a hardened reverse proxy in front of it.

- All passwords hashed with PBKDF2-SHA256 (200,000 iterations) + per-user salt
- All API keys, webhook URLs, NAS credentials encrypted at rest with Fernet,
  key derived from `/etc/machine-id` + a per-deployment salt via PBKDF2
- Session cookies are HttpOnly + SameSite=Lax; `Secure` flag flipped on
  by setting `SOC_COOKIE_SECURE=1` (do this once you're behind TLS)
- Every state-changing API endpoint records to the audit log
- SSH commands use explicit argv lists; no `shell=True`

## Known limitations

- **No CSRF protection** — acceptable on single-user LAN; matters once you
  expose this to multiple users. Add Flask-WTF or similar before opening up.
- **No rate limiting on `/login`** — brute-force-able if exposed. Put it
  behind a reverse proxy with rate limits, or add `flask-limiter`.
- **The session secret is regenerated only if you delete it from the
  settings table** — if leaked, rotate it manually.
- **Per-machine encryption means data migration requires re-entering keys** —
  if you copy the DB to a new host, API keys / webhook URLs / NAS creds
  won't decrypt.
