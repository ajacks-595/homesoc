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

- All passwords hashed with PBKDF2-SHA256 (600,000 iterations, OWASP-2023) +
  per-user salt; legacy lower-iteration hashes are upgraded on next login
- All API keys, webhook URLs, NAS credentials encrypted at rest with Fernet,
  key derived from `/etc/machine-id` + a per-deployment salt via PBKDF2
  (see "local host access" under Known limitations for the trust boundary)
- Rendered markdown (briefings, AI explanations, chat) is HTML-sanitized with
  nh3 server-side; the client escapes attribute contexts and allowlists URL
  schemes (`http(s)`/`mailto`/same-origin only)
- Outbound webhook URLs are SSRF-checked (loopback / link-local / cloud
  metadata blocked; `SOC_WEBHOOK_ALLOW_PRIVATE=0` also blocks LAN ranges)
- `/login` is rate-limited per IP + username, with a failed-login audit trail
- Session cookies are HttpOnly + SameSite=Lax; `Secure` flag flipped on
  by setting `SOC_COOKIE_SECURE=1` (do this once you're behind TLS)
- Every state-changing API endpoint records to the audit log
- SSH commands use explicit argv lists (validated against argument injection);
  no `shell=True`

## The home consumer API (`/api/home/*`)

HomeSOC exposes an optional read-mostly API for a LAN consumer (e.g. a
wall-display dashboard). It is **disabled by default** and hardened as follows:

- **Default-OFF**: with no token configured, every `/api/home/*` route returns
  403. A fresh deployment is never exposed until the operator opts in.
- **Token-gated**: enable it by generating a token in Settings → Home Consumer
  API. Callers send it as `X-HomeSOC-Token: <token>` (or `Authorization:
  Bearer <token>`). The SSE stream `/api/home/events` also accepts `?token=`
  since `EventSource` cannot set headers — prefer the header elsewhere.
- **Constant-time comparison**: tokens are compared with `hmac.compare_digest`;
  stored Fernet-encrypted at rest.
- **Read-only by default**: the only mutating endpoint
  (`POST /api/home/pipeline/run`) returns 403 even with a valid token unless
  you explicitly enable mutations in Settings. Pipeline `kind` is validated
  against an allowlist — callers can never run arbitrary commands. Mutations
  are recorded in the audit log.

If you don't run a consumer, leave it disabled (the default) and `/api/home/*`
stays closed.

## The MCP triage server (`mcp_server.py`)

HomeSOC ships an optional Model Context Protocol server so an interactive
Claude Code session can triage alerts. It is **not** an additional network
listener — it speaks MCP over stdio and is intended to be spawned over SSH:

- **SSH is the auth boundary.** Whoever can spawn the process already has shell
  access to the dashboard host (and thus the DB). The MCP server grants no
  privilege that SSH access didn't already imply.
- **Read-only by default.** State-changing tools (`resolve_alert`,
  `bulk_resolve`, `add_suppression`, `delete_suppression`) return an error
  unless `SOC_MCP_ALLOW_MUTATIONS=1` is set in the spawned environment. Read
  tools always work.
- **Audited.** Every mutation is written to the audit log with username
  `SOC_MCP_OPERATOR` (default `mcp`) and a details payload stamped
  `{"via": "mcp"}`, so MCP-originated changes are distinguishable from web-UI
  changes after the fact.
- **Same safe Wazuh path.** `add_suppression` / `delete_suppression` reuse the
  web UI's write → `wazuh-analysisd -t` validate → roll-back-on-failure →
  restart flow. Tools take structured arguments — callers cannot inject raw
  XML or shell.
- **No new secrets.** The server reuses the dashboard's machine-bound Fernet
  key and configured API keys; it does not store or transmit credentials.

Don't expose stdio MCP over anything other than trusted SSH. If you want it
disabled entirely, simply don't install `requirements-mcp.txt` / don't add the
`.mcp.json` entry.

## Known limitations

- **No CSRF tokens** — state-changing requests are JSON over `fetch`, which
  `SameSite=Lax` session cookies already shield from cross-site forgery in
  practice. Add Flask-WTF before exposing the app to multiple users or a
  public origin.
- **Local host access — the encryption trust boundary.** The Fernet key is
  derived from `/etc/machine-id`, which is world-readable. This protects an
  *exfiltrated DB/backup taken to another host*, but NOT a local user on the
  dashboard host: anyone who can read the DB file there can re-derive the key
  (and thus the session secret and stored API keys). The DB and on-disk backup
  snapshots are created `0600` to limit this, but shell access to the host
  should be treated as equivalent to full compromise.
- **The SSE stream accepts the home-API token as a `?token=` query param**
  (EventSource cannot set headers). Query strings can land in proxy/access
  logs — prefer the `X-HomeSOC-Token` header everywhere else, and rotate the
  token if such a log is exposed.
- **The session secret is regenerated only if you delete it from the
  settings table** — if leaked, rotate it manually.
- **Per-machine encryption means data migration requires re-entering keys** —
  if you copy the DB to a new host, API keys / webhook URLs / NAS creds
  won't decrypt.
