#!/usr/bin/env bash
#
# deploy-soc-dashboard.sh — push soc-dashboard to wazuh-vm and restart it.
#
# WHY THIS EXISTS (permissions audit, 2026-05): the recurring deploy was a raw
#   ssh -i .../collector_key wazuh@10.0.0.213 '<arbitrary remote command>'
# which can't be safely allowlisted (the quoted payload is unbounded). This
# wrapper bounds the capability to exactly "rsync a fixed file set + restart one
# service", so it is safe to add as a single allow rule:
#
#   "Bash(./deploy-soc-dashboard.sh:*)"   (or the absolute path)
#
# PREREQUISITES on wazuh-vm (already in place per the transcripts):
#   - SSH key auth for wazuh@10.0.0.213 via ~/.ssh/collector_key
#   - sudoers NOPASSWD entry, e.g.:
#       wazuh ALL=(root) NOPASSWD: /usr/bin/systemctl restart soc-dashboard.service
#     (the restart line below must match that sudoers spec EXACTLY, incl. the
#      absolute /usr/bin/systemctl path, or `sudo -n` will fail)
#
set -euo pipefail

# --- config ---------------------------------------------------------------
HOST="wazuh@10.0.0.213"
KEY="${SOC_DEPLOY_KEY:-$HOME/.ssh/collector_key}"
REMOTE_DIR="/opt/dashboard"
SERVICE="soc-dashboard.service"
HEALTH_URL="http://10.0.0.213:8080/login"     # expect HTTP 200 once up
SRC_DIR="${SOC_SRC_DIR:-$HOME/projects/soc-dashboard}"
SSH=(ssh -i "$KEY" -o ConnectTimeout=5 "$HOST")

# Files to ship. Explicit allowlist (NOT a blanket `rsync --delete` of the tree)
# so we never clobber server-side venv/, .ssh/, or data dirs under
# /opt/dashboard. Whole DIRECTORIES (templates/, static/) are listed rather than
# individual files: a hand-picked per-file template list silently drifts —
# app.py's CSP nonce shipped while 8 templates stayed on their pre-hardening
# versions and CSP-blocked every page (CLAUDE.md gotcha 15, 2026-06-07). rsync
# -R recurses directories, so this ships every template/asset every time.
# Override with an explicit file list: ./deploy-soc-dashboard.sh app.py sync.py
DEFAULT_MANIFEST=(
  config.py database.py app.py sync.py ai.py wazuh.py auth.py backup.py
  notifications.py osint.py parsers.py vulntrack.py mcp_server.py
  templates static/js static/css
  requirements.txt requirements.lock requirements-mcp.txt
  soc-dashboard.service
)
# --------------------------------------------------------------------------

cd "$SRC_DIR"
MANIFEST=("$@")
if [ "${#MANIFEST[@]}" -eq 0 ]; then
  MANIFEST=("${DEFAULT_MANIFEST[@]}")
fi

# Only ship files that actually exist locally (skip-and-warn on the rest).
TO_SYNC=()
for f in "${MANIFEST[@]}"; do
  if [ -e "$f" ]; then TO_SYNC+=("$f"); else echo "  skip (missing): $f" >&2; fi
done
[ "${#TO_SYNC[@]}" -gt 0 ] || { echo "nothing to deploy" >&2; exit 1; }

echo "==> Syncing ${#TO_SYNC[@]} file(s) to ${HOST}:${REMOTE_DIR}/"
# -R preserves relative paths so templates/ and static/js/ land in subdirs.
rsync -az -R --info=NAME -e "ssh -i $KEY -o ConnectTimeout=5" \
  "${TO_SYNC[@]}" "${HOST}:${REMOTE_DIR}/"

echo "==> Restarting ${SERVICE}"
# Exact, sudoers-pinned command — the ONLY privileged thing this script does.
"${SSH[@]}" "sudo -n /usr/bin/systemctl restart ${SERVICE}"

echo -n "==> Waiting for health "
for i in $(seq 1 15); do
  code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$HEALTH_URL" || true)"
  if [ "$code" = "200" ]; then echo " OK (200)"; exit 0; fi
  echo -n "."; sleep 2
done

echo " FAILED (last code: ${code:-none})" >&2
# The log file is chowned to wazuh by deploy.sh, so no sudo is needed (and there
# is no sudoers rule for journalctl — the previous `sudo -n journalctl` always
# died with "a password is required", masked by `|| true`).
echo "==> Last 30 log lines:" >&2
"${SSH[@]}" "tail -n 30 /var/log/soc-dashboard.log" >&2 || true
exit 1
