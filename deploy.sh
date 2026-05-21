#!/usr/bin/env bash
#
# Deploy HomeSOC to your Wazuh manager (or any target host).
# Runs from your dev machine. Set the env vars below before first use.
#
# Usage:
#   WAZUH_HOST=10.x.x.x WAZUH_USER=wazuh SSH_KEY=~/.ssh/id_ed25519 ./deploy.sh

set -euo pipefail
cd "$(dirname "$0")"

WAZUH_HOST="${WAZUH_HOST:-}"
WAZUH_USER="${WAZUH_USER:-wazuh}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
REMOTE_DIR="${REMOTE_DIR:-/opt/dashboard}"

if [ -z "$WAZUH_HOST" ]; then
  echo "ERROR: WAZUH_HOST is not set. Run with:"
  echo "  WAZUH_HOST=10.x.x.x ./deploy.sh"
  echo "or set the defaults inside this script for repeated use."
  exit 1
fi

SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=accept-new $WAZUH_USER@$WAZUH_HOST"
# For steps that invoke sudo on the remote we need a TTY so sudo can prompt.
SSH_T="ssh -t -i $SSH_KEY -o StrictHostKeyChecking=accept-new $WAZUH_USER@$WAZUH_HOST"
RSYNC_E="ssh -i $SSH_KEY -o StrictHostKeyChecking=accept-new"

if [ "$(id -u)" = "0" ]; then
  err "Do not run this with sudo locally — it should run as your normal user (dev) so it uses /home/dev/.ssh/collector_key and prompts on wazuh-vm only."
  exit 1
fi

say() { printf "\n\033[1;36m>>> %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m!! %s\033[0m\n" "$*"; }
err() { printf "\033[1;31mXX %s\033[0m\n" "$*" >&2; }

say "Sanity check: SSH to $WAZUH_USER@$WAZUH_HOST"
$SSH 'echo SSH_OK; whoami; hostname' || { err "SSH failed — check $SSH_KEY"; exit 1; }

say "Ensure $REMOTE_DIR exists and is owned by $WAZUH_USER (will prompt for sudo on wazuh-vm)"
$SSH_T "sudo mkdir -p $REMOTE_DIR/data/siem/briefings $REMOTE_DIR/data/siem/logs $REMOTE_DIR/.ssh && sudo chown -R $WAZUH_USER:$WAZUH_USER $REMOTE_DIR && sudo touch /var/log/soc-dashboard.log && sudo chown $WAZUH_USER:$WAZUH_USER /var/log/soc-dashboard.log"

say "Generate SSH key on wazuh-vm for reverse access to claude-dev (if missing)"
$SSH "test -f $REMOTE_DIR/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N '' -f $REMOTE_DIR/.ssh/id_ed25519 -C 'soc-dashboard@wazuh-vm'"
PUBKEY=$($SSH "cat $REMOTE_DIR/.ssh/id_ed25519.pub")
echo
echo "============================================================"
echo "  ACTION REQUIRED:  add the following public key to claude-dev"
echo "  ~/.ssh/authorized_keys (for user 'dev'):"
echo
echo "  $PUBKEY"
echo
echo "  Without this, 'Run Collection Now' / DNS sync from the dashboard"
echo "  will fail because wazuh-vm cannot SSH back to claude-dev."
echo "============================================================"
echo

say "rsync project → $REMOTE_DIR (excluding venv/data/.ssh/.git)"
rsync -az --delete \
  --exclude 'venv/' --exclude 'data/' --exclude '.ssh/' \
  --exclude '__pycache__/' --exclude '*.log' --exclude '.git/' \
  -e "$RSYNC_E" \
  ./ "$WAZUH_USER@$WAZUH_HOST:$REMOTE_DIR/"

say "Initial data seed: rsync briefings + context.md → $REMOTE_DIR/data/siem/"
rsync -az -e "$RSYNC_E" \
  /opt/siem/briefings/ "$WAZUH_USER@$WAZUH_HOST:$REMOTE_DIR/data/siem/briefings/" || true
rsync -az -e "$RSYNC_E" \
  /opt/siem/context.md "$WAZUH_USER@$WAZUH_HOST:$REMOTE_DIR/data/siem/context.md" || true

say "Create / refresh virtualenv and install dependencies"
$SSH "cd $REMOTE_DIR && python3 -m venv venv && ./venv/bin/pip install --quiet --upgrade pip && ./venv/bin/pip install --quiet -r requirements.txt"

say "Install systemd units + timers (sudo on wazuh-vm)"
$SSH_T "sudo cp $REMOTE_DIR/soc-dashboard.service /etc/systemd/system/ && \
        sudo cp $REMOTE_DIR/systemd/soc-dashboard-sync@.service /etc/systemd/system/ && \
        sudo cp $REMOTE_DIR/systemd/soc-dashboard-sync-alerts.timer /etc/systemd/system/ && \
        sudo cp $REMOTE_DIR/systemd/soc-dashboard-sync-dns.timer /etc/systemd/system/ && \
        sudo cp $REMOTE_DIR/systemd/soc-dashboard-sync-agents.timer /etc/systemd/system/ && \
        sudo systemctl daemon-reload && \
        sudo systemctl enable --now soc-dashboard.service \
                                    soc-dashboard-sync-alerts.timer \
                                    soc-dashboard-sync-dns.timer \
                                    soc-dashboard-sync-agents.timer"

say "Sudoers — skipping (you already installed it manually)."

say "Restart service (sudo on wazuh-vm)"
$SSH_T "sudo systemctl restart soc-dashboard.service"
sleep 2

say "Tail logs for 10 seconds"
$SSH "timeout 10 tail -f /var/log/soc-dashboard.log || true"

say "Done."
echo
echo "Dashboard URL:  http://$WAZUH_HOST:8080"
echo
echo "Remaining manual step:"
echo "  1) Add the public key shown above to dev@claude-dev:~/.ssh/authorized_keys"
echo "  2) Install /etc/sudoers.d/soc-dashboard-claudedev on claude-dev:"
echo "       sudo install -m 0440 sudoers.d/soc-dashboard-claudedev /etc/sudoers.d/soc-dashboard-claudedev"
echo "  3) Browse to the URL above; configure API keys on /settings"
