#!/usr/bin/env bash
# ==============================================================================
# TGVPANEL — Safe Zero-Data-Loss Updater
# Automatically backs up data/tgvpanel.db (and migrates legacy data/hkvm.db /
# .hkvm-secret) via SQLite VACUUM INTO before migrating.
# ==============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

log() { printf "\033[1;34m[TGVPANEL-UPDATE]\033[0m %s\n" "$*"; }
ok()  { printf "\033[1;32m[  OK  ]\033[0m %s\n" "$*"; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p data/backups

if [[ -f .hkvm-secret && ! -f .tgvpanel-secret ]]; then
  mv .hkvm-secret .tgvpanel-secret
  chmod 600 .tgvpanel-secret 2>/dev/null || true
  ok "Migrated secret vault .hkvm-secret -> .tgvpanel-secret"
fi

LIVE_BACKUP_FILE=""
ACTIVE_DB=""
if [[ -f data/tgvpanel.db ]]; then
  ACTIVE_DB="data/tgvpanel.db"
elif [[ -f data/hkvm.db ]]; then
  ACTIVE_DB="data/hkvm.db"
fi

if [[ -n "$ACTIVE_DB" ]]; then
  LIVE_BACKUP_FILE="data/backups/tgvpanel_pre_update_${STAMP}.db"
  log "Creating verified pre-update SQLite backup from ${ACTIVE_DB}: $LIVE_BACKUP_FILE"
  node -e "
    const sqlite3 = require('sqlite3');
    const db = new sqlite3.Database('${ACTIVE_DB}');
    db.run(\"VACUUM INTO '${LIVE_BACKUP_FILE}'\", (err) => {
      if (err) { console.error(err); process.exit(1); }
      db.close();
    });
  "
  ok "Backup saved to $LIVE_BACKUP_FILE"
fi

HAD_LEGACY_HKVM_DB=0
if [[ "$ACTIVE_DB" == "data/hkvm.db" ]]; then
  HAD_LEGACY_HKVM_DB=1
  if [[ -d .git ]] && git ls-files --error-unmatch data/hkvm.db >/dev/null 2>&1; then
    git checkout -- data/hkvm.db 2>/dev/null || true
  fi
fi

if [[ -d .git && "${SKIP_GIT_PULL:-0}" != "1" ]]; then
  log "Fetching latest repository updates..."
  git pull --ff-only || log "Skipping git fast-forward (local working branch)."
fi

if [[ "$HAD_LEGACY_HKVM_DB" == "1" && -n "$LIVE_BACKUP_FILE" && -f "$LIVE_BACKUP_FILE" ]]; then
  cp -f "$LIVE_BACKUP_FILE" data/tgvpanel.db
  rm -f data/hkvm.db data/hkvm.db-wal data/hkvm.db-shm data/tgvpanel.db-wal data/tgvpanel.db-shm
  ok "Migrated live database data/hkvm.db -> data/tgvpanel.db"
fi

if [[ -d /usr/local/include/node ]]; then
  export npm_config_nodedir="/usr/local"
fi

log "Updating Node.js packages & rebuilding TypeScript..."
npm install
npm run build

log "Applying versioned database migrations..."
npm run migrate

if [[ $EUID -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet tgvpanel.service && systemctl restart tgvpanel.service && ok "Restarted tgvpanel.service"
  systemctl is-active --quiet tgvpanel-node-agent.service && systemctl restart tgvpanel-node-agent.service && ok "Restarted tgvpanel-node-agent.service"
  systemctl is-active --quiet hkvm-panel.service && systemctl restart hkvm-panel.service && ok "Restarted hkvm-panel.service"
  systemctl is-active --quiet hkvm-node-agent.service && systemctl restart hkvm-node-agent.service && ok "Restarted hkvm-node-agent.service"
fi

ok "TGVPANEL update finished cleanly."
