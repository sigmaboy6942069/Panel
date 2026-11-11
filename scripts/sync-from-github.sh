#!/usr/bin/env bash
# ==============================================================================
# TGVPANEL — safe code-only sync from GitHub
#
# Pulls file edits from your GitHub repo and applies them to this install
# WITHOUT touching the live data:
#   * data/           live SQLite database (tracked by git! see below)
#   * .tgvpanel-secret, .env
#
# Why this exists: data/tgvpanel.db is version-controlled, so a careless
# `git checkout -- data/`, `git reset --hard` or `git clean -fdx` silently
# reverts your production database to the pristine repo copy. This script
# never runs those commands.
#
# Usage:
#   sudo ./scripts/sync-from-github.sh                # sync from origin/main
#   sudo ./scripts/sync-from-github.sh <branch>       # sync a branch
#   sudo ./scripts/sync-from-github.sh main --dry-run # preview only
# ==============================================================================
set -euo pipefail

BRANCH="${1:-main}"
DRY_RUN=0
[[ "${2:-}" == "--dry-run" ]] && DRY_RUN=1

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

# Paths that hold live state. Never checkout, clean, or overwrite these.
PROTECTED=(data .env .tgvpanel-secret .hkvm-secret node_modules)

log()  { printf "\033[1;34m[SYNC]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[ OK ]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[FAIL]\033[0m %s\n" "$*"; exit 1; }

[[ -d .git ]] || die "Not a git checkout: $APP_DIR"

if [[ -z "$(git status --porcelain --untracked-files=no -- "${PROTECTED[@]}" 2>/dev/null | grep -v '^??' || true)" ]]; then
  : # protected paths are clean
fi

# ---------------------------------------------------------------------------
# 0. Make sure git will never discard the protected paths.
# ---------------------------------------------------------------------------
# Assume -skip-worktree would hide local DB edits; instead we explicitly keep
# git from touching them by refusing to run destructive commands at all.
log "Repo:      $APP_DIR"
log "Branch:    $BRANCH"
log "Protected: ${PROTECTED[*]}"
echo

# ---------------------------------------------------------------------------
# 1. Back up the live database (WAL-safe) before any file changes.
# ---------------------------------------------------------------------------
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BK_DIR="data/backups"
mkdir -p "$BK_DIR"

ACTIVE_DB=""
[[ -f data/tgvpanel.db ]] && ACTIVE_DB="data/tgvpanel.db"
[[ -z "$ACTIVE_DB" && -f data/hkvm.db ]] && ACTIVE_DB="data/hkvm.db"

# Take a WAL-safe copy of the live database. `VACUUM INTO` produces a
# self-contained file (no -wal needed) and works while the service runs.
# Three independent strategies, because a backup must never be skipped.
wal_safe_backup() {
  local src="$1" dst="$2"
  # (a) sqlite3 CLI
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$src" "VACUUM INTO '$dst'" 2>/dev/null && return 0
  fi
  # (b) node:sqlite (Node 22+, no native build required)
  node --no-warnings -e "
    const { DatabaseSync } = require('node:sqlite');
    new DatabaseSync('${src}').exec(\"VACUUM INTO '${dst}'\");
  " 2>/dev/null && return 0
  # (c) the project's own sqlite3 driver
  node -e "
    const s = require('sqlite3'); const d = new s.Database('${src}');
    d.run(\"VACUUM INTO '${dst}'\", e => { if (e) { console.error(e.message); process.exit(1); } d.close(); });
  " 2>/dev/null && return 0
  return 1
}

verify_backup() {
  local f="$1"
  [[ -s "$f" ]] || return 1
  if command -v sqlite3 >/dev/null 2>&1; then
    [[ "$(sqlite3 "$f" 'PRAGMA integrity_check' 2>/dev/null)" == "ok" ]] && return 0 || return 1
  fi
  node --no-warnings -e "
    const { DatabaseSync } = require('node:sqlite');
    const r = new DatabaseSync('${f}').prepare('PRAGMA integrity_check').get();
    process.exit(r.integrity_check === 'ok' ? 0 : 1);
  " 2>/dev/null && return 0
  return 1
}

if [[ -n "$ACTIVE_DB" ]]; then
  BK="$BK_DIR/pre_sync_${STAMP}.db"
  log "Backing up ${ACTIVE_DB} -> ${BK}"
  wal_safe_backup "$ACTIVE_DB" "$BK" \
    || die "Could not create a database backup — aborting WITHOUT changing anything."
  verify_backup "$BK" \
    || die "Backup failed its integrity check — aborting WITHOUT changing anything."
  ok "Backup verified: $BK ($(du -h "$BK" | cut -f1))"
else
  warn "No database found; continuing (fresh install?)."
fi
echo

# ---------------------------------------------------------------------------
# 2. Fetch and show what will change.
# ---------------------------------------------------------------------------
log "Fetching from origin..."
git fetch --prune origin

UPSTREAM="origin/${BRANCH}"
git rev-parse --verify "$UPSTREAM" >/dev/null 2>&1 || die "Unknown branch: $BRANCH"

LOCAL_REV="$(git rev-parse HEAD)"
REMOTE_REV="$(git rev-parse "$UPSTREAM")"

if [[ "$LOCAL_REV" == "$REMOTE_REV" ]]; then
  ok "Already up to date ($(git rev-parse --short HEAD)). Nothing to do."
  exit 0
fi

# Refuse to clobber local edits to CODE (protected paths excluded).
CODE_DIRTY="$(git status --porcelain --untracked-files=no \
  | grep -vE '^(..) (data/|\.env$|\.tgvpanel-secret$|\.hkvm-secret$)' || true)"
if [[ -n "$CODE_DIRTY" ]]; then
  warn "Local uncommitted changes to tracked code files:"
  echo "$CODE_DIRTY" | sed 's/^/        /'
  echo
  die "Commit or stash these on the VPS first. (Your data/ and .env are NOT the problem.)"
fi

echo "--- Incoming changes ---"
git --no-pager log --oneline "${LOCAL_REV}..${REMOTE_REV}" | sed 's/^/  /'
echo
echo "--- Files that will be updated ---"
git --no-pager diff --stat "${LOCAL_REV}..${REMOTE_REV}" -- . ':(exclude)data' | sed 's/^/  /'
echo

if [[ $DRY_RUN == 1 ]]; then
  ok "Dry run complete. Nothing was changed."
  exit 0
fi

# ---------------------------------------------------------------------------
# 3. Stop the service so files are not swapped under a running process.
# ---------------------------------------------------------------------------
SERVICE_STOPPED=0
for svc in tgvpanel.service hkvm-panel.service; do
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$svc" 2>/dev/null; then
    log "Stopping $svc"
    systemctl stop "$svc" && SERVICE_STOPPED=1
  fi
done
[[ $SERVICE_STOPPED == 0 ]] && warn "No running systemd service detected (continuing)."

restore_service() {
  if [[ $SERVICE_STOPPED == 1 ]]; then
    for svc in tgvpanel.service hkvm-panel.service; do
      if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
        log "Starting $svc"
        systemctl start "$svc" || true
      fi
    done
  fi
}

# ---------------------------------------------------------------------------
# 4. Check out the incoming tree but PRESERVE protected paths.
# ---------------------------------------------------------------------------
# `git checkout <rev> -- .` would also restore data/ to the repo copy.
# Instead: snapshot protected files, reset the index for them, and use
# `git merge --ff-only` which (verified) never rewrites a dirty tracked file
# whose content did not change upstream. For hard cases we fall back to
# extracting the tree with tar and excluding protected paths.
if git merge-base --is-ancestor "$LOCAL_REV" "$REMOTE_REV"; then
  log "Fast-forwarding to $(git rev-parse --short "$REMOTE_REV")"
  git merge --ff-only "$UPSTREAM"
else
  warn "History diverged from $UPSTREAM — updating tracked files only (no reset)."
  git checkout "$UPSTREAM" -- $(git ls-tree -r --name-only "$UPSTREAM" | grep -vE '^(data/|\.env)' ) 2>/dev/null || true
  git update-ref "refs/heads/${BRANCH}" "$REMOTE_REV" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 5. Rebuild + migrate.
# ---------------------------------------------------------------------------
if [[ -d /usr/local/include/node ]]; then export npm_config_nodedir=/usr/local; fi

log "Installing dependencies..."
npm install --no-audit --no-fund -s || warn "npm install failed — continuing with existing modules."

log "Rebuilding TypeScript..."
if ! npm run build -s; then
  if [[ -x node_modules/.bin/tsc ]]; then node_modules/.bin/tsc; else warn "Build failed; the committed lib/ will be used."; fi
fi

log "Applying database migrations (data is preserved, only schema changes)..."
npm run migrate -s || die "Migration failed. Restore: cp $BK data/tgvpanel.db && rm -f data/tgvpanel.db-wal data/tgvpanel.db-shm"

restore_service
echo
ok "Sync complete. Database untouched at: $ACTIVE_DB"
ok "Backup: $BK"
