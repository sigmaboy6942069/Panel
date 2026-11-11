# Syncing Code Edits to a Live VPS

A practical tutorial for editing files in the GitHub web UI (or on any machine) and
getting those edits onto a **running** TGVPANEL install — **without touching the
database, uploads, or secrets**.

---

## Table of Contents

1. [The One Rule](#1-the-one-rule)
2. [Why This Is Dangerous](#2-why-this-is-dangerous)
3. [One-Time Setup](#3-one-time-setup)
4. [Daily Workflow: Sync Code Edits](#4-daily-workflow-sync-code-edits)
5. [What the Script Actually Does](#5-what-the-script-actually-does)
6. [Manual Commands (No Script)](#6-manual-commands-no-script)
7. [Backups and Restore](#7-backups-and-restore)
8. [Recovering an Empty or Wiped Install Directory](#8-recovering-an-empty-or-wiped-install-directory)
9. [Troubleshooting](#9-troubleshooting)
10. [Private Repository: Auth on the VPS](#10-private-repository-auth-on-the-vps)
11. [Command Reference](#11-command-reference)

---

## 1. The One Rule

> **The database lives in `data/tgvpanel.db`, and git tracks that file.**
> Never let git "restore" it. Never copy it with `cp`. Always back it up with
> `VACUUM INTO`.

Everything else on this page follows from that single fact.

Your live state — the things that must survive every sync:

| Path | What it is | If you lose it |
| --- | --- | --- |
| `data/tgvpanel.db` | Users, servers, orders, settings | **All panel data gone** |
| `data/backups/` | Automatic pre-migration backups | No rollback available |
| `.tgvpanel-secret` | AES-256-GCM keys for stored credentials | Every encrypted credential becomes unreadable — **unrecoverable** |
| `.env` | Your port, paths, API keys | Panel misconfigures on restart |
| `node_modules/` | Installed dependencies | Must reinstall |

---

## 2. Why This Is Dangerous

`data/tgvpanel.db` is committed to the repository. That means ordinary git
commands treat your **production database as a source file**, and will happily
overwrite it with the pristine copy from the repo.

These three commands are the usual culprits. The first one is the most
common — it reads like "discard my local changes", but here that means
"discard my customers".

| Command | What actually happens |
| --- | --- |
| `git checkout -- data/tgvpanel.db` | Database reverted to the repo copy. **Live data destroyed.** |
| `git reset --hard` | Same, for every tracked file including the database. |
| `git clean -fdx` | Deletes untracked files — including `.tgvpanel-secret`. Credentials orphaned forever. |
| `cp data/tgvpanel.db backup.db` | Backup **silently incomplete** (see below). |

### The WAL trap

SQLite runs in **WAL mode**. Recent writes sit in `data/tgvpanel.db-wal` until a
checkpoint folds them into the main `.db` file. So a plain `cp` of the `.db`
file captures a stale snapshot.

This is not theoretical. On a test instance the main file was 356 KB while a
**370 KB `-wal` file** held the actual data:

```
$ cp data/tgvpanel.db /tmp/backup.db          # naive copy
$ sqlite3 /tmp/backup.db 'SELECT MAX(version) FROM schema_migrations'
5                                             # ← should be 13! data missing

$ sqlite3 data/tgvpanel.db "VACUUM INTO '/tmp/backup.db'"   # correct
$ sqlite3 /tmp/backup.db 'SELECT MAX(version) FROM schema_migrations'
13                                            # complete
```

**`VACUUM INTO` is the only correct way to copy a live SQLite database.** It
produces a single self-contained file with no `-wal` dependency, and it works
while the service is running.

---

## 3. One-Time Setup

Run on the VPS, in your install directory (often `/opt/TGVPANEL` or
`/root/TGVPANEL` — check with `systemctl cat tgvpanel | grep WorkingDirectory`).

### 3.1 Confirm the checkout

```bash
cd /opt/TGVPANEL
git remote -v          # should point at your repo
git status --short     # note which files are modified
```

You will likely see `M data/tgvpanel.db`. **That is normal and expected** — it is
your live data diverging from the repo copy. Do not "fix" it.

### 3.2 Install the sync script

The script ships in the repo at `scripts/sync-from-github.sh`. Give it the
executable bit:

```bash
sudo chmod +x scripts/sync-from-github.sh
```

It works from **any** of these locations — it finds the install by asking git,
not by assuming its own position:

| Where you put it | Works |
| --- | --- |
| `scripts/sync-from-github.sh` (repo layout) | ✅ |
| `./sync.sh` at the repo root | ✅ |
| `/usr/local/bin/sync` as a symlink | ✅ |
| Anywhere, with `TGVPANEL_DIR=/opt/tgvpanel` | ✅ |

> **If you get `[FAIL] Not a git checkout: /opt`** you are running an older
> copy of the script (before this was fixed). Grab the current one:
>
> ```bash
> cd /opt/tgvpanel
> sudo git fetch origin
> sudo git show origin/main:scripts/sync-from-github.sh > sync.sh
> sudo chmod +x sync.sh
> ```

### 3.3 Verify prerequisites

```bash
node -v                 # need 20+
command -v sqlite3      # optional, but makes backups faster
systemctl is-active tgvpanel
```

---

## 4. Daily Workflow: Sync Code Edits

### Step 1 — Edit files on GitHub

Use the web editor: open a file → pencil icon → commit to `main`.
You can add, modify, rename, or delete files. Do **not** upload a database file.

### Step 2 — Preview the change on the VPS

```bash
cd /opt/TGVPANEL
sudo ./scripts/sync-from-github.sh main --dry-run
```

This backs up the database first, then prints exactly which commits and files
would change — and then stops without modifying anything.

```
[SYNC] Backing up data/tgvpanel.db -> data/backups/pre_sync_20261111T075233Z.db
[ OK ] Backup verified: data/backups/pre_sync_20261111T075233Z.db (356K)
--- Incoming changes ---
  f31fd82 web edits: view tweak, new partial, delete a file
--- Files that will be updated ---
   views/users/store.ejs          |   2 +-
   views/partials/from-github.ejs |   1 +
[ OK ] Dry run complete. Nothing was changed.
```

### Step 3 — Apply

```bash
sudo ./scripts/sync-from-github.sh main
```

### Step 4 — Verify

```bash
sudo systemctl status tgvpanel --no-pager
sudo journalctl -u tgvpanel -n 40 --no-pager | grep -iE "error|migration"
```

Then load the panel in your browser.

### Updating the script itself

If a future edit changes `scripts/sync-from-github.sh`, grab the new version
first so you run the fixed logic:

```bash
sudo git fetch origin
sudo git checkout origin/main -- scripts/sync-from-github.sh
```

---

## 5. What the Script Actually Does

| # | Step | Why |
| --- | --- | --- |
| 1 | `VACUUM INTO data/backups/pre_sync_*.db` | WAL-safe, point-in-time backup |
| 2 | `PRAGMA integrity_check` on the backup | A corrupt backup is worse than none — abort if it fails |
| 3 | `git fetch`, show incoming commits + file diff | You see what is about to change |
| 4 | Refuse if tracked **code** is dirty | Prevents a merge clobbering uncommitted local edits |
| 5 | `git merge --ff-only` | Safe fast-forward; never rewrites your dirty database |
| 6 | Fallback: checkout tracked files only | Used when history diverged; excludes `data/` and `.env` |
| 7 | `npm install`, `npm run build` | Dependencies and TypeScript |
| 8 | `npm run migrate` | Schema only — **existing rows preserved** |
| 9 | Restart the service | Pick up new code |

Guarantees:

- **`data/`, `.env`, `.tgvpanel-secret` are never written by git.**
- The script **aborts before changing anything** if it cannot back up.
- `--dry-run` is fully read-only apart from creating the backup.

The script never runs `checkout -- data/`, `reset --hard`, or `clean -fdx`.

---

## 6. Manual Commands (No Script)

If you prefer to do it by hand, or the script is unavailable. **Copy these
exactly** — the ordering matters.

```bash
cd /opt/TGVPANEL

# 1. Stop the panel (also checkpoints the WAL into the .db file)
sudo systemctl stop tgvpanel

# 2. Back up the database correctly (NOT cp)
sudo sqlite3 data/tgvpanel.db "VACUUM INTO 'data/backups/manual_$(date +%F_%H%M).db'"
#    No sqlite3 CLI? Use Node instead:
#    sudo node --no-warnings -e "const {DatabaseSync}=require('node:sqlite');
#      new DatabaseSync('data/tgvpanel.db').exec(\"VACUUM INTO 'data/backups/manual.db'\")"

# 3. Verify the backup opens and has your schema version
sudo sqlite3 data/backups/manual_*.db 'PRAGMA integrity_check; SELECT MAX(version) FROM schema_migrations;'

# 4. Back up secrets
sudo cp -a .tgvpanel-secret .tgvpanel-secret.bak-$(date +%F)

# 5. Pull the code
sudo git fetch origin
sudo git merge --ff-only origin/main

# 6. Rebuild and migrate
sudo npm install
sudo npm run build
sudo npm run migrate

# 7. Start
sudo systemctl start tgvpanel
sudo systemctl status tgvpanel --no-pager
```

### If step 5 refuses to fast-forward

`git merge --ff-only` fails when the VPS has its own commits. Recover **without
touching data**:

```bash
# See what is blocking it
git log --oneline origin/main..HEAD

# Safest: park local code edits, then sync
sudo git stash push -m "vps-local-$(date +%F)" -- src lib views public scripts docs
sudo git merge --ff-only origin/main
```

Your `data/` and `.env` are untouched by `stash` because they are not in that
path list.

---

## 7. Backups and Restore

### Taking a backup (any time, service can stay up)

```bash
cd /opt/TGVPANEL
sudo sqlite3 data/tgvpanel.db "VACUUM INTO 'data/backups/manual_$(date +%F_%H%M).db'"
```

### Listing backups

```bash
ls -lh data/backups/
```

### Restoring

```bash
cd /opt/TGVPANEL
sudo systemctl stop tgvpanel

# Pick the backup you want
ls -lh data/backups/

sudo cp data/backups/pre_sync_YYYYMMDDTHHMMSSZ.db data/tgvpanel.db

# CRITICAL: remove stale WAL/SHM or they replay over your restore
sudo rm -f data/tgvpanel.db-wal data/tgvpanel.db-shm

sudo systemctl start tgvpanel
```

> Removing `-wal` and `-shm` is **not optional**. A leftover WAL replayed
> against a restored database corrupts it.

### Verifying a backup without restoring it

```bash
sqlite3 data/backups/pre_sync_*.db \
  'PRAGMA integrity_check; SELECT MAX(version) FROM schema_migrations;'
```

`integrity_check` must print `ok`.

---

## 8. Recovering an Empty or Wiped Install Directory

If `sync-from-github.sh` reports something like:

```
[WARN] No database found; continuing (fresh install?)
...
[WARN] Local uncommitted changes to tracked code files:
         D app.js
         D lib/db/database.js
         D views/users/login.ejs
         ...
[FAIL] Commit or stash these on the VPS first.
```

…then every tracked file in your install directory is **deleted**. This is not
an uncommitted edit; it means the directory was emptied (`rm -rf *`, a failed
move, or the script run against the wrong folder).

### Why git cannot fix this alone

| Thing | In git? | Restorable by `git checkout`? |
| --- | --- | --- |
| Code (`app.js`, `src/`, `views/`, `lib/`…) | ✅ yes | **Yes** |
| `data/tgvpanel.db` — your database | ⚠️ only the pristine template | **No** — restoring gives you an empty panel |
| `.tgvpanel-secret` — credential keys | ❌ gitignored | **No** — and without it, stored credentials are unreadable forever |
| `.env` | ❌ gitignored | **No** |

### Step 1 — Find your data before touching anything

```bash
cd /opt/tgvpanel
ls -la data/ .tgvpanel-secret .env 2>&1
```

If `data/tgvpanel.db` exists, **your data is safe** — only code is missing.

If it is gone, search before restoring anything (do this first, before any git
command creates a fresh database on top of the old path):

```bash
find / -name 'tgvpanel.db' -o -name 'pre_sync_*.db' -o -name 'tgvpanel.db-*' 2>/dev/null
```

Also check for a surviving `-wal` file — it can hold data that is not yet in the
main file:

```bash
ls -la data/tgvpanel.db-wal data/tgvpanel.db-shm 2>/dev/null
```

If you find `tgvpanel.db` **and** its `-wal`, keep them together. Copying the
`.db` without the `-wal` loses the newest writes (see [§2](#the-wal-trap)).

### Step 2 — Restore the code

This restores **only tracked files** from the repository. It does not touch
`data/`, `.env`, or `.tgvpanel-secret`.

```bash
cd /opt/tgvpanel
git checkout main -- .
git status --short          # expect: only sync.sh, data/, .env untracked
```

### Step 3 — Put the data back (only if step 1 showed it missing)

```bash
# If you found a copy elsewhere:
mkdir -p data
cp /path/to/found/tgvpanel.db data/tgvpanel.db
# If you also found its -wal, copy that too, otherwise remove any stale one:
cp /path/to/found/tgvpanel.db-wal data/tgvpanel.db-wal 2>/dev/null || true

# If you have a backup from data/backups/:
cp data/backups/pre_sync_YYYYMMDDTHHMMSSZ.db data/tgvpanel.db
rm -f data/tgvpanel.db-wal data/tgvpanel.db-shm
```

Then verify it opens:

```bash
sqlite3 data/tgvpanel.db 'PRAGMA integrity_check; SELECT COUNT(*) FROM users;'
```

### Step 4 — Restore secrets

```bash
# From your own backup:
cp /path/to/.tgvpanel-secret .tgvpanel-secret
chmod 600 .tgvpanel-secret
```

> If `.tgvpanel-secret` is lost **and** you have no backup, stored credentials
> (reseller API keys, server root passwords) cannot be decrypted. The panel will
> run, but those values are gone and must be re-entered. Keep a copy of this
> file off-server.

### Step 5 — Rebuild and start

```bash
npm install
npm run build
npm run migrate
sudo systemctl start tgvpanel
sudo journalctl -u tgvpanel -n 40 --no-pager
```

### Prevention

- Keep `data/` **outside** the git checkout, or at least never `rm -rf` the
  install directory. `TGVPANEL_DATA_DIR=/var/lib/tgvpanel` in `.env` moves the
  database out of the repo entirely — the cleanest long-term fix.
- Copy `.tgvpanel-secret` and `data/backups/` somewhere off-server regularly.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Every file shows `D` (deleted) | Install directory was emptied | See [§8](#8-recovering-an-empty-or-wiped-install-directory) — do not run `git checkout` before checking for your database |
| `Not a git checkout: /opt` | Old script copied to the repo root; it walked up one level | Update the script ([§3.2](#32-install-the-sync-script)), or run `cd /opt/tgvpanel && sudo ./sync.sh main` |
| `Database backup failed` | No `sqlite3` CLI and no `node:sqlite` | Install `sqlite3`, or use Node 22+ |
| `Local uncommitted changes to tracked code files` | Someone edited code on the VPS | Commit, or `git stash` those paths |
| `merge --ff-only` refuses | VPS has local commits | See [§6 fallback](#if-step-5-refuses-to-fast-forward) |
| `tsc: not found` | TypeScript not installed | `sudo npm install` then `sudo npm run build` |
| Build fails but panel runs | Committed `lib/` is used | Will still boot; fix before next sync |
| Panel 502 after sync | Service failed to start | `sudo journalctl -u tgvpanel -n 60 --no-pager` |
| Login broken, credentials unreadable | `.tgvpanel-secret` changed or lost | Restore from your backup of it — cannot be regenerated |
| Migration failed mid-way | Schema conflict | Restore the `pre_sync_*.db` backup |
| Data looks old after restore | Stale `-wal` replayed | `rm -f data/tgvpanel.db-wal data/tgvpanel.db-shm` and restart |

### Reading the log

```bash
sudo journalctl -u tgvpanel -n 100 --no-pager
sudo journalctl -u tgvpanel -f            # follow live
```

---

## 10. Private Repository: Auth on the VPS

If your repo is **private**, `git fetch` on the VPS needs credentials. A
browser-based GitHub edit does not grant the VPS access by itself.

**Recommended — SSH deploy key (read-only, per-repository):**

```bash
# On the VPS
ssh-keygen -t ed25519 -C "tgvpanel-deploy" -f ~/.ssh/tgvpanel_deploy -N ""

cat ~/.ssh/tgvpanel_deploy.pub
```

Then on GitHub: **repo → Settings → Deploy keys → Add deploy key**, paste the
public key, leave *Allow write access* **unchecked**.

Point the repo at SSH:

```bash
cd /opt/TGVPANEL
sudo git remote set-url origin git@github.com:YOURUSER/YOURREPO.git
sudo ssh -T git@github.com      # expect: "successfully authenticated"
sudo -E git fetch origin
```

**Alternative — Personal Access Token (fine-grained, read-only):**

```bash
sudo git remote set-url origin https://YOURUSER:YOUR_TOKEN@github.com/YOURUSER/YOURREPO.git
```

> Warning: this stores the token in `.git/config` in plaintext. Restrict it to
> this one repository, read-only, with a short expiry. A deploy key is safer.

Once configured, `git fetch` works unattended inside `scripts/update.sh` too.

---

## 11. Command Reference

```bash
# ---------- routine sync ----------
cd /opt/TGVPANEL
sudo ./scripts/sync-from-github.sh main --dry-run    # preview
sudo ./scripts/sync-from-github.sh main              # apply

# ---------- sync a different branch ----------
sudo ./scripts/sync-from-github.sh arena/d867a420-panel

# ---------- backup now ----------
sudo sqlite3 data/tgvpanel.db "VACUUM INTO 'data/backups/manual_$(date +%F_%H%M).db'"
ls -lh data/backups/

# ---------- verify a backup ----------
sqlite3 data/backups/pre_sync_*.db 'PRAGMA integrity_check; SELECT MAX(version) FROM schema_migrations;'

# ---------- restore ----------
sudo systemctl stop tgvpanel
sudo cp data/backups/pre_sync_YYYYMMDDTHHMMSSZ.db data/tgvpanel.db
sudo rm -f data/tgvpanel.db-wal data/tgvpanel.db-shm
sudo systemctl start tgvpanel

# ---------- health ----------
sudo systemctl status tgvpanel --no-pager
sudo journalctl -u tgvpanel -n 50 --no-pager
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/login

# ---------- never run these ----------
# git checkout -- data/tgvpanel.db
# git reset --hard
# git clean -fdx
# cp data/tgvpanel.db somewhere.db
```

---

## Quick Reference Card

```
 ┌──────────────────────────────────────────────────────────────┐
 │  SAFE:    VACUUM INTO ... for backups                        │
 │  SAFE:    git merge --ff-only                                │
 │  SAFE:    scripts/sync-from-github.sh                        │
 │                                                              │
 │  FATAL:   git checkout -- data/tgvpanel.db                   │
 │  FATAL:   git reset --hard                                   │
 │  FATAL:   git clean -fdx        (kills .tgvpanel-secret)     │
 │  WRONG:   cp data/tgvpanel.db   (misses the -wal file)       │
 └──────────────────────────────────────────────────────────────┘
```
