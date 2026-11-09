# Agent handoff — TGVPANEL / Panel

_Last updated: 2026-11-09 (UTC). Read this alongside `README.md` and the relevant docs; it is a snapshot, not a substitute for checking the current worktree._

## What the user asked for in this session

The user requested a file that another agent can use to understand what has been done, what was edited, and how to continue, then requested a backup. **No feature change or bug fix was requested in this session.** The only repository file changed in this session is this handoff file. The user wants a GitHub restore point containing source plus the tracked SQLite database (see backup status below).

## Git / change state at handoff

- Repository: `sigmaboy6942069/Panel`, checkout at `/home/user/Panel`.
- Current branch in this session: `arena/6609e824-panel`. Work on this branch if continuing this Arena session; do not switch or push to another branch.
- Starting commit: `bf32d2ac7c0afb1024e65dfe5f55547e8a9407a8` (`Merge pull request #2 from sigmaboy6942069/arena/f4eb0b6d-panel`). At the start of this session, the working tree was clean and this branch matched `main` / `origin/main`. The checkout started shallow; `git fetch --unshallow origin` was run during the backup attempt, so full reachable history is now available locally.
- **Files changed in this session:** `AGENT_HANDOFF.md` (new; updated to record the backup attempt and restore point). No existing source, DB, configuration, dependency, or test files were edited. No PR, migration, or server startup was performed. Check the current commit and remote state with `git log -1 --oneline` and `git ls-remote --heads origin arena/6609e824-panel`.
- Always check fresh state before changing anything: `git status --short --branch && git diff --stat && git log -5 --oneline`.

### Prior merged work (already in the starting commit; not done in this session)

- [PR #1](https://github.com/sigmaboy6942069/Panel/pull/1), merged 2026-11-09: introduced reseller-related source, generated `lib/` code, migrations, routes, UI, and documentation. Consult its file list/diff for exact historical edits; the PR had no descriptive body.
- [PR #2](https://github.com/sigmaboy6942069/Panel/pull/2), merged 2026-11-09: removed provider-specific prefixes from reseller API key examples in the reseller client, UI, examples, and docs. It is already part of the baseline, not pending work.
- Do not interpret those PRs as evidence that the current session made those edits.

## Backup status (requested later in this session)

- The user selected a **private GitHub repository**, including source and `data/tgvpanel.db`, but excluding secrets and Git internals. Attempted to create `sigmaboy6942069/Panel-backup-2026-11-09` with `gh repo create ... --private`; GitHub returned `GraphQL: Resource not accessible by integration (createRepository)`. No separate backup repository was created. The GitHub connection needs repository-creation permission to make one; do not ask the user for credentials or tokens.
- Instead, this session uses the existing **private** [`sigmaboy6942069/Panel`](https://github.com/sigmaboy6942069/Panel) repository. The restore-point branch is `arena/6609e824-panel`. The intended independently downloadable snapshot is a GitHub Release called `backup-2026-11-09-062153`, attached to that branch's backup commit. **Verify the branch and release on GitHub before relying on them**: `git ls-remote --heads origin arena/6609e824-panel` and `gh release view backup-2026-11-09-062153 --repo sigmaboy6942069/Panel`.
- The archive `/home/user/Panel-backup-2026-11-09.tar.gz` contains the tracked files (including this handoff and the tracked SQLite database) under `Panel/`; its checksum is `/home/user/Panel-backup-2026-11-09.tar.gz.sha256`. The GitHub release is intended to carry copies of both files. The archive excludes `.git/`, `node_modules/`, ignored runtime files, and local secrets.
- To recover from later code changes, download/extract the release asset or ask an agent to restore files from the release tag/backup commit **in a new commit**, keeping later history rather than force-pushing. The release asset is a source snapshot, not a production backup of live VM/container disks, untracked runtime state, or deployment secrets. If the user still wants a separate repository, reconnect GitHub with repository-creation access and create one privately, then verify privacy and contents.

## Project orientation

TGVPANEL is a Node.js + TypeScript/Express/EJS control panel for QEMU/KVM VMs and LXC containers with a standalone node agent, SQLite database, REST API, multi-node management, and an upstream reseller integration. `README.md` is the main introduction; `package.json` contains the commands.

| Location | Purpose |
|---|---|
| `app.js` | Express/HTTP/WebSocket entry point and legacy KVM routes; imports compiled modules from `lib/`. |
| `src/context.ts`, `src/api/` | Unified runtime, REST API (`/api/v1/*`), and web routes. |
| `src/services/` | Virtualization, nodes, storage, networking, backups, migrations, monitoring, reseller. |
| `src/node-agent/`, `src/security/`, `src/db/` | Remote agent, security/auth, SQLite schema/legacy importer. |
| `lib/` | Tracked JavaScript and declaration files compiled from `src/`; rebuild when changing TS and check whether generated files need inclusion. |
| `views/`, `public/` | EJS admin/user templates and browser assets. |
| `data/tgvpanel.db` | **Tracked SQLite file**; avoid inadvertently modifying/committing live DB state. |
| `tests/run-all.js` | Acceptance/integration suite (uses an isolated temporary copy of the tracked DB). |
| `menu.sh`, `scripts/` | Installer/setup/update flows; these may affect the host. |
| `docs/` | Multi-node setup, migration notes/checklist, reseller integration, optional PostgreSQL path. |

Important existing documentation: `docs/MULTINODE_SETUP.md` for node deployment, `docs/RESELLER_INTEGRATION.md` for reseller flow, and `docs/MIGRATION_CHECKLIST.md` for historical feature status. The README still says migrations `v001`–`v009` and 20 suites, but the current `src/db/migrations.ts` defines **v001–v012** and `tests/run-all.js` contains **T01–T25**. Verify actual code rather than assuming older doc counts are current. This discrepancy was observed, **not fixed** by this handoff request.

## Setup / validation for the next agent

- Observed environment: Node `v22.22.3`, npm `10.9.8`; `node_modules/` was absent. **No build or test was run in this session**, so there is no verified pass/fail result to report.
- Typical workflow: `npm ci`, `npm run build`, `npm test`. Native dependencies (`sqlite3`, `node-pty`) may need build tools/Node headers. See the README's offline Node-header note if installation fails.
- `npm test` copies `data/tgvpanel.db` into a temporary test directory and exercises HTTP/WebSocket/agent components. Inspect tests and environment requirements before running on a production host.
- Avoid `npm run migrate` or starting the actual panel against the tracked database unless deliberately needed; use an isolated DB/data dir via `TGVPANEL_DB_PATH` / `TGVPANEL_DATA_DIR` for experiments.
- Do not include `.env`, secret-vault files, keys, or runtime DB artifacts in handoff notes or commits; see `.gitignore` and `.env.example`.

## Next steps

1. Ask the user for the actual feature/bug/task they want next (there is none specified in this conversation beyond writing this file).
2. Recheck `git status`, inspect the relevant source and docs, make scoped changes, and record any new edits, verification results, open questions, and follow-up steps here so future agents have an accurate handoff.
3. If a task touches TypeScript, rebuild the tracked `lib/` output and review the generated diff. Verify with tests where feasible and state any tests you could not run.

This file only documents repository facts observed during this session and prior merged PR metadata; it does not claim knowledge of other agents' private plans or unobserved deployment state.
