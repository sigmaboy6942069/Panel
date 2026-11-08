# TGVPANEL Unified Migration & Implementation Checklist

Status Legend: `Not started` | `In progress` | `Implemented` | `Tested` | `Blocked`

---

## Phase-by-Phase Execution Status (Part 24)

| Phase | Milestone | Status | Verification & Notes |
|---|---|---|---|
| **Phase 1** | Audit codebases & host capabilities | `Tested` | Documented in `docs/PHASE1_SOURCE_AUDIT.md`; legacy KVM bugs identified and patched in `app.js`. |
| **Phase 2** | Design unified architecture & schema | `Tested` | Unified adapter pattern (`KVMAdapter` + `LXCAdapter` + `VirtualizationManager` + `InstanceManager`) & PostgreSQL 15+ guide (`docs/POSTGRESQL_MIGRATION.md`). |
| **Phase 3** | Back up `data/tgvpanel.db` & build migrations | `Tested` | Automatic pre-migration backups (`tgvpanel_pre_migration_*.db`), automatic legacy DB & secret-vault file migration, transactional migrations `v001`–`v009` + `importHvmDatabase` tested in **T01** & **T03**. |
| **Phase 4** | Build Node.js + TypeScript Node Agent | `Tested` | `src/node-agent/*.ts` (`agent.ts`, `authentication.ts`, `command-runner.ts`, `container-manager.ts`, `container-console.ts`, `shell-manager.ts`, `snapshot-manager.ts`, `transfer-manager.ts`); HMAC + replay defense (`409`) tested in **T07** & **T09**. |
| **Phase 5** | Build Virtualization Manager (`KVMAdapter` + `LXCAdapter`) | `Tested` | Capability profiles, lifecycle hooks, Linux `/proc/<pid>` telemetry, sharing, expiration, and honest host binary checks tested in **T06** & **T08**. |
| **Phase 6** | Integrate nodes, LXC templates, networking, ports, firewall, backups, migrations & monitoring | `Tested` | `NodeManager`, `StorageManager`, `NetworkManager`, `BackupSnapshotManager`, `MigrationManager`, `MonitoringService` tested in **T07**, **T10**, **T11**. |
| **Phase 7** | Integrate unified REST API v1, Auth, 2FA, RBAC, CSRF, API Keys, Webhooks & Impersonation | `Tested` | `src/api/v1/router.ts`, `src/api/web-routes.ts`, `src/security/*` tested in **T02**, **T04**, **T05**, **T06**, **T11**. |
| **Phase 8** | Upgrade Admin (23 sidebar items) & User EJS Frontend | `Tested` | Preserved EJS + dark/light CSS variables, local `/vendor/xterm/`, `public/js/tgvpanel-v3.js`, all 23 Admin routes + User routes verified `200 OK` with `TGVPANEL` branding in **T12**. |
| **Phase 9** | Build `scripts/install.sh` & `scripts/update.sh` | `Tested` | Capability detection (`/dev/kvm`, `qemu-*`, `lxc-*`, `cgroups v2`), 4 install modes, offline Node header support, `tgvpanel.service` systemd units, syntax verified via `bash -n`. |
| **Phase 10** | Run acceptance tests, security audit & final verification | `Tested` | `npm test` -> **25/25 Acceptance Suites Passed** (`T01`–`T25`); zero plaintext secrets. |

---

## Detailed Feature Migration Matrix (TGVPANEL Unified Platform)

| Capability Area | Source | Target Module(s) | Status | Notes / Host Constraints |
|---|---|---|---|---|
| Express + EJS Foundation & Branding (`TGVPANEL`) | Core KVM Panel | `app.js`, `views/**`, `public/**` | `Tested` | Preserved 100%; rebranded UI, routes, database (`data/tgvpanel.db`), secret vault (`.tgvpanel-secret`), and docs to `TGVPANEL` (**T01**, **T02**, **T12**). |
| Users, Roles (`admin`/`subadmin`/`operator`/`user`/`readonly`), Discord OAuth | Unified Auth | `app.js`, `src/security/middleware.ts` | `Tested` | Preserved Discord OAuth; added granular RBAC & audited user impersonation. |
| Legacy User/VPS/Node/Port Importer & Werkzeug Rehash | Legacy Importer | `src/db/hvm-importer.ts`, `app.js` | `Tested` | Verifies `pbkdf2:sha256` & `scrypt`, auto-upgrades to `bcrypt` on login (**T03**). |
| TOTP Two-Factor Authentication (RFC 6238 + QR) | Security Module | `src/security/crypto-vault.ts`, `views/users/login-2fa.ejs` | `Tested` | End-to-end setup (`issuer=TGVPANEL`), QR generation, and 2-step login tested (**T05**). |
| Secret Vault (`.tgvpanel-secret`), AES-256-GCM, CSRF, Scoped PATs | Security Module | `src/security/crypto-vault.ts`, `middleware.ts` | `Tested` | Auto-migrates legacy secret vaults to `.tgvpanel-secret`; encrypts VM/LXC/node credentials (**T02**, **T04**). |
| QEMU/KVM Lifecycle, Proxmox VE 8 & 9 Templates, ISO, Cloud-Init, CPU/SMBIOS, VM Edit | KVM Engine | `app.js`, `KVMAdapter.ts`, `views/admin/vm-create.ejs` | `Tested` | Built-in Proxmox VE 8 (Bookworm) & Proxmox VE 9 (Trixie) hypervisor templates, unattended Cloud-Init bootstrap (`pve-no-subscription`, `vmbr0`, serial GRUB), native ISO-9660 `cidata` fallback, QEMU NAT `:8006` Web UI forwarding + collision avoidance, encrypted reinstall, Linux `/proc/<pid>` telemetry, persistent VM deletion (**T06**, **T08**, **T11**, **T20**, **T24**). |
| Complete LXC Lifecycle (create/start/stop/restart/freeze/unfreeze/suspend/reinstall/resize/renew/share) | LXC Engine | `LXCAdapter.ts`, `container-manager.ts` | `Tested` | Native `lxc-*` via allowlisted `execFile`, ext4 loop disk quotas, KVM nesting, and cgroup v2 `init.scope` + `hkvm.lxc` full controller delegation with `"domain threaded"` / `"domain invalid"` self-healing (**T13**–**T19**). |
| Centralized LXC OS Template Catalog (19 distros + custom upload) | Storage Module | `migrations.ts`, `StorageManager.ts`, `/admin/lxc-templates` | `Tested` | Ubuntu, Debian, Alpine, AlmaLinux, Rocky, Fedora, Arch, Kali, OpenSUSE, CentOS Stream, Devuan, Void, BusyBox (**T01**, **T10**, **T13**). |
| Real xterm.js Consoles (KVM Serial, KVM SSH, LXC PTY, Restricted Admin Node Shell) | Console Module | `context.ts`, `container-console.ts`, `shell-manager.ts` | `Tested` | Bundled local `/vendor/xterm/`; real `node-pty` WebSocket shell tested (**T12**, **T14**). |
| Storage Pools, Network Bridges/NAT, IPv4/IPv6 CIDR, Port Forwards, Firewall Rollback | Storage & Network | `StorageManager.ts`, `NetworkManager.ts` | `Tested` | Pool/IP/port/firewall CRUD, DNS relay, Netplan sync & `iptables-save`/`iptables-restore` rollback (**T10**, **T16**, **T17**). |
| Unified Snapshots, SHA-256 Verified Backups & Offline Verified Migration | Backup & Migration | `BackupSnapshotManager.ts`, `MigrationManager.ts` | `Tested` | Real `tar.gz` backup + SHA-256 verification & 7-stage offline migration with pre-commit rollback (**T11**, **T14**). |
| Multi-Node Agent, Cloudflare Tunnel (No-IPv4) Support, 1-Command Pairing (`--join`), TOFU TLS Pinning, Push Heartbeats, Remote Storage/Ports/Firewall, Circuit Breakers & Monitoring | Nodes & Monitoring | `NodeClient.ts`, `MonitoringService.ts`, `agent.ts`, `menu.sh` | `Tested` | Cloudflare Tunnel / Reverse Proxy domain-only onboarding without public IPv4, combined system Root CA + TOFU X.509 pinning, single-use join tokens (`TGVPANEL_ADVERTISE_URL`), active agent->controller heartbeats, remote `statfs`/NAT/firewall/custom-template staging, multi-node `sync-host`, cross-node backup restore & bridged WSS PTY (**T07**, **T11**, **T21**, **T22**, **T25**). |
