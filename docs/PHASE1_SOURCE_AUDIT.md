# TGVPANEL — Phase 1: Complete Source Audit & Unification Mapping

## 1. Executive Summary
This document captures the Phase 1 architecture audit and unification mapping for **TGVPANEL**:
- **Primary Express/EJS KVM Foundation**: Located at repository root (`/home/user/TGVPANEL`), built on Node.js + Express + EJS + SQLite (`data/tgvpanel.db`) + `ws` + `ssh2`, managing QEMU/KVM virtual machines.
- **Unified LXC & Multi-Node Feature Source**: Migrated natively into **TGVPANEL** (Node.js + Express + TypeScript modules + EJS UI + unified SQLite DB `data/tgvpanel.db` with PostgreSQL migration path + Node.js/TypeScript Node Agent). No separate Python/Flask sidecar is run or reverse-proxied.

---

## 2. Core KVM Foundation Inventory
| Domain | Source File(s) | Existing Capabilities & Audit Notes |
|---|---|---|
| Core HTTP & WS Server | `app.js` | Express 4 + `http.Server` + `ws.Server` on `PORT` (default `8080`), backed by `./data/tgvpanel.db` (overridable via `TGVPANEL_DATA_DIR` / `TGVPANEL_DB_PATH`). |
| Authentication & Sessions | `app.js`, `views/users/login.ejs` | `express-session`, `bcryptjs` password verification, `checkAuth` / `checkAdmin` middleware, `/api/login`, `/api/logout`, `/api/auth/check`. |
| Discord OAuth2 | `app.js`, `views/admin/settings.ejs`, `views/users/profile.ejs` | `/api/discord-enabled`, `/api/discord-auth-url`, `/auth/discord/callback`, `/api/link-discord-account`, `/api/unlink-discord-account`, `/api/discord-account-info`, `discord_settings` & `user_discord_accounts` tables. |
| Licensing | `licenses.js`, `views/license_activation.ejs` | Free edition stub (`isActivated() -> true`, `license_state` table). Preserved intact. |
| KVM Lifecycle | `app.js` | Create (`POST /api/vms`), Start (`POST /api/vms/:vm_id/start`), Stop (`POST /api/vms/:vm_id/stop`), Restart (`POST /api/vms/:vm_id/restart`), Reinstall (`POST /api/vms/:vm_id/reinstall`), Edit (`GET/PUT /api/vms/:vm_id/edit`), Delete (`DELETE /api/vms/:vm_id`). Audit note: `DELETE` & `GET edit/logs` lacked non-admin ownership checks; fixed in V3. Also adding Force Stop, Suspend/Pause & Resume (QMP/SIGSTOP), and Clone. |
| KVM Hardware & Cloud-Init | `app.js` | `CPU_MODELS` (host, max, qemu64, kvm64, core2duo, corei7, skylake, cascadelake, opteron, epyc), `MACHINE_TYPES` (pc, q35, microvm, virt, etc.), SMBIOS type 0/1/2, ACPI, BIOS/UEFI, `qemu-img` qcow2 creation & resize, Cloud-Init `cidata` seed ISO (`genisoimage`/`mkisofs`/fallback ISO9660 builder) for NAT DHCP & Static Public IPv4 netplan v2. |
| KVM Console & SSH | `app.js`, `views/*/vm-console.ejs`, `views/*/vm-ssh.ejs` | Serial console (`-nographic -serial mon:stdio` + log streaming over WebSocket `/console/:id`) and browser WebSocket SSH relay (`/ssh-terminal` via `ssh2` + xterm.js). Audit note: serial console WS input only appended to log file rather than writing to `qemuStdins`; fixed in V3 + WS session auth added. |
| KVM Snapshots, ISOs & Templates | `app.js`, `views/admin/templates*.ejs` | Built-in `OS_TEMPLATES` (Ubuntu 22/24, Debian 12, Fedora 40, CentOS 9, AlmaLinux 9) + custom `os_templates`, cache download/clear, ISO list & attach/detach (`/api/vms/:vm_id/iso/*`), `vm_snapshots` table (upgraded in V3 to execute real `qemu-img snapshot -c/-a/-d/-l`). |
| KVM Stats | `app.js` | `GET /api/vms/:vm_id/stats`. Audit note: used Windows `shell: 'cmd'` and `2>nul`; fixed in V3 to use Linux `/proc/<pid>` & `ps` metrics + disk/network stats. |

---

## 3. HVM V9 Feature Inventory (Source to Migrate)
| Domain | Source File(s) | Capabilities Migrated into TGVPANEL |
|---|---|---|
| LXC VPS Lifecycle | `hvm/hvm.py`, `hvm/api.py` | Create (async background installer with live progress), Start, Stop, Force Stop, Restart, Freeze, Unfreeze, Suspend (with reason & suspension history), Unsuspend, Reinstall, Resize (CPU/RAM/Swap/Disk), Update config, Delete, Bulk Start, Bulk Stop, Ownership transfer, VPS Sharing (`shared_with`), Resource-monitor Whitelist (`whitelisted`). |
| LXC Container Configuration | `hvm/hvm.py` | Container name/ID, hostname, OS catalog (`OS_OPTIONS`: Ubuntu 20.04/22.04/24.04, Debian 11/12/13, CentOS Stream 9/10, AlmaLinux 8/9/10, Rocky 8/9/10, Fedora 40-43, Kali), CPU cores/pinning/limits/shares/priority, RAM hard limit, 3-layer Swap control (LXC config + cgroup v1/v2 + guest), Disk rootfs quota, Mount points, Nesting/Privileged/AppArmor security profiles, `/dev/fuse` & `/dev/net/tun`, Root password & distro-aware OpenSSH setup (`apt` vs `dnf`/`yum`). |
| LXC Container Management | `hvm/hvm.py` | Live container status, process list, resource metrics, logs, PTY interactive container shell (`lxc exec` / `lxc-attach`), command execution, container filesystem browser/editor/upload/download/chmod/archive (`/files/*`). |
| LXC OS Templates & Icons | `hvm/hvm.py`, `hvm/api.py` | Centralized LXC image/template catalog, remote image verification (`images:` & `ubuntu:`), template download/caching with progress & SHA-256 verification, safe deletion, custom OS icons (`os_icons`). |
| Node Agent (`node.py`) | `hvm/node.py` | Standalone agent migrated to TypeScript (`src/node-agent/`): `/api/health`, `/api/ping`, `/api/info`, `/api/system/check` (reports LXC + QEMU/KVM versions & `/dev/kvm`), `/api/host/stats`, `/api/container/list`, `/api/container/stats`, `/api/container/{start,stop,restart,freeze,unfreeze,create,delete,exec,config}`, `/api/container/snapshot`, `/api/shell/{open,io,resize,close,list}` (real PTY via `node-pty`), `/api/snapshot/{export,upload,transfers,file/:id}`, HMAC-SHA256 request signing + timestamp/nonce replay protection + TLS/HTTPS support. |
| Node Management & Health | `hvm/hvm.py`, `hvm/api.py` | Multi-node CRUD (capabilities: `kvm`, `lxc`, or `both`), test connection, reconnect, credential rotation, circuit breaker & failure tracking, node health & live stats, running instances per node, admin-only audited Node Console. |
| Networking, IPs & Ports | `hvm/hvm.py`, `hvm/api.py` | Routed public IPv4 (`ip addr` + routed NIC with rollback), Linux bridges & NAT, IPv4/IPv6 pool & static IP allocations, VLANs, MAC generation, per-user port allocations (`port_allocations`), TCP/UDP port forwards (`port_forwards` via LXC proxy devices / `iptables` NAT), custom & bulk port ranges, ingress/egress Mbps rate limits, monthly bandwidth quotas & RX/TX tracking, firewall rule helpers. |
| Live Monitoring & Metrics | `hvm/live_stats_manager.py`, `hvm/static/js/live-stats.js`, `hvm/hvm.py` | Background `LiveStatsManager` in TypeScript (`src/services/monitoring/LiveStatsManager.ts`) + browser WebSocket/polling client (`public/js/live-stats.js`), caching, `MISS_THRESHOLD` missing-instance protection, `vps_metrics` & `node_metrics` historical time-series, threshold alerts & optional auto-suspend. |
| Backups & Snapshots | `hvm/hvm.py`, `hvm/node.py`, `hvm/api.py` | Unified KVM (`qemu-img snapshot` + qcow2 backup archive with SHA-256) and LXC (`lxc snapshot` / `lxc-snapshot` + `lxc export` tarball with SHA-256), snapshot restore/delete/export/upload, scheduled snapshots & backups with retention pruning, panel DB backups (with pre-migration auto-backup, vacuum, restore, download). |
| VPS Migration | `hvm/hvm.py` | Upgraded to real **Offline Snapshot-Transfer Migration** (`vps_migrations` table): stops source -> snapshots & exports tarball with SHA-256 -> streams to target node -> imports & applies config/IP/ports -> verifies target instance -> commits DB -> cleans up source, with full automatic rollback if any pre-commit step fails. |
| Expiration & Renewal | `hvm/hvm.py`, `hvm/api.py` | `expires_at`, `expiration_days`, `auto_suspend_enabled`, renewal history, expiring-soon notifications (3-day warning), auto-suspend background job, admin renewal & expiration management UI. |
| Unified User/Admin Extras | `hvm/hvm.py`, `hvm/api.py` | TOTP Two-Factor Authentication (2FA setup/verify/disable), Password Reset tokens, User & Admin API Keys (`api_keys` with scoped permissions & toggle), Webhooks (`webhooks` with HMAC-signed event delivery), In-panel Notifications (`notifications`), Activity/Audit Logs (`activity_logs`), Maintenance Mode, System Info, Resource Check, and Confirmation-gated Emergency Actions. |

---

## 4. API Inventory
### 4.1 Preserved Core KVM Endpoints
All existing KVM endpoints remain 100% functional for existing EJS pages and scripts:
- Auth & Discord: `POST /api/login`, `POST /api/logout`, `GET /api/auth/check`, `GET /api/discord-enabled`, `GET /api/discord-auth-url`, `GET /auth/discord/callback`, `POST /api/link-discord-account`, `POST /api/unlink-discord-account`, `GET /api/discord-account-info`
- KVM VMs: `GET /api/vms`, `GET /api/admin/vms`, `POST /api/vms`, `GET /api/vms/:vm_id`, `GET/PUT /api/vms/:vm_id/edit`, `POST /api/vms/:vm_id/{start,stop,restart,reinstall}`, `DELETE /api/vms/:vm_id`, `GET /api/vms/:vm_id/{stats,logs,console,snapshots}`, `POST /api/vms/:vm_id/console/command`, `POST /api/vms/:vm_id/snapshots`, `POST /api/vms/:vm_id/iso/{attach,detach}`, `GET /api/vms/:vm_id/iso/status`, `POST /api/ssh/connect`, `POST /api/ssh/command`
- Templates, Metadata & Users: `GET /api/os-templates`, `GET/POST /api/admin/templates`, `PUT/DELETE /api/admin/templates/:id`, `PUT /api/admin/templates/builtin/:key`, `POST /api/admin/templates/:key/download`, `GET /api/admin/templates/cache/info`, `POST /api/admin/templates/cache/clear`, `GET /api/{cpu-models,smbios,network-types,dns-providers,iso-list}`, `GET /api/users/list`, `GET/POST /api/admin/users`, `GET/PUT/DELETE /api/admin/users/:id`, `GET /api/admin/users/:id/discord-info`, `GET/PUT /api/user/profile`, `PUT /api/user/password`, `GET/PUT /api/settings`, `POST /api/settings/:key`, `GET/PUT /api/admin/discord-settings`, `GET /api/admin/dashboard`, `GET /api/admin/activity`, `GET /api/system/status`

### 4.2 Unified TGVPANEL Versioned REST API (`/api/v1/...`)
- `/api/v1/auth/*` — session login/logout, 2FA TOTP enroll/verify/disable, password reset request & confirm, `/me`
- `/api/v1/users/*` — user CRUD, profile, preferences, password reset, API key management
- `/api/v1/instances/*` — unified KVM + LXC instance list, filter, search, detail, common lifecycle (`start`, `stop`, `restart`, `delete`, `reinstall`, `stats`, `logs`, `snapshots`)
- `/api/v1/instances/kvm/*` — KVM-specific creation, ISO attach/detach, boot order, BIOS/UEFI, machine type, SMBIOS, cloud-init, virtual disk resize, suspend/resume, clone
- `/api/v1/instances/lxc/*` — LXC VPS creation, start/stop/restart/freeze/unfreeze/suspend/unsuspend, resize, reinstall, bulk start/stop, renew, expiration, whitelist, share/unshare, password & SSH config, bandwidth quota/usage, container exec, container file manager, offline snapshot migration & progress
- `/api/v1/nodes/*` — node CRUD, capabilities (`kvm`/`lxc`/`both`), test connection, reconnect, credential rotation, circuit breaker reset, health, host stats, storage, networking, audited admin shell
- `/api/v1/storage/*` — storage pools (RAW, QCOW2, dir, LVM, Btrfs, ZFS), capacity/allocated/available metrics, ISO uploads/library, KVM & LXC OS templates
- `/api/v1/network/*` — bridges, IP pools & `ip_allocations` (IPv4/IPv6), routed IPs, VLANs, MAC generator, `port_allocations`, `port_forwards` (single, custom, bulk), bandwidth & firewall rules
- `/api/v1/backups/*` — KVM/LXC instance backups, DB backups, backup schedules & retention, integrity verification, download, restore, delete
- `/api/v1/snapshots/*` — unified & engine-specific snapshots, schedules, export tarball, upload/import tarball, restore, delete
- `/api/v1/monitoring/*` — live stats overview, per-node & per-instance live/historical metrics, alerts, LiveStatsManager status/cache control
- `/api/v1/notifications/*` — list, unread count, mark read, mark all read, delete, clear
- `/api/v1/admin/*` — overview stats, maintenance mode, system info, DB vacuum, resource check, API keys, webhooks, activity/audit logs, confirmation-gated emergency actions, HVM database importer, OpenAPI JSON/HTML docs (`/api/v1/docs`)

---

## 5. Database Schema Inventory & Unification Plan
### Core Tables (`data/tgvpanel.db` — Preserved 100%)
`users`, `vms`, `vm_logs`, `vm_snapshots`, `os_templates`, `settings`, `discord_settings`, `user_discord_accounts`, `license_state`.

### New Unified Tables Added via Versioned Transactional Migrations (`src/db/migrations/`)
1. `schema_migrations` — tracks applied migration versions & checksums
2. `nodes` — local & remote virtualization hosts (`id`, `name`, `hostname`, `ip_address`, `location`, `url`, `is_local`, `verify_ssl`, `status`, `cpu_model`, `cpu_cores`, `ram_total_mb`, `disk_total_gb`, `agent_version`, `lxc_version`, `qemu_version`, `last_seen`, etc.)
3. `node_capabilities` — per-node virtualization engine flags (`supports_kvm`, `supports_lxc`, `kvm_available`, `lxc_available`, `storage_backends`, `network_bridges`)
4. `node_credentials` — per-node unique `api_key_hash`, encrypted `api_key_enc`, `hmac_secret_enc`, `tls_fingerprint`, rotation timestamps
5. `instances` — unified catalog linking both `kvm` (`vm_id`) and `lxc` (`lxc_id`) instances with owner, node, status, resource summary, and tags
6. `lxc_instances` — complete LXC VPS table (`id`, `instance_id`, `user_id`, `node_id`, `container_name`, `hostname`, `os_template`, `os_family`, `cpu_cores`, `cpu_limit`, `cpu_shares`, `ram_mb`, `swap_mb`, `disk_gb`, `storage_pool`, `rootfs_path`, `mount_points`, `privileged`, `nesting`, `security_profile`, `root_password_enc`, `ssh_port`, `ip_address`, `ipv6_address`, `gateway`, `mac_address`, `bridge_name`, `status`, `suspended`, `suspended_reason`, `suspension_history`, `whitelisted`, `shared_with`, `bandwidth_quota_gb`, `bandwidth_used_gb`, `network_ingress_mbps`, `network_egress_mbps`, `network_priority`, `snapshot_limit`, `install_progress`, `install_message`, `notes`, `metadata`, `expires_at`, `expiration_days`, `auto_suspend_enabled`, `last_renewed_at`, `created_at`, `updated_at`)
7. `lxc_templates` — centralized LXC OS template & cached rootfs image registry (`template_key`, `label`, `image_alias`, `fallback_alias`, `family`, `version`, `arch`, `local_path`, `sha256`, `size_bytes`, `download_status`, `download_progress`, `min_disk_gb`, `min_ram_mb`, `icon`, `is_active`)
8. `storage_pools` — KVM & LXC storage pools (`name`, `node_id`, `engine`, `pool_type`, `path`, `total_bytes`, `used_bytes`, `avail_bytes`, `allocated_bytes`, `thin_provisioning`, `is_default`, `status`)
9. `ip_allocations` — IPv4/IPv6 pool & static IP assignments (`ip_address`, `cidr`, `gateway`, `ip_version`, `bridge`, `vlan_id`, `mac_address`, `node_id`, `instance_type`, `instance_ref_id`, `is_routed`, `ip_alias`, `assigned_to`)
10. `port_allocations` — per-user port forward quota (`user_id`, `allocated_ports`, `used_ports`)
11. `port_forwards` — NAT / LXC proxy port forwards (`id`, `user_id`, `node_id`, `instance_type`, `instance_ref_id`, `container_name`, `guest_port`, `host_port`, `protocol`, `description`, `is_custom`, `is_bulk`, `bulk_range_id`, `created_by_admin`, `hits`, `last_used`, `created_at`)
12. `container_snapshots` — LXC snapshots (`id`, `lxc_id`, `snapshot_name`, `description`, `size_bytes`, `snapshot_type`, `stateful`, `file_path`, `sha256`, `status`, `created_by`, `created_at`, `expires_at`)
13. `container_backups` — Unified KVM & LXC backup archives (`id`, `instance_type`, `instance_ref_id`, `node_id`, `backup_name`, `file_path`, `size_bytes`, `sha256`, `verified`, `status`, `logs`, `created_by`, `created_at`, `expires_at`)
14. `backup_schedules` — automated backup schedules (`id`, `instance_type`, `instance_ref_id`, `enabled`, `frequency`, `retention_count`, `last_run`, `next_run`)
15. `snapshot_schedules` — automated snapshot schedules (`id`, `instance_type`, `instance_ref_id`, `enabled`, `frequency`, `retention_count`, `last_run`, `next_run`)
16. `vps_migrations` — offline snapshot-transfer migration state machine & rollback log (`id`, `lxc_id`, `container_name`, `source_node_id`, `target_node_id`, `strategy`, `status`, `progress`, `message`, `snapshot_name`, `transfer_sha256`, `was_running`, `source_deleted`, `error_message`, `rollback_log`, `started_at`, `committed_at`, `completed_at`)
17. `vps_expiration` — renewal & expiration ledger (`id`, `lxc_id`, `expires_at`, `expiration_days`, `auto_suspend_enabled`, `warned_at`, `last_renewed_at`, `renewed_by`, `renewal_count`, `notes`)
18. `vps_metrics` — historical KVM & LXC instance resource metrics
19. `node_metrics` — historical host/node resource metrics
20. `notifications` — user & admin notifications
21. `webhooks` — event webhooks with HMAC signing secret & delivery status
22. `api_keys` — hashed API keys (`key_prefix`, `key_hash`, `name`, `permissions`, `is_active`, `last_used_at`, `expires_at`)
23. `agent_sessions` — active PTY terminal & node-agent sessions for auditing and cleanup
24. `activity_logs` — comprehensive audit trail (`user_id`, `action`, `resource_type`, `resource_id`, `details`, `ip_address`, `user_agent`, `created_at`)
25. `password_reset_tokens` & safe `users` column additions (`two_factor_secret_enc`, `two_factor_enabled`, `preferences`, `avatar_url`)

---

## 6. Dependencies & Frontend Inventory Mapping
- **Dependencies**: Preserving `express`, `ejs`, `sqlite3`, `sqlite`, `bcryptjs`, `express-session`, `ws`, `ssh2`, `axios`, `cors`, `dotenv`, `uuid`; adding `typescript`, `node-pty` (real POSIX PTY), `multer` (secure uploads), `qrcode` (2FA TOTP QR), and local `@xterm/xterm` + `@xterm/addon-fit` assets.
- **Frontend**: Extending `views/partials/admin/sidebar.ejs` (all 23 required navigation items), `views/partials/admin/header.ejs` (live notifications badge, unified search across KVM + LXC + nodes + users), `views/partials/users/sidebar.ejs`, and adding unified TGVPANEL-styled EJS views for All Instances, LXC VPS list/create/detail/edit/console/files, Nodes list/create/detail/console, Storage, Networking, IP Management, Port Management, Backups, Snapshots, Live Statistics, Monitoring, API Management, Notifications, Activity Logs, System Info, and Maintenance.
