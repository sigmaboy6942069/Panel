"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MIGRATIONS = exports.BUILTIN_LXC_OS_CATALOG = void 0;
exports.runMigrations = runMigrations;
const crypto_1 = __importDefault(require("crypto"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
const crypto_vault_1 = require("../security/crypto-vault");
exports.BUILTIN_LXC_OS_CATALOG = [
    {
        key: 'ubuntu-20.04',
        label: 'Ubuntu 20.04 LTS (Focal)',
        alias: 'ubuntu:20.04',
        fallback: 'images:ubuntu/20.04',
        family: 'debian',
        category: 'Ubuntu',
        version: '20.04',
        icon: 'ubuntu',
        minDiskGb: 5,
        minRamMb: 256,
        description: 'Long-Term Support release, supported until 2030.',
    },
    {
        key: 'ubuntu-22.04',
        label: 'Ubuntu 22.04 LTS (Jammy)',
        alias: 'ubuntu:22.04',
        fallback: 'images:ubuntu/22.04',
        family: 'debian',
        category: 'Ubuntu',
        version: '22.04',
        icon: 'ubuntu',
        minDiskGb: 5,
        minRamMb: 256,
        description: 'Long-Term Support release, supported until 2032.',
    },
    {
        key: 'ubuntu-24.04',
        label: 'Ubuntu 24.04 LTS (Noble)',
        alias: 'ubuntu:24.04',
        fallback: 'images:ubuntu/24.04',
        family: 'debian',
        category: 'Ubuntu',
        version: '24.04',
        icon: 'ubuntu',
        minDiskGb: 5,
        minRamMb: 256,
        description: 'Latest Long-Term Support release, supported until 2034.',
    },
    {
        key: 'debian-11',
        label: 'Debian 11 (Bullseye)',
        alias: 'images:debian/11',
        fallback: null,
        family: 'debian',
        category: 'Debian',
        version: '11',
        icon: 'debian',
        minDiskGb: 3,
        minRamMb: 256,
        description: 'Stable, conservative defaults. LTS support.',
    },
    {
        key: 'debian-12',
        label: 'Debian 12 (Bookworm)',
        alias: 'images:debian/12',
        fallback: null,
        family: 'debian',
        category: 'Debian',
        version: '12',
        icon: 'debian',
        minDiskGb: 3,
        minRamMb: 256,
        description: 'Current Debian stable. Recommended for most workloads.',
    },
    {
        key: 'debian-13',
        label: 'Debian 13 (Trixie)',
        alias: 'images:debian/13',
        fallback: 'images:debian/12',
        family: 'debian',
        category: 'Debian',
        version: '13',
        icon: 'debian',
        minDiskGb: 3,
        minRamMb: 256,
        description: 'Latest Debian release.',
    },
    {
        key: 'centos-9-stream',
        label: 'CentOS Stream 9',
        alias: 'images:centos/9-Stream',
        fallback: null,
        family: 'rhel',
        category: 'CentOS Stream',
        version: '9-Stream',
        icon: 'centos',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Rolling upstream of RHEL 9.',
    },
    {
        key: 'centos-10-stream',
        label: 'CentOS Stream 10',
        alias: 'images:centos/10-Stream',
        fallback: 'images:centos/9-Stream',
        family: 'rhel',
        category: 'CentOS Stream',
        version: '10-Stream',
        icon: 'centos',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Rolling upstream of RHEL 10.',
    },
    {
        key: 'almalinux-8',
        label: 'AlmaLinux 8',
        alias: 'images:almalinux/8',
        fallback: null,
        family: 'rhel',
        category: 'AlmaLinux',
        version: '8',
        icon: 'alma',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Community-driven RHEL 8 rebuild.',
    },
    {
        key: 'almalinux-9',
        label: 'AlmaLinux 9',
        alias: 'images:almalinux/9',
        fallback: 'images:almalinux/8',
        family: 'rhel',
        category: 'AlmaLinux',
        version: '9',
        icon: 'alma',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Community-driven RHEL 9 rebuild.',
    },
    {
        key: 'almalinux-10',
        label: 'AlmaLinux 10',
        alias: 'images:almalinux/10',
        fallback: 'images:almalinux/9',
        family: 'rhel',
        category: 'AlmaLinux',
        version: '10',
        icon: 'alma',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Community-driven RHEL 10 rebuild.',
    },
    {
        key: 'rockylinux-8',
        label: 'Rocky Linux 8',
        alias: 'images:rockylinux/8',
        fallback: null,
        family: 'rhel',
        category: 'Rocky Linux',
        version: '8',
        icon: 'rocky',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Enterprise-grade RHEL 8 rebuild.',
    },
    {
        key: 'rockylinux-9',
        label: 'Rocky Linux 9',
        alias: 'images:rockylinux/9',
        fallback: 'images:rockylinux/8',
        family: 'rhel',
        category: 'Rocky Linux',
        version: '9',
        icon: 'rocky',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Enterprise-grade RHEL 9 rebuild.',
    },
    {
        key: 'rockylinux-10',
        label: 'Rocky Linux 10',
        alias: 'images:rockylinux/10',
        fallback: 'images:rockylinux/9',
        family: 'rhel',
        category: 'Rocky Linux',
        version: '10',
        icon: 'rocky',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Enterprise-grade RHEL 10 rebuild.',
    },
    {
        key: 'fedora-40',
        label: 'Fedora 40',
        alias: 'images:fedora/40',
        fallback: null,
        family: 'rhel',
        category: 'Fedora',
        version: '40',
        icon: 'fedora',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Cutting-edge Red Hat-based distribution.',
    },
    {
        key: 'fedora-41',
        label: 'Fedora 41',
        alias: 'images:fedora/41',
        fallback: 'images:fedora/40',
        family: 'rhel',
        category: 'Fedora',
        version: '41',
        icon: 'fedora',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Cutting-edge Red Hat-based distribution.',
    },
    {
        key: 'fedora-42',
        label: 'Fedora 42',
        alias: 'images:fedora/42',
        fallback: 'images:fedora/41',
        family: 'rhel',
        category: 'Fedora',
        version: '42',
        icon: 'fedora',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Cutting-edge Red Hat-based distribution.',
    },
    {
        key: 'fedora-43',
        label: 'Fedora 43',
        alias: 'images:fedora/43',
        fallback: 'images:fedora/42',
        family: 'rhel',
        category: 'Fedora',
        version: '43',
        icon: 'fedora',
        minDiskGb: 5,
        minRamMb: 512,
        description: 'Latest Fedora release.',
    },
    {
        key: 'kali-rolling',
        label: 'Kali Linux',
        alias: 'images:kali',
        fallback: 'images:kali/current',
        family: 'debian',
        category: 'Kali',
        version: 'rolling',
        icon: 'kali',
        minDiskGb: 8,
        minRamMb: 512,
        description: 'Debian-based security & penetration testing distribution.',
    },
];
async function ensureColumn(db, table, column, definition) {
    const cols = await db.all(`PRAGMA table_info(${table})`);
    if (cols.length > 0 && !cols.some((c) => c.name === column)) {
        await db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
}
exports.MIGRATIONS = [
    {
        version: 1,
        name: 'v001_extend_hkvm_core_tables',
        up: async (db) => {
            // Ensure core baseline tables exist when `npm run migrate` runs on a brand-new empty DB
            await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          email TEXT UNIQUE,
          full_name TEXT,
          role TEXT DEFAULT 'user',
          is_active BOOLEAN DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login DATETIME
        );

        CREATE TABLE IF NOT EXISTS vms (
          vm_id INTEGER PRIMARY KEY AUTOINCREMENT,
          vm_name TEXT UNIQUE NOT NULL,
          os_type TEXT,
          template_type TEXT,
          hostname TEXT,
          username TEXT,
          password TEXT,
          memory INTEGER,
          cpus INTEGER,
          cpu_sockets INTEGER DEFAULT 1,
          cpu_cores INTEGER DEFAULT 2,
          cpu_threads INTEGER DEFAULT 1,
          cpu_model TEXT DEFAULT 'host',
          custom_cpu_name TEXT,
          machine_type TEXT DEFAULT 'pc',
          board_name TEXT DEFAULT 'Main-Board',
          product_name TEXT DEFAULT 'Virtual Machine',
          custom_smbios_manufacturer TEXT DEFAULT 'QEMU',
          disk_size TEXT,
          img_file TEXT,
          seed_file TEXT,
          disk_file TEXT,
          status TEXT DEFAULT 'stopped',
          pid INTEGER,
          uptime INTEGER DEFAULT 0,
          node_name TEXT DEFAULT 'localhost',
          smbios_manufacturer TEXT DEFAULT 'QEMU',
          smbios_product TEXT DEFAULT 'KVM Virtual Machine',
          smbios_version TEXT DEFAULT '1.0',
          smbios_serial TEXT,
          extra_args TEXT,
          enable_acpi BOOLEAN DEFAULT 1,
          enable_kvm BOOLEAN DEFAULT 1,
          network_type TEXT DEFAULT 'nat',
          ipv4_address TEXT,
          gateway TEXT,
          ipv4_gateway TEXT,
          netmask TEXT DEFAULT '24',
          ipv4_netmask TEXT DEFAULT '255.255.255.0',
          dns_servers TEXT DEFAULT '8.8.8.8,8.8.4.4',
          dns_primary TEXT DEFAULT '8.8.8.8',
          dns_secondary TEXT DEFAULT '8.8.4.4',
          ssh_port INTEGER,
          ssh_port_static INTEGER DEFAULT 22,
          http_port INTEGER DEFAULT 80,
          ipv6_address TEXT,
          ipv6_gateway TEXT,
          mac_address TEXT,
          bridge_interface TEXT,
          bridge_device TEXT DEFAULT 'vmbr0',
          vlan_id INTEGER,
          iso_attached TEXT,
          boot_from_iso BOOLEAN DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          owner_id INTEGER,
          FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS vm_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          vm_id INTEGER,
          action TEXT,
          status TEXT,
          message TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vm_snapshots (
          snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
          vm_id INTEGER,
          snapshot_name TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          size_gb REAL,
          description TEXT,
          FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS os_templates (
          template_id INTEGER PRIMARY KEY AUTOINCREMENT,
          template_key TEXT UNIQUE NOT NULL,
          template_name TEXT NOT NULL,
          template_type TEXT DEFAULT 'cloud-init',
          icon TEXT,
          description TEXT,
          disk_size TEXT DEFAULT '20G',
          memory INTEGER DEFAULT 2048,
          cpus INTEGER DEFAULT 2,
          download_url TEXT,
          local_path TEXT,
          username TEXT,
          password TEXT,
          is_custom BOOLEAN DEFAULT 0,
          is_active BOOLEAN DEFAULT 1,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS settings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          setting_key TEXT UNIQUE NOT NULL,
          setting_value TEXT,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);
            // Extend users safely without overwriting existing rows
            await ensureColumn(db, 'users', 'two_factor_secret_enc', 'TEXT');
            await ensureColumn(db, 'users', 'two_factor_enabled', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'users', 'preferences', "TEXT DEFAULT '{}'");
            await ensureColumn(db, 'users', 'avatar_url', 'TEXT');
            await ensureColumn(db, 'users', 'hvm_legacy_id', 'INTEGER');
            // Extend KVM vms table with node_id, firmware (BIOS/UEFI), suspension, SSH keys, clone tracking
            await ensureColumn(db, 'vms', 'node_id', 'INTEGER DEFAULT 1');
            await ensureColumn(db, 'vms', 'firmware_type', "TEXT DEFAULT 'bios'");
            await ensureColumn(db, 'vms', 'boot_order', "TEXT DEFAULT 'disk,cdrom'");
            await ensureColumn(db, 'vms', 'suspended', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'vms', 'suspended_reason', 'TEXT');
            await ensureColumn(db, 'vms', 'ssh_keys', 'TEXT');
            await ensureColumn(db, 'vms', 'storage_pool_id', 'INTEGER');
            await ensureColumn(db, 'vms', 'disk_format', "TEXT DEFAULT 'qcow2'");
            await ensureColumn(db, 'vms', 'clone_of', 'INTEGER');
            // Extend vm_snapshots for real qemu-img snapshot metadata
            await ensureColumn(db, 'vm_snapshots', 'tag_name', 'TEXT');
            await ensureColumn(db, 'vm_snapshots', 'file_path', 'TEXT');
            await ensureColumn(db, 'vm_snapshots', 'sha256', 'TEXT');
            await ensureColumn(db, 'vm_snapshots', 'stateful', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'vm_snapshots', 'status', "TEXT DEFAULT 'completed'");
        },
    },
    {
        version: 2,
        name: 'v002_create_unified_virtualization_and_node_tables',
        up: async (db) => {
            await db.exec(`
        CREATE TABLE IF NOT EXISTS nodes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          hostname TEXT,
          ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
          location TEXT DEFAULT 'Local Datacenter',
          url TEXT NOT NULL DEFAULT 'http://127.0.0.1:5050',
          is_local INTEGER DEFAULT 0,
          verify_ssl INTEGER DEFAULT 0,
          status TEXT DEFAULT 'unknown',
          health_status TEXT DEFAULT 'unknown',
          cpu_model TEXT DEFAULT 'Unknown',
          cpu_cores INTEGER DEFAULT 0,
          ram_total_mb INTEGER DEFAULT 0,
          disk_total_gb REAL DEFAULT 0,
          max_instances INTEGER DEFAULT 100,
          agent_version TEXT DEFAULT '3.0.0',
          lxc_version TEXT,
          qemu_version TEXT,
          network_interfaces TEXT DEFAULT '[]',
          ip_aliases TEXT DEFAULT '[]',
          tags TEXT DEFAULT '[]',
          circuit_breaker_open INTEGER DEFAULT 0,
          consecutive_failures INTEGER DEFAULT 0,
          last_failure_at DATETIME,
          last_seen DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS node_capabilities (
          node_id INTEGER PRIMARY KEY,
          supports_kvm INTEGER DEFAULT 1,
          supports_lxc INTEGER DEFAULT 1,
          kvm_available INTEGER DEFAULT 0,
          lxc_available INTEGER DEFAULT 0,
          lxc_driver TEXT DEFAULT 'none',
          storage_backends TEXT DEFAULT '["dir","qcow2","raw"]',
          network_bridges TEXT DEFAULT '[]',
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS node_credentials (
          node_id INTEGER PRIMARY KEY,
          api_key_prefix TEXT NOT NULL,
          api_key_hash TEXT NOT NULL,
          api_key_enc TEXT NOT NULL,
          hmac_secret_enc TEXT NOT NULL,
          tls_cert_fingerprint TEXT,
          rotated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_used_at DATETIME,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS storage_pools (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          node_id INTEGER NOT NULL DEFAULT 1,
          engine TEXT NOT NULL DEFAULT 'both',
          pool_type TEXT NOT NULL DEFAULT 'dir',
          path TEXT NOT NULL,
          volume_group TEXT,
          thin_provisioning INTEGER DEFAULT 1,
          total_bytes INTEGER DEFAULT 0,
          used_bytes INTEGER DEFAULT 0,
          avail_bytes INTEGER DEFAULT 0,
          allocated_bytes INTEGER DEFAULT 0,
          is_default INTEGER DEFAULT 0,
          is_active INTEGER DEFAULT 1,
          status TEXT DEFAULT 'online',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS lxc_instances (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          node_id INTEGER NOT NULL DEFAULT 1,
          container_name TEXT UNIQUE NOT NULL,
          container_id TEXT,
          hostname TEXT NOT NULL,
          os_template TEXT NOT NULL DEFAULT 'ubuntu:22.04',
          os_family TEXT DEFAULT 'debian',
          os_version TEXT DEFAULT '22.04',
          cpu_cores INTEGER NOT NULL DEFAULT 1,
          cpu_limit TEXT,
          cpu_shares INTEGER DEFAULT 1024,
          ram_mb INTEGER NOT NULL DEFAULT 1024,
          swap_mb INTEGER NOT NULL DEFAULT 0,
          disk_gb INTEGER NOT NULL DEFAULT 10,
          storage_pool TEXT DEFAULT 'default',
          storage_pool_id INTEGER,
          rootfs_path TEXT,
          mount_points TEXT DEFAULT '[]',
          privileged INTEGER DEFAULT 0,
          nesting INTEGER DEFAULT 1,
          security_profile TEXT DEFAULT 'default',
          root_password_enc TEXT,
          ssh_port INTEGER DEFAULT 22,
          ssh_keys TEXT,
          ip_address TEXT,
          ip_cidr INTEGER DEFAULT 24,
          ip_alias TEXT,
          gateway TEXT,
          ipv6_address TEXT,
          ipv6_gateway TEXT,
          dns_servers TEXT DEFAULT '8.8.8.8,1.1.1.1',
          mac_address TEXT,
          bridge_name TEXT DEFAULT 'lxcbr0',
          network_mode TEXT DEFAULT 'nat',
          is_routed_ip INTEGER DEFAULT 0,
          status TEXT DEFAULT 'stopped',
          suspended INTEGER DEFAULT 0,
          suspended_reason TEXT,
          suspension_history TEXT DEFAULT '[]',
          whitelisted INTEGER DEFAULT 0,
          shared_with TEXT DEFAULT '[]',
          bandwidth_quota_gb INTEGER DEFAULT 0,
          bandwidth_used_gb REAL DEFAULT 0.0,
          bandwidth_reset_date DATETIME,
          network_ingress_mbps INTEGER DEFAULT 0,
          network_egress_mbps INTEGER DEFAULT 0,
          network_priority INTEGER DEFAULT 5,
          snapshot_limit INTEGER DEFAULT 5,
          install_progress INTEGER DEFAULT 100,
          install_message TEXT DEFAULT 'Ready',
          notes TEXT,
          metadata TEXT DEFAULT '{}',
          expires_at DATETIME,
          expiration_days INTEGER DEFAULT 0,
          auto_suspend_enabled INTEGER DEFAULT 0,
          last_renewed_at DATETIME,
          last_started DATETIME,
          last_stopped DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(node_id) REFERENCES nodes(id)
        );

        CREATE TABLE IF NOT EXISTS instances (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          engine TEXT NOT NULL CHECK(engine IN ('kvm', 'lxc')),
          ref_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          hostname TEXT,
          owner_id INTEGER,
          node_id INTEGER NOT NULL DEFAULT 1,
          status TEXT DEFAULT 'stopped',
          suspended INTEGER DEFAULT 0,
          os_label TEXT,
          cpu_cores INTEGER DEFAULT 1,
          ram_mb INTEGER DEFAULT 1024,
          disk_gb REAL DEFAULT 10,
          primary_ip TEXT,
          shared_with TEXT DEFAULT '[]',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(engine, ref_id),
          FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL,
          FOREIGN KEY(node_id) REFERENCES nodes(id)
        );

        CREATE TABLE IF NOT EXISTS lxc_templates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          template_key TEXT UNIQUE NOT NULL,
          label TEXT NOT NULL,
          image_alias TEXT NOT NULL,
          fallback_alias TEXT,
          family TEXT DEFAULT 'debian',
          category TEXT DEFAULT 'Linux',
          version TEXT,
          arch TEXT DEFAULT 'amd64',
          description TEXT,
          icon TEXT DEFAULT 'linux',
          min_disk_gb INTEGER DEFAULT 5,
          min_ram_mb INTEGER DEFAULT 256,
          download_url TEXT,
          local_path TEXT,
          sha256 TEXT,
          size_bytes INTEGER DEFAULT 0,
          download_status TEXT DEFAULT 'remote',
          download_progress INTEGER DEFAULT 0,
          verified INTEGER DEFAULT 0,
          is_custom INTEGER DEFAULT 0,
          is_active INTEGER DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);
        },
    },
    {
        version: 3,
        name: 'v003_create_network_backup_migration_monitoring_security_tables',
        up: async (db) => {
            await db.exec(`
        CREATE TABLE IF NOT EXISTS ip_allocations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL DEFAULT 1,
          ip_address TEXT UNIQUE NOT NULL,
          cidr INTEGER DEFAULT 24,
          gateway TEXT,
          ip_version INTEGER DEFAULT 4,
          bridge TEXT DEFAULT 'vmbr0',
          vlan_id INTEGER,
          mac_address TEXT,
          is_routed INTEGER DEFAULT 0,
          ip_alias TEXT,
          instance_type TEXT,
          instance_ref_id INTEGER,
          assigned_user_id INTEGER,
          notes TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
          FOREIGN KEY(assigned_user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS port_allocations (
          user_id INTEGER PRIMARY KEY,
          allocated_ports INTEGER DEFAULT 10,
          used_ports INTEGER DEFAULT 0,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS port_forwards (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          node_id INTEGER NOT NULL DEFAULT 1,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER,
          container_name TEXT NOT NULL,
          guest_port INTEGER NOT NULL,
          host_port INTEGER NOT NULL,
          protocol TEXT NOT NULL DEFAULT 'tcp,udp',
          description TEXT,
          is_custom INTEGER DEFAULT 0,
          is_bulk INTEGER DEFAULT 0,
          bulk_range_id TEXT,
          created_by_admin INTEGER DEFAULT 0,
          hits INTEGER DEFAULT 0,
          last_used DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(node_id, host_port, protocol),
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS container_snapshots (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          lxc_id INTEGER NOT NULL,
          snapshot_name TEXT NOT NULL,
          description TEXT,
          size_bytes INTEGER DEFAULT 0,
          snapshot_type TEXT DEFAULT 'manual',
          stateful INTEGER DEFAULT 0,
          file_path TEXT,
          sha256 TEXT,
          status TEXT DEFAULT 'completed',
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME,
          FOREIGN KEY(lxc_id) REFERENCES lxc_instances(id) ON DELETE CASCADE,
          FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS container_backups (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER NOT NULL,
          node_id INTEGER NOT NULL DEFAULT 1,
          backup_name TEXT NOT NULL,
          file_path TEXT NOT NULL,
          size_bytes INTEGER DEFAULT 0,
          sha256 TEXT,
          verified INTEGER DEFAULT 0,
          progress INTEGER DEFAULT 100,
          status TEXT DEFAULT 'completed',
          logs TEXT,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
          FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS backup_schedules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER NOT NULL,
          enabled INTEGER DEFAULT 1,
          frequency TEXT NOT NULL DEFAULT 'daily',
          retention_count INTEGER DEFAULT 7,
          last_run DATETIME,
          next_run DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(instance_type, instance_ref_id)
        );

        CREATE TABLE IF NOT EXISTS snapshot_schedules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER NOT NULL,
          enabled INTEGER DEFAULT 1,
          frequency TEXT NOT NULL DEFAULT 'daily',
          retention_count INTEGER DEFAULT 7,
          last_run DATETIME,
          next_run DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(instance_type, instance_ref_id)
        );

        CREATE TABLE IF NOT EXISTS vps_migrations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          lxc_id INTEGER NOT NULL,
          container_name TEXT NOT NULL,
          source_node_id INTEGER NOT NULL,
          target_node_id INTEGER NOT NULL,
          strategy TEXT NOT NULL DEFAULT 'offline_snapshot_transfer',
          status TEXT NOT NULL DEFAULT 'preparing',
          progress INTEGER DEFAULT 0,
          message TEXT,
          snapshot_name TEXT,
          transfer_id TEXT,
          transfer_sha256 TEXT,
          transfer_bytes INTEGER DEFAULT 0,
          was_running INTEGER DEFAULT 0,
          destination_verified INTEGER DEFAULT 0,
          source_deleted INTEGER DEFAULT 0,
          error_message TEXT,
          rollback_log TEXT,
          initiated_by INTEGER,
          started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          committed_at DATETIME,
          completed_at DATETIME,
          FOREIGN KEY(lxc_id) REFERENCES lxc_instances(id) ON DELETE CASCADE,
          FOREIGN KEY(source_node_id) REFERENCES nodes(id),
          FOREIGN KEY(target_node_id) REFERENCES nodes(id)
        );

        CREATE TABLE IF NOT EXISTS vps_expiration (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          lxc_id INTEGER UNIQUE NOT NULL,
          expires_at DATETIME,
          expiration_days INTEGER DEFAULT 0,
          auto_suspend_enabled INTEGER DEFAULT 0,
          warned_at DATETIME,
          last_renewed_at DATETIME,
          renewed_by INTEGER,
          renewal_count INTEGER DEFAULT 0,
          notes TEXT,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(lxc_id) REFERENCES lxc_instances(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vps_metrics (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER NOT NULL,
          node_id INTEGER DEFAULT 1,
          cpu_percent REAL DEFAULT 0,
          ram_used_mb REAL DEFAULT 0,
          ram_total_mb REAL DEFAULT 0,
          ram_percent REAL DEFAULT 0,
          swap_used_mb REAL DEFAULT 0,
          disk_used_bytes INTEGER DEFAULT 0,
          disk_total_bytes INTEGER DEFAULT 0,
          disk_percent REAL DEFAULT 0,
          disk_read_bytes INTEGER DEFAULT 0,
          disk_write_bytes INTEGER DEFAULT 0,
          net_rx_bytes INTEGER DEFAULT 0,
          net_tx_bytes INTEGER DEFAULT 0,
          processes INTEGER DEFAULT 0,
          load_1 REAL DEFAULT 0,
          load_5 REAL DEFAULT 0,
          load_15 REAL DEFAULT 0,
          recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS node_metrics (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL,
          cpu_percent REAL DEFAULT 0,
          ram_used_mb REAL DEFAULT 0,
          ram_total_mb REAL DEFAULT 0,
          ram_percent REAL DEFAULT 0,
          disk_used_bytes INTEGER DEFAULT 0,
          disk_total_bytes INTEGER DEFAULT 0,
          disk_percent REAL DEFAULT 0,
          disk_read_bytes INTEGER DEFAULT 0,
          disk_write_bytes INTEGER DEFAULT 0,
          net_rx_bytes INTEGER DEFAULT 0,
          net_tx_bytes INTEGER DEFAULT 0,
          load_1 REAL DEFAULT 0,
          load_5 REAL DEFAULT 0,
          load_15 REAL DEFAULT 0,
          uptime_seconds INTEGER DEFAULT 0,
          recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notifications (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          type TEXT NOT NULL DEFAULT 'info',
          title TEXT NOT NULL,
          message TEXT NOT NULL,
          is_read INTEGER DEFAULT 0,
          data TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS webhooks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          url TEXT NOT NULL,
          events TEXT NOT NULL DEFAULT '["*"]',
          secret_enc TEXT,
          is_active INTEGER DEFAULT 1,
          last_triggered_at DATETIME,
          last_status_code INTEGER,
          failure_count INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS api_keys (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          description TEXT,
          key_prefix TEXT NOT NULL,
          key_hash TEXT UNIQUE NOT NULL,
          permissions TEXT DEFAULT '["read","write"]',
          is_active INTEGER DEFAULT 1,
          last_used_at DATETIME,
          expires_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS agent_sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_token TEXT UNIQUE NOT NULL,
          user_id INTEGER NOT NULL,
          node_id INTEGER NOT NULL,
          session_type TEXT NOT NULL DEFAULT 'lxc_shell',
          target_name TEXT,
          remote_session_id TEXT,
          status TEXT DEFAULT 'active',
          ip_address TEXT,
          started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_active_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          closed_at DATETIME,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          action TEXT NOT NULL,
          resource_type TEXT,
          resource_id TEXT,
          details TEXT,
          ip_address TEXT,
          user_agent TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          token_hash TEXT UNIQUE NOT NULL,
          ip_address TEXT,
          used INTEGER DEFAULT 0,
          used_at DATETIME,
          expires_at DATETIME NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS os_icons (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          os_name TEXT UNIQUE NOT NULL,
          icon_path TEXT NOT NULL,
          uploaded_by INTEGER,
          uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
        );

        -- Performance Indexes
        CREATE INDEX IF NOT EXISTS idx_instances_owner ON instances(owner_id);
        CREATE INDEX IF NOT EXISTS idx_instances_node ON instances(node_id);
        CREATE INDEX IF NOT EXISTS idx_instances_engine_status ON instances(engine, status);
        CREATE INDEX IF NOT EXISTS idx_lxc_user ON lxc_instances(user_id);
        CREATE INDEX IF NOT EXISTS idx_lxc_node ON lxc_instances(node_id);
        CREATE INDEX IF NOT EXISTS idx_lxc_status ON lxc_instances(status);
        CREATE INDEX IF NOT EXISTS idx_lxc_expires ON lxc_instances(expires_at);
        CREATE INDEX IF NOT EXISTS idx_port_forwards_user ON port_forwards(user_id);
        CREATE INDEX IF NOT EXISTS idx_port_forwards_container ON port_forwards(container_name);
        CREATE INDEX IF NOT EXISTS idx_vps_metrics_lookup ON vps_metrics(instance_type, instance_ref_id, recorded_at);
        CREATE INDEX IF NOT EXISTS idx_node_metrics_lookup ON node_metrics(node_id, recorded_at);
        CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read);
        CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at DESC);
      `);
        },
    },
    {
        version: 4,
        name: 'v004_seed_defaults_encrypt_credentials_and_sync_instances',
        up: async (db) => {
            // 1. Seed default localhost node if no nodes exist yet
            const existingNode = await db.get(`SELECT id FROM nodes ORDER BY id ASC LIMIT 1`);
            let localNodeId = existingNode?.id;
            if (!localNodeId) {
                const cpus = os_1.default.cpus();
                const agentPort = parseInt(process.env.LOCAL_NODE_AGENT_PORT || '5050', 10);
                const ins = await db.run(`INSERT INTO nodes (name, hostname, ip_address, location, url, is_local, verify_ssl, status, health_status, cpu_model, cpu_cores, ram_total_mb)
           VALUES (?, ?, '127.0.0.1', 'Primary Local Host', ?, 1, 0, 'online', 'healthy', ?, ?, ?)`, [
                    'localhost',
                    os_1.default.hostname(),
                    `http://127.0.0.1:${agentPort}`,
                    cpus[0]?.model || 'Linux Host CPU',
                    cpus.length || 1,
                    Math.round(os_1.default.totalmem() / (1024 * 1024)),
                ]);
                localNodeId = ins.lastID;
                const keyPair = (0, crypto_vault_1.generateApiKeyPair)('hkvm_node');
                const hmacSecret = crypto_1.default.randomBytes(32).toString('hex');
                await db.run(`INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc)
           VALUES (?, ?, ?, ?, ?)`, [
                    localNodeId,
                    keyPair.keyPrefix,
                    keyPair.keyHash,
                    (0, crypto_vault_1.encryptSecret)(keyPair.rawKey),
                    (0, crypto_vault_1.encryptSecret)(hmacSecret),
                ]);
                await db.run(`INSERT INTO node_capabilities (node_id, supports_kvm, supports_lxc, kvm_available, lxc_available)
           VALUES (?, 1, 1, 0, 0)`, [localNodeId]);
            }
            // 2. Seed default KVM & LXC storage pools if empty
            const poolCount = await db.get(`SELECT COUNT(*) as cnt FROM storage_pools`);
            if (!poolCount || poolCount.cnt === 0) {
                const vmPath = process.env.TGVPANEL_VM_DIR || process.env.HKVM_VM_DIR || path_1.default.join(os_1.default.homedir(), 'vms');
                const lxcPath = process.env.TGVPANEL_LXC_DIR || process.env.HKVM_LXC_DIR || '/var/lib/lxc';
                await db.run(`INSERT INTO storage_pools (name, node_id, engine, pool_type, path, thin_provisioning, is_default, is_active, status)
           VALUES ('local-kvm', ?, 'kvm', 'qcow2', ?, 1, 1, 1, 'online')`, [localNodeId, vmPath]);
                await db.run(`INSERT INTO storage_pools (name, node_id, engine, pool_type, path, thin_provisioning, is_default, is_active, status)
           VALUES ('local-lxc', ?, 'lxc', 'dir', ?, 0, 1, 1, 'online')`, [localNodeId, lxcPath]);
            }
            // 3. Seed built-in HVM V9 LXC OS template catalog
            for (const tpl of exports.BUILTIN_LXC_OS_CATALOG) {
                await db.run(`INSERT OR IGNORE INTO lxc_templates
           (template_key, label, image_alias, fallback_alias, family, category, version, icon, min_disk_gb, min_ram_mb, description, is_custom, is_active)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1)`, [
                    tpl.key,
                    tpl.label,
                    tpl.alias,
                    tpl.fallback,
                    tpl.family,
                    tpl.category,
                    tpl.version,
                    tpl.icon,
                    tpl.minDiskGb,
                    tpl.minRamMb,
                    tpl.description,
                ]);
            }
            // 4. Encrypt any legacy plaintext VM passwords & template passwords in-place
            const vms = await db.all(`SELECT * FROM vms`);
            for (const vm of vms) {
                if (vm.password && !(0, crypto_vault_1.isEncryptedSecret)(vm.password)) {
                    await db.run(`UPDATE vms SET password = ? WHERE vm_id = ?`, [
                        (0, crypto_vault_1.encryptSecret)(vm.password),
                        vm.vm_id,
                    ]);
                }
                const diskGb = parseFloat(String(vm.disk_size || '20').replace(/[^0-9.]/g, '')) || 20;
                await db.run(`INSERT OR REPLACE INTO instances
           (engine, ref_id, name, hostname, owner_id, node_id, status, os_label, cpu_cores, ram_mb, disk_gb, primary_ip)
           VALUES ('kvm', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                    vm.vm_id,
                    vm.vm_name,
                    vm.hostname || vm.vm_name,
                    vm.owner_id,
                    vm.node_id || localNodeId,
                    vm.status || 'stopped',
                    vm.os_type || 'KVM Linux',
                    vm.cpus || 1,
                    vm.memory || 1024,
                    diskGb,
                    vm.ipv4_address || null,
                ]);
            }
            // 5. Ensure default unified settings exist without overwriting customized values
            const defaultV3Settings = {
                panel_version: 'V3.0',
                maintenance_mode: '0',
                maintenance_message: 'TGVPANEL is currently undergoing scheduled maintenance.',
                cpu_threshold: '90',
                ram_threshold: '90',
                auto_suspend_high_usage: '0',
                backup_enabled: '1',
                backup_retention: '7',
                default_user_port_quota: '10',
            };
            for (const [key, val] of Object.entries(defaultV3Settings)) {
                const existing = await db.get(`SELECT setting_value FROM settings WHERE setting_key = ?`, [key]);
                if (!existing) {
                    await db.run(`INSERT INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`, [key, val]);
                }
            }
        },
    },
    {
        version: 5,
        name: 'v005_unify_service_columns_and_auxiliary_tables',
        up: async (db) => {
            // Extend vms for unified KVM telemetry & sharing
            await ensureColumn(db, 'vms', 'pid', 'INTEGER');
            await ensureColumn(db, 'vms', 'shared_with', "TEXT DEFAULT '[]'");
            await ensureColumn(db, 'vms', 'expires_at', 'DATETIME');
            // Extend nodes, capabilities & credentials
            await ensureColumn(db, 'nodes', 'maintenance_mode', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'nodes', 'mtls_enabled', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'nodes', 'last_heartbeat', 'DATETIME');
            await ensureColumn(db, 'nodes', 'circuit_state', "TEXT DEFAULT 'closed'");
            await ensureColumn(db, 'nodes', 'notes', 'TEXT');
            await ensureColumn(db, 'node_capabilities', 'nested_virt', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'node_capabilities', 'cgroup_version', 'INTEGER DEFAULT 2');
            await ensureColumn(db, 'node_capabilities', 'network_backends', "TEXT DEFAULT '[]'");
            await ensureColumn(db, 'node_capabilities', 'qemu_version', 'TEXT');
            await ensureColumn(db, 'node_capabilities', 'lxc_version', 'TEXT');
            await ensureColumn(db, 'node_capabilities', 'kernel_version', 'TEXT');
            await ensureColumn(db, 'node_credentials', 'tls_ca_pem', 'TEXT');
            await ensureColumn(db, 'node_credentials', 'tls_client_cert_pem', 'TEXT');
            await ensureColumn(db, 'node_credentials', 'tls_client_key_enc', 'TEXT');
            // Extend lxc_instances & lxc_templates
            await ensureColumn(db, 'lxc_instances', 'arch', "TEXT DEFAULT 'amd64'");
            await ensureColumn(db, 'lxc_instances', 'cpu_limit_pct', 'INTEGER DEFAULT 100');
            await ensureColumn(db, 'lxc_instances', 'cpu_pinning', 'TEXT');
            await ensureColumn(db, 'lxc_instances', 'rootfs_storage_type', "TEXT DEFAULT 'dir'");
            await ensureColumn(db, 'lxc_instances', 'autostart', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'lxc_instances', 'bridge', "TEXT DEFAULT 'lxcbr0'");
            await ensureColumn(db, 'lxc_instances', 'vlan_id', 'INTEGER');
            await ensureColumn(db, 'lxc_templates', 'slug', 'TEXT');
            await ensureColumn(db, 'lxc_templates', 'name', 'TEXT');
            await ensureColumn(db, 'lxc_templates', 'distro', 'TEXT');
            await ensureColumn(db, 'lxc_templates', 'release', 'TEXT');
            await ensureColumn(db, 'lxc_templates', 'variant', "TEXT DEFAULT 'default'");
            await ensureColumn(db, 'lxc_templates', 'file_path', 'TEXT');
            await ensureColumn(db, 'lxc_templates', 'checksum_sha256', 'TEXT');
            await ensureColumn(db, 'lxc_templates', 'enabled', 'INTEGER DEFAULT 1');
            const tpls = await db.all(`SELECT * FROM lxc_templates`);
            for (const t of tpls) {
                const alias = String(t.image_alias || 'ubuntu:24.04').replace(/^images:/, '');
                const parts = alias.split(/[:/]/);
                const distro = parts[0] || 'ubuntu';
                const release = parts[1] || t.version || '24.04';
                await db.run(`UPDATE lxc_templates
           SET slug = COALESCE(slug, template_key),
               name = COALESCE(name, label),
               distro = COALESCE(distro, ?),
               release = COALESCE(release, ?),
               enabled = COALESCE(enabled, is_active, 1)
           WHERE id = ?`, [distro, release, t.id]);
            }
            await db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_lxc_templates_slug ON lxc_templates(slug)`);
            // Extend storage_pools & add storage_volumes
            await ensureColumn(db, 'storage_pools', 'engine_scope', "TEXT DEFAULT 'both'");
            await ensureColumn(db, 'storage_pools', 'available_bytes', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'storage_pools', 'overcommit_ratio', 'REAL DEFAULT 1.5');
            await ensureColumn(db, 'storage_pools', 'enabled', 'INTEGER DEFAULT 1');
            await db.run(`UPDATE storage_pools SET engine_scope = COALESCE(engine, 'both')`);
            await db.exec(`
        CREATE TABLE IF NOT EXISTS storage_volumes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          pool_id INTEGER NOT NULL,
          instance_type TEXT NOT NULL,
          instance_ref_id INTEGER NOT NULL,
          volume_name TEXT NOT NULL,
          format TEXT DEFAULT 'qcow2',
          file_path TEXT NOT NULL,
          size_bytes INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(pool_id) REFERENCES storage_pools(id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS network_pools (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL DEFAULT 1,
          name TEXT NOT NULL,
          network_type TEXT NOT NULL DEFAULT 'bridge',
          bridge_name TEXT NOT NULL DEFAULT 'lxcbr0',
          cidr TEXT,
          gateway TEXT,
          ipv6_cidr TEXT,
          ipv6_gateway TEXT,
          vlan_id INTEGER,
          dns_servers TEXT DEFAULT '["1.1.1.1","8.8.8.8"]',
          enabled INTEGER DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS firewall_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL DEFAULT 1,
          instance_type TEXT,
          instance_ref_id INTEGER,
          direction TEXT NOT NULL DEFAULT 'in',
          action TEXT NOT NULL DEFAULT 'ACCEPT',
          protocol TEXT NOT NULL DEFAULT 'tcp',
          source_cidr TEXT,
          dest_port TEXT,
          priority INTEGER DEFAULT 100,
          enabled INTEGER DEFAULT 1,
          comment TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS metrics_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          target_type TEXT NOT NULL,
          target_id INTEGER NOT NULL,
          cpu_percent REAL DEFAULT 0,
          ram_used_mb REAL DEFAULT 0,
          ram_total_mb REAL DEFAULT 0,
          disk_used_gb REAL DEFAULT 0,
          disk_total_gb REAL DEFAULT 0,
          net_rx_bytes INTEGER DEFAULT 0,
          net_tx_bytes INTEGER DEFAULT 0,
          load_avg_1 REAL DEFAULT 0,
          recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_history_target ON metrics_history(target_type, target_id, recorded_at);

        CREATE TABLE IF NOT EXISTS alert_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          target_scope TEXT NOT NULL DEFAULT 'node',
          metric TEXT NOT NULL DEFAULT 'cpu_percent',
          operator TEXT NOT NULL DEFAULT '>=',
          threshold REAL NOT NULL DEFAULT 90,
          severity TEXT NOT NULL DEFAULT 'warning',
          enabled INTEGER DEFAULT 1,
          last_triggered_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);
            await ensureColumn(db, 'ip_allocations', 'pool_id', 'INTEGER');
            await ensureColumn(db, 'ip_allocations', 'version', 'INTEGER DEFAULT 4');
            await ensureColumn(db, 'ip_allocations', 'status', "TEXT DEFAULT 'available'");
            await ensureColumn(db, 'port_forwards', 'guest_ip', 'TEXT');
            await ensureColumn(db, 'container_backups', 'checksum_sha256', 'TEXT');
            await ensureColumn(db, 'vps_migrations', 'instance_type', "TEXT DEFAULT 'lxc'");
            await ensureColumn(db, 'vps_migrations', 'instance_ref_id', 'INTEGER');
            await ensureColumn(db, 'vps_migrations', 'migration_mode', "TEXT DEFAULT 'offline_snapshot'");
            await ensureColumn(db, 'vps_migrations', 'checksum_sha256', 'TEXT');
            await ensureColumn(db, 'vps_migrations', 'bytes_transferred', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'vps_migrations', 'rollback_performed', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'api_keys', 'ip_whitelist', 'TEXT');
            await ensureColumn(db, 'password_reset_tokens', 'requested_ip', 'TEXT');
        },
    },
    {
        version: 6,
        name: 'v006_add_lxc_kvm_nesting',
        up: async (db) => {
            await ensureColumn(db, 'lxc_instances', 'kvm_nesting', 'INTEGER DEFAULT 0');
        },
    },
    {
        version: 7,
        name: 'v007_rebrand_default_admin_email',
        up: async (db) => {
            await db.run(`UPDATE users
         SET email = 'admin@shadowgamerind.local'
         WHERE LOWER(email) IN ('admin@hopingboyz.local', 'admin@hopingboy.local')`);
        },
    },
    {
        version: 8,
        name: 'v008_rebrand_visible_hkvm_to_tgvpanel',
        up: async (db) => {
            await db.run(`UPDATE settings
         SET setting_value = 'TGVPANEL', updated_at = datetime('now')
         WHERE setting_key = 'site_name'
           AND LOWER(TRIM(setting_value)) IN ('hkvm', 'hkvm panel', 'hkvm v3', 'my custom panel')`);
            await db.run(`UPDATE settings
         SET setting_value = 'TGVPANEL V3.0', updated_at = datetime('now')
         WHERE setting_key = 'panel_title'
           AND LOWER(TRIM(setting_value)) LIKE 'hkvm%'`);
            await db.run(`UPDATE settings
         SET setting_value = 'TGVPANEL is currently undergoing scheduled maintenance.', updated_at = datetime('now')
         WHERE setting_key = 'maintenance_message'
           AND setting_value = 'HKVM is currently undergoing scheduled maintenance.'`);
        },
    },
    {
        version: 9,
        name: 'v009_cascade_vm_child_foreign_keys',
        up: async (db) => {
            const hasVms = await db.get(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vms'`);
            if (!hasVms)
                return;
            const hasVmLogs = await db.get(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vm_logs'`);
            if (hasVmLogs) {
                await db.exec(`
          CREATE TABLE vm_logs_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vm_id INTEGER,
            action TEXT,
            status TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
          );
          INSERT INTO vm_logs_new (id, vm_id, action, status, message, timestamp)
          SELECT id, vm_id, action, status, message, timestamp
          FROM vm_logs
          WHERE vm_id IS NULL OR vm_id IN (SELECT vm_id FROM vms);
          DROP TABLE vm_logs;
          ALTER TABLE vm_logs_new RENAME TO vm_logs;
          CREATE INDEX IF NOT EXISTS idx_vm_logs_vm_id ON vm_logs(vm_id);
        `);
            }
            const hasVmSnapshots = await db.get(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vm_snapshots'`);
            if (hasVmSnapshots) {
                await ensureColumn(db, 'vm_snapshots', 'tag_name', 'TEXT');
                await ensureColumn(db, 'vm_snapshots', 'file_path', 'TEXT');
                await ensureColumn(db, 'vm_snapshots', 'sha256', 'TEXT');
                await ensureColumn(db, 'vm_snapshots', 'stateful', 'INTEGER DEFAULT 0');
                await ensureColumn(db, 'vm_snapshots', 'status', "TEXT DEFAULT 'completed'");
                await db.exec(`
          CREATE TABLE vm_snapshots_new (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            vm_id INTEGER,
            snapshot_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            size_gb REAL,
            description TEXT,
            tag_name TEXT,
            file_path TEXT,
            sha256 TEXT,
            stateful INTEGER DEFAULT 0,
            status TEXT DEFAULT 'completed',
            FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
          );
          INSERT INTO vm_snapshots_new (snapshot_id, vm_id, snapshot_name, created_at, size_gb, description, tag_name, file_path, sha256, stateful, status)
          SELECT snapshot_id, vm_id, snapshot_name, created_at, size_gb, description, tag_name, file_path, sha256, COALESCE(stateful, 0), COALESCE(status, 'completed')
          FROM vm_snapshots
          WHERE vm_id IS NULL OR vm_id IN (SELECT vm_id FROM vms);
          DROP TABLE vm_snapshots;
          ALTER TABLE vm_snapshots_new RENAME TO vm_snapshots;
          CREATE INDEX IF NOT EXISTS idx_vm_snapshots_vm_id ON vm_snapshots(vm_id);
        `);
            }
            // Also clean up any orphaned `instances` registry rows whose KVM VM was already deleted
            const hasInstances = await db.get(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'instances'`);
            if (hasInstances) {
                await db.run(`DELETE FROM instances
           WHERE engine = 'kvm' AND ref_id NOT IN (SELECT vm_id FROM vms)`);
            }
        },
    },
    {
        version: 10,
        name: 'v010_ensure_vm_snapshots_extended_columns',
        up: async (db) => {
            const hasVmSnapshots = await db.get(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vm_snapshots'`);
            if (!hasVmSnapshots)
                return;
            await ensureColumn(db, 'vm_snapshots', 'tag_name', 'TEXT');
            await ensureColumn(db, 'vm_snapshots', 'file_path', 'TEXT');
            await ensureColumn(db, 'vm_snapshots', 'sha256', 'TEXT');
            await ensureColumn(db, 'vm_snapshots', 'stateful', 'INTEGER DEFAULT 0');
            await ensureColumn(db, 'vm_snapshots', 'status', "TEXT DEFAULT 'completed'");
        },
    },
    {
        version: 11,
        name: 'v011_multi_node_pairing_and_error_tracking',
        up: async (db) => {
            await ensureColumn(db, 'nodes', 'last_error', 'TEXT');
            await ensureColumn(db, 'nodes', 'last_error_at', 'DATETIME');
            await db.exec(`
        CREATE TABLE IF NOT EXISTS node_join_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
          token_prefix TEXT NOT NULL,
          token_hash TEXT UNIQUE NOT NULL,
          controller_url TEXT,
          expires_at DATETIME NOT NULL,
          used_at DATETIME,
          used_from_ip TEXT,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_node_join_tokens_node_id ON node_join_tokens(node_id);
      `);
        },
    },
    {
        version: 12,
        name: 'v012_reseller_upstream_provisioning',
        up: async (db) => {
            await db.exec(`
        -- ============================================================
        -- Upstream reseller catalogue (e.g. Bukkit-Hosting KVM plans).
        -- Costs are what WE pay upstream; retail_* is what the customer
        -- pays us. All money is stored as INTEGER cents to avoid float
        -- rounding drift on invoices.
        -- ============================================================
        CREATE TABLE IF NOT EXISTS reseller_plans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          provider TEXT NOT NULL DEFAULT 'bukkit-hosting',
          upstream_plan_id TEXT,
          kind TEXT NOT NULL DEFAULT 'package',
          slug TEXT UNIQUE,
          display_name TEXT NOT NULL,
          description TEXT,
          cpu_family TEXT,
          cpu_label TEXT,
          cores INTEGER NOT NULL DEFAULT 1,
          memory_gb INTEGER NOT NULL DEFAULT 1,
          disk_gb INTEGER NOT NULL DEFAULT 10,
          ipv4_count INTEGER NOT NULL DEFAULT 1,
          ipv6_count INTEGER NOT NULL DEFAULT 1,
          connection_gbit REAL NOT NULL DEFAULT 1,
          duration_months INTEGER NOT NULL DEFAULT 1,
          cost_cents INTEGER NOT NULL DEFAULT 0,
          cost_renew_cents INTEGER NOT NULL DEFAULT 0,
          retail_cents INTEGER NOT NULL DEFAULT 0,
          retail_renew_cents INTEGER NOT NULL DEFAULT 0,
          setup_cents INTEGER NOT NULL DEFAULT 0,
          currency TEXT NOT NULL DEFAULT 'EUR',
          is_enabled INTEGER NOT NULL DEFAULT 0,
          is_visible INTEGER NOT NULL DEFAULT 1,
          is_popular INTEGER NOT NULL DEFAULT 0,
          sort_order INTEGER NOT NULL DEFAULT 0,
          stock_state TEXT NOT NULL DEFAULT 'unknown',
          upstream_available INTEGER,
          upstream_exclusive INTEGER NOT NULL DEFAULT 0,
          upstream_discount_percent INTEGER NOT NULL DEFAULT 0,
          upstream_discount_ends_at DATETIME,
          upstream_raw TEXT,
          last_synced_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_reseller_plans_provider ON reseller_plans(provider, kind);
        CREATE INDEX IF NOT EXISTS idx_reseller_plans_upstream ON reseller_plans(upstream_plan_id);
        CREATE INDEX IF NOT EXISTS idx_reseller_plans_enabled ON reseller_plans(is_enabled, sort_order);

        -- Upstream OS images offered for order + reinstall (GET /kvm/os)
        CREATE TABLE IF NOT EXISTS reseller_os_images (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          provider TEXT NOT NULL DEFAULT 'bukkit-hosting',
          upstream_os_id TEXT NOT NULL,
          display_name TEXT NOT NULL,
          family TEXT NOT NULL DEFAULT 'linux',
          is_windows INTEGER NOT NULL DEFAULT 0,
          min_disk_gb INTEGER,
          is_enabled INTEGER NOT NULL DEFAULT 1,
          icon TEXT,
          sort_order INTEGER NOT NULL DEFAULT 0,
          last_synced_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(provider, upstream_os_id)
        );

        -- ============================================================
        -- Orders. One row per customer checkout attempt. The
        -- idempotency_key is generated BEFORE the upstream call and
        -- persisted, so a retry after a network timeout replays the
        -- stored upstream response instead of buying a second server.
        -- ============================================================
        CREATE TABLE IF NOT EXISTS reseller_orders (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          order_ref TEXT UNIQUE NOT NULL,
          user_id INTEGER,
          plan_id INTEGER,
          provider TEXT NOT NULL DEFAULT 'bukkit-hosting',
          server_name TEXT,
          hostname TEXT,
          os_id TEXT,
          cores INTEGER,
          memory_gb INTEGER,
          disk_gb INTEGER,
          ipv4_count INTEGER,
          ipv6_count INTEGER,
          cpu_family TEXT,
          duration_months INTEGER NOT NULL DEFAULT 1,
          auto_renew INTEGER NOT NULL DEFAULT 1,
          retail_cents INTEGER NOT NULL DEFAULT 0,
          setup_cents INTEGER NOT NULL DEFAULT 0,
          charged_cents INTEGER NOT NULL DEFAULT 0,
          cost_cents INTEGER NOT NULL DEFAULT 0,
          currency TEXT NOT NULL DEFAULT 'EUR',
          payment_mode TEXT NOT NULL DEFAULT 'wallet',
          status TEXT NOT NULL DEFAULT 'pending',
          idempotency_key TEXT UNIQUE,
          upstream_product_id TEXT,
          upstream_state TEXT,
          upstream_price_cents INTEGER,
          upstream_balance_after_cents INTEGER,
          upstream_request_id TEXT,
          error_code TEXT,
          error_message TEXT,
          attempts INTEGER NOT NULL DEFAULT 0,
          sandbox INTEGER NOT NULL DEFAULT 0,
          placed_by INTEGER,
          notes TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          provisioned_at DATETIME,
          failed_at DATETIME,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
          FOREIGN KEY(plan_id) REFERENCES reseller_plans(id) ON DELETE SET NULL,
          FOREIGN KEY(placed_by) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reseller_orders_user ON reseller_orders(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_reseller_orders_status ON reseller_orders(status);
        CREATE INDEX IF NOT EXISTS idx_reseller_orders_product ON reseller_orders(upstream_product_id);

        -- ============================================================
        -- Provisioned upstream servers, mapped onto a local panel user.
        -- provider_product_id is the upstream UUID; it stays NULL while
        -- the order is still queued, hence no UNIQUE constraint on it.
        -- ============================================================
        CREATE TABLE IF NOT EXISTS cloud_servers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          order_id INTEGER,
          provider TEXT NOT NULL DEFAULT 'bukkit-hosting',
          provider_product_id TEXT,
          name TEXT NOT NULL,
          hostname TEXT,
          cpu_family TEXT,
          cpu_label TEXT,
          cores INTEGER NOT NULL DEFAULT 1,
          memory_gb INTEGER NOT NULL DEFAULT 1,
          disk_gb INTEGER NOT NULL DEFAULT 10,
          connection_gbit REAL NOT NULL DEFAULT 1,
          ipv4_count INTEGER NOT NULL DEFAULT 1,
          ipv6_count INTEGER NOT NULL DEFAULT 1,
          primary_ipv4 TEXT,
          primary_ipv6 TEXT,
          os_id TEXT,
          os_label TEXT,
          ssh_user TEXT,
          ssh_port INTEGER NOT NULL DEFAULT 22,
          credentials_enc TEXT,
          upstream_state TEXT NOT NULL DEFAULT 'install',
          power_status TEXT NOT NULL DEFAULT 'unknown',
          retail_cents INTEGER NOT NULL DEFAULT 0,
          renew_cents INTEGER NOT NULL DEFAULT 0,
          cost_cents INTEGER NOT NULL DEFAULT 0,
          currency TEXT NOT NULL DEFAULT 'EUR',
          duration_months INTEGER NOT NULL DEFAULT 1,
          auto_renew INTEGER NOT NULL DEFAULT 1,
          billing_mode TEXT NOT NULL DEFAULT 'wallet',
          expires_at DATETIME,
          suspended INTEGER NOT NULL DEFAULT 0,
          suspended_reason TEXT,
          last_synced_at DATETIME,
          last_status_at DATETIME,
          last_error TEXT,
          upstream_created_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(order_id) REFERENCES reseller_orders(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cloud_servers_user ON cloud_servers(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_cloud_servers_product ON cloud_servers(provider_product_id);
        CREATE INDEX IF NOT EXISTS idx_cloud_servers_state ON cloud_servers(upstream_state);

        -- Per-user wallet. Balance is derived from the ledger so every
        -- euro cent is traceable back to a grant or an order.
        CREATE TABLE IF NOT EXISTS reseller_wallet_ledger (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          delta_cents INTEGER NOT NULL,
          balance_after_cents INTEGER NOT NULL,
          kind TEXT NOT NULL,
          reference TEXT,
          description TEXT,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_wallet_ledger_user ON reseller_wallet_ledger(user_id, id);

        -- Raw upstream API traffic for support/debugging. Bodies are
        -- truncated and credential fields are redacted before insert.
        CREATE TABLE IF NOT EXISTS reseller_api_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          provider TEXT NOT NULL DEFAULT 'bukkit-hosting',
          method TEXT NOT NULL,
          endpoint TEXT NOT NULL,
          status_code INTEGER,
          state TEXT,
          error_code TEXT,
          duration_ms INTEGER,
          request_id TEXT,
          idempotency_key TEXT,
          user_id INTEGER,
          request_body TEXT,
          response_body TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_reseller_api_logs_created ON reseller_api_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_reseller_api_logs_endpoint ON reseller_api_logs(endpoint, created_at);
      `);
            // Default reseller configuration. The API key itself is stored
            // AES-256-GCM encrypted via lib/security/crypto-vault.
            const defaults = [
                ['reseller_enabled', '0'],
                ['reseller_provider', 'bukkit-hosting'],
                ['reseller_api_base_url', 'https://bukkit-hosting.eu/api/v2'],
                ['reseller_api_key_enc', ''],
                ['reseller_api_key_hint', ''],
                ['reseller_store_enabled', '1'],
                ['reseller_default_markup_percent', '20'],
                ['reseller_auto_renew_default', '1'],
                ['reseller_allow_configurator', '0'],
                ['reseller_request_timeout_ms', '20000'],
                ['reseller_sync_interval_sec', '900'],
                ['reseller_poll_interval_sec', '30'],
                ['reseller_low_balance_alert_cents', '2000'],
                ['reseller_tos_text', ''],
                ['reseller_upstream_account_id', ''],
                ['reseller_upstream_balance_cents', ''],
                ['reseller_last_sync_at', ''],
            ];
            for (const [key, value] of defaults) {
                const row = await db.get(`SELECT setting_value FROM settings WHERE setting_key = ?`, [key]);
                if (!row) {
                    await db.run(`INSERT INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`, [key, value]);
                }
            }
        },
    },
];
async function runMigrations(db) {
    await db.run('PRAGMA foreign_keys = ON');
    await db.run(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
    const appliedRows = await db.all(`SELECT version FROM schema_migrations`);
    const appliedSet = new Set(appliedRows.map((r) => r.version));
    const pending = exports.MIGRATIONS.filter((m) => !appliedSet.has(m.version));
    if (pending.length === 0) {
        return { applied: [] };
    }
    // Automatic database backup before applying any pending migration (Part 20 & Part 22)
    const backup = await db.createBackup(`pre_migration_v${pending[0].version}`);
    const newlyApplied = [];
    for (const migration of pending) {
        const checksum = crypto_1.default
            .createHash('sha256')
            .update(`${migration.version}:${migration.name}`)
            .digest('hex');
        await db.transaction(async () => {
            await migration.up(db);
            await db.run(`INSERT INTO schema_migrations (version, name, checksum, applied_at)
         VALUES (?, ?, ?, datetime('now'))`, [migration.version, migration.name, checksum]);
        });
        newlyApplied.push(migration.name);
    }
    return { applied: newlyApplied, backupPath: backup.backupPath };
}
