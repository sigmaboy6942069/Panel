const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { spawn, exec, execSync } = require('child_process');
const os = require('os');
const util = require('util');
const execPromise = util.promisify(exec);
const { Client } = require('ssh2');
require('dotenv').config();
const licenses = require("./licenses");

// ============= PLATFORM DETECTION =============
const isWindows = process.platform === 'win32';
const isLinux = process.platform === 'linux';

// ============= CONSTANTS =============
const DEFAULT_SSH_PORT = 2222;

// ============= UTILITY FUNCTIONS =============

/**
 * Get validated SSH port from VM
 * Consolidates ssh_port and ssh_port_static into single value
 */
function getSSHPort(vm) {
  const port = vm.ssh_port || vm.ssh_port_static || DEFAULT_SSH_PORT;
  const portNum = parseInt(port);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    return DEFAULT_SSH_PORT;
  }
  return portNum;
}



/**
 * Log errors with VM context
 */
function logError(component, vm_id, action, error) {
  console.error(`[${component}-${vm_id}] ${action} FAILED: ${error.message}`);
  if (error.stack) {
    console.error(`[${component}-${vm_id}] Stack: ${error.stack}`);
  }
}

const { getSecretBundle, encryptSecret, decryptSecret, isEncryptedSecret } = require('./lib/security/crypto-vault');
const { resolveAndMigrateDatabasePath } = require('./lib/db/database');
const { verifyPasswordWithLegacySupport } = require('./lib/db/hvm-importer');
const { securityHeadersAndCsrfMiddleware, verifyCsrfMiddleware, createUnifiedAuthMiddleware } = require('./lib/security/middleware');
const { initializeUnifiedHkvmRuntime, attachUnifiedWebSockets } = require('./lib/context');
const { createApiV1Router } = require('./lib/api/v1/router');
const { createUnifiedWebRouter } = require('./lib/api/web-routes');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });
const PORT = process.env.PORT || 8080;
let hkvmV3Context = null;
let v3PrincipalMiddleware = null;
let v3ApiRouter = null;
let v3WebRouter = null;

// Unified TGVPANEL SQLite store inside ./data/tgvpanel.db (auto-migrates legacy ./data/hkvm.db)
const dbDir =
  process.env.TGVPANEL_DATA_DIR ||
  process.env.HKVM_DATA_DIR ||
  path.join(__dirname, 'data');
let dbPath;
try {
  dbPath = resolveAndMigrateDatabasePath(
    dbDir,
    process.env.TGVPANEL_DB_PATH || process.env.HKVM_DB_PATH
  );
} catch (error) {
  console.error('[Init] Failed to initialize database directory:', dbDir, error.message);
  process.exit(1);
}

const db = new sqlite3.Database(dbPath);

const VM_DIR = path.join(os.homedir(), 'vms');
const TEMPLATES_DIR = path.join(VM_DIR, 'templates');
const ISO_DIR = path.join(VM_DIR, 'iso');
const CLOUDVM_DIR = path.join(VM_DIR, 'cloudvm');

// Create directories if they don't exist
if (!fs.existsSync(VM_DIR)) {
  fs.mkdirSync(VM_DIR, { recursive: true });
}
if (!fs.existsSync(TEMPLATES_DIR)) {
  fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
}
if (!fs.existsSync(ISO_DIR)) {
  fs.mkdirSync(ISO_DIR, { recursive: true });
}
if (!fs.existsSync(CLOUDVM_DIR)) {
  fs.mkdirSync(CLOUDVM_DIR, { recursive: true });
}

// CPU Models available
const CPU_MODELS = {
  'host': {
    name: 'Host CPU (Native)',
    description: 'Use host CPU directly - best performance',
    features: 'host'
  },
  'max': {
    name: 'Maximum Features',
    description: 'Maximum supported features by QEMU',
    features: 'max'
  },
  'qemu64': {
    name: 'QEMU 64-bit',
    description: 'Generic 64-bit processor',
    features: 'qemu64'
  },
  'kvm64': {
    name: 'KVM 64-bit',
    description: 'Optimized for KVM',
    features: 'kvm64'
  },
  'core2duo': {
    name: 'Core 2 Duo',
    description: 'Intel Core 2 Duo',
    features: 'core2duo'
  },
  'corei7': {
    name: 'Core i7',
    description: 'Intel Core i7',
    features: 'corei7'
  },
  'skylake': {
    name: 'Skylake',
    description: 'Intel Skylake',
    features: 'Skylake-Client'
  },
  'cascadelake': {
    name: 'Cascade Lake',
    description: 'Intel Cascade Lake (Server)',
    features: 'Cascadelake-Server'
  },
  'opteron': {
    name: 'Opteron',
    description: 'AMD Opteron',
    features: 'opteron'
  },
  'epyc': {
    name: 'EPYC',
    description: 'AMD EPYC (Server)',
    features: 'EPYC'
  }
};

// Machine Types available for QEMU
const MACHINE_TYPES = {
  'pc': {
    name: 'PC (i440fx - Standard)',
    description: 'Legacy PC emulation, compatible with old guests',
    arch: 'x86_64',
    features: 'Legacy BIOS, VGA, ISA/PCI buses'
  },
  'q35': {
    name: 'Q35 (ICH9 - Modern)',
    description: 'Modern chipset, recommended for newer OS',
    arch: 'x86_64',
    features: 'UEFI-ready, PCIe support, higher performance'
  },
  'microvm': {
    name: 'MicroVM (Minimal)',
    description: 'Lightweight machine type with minimal overhead',
    arch: 'x86_64',
    features: 'Fast boot, low memory footprint, optimal for containers'
  },
  'virt': {
    name: 'Virtual (ARM Generic)',
    description: 'Generic virtual platform for ARM64',
    arch: 'aarch64',
    features: 'ARM64 architecture, flexible device model'
  },
  'versatilepb': {
    name: 'Versatile Platform Baseboard (ARM)',
    description: 'ARM reference board platform',
    arch: 'arm',
    features: 'ARM 32-bit, integrator-style board'
  },
  'raspi2': {
    name: 'Raspberry Pi 2 (ARM)',
    description: 'Emulate Raspberry Pi 2 hardware',
    arch: 'arm',
    features: 'ARM-based SBC, GPIO and peripherals'
  },
  'raspi3': {
    name: 'Raspberry Pi 3 (ARM)',
    description: 'Emulate Raspberry Pi 3 hardware',
    arch: 'arm',
    features: 'ARM 64-bit, WiFi/Bluetooth simulation'
  },
  'pseries': {
    name: 'POWER Series (PowerPC)',
    description: 'IBM Power Systems emulation',
    arch: 'ppc64',
    features: 'PowerPC 64-bit, server-class machine'
  },
  's390-ccw-virtio': {
    name: 'IBM System Z (s390x)',
    description: 'IBM mainframe architecture',
    arch: 's390x',
    features: 's390x architecture, enterprise computing'
  }
};

// Network Configuration Types
const NETWORK_TYPES = {
  nat: {
    name: 'NAT (User Mode)',
    description: 'User-mode networking with automatic port forwarding',
    icon: '<svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: #3B82F6;"><rect x="2" y="2" width="20" height="20" rx="2"/><path d="M12 2v20M2 12h20M6 6h12M6 12h12M6 18h12"/></svg>'
  },
  static_public: {
    name: 'Static Public IPv4',
    description: 'Fixed public IP with bridge network',
    icon: '<svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: #10B981;"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.88 20.73 6.96M12 22.08v-9.53"/></svg>'
  }
};

// DNS Providers
const DNS_PROVIDERS = [
  { name: 'Google DNS', primary: '8.8.8.8', secondary: '8.8.4.4' },
  { name: 'Cloudflare DNS', primary: '1.1.1.1', secondary: '1.0.0.1' },
  { name: 'Quad9 DNS', primary: '9.9.9.9', secondary: '149.112.112.112' },
  { name: 'OpenDNS', primary: '208.67.222.222', secondary: '208.67.220.220' },
  { name: 'Custom', primary: '', secondary: '' }
];

// SMBIOS Manufacturers
const SMBIOS_MANUFACTURERS = [
  'QEMU',
  'Proxmox',
  'Red Hat',
  'VirtualBox',
  'Microsoft Corporation',
  'Dell Inc.',
  'HP Inc.',
  'Lenovo',
  'Custom'
];

// SMBIOS Products
const SMBIOS_PRODUCTS = [
  'KVM Virtual Machine',
  'Standard PC',
  'RHEL Guest',
  'VirtualBox',
  'Virtual Machine',
  'Custom VM',
  'Cloud Instance'
];
const OS_TEMPLATES = {
  ubuntu_22_cloud: {
    name: 'Ubuntu 22.04 LTS',
    type: 'cloud-init',
    icon: '/images/os/ubuntu.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img',
    username: 'ubuntu',
    password: 'ubuntu'
  },
  ubuntu_24_cloud: {
    name: 'Ubuntu 24.04 LTS',
    type: 'cloud-init',
    icon: '/images/os/ubuntu.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img',
    username: 'ubuntu',
    password: 'ubuntu'
  },
  debian_12_cloud: {
    name: 'Debian 12',
    type: 'cloud-init',
    icon: '/images/os/debian.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2',
    username: 'debian',
    password: 'debian'
  },
  fedora_40_cloud: {
    name: 'Fedora 40',
    type: 'cloud-init',
    icon: '/images/os/fedora.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-40-1.14.x86_64.qcow2',
    username: 'fedora',
    password: 'fedora'
  },
  centos_9_cloud: {
    name: 'CentOS Stream 9',
    type: 'cloud-init',
    icon: '/images/os/centos.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2',
    username: 'centos',
    password: 'centos'
  },
  almalinux_9_cloud: {
    name: 'AlmaLinux 9',
    type: 'cloud-init',
    icon: '/images/os/almalinux.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2',
    username: 'almalinux',
    password: 'almalinux'
  },
  proxmox_ve_8: {
    name: 'Proxmox VE 8',
    type: 'cloud-init',
    category: 'hypervisor',
    proxmox_codename: 'bookworm',
    proxmox_gpg_url: 'https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg',
    base_cache_key: 'debian_12_cloud',
    web_port: 8006,
    description: 'Proxmox Virtual Environment 8 on Debian 12 Bookworm (KVM + LXC Hypervisor, HTTPS Web UI on :8006)',
    icon: '/images/os/proxmox.svg',
    disk_size: '40G',
    memory: 4096,
    cpus: 4,
    url: 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2',
    username: 'root',
    password: 'proxmox'
  },
  proxmox_ve_9: {
    name: 'Proxmox VE 9',
    type: 'cloud-init',
    category: 'hypervisor',
    proxmox_codename: 'trixie',
    proxmox_gpg_url: 'https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg',
    web_port: 8006,
    description: 'Proxmox Virtual Environment 9 on Debian 13 Trixie (KVM + LXC Hypervisor, HTTPS Web UI on :8006)',
    icon: '/images/os/proxmox.svg',
    disk_size: '40G',
    memory: 4096,
    cpus: 4,
    url: 'https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2',
    username: 'root',
    password: 'proxmox'
  }
};

function inferDistroLocalIcon(hintText) {
  const s = String(hintText || '').toLowerCase();
  if (s.includes('proxmox') || s.includes('pve')) return '/images/os/proxmox.svg';
  if (s.includes('ubuntu')) return '/images/os/ubuntu.svg';
  if (s.includes('debian')) return '/images/os/debian.svg';
  if (s.includes('fedora')) return '/images/os/fedora.svg';
  if (s.includes('centos')) return '/images/os/centos.svg';
  if (s.includes('alma')) return '/images/os/almalinux.svg';
  return '/images/os/linux.svg';
}

function normalizeOsIcon(icon, hintText = '') {
  const raw = String(icon || '').trim();
  if (!raw || raw === '⚫' || raw.includes('imgur.com')) {
    return inferDistroLocalIcon(hintText);
  }
  return raw;
}

function isProxmoxTemplate(vmOrKey) {
  if (!vmOrKey) return false;
  if (typeof vmOrKey === 'string') {
    const key = vmOrKey.trim().toLowerCase();
    return Boolean(
      (OS_TEMPLATES[vmOrKey] && OS_TEMPLATES[vmOrKey].proxmox_codename) ||
      key.startsWith('proxmox')
    );
  }
  const tplKey = String(vmOrKey.os_template || vmOrKey.template_type || '').trim();
  if (tplKey && OS_TEMPLATES[tplKey] && OS_TEMPLATES[tplKey].proxmox_codename) {
    return true;
  }
  const combined = `${tplKey} ${vmOrKey.os_type || ''} ${vmOrKey.template_name || ''}`.toLowerCase();
  return combined.includes('proxmox');
}

function getProxmoxWebUiPort(vm) {
  if (!vm) return 8006;
  const parsed = parseInt(vm.http_port, 10);
  if (!Number.isNaN(parsed) && parsed >= 1024 && parsed <= 65535 && parsed !== 80) {
    return parsed;
  }
  return 8006;
}

function enrichVmTemplateMetadata(vm) {
  if (!vm || typeof vm !== 'object') return vm;
  const builtIn = vm.template_type && OS_TEMPLATES[vm.template_type] ? OS_TEMPLATES[vm.template_type] : null;
  if (builtIn) {
    if (!vm.template_icon || vm.template_icon === '⚫' || String(vm.template_icon).includes('imgur.com')) {
      vm.template_icon = builtIn.icon;
    }
    if (!vm.template_name || vm.template_name === 'Custom') {
      vm.template_name = builtIn.name;
    }
  } else {
    vm.template_icon = normalizeOsIcon(
      vm.template_icon,
      `${vm.template_type || ''} ${vm.os_type || ''} ${vm.template_name || ''}`
    );
  }
  if (isProxmoxTemplate(vm)) {
    vm.is_proxmox = true;
    vm.web_ui_port = getProxmoxWebUiPort(vm);
  }
  return vm;
}

function resolveAvailableProxmoxWebPort(preferredPort = 8006, excludeVmId = null) {
  return new Promise((resolve) => {
    const query = excludeVmId
      ? `SELECT http_port, ssh_port, ssh_port_static FROM vms WHERE vm_id != ?`
      : `SELECT http_port, ssh_port, ssh_port_static FROM vms`;
    const params = excludeVmId ? [excludeVmId] : [];
    db.all(query, params, (err, rows) => {
      if (err || !Array.isArray(rows)) {
        return resolve(preferredPort);
      }
      const usedPorts = new Set();
      for (const r of rows) {
        if (r.http_port) usedPorts.add(Number(r.http_port));
        if (r.ssh_port) usedPorts.add(Number(r.ssh_port));
        if (r.ssh_port_static) usedPorts.add(Number(r.ssh_port_static));
      }
      let candidate = Number(preferredPort) || 8006;
      while (usedPorts.has(candidate) && candidate < 65000) {
        candidate += 1;
      }
      resolve(candidate);
    });
  });
}

// Middleware
app.use(
  express.json({
    limit: '50mb',
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  })
);
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.get('/js/hkvm-v3.js', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'js', 'tgvpanel-v3.js'));
});
app.use(express.static(path.join(__dirname, 'public')));

const sessionParser = session({
  secret: getSecretBundle().sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
});
app.use(sessionParser);
app.use(securityHeadersAndCsrfMiddleware);

app.use((req, res, next) => {
  res.locals.user = req.session && req.session.userId
    ? {
        id: req.session.userId,
        userId: req.session.userId,
        username: req.session.username,
        role: req.session.role
      }
    : null;
  next();
});

// Initialize License Middleware
licenses.initLicenseMiddleware(app);

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// TGVPANEL Unified Principal, REST API v1, and Unified Web Routes
app.use((req, res, next) => {
  if (v3PrincipalMiddleware) return v3PrincipalMiddleware(req, res, next);
  next();
});
app.use('/api/v1', verifyCsrfMiddleware, (req, res, next) => {
  if (v3ApiRouter) return v3ApiRouter(req, res, next);
  res.status(503).json({ error: 'TGVPANEL runtime is initializing' });
});
app.use((req, res, next) => {
  if (v3WebRouter) return v3WebRouter(req, res, next);
  next();
});

// VM Process Manager (Global)
const vmProcesses = new Map();
// Store QEMU process stdin for console input
const qemuStdins = new Map();

// Initialize Database
function initializeDatabase() {
  // Enable WAL mode to reduce locking issues
  db.run('PRAGMA journal_mode = WAL', (err) => {
    if (err) console.log('[DB] Could not enable WAL mode:', err.message);
  });
  
  db.run('PRAGMA busy_timeout = 5000', (err) => {
    if (err) console.log('[DB] Could not set busy timeout:', err.message);
  });
  
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      full_name TEXT,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      is_active BOOLEAN DEFAULT 1
    )`);

    // Add missing columns if they don't exist
    db.all(`PRAGMA table_info(users)`, (err, columns) => {
      const columnNames = columns.map(c => c.name);
      if (!columnNames.includes('full_name')) {
        db.run(`ALTER TABLE users ADD COLUMN full_name TEXT`, (err) => {
          if (err) console.log('[DB] full_name column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('last_login')) {
        db.run(`ALTER TABLE users ADD COLUMN last_login DATETIME`, (err) => {
          if (err) console.log('[DB] last_login column already exists or error:', err.message);
        });
      }
    });

    db.run(`CREATE TABLE IF NOT EXISTS vms (
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
      ssh_port INTEGER,
      ssh_port_static INTEGER DEFAULT 22,
      http_port INTEGER DEFAULT 80,
      ipv6_address TEXT,
      ipv6_gateway TEXT,
      mac_address TEXT,
      bridge_interface TEXT,
      vlan_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      owner_id INTEGER,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    )`);

    // Add missing columns for existing databases (safe - ignores if already exist)
    const missingColumns = [
      { name: 'custom_cpu_name', def: 'TEXT' },
      { name: 'machine_type', def: "TEXT DEFAULT 'pc'" },
      { name: 'board_name', def: "TEXT DEFAULT 'Main-Board'" },
      { name: 'product_name', def: "TEXT DEFAULT 'Virtual Machine'" },
      { name: 'custom_smbios_manufacturer', def: "TEXT DEFAULT 'QEMU'" },
      { name: 'ipv4_netmask', def: "TEXT DEFAULT '255.255.255.0'" },
      { name: 'dns_primary', def: "TEXT DEFAULT '8.8.8.8'" },
      { name: 'dns_secondary', def: "TEXT DEFAULT '8.8.4.4'" },
      { name: 'iso_attached', def: 'TEXT' },
      { name: 'boot_from_iso', def: 'BOOLEAN DEFAULT 0' },
      { name: 'bridge_device', def: "TEXT DEFAULT 'vmbr0'" }
    ];

    missingColumns.forEach(col => {
      db.run(`ALTER TABLE vms ADD COLUMN ${col.name} ${col.def}`, (err) => {
        if (err) {
          if (!err.message.includes('duplicate column')) {
            console.log(`Note: Column ${col.name} - ${err.message}`);
          }
        } else {
          console.log(`✓ Added column: ${col.name}`);
        }
      });
    });

    db.run(`CREATE TABLE IF NOT EXISTS vm_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_id INTEGER,
      action TEXT,
      status TEXT,
      message TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS vm_snapshots (
      snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_id INTEGER,
      snapshot_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      size_gb REAL,
      description TEXT,
      FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS os_templates (
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
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      setting_key TEXT UNIQUE NOT NULL,
      setting_value TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Discord OAuth settings table
    db.run(`CREATE TABLE IF NOT EXISTS discord_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      enabled BOOLEAN DEFAULT 0,
      client_id TEXT,
      client_secret TEXT,
      redirect_uri TEXT,
      bot_token TEXT,
      guild_id TEXT,
      auto_role_id TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Discord user accounts linking table
    db.run(`CREATE TABLE IF NOT EXISTS user_discord_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      discord_id TEXT UNIQUE NOT NULL,
      discord_username TEXT,
      discord_email TEXT,
      discord_avatar TEXT,
      connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Initialize default site settings if not exist
    const defaultSettings = {
      'site_name': 'TGVPANEL',
      'site_description': 'Virtual Machine Management System',
      'site_icon_url': '/images/logo.png',
    };
    
    Object.entries(defaultSettings).forEach(([key, value]) => {
      db.get(`SELECT * FROM settings WHERE setting_key = ?`, [key], (err, row) => {
        if (!row) {
          db.run(`INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)`, [key, value]);
        }
      });
    });

    // Add Discord columns to users table if they don't exist
    db.all(`PRAGMA table_info(users)`, (err, columns) => {
      if (columns) {
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('discord_id')) {
          db.run(`ALTER TABLE users ADD COLUMN discord_id TEXT`, (err) => {
            if (!err) console.log('✓ Added column: discord_id');
          });
        }
      }
    });

    db.get(`SELECT * FROM users WHERE username = 'admin'`, (err, row) => {
      if (!row) {
        const hashedPassword = bcrypt.hashSync('admin', 10);
        db.run(`INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`,
          ['admin', hashedPassword, 'admin@shadowgamerind.local', 'admin']);
        console.log('✓ Default admin created: admin/admin (role: admin)');
      } else {
        console.log(`✓ Admin user exists: ${row.username} (role: ${row.role})`);
      }
    });
  });
}

// AUTH
function checkAuth(req, res, next) {
  if (!req.session.userId) {
    console.warn(`[Auth Error] Unauthenticated access attempt to ${req.method} ${req.path}`);
    // Always redirect to login, never return JSON error
    return res.redirect('/login');
  }
  console.log(`[Auth Success] User ${req.session.userId} (${req.session.username}) accessing ${req.method} ${req.path}`);
  next();
}

function checkAdmin(req, res, next) {
  if (!req.session.userId) {
    console.warn(`[Auth Error] Unauthenticated access attempt to admin ${req.method} ${req.path}`);
    // Always redirect to login
    return res.redirect('/login');
  }
  
  if (req.session.role !== 'admin') {
    console.warn(`[Auth Error] Non-admin user ${req.session.userId} (${req.session.username}) attempted admin access to ${req.method} ${req.path}`);
    // Redirect to dashboard for non-admin
    return res.redirect('/admin/dashboard');
  }
  console.log(`[Auth Success] Admin ${req.session.userId} (${req.session.username}) accessing ${req.method} ${req.path}`);
  next();
}

// ============= AUTH ROUTES =============

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  console.log(`[Auth] Login attempt for username: ${username}`);
  
  db.get(`SELECT * FROM users WHERE username = ? AND is_active = 1`, [username], (err, user) => {
    if (err) {
      console.error(`[Auth Error] Login query failed for ${username}:`, err);
      return res.status(500).json({ error: err.message });
    }
    
    const verdict = user
      ? verifyPasswordWithLegacySupport(String(password || ''), user.password)
      : { valid: false, needsRehash: false };

    if (!user || !verdict.valid) {
      console.warn(`[Auth Error] Invalid credentials for username: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (verdict.needsRehash) {
      const upgradedHash = bcrypt.hashSync(String(password), 12);
      db.run(
        `UPDATE users SET password = ? WHERE id = ?`,
        [upgradedHash, user.id],
        (rehashErr) => {
          if (rehashErr) console.error('[DB Error] Legacy password rehash failed:', rehashErr);
        }
      );
    }

    // Check if TOTP 2FA is enabled for this user
    if (user.two_factor_enabled && user.two_factor_secret_enc) {
      req.session.pending2faUser = {
        id: user.id,
        username: user.username,
        role: user.role,
        email: user.email
      };
      return res.json({
        success: true,
        requires2FA: true,
        redirectTo: '/login/2fa'
      });
    }
    
    // Update last login
    db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id], (err) => {
      if (err) console.error('[DB Error] Failed to update last_login:', err);
    });
    
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    req.session.user = { id: user.id, username: user.username, role: user.role };
    if (hkvmV3Context) {
      hkvmV3Context.db
        .logActivity({
          userId: user.id,
          action: 'auth.login',
          resourceType: 'user',
          resourceId: user.id,
          ipAddress: req.ip
        })
        .catch(() => undefined);
    }
    console.log(`[Auth Success] User ${user.id} (${user.username}) logged in with role: ${user.role}`);
    res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
  });
});

app.post('/api/logout', (req, res) => {
  console.log(`[Auth] User ${req.session.userId} (${req.session.username}) logged out`);
  req.session.destroy(() => {
    console.log(`[Auth] Session destroyed`);
    res.json({ success: true });
  });
});

app.get('/api/auth/check', (req, res) => {
  if (req.session.userId) {
    res.json({ authenticated: true, user: { id: req.session.userId, username: req.session.username, role: req.session.role } });
  } else {
    res.json({ authenticated: false });
  }
});

// ============= DISCORD OAUTH ROUTES =============

const axios = require('axios');

// Get Discord OAuth state from session
function generateDiscordAuthUrl() {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM discord_settings WHERE enabled = 1`, (err, settings) => {
      if (err || !settings || !settings.client_id) {
        return reject(new Error('Discord auth not configured'));
      }

      const params = new URLSearchParams({
        client_id: settings.client_id,
        redirect_uri: settings.redirect_uri,
        response_type: 'code',
        scope: 'identify email',
        state: require('crypto').randomBytes(16).toString('hex')
      });

      resolve({
        url: `https://discord.com/api/oauth2/authorize?${params.toString()}`,
        state: params.get('state')
      });
    });
  });
}

// Check if Discord auth is enabled (public endpoint for login page)
app.get('/api/discord-enabled', (req, res) => {
  db.get(`SELECT enabled FROM discord_settings LIMIT 1`, (err, settings) => {
    if (err || !settings) {
      return res.json({ enabled: false });
    }
    res.json({ enabled: settings.enabled ? true : false });
  });
});

app.get('/api/discord-auth-url', async (req, res) => {
  try {
    const authData = await generateDiscordAuthUrl();
    req.session.discordState = authData.state;
    res.json({ url: authData.url });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code) {
    return res.redirect('/login?error=Discord authentication failed');
  }

  // Verify state to prevent CSRF
  if (state !== req.session.discordState) {
    console.error('[Discord Auth] State mismatch - possible CSRF attack');
    return res.redirect('/login?error=State validation failed');
  }

  try {
    // Get Discord settings
    const settings = await new Promise((resolve, reject) => {
      db.get(`SELECT * FROM discord_settings WHERE enabled = 1`, (err, s) => {
        if (err || !s) reject(new Error('Discord auth not configured'));
        else resolve(s);
      });
    });

    // Exchange code for token
    const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', {
      client_id: settings.client_id,
      client_secret: settings.client_secret,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: settings.redirect_uri,
      scope: 'identify email'
    }, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const access_token = tokenResponse.data.access_token;

    // Get Discord user info
    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });

    const discordUser = userResponse.data;
    const discordId = discordUser.id;
    const discordUsername = discordUser.username;
    const discordEmail = discordUser.email;
    const discordAvatar = discordUser.avatar;

    console.log(`[Discord Auth] User ${discordUsername} (${discordId}) authenticated`);

    // Check if Discord account is already linked
    db.get(`SELECT * FROM user_discord_accounts WHERE discord_id = ?`, [discordId], (err, linked) => {
      if (err) {
        console.error('[Discord Auth] DB error:', err);
        return res.redirect('/login?error=Database error');
      }

      if (linked) {
        // Already linked - update avatar and log them in
        db.run(`UPDATE user_discord_accounts SET discord_avatar = ? WHERE discord_id = ?`, [discordAvatar || '', discordId], (err) => {
          if (err) console.error('[Discord Auth] Failed to update avatar:', err);
        });
        
        db.get(`SELECT * FROM users WHERE id = ?`, [linked.user_id], (err, user) => {
          if (err || !user) {
            return res.redirect('/login?error=User not found');
          }

          // Update last login
          db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id]);

          req.session.userId = user.id;
          req.session.username = user.username;
          req.session.role = user.role;

          console.log(`[Discord Auth] User ${user.username} (${user.id}) logged in via Discord`);
          res.redirect('/dashboard');
        });
      } else {
        // Check if email exists in system
        if (discordEmail) {
          db.get(`SELECT * FROM users WHERE email = ?`, [discordEmail], (err, existingUser) => {
            if (err) {
              console.error('[Discord Auth] DB error:', err);
              return res.redirect('/login?error=Database error');
            }

            if (existingUser) {
              // Email exists - offer to link
              req.session.pendingDiscordAuth = {
                discordId: discordId,
                discordUsername: discordUsername,
                discordEmail: discordEmail,
                discordAvatar: discordAvatar,
                action: 'link'
              };
              res.redirect('/link-discord-account');
            } else {
              // New user - create account
              createDiscordUser(discordId, discordUsername, discordEmail, discordAvatar, res, req);
            }
          });
        } else {
          // No email - require manual creation
          req.session.pendingDiscordAuth = {
            discordId: discordId,
            discordUsername: discordUsername,
            discordEmail: discordEmail,
            discordAvatar: discordAvatar,
            action: 'create'
          };
          res.redirect('/create-account-discord');
        }
      }
    });
  } catch (err) {
    console.error('[Discord Auth] Error:', err.message);
    res.redirect('/login?error=' + encodeURIComponent(err.message));
  }
});

function createDiscordUser(discordId, discordUsername, discordEmail, discordAvatar, res, req) {
  // Generate a random password (user won't use it for Discord login)
  const tempPassword = require('crypto').randomBytes(16).toString('hex');
  const hashedPassword = bcrypt.hashSync(tempPassword, 10);

  db.run(
    `INSERT INTO users (username, password, email, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, ?)`,
    [discordUsername, hashedPassword, discordEmail, discordUsername, 'user', 1],
    function(err) {
      if (err) {
        console.error('[Discord Auth] Failed to create user:', err);
        return res.redirect('/login?error=Failed to create account');
      }

      const userId = this.lastID;

      // Link Discord account
      db.run(
        `INSERT INTO user_discord_accounts (user_id, discord_id, discord_username, discord_email, discord_avatar) VALUES (?, ?, ?, ?, ?)`,
        [userId, discordId, discordUsername, discordEmail, discordAvatar || ''],
        (err) => {
          if (err) {
            console.error('[Discord Auth] Failed to link Discord account:', err);
            return res.redirect('/login?error=Failed to link account');
          }

          // Log them in
          db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [userId]);

          req.session.userId = userId;
          req.session.username = discordUsername;
          req.session.role = 'user';

          console.log(`[Discord Auth] New user ${discordUsername} (${userId}) created via Discord`);
          res.redirect('/dashboard');
        }
      );
    }
  );
}

// Link Discord to existing account (requires login first)
app.post('/api/link-discord-account', checkAuth, (req, res) => {
  if (!req.session.pendingDiscordAuth) {
    return res.status(400).json({ error: 'No pending Discord authentication' });
  }

  const { discordId, discordUsername, discordEmail, discordAvatar } = req.session.pendingDiscordAuth;
  const userId = req.session.userId;

  db.run(
    `INSERT OR REPLACE INTO user_discord_accounts (user_id, discord_id, discord_username, discord_email, discord_avatar) VALUES (?, ?, ?, ?, ?)`,
    [userId, discordId, discordUsername, discordEmail, discordAvatar || ''],
    (err) => {
      if (err) {
        console.error('[Discord Auth] Failed to link account:', err);
        return res.status(500).json({ error: err.message });
      }

      delete req.session.pendingDiscordAuth;
      console.log(`[Discord Auth] Linked Discord account ${discordUsername} to user ${userId}`);
      res.json({ success: true, message: 'Discord account linked successfully' });
    }
  );
});

// Unlink Discord account
app.post('/api/unlink-discord-account', checkAuth, (req, res) => {
  const userId = req.session.userId;

  db.run(`DELETE FROM user_discord_accounts WHERE user_id = ?`, [userId], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    console.log(`[Discord Auth] Unlinked Discord account from user ${userId}`);
    res.json({ success: true, message: 'Discord account unlinked' });
  });
});

// Get Discord account info
app.get('/api/discord-account-info', checkAuth, (req, res) => {
  const userId = req.session.userId;

  db.get(
    `SELECT discord_id, discord_username, discord_email, discord_avatar, connected_at FROM user_discord_accounts WHERE user_id = ?`,
    [userId],
    (err, account) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      // Return null if no Discord account linked, or the account object if linked
      if (!account) {
        return res.json(null);
      }
      res.json(account);
    }
  );
});

// ============= OS TEMPLATES =============

app.get('/api/os-templates', (req, res) => {
  // First get database templates
  db.all(`SELECT * FROM os_templates WHERE is_active = 1 ORDER BY created_at DESC`, (err, dbTemplates) => {
    if (err || !dbTemplates) {
      // If error, return default built-in templates only
      return res.json(OS_TEMPLATES);
    }

    // Combine DB templates with built-in templates
    const dbTemplateMap = {};
    if (dbTemplates && dbTemplates.length > 0) {
      dbTemplates.forEach(t => {
        dbTemplateMap[t.template_key] = t;
      });
    }

    // Get built-in templates as object
    const allTemplates = { ...OS_TEMPLATES };
    
    // Add custom templates from DB
    if (dbTemplates && dbTemplates.length > 0) {
      dbTemplates.forEach(t => {
        if (OS_TEMPLATES[t.template_key] && !t.is_custom) {
          return;
        }
        allTemplates[t.template_key] = {
          template_key: t.template_key,
          name: t.template_name,
          type: t.template_type,
          icon: normalizeOsIcon(t.icon, `${t.template_key} ${t.template_name}`),
          description: t.description || null,
          disk_size: t.disk_size,
          memory: t.memory,
          cpus: t.cpus,
          username: t.username,
          password: t.password || 'password',
          url: t.download_url,
          is_custom: true
        };
      });
    }

    res.json(allTemplates);
  });
});

// Get all templates (admin) - includes inactive
app.get('/api/admin/templates', checkAuth, checkAdmin, (req, res) => {
  console.log(`[API] GET /api/admin/templates - Admin requesting all templates`);
  
  // Query custom templates from database
  db.all(`SELECT * FROM os_templates ORDER BY is_custom DESC, created_at DESC`, [], (err, dbTemplates) => {
    if (err) {
      console.error(`[API] GET /api/admin/templates - DB Query Error:`, err.message);
      return res.status(500).json({ 
        error: 'Database error', 
        message: err.message,
        status: 'error'
      });
    }

    // Build built-in templates list
    const builtInList = [];
    for (const [key, template] of Object.entries(OS_TEMPLATES)) {
      builtInList.push({
        template_id: null,
        template_key: key,
        template_name: template.name,
        template_type: template.type,
        icon: template.icon,
        description: template.description || `Built-in template for ${template.name}`,
        disk_size: template.disk_size,
        memory: template.memory,
        cpus: template.cpus,
        web_port: template.web_port || null,
        category: template.category || 'os',
        download_url: template.url,
        local_path: null,
        username: template.username,
        password: template.password,
        is_custom: 0,
        is_active: 1,
        created_at: null,
        created_by: null
      });
    }

    // Combine: custom templates + built-in templates
    const allTemplates = [];
    
    // Add custom templates first
    if (dbTemplates && Array.isArray(dbTemplates)) {
      dbTemplates.forEach(t => {
        if (OS_TEMPLATES[t.template_key] && !t.is_custom) {
          return;
        }
        allTemplates.push({
          template_id: t.template_id,
          template_key: t.template_key,
          template_name: t.template_name,
          template_type: t.template_type,
          icon: normalizeOsIcon(t.icon, `${t.template_key} ${t.template_name}`),
          description: t.description,
          disk_size: t.disk_size,
          memory: t.memory,
          cpus: t.cpus,
          download_url: t.download_url,
          local_path: t.local_path,
          username: t.username,
          password: t.password,
          is_custom: t.is_custom,
          is_active: t.is_active,
          created_at: t.created_at,
          created_by: t.created_by
        });
      });
    }
    
    // Add built-in templates
    allTemplates.push(...builtInList);

    console.log(`[API] GET /api/admin/templates - Returning ${allTemplates.length} templates (${dbTemplates ? dbTemplates.length : 0} custom + ${builtInList.length} built-in)`);
    res.json(allTemplates);
  });
});

// Create custom template
app.post('/api/admin/templates', checkAuth, checkAdmin, async (req, res) => {
  const { template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, username, password } = req.body;

  if (!template_key || !template_name) {
    return res.status(400).json({ error: 'Template key and name are required' });
  }

  if (!disk_size) {
    return res.status(400).json({ error: 'Disk size is required' });
  }

  // Check if template key already exists
  db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [template_key], async (err, existing) => {
    if (existing) {
      return res.status(400).json({ error: 'Template with this key already exists' });
    }

    try {
      // Just store the template metadata - NO AUTO DOWNLOAD
      // User can download manually from templates list if needed
      const localPath = null; // Leave empty - user downloads manually

      // Insert into database
      db.run(
        `INSERT INTO os_templates 
        (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, local_path, username, password, is_custom, created_by) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
        [template_key, template_name, template_type || 'cloud-init', icon || '📦', description || '', disk_size, memory || 2048, cpus || 2, download_url || '', localPath || '', username || '', password || '', req.session.userId],
        function(err) {
          if (err) return res.status(500).json({ error: err.message });
          
          res.json({
            success: true,
            template_id: this.lastID,
            template_key,
            message: 'Template created successfully! Download it manually from the templates list if needed.'
          });
        }
      );
    } catch (error) {
      res.status(500).json({ error: 'Failed to create template: ' + error.message });
    }
  });
});

// Update template
app.put('/api/admin/templates/:id', checkAuth, checkAdmin, (req, res) => {
  const { template_name, icon, description, disk_size, memory, cpus, username, password, is_active } = req.body;
  const templateId = req.params.id;

  const updates = [];
  const values = [];

  if (template_name) { updates.push('template_name = ?'); values.push(template_name); }
  if (icon !== undefined) { updates.push('icon = ?'); values.push(icon || '📦'); }
  if (description !== undefined) { updates.push('description = ?'); values.push(description || ''); }
  if (disk_size) { updates.push('disk_size = ?'); values.push(disk_size); }
  if (memory) { updates.push('memory = ?'); values.push(memory); }
  if (cpus) { updates.push('cpus = ?'); values.push(cpus); }
  if (username) { updates.push('username = ?'); values.push(username); }
  if (password) { updates.push('password = ?'); values.push(password); }
  if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active ? 1 : 0); }
  
  updates.push('updated_at = datetime("now")');

  if (updates.length === 1) { // Only updated_at
    return res.status(400).json({ error: 'No fields to update' });
  }

  values.push(templateId);
  const query = `UPDATE os_templates SET ${updates.join(', ')} WHERE template_id = ?`;

  db.run(query, values, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, message: 'Template updated successfully' });
  });
});

// Update Built-in Template (creates/updates in database)
app.put('/api/admin/templates/builtin/:key', checkAuth, checkAdmin, (req, res) => {
  const templateKey = req.params.key;
  const { template_name, icon, description, disk_size, memory, cpus, username, password } = req.body;

  if (!OS_TEMPLATES[templateKey]) {
    return res.status(404).json({ error: 'Built-in template not found' });
  }

  const builtIn = OS_TEMPLATES[templateKey];

  // Check if already exists in database
  db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [templateKey], (err, existing) => {
    if (err) return res.status(500).json({ error: err.message });

    const finalData = {
      template_key: templateKey,
      template_name: template_name || builtIn.name,
      template_type: builtIn.type,
      icon: icon || builtIn.icon,
      description: description || `Built-in: ${builtIn.name}`,
      disk_size: disk_size || builtIn.disk_size,
      memory: memory || builtIn.memory,
      cpus: cpus || builtIn.cpus,
      download_url: builtIn.url,
      username: username || builtIn.username,
      password: password || builtIn.password,
      is_custom: 0
    };

    if (existing) {
      // Update existing
      db.run(
        `UPDATE os_templates SET 
         template_name = ?, icon = ?, description = ?, disk_size = ?, memory = ?, cpus = ?, 
         username = ?, password = ?, updated_at = datetime("now")
         WHERE template_key = ?`,
        [finalData.template_name, finalData.icon, finalData.description, finalData.disk_size, 
         finalData.memory, finalData.cpus, finalData.username, finalData.password, templateKey],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true, message: 'Built-in template updated successfully' });
        }
      );
    } else {
      // Insert new
      db.run(
        `INSERT INTO os_templates 
         (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, 
          download_url, username, password, is_custom, created_by) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
        [finalData.template_key, finalData.template_name, finalData.template_type, finalData.icon, 
         finalData.description, finalData.disk_size, finalData.memory, finalData.cpus, 
         finalData.download_url, finalData.username, finalData.password, 1],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true, message: 'Built-in template saved successfully' });
        }
      );
    }
  });
});

// Delete template
app.delete('/api/admin/templates/:id', checkAuth, checkAdmin, (req, res) => {
  const templateId = req.params.id;

  db.get(`SELECT * FROM os_templates WHERE template_id = ?`, [templateId], (err, template) => {
    if (err || !template) return res.status(404).json({ error: 'Template not found' });

    // Delete local file if exists
    if (template.local_path && fs.existsSync(template.local_path)) {
      try {
        fs.unlinkSync(template.local_path);
      } catch (e) {
        console.error('Failed to delete template file:', e.message);
      }
    }

    // Delete from database
    db.run(`DELETE FROM os_templates WHERE template_id = ?`, [templateId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, message: 'Template deleted successfully' });
    });
  });
});

// Download template file (get template by key)
app.post('/api/admin/templates/:key/download', checkAuth, checkAdmin, async (req, res) => {
  const templateKey = req.params.key;

  try {
    // Check if it's a built-in template
    if (OS_TEMPLATES[templateKey]) {
      const template = OS_TEMPLATES[templateKey];
      const fileName = `${templateKey}-template.qcow2`;
      const localPath = path.join(TEMPLATES_DIR, fileName);

      // Create templates directory if it doesn't exist
      if (!fs.existsSync(TEMPLATES_DIR)) {
        fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
      }

      if (fs.existsSync(localPath)) {
        console.log(`[TEMPLATE] ${templateKey} already cached at ${localPath}`);
        return res.json({ success: true, message: 'Template already cached locally', local_path: localPath });
      }

      console.log(`[TEMPLATE] Starting download of ${templateKey} from ${template.url}`);

      // Download the template
      await downloadTemplateFromURL(template.url, localPath);

      console.log(`[TEMPLATE] Download complete for ${templateKey}`);

      // Save to database
      db.run(
        `INSERT OR REPLACE INTO os_templates 
        (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, local_path, username, password, is_custom) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
        [templateKey, template.name, template.type, template.icon, `Built-in: ${template.name}`, template.disk_size, template.memory, template.cpus, template.url, localPath, template.username, template.password],
        (err) => {
          if (err) console.error('Failed to save template to database:', err);
          res.json({ success: true, message: 'Template downloaded and cached', local_path: localPath });
        }
      );
    } else {
      // Custom template
      db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [templateKey], async (err, template) => {
        if (err || !template) return res.status(404).json({ error: 'Template not found' });
        
        // Create templates directory if it doesn't exist
        if (!fs.existsSync(TEMPLATES_DIR)) {
          fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
        }

        // Generate local path if not set
        let localPath = template.local_path;
        if (!localPath) {
          // Extract filename from URL or use template key
          const urlParts = template.download_url.split('/');
          const fileName = urlParts[urlParts.length - 1] || `${templateKey}-template.qcow2`;
          localPath = path.join(TEMPLATES_DIR, fileName);
        }

        if (fs.existsSync(localPath)) {
          console.log(`[TEMPLATE] Custom template ${templateKey} already cached at ${localPath}`);
          
          // Update database with local path if not set
          if (!template.local_path) {
            db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`, 
              [localPath, templateKey], 
              (err) => {
                if (err) console.error('Failed to update template path:', err);
              }
            );
          }
          
          return res.json({ success: true, message: 'Template cached locally', local_path: localPath });
        }

        // Download the template
        try {
          console.log(`[TEMPLATE] Starting download of custom template (${templateKey}) from ${template.download_url}`);
          console.log(`[TEMPLATE] Saving to: ${localPath}`);
          
          await downloadTemplateFromURL(template.download_url, localPath);
          
          console.log(`[TEMPLATE] Download complete for custom template ${templateKey}`);

          // Update database with local path
          db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`, 
            [localPath, templateKey], 
            (err) => {
              if (err) console.error('Failed to update template path:', err);
            }
          );

          res.json({ success: true, message: 'Template downloaded and cached', local_path: localPath });
        } catch (downloadErr) {
          console.error(`[TEMPLATE] Download error for ${templateKey}:`, downloadErr.message);
          res.status(500).json({ error: 'Failed to download template: ' + downloadErr.message });
        }
      });
    }
  } catch (error) {
    console.error(`[TEMPLATE] Error:`, error.message);
    res.status(500).json({ error: 'Failed to download template: ' + error.message });
  }
});

// Get template cache info
app.get('/api/admin/templates/cache/info', checkAuth, checkAdmin, (req, res) => {
  try {
    const templates = [];
    
    if (fs.existsSync(TEMPLATES_DIR)) {
      const files = fs.readdirSync(TEMPLATES_DIR);
      files.forEach(file => {
        const filePath = path.join(TEMPLATES_DIR, file);
        const stat = fs.statSync(filePath);
        templates.push({
          filename: file,
          size: stat.size,
          size_readable: (stat.size / (1024 * 1024 * 1024)).toFixed(2) + ' GB',
          created: stat.birthtime,
          modified: stat.mtime
        });
      });
    }

    res.json({
      cache_directory: TEMPLATES_DIR,
      templates: templates,
      total_count: templates.length,
      total_size: templates.reduce((sum, t) => sum + t.size, 0),
      total_size_readable: (templates.reduce((sum, t) => sum + t.size, 0) / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Clear template cache (admin only)
app.post('/api/admin/templates/cache/clear', checkAuth, checkAdmin, (req, res) => {
  try {
    if (!fs.existsSync(TEMPLATES_DIR)) {
      return res.json({ success: true, message: 'Cache directory does not exist' });
    }

    const files = fs.readdirSync(TEMPLATES_DIR);
    let deleted = 0;
    let errors = [];

    files.forEach(file => {
      const filePath = path.join(TEMPLATES_DIR, file);
      try {
        fs.unlinkSync(filePath);
        deleted++;
      } catch (e) {
        errors.push(file + ': ' + e.message);
      }
    });

    res.json({
      success: true,
      deleted: deleted,
      errors: errors.length > 0 ? errors : null,
      message: `Cleared ${deleted} cached templates`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get CPU Models
app.get('/api/cpu-models', (req, res) => {
  res.json(CPU_MODELS);
});

// Get SMBIOS options
app.get('/api/smbios', (req, res) => {
  res.json({
    manufacturers: SMBIOS_MANUFACTURERS,
    products: SMBIOS_PRODUCTS
  });
});

// Get Network Types
app.get('/api/network-types', (req, res) => {
  res.json(NETWORK_TYPES);
});

// Get DNS Providers
app.get('/api/dns-providers', (req, res) => {
  res.json(DNS_PROVIDERS);
});

// List available ISO files
app.get('/api/iso-list', (req, res) => {
  try {
    const files = fs.readdirSync(ISO_DIR).filter(f => f.endsWith('.iso'));
    res.json(files);
  } catch (error) {
    res.json([]);
  }
});

// ============= VIEW ROUTES (EJS Pages) =============

// Favicon endpoint
app.get('/favicon.ico', (req, res) => {
  res.redirect('/public/images/logo.png');
});

// Middleware to pass user and settings to all views
app.use((req, res, next) => {
  // Set defaults first
  res.locals.user = req.session.userId ? {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role
  } : null;
  
  // Panel version from .env
  res.locals.panelVersion = process.env.PANEL_VERSION || 'V3.0';
  
  // Set default logo and site name
  res.locals.siteLogo = process.env.DEFAULT_LOGO_URL || '/images/logo.png';
  res.locals.siteName =
    process.env.PANEL_NAME && !/^hkvm(\s+panel)?$/i.test(process.env.PANEL_NAME.trim())
      ? process.env.PANEL_NAME
      : 'TGVPANEL';
  
  // Load site settings from database (blocking, so sidebar reflects changes immediately)
  db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_icon_url' LIMIT 1`, (err, row) => {
    if (!err && row && row.setting_value) {
      res.locals.siteLogo = row.setting_value;
    }
    db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_name' LIMIT 1`, (err2, row2) => {
      if (!err2 && row2 && row2.setting_value) {
        const dbSiteName = String(row2.setting_value).trim();
        res.locals.siteName = /^hkvm(\s+panel)?(\s+v[\d.]+)?$/i.test(dbSiteName)
          ? 'TGVPANEL'
          : row2.setting_value;
      }
      next();
    });
  });
});

// License check middleware — silently bypassed
app.use((req, res, next) => { next(); });

// Login page
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('users/login', { 
    title: 'Login - TGVPANEL',
    currentPage: 'login',
    siteLogo: res.locals.siteLogo || process.env.DEFAULT_LOGO_URL || '/images/logo.png',
    siteName: res.locals.siteName || 'TGVPANEL'
  });
});



// License Activation Page — redirect to dashboard
app.get('/license_activation', (req, res) => {
  res.redirect('/dashboard');
});

// License Activation POST — always succeeds
app.post('/api/license/activate', (req, res) => {
  res.json({ success: true, message: 'License active', redirect: '/dashboard' });
});

// Dashboard - Normal users only
app.get('/dashboard', checkAuth, (req, res) => {
  // Show user dashboard (works for both regular users and admins)
  res.render('users/dashboard', {
    title: 'My VMs - TGVPANEL',
    currentPage: 'dashboard',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});
// Admin Dashboard - Admin only
app.get('/admin/dashboard', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/dashboard', {
    title: 'Dashboard - TGVPANEL',
    currentPage: 'dashboard',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Virtual Machines list (Admin only)
app.get('/admin/vms', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vms', {
    title: 'Virtual Machines - TGVPANEL',
    currentPage: 'vms'
  });
});

// Create VM (Admin only)
app.get('/admin/vm-create', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-create', {
    title: 'Create Virtual Machine - TGVPANEL',
    currentPage: 'vm-create',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// VM Details (Admin only)
app.get('/admin/vm/:id', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-detail', {
    title: 'VM Details - TGVPANEL',
    currentPage: 'vm-detail',
    vmId: req.params.id
  });
});

// VM Console (Admin only)
app.get('/admin/vm/:id/console', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-console', {
    title: 'VM Console - TGVPANEL',
    currentPage: 'vm-console',
    vmId: req.params.id
  });
});

// VM Edit Configuration Page (Admin only)
app.get('/admin/vm/:id/edit', checkAuth, checkAdmin, (req, res) => {
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.id], (err, vm) => {
    if (err || !vm) return res.status(404).render('users/404', { message: 'VM not found' });
    
    res.render('admin/vm-edit', {
      title: 'Edit VM - TGVPANEL',
      currentPage: 'vm-edit',
      vmId: req.params.id,
      vm: vm
    });
  });
});

// Users management (admin only)
app.get('/admin/users', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/users', {
    title: 'Users - TGVPANEL',
    currentPage: 'users'
  });
});

// Create new user page (admin only)
app.get('/admin/users/create', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/users-create', {
    title: 'Create User - TGVPANEL',
    currentPage: 'users'
  });
});

// Edit user page (admin only)
app.get('/admin/users/:id/edit', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) {
    return res.status(400).render('admin/404', { title: 'Invalid User ID' });
  }
  
  res.render('admin/users-edit', {
    title: 'Edit User - TGVPANEL',
    currentPage: 'users',
    userId: userId
  });
});

// Settings (admin only)
app.get('/admin/settings', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/settings', {
    title: 'Settings - TGVPANEL',
    currentPage: 'settings'
  });
});

// OS Templates Management (admin only)
app.get('/admin/templates', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/templates', {
    title: 'OS Templates - TGVPANEL',
    currentPage: 'templates'
  });
});

// Add OS Template (admin only)
app.get('/admin/templates/add', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/templates-add', {
    title: 'Add OS Template - TGVPANEL',
    currentPage: 'templates'
  });
});

// Edit Built-in OS Template (admin only)
app.get('/admin/templates/builtin/:key/edit', checkAuth, checkAdmin, (req, res) => {
  const templateKey = req.params.key;
  console.log(`[ROUTE] GET /admin/templates/builtin/${templateKey}/edit`);
  
  if (!OS_TEMPLATES[templateKey]) {
    console.error(`[ERROR] Template key not found: ${templateKey}`);
    return res.status(400).render('admin/404', { title: 'Built-in Template Not Found' });
  }
  
  const template = OS_TEMPLATES[templateKey];
  console.log(`[SUCCESS] Found built-in template: ${template.name}`);
  
  // Build template object for display
  const templateObj = {
    template_key: templateKey,
    template_name: template.name,
    template_type: template.type,
    icon: template.icon,
    description: template.description || `Built-in template for ${template.name}`,
    disk_size: template.disk_size,
    memory: template.memory,
    cpus: template.cpus,
    web_port: template.web_port || null,
    download_url: template.url,
    username: template.username,
    password: template.password,
    is_custom: 0,
    is_builtin: 1
  };
  
  res.render('admin/templates-edit', {
    title: `View ${template.name} - TGVPANEL`,
    currentPage: 'templates',
    siteLogo: res.locals.siteLogo || '/images/logo.png',
    templateKey: templateKey,
    isBuiltin: true,
    template: templateObj
  });
});

// ============= USER ROUTES (Non-Admin Users) =============

// User VMs list
app.get('/vms', checkAuth, (req, res) => {
  res.render('users/vms', {
    title: 'My Virtual Machines - TGVPANEL',
    currentPage: 'vms',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User VM detail page
app.get('/vm/:id', checkAuth, (req, res) => {
  res.render('users/vm-detail', {
    title: 'VM Details - TGVPANEL',
    currentPage: 'vm-detail',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User VM console page
app.get('/vm/:id/console', checkAuth, (req, res) => {
  res.render('users/vm-console', {
    title: 'VM Console - TGVPANEL',
    currentPage: 'vm-console',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User VM SSH connection page
app.get('/vm/:id/ssh', checkAuth, (req, res) => {
  res.render('users/vm-ssh', {
    title: 'SSH Connection - TGVPANEL',
    currentPage: 'vm-ssh',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Admin VM SSH connection page
app.get('/admin/vm/:id/ssh', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-ssh', {
    title: 'SSH Connection - TGVPANEL Admin',
    currentPage: 'vm-ssh',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User profile page
app.get('/profile', checkAuth, (req, res) => {
  res.render('users/profile', {
    title: 'My Profile - TGVPANEL',
    currentPage: 'profile',
    user: {
      username: req.session.username,
      role: req.session.role,
      userId: req.session.userId
    }
  });
});

// ============= API ROUTES =============

// Get list of users for dropdown/assignment (accessible to admins)
app.get('/api/users/list', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT id, username, email, role FROM users WHERE is_active = 1 ORDER BY username`, (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(users);
  });
});

app.get('/api/admin/users', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT id, username, email, role, created_at, is_active FROM users`, (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(users);
  });
});

// Get single user
app.get('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  db.get(`SELECT id, username, email, full_name, role, created_at, is_active FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

// Get user Discord info (for avatar display) - admin only
app.get('/api/admin/users/:id/discord-info', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  db.get(
    `SELECT discord_id, discord_avatar FROM user_discord_accounts WHERE user_id = ?`,
    [userId],
    (err, discordAccount) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!discordAccount) return res.status(404).json({ error: 'No Discord account linked' });
      res.json(discordAccount);
    }
  );
});

app.post('/api/admin/users', checkAuth, checkAdmin, (req, res) => {
  const { username, password, email, full_name, role } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run(
    `INSERT INTO users (username, password, email, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
    [username, hashedPassword, email || null, full_name || null, role || 'user'],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Username already exists' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Update user
app.put('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  const { email, full_name, password, role, is_active } = req.body;
  
  if (userId === 1 && role && role !== 'admin') {
    return res.status(400).json({ error: 'Default admin must remain an admin' });
  }
  
  let query = 'UPDATE users SET ';
  let values = [];
  
  if (email !== undefined) {
    query += 'email = ?, ';
    values.push(email);
  }
  
  if (full_name !== undefined) {
    query += 'full_name = ?, ';
    values.push(full_name);
  }
  
  if (password) {
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    query += 'password = ?, ';
    values.push(bcrypt.hashSync(password, 10));
  }
  
  if (role !== undefined) {
    query += 'role = ?, ';
    values.push(role);
  }
  
  if (is_active !== undefined) {
    query += 'is_active = ?, ';
    values.push(is_active ? 1 : 0);
  }
  
  query = query.slice(0, -2); // Remove trailing comma and space
  query += ' WHERE id = ?';
  values.push(userId);
  
  db.run(query, values, (err) => {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true });
  });
});

app.delete('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  if (req.params.id === '1') {
    return res.status(400).json({ error: 'Cannot delete default admin' });
  }
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ============= VM MANAGEMENT (VM ID BASED) =============

app.get('/api/vms', checkAuth, (req, res) => {
  const userId = req.session.userId;
  
  // User pages always show ONLY the logged-in user's own VMs
  // (even if user is admin - they see their own VMs, not all VMs)
  // For all VMs, use /api/admin/vms endpoint
  let query = `SELECT vms.*, COALESCE(t.icon, '⚫') as template_icon, COALESCE(t.template_name, vms.os_type) as template_name
              FROM vms 
              LEFT JOIN os_templates t ON vms.template_type = t.template_key
              WHERE vms.owner_id = ?
              ORDER BY vms.vm_id DESC`;
  let params = [userId];
  
  db.all(query, params, (err, vms) => {
    if (err) {
      console.error('[API Error] /api/vms:', err);
      return res.status(500).json({ error: err.message });
    }
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    const enriched = (vms || []).map(enrichVmTemplateMetadata);
    console.log(`[API Success] /api/vms: User ${userId} (${req.session.role}) fetched ${enriched.length} VMs (own VMs only)`);
    res.json(enriched);
  });
});

// Admin API endpoint: Get all VMs for admin pages
app.get('/api/admin/vms', checkAuth, checkAdmin, (req, res) => {
  const userId = req.session.userId;
  
  // Admin pages can see ALL VMs in the system
  let query = `SELECT vms.*, COALESCE(t.icon, '⚫') as template_icon, COALESCE(t.template_name, vms.os_type) as template_name
              FROM vms 
              LEFT JOIN os_templates t ON vms.template_type = t.template_key
              ORDER BY vms.vm_id DESC`;
  let params = [];
  
  db.all(query, params, (err, vms) => {
    if (err) {
      console.error('[API Error] /api/admin/vms:', err);
      return res.status(500).json({ error: err.message });
    }
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    const enriched = (vms || []).map(enrichVmTemplateMetadata);
    console.log(`[API Success] /api/admin/vms: Admin ${userId} fetched ${enriched.length} VMs (all VMs)`);
    res.json(enriched);
  });
});

app.get('/api/vms/:vm_id', checkAuth, (req, res) => {
  const userId = req.session.userId;
  let query = `
    SELECT 
      vms.*,
      COALESCE(vms.ipv4_gateway, vms.gateway) as gateway,
      COALESCE(ot.icon, '⚫') as template_icon,
      COALESCE(ot.template_name, vms.os_type) as template_name
    FROM vms
    LEFT JOIN os_templates ot ON vms.template_type = ot.template_key
    WHERE vms.vm_id = ?
  `;
  let params = [req.params.vm_id];
  
  // Normal users can only see their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND vms.owner_id = ?`;
    params.push(userId);
  }
  
  db.get(query, params, (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    if (vm.password && isEncryptedSecret(vm.password)) {
      try {
        vm.password = decryptSecret(vm.password);
      } catch (e) {}
    }
    enrichVmTemplateMetadata(vm);
    res.json(vm);
  });
});

// VM CONSOLE - Stream last 100 lines of VM serial output
app.get('/api/vms/:vm_id/console', checkAuth, (req, res) => {
  const vm_id = req.params.vm_id;
  const logFile = path.join(VM_DIR, `vm-${vm_id}.log`);
  
  if (!fs.existsSync(logFile)) {
    return res.json({ vm_id: vm_id, logs: 'Console not available yet', lines: 0 });
  }
  
  try {
    const logs = fs.readFileSync(logFile, 'utf8');
    const lines = logs.split('\n');
    const last100 = lines.slice(-100).join('\n');
    res.json({
      vm_id: vm_id,
      logs: last100,
      total_lines: lines.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VM CONSOLE COMMAND - Send command to VM via serial console
app.post('/api/vms/:vm_id/console/command', checkAuth, async (req, res) => {
  const vm_id = req.params.vm_id;
  const { command } = req.body;
  const userId = req.session.userId;

  if (!command) {
    return res.status(400).json({ error: 'Command required' });
  }

  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [vm_id];
  
  // Normal users can only send commands to their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }

  db.get(query, params, async (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });

    if (vm.status !== 'running') {
      return res.status(400).json({ error: 'VM is not running' });
    }

    try {
      // Command is sent via WebSocket to console
      // Append to log so it appears in console
      const logFile = path.join(VM_DIR, `vm-${vm_id}.log`);
      fs.appendFileSync(logFile, command);
      
      console.log(`[VM-${vm_id}] Command executed: ${command}`);
      res.json({ 
        success: true, 
        message: 'Command sent to VM console',
        command: command,
        vmId: vm_id
      });
    } catch (error) {
      console.error(`[VM-${vm_id}] Error sending command:`, error.message);
      res.status(500).json({ error: 'Failed to send command: ' + error.message });
    }
  });
});

// GET VM EDIT CONFIG (retrieve editable fields)
app.get('/api/vms/:vm_id/edit', checkAuth, (req, res) => {
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.vm_id], (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found' });
    if (req.session.role !== 'admin' && vm.owner_id !== req.session.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Return editable fields
    res.json({
      vm_id: vm.vm_id,
      vm_name: vm.vm_name,
      hostname: vm.hostname,
      memory: vm.memory,
      cpus: vm.cpus,
      cpu_sockets: vm.cpu_sockets,
      cpu_cores: vm.cpu_cores,
      cpu_threads: vm.cpu_threads,
      cpu_model: vm.cpu_model,
      disk_size: vm.disk_size,
      status: vm.status,
      enable_acpi: vm.enable_acpi,
      enable_kvm: vm.enable_kvm,
      extra_args: vm.extra_args,
      network_type: vm.network_type,
      ipv4_address: vm.ipv4_address,
      ipv4_gateway: vm.ipv4_gateway,
      ipv4_netmask: vm.ipv4_netmask,
      dns_primary: vm.dns_primary,
      dns_secondary: vm.dns_secondary,
      ipv6_address: vm.ipv6_address,
      ipv6_gateway: vm.ipv6_gateway,
      mac_address: vm.mac_address,
      vlan_id: vm.vlan_id,
      can_edit: vm.status === 'stopped'
    });
  });
});

// Resize disk qcow2 file (expand or shrink)
async function resizeDisk(vm_id, diskFilePath, newSize) {
  return new Promise((resolve, reject) => {
    try {
      if (!fs.existsSync(diskFilePath)) {
        return reject(new Error('Disk file not found'));
      }

      // Parse size to bytes (handle G, GB, T, TB)
      const parseSize = (sizeStr) => {
        const match = sizeStr.match(/^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$/i);
        if (!match) return null;
        
        let size = parseFloat(match[1]);
        const unit = (match[2] || '').toUpperCase();
        
        const multipliers = { 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4 };
        if (unit.startsWith('K')) size *= multipliers['K'];
        else if (unit.startsWith('M')) size *= multipliers['M'];
        else if (unit.startsWith('G')) size *= multipliers['G'];
        else if (unit.startsWith('T')) size *= multipliers['T'];
        
        return Math.floor(size);
      };

      const newSizeBytes = parseSize(newSize);
      if (!newSizeBytes) {
        return reject(new Error('Invalid size format. Use: 20G, 100GB, 1T, etc.'));
      }

      // Get current disk size from qemu-img (not file size, but virtual size)
      let currentSize;
      try {
        const infoOutput = execSync(`qemu-img info "${diskFilePath}" --output=json`, { stdio: 'pipe', encoding: 'utf8' });
        const imageInfo = JSON.parse(infoOutput);
        currentSize = imageInfo['virtual-size'] || imageInfo['VirtualSize'] || 0;
        console.log(`[DISK-${vm_id}] Detected via qemu-img: Virtual size = ${(currentSize / (1024**3)).toFixed(2)}GB`);
      } catch (err) {
        console.warn(`[DISK-${vm_id}] Could not get size from qemu-img, falling back to file size`);
        const stats = fs.statSync(diskFilePath);
        currentSize = stats.size;
      }

      console.log(`[DISK-${vm_id}] Current: ${(currentSize / (1024**3)).toFixed(2)}GB, Target: ${(newSizeBytes / (1024**3)).toFixed(2)}GB`);

      if (newSizeBytes === currentSize) {
        return resolve({ message: 'size unchanged' });
      }

      // Determine if we're expanding or shrinking
      const isShrink = newSizeBytes < currentSize;
      const operation = isShrink ? 'shrink' : 'expand';

      // Use qemu-img to resize - always use +SIZE syntax for expand, =SIZE for shrink
      let resizeCmd;
      if (isShrink) {
        // Shrinking requires --shrink flag and = syntax
        resizeCmd = `qemu-img resize --shrink "${diskFilePath}" ${newSize}`;
      } else {
        // Expanding - use = syntax (not + syntax)
        resizeCmd = `qemu-img resize "${diskFilePath}" ${newSize}`;
      }

      console.log(`[DISK-${vm_id}] ${operation.toUpperCase()}: Executing: ${resizeCmd}`);
      
      // Execute and capture both stdout and stderr
      let output;
      try {
        output = execSync(resizeCmd, { stdio: 'pipe', encoding: 'utf8', shell: true });
        console.log(`[DISK-${vm_id}] Command output: ${output}`);
      } catch (execErr) {
        // Check if it's just a warning
        const stderr = execErr.stderr ? execErr.stderr.toString() : '';
        const stdout = execErr.stdout ? execErr.stdout.toString() : '';
        
        // If it's a shrink warning, it might still work
        if (isShrink && stderr.includes('Shrinking an image')) {
          console.log(`[DISK-${vm_id}] Shrink warning (expected):`, stderr);
        } else {
          throw execErr;
        }
      }

      console.log(`[DISK-${vm_id}] Disk ${operation}ed to ${newSize}`);
      resolve({ message: `${operation}ed to ${newSize}` });
    } catch (err) {
      reject(err);
    }
  });
}

// Regenerate cloud-init seed for a VM

// UPDATE VM CONFIGURATION (PUT request)
app.put('/api/vms/:vm_id/edit', checkAuth, (req, res) => {
  const vm_id = req.params.vm_id;
  const userId = req.session.userId;
  const {
    vm_name, hostname, memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model,
    custom_cpu_name, username, password,
    disk_size, enable_acpi, enable_kvm, extra_args,
    network_type, ipv4_address, ipv4_gateway, ipv4_netmask, bridge_device,
    dns_primary, dns_secondary, ipv6_address, ipv6_gateway, mac_address, vlan_id,
    machine_type, board_name, product_name, custom_smbios_manufacturer,
    smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
    ssh_port, ssh_port_static,
    owner_id
  } = req.body;

  let query = `SELECT status, template_type, seed_file FROM vms WHERE vm_id = ?`;
  let params = [vm_id];
  
  // Normal users can only edit their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }

  db.get(query, params, (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    
    // Only allow editing stopped VMs
    if (vm.status !== 'stopped') {
      return res.status(400).json({ error: 'VM must be stopped to edit configuration' });
    }

    // Store original VM state for change detection
    const originalVm = { ...vm };

    // Validate inputs - remove strict limits, allow any positive values
    const validatedMemory = memory ? parseInt(memory) : undefined;
    if (validatedMemory && validatedMemory < 1) {
      return res.status(400).json({ error: 'Memory must be at least 1 MB' });
    }
    
    const validatedCpus = cpus ? parseInt(cpus) : undefined;
    if (validatedCpus && validatedCpus < 1) {
      return res.status(400).json({ error: 'CPUs must be at least 1' });
    }
    
    const validatedSockets = cpu_sockets && cpu_sockets >= 1 ? cpu_sockets : undefined;
    const validatedCores = cpu_cores && cpu_cores >= 1 ? cpu_cores : undefined;
    const validatedThreads = cpu_threads && cpu_threads >= 1 ? cpu_threads : undefined;

    // Build update query dynamically
    const updates = [];
    const values = [];

    if (vm_name) { updates.push('vm_name = ?'); values.push(vm_name); }
    if (hostname) { updates.push('hostname = ?'); values.push(hostname); }
    if (validatedMemory) { updates.push('memory = ?'); values.push(validatedMemory); }
    if (validatedCpus) { updates.push('cpus = ?'); values.push(validatedCpus); }
    if (validatedSockets) { updates.push('cpu_sockets = ?'); values.push(validatedSockets); }
    if (validatedCores) { updates.push('cpu_cores = ?'); values.push(validatedCores); }
    if (validatedThreads) { updates.push('cpu_threads = ?'); values.push(validatedThreads); }
    if (cpu_model) { updates.push('cpu_model = ?'); values.push(cpu_model); }
    if (disk_size) { updates.push('disk_size = ?'); values.push(disk_size); }
    if (username) { updates.push('username = ?'); values.push(username); }
    if (password) { updates.push('password = ?'); values.push(encryptSecret(String(password))); }
    if (enable_acpi !== undefined) { updates.push('enable_acpi = ?'); values.push(enable_acpi ? 1 : 0); }
    if (enable_kvm !== undefined) { updates.push('enable_kvm = ?'); values.push(enable_kvm ? 1 : 0); }
    if (extra_args !== undefined) { updates.push('extra_args = ?'); values.push(extra_args || ''); }
    if (network_type) { updates.push('network_type = ?'); values.push(network_type); }
    if (ipv4_address !== undefined) { updates.push('ipv4_address = ?'); values.push(ipv4_address); }
    if (ipv4_gateway !== undefined) { updates.push('ipv4_gateway = ?'); values.push(ipv4_gateway); }
    if (ipv4_netmask !== undefined) { updates.push('ipv4_netmask = ?'); values.push(ipv4_netmask); }
    if (bridge_device !== undefined) { updates.push('bridge_device = ?'); values.push(bridge_device || 'vmbr0'); }
    if (dns_primary) { updates.push('dns_primary = ?'); values.push(dns_primary); }
    if (dns_secondary) { updates.push('dns_secondary = ?'); values.push(dns_secondary); }
    if (ipv6_address !== undefined) { updates.push('ipv6_address = ?'); values.push(ipv6_address); }
    if (ipv6_gateway !== undefined) { updates.push('ipv6_gateway = ?'); values.push(ipv6_gateway); }
    if (mac_address) { updates.push('mac_address = ?'); values.push(mac_address); }
    if (vlan_id !== undefined) { updates.push('vlan_id = ?'); values.push(vlan_id); }
    if (custom_cpu_name) { updates.push('custom_cpu_name = ?'); values.push(custom_cpu_name); }
    if (board_name) { updates.push('board_name = ?'); values.push(board_name); }
    if (product_name) { updates.push('product_name = ?'); values.push(product_name); }
    if (machine_type) { updates.push('machine_type = ?'); values.push(machine_type); }
    if (smbios_manufacturer) { updates.push('smbios_manufacturer = ?'); values.push(smbios_manufacturer); }
    if (smbios_product) { updates.push('smbios_product = ?'); values.push(smbios_product); }
    if (smbios_version) { updates.push('smbios_version = ?'); values.push(smbios_version); }
    if (smbios_serial) { updates.push('smbios_serial = ?'); values.push(smbios_serial); }
    
    // Handle SSH port - prefer ssh_port_static if provided, else use ssh_port
    if (ssh_port_static !== undefined) { updates.push('ssh_port_static = ?'); values.push(ssh_port_static); }
    if (ssh_port !== undefined) { updates.push('ssh_port = ?'); values.push(ssh_port); }
    
    // Only admins can change owner
    if (owner_id !== undefined && req.session.role === 'admin') {
      updates.push('owner_id = ?');
      values.push(owner_id || null); // Allow null to clear owner
      console.log(`[VM ${vm_id}] Admin changing owner to ${owner_id || 'null'}`);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    values.push(vm_id);
    const query = `UPDATE vms SET ${updates.join(', ')} WHERE vm_id = ?`;

    db.run(query, values, async (err) => {
      if (err) return res.status(500).json({ error: err.message });
      
      try {
        // ALWAYS regenerate cloud-init seed when editing ANY field on a cloud-init VM
        // Delete old seed ISO and create new one with current config
        console.log(`[VM-${vm_id}] Template type check: '${originalVm.template_type}'`);
        
        // Always regenerate regardless of template_type
        console.log(`[VM-${vm_id}] ✓ Regenerating seed with current configuration...`);
        
        // Always delete old seed ISO first
        const seedIsoPath = path.join(VM_DIR, `vm-${vm_id}-seed.iso`);
        console.log(`[VM-${vm_id}] Checking for old seed: ${seedIsoPath}`);
        
        if (fs.existsSync(seedIsoPath)) {
          try {
            fs.unlinkSync(seedIsoPath);
            console.log(`[VM-${vm_id}] ✓ Deleted old seed ISO: ${seedIsoPath}`);
          } catch (delErr) {
            console.error(`[VM-${vm_id}] Failed to delete old seed: ${delErr.message}`);
          }
        } else {
          console.log(`[VM-${vm_id}] Old seed not found (OK if first time)`);
        }
        
        // Fetch updated VM with new config and create new seed ISO
        db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vm_id], (err, updatedVm) => {
          if (err) {
            console.error(`[VM-${vm_id}] Failed to fetch updated VM:`, err.message);
            return;
          }
          
          if (!updatedVm) {
            console.error(`[VM-${vm_id}] Updated VM not found in database`);
            return;
          }
          
          console.log(`[VM-${vm_id}] Creating new seed ISO with config - network_type: ${updatedVm.network_type}, ipv4: ${updatedVm.ipv4_address}, gateway: ${updatedVm.ipv4_gateway || updatedVm.gateway}`);
          
          createCloudInitSeed(vm_id, updatedVm)
            .then(() => {
              console.log(`[VM-${vm_id}] ✓ New cloud-init seed ISO created successfully`);
              logVMAction(vm_id, 'edit', 'success', `Cloud-init seed regenerated with updated configuration. Changes will apply on next VM boot.`);
            })
            .catch(seedErr => {
              console.error(`[VM-${vm_id}] ✗ Failed to create cloud-init seed: ${seedErr.message}`);
              logVMAction(vm_id, 'edit', 'warning', `Configuration updated but cloud-init seed creation failed: ${seedErr.message}`);
            });
        });
      } catch (err) {
        console.error(`[VM-${vm_id}] Error during seed regeneration:`, err.message);
      }
      
      res.json({ success: true, message: 'VM configuration updated', vm_id });
    });
  });
});

app.get('/api/vms/:vm_id/stats', checkAuth, async (req, res) => {
  try {
    db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.vm_id], async (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found' });
      if (req.session.role !== 'admin' && vm.owner_id !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
      }

      const activePid = vmProcesses.get(vm.vm_id) || vm.pid || null;
      const stats = {
        vm_id: vm.vm_id,
        vm_name: vm.vm_name,
        status: vm.status,
        memory: vm.memory,
        cpus: vm.cpus,
        disk_size: vm.disk_size,
        uptime: vm.uptime || 0,
        cpu_usage: 0,
        memory_usage: 0,
        disk_usage: 'N/A',
        pid: activePid
      };

      if (hkvmV3Context) {
        try {
          const tel = await hkvmV3Context.kvmAdapter.getTelemetry(vm.vm_id);
          stats.cpu_usage = tel.cpuPercent;
          stats.memory_usage = tel.ramPercent;
          stats.disk_usage = `${tel.diskUsedGb} GB`;
          stats.pid = tel.pid || activePid;
        } catch (e) {}
      } else if ((vm.disk_file || vm.img_file) && fs.existsSync(vm.disk_file || vm.img_file)) {
        const size = fs.statSync(vm.disk_file || vm.img_file).size / (1024 * 1024 * 1024);
        stats.disk_usage = size.toFixed(2) + ' GB';
      }

      res.json(stats);
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// VM REINSTALL ENDPOINT
// ============================================
// POST /api/vms/:vm_id/reinstall
// Owner can reinstall their VM with a different OS template
// Deletes disk and seed ISO but keeps logs
app.post('/api/vms/:vm_id/reinstall', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const { new_os_template, new_username, new_password, confirm } = req.body;
    const userId = req.session.userId;

    if (!confirm) {
      return res.status(400).json({ error: 'Reinstall must be confirmed' });
    }

    if (!new_os_template) {
      return res.status(400).json({ error: 'Please select an OS template' });
    }

    // Get VM
    const getVmQuery = req.session.role === 'admin' 
      ? `SELECT * FROM vms WHERE vm_id = ?`
      : `SELECT * FROM vms WHERE vm_id = ? AND (owner_id = ? OR owner_id IS NULL)`;
    
    const params = req.session.role === 'admin' 
      ? [vm_id]
      : [vm_id, userId];

    db.get(getVmQuery, params, async (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Only allow reinstall if VM is stopped
      if (vm.status !== 'stopped') {
        return res.status(400).json({ error: 'VM must be stopped to reinstall' });
      }

      console.log(`[VM-${vm_id}] ✓ Starting reinstall with template: ${new_os_template}`);
      console.log(`[VM-${vm_id}] Current status: ${vm.status}`);

      try {
        // Validate new template
        let template = null;
        let isCloudInit = false;
        let templateName = 'Custom OS';
        let username = new_username || 'root';
        let password = new_password || 'password';

        if (OS_TEMPLATES[new_os_template]) {
          // Built-in template
          template = OS_TEMPLATES[new_os_template];
          isCloudInit = true;
          templateName = template.name;
          username = new_username || template.username;
          password = new_password || template.password;
          console.log(`[VM-${vm_id}] Using built-in template: ${templateName}`);
        } else {
          // Check database for custom template
          const customTemplate = await new Promise((resolve, reject) => {
            db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [new_os_template], (err, result) => {
              if (err) reject(err);
              else resolve(result);
            });
          });

          if (!customTemplate) {
            const builtInKeys = Object.keys(OS_TEMPLATES);
            return res.status(400).json({ 
              error: `Invalid OS template: ${new_os_template}. Available: ${builtInKeys.join(', ')}` 
            });
          }

          template = customTemplate;
          isCloudInit = customTemplate.template_type === 'cloud-init';
          templateName = customTemplate.template_name;
          username = new_username || customTemplate.username || 'ubuntu';
          password = new_password || customTemplate.password || 'password';
          console.log(`[VM-${vm_id}] Using custom template: ${templateName}`);
        }

        // Delete old files (but keep logs)
        console.log(`[VM-${vm_id}] Cleaning up old files...`);
        const targetDiskFile = vm.disk_file || path.join(VM_DIR, `vm-${vm_id}-disk.qcow2`);
        const targetSeedFile = vm.seed_file || path.join(VM_DIR, `vm-${vm_id}-seed.iso`);
        
        if (vm.disk_file && fs.existsSync(vm.disk_file)) {
          try {
            fs.unlinkSync(vm.disk_file);
            console.log(`[VM-${vm_id}] ✓ Deleted disk file: ${vm.disk_file}`);
          } catch (err) {
            console.warn(`[VM-${vm_id}] ⚠ Failed to delete disk file:`, err.message);
          }
        }
        if (vm.img_file && vm.img_file !== vm.disk_file && fs.existsSync(vm.img_file)) {
          try {
            fs.unlinkSync(vm.img_file);
            console.log(`[VM-${vm_id}] ✓ Deleted legacy img file: ${vm.img_file}`);
          } catch (err) {
            console.warn(`[VM-${vm_id}] ⚠ Failed to delete legacy img file:`, err.message);
          }
        }

        if (vm.seed_file && fs.existsSync(vm.seed_file)) {
          try {
            fs.unlinkSync(vm.seed_file);
            console.log(`[VM-${vm_id}] ✓ Deleted seed ISO: ${vm.seed_file}`);
          } catch (err) {
            console.warn(`[VM-${vm_id}] ⚠ Failed to delete seed ISO:`, err.message);
          }
        }

        // NOTE: Keep log files for audit trail

        const encryptedPassword = password
          ? (isEncryptedSecret(String(password)) ? String(password) : encryptSecret(String(password)))
          : '';
        let nextHttpPort = vm.http_port || 80;
        if (isProxmoxTemplate(new_os_template) && (!vm.http_port || Number(vm.http_port) === 80)) {
          nextHttpPort = vm.network_type === 'nat'
            ? await resolveAvailableProxmoxWebPort(8006, vm_id)
            : 8006;
        }

        // Update VM with new template info and credentials
        db.run(
          `UPDATE vms SET 
            os_type = ?, template_type = ?, username = ?, password = ?, http_port = ?,
            img_file = '', seed_file = ?, disk_file = ?
          WHERE vm_id = ?`,
          [templateName, new_os_template, username, encryptedPassword, nextHttpPort, targetSeedFile, targetDiskFile, vm_id],
          async (err) => {
            if (err) {
              console.error(`[VM-${vm_id}] Failed to update VM info:`, err.message);
              return res.status(500).json({ error: 'Failed to update VM: ' + err.message });
            }

            console.log(`[VM-${vm_id}] ✓ VM info updated - template: ${templateName}, user: ${username}`);

            try {
              // Re-download/setup template if cloud-init
              if (isCloudInit) {
                console.log(`[VM-${vm_id}] Preparing cloud-init template...`);

                db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vm_id], async (err, updatedVm) => {
                  if (err || !updatedVm) {
                    console.error(`[VM-${vm_id}] Failed to fetch updated VM`);
                    return;
                  }

                  try {
                    // Handle template download/copy
                    let imgSourcePath = null;

                    if (OS_TEMPLATES[new_os_template]) {
                      // Built-in template - check cache (or shared base cloud image cache)
                      const cachedTemplateName = `${new_os_template}-template.qcow2`;
                      const cachedTemplatePath = path.join(TEMPLATES_DIR, cachedTemplateName);
                      const baseCacheKey = OS_TEMPLATES[new_os_template].base_cache_key;
                      const baseCachedPath = baseCacheKey
                        ? path.join(TEMPLATES_DIR, `${baseCacheKey}-template.qcow2`)
                        : null;

                      if (fs.existsSync(cachedTemplatePath)) {
                        console.log(`[VM-${vm_id}] ✓ Using cached template: ${cachedTemplatePath}`);
                        imgSourcePath = cachedTemplatePath;
                      } else if (baseCachedPath && fs.existsSync(baseCachedPath)) {
                        console.log(`[VM-${vm_id}] ✓ Reusing shared base cloud image cache: ${baseCachedPath}`);
                        imgSourcePath = baseCachedPath;
                      } else {
                        // Download template
                        const downloadUrl = OS_TEMPLATES[new_os_template].url;
                        console.log(`[VM-${vm_id}] Downloading template from: ${downloadUrl}`);
                        
                        await downloadTemplate(new_os_template, cachedTemplatePath);
                        imgSourcePath = cachedTemplatePath;
                        console.log(`[VM-${vm_id}] ✓ Template downloaded and cached`);
                      }
                    } else {
                      // Custom template - use local path
                      const customTemplate = await new Promise((resolve, reject) => {
                        db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [new_os_template], (err, result) => {
                          if (err) reject(err);
                          else resolve(result);
                        });
                      });

                      if (customTemplate && customTemplate.local_path && fs.existsSync(customTemplate.local_path)) {
                        imgSourcePath = customTemplate.local_path;
                        console.log(`[VM-${vm_id}] ✓ Using custom template: ${imgSourcePath}`);
                      }
                    }

                    if (!imgSourcePath) {
                      console.error(`[VM-${vm_id}] Failed to locate template`);
                      logVMAction(vm_id, 'reinstall', 'error', 'Failed to locate OS template');
                      return;
                    }

                    // Create new disk from template
                    console.log(`[VM-${vm_id}] Creating new disk from template...`);
                    const diskSizeVal = updatedVm.disk_size || '20G';
                    
                    try {
                      // Copy template to disk file
                      const copyCommand = process.platform === 'win32'
                        ? `Copy-Item -Path "${imgSourcePath}" -Destination "${updatedVm.disk_file}" -Force`
                        : `cp "${imgSourcePath}" "${updatedVm.disk_file}"`;

                      execSync(copyCommand, { shell: process.platform === 'win32' ? 'powershell' : '/bin/bash' });
                      console.log(`[VM-${vm_id}] ✓ Disk file created`);

                      // Resize disk to specified size
                      const resizeCommand = process.platform === 'win32'
                        ? `qemu-img resize "${updatedVm.disk_file}" ${diskSizeVal}`
                        : `qemu-img resize "${updatedVm.disk_file}" ${diskSizeVal}`;

                      execSync(resizeCommand, { stdio: 'pipe' });
                      console.log(`[VM-${vm_id}] ✓ Disk resized to ${diskSizeVal}`);

                      // Create new cloud-init seed
                      console.log(`[VM-${vm_id}] Creating cloud-init seed with new credentials...`);
                      await createCloudInitSeed(vm_id, updatedVm);
                      console.log(`[VM-${vm_id}] ✓ Cloud-init seed created`);

                      // Log the action
                      logVMAction(vm_id, 'reinstall', 'success', 
                        `VM reinstalled with ${templateName}. Old disk and seed deleted. New credentials: ${username} / ****. VM ready to start.`);

                      res.json({ 
                        success: true, 
                        message: `VM ${vm_id} reinstalled successfully with ${templateName}. Ready to start.`,
                        vm_id 
                      });

                    } catch (err) {
                      console.error(`[VM-${vm_id}] Disk creation failed:`, err.message);
                      logVMAction(vm_id, 'reinstall', 'error', `Disk creation failed: ${err.message}`);
                      res.status(500).json({ error: 'Failed to create disk: ' + err.message });
                    }

                  } catch (err) {
                    console.error(`[VM-${vm_id}] Reinstall failed:`, err.message);
                    logVMAction(vm_id, 'reinstall', 'error', `Reinstall failed: ${err.message}`);
                    res.status(500).json({ error: 'Reinstall failed: ' + err.message });
                  }
                });

              } else {
                // Non-cloud-init template (ISO) - recreate blank qcow2 root disk
                const diskSizeVal = vm.disk_size || '20G';
                execSync(`qemu-img create -f qcow2 "${targetDiskFile}" ${diskSizeVal}`, { stdio: 'pipe' });
                console.log(`[VM-${vm_id}] ✓ Blank ISO disk created at ${targetDiskFile} (${diskSizeVal})`);
                logVMAction(vm_id, 'reinstall', 'success', `VM configuration and fresh disk created for ${templateName}. Ready to start.`);
                res.json({ 
                  success: true, 
                  message: `VM updated to ${templateName}. Ready to start.`,
                  vm_id 
                });
              }

            } catch (err) {
              console.error(`[VM-${vm_id}] Post-reinstall processing failed:`, err.message);
              logVMAction(vm_id, 'reinstall', 'error', `Post-reinstall processing failed: ${err.message}`);
              res.status(500).json({ error: 'Post-reinstall processing failed: ' + err.message });
            }
          }
        );

      } catch (err) {
        console.error(`[VM-${vm_id}] Reinstall error:`, err.message);
        logVMAction(vm_id, 'reinstall', 'error', err.message);
        res.status(500).json({ error: 'Reinstall failed: ' + err.message });
      }
    });

  } catch (err) {
    console.error(`Reinstall endpoint error:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// VM CREATE (Admin only)
app.post('/api/vms', checkAuth, checkAdmin, async (req, res) => {
  const { 
    vm_name, os_template, hostname, custom_memory, custom_cpus,
    iso_file, custom_username, custom_password, disk_size,
    cpu_sockets, cpu_cores, cpu_threads, cpu_model, custom_cpu_name,
    machine_type, board_name, product_name, custom_smbios_manufacturer,
    smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
    enable_acpi, enable_kvm, extra_args,
    network_type, ipv4_address, gateway, netmask, bridge_device,
    dns_servers, ssh_port, ssh_port_static, http_port,
    ipv6_address, ipv6_gateway, mac_address, vlan_id, owner_id
  } = req.body;
  
  // Alias gateway/netmask to ipv4_gateway/ipv4_netmask (accepting either field name)
  const ipv4_gateway = req.body.ipv4_gateway || gateway;
  const ipv4_netmask = req.body.ipv4_netmask || netmask;
  // Parse DNS servers - can be comma-separated
  const dns_list = dns_servers ? dns_servers.split(',').map(d => d.trim()) : ['8.8.8.8', '8.8.4.4'];
  const dns_primary = dns_list[0] || '8.8.8.8';
  const dns_secondary = dns_list[1] || '8.8.4.4';
  
  // Either os_template or iso_file must be provided
  if (!os_template && !iso_file) {
    return res.status(400).json({ error: 'Please select a template or upload ISO' });
  }

  // Validate memory when explicitly provided (otherwise template default is used below)
  if (custom_memory !== undefined && custom_memory !== null && String(custom_memory).trim() !== '') {
    const memoryNum = parseInt(custom_memory, 10);
    if (!memoryNum || memoryNum < 1) {
      return res.status(400).json({ error: 'Memory must be at least 1 MB' });
    }
  }

  // Validate CPUs when explicitly provided (otherwise template default is used below)
  if (custom_cpus !== undefined && custom_cpus !== null && String(custom_cpus).trim() !== '') {
    const cpusNum = parseInt(custom_cpus, 10);
    if (!cpusNum || cpusNum < 1) {
      return res.status(400).json({ error: 'CPUs must be at least 1' });
    }
  }

  // Validate bridge device if using static IP
  if (network_type === 'static_public' && bridge_device) {
    if (!/^[a-z0-9]+$/.test(bridge_device)) {
      return res.status(400).json({ error: 'Invalid bridge device name. Use only lowercase letters and numbers (e.g., vmbr0, vmbr1)' });
    }
  }

  let template = null;
  let isCloudInit = false;
  let templateName = 'Custom ISO';
  let username = custom_username || 'root';
  let password = custom_password || 'password';

  if (os_template) {
    // Check if it's a built-in template
    if (OS_TEMPLATES[os_template]) {
      template = OS_TEMPLATES[os_template];
      isCloudInit = true;
      templateName = template.name;
      username = custom_username || template.username;
      password = custom_password || template.password;
    } else {
      // Not built-in, check database for custom template
      const customTemplate = await new Promise((resolve, reject) => {
        db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [os_template], (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      });

      if (!customTemplate) {
        const builtInKeys = Object.keys(OS_TEMPLATES);
        console.warn(`[VM Creation] Invalid template key: "${os_template}". Available built-in: ${builtInKeys.join(', ')}`);
        return res.status(400).json({ error: `Invalid OS template: ${os_template}. Please select a valid template.` });
      }

      // Use custom template
      template = customTemplate;
      isCloudInit = customTemplate.template_type === 'cloud-init';
      templateName = customTemplate.template_name;
      username = custom_username || customTemplate.username || 'ubuntu';
      password = custom_password || customTemplate.password || 'password';
      console.log(`[VM Creation] Using custom template: ${templateName} (${os_template})`);
    }
  }

  const memory = parseInt(custom_memory) || (template ? template.memory : 2048);
  const cpuCount = parseInt(custom_cpus) || (template ? template.cpus : 2);
  const sockets = cpu_sockets || 1;
  const cores = cpu_cores || cpuCount;
  const threads = cpu_threads || 1;
  const cpuModelToUse = cpu_model && CPU_MODELS[cpu_model] ? cpu_model : 'host';
  const diskSizeVal = disk_size || (template ? template.disk_size : '20G');
  const netType = network_type || 'nat';
  const macAddr = mac_address || generateMACAddress();
  const vmOwner = owner_id || req.session.userId; // Use selected owner if provided, else current user
  
  // Handle SSH port - prefer ssh_port_static if provided, else use ssh_port
  const sshPortVal = ssh_port_static || ssh_port || 22;
  const isProxmoxVm = isProxmoxTemplate({ os_template, os_type: templateName });
  let effectiveHttpPort = parseInt(http_port, 10) || 80;
  if (isProxmoxVm) {
    const requestedWebPort = parseInt(http_port, 10);
    if (!Number.isNaN(requestedWebPort) && requestedWebPort >= 1024 && requestedWebPort <= 65535 && requestedWebPort !== 80) {
      effectiveHttpPort = requestedWebPort;
    } else if (netType === 'nat') {
      effectiveHttpPort = await resolveAvailableProxmoxWebPort(8006);
    } else {
      effectiveHttpPort = 8006;
    }
  }
  
  // Insert VM first to get vm_id
  db.run(
    `INSERT INTO vms (
      vm_name, os_type, template_type, hostname, username, password, 
      memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model, custom_cpu_name,
      machine_type, board_name, product_name, custom_smbios_manufacturer,
      disk_size, img_file, seed_file, disk_file,
      status, uptime, node_name,
      smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
      extra_args, enable_acpi, enable_kvm,
      network_type, ipv4_address, ipv4_gateway, ipv4_netmask,
      dns_servers, dns_primary, dns_secondary, ssh_port, ssh_port_static, http_port,
      ipv6_address, ipv6_gateway, mac_address, bridge_device, vlan_id, owner_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      vm_name, templateName, os_template || (isCloudInit ? 'cloud-init' : 'iso-installer'), hostname, 
      username, password ? encryptSecret(String(password)) : '', memory, cpuCount, sockets, cores, threads, cpuModelToUse, custom_cpu_name || null,
      machine_type || 'pc', board_name || 'Main-Board', product_name || 'Virtual Machine', custom_smbios_manufacturer || 'QEMU',
      diskSizeVal, '', '', '',
      'stopped', 0, 'localhost',
      smbios_manufacturer || 'QEMU', smbios_product || 'KVM Virtual Machine',
      smbios_version || '1.0', smbios_serial || `vm-${Date.now()}`,
      extra_args || '', enable_acpi !== false ? 1 : 0, enable_kvm !== false ? 1 : 0,
      netType, ipv4_address || null, ipv4_gateway || null, ipv4_netmask || '255.255.255.0',
      dns_servers || '8.8.8.8,8.8.4.4', dns_primary || '8.8.8.8', dns_secondary || '8.8.4.4', null, sshPortVal, effectiveHttpPort,
      ipv6_address || null, ipv6_gateway || null,
      macAddr, bridge_device || 'vmbr0', vlan_id || null, vmOwner
    ],
    async function(err) {
      if (err) return res.status(500).json({ error: err.message });
      
      const vm_id = this.lastID;
      // Cloud-init images go to /cloudvm, ISO images go to /iso
      const img_file = isCloudInit 
        ? path.join(CLOUDVM_DIR, `${os_template || 'custom'}-${vm_id}.qcow2`)
        : path.join(ISO_DIR, `${os_template || 'custom'}-${vm_id}.qcow2`);
      const disk_file = path.join(VM_DIR, `vm-${vm_id}-disk.qcow2`);
      const seed_file = path.join(VM_DIR, `vm-${vm_id}-seed.iso`);

      try {
        // Update with file paths
        db.run(
          `UPDATE vms SET img_file = ?, seed_file = ?, disk_file = ? WHERE vm_id = ?`,
          [img_file, seed_file, disk_file, vm_id],
          async (err) => {
            if (err) {
              cleanupFailedVmCreation(vm_id);
              return res.status(500).json({ error: err.message });
            }

            try {
              // If using cloud-init template, check cache first
              if (os_template && isCloudInit) {
                // Check if it's a built-in or custom template
                let templateSourcePath = null;

                if (OS_TEMPLATES[os_template]) {
                  // Built-in template - use cache in /vms/templates (or shared base cloud image cache)
                  const cachedTemplateName = `${os_template}-template.qcow2`;
                  const cachedTemplatePath = path.join(TEMPLATES_DIR, cachedTemplateName);
                  const baseCacheKey = OS_TEMPLATES[os_template].base_cache_key;
                  const baseCachedPath = baseCacheKey
                    ? path.join(TEMPLATES_DIR, `${baseCacheKey}-template.qcow2`)
                    : null;

                  if (fs.existsSync(cachedTemplatePath)) {
                    console.log(`[VM-${vm_id}] Using cached built-in template from: ${cachedTemplatePath}`);
                    templateSourcePath = cachedTemplatePath;
                  } else if (baseCachedPath && fs.existsSync(baseCachedPath)) {
                    console.log(`[VM-${vm_id}] Reusing shared base cloud image cache: ${baseCachedPath}`);
                    templateSourcePath = baseCachedPath;
                  } else {
                    console.log(`[VM-${vm_id}] Cached template not found at ${cachedTemplatePath}`);
                    console.log(`[VM-${vm_id}] Downloading built-in template: ${templateName} to cache...`);
                    
                    // Download to cache first
                    try {
                      await downloadTemplate(os_template, cachedTemplatePath);
                      console.log(`[VM-${vm_id}] ✓ Built-in template cached to: ${cachedTemplatePath}`);
                      templateSourcePath = cachedTemplatePath;
                    } catch (dlErr) {
                      console.error(`[VM-${vm_id}] Template download failed:`, dlErr.message);
                      throw new Error(`Failed to download built-in template: ${dlErr.message}`);
                    }
                  }
                } else {
                  // Custom template - check database for local path
                  const customTemplate = await new Promise((resolve, reject) => {
                    db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [os_template], (err, result) => {
                      if (err) reject(err);
                      else resolve(result);
                    });
                  });

                  if (!customTemplate) {
                    throw new Error(`Custom template "${os_template}" not found in database`);
                  }

                  if (customTemplate.local_path && fs.existsSync(customTemplate.local_path)) {
                    console.log(`[VM-${vm_id}] Using cached custom template from: ${customTemplate.local_path}`);
                    templateSourcePath = customTemplate.local_path;
                  } else if (customTemplate.download_url) {
                    console.log(`[VM-${vm_id}] Custom template not cached, downloading from ${customTemplate.download_url}...`);
                    
                    // Generate local path if not set
                    let localPath = customTemplate.local_path;
                    if (!localPath) {
                      const urlParts = customTemplate.download_url.split('/');
                      const fileName = urlParts[urlParts.length - 1] || `${os_template}-template.qcow2`;
                      localPath = path.join(TEMPLATES_DIR, fileName);
                    }

                    try {
                      // Create templates directory if needed
                      if (!fs.existsSync(TEMPLATES_DIR)) {
                        fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
                      }

                      await downloadTemplateFromURL(customTemplate.download_url, localPath);
                      console.log(`[VM-${vm_id}] ✓ Custom template downloaded to: ${localPath}`);
                      
                      // Update database with local path
                      await new Promise((resolve, reject) => {
                        db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`,
                          [localPath, os_template],
                          (err) => {
                            if (err) {
                              console.error('Failed to update template path in DB:', err);
                              reject(err);
                            } else {
                              resolve();
                            }
                          }
                        );
                      });

                      templateSourcePath = localPath;
                    } catch (dlErr) {
                      console.error(`[VM-${vm_id}] Custom template download failed:`, dlErr.message);
                      throw new Error(`Failed to download custom template: ${dlErr.message}`);
                    }
                  } else {
                    throw new Error(`Custom template "${os_template}" has no local path or download URL`);
                  }
                }

                // Copy template to VM's image file
                if (templateSourcePath) {
                  try {
                    const copyCmd = process.platform === 'win32' 
                      ? `copy "${templateSourcePath}" "${img_file}"`
                      : `cp "${templateSourcePath}" "${img_file}"`;
                    
                    console.log(`[VM-${vm_id}] Copying template to: ${img_file}`);
                    await execPromise(copyCmd, { 
                      shell: process.platform === 'win32' ? 'cmd' : '/bin/bash',
                      stdio: 'pipe'
                    });
                    console.log(`[VM-${vm_id}] ✓ Copied template to ${img_file}`);
                  } catch (copyErr) {
                    console.error(`[VM-${vm_id}] Failed to copy template:`, copyErr.message);
                    throw new Error(`Failed to copy template: ${copyErr.message}`);
                  }
                }
              }

              // Create cloud-init seed if cloud-init type
              if (isCloudInit) {
                const vmData = {
                  vm_id,
                  vm_name,
                  os_template,
                  template_type: os_template,
                  os_type: templateName,
                  hostname,
                  username,
                  password,
                  http_port: effectiveHttpPort,
                  network_type: netType,
                  ipv4_address: ipv4_address || null,
                  ipv4_gateway: ipv4_gateway || null,
                  ipv4_netmask: ipv4_netmask || '255.255.255.0',
                  dns_servers: dns_servers || `${dns_primary || '8.8.8.8'},${dns_secondary || '8.8.4.4'}`,
                  dns_primary: dns_primary || '8.8.8.8',
                  dns_secondary: dns_secondary || '8.8.4.4',
                  ipv6_address: ipv6_address || null,
                  ipv6_gateway: ipv6_gateway || null,
                  bridge_device: bridge_device || 'vmbr0'
                };
                await createCloudInitSeed(vm_id, vmData);
                
                // Create disk from template with resize to specified size
                console.log(`[VM-${vm_id}] Creating and resizing disk to ${diskSizeVal}...`);
                try {
                  // Copy template to disk file and resize in one step
                  const resizeDiskCmd = `qemu-img convert -O qcow2 "${img_file}" "${disk_file}" && qemu-img resize "${disk_file}" ${diskSizeVal}`;
                  await execPromise(resizeDiskCmd, { 
                    shell: isWindows ? 'cmd' : '/bin/bash',
                    stdio: 'pipe'
                  });
                  
                  console.log(`[VM-${vm_id}] ✓ Disk created and resized to: ${diskSizeVal}`);
                } catch (diskError) {
                  logError('DISK', vm_id, 'creation', diskError);
                  throw new Error(`Disk creation failed: ${diskError.message}`);
                }
              } else {
                // ISO mode: Create a new disk from scratch with specified size
                console.log(`[VM-${vm_id}] Creating disk: ${disk_file} (size: ${diskSizeVal})`);
                try {
                  const createDiskCmd = `qemu-img create -f qcow2 "${disk_file}" ${diskSizeVal}`;
                  
                  await execPromise(createDiskCmd, { 
                    shell: isWindows ? 'cmd' : '/bin/bash',
                    stdio: 'pipe'
                  });
                  console.log(`[VM-${vm_id}] ✓ Disk created: ${diskSizeVal}`);
                } catch (diskError) {
                  logError('DISK', vm_id, 'creation', diskError);
                  throw new Error(`Disk creation failed: ${diskError.message}`);
                }
              }

              logVMAction(vm_id, 'create', 'pending', `VM ${vm_name} (ID:${vm_id}) created from ${templateName}`);
              if (hkvmV3Context) {
                hkvmV3Context.kvmAdapter.syncRegistryRow(vm_id).catch(() => undefined);
              }
              res.json({ 
                success: true, 
                vm_id: vm_id, 
                template: isCloudInit ? 'cloud-init' : 'iso-installer',
                config: {
                  cpus: cpuCount,
                  sockets: sockets,
                  cores: cores,
                  threads: threads,
                  cpu_model: cpuModelToUse,
                  memory: memory,
                  disk_size: diskSizeVal,
                  network_type: netType,
                  mac_address: macAddr,
                  http_port: effectiveHttpPort,
                  is_proxmox: isProxmoxVm,
                  ipv4: ipv4_address,
                  gateway: ipv4_gateway
                }
              });
            } catch (downloadError) {
              logError('TEMPLATE', vm_id, 'download', downloadError);
              // Clean up partial files
              if (fs.existsSync(img_file)) {
                try { fs.unlinkSync(img_file); } catch (e) {}
              }
              cleanupFailedVmCreation(vm_id);
              return res.status(500).json({ error: `Failed to download template: ${downloadError.message}` });
            }
          }
        );
      } catch (error) {
        logError('VM', vm_id, 'creation', error);
        cleanupFailedVmCreation(vm_id);
        res.status(500).json({ error: error.message });
      }
    }
  );
});

// VM START (Using VM ID)
app.post('/api/vms/:vm_id/start', checkAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [req.params.vm_id];
    
    // Normal users can only start their own VMs
    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }
    
    db.get(query, params, async (err, vm) => {
      if (err || !vm) {
        console.error(`[API Error] /api/vms/${req.params.vm_id}/start: VM not found or access denied`);
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      if (vm.status === 'running') {
        console.log(`[API] VM ${vm.vm_id} already running`);
        return res.json({ success: true, message: `VM ${vm.vm_name} is already running` });
      }

      try {
        console.log(`[API] Starting VM ${vm.vm_id} (${vm.vm_name}) by user ${userId}`);
        const result = await startQemuVM(vm);
        if (result.success) {
          vmProcesses.set(vm.vm_id, result.pid);
          db.run(`UPDATE vms SET status = 'running', pid = ?, uptime = 0 WHERE vm_id = ?`, [result.pid, vm.vm_id], () => {
            if (hkvmV3Context) hkvmV3Context.kvmAdapter.syncRegistryRow(vm.vm_id).catch(() => undefined);
          });
          logVMAction(vm.vm_id, 'start', 'running', `VM started successfully`);
          console.log(`[API Success] VM ${vm.vm_id} started successfully`);
          res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) started`, vm_id: vm.vm_id });
        } else {
          console.error(`[API Error] Failed to start VM ${vm.vm_id}`);
          res.status(500).json({ error: 'Failed to start VM' });
        }
      } catch (error) {
        console.error(`[API Error] Exception starting VM ${vm.vm_id}:`, error);
        logVMAction(vm.vm_id, 'start', 'failed', error.message);
        res.status(500).json({ error: error.message });
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VM STOP (Using VM ID)
app.post('/api/vms/:vm_id/stop', checkAuth, (req, res) => {
  const userId = req.session.userId;
  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  
  // Normal users can only stop their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }
  
  db.get(query, params, (err, vm) => {
    if (err || !vm) {
      console.error(`[API Error] /api/vms/${req.params.vm_id}/stop: VM not found or access denied`);
      return res.status(404).json({ error: 'VM not found or access denied' });
    }

    if (vm.status === 'stopped') {
      console.log(`[API] VM ${vm.vm_id} already stopped`);
      return res.json({ success: true, message: 'VM already stopped' });
    }

    try {
      console.log(`[API] Stopping VM ${vm.vm_id} (${vm.vm_name}) by user ${userId}`);
      const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
      if (fs.existsSync(pidFile)) {
        const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
        try {
          // On Windows, use taskkill; on Unix, use process group kill
          if (isWindows) {
            exec(`taskkill /F /PID ${pid}`, { shell: 'cmd' });
          } else {
            // Kill entire process group (- prefix means pgid)
            process.kill(-pid, 'SIGTERM');
            setTimeout(() => {
              try {
                process.kill(-pid, 'SIGKILL');
              } catch (e) {}
            }, 3000);
          }
        } catch (e) {
          // Process may already be dead
        }
      }

      vmProcesses.delete(vm.vm_id);
      qemuStdins.delete(vm.vm_id);
      db.run(`UPDATE vms SET status = 'stopped', pid = NULL WHERE vm_id = ?`, [vm.vm_id], () => {
        if (hkvmV3Context) hkvmV3Context.kvmAdapter.syncRegistryRow(vm.vm_id).catch(() => undefined);
      });
      logVMAction(vm.vm_id, 'stop', 'stopped', `VM stopped`);
      console.log(`[API Success] VM ${vm.vm_id} stopped successfully`);
      res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) stopped` });
    } catch (error) {
      console.error(`[API Error] Exception stopping VM ${vm.vm_id}:`, error);
      res.status(500).json({ error: error.message });
    }
  });
});

// VM RESTART (Using VM ID)
app.post('/api/vms/:vm_id/restart', checkAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [req.params.vm_id];
    
    // Normal users can only restart their own VMs
    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }
    
    db.get(query, params, async (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });

      try {
        const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
        if (fs.existsSync(pidFile)) {
          const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
          try {
            process.kill(pid, 'SIGTERM');
          } catch (e) {}
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));

        const result = await startQemuVM(vm);
        if (result.success) {
          vmProcesses.set(vm.vm_id, result.pid);
          db.run(`UPDATE vms SET status = 'running' WHERE vm_id = ?`, [vm.vm_id]);
          logVMAction(vm.vm_id, 'restart', 'running', `VM restarted successfully`);
          res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) restarted` });
        } else {
          res.status(500).json({ error: 'Failed to restart VM' });
        }
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VM REINSTALL (Using VM ID)

function dbRunAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function dbGetAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function cleanupFailedVmCreation(vmId) {
  db.serialize(() => {
    db.run(`DELETE FROM vm_logs WHERE vm_id = ?`, [vmId], () => {});
    db.run(`DELETE FROM vm_snapshots WHERE vm_id = ?`, [vmId], () => {});
    db.run(`DELETE FROM instances WHERE engine = 'kvm' AND ref_id = ?`, [vmId], () => {});
    db.run(`DELETE FROM vms WHERE vm_id = ?`, [vmId], () => {});
  });
}

function safeUnlinkVmArtifact(filePath, vmId) {
  if (!filePath || typeof filePath !== 'string') return;
  const resolved = path.resolve(filePath);
  const sharedTemplatesDir = path.resolve(TEMPLATES_DIR) + path.sep;
  const sharedIsoDir = path.resolve(ISO_DIR) + path.sep;
  if (resolved.startsWith(sharedTemplatesDir)) return;
  if (resolved.startsWith(sharedIsoDir) && resolved.toLowerCase().endsWith('.iso')) return;
  try {
    if (fs.existsSync(resolved)) {
      fs.unlinkSync(resolved);
    }
  } catch (e) {
    console.warn(`[VM-${vmId}] Could not remove artifact ${resolved}: ${e.message}`);
  }
}

async function performFullVmDelete(vm, actorUserId = null) {
  const vmId = Number(vm.vm_id);
  const candidatePids = new Set();
  if (vmProcesses.has(vmId)) candidatePids.add(Number(vmProcesses.get(vmId)));
  if (vm.pid) candidatePids.add(Number(vm.pid));

  const pidFile = path.join(VM_DIR, `vm-${vmId}.pid`);
  if (fs.existsSync(pidFile)) {
    try {
      const parsedPid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
      if (parsedPid > 1) candidatePids.add(parsedPid);
    } catch (e) {}
  }

  for (const pid of candidatePids) {
    if (pid && pid > 1) {
      try {
        process.kill(pid, 'SIGKILL');
      } catch (e) {}
    }
  }

  vmProcesses.delete(vmId);
  qemuStdins.delete(vmId);

  safeUnlinkVmArtifact(vm.img_file, vmId);
  safeUnlinkVmArtifact(vm.seed_file, vmId);
  safeUnlinkVmArtifact(vm.disk_file, vmId);
  safeUnlinkVmArtifact(pidFile, vmId);
  safeUnlinkVmArtifact(path.join(VM_DIR, `vm-${vmId}.log`), vmId);

  // Delete dependent rows BEFORE deleting `vms(vm_id)` so SQLite foreign_keys enforcement
  // never rejects `DELETE FROM vms WHERE vm_id = ?` with SQLITE_CONSTRAINT!
  await dbRunAsync(`DELETE FROM vm_logs WHERE vm_id = ?`, [vmId]);
  await dbRunAsync(`DELETE FROM vm_snapshots WHERE vm_id = ?`, [vmId]);
  await dbRunAsync(`DELETE FROM instances WHERE engine = 'kvm' AND ref_id = ?`, [vmId]).catch(
    () => undefined
  );
  await dbRunAsync(
    `UPDATE ip_allocations
     SET instance_type = NULL, instance_ref_id = NULL, assigned_user_id = NULL
     WHERE instance_type = 'kvm' AND instance_ref_id = ?`,
    [vmId]
  ).catch(() => undefined);
  await dbRunAsync(
    `DELETE FROM port_forwards WHERE instance_type = 'kvm' AND instance_ref_id = ?`,
    [vmId]
  ).catch(() => undefined);
  await dbRunAsync(
    `DELETE FROM metrics_history WHERE target_type = 'kvm' AND target_id = ?`,
    [vmId]
  ).catch(() => undefined);
  await dbRunAsync(`DELETE FROM vms WHERE vm_id = ?`, [vmId]);

  const remaining = await dbGetAsync(`SELECT vm_id FROM vms WHERE vm_id = ?`, [vmId]);
  if (remaining) {
    throw new Error(`Database failed to remove VM #${vmId}`);
  }

  if (hkvmV3Context) {
    await hkvmV3Context.db
      .logActivity({
        userId: actorUserId || null,
        action: 'vm_delete',
        resourceType: 'kvm',
        resourceId: String(vmId),
        details: { vm_name: vm.vm_name },
      })
      .catch(() => undefined);
  }
}

// VM DELETE (Using VM ID)
app.delete('/api/vms/:vm_id', checkAuth, (req, res) => {
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.vm_id], async (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found' });
    if (req.session.role !== 'admin' && vm.owner_id !== req.session.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    try {
      await performFullVmDelete(vm, req.session.userId);
      res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) deleted` });
    } catch (error) {
      console.error(`[API Error] DELETE /api/vms/${vm.vm_id}:`, error);
      res.status(500).json({ error: error.message });
    }
  });
});

// VM LOGS (Using VM ID)
app.get('/api/vms/:vm_id/logs', checkAuth, (req, res) => {
  db.get(`SELECT owner_id FROM vms WHERE vm_id = ?`, [req.params.vm_id], (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found' });
    if (req.session.role !== 'admin' && vm.owner_id !== req.session.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }
    db.all(
      `SELECT * FROM vm_logs WHERE vm_id = ? ORDER BY timestamp DESC LIMIT 50`,
      [req.params.vm_id],
      (err2, logs) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json(logs || []);
      }
    );
  });
});

// VM SNAPSHOTS (Using VM ID)
app.get('/api/vms/:vm_id/snapshots', checkAuth, (req, res) => {
  const userId = req.session.userId;
  let query = `SELECT * FROM vm_snapshots WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  
  // First check ownership if not admin
  if (req.session.role !== 'admin') {
    // Check if user owns this VM
    db.get(`SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`, [req.params.vm_id, userId], (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
      
      db.all(query, params, (err, snapshots) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(snapshots || []);
      });
    });
  } else {
    db.all(query, params, (err, snapshots) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(snapshots || []);
    });
  }
});

// ============= ISO ATTACH/DETACH ENDPOINTS =============

// Attach ISO to VM (for ISO templates or manual ISO installation)
app.post('/api/vms/:vm_id/iso/attach', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const { iso_file } = req.body;
    const userId = req.session.userId;

    if (!iso_file) {
      return res.status(400).json({ error: 'ISO file is required' });
    }

    // Get VM
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Verify ISO file exists
      const isoPath = path.join(ISO_DIR, iso_file);
      if (!fs.existsSync(isoPath)) {
        return res.status(400).json({ error: 'ISO file not found' });
      }

      // Update VM with attached ISO
      db.run(
        `UPDATE vms SET iso_attached = ?, boot_from_iso = 1 WHERE vm_id = ?`,
        [iso_file, vm_id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          logVMAction(vm_id, 'iso_attach', 'completed', `ISO file attached: ${iso_file}`);
          res.json({ success: true, message: `ISO file "${iso_file}" attached successfully` });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Detach ISO from VM
app.post('/api/vms/:vm_id/iso/detach', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const userId = req.session.userId;

    // Get VM
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Update VM to remove attached ISO and boot from disk
      db.run(
        `UPDATE vms SET iso_attached = NULL, boot_from_iso = 0 WHERE vm_id = ?`,
        [vm_id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          logVMAction(vm_id, 'iso_detach', 'completed', 'ISO file detached, will boot from disk');
          res.json({ success: true, message: 'ISO file detached successfully' });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get VM ISO status
app.get('/api/vms/:vm_id/iso/status', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const userId = req.session.userId;

    let query = `SELECT vm_id, iso_attached, boot_from_iso, status FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      res.json({
        vm_id: vm.vm_id,
        iso_attached: vm.iso_attached || null,
        boot_from_iso: vm.boot_from_iso ? true : false,
        vm_status: vm.status
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/vms/:vm_id/snapshots', checkAuth, async (req, res) => {
  const userId = req.session.userId;
  const { snapshot_name, description } = req.body;
  
  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  
  // Normal users can only create snapshots for their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }
  
  db.get(query, params, async (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    if (!hkvmV3Context) return res.status(503).json({ error: 'TGVPANEL runtime initializing' });
    try {
      const snap = await hkvmV3Context.kvmAdapter.createQcow2Snapshot(
        Number(req.params.vm_id),
        String(snapshot_name || ''),
        String(description || '')
      );
      logVMAction(req.params.vm_id, 'snapshot', 'completed', `Snapshot ${snap.name} created`);
      res.json({ success: true, snapshot_id: snap.id });
    } catch (snapErr) {
      res.status(400).json({ error: snapErr.message });
    }
  });
});

// ADMIN DASHBOARD
app.get('/api/admin/dashboard', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT COUNT(*) as total FROM users`, (err, userCount) => {
    db.all(`SELECT COUNT(*) as total FROM vms`, (err, vmCount) => {
      db.all(`SELECT COUNT(*) as total FROM vms WHERE status = 'running'`, (err, runningCount) => {
        res.json({
          totalUsers: userCount ? userCount[0].total : 0,
          totalVMs: vmCount ? vmCount[0].total : 0,
          runningVMs: runningCount ? runningCount[0].total : 0
        });
      });
    });
  });
});

// HELPER FUNCTIONS

function logVMAction(vm_id, action, status, message) {
  db.run(
    `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, ?, ?, ?)`,
    [vm_id, action, status, message],
    (err) => {
      if (err) {
        console.warn(`[VM-${vm_id}] logVMAction(${action}) skipped: ${err.message}`);
      }
    }
  );
}

// Download OS template image
// Download template from URL with redirect support
async function downloadTemplateFromURL(url, targetPath) {
  return new Promise((resolve, reject) => {
    console.log(`[TEMPLATE] Downloading from URL: ${url}`);

    // Ensure parent directory exists
    const targetDir = path.dirname(targetPath);
    if (!fs.existsSync(targetDir)) {
      try {
        fs.mkdirSync(targetDir, { recursive: true });
        console.log(`[TEMPLATE] Created directory: ${targetDir}`);
      } catch (err) {
        console.error(`[TEMPLATE] Failed to create directory ${targetDir}:`, err.message);
        return reject(new Error(`Cannot create directory: ${err.message}`));
      }
    }

    const file = fs.createWriteStream(targetPath);
    const https = url.startsWith('https') ? require('https') : require('http');
    
    const makeRequest = (currentUrl, redirectCount = 0) => {
      // Limit redirects to prevent infinite loops
      if (redirectCount > 5) {
        fs.unlink(targetPath, () => {});
        return reject(new Error('Too many redirects'));
      }

      https.get(currentUrl, (response) => {
        // Handle redirects (301, 302, 303, 307, 308)
        if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
          const redirectUrl = response.headers.location;
          if (!redirectUrl) {
            fs.unlink(targetPath, () => {});
            return reject(new Error(`Redirect without location header`));
          }
          console.log(`[TEMPLATE] Redirect (${response.statusCode}) to: ${redirectUrl}`);
          return makeRequest(redirectUrl, redirectCount + 1);
        }

        if (response.statusCode !== 200) {
          fs.unlink(targetPath, () => {});
          return reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
        }

        const len = parseInt(response.headers['content-length'], 10);
        let downloaded = 0;

        response.on('data', (chunk) => {
          downloaded += chunk.length;
          if (len) {
            const percent = ((downloaded / len) * 100).toFixed(2);
            console.log(`[TEMPLATE] Download progress: ${percent}%`);
          }
        });

        response.pipe(file);
        file.on('finish', () => {
          file.close();
          console.log(`[TEMPLATE] Downloaded successfully`);
          resolve(true);
        });
        file.on('error', (err) => {
          fs.unlink(targetPath, () => {});
          reject(err);
        });
      }).on('error', (err) => {
        fs.unlink(targetPath, () => {});
        reject(err);
      });
    };

    makeRequest(url);
  });
}

// Download OS template from built-in templates OR directly from URL
async function downloadTemplate(sourceOrKey, targetPath) {
  return new Promise(async (resolve, reject) => {
    try {
      let url;
      let templateName;

      // Check if it's a template key or a direct URL
      if (OS_TEMPLATES[sourceOrKey]) {
        const template = OS_TEMPLATES[sourceOrKey];
        url = template.url;
        templateName = template.name;
      } else if (sourceOrKey.startsWith('http')) {
        // It's a direct URL
        url = sourceOrKey;
        templateName = 'custom template';
      } else {
        return reject(new Error('Invalid template key or URL'));
      }

      console.log(`[TEMPLATE] Downloading ${templateName} from ${url}...`);

      await downloadTemplateFromURL(url, targetPath);
      console.log(`[TEMPLATE] Download complete for ${templateName}`);
      resolve(true);
    } catch (err) {
      reject(err);
    }
  });
}

// Generate Cloud-Init config for NAT (User Mode)
// Configures DHCP networking automatically
function generateNATCloudInitConfig(vm) {
  const username = vm.username || 'root';
  const password = vm.password || 'password';
  const hostname = vm.hostname || 'tgvpanel-instance';

  // Build users section - support root and custom users
  let usersSection = `users:`;
  let chpasswdList = ``;
  
  if (username.toLowerCase() === 'root') {
    // If root user, configure root directly
    usersSection += `
  - name: root
    lock_passwd: false
    shell: /bin/bash
    homedir: /root`;
    chpasswdList = `    - root:${password}`;
  } else {
    // If custom user, create the user with sudo privileges
    usersSection += `
  - name: ${username}
    lock_passwd: false
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    homedir: /home/${username}
    createhome: true
    
  - name: root
    lock_passwd: false
    shell: /bin/bash`;
    chpasswdList = `    - ${username}:${password}
    - root:password`;
  }

  const config = `#cloud-config

# ================================================
# SYSTEM CONFIG
# ================================================
hostname: ${hostname}
manage_etc_hosts: true
preserve_hostname: false

# ================================================
# USERS & AUTH
# ================================================
${usersSection}

disable_root: false
ssh_pwauth: true

chpasswd:
  expire: false
  list:
${chpasswdList}

# ================================================
# SSH CONFIG
# ================================================
write_files:
  - path: /etc/ssh/sshd_config.d/50-cloud-init.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin yes
      PasswordAuthentication yes

# ================================================
# NETWORKING (DHCP - Automatic)
# ================================================
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      dhcp6: false

# ================================================
# FINAL MESSAGE
# ================================================
final_message: |
  ✓ VM CONFIGURED - NAT (User Mode)
  Hostname: ${hostname}
  Network: DHCP (Automatic)
  SSH: Default ports with forwarding
`;

  return config;
}

// Generate Cloud-Init config for Static Public IPv4 ONLY
// Configures static IPv4 with netplan v2 - NO DHCP
function generateStaticPublicIPv4CloudInitConfig(vm) {
  const username = vm.username || 'root';
  const password = vm.password || 'password';
  const hostname = vm.hostname || 'tgvpanel-instance';
  const ipv4_address = vm.ipv4_address || '10.0.0.100';
  const gateway = vm.gateway || vm.ipv4_gateway || '10.0.0.1';
  const netmask = vm.netmask || vm.ipv4_netmask || 24;
  const dns = (vm.dns_primary || '8.8.8.8').trim();
  const dns_secondary = (vm.dns_secondary || '8.8.4.4').trim();

  // Convert netmask to CIDR
  let cidr = netmask;
  if (typeof netmask === 'string' && netmask.includes('.')) {
    const parts = netmask.split('.');
    cidr = parts.reduce((sum, octet) => {
      return sum + parseInt(octet).toString(2).replace(/0/g, '').length;
    }, 0);
  }

  // Build users section - support root and custom users
  let usersSection = `users:`;
  let chpasswdList = ``;
  
  if (username.toLowerCase() === 'root') {
    // If root user, configure root directly
    usersSection += `
  - name: root
    lock_passwd: false
    shell: /bin/bash
    homedir: /root`;
    chpasswdList = `    - root:${password}`;
  } else {
    // If custom user, create the user with sudo privileges
    usersSection += `
  - name: ${username}
    lock_passwd: false
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    homedir: /home/${username}
    createhome: true
    
  - name: root
    lock_passwd: false
    shell: /bin/bash`;
    chpasswdList = `    - ${username}:${password}
    - root:password`;
  }

  const config = `#cloud-config

# ================================================
# SYSTEM CONFIG
# ================================================
hostname: ${hostname}
manage_etc_hosts: true
preserve_hostname: false

# ================================================
# USERS & AUTH
# ================================================
${usersSection}

disable_root: false
ssh_pwauth: true

chpasswd:
  expire: false
  list:
${chpasswdList}

# ================================================
# SSH CONFIG
# ================================================
write_files:
  - path: /etc/ssh/sshd_config.d/50-cloud-init.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin yes
      PasswordAuthentication yes

  - path: /etc/netplan/99-static.yaml
    owner: root:root
    permissions: '0600'
    content: |
      network:
        version: 2
        renderer: networkd
        ethernets:
          ens3:
            dhcp4: false
            dhcp6: false
            addresses:
              - ${ipv4_address}/${cidr}
            routes:
              - to: 0.0.0.0/0
                via: ${gateway}
            nameservers:
              addresses: [${dns}, ${dns_secondary}]

  - path: /usr/local/bin/apply-network.sh
    owner: root:root
    permissions: '0755'
    content: |
      #!/bin/bash
      
      {
      echo "========== VERIFYING NETWORK CONFIG =========="
      echo "Time: $(date)"
      
      # Check if netplan config exists and is correct
      echo ""
      echo "Step 1: Checking netplan config..."
      if [ ! -f /etc/netplan/99-static.yaml ]; then
        echo "✗ Netplan config not found!"
        exit 1
      fi
      
      cat /etc/netplan/99-static.yaml
      
      # Apply (skip validate - netplan v2.12+ removed validate command)
      echo ""
      echo "Step 2: Applying netplan..."
      netplan apply || {
        echo "✗ Netplan apply failed!"
        systemctl status systemd-networkd || true
        exit 1
      }
      echo "✓ Netplan applied"
      
      sleep 2
      
      # Show final state
      echo ""
      echo "Step 3: Interface state AFTER netplan apply:"
      ip addr show
      ip route show
      
      echo ""
      echo "========== NETWORK CONFIG VERIFIED =========="
      } 2>&1 | tee /var/log/apply-network.log

# ================================================
# DISABLE WAIT-ONLINE + APPLY CONFIG
# ================================================
runcmd:
  - systemctl mask systemd-networkd-wait-online.service
  - systemctl mask systemd-network-online.target
  - bash /usr/local/bin/apply-network.sh

# ================================================
# FINAL MESSAGE
# ================================================
final_message: |
  ✓ VM CONFIGURED - Static IPv4
  IP: ${ipv4_address}/${cidr}
  Gateway: ${gateway}
  Hostname: ${hostname}
`;

  return config;
}

// Generate random MAC address
function generateMACAddress() {
  return 'fa:16:3e:' + [0, 1, 2].map(() => {
    return Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  }).join(':');
}

/**
 * Validate static IPv4 configuration
 * Returns {valid: boolean, error: string|null}
 */
function validateStaticIPv4Config(vm) {
  // Check required fields
  if (!vm.network_type || vm.network_type !== 'static_public') {
    return { valid: false, error: 'Network type must be static_public' };
  }
  
  if (!vm.ipv4_address) {
    return { valid: false, error: 'IPv4 address is required' };
  }
  
  // Validate IPv4 address format (basic check)
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(vm.ipv4_address)) {
    return { valid: false, error: `Invalid IPv4 address format: ${vm.ipv4_address}` };
  }
  
  // Validate each octet is 0-255
  const octets = vm.ipv4_address.split('.');
  for (const octet of octets) {
    const num = parseInt(octet);
    if (isNaN(num) || num < 0 || num > 255) {
      return { valid: false, error: `IPv4 octet out of range: ${octet}` };
    }
  }
  
  // Validate gateway
  const gateway = vm.gateway || vm.ipv4_gateway;
  if (gateway) {
    if (!ipv4Regex.test(gateway)) {
      return { valid: false, error: `Invalid gateway IPv4 format: ${gateway}` };
    }
    const gwOctets = gateway.split('.');
    for (const octet of gwOctets) {
      const num = parseInt(octet);
      if (isNaN(num) || num < 0 || num > 255) {
        return { valid: false, error: `Gateway octet out of range: ${octet}` };
      }
    }
  } else {
    return { valid: false, error: 'Gateway is required for static IPv4' };
  }
  
  // Validate netmask/CIDR
  let cidr = vm.netmask || vm.ipv4_netmask || 24;
  let cidrNum = parseInt(cidr);
  
  // If it contains dots, it's a dotted-decimal mask
  if (cidr.toString().includes('.')) {
    const parts = cidr.split('.');
    if (parts.length !== 4) {
      return { valid: false, error: 'Invalid netmask format' };
    }
    // Convert to CIDR to validate
    cidrNum = parts.reduce((sum, octet) => {
      const num = parseInt(octet);
      if (isNaN(num) || num < 0 || num > 255) {
        return -1;
      }
      return sum + num.toString(2).replace(/0/g, '').length;
    }, 0);
  }
  
  if (isNaN(cidrNum) || cidrNum < 1 || cidrNum > 32) {
    return { valid: false, error: `Invalid CIDR range: ${cidr} (must be 1-32)` };
  }
  
  // Validate DNS servers
  const dnsServers = (vm.dns_servers || vm.dns_primary || '8.8.8.8').split(',');
  for (const dns of dnsServers) {
    const cleanDns = dns.trim();
    if (cleanDns && !ipv4Regex.test(cleanDns)) {
      return { valid: false, error: `Invalid DNS server IP format: ${cleanDns}` };
    }
  }
  
  // Validate bridge device (if provided)
  if (vm.bridge_device && typeof vm.bridge_device === 'string') {
    if (!/^[a-z0-9]+$/.test(vm.bridge_device)) {
      return { valid: false, error: `Invalid bridge device name: ${vm.bridge_device}` };
    }
  }
  
  return { valid: true, error: null };
}

function generateProxmoxCloudInitConfig(vm) {
  const tplKey = String(vm.os_template || vm.template_type || 'proxmox_ve_8').trim();
  const builtIn = OS_TEMPLATES[tplKey] || null;
  const isPve9 = Boolean(
    (builtIn && builtIn.proxmox_codename === 'trixie') ||
    tplKey.toLowerCase().includes('9') ||
    String(vm.os_type || '').toLowerCase().includes('9')
  );
  const codename = isPve9 ? 'trixie' : 'bookworm';
  const defaultGpgUrl = isPve9
    ? 'https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg'
    : 'https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg';
  const fallbackGpgUrl = isPve9
    ? 'https://enterprise.proxmox.com/debian/proxmox-release-trixie.gpg'
    : 'https://enterprise.proxmox.com/debian/proxmox-archive-keyring-bookworm.gpg';
  const gpgUrl = (builtIn && builtIn.proxmox_gpg_url) ? builtIn.proxmox_gpg_url : defaultGpgUrl;
  const pveReleaseLabel = isPve9 ? 'Proxmox VE 9 (Debian 13 Trixie)' : 'Proxmox VE 8 (Debian 12 Bookworm)';

  const rawHost = String(vm.hostname || 'pve').trim().toLowerCase();
  const safeHost = rawHost.replace(/[^a-z0-9.-]/g, '-').replace(/^-+|-+$/g, '') || 'pve';
  const shortHost = safeHost.split('.')[0] || 'pve';
  const fqdn = safeHost.includes('.') ? safeHost : `${shortHost}.proxmox.local`;

  const rawUser = String(vm.username || 'root').trim();
  const safeUser = /^[a-z_][a-z0-9_-]{0,31}$/i.test(rawUser) ? rawUser : 'root';
  const cleanPass = String(vm.password || 'proxmox').replace(/[\r\n]/g, '');

  const isStatic = vm.network_type === 'static_public';
  let cidrNum = 24;
  if (isStatic) {
    const rawMask = String(vm.netmask || vm.ipv4_netmask || '24');
    if (rawMask.includes('.')) {
      cidrNum = rawMask.split('.').reduce((sum, octet) => {
        const n = parseInt(octet, 10) || 0;
        return sum + n.toString(2).replace(/0/g, '').length;
      }, 0);
    } else {
      cidrNum = parseInt(rawMask, 10) || 24;
    }
  }
  const staticIp = String(vm.ipv4_address || '');
  const staticGateway = String(vm.gateway || vm.ipv4_gateway || '');
  const dnsList = String(vm.dns_servers || `${vm.dns_primary || '8.8.8.8'},${vm.dns_secondary || '1.1.1.1'}`)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .join(' ');

  const extraUserYaml = safeUser !== 'root'
    ? [
        'users:',
        '  - default',
        `  - name: ${safeUser}`,
        '    groups: sudo',
        '    shell: /bin/bash',
        '    lock_passwd: false',
        '    sudo: ALL=(ALL) NOPASSWD:ALL',
      ].join('\n')
    : [
        'users:',
        '  - default',
      ].join('\n');

  const chpasswdLines = [`    root:${cleanPass}`];
  if (safeUser !== 'root') {
    chpasswdLines.push(`    ${safeUser}:${cleanPass}`);
  }

  const profileStatusScriptLines = [
    '#!/bin/sh',
    'case "$-" in *i*) ;; *) return 0 2>/dev/null || exit 0 ;; esac',
    'if [ -f /var/lib/tgvpanel-proxmox-installed ]; then',
    '  PVE_IP=$(hostname -I 2>/dev/null | awk \'{print $1}\')',
    '  echo "=================================================================="',
    `  echo " [TGVPANEL] ${pveReleaseLabel} is READY"`,
    '  echo " Web Console: https://${PVE_IP:-127.0.0.1}:8006  (login: root / PAM)"',
    '  echo "=================================================================="',
    'elif systemctl is-active --quiet tgvpanel-proxmox-setup.service 2>/dev/null; then',
    '  CUR_STEP=$(cat /run/tgvpanel-proxmox-step 2>/dev/null || echo "Installing Proxmox VE packages...")',
    '  echo "=================================================================="',
    `  echo " [TGVPANEL] ${pveReleaseLabel} Bootstrap IN PROGRESS"`,
    '  echo " Status: ${CUR_STEP}"',
    '  echo " Note: APT/dpkg is temporarily locked while installing proxmox-ve."',
    '  echo " Live log: tail -f /var/log/proxmox-install.log"',
    '  echo " The VM will automatically reboot into Proxmox VE (:8006) when done."',
    '  echo "=================================================================="',
    'elif systemctl is-failed --quiet tgvpanel-proxmox-setup.service 2>/dev/null; then',
    '  echo "=================================================================="',
    '  echo " [TGVPANEL] Proxmox VE bootstrap encountered an issue."',
    '  echo " Check log: cat /var/log/proxmox-install.log"',
    '  echo " Retry:     systemctl restart tgvpanel-proxmox-setup.service"',
    '  echo "=================================================================="',
    'fi',
  ];

  const installerScriptLines = [
    '#!/bin/bash',
    'set -euo pipefail',
    'MARKER_FILE="/var/lib/tgvpanel-proxmox-installed"',
    'STEP_FILE="/run/tgvpanel-proxmox-step"',
    'LOG_FILE="/var/log/proxmox-install.log"',
    'if [ -f "$MARKER_FILE" ]; then',
    '  echo "[TGVPANEL-PVE] Proxmox VE already installed, skipping."',
    '  exit 0',
    'fi',
    'exec > >(tee -a "$LOG_FILE" /dev/console) 2>&1',
    `echo "=== [TGVPANEL] Starting Unattended ${pveReleaseLabel} Bootstrap ==="`,
    'export DEBIAN_FRONTEND=noninteractive',
    'APT_OPTS=(-y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold")',
    'echo "[1/6] Stopping background apt-daily timers to prevent APT lock contention" > "$STEP_FILE"',
    'systemctl stop apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service 2>/dev/null || true',
    'systemctl mask apt-daily.service apt-daily-upgrade.service 2>/dev/null || true',
    `SHORT_HOST="${shortHost}"`,
    `FQDN_HOST="${fqdn}"`,
    `CODENAME="${codename}"`,
    `GPG_URL="${gpgUrl}"`,
    `FALLBACK_GPG_URL="${fallbackGpgUrl}"`,
    `NET_MODE="${isStatic ? 'static_public' : 'nat'}"`,
    `STATIC_IP="${staticIp}"`,
    `STATIC_CIDR="${cidrNum}"`,
    `STATIC_GW="${staticGateway}"`,
    `DNS_SERVERS="${dnsList || '8.8.8.8 1.1.1.1'}"`,
    'download_file() {',
    '  local url="$1" dest="$2"',
    '  if command -v curl >/dev/null 2>&1; then',
    '    curl -fsSL --retry 3 --connect-timeout 15 "$url" -o "$dest"',
    '  elif command -v wget >/dev/null 2>&1; then',
    '    wget -q --tries=3 --timeout=15 "$url" -O "$dest"',
    '  elif command -v python3 >/dev/null 2>&1; then',
    '    python3 -c "import sys,urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" "$url" "$dest"',
    '  else',
    '    return 1',
    '  fi',
    '}',
    'PRIMARY_IFACE=$(ip -o -4 route show to default | awk \'{print $5}\' | head -n1 || true)',
    'if [ -z "$PRIMARY_IFACE" ]; then',
    '  PRIMARY_IFACE=$(ls /sys/class/net | grep -vE "^(lo|vmbr|tap|veth|fwbr|fwpr|fwln)" | head -n1 || echo "eth0")',
    'fi',
    'if [ "$NET_MODE" = "static_public" ] && [ -n "$STATIC_IP" ]; then',
    '  HOST_IP="$STATIC_IP"',
    'else',
    '  for _i in 1 2 3 4 5 6 7 8 9 10; do',
    '    HOST_IP=$(ip -4 -o addr show dev "$PRIMARY_IFACE" scope global | awk \'{print $4}\' | cut -d/ -f1 | head -n1 || true)',
    '    [ -n "$HOST_IP" ] && break',
    '    sleep 1',
    '  done',
    '  if [ -z "${HOST_IP:-}" ]; then',
    '    HOST_IP="10.0.2.15"',
    '  fi',
    'fi',
    'echo "[2/6] Configuring hostname (${FQDN_HOST}) and Proxmox APT repository" > "$STEP_FILE"',
    'hostnamectl set-hostname "$SHORT_HOST" || echo "$SHORT_HOST" > /etc/hostname',
    'cat > /etc/hosts <<EOF',
    '127.0.0.1 localhost',
    '${HOST_IP} ${FQDN_HOST} ${SHORT_HOST}',
    '::1 localhost ip6-localhost ip6-loopback',
    'ff02::1 ip6-allnodes',
    'ff02::2 ip6-allrouters',
    'EOF',
    'echo "[TGVPANEL-PVE] Configured /etc/hosts with ${HOST_IP} -> ${FQDN_HOST} (${SHORT_HOST})"',
    'mkdir -p /usr/share/keyrings /etc/apt/trusted.gpg.d /etc/apt/sources.list.d',
    'if ! download_file "$GPG_URL" /usr/share/keyrings/proxmox-archive-keyring.gpg || [ ! -s /usr/share/keyrings/proxmox-archive-keyring.gpg ]; then',
    '  download_file "$FALLBACK_GPG_URL" /usr/share/keyrings/proxmox-archive-keyring.gpg',
    'fi',
    'test -s /usr/share/keyrings/proxmox-archive-keyring.gpg',
    'cp /usr/share/keyrings/proxmox-archive-keyring.gpg "/etc/apt/trusted.gpg.d/proxmox-archive-keyring-${CODENAME}.gpg"',
    'chmod 0644 /usr/share/keyrings/proxmox-archive-keyring.gpg "/etc/apt/trusted.gpg.d/proxmox-archive-keyring-${CODENAME}.gpg"',
    'if [ "$CODENAME" = "trixie" ]; then',
    '  rm -f /etc/apt/sources.list.d/pve-no-subscription.list',
    '  cat > /etc/apt/sources.list.d/pve-install-repo.sources <<EOF',
    'Types: deb',
    'URIs: http://download.proxmox.com/debian/pve',
    'Suites: trixie',
    'Components: pve-no-subscription',
    'Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg',
    'EOF',
    'else',
    '  cat > /etc/apt/sources.list.d/pve-no-subscription.list <<EOF',
    'deb [signed-by=/usr/share/keyrings/proxmox-archive-keyring.gpg] http://download.proxmox.com/debian/pve ${CODENAME} pve-no-subscription',
    'EOF',
    'fi',
    'echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections',
    'echo "postfix postfix/mailname string ${FQDN_HOST}" | debconf-set-selections',
    'echo "samba-common samba-common/workgroup string WORKGROUP" | debconf-set-selections || true',
    'echo "samba-common samba-common/dhcp boolean false" | debconf-set-selections || true',
    'echo "[3/6] Refreshing APT package lists & upgrading Debian base (${CODENAME})" > "$STEP_FILE"',
    'apt-get update -o DPkg::Lock::Timeout=300',
    'apt-get full-upgrade "${APT_OPTS[@]}"',
    'echo "[4/6] Installing Proxmox VE kernel (${CODENAME})" > "$STEP_FILE"',
    'apt-get install "${APT_OPTS[@]}" proxmox-default-kernel',
    'echo "[5/6] Installing Proxmox VE hypervisor, LXC, QEMU & Web UI (:8006)" > "$STEP_FILE"',
    'apt-get install "${APT_OPTS[@]}" proxmox-ve postfix open-iscsi chrony ifupdown2 iptables curl wget gnupg',
    'apt-get install "${APT_OPTS[@]}" isc-dhcp-client || apt-get install "${APT_OPTS[@]}" dhcpcd-base || true',
    'rm -f /etc/apt/sources.list.d/pve-enterprise.list /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/ceph.list /etc/apt/sources.list.d/ceph.sources || true',
    'apt-get remove "${APT_OPTS[@]}" os-prober || true',
    'echo "[6/6] Finalizing vmbr0 bridge, serial GRUB & rebooting into PVE kernel" > "$STEP_FILE"',
    'if [ -f /etc/default/grub ]; then',
    '  sed -i \'s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"/\' /etc/default/grub',
    '  update-grub || true',
    'fi',
    'if [ "$NET_MODE" = "static_public" ] && [ -n "$STATIC_IP" ] && [ -n "$STATIC_GW" ]; then',
    '  cat > /etc/network/interfaces <<EOF',
    'auto lo',
    'iface lo inet loopback',
    '',
    'iface ${PRIMARY_IFACE} inet manual',
    '',
    'auto vmbr0',
    'iface vmbr0 inet static',
    '    address ${STATIC_IP}/${STATIC_CIDR}',
    '    gateway ${STATIC_GW}',
    '    bridge-ports ${PRIMARY_IFACE}',
    '    bridge-stp off',
    '    bridge-fd 0',
    '    dns-nameservers ${DNS_SERVERS}',
    'EOF',
    'else',
    '  cat > /etc/network/interfaces <<EOF',
    'auto lo',
    'iface lo inet loopback',
    '',
    'auto ${PRIMARY_IFACE}',
    'iface ${PRIMARY_IFACE} inet dhcp',
    '',
    'auto vmbr0',
    'iface vmbr0 inet static',
    '    address 10.10.10.1/24',
    '    bridge-ports none',
    '    bridge-stp off',
    '    bridge-fd 0',
    '    post-up echo 1 > /proc/sys/net/ipv4/ip_forward',
    '    post-up iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o ${PRIMARY_IFACE} -j MASQUERADE',
    '    post-down iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o ${PRIMARY_IFACE} -j MASQUERADE',
    'EOF',
    'fi',
    'mkdir -p /etc/cloud/cloud.cfg.d',
    'echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg',
    'rm -f /etc/netplan/*.yaml || true',
    'systemctl enable networking.service 2>/dev/null || true',
    'systemctl unmask apt-daily.service apt-daily-upgrade.service 2>/dev/null || true',
    'mkdir -p /var/lib',
    'date -u +"%Y-%m-%dT%H:%M:%SZ" > "$MARKER_FILE"',
    'rm -f "$STEP_FILE"',
    'echo "=== [TGVPANEL] Proxmox VE installation complete! Rebooting into PVE kernel (Web UI: https://${HOST_IP}:8006) ==="',
    'systemctl reboot',
  ];

  const formatYamlBlock = (linesArr) =>
    linesArr
      .map((line) => {
        if (!line) return '';
        const leading = line.match(/^ */)[0].length;
        const evenLeading = leading % 2 === 0 ? leading : leading + 1;
        return ' '.repeat(6 + evenLeading) + line.trimStart();
      })
      .join('\n');

  const formattedProfileBlock = formatYamlBlock(profileStatusScriptLines);
  const formattedScriptBlock = formatYamlBlock(installerScriptLines);

  const config = `#cloud-config
hostname: ${shortHost}
fqdn: ${fqdn}
manage_etc_hosts: false
ssh_pwauth: true
disable_root: false

${extraUserYaml}

chpasswd:
  expire: false
  list: |
${chpasswdLines.join('\n')}

write_files:
  - path: /etc/ssh/sshd_config.d/50-cloud-init.conf
    permissions: '0600'
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes
  - path: /etc/apt/apt.conf.d/99-tgvpanel-lock-timeout
    permissions: '0644'
    content: |
      DPkg::Lock::Timeout "180";
  - path: /etc/profile.d/tgvpanel-proxmox-status.sh
    permissions: '0755'
    content: |
${formattedProfileBlock}
  - path: /usr/local/sbin/tgvpanel-install-proxmox.sh
    permissions: '0755'
    content: |
${formattedScriptBlock}
  - path: /etc/systemd/system/tgvpanel-proxmox-setup.service
    permissions: '0644'
    content: |
      [Unit]
      Description=TGVPANEL Unattended Proxmox VE Bootstrap
      After=network-online.target ssh.service
      Wants=network-online.target
      ConditionPathExists=!/var/lib/tgvpanel-proxmox-installed

      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/tgvpanel-install-proxmox.sh
      RemainAfterExit=yes
      Restart=on-failure
      RestartSec=15
      StandardOutput=journal+console
      StandardError=journal+console

      [Install]
      WantedBy=multi-user.target

runcmd:
  - systemctl restart ssh || systemctl restart sshd || true
  - systemctl daemon-reload
  - systemctl enable tgvpanel-proxmox-setup.service
  - systemctl start --no-block tgvpanel-proxmox-setup.service

final_message: |
  TGVPANEL Proxmox VE Cloud-Init seed applied (${pveReleaseLabel})
  Hostname: ${fqdn}
  Web UI: https://<host-or-vm-ip>:8006 (login: root@pam)
`;

  return config;
}

/**
 * Pure Node.js ECMA-119 ISO-9660 + Rock Ridge ('cidata') generator fallback
 * Used when external genisoimage / mkisofs / xorriso / cloud-localds binaries are absent.
 */
function writeNoCloudIso9660(outputPath, filesMap) {
  const SECTOR = 2048;
  const entries = Object.entries(filesMap).map(([name, content], idx) => {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    const sectors = Math.max(1, Math.ceil(data.length / SECTOR));
    const upperBase = name.replace(/[^A-Za-z0-9]/g, '_').toUpperCase().slice(0, 8) || `FILE${idx}`;
    const isoId = `${upperBase}.;1`;
    return { name, isoId, data, size: data.length, sectors, extent: 0 };
  });

  const writeBoth32 = (buf, offset, val) => {
    buf.writeUInt32LE(val >>> 0, offset);
    buf.writeUInt32BE(val >>> 0, offset + 4);
  };
  const writeBoth16 = (buf, offset, val) => {
    buf.writeUInt16LE(val & 0xffff, offset);
    buf.writeUInt16BE(val & 0xffff, offset + 2);
  };
  const writeDirTime = (buf, offset, d) => {
    buf[offset] = d.getUTCFullYear() - 1900;
    buf[offset + 1] = d.getUTCMonth() + 1;
    buf[offset + 2] = d.getUTCDate();
    buf[offset + 3] = d.getUTCHours();
    buf[offset + 4] = d.getUTCMinutes();
    buf[offset + 5] = d.getUTCSeconds();
    buf[offset + 6] = 0;
  };
  const makeDirRecord = (idBuf, extent, dataLen, isDir, suBuf, now) => {
    const idLen = idBuf.length;
    const baseLen = 33 + idLen + (idLen % 2 === 0 ? 1 : 0);
    const suLen = suBuf ? suBuf.length : 0;
    const totalLen = baseLen + suLen + ((baseLen + suLen) % 2 === 1 ? 1 : 0);
    const rec = Buffer.alloc(totalLen, 0);
    rec[0] = totalLen;
    rec[1] = 0;
    writeBoth32(rec, 2, extent);
    writeBoth32(rec, 10, dataLen);
    writeDirTime(rec, 18, now);
    rec[25] = isDir ? 0x02 : 0x00;
    rec[26] = 0;
    rec[27] = 0;
    writeBoth16(rec, 28, 1);
    rec[32] = idLen;
    idBuf.copy(rec, 33);
    if (suBuf && suLen > 0) {
      suBuf.copy(rec, baseLen);
    }
    return rec;
  };

  const rootExtent = 20;
  let nextExtent = 21;
  for (const entry of entries) {
    entry.extent = nextExtent;
    nextExtent += entry.sectors;
  }
  const totalSectors = nextExtent;
  const isoBuf = Buffer.alloc(totalSectors * SECTOR, 0);
  const now = new Date();

  // Root directory sector (sector 20) with SUSP SP + Rock Ridge NM entries
  const rootSector = Buffer.alloc(SECTOR, 0);
  let dirOffset = 0;
  const spSu = Buffer.from([0x53, 0x50, 0x07, 0x01, 0xbe, 0xef, 0x00]);
  const dotRec = makeDirRecord(Buffer.from([0x00]), rootExtent, SECTOR, true, spSu, now);
  dotRec.copy(rootSector, dirOffset);
  dirOffset += dotRec.length;

  const dotDotRec = makeDirRecord(Buffer.from([0x01]), rootExtent, SECTOR, true, null, now);
  dotDotRec.copy(rootSector, dirOffset);
  dirOffset += dotDotRec.length;

  for (const entry of entries) {
    const nmBytes = Buffer.from(entry.name, 'utf8');
    const nmSu = Buffer.alloc(5 + nmBytes.length);
    nmSu[0] = 0x4e; // 'N'
    nmSu[1] = 0x4d; // 'M'
    nmSu[2] = nmSu.length;
    nmSu[3] = 0x01;
    nmSu[4] = 0x00;
    nmBytes.copy(nmSu, 5);
    const fileRec = makeDirRecord(Buffer.from(entry.isoId, 'ascii'), entry.extent, entry.size, false, nmSu, now);
    fileRec.copy(rootSector, dirOffset);
    dirOffset += fileRec.length;
  }
  rootSector.copy(isoBuf, rootExtent * SECTOR);

  // Path tables (sector 18 L-table, sector 19 M-table)
  const pathTableSize = 10;
  const lPath = isoBuf.subarray(18 * SECTOR, 18 * SECTOR + pathTableSize);
  lPath[0] = 1;
  lPath[1] = 0;
  lPath.writeUInt32LE(rootExtent, 2);
  lPath.writeUInt16LE(1, 6);
  lPath[8] = 0;
  lPath[9] = 0;

  const mPath = isoBuf.subarray(19 * SECTOR, 19 * SECTOR + pathTableSize);
  mPath[0] = 1;
  mPath[1] = 0;
  mPath.writeUInt32BE(rootExtent, 2);
  mPath.writeUInt16BE(1, 6);
  mPath[8] = 0;
  mPath[9] = 0;

  // Primary Volume Descriptor (sector 16)
  const pvd = isoBuf.subarray(16 * SECTOR, 17 * SECTOR);
  pvd[0] = 1;
  pvd.write('CD001', 1, 5, 'ascii');
  pvd[6] = 1;
  pvd.write('LINUX'.padEnd(32, ' '), 8, 32, 'ascii');
  pvd.write('cidata'.padEnd(32, ' '), 40, 32, 'ascii');
  writeBoth32(pvd, 80, totalSectors);
  writeBoth16(pvd, 120, 1);
  writeBoth16(pvd, 124, 1);
  writeBoth16(pvd, 128, SECTOR);
  writeBoth32(pvd, 132, pathTableSize);
  pvd.writeUInt32LE(18, 140);
  pvd.writeUInt32BE(19, 148);
  const pvdRootRec = makeDirRecord(Buffer.from([0x00]), rootExtent, SECTOR, true, null, now);
  pvdRootRec.copy(pvd, 156, 0, 34);
  pvd.write(' '.repeat(128), 190, 128, 'ascii');
  pvd.write('TGVPANEL CLOUD-INIT'.padEnd(128, ' '), 318, 128, 'ascii');
  pvd.write('TGVPANEL'.padEnd(128, ' '), 446, 128, 'ascii');
  pvd.write('TGVPANEL NOCLOUD ISO'.padEnd(128, ' '), 574, 128, 'ascii');
  const decNow = (
    String(now.getUTCFullYear()).padStart(4, '0') +
    String(now.getUTCMonth() + 1).padStart(2, '0') +
    String(now.getUTCDate()).padStart(2, '0') +
    String(now.getUTCHours()).padStart(2, '0') +
    String(now.getUTCMinutes()).padStart(2, '0') +
    String(now.getUTCSeconds()).padStart(2, '0') +
    '00'
  );
  for (const dtOffset of [813, 830]) {
    pvd.write(decNow, dtOffset, 16, 'ascii');
    pvd[dtOffset + 16] = 0;
  }
  for (const zeroOffset of [847, 864]) {
    pvd.write('0000000000000000', zeroOffset, 16, 'ascii');
    pvd[zeroOffset + 16] = 0;
  }
  pvd[881] = 1;

  // Volume Descriptor Set Terminator (sector 17)
  const term = isoBuf.subarray(17 * SECTOR, 18 * SECTOR);
  term[0] = 255;
  term.write('CD001', 1, 5, 'ascii');
  term[6] = 1;

  // File data sectors
  for (const entry of entries) {
    if (entry.size > 0) {
      entry.data.copy(isoBuf, entry.extent * SECTOR);
    }
  }

  fs.writeFileSync(outputPath, isoBuf);
}

/**
 * Create Cloud-Init seed ISO with proper netplan v2 / Proxmox VE configuration
 * Includes meta-data and user-data in correct format
 * Validates YAML syntax before creating ISO
 */
async function createCloudInitSeed(vm_id, rawVm) {
  return new Promise((resolve, reject) => {
    try {
      const vm = Object.assign({}, rawVm);
      if (vm.password && isEncryptedSecret(vm.password)) {
        try {
          vm.password = decryptSecret(vm.password);
        } catch (_e) {}
      }

      // Validate static IPv4 configuration if applicable
      if (vm.network_type === 'static_public') {
        const validation = validateStaticIPv4Config(vm);
        if (!validation.valid) {
          console.error(`[CLOUDINIT-${vm_id}] ✗ Validation Error: ${validation.error}`);
          return reject(new Error(`Static IPv4 validation failed: ${validation.error}`));
        }
        console.log(`[CLOUDINIT-${vm_id}] ✓ Static IPv4 configuration validated`);
      }
      
      const seedDir = path.join(VM_DIR, `vm-${vm_id}-seed-dir`);
      const seedIso = path.join(VM_DIR, `vm-${vm_id}-seed.iso`);
      const metaDataFile = path.join(seedDir, 'meta-data');
      const userDataFile = path.join(seedDir, 'user-data');

      // Clean up and create seed directory
      if (fs.existsSync(seedDir)) {
        fs.rmSync(seedDir, { recursive: true, force: true });
      }
      fs.mkdirSync(seedDir, { recursive: true });

      // Meta-data (instance information)
      const metaData = `instance-id: vm-${vm_id}
local-hostname: ${vm.hostname}
`;

      // User-data (cloud-init configuration) - Choose Proxmox hypervisor bootstrap or standard Linux config
      let userData;
      if (isProxmoxTemplate(vm)) {
        console.log(`[CLOUDINIT-${vm_id}] Using Proxmox VE Unattended Hypervisor Bootstrap (${vm.network_type || 'nat'})`);
        userData = generateProxmoxCloudInitConfig(vm);
      } else if (vm.network_type === 'nat') {
        console.log(`[CLOUDINIT-${vm_id}] Using NAT (User Mode) configuration`);
        userData = generateNATCloudInitConfig(vm);
      } else {
        console.log(`[CLOUDINIT-${vm_id}] Using Static Public IPv4 configuration`);
        userData = generateStaticPublicIPv4CloudInitConfig(vm);
      }

      // Validate cloud-init YAML before writing
      console.log(`[CLOUDINIT-${vm_id}] Validating cloud-init configuration...`);
      
      // Basic YAML validation - check for common issues
      const validateCloudInitConfig = (config) => {
        const errors = [];
        
        // Check if it starts with #cloud-config
        if (!config.startsWith('#cloud-config')) {
          errors.push('Must start with #cloud-config');
        }
        
        // Check for proper indentation (2 spaces)
        const lines = config.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Check tab characters (bad in YAML)
          if (line.includes('\t')) {
            errors.push(`Line ${i + 1}: Contains tab character (use spaces instead)`);
          }
          // Check indentation is multiple of 2
          const indent = line.match(/^ */)[0].length;
          if (indent > 0 && indent % 2 !== 0) {
            errors.push(`Line ${i + 1}: Invalid indentation (must be multiple of 2)`);
          }
        }
        
        return errors;
      };
      
      const validationErrors = validateCloudInitConfig(userData);
      if (validationErrors.length > 0) {
        console.warn(`[CLOUDINIT-${vm_id}] ⚠ Configuration warnings:`);
        validationErrors.forEach(err => console.warn(`  - ${err}`));
      } else {
        console.log(`[CLOUDINIT-${vm_id}] ✓ Cloud-init configuration is valid`);
      }

      // Write configuration files - only meta-data and user-data (no separate network-config)
      fs.writeFileSync(metaDataFile, metaData, 'utf8');
      fs.writeFileSync(userDataFile, userData, 'utf8');

      console.log(`[CLOUDINIT-${vm_id}] ✓ Configuration files written`);
      console.log(`[CLOUDINIT-${vm_id}] - meta-data: ${(metaData.length / 1024).toFixed(2)}KB`);
      console.log(`[CLOUDINIT-${vm_id}] - user-data: ${(userData.length / 1024).toFixed(2)}KB`);

      // Create ISO from seed files
      let isoCommand;
      try {
        if (isWindows) {
          try {
            isoCommand = `mkisofs -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`;
            execSync(isoCommand, { stdio: 'pipe', shell: 'cmd' });
          } catch (e) {
            writeNoCloudIso9660(seedIso, { 'meta-data': metaData, 'user-data': userData });
          }
        } else {
          // On Linux, try genisoimage -> mkisofs -> xorriso -> cloud-localds -> pure-JS ISO9660 fallback
          let createdByCli = false;
          for (const candidateCmd of [
            `genisoimage -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`,
            `mkisofs -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`,
            `xorriso -as mkisofs -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`,
            `cloud-localds "${seedIso}" "${userDataFile}" "${metaDataFile}"`,
          ]) {
            try {
              execSync(candidateCmd, { stdio: 'pipe', shell: '/bin/bash' });
              createdByCli = true;
              break;
            } catch (_cliErr) {}
          }
          if (!createdByCli) {
            console.log(`[CLOUDINIT-${vm_id}] System ISO CLI not found; generating ISO-9660 + Rock Ridge cidata image natively`);
            writeNoCloudIso9660(seedIso, { 'meta-data': metaData, 'user-data': userData });
          }
        }
        
        console.log(`[CLOUDINIT-${vm_id}] ✓ ISO seed created: ${seedIso}`);
        
        // Verify ISO was created
        if (fs.existsSync(seedIso)) {
          const size = fs.statSync(seedIso).size;
          console.log(`[CLOUDINIT-${vm_id}] ✓ ISO size: ${(size / 1024).toFixed(2)}KB`);
          
          // Clean up seed directory after successful ISO creation
          try {
            fs.rmSync(seedDir, { recursive: true, force: true });
            console.log(`[CLOUDINIT-${vm_id}] ✓ Seed directory cleaned up`);
          } catch (e) {
            console.warn(`[CLOUDINIT-${vm_id}] ⚠ Could not clean seed directory`);
          }
          
          resolve(true);
        } else {
          throw new Error('ISO file not created');
        }
      } catch (isoError) {
        console.error(`[CLOUDINIT-${vm_id}] ✗ ISO creation failed: ${isoError.message}`);
        console.error(`[CLOUDINIT-${vm_id}] Please install: genisoimage, mkisofs, or cloud-utils`);
        logError('CLOUDINIT', vm_id, 'ISO creation', isoError);
        reject(new Error('ISO creation tool not available - install genisoimage, mkisofs, or cloud-utils'));
      }
    } catch (error) {
      console.error(`[CLOUDINIT-${vm_id}] Error: ${error.message}`);
      console.error(`[CLOUDINIT-${vm_id}] Stack: ${error.stack}`);
      reject(error);
    }
  });
}

function buildQemuNatNetdevSpec(vm, netdevId = 'n0') {
  const sshPort = vm.ssh_port || vm.ssh_port_static || 2222;
  const hostfwds = [`hostfwd=tcp::${sshPort}-:22`];
  let pveWebPort = null;
  if (isProxmoxTemplate(vm)) {
    pveWebPort = getProxmoxWebUiPort(vm);
    if (pveWebPort !== Number(sshPort)) {
      hostfwds.push(`hostfwd=tcp::${pveWebPort}-:8006`);
    }
  }
  return {
    sshPort,
    pveWebPort,
    netdevArg: `user,id=${netdevId},${hostfwds.join(',')}`,
  };
}

async function startQemuVM(vm) {
  return new Promise((resolve, reject) => {
    try {
      const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
      const logFile = path.join(VM_DIR, `vm-${vm.vm_id}.log`);
      
      // Validate CPU model - fallback to 'host' if model not available
      let cpuToUse = 'host';
      if (vm.custom_cpu_name) {
        // Custom CPU name + CPU model - use both for full flexibility
        // Format: -cpu <cpu_model>,model-id=Custom Name
        // Note: No quotes needed when using spawn() array format
        let baseCpuModel = 'host';
        if (vm.cpu_model && CPU_MODELS[vm.cpu_model]) {
          baseCpuModel = vm.cpu_model;
        }
        cpuToUse = `${baseCpuModel},model-id=${vm.custom_cpu_name}`;
        console.log(`[VM-${vm.vm_id}] Using custom CPU: ${vm.custom_cpu_name} (base: ${baseCpuModel})`);
      } else if (vm.cpu_model && CPU_MODELS[vm.cpu_model]) {
        cpuToUse = vm.cpu_model;
        console.log(`[VM-${vm.vm_id}] Using preset CPU: ${cpuToUse}`);
      } else if (vm.cpu_model) {
        console.warn(`[VM-${vm.vm_id}] CPU model '${vm.cpu_model}' not found, falling back to 'host'`);
        cpuToUse = 'host';
        // Also update the database to fix the VM's CPU model
        db.run(`UPDATE vms SET cpu_model = 'host' WHERE vm_id = ?`, [vm.vm_id], (err) => {
          if (!err) console.log(`[VM-${vm.vm_id}] Updated database: cpu_model -> 'host'`);
        });
      }
      
      // Build QEMU command line as array (safer than string concatenation)
      const args = [
        `-m`, `${vm.memory}`,
        `-smp`, `cores=${vm.cpu_cores},threads=${vm.cpu_threads},sockets=${vm.cpu_sockets}`,
        `-cpu`, cpuToUse,
        `-name`, `vm-${vm.vm_id}`,
        `-machine`, `${vm.machine_type || 'pc'},accel=kvm:tcg`,
        `-enable-kvm`,
        `-nographic`
      ];
      
      // SMBIOS Configuration
      const smbiosManufacturer = vm.smbios_manufacturer || vm.custom_smbios_manufacturer || 'QEMU';
      const smbiosaProduct = vm.smbios_product || 'KVM Virtual Machine';
      const smbiosaVersion = vm.smbios_version || '1.0';
      const smbiosaSerial = vm.smbios_serial || `vm-${vm.vm_id}`;
      const boardName = vm.board_name || 'Main-Board';
      
      args.push(`-smbios`, `type=0,vendor=${smbiosManufacturer},version=${smbiosaVersion}`);
      args.push(`-smbios`, `type=1,manufacturer=${smbiosManufacturer},product=${smbiosaProduct},version=${smbiosaVersion},serial=${smbiosaSerial}`);
      args.push(`-smbios`, `type=2,manufacturer=${smbiosManufacturer},product=${boardName},version=${smbiosaVersion}`);
      
      console.log(`[VM-${vm.vm_id}] SMBIOS Config:`);
      console.log(`[VM-${vm.vm_id}]   Manufacturer: ${smbiosManufacturer}`);
      console.log(`[VM-${vm.vm_id}]   Product: ${smbiosaProduct}`);
      console.log(`[VM-${vm.vm_id}]   Board: ${boardName}`);
      console.log(`[VM-${vm.vm_id}]   Serial: ${smbiosaSerial}`);
      
      // ACPI configuration
      if (vm.enable_acpi === 0) {
        args.push(`-no-acpi`);
      }
      
      // Boot settings - check if ISO should boot first or disk
      if (vm.boot_from_iso && vm.iso_attached) {
        // Boot from ISO first, then fall back to disk
        args.push(`-boot`, `order=d,menu=off`);  // d = CDROM, then fallback
        console.log(`[VM-${vm.vm_id}] Boot Order: ISO (${vm.iso_attached}) → Disk`);
      } else {
        // Boot from HDD/disk only
        args.push(`-boot`, `c`);
        console.log(`[VM-${vm.vm_id}] Boot Order: Disk only`);
      }
      
      // Disable floppy device completely to avoid fd0 errors
      args.push(`-drive`, `if=floppy,index=-1`);
      
      // Drives - root disk
      // Support both current and legacy disk path fields
      const diskPath = vm.disk_file || vm.img_file;

      if (!diskPath || !fs.existsSync(diskPath)) {
        throw new Error(
          `[VM-${vm.vm_id}] Disk image missing or invalid: ${diskPath || 'No disk path in database'}`
        );
      }

      console.log(`[VM-${vm.vm_id}] Image File: ${diskPath}`);

      args.push(
        '-drive',
        `file=${diskPath},format=qcow2,if=virtio,media=disk`
      );
      
      // ISO media (if attached) - CD/DVD drive
      if (vm.iso_attached) {
        const isoPath = path.join(ISO_DIR, vm.iso_attached);
        if (fs.existsSync(isoPath)) {
          args.push(`-drive`, `file=${isoPath},format=raw,media=cdrom,if=ide,index=0`);
          console.log(`[VM-${vm.vm_id}] ISO Media Attached: ${vm.iso_attached}`);
        } else {
          console.warn(`[VM-${vm.vm_id}] ISO file not found: ${vm.iso_attached}`);
        }
      }
      
      // Cloud-init seed disk (CD-ROM) - MUST have for cloud-init to work
      const seedIso = path.join(VM_DIR, `vm-${vm.vm_id}-seed.iso`);
      if (fs.existsSync(seedIso)) {
        args.push(`-drive`, `file=${seedIso},format=raw,media=cdrom,if=ide,index=1`);
      }
      
      // Network Configuration - Support both NAT and Static IPv4
      const netdevId = 'n0';
      const macAddress = vm.mac_address || generateMACAddress();
      
      if (vm.network_type === 'nat') {
        // NAT (User Mode) Network with SSH port forwarding (+ HTTPS :8006 for Proxmox VE)
        const { sshPort, pveWebPort, netdevArg } = buildQemuNatNetdevSpec(vm, netdevId);
        
        // Add virtio network device
        args.push(`-device`, `virtio-net-pci,netdev=${netdevId},mac=${macAddress}`);
        
        // Add user-mode network with SSH (and Proxmox Web UI :8006 if applicable) port forwarding
        args.push(`-netdev`, netdevArg);
        
        console.log(`[VM-${vm.vm_id}] Network: NAT (User Mode) with Port Forwarding`);
        console.log(`[VM-${vm.vm_id}] QEMU Command:`);
        console.log(`[VM-${vm.vm_id}]   -device virtio-net-pci,netdev=${netdevId},mac=${macAddress}`);
        console.log(`[VM-${vm.vm_id}]   -netdev ${netdevArg}`);
        console.log(`[VM-${vm.vm_id}] SSH Port Forwarding: 0.0.0.0:${sshPort} → VM:22`);
        if (pveWebPort) {
          console.log(`[VM-${vm.vm_id}] Proxmox Web UI Forwarding: https://0.0.0.0:${pveWebPort} → VM:8006`);
        }
        console.log(`[VM-${vm.vm_id}] MAC Address: ${macAddress}`);
      } else {
        // Static Public IPv4 - Bridge Mode
        const bridgeDevice = vm.bridge_device || 'vmbr0';
        const dnsServers = vm.dns_servers || '8.8.8.8,8.8.4.4';
        
        // Add network device
        args.push(`-device`, `virtio-net-pci,netdev=${netdevId},mac=${macAddress}`);
        
        // Add bridge network interface
        args.push(`-netdev`, `bridge,id=${netdevId},br=${bridgeDevice}`);
        
        console.log(`[VM-${vm.vm_id}] Network: Static Public IPv4 (Bridge Mode)`);
        console.log(`[VM-${vm.vm_id}] QEMU Command:`);
        console.log(`[VM-${vm.vm_id}]   -device virtio-net-pci,netdev=${netdevId},mac=${macAddress}`);
        console.log(`[VM-${vm.vm_id}]   -netdev bridge,id=${netdevId},br=${bridgeDevice}`);
        console.log(`[VM-${vm.vm_id}] Bridge Device: ${bridgeDevice}`);
        console.log(`[VM-${vm.vm_id}] Configured Static IP: ${vm.ipv4_address}/${vm.netmask}`);
        console.log(`[VM-${vm.vm_id}] Gateway: ${vm.gateway}`);
        console.log(`[VM-${vm.vm_id}] DNS: ${dnsServers}`);
        console.log(`[VM-${vm.vm_id}] MAC Address: ${macAddress}`);
      }
      
      // Serial console with monitor support - stdin/stdout for direct terminal access
      args.push(`-serial`, `mon:stdio`);
      
      // Extra arguments if provided
      if (vm.extra_args) {
        args.push(vm.extra_args);
      }

      console.log(`[VM-${vm.vm_id}] CPU Config: ${vm.cpu_sockets} sockets x ${vm.cpu_cores} cores x ${vm.cpu_threads} threads = ${vm.cpus} total`);
      const cpuDisplayName = vm.custom_cpu_name || vm.cpu_model || 'host';
      console.log(`[VM-${vm.vm_id}] CPU Model: ${cpuDisplayName}`);
      console.log(`[VM-${vm.vm_id}] SMBIOS: ${vm.smbios_manufacturer} ${vm.smbios_product} (${vm.smbios_serial})`);
      console.log(`[VM-${vm.vm_id}] Network Mode: ${vm.network_type === 'nat' ? 'NAT (User Mode)' : 'Static Public IPv4'}`);
      if (vm.network_type !== 'nat') {
        console.log(`[VM-${vm.vm_id}] IPv4 Address: ${vm.ipv4_address}`);
      }
      console.log(`[VM-${vm.vm_id}] Template: ${vm.template_type} (${vm.os_type})`);
      console.log(`[VM-${vm.vm_id}] Starting: ${vm.vm_name}`);
      console.log(`[VM-${vm.vm_id}] Disk File: ${diskPath}`);
      console.log(`[VM-${vm.vm_id}] Console: Direct terminal access via -nographic -serial mon:stdio`);

      // Use spawn for background process execution
      const qemuProcess = spawn('qemu-system-x86_64', args, {
        stdio: ['pipe', 'pipe', 'pipe'],  // stdin: pipe (for console input), stdout: pipe, stderr: pipe
        detached: true,  // Let process run independently
        shell: false
      });
      
      // Store stdin for console input
      qemuStdins.set(vm.vm_id, qemuProcess.stdin);
      qemuProcess.stdin.on('error', (err) => {
        console.error(`[VM-${vm.vm_id}] stdin error:`, err.message);
      });

      const pid = qemuProcess.pid;
      
      // Save PID to file for later management
      fs.writeFileSync(pidFile, pid.toString());
      console.log(`[VM-${vm.vm_id}] ✓ Started with PID: ${pid}`);
      
      // Capture QEMU output to log file with rotation
      const rotateLogIfNeeded = () => {
        if (fs.existsSync(logFile)) {
          const stat = fs.statSync(logFile);
          if (stat.size > 10 * 1024 * 1024) {  // 10MB
            const backupFile = `${logFile}.${Date.now()}.bak`;
            fs.renameSync(logFile, backupFile);
            console.log(`[VM-${vm.vm_id}] Log rotated: ${backupFile}`);
          }
        }
      };
      
      if (qemuProcess.stdout) {
        qemuProcess.stdout.on('data', (data) => {
          rotateLogIfNeeded();
          fs.appendFileSync(logFile, data.toString());
        });
      }
      
      if (qemuProcess.stderr) {
        qemuProcess.stderr.on('data', (data) => {
          rotateLogIfNeeded();
          fs.appendFileSync(logFile, data.toString());
        });
      }
      
      // Handle process exit
      qemuProcess.on('exit', (code, signal) => {
        console.log(`[VM-${vm.vm_id}] Process exited with code ${code}, signal ${signal}`);
        qemuStdins.delete(vm.vm_id);
        try {
          fs.unlinkSync(pidFile);
        } catch (e) {}
      });
      
      qemuProcess.on('error', (err) => {
        console.error(`[VM-${vm.vm_id}] Process error: ${err.message}`);
        logError('QEMU', vm.vm_id, 'startup', err);
      });

      resolve({ pid, success: true });
    } catch (error) {
      logError('QEMU', vm.vm_id, 'initialization', error);
      reject(new Error(`Failed to start VM: ${error.message}`));
    }
  });
}

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Redirect / to dashboard or login
app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

// ============= SETTINGS ROUTES =============

// Get all settings (no auth required for reading defaults)
app.get('/api/settings', (req, res) => {
  db.all(`SELECT setting_key, setting_value FROM settings`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const settings = {
      panel_version: 'V3.0',
      panel_title: 'TGVPANEL V3.0',
      panel_description: 'Professional VM Management Panel',
      site_name: 'TGVPANEL',
      site_icon_url: '/images/logo.png',
      session_timeout: 24,
      max_sessions: 10
    };

    // Override with DB values
    if (rows && rows.length > 0) {
      rows.forEach(row => {
        if (
          row.setting_key === 'site_name' &&
          /^hkvm(\s+panel)?(\s+v[\d.]+)?$/i.test(String(row.setting_value || '').trim())
        ) {
          settings[row.setting_key] = 'TGVPANEL';
        } else if (
          row.setting_key === 'panel_title' &&
          /^hkvm(\s+panel)?(\s+v[\d.]+)?$/i.test(String(row.setting_value || '').trim())
        ) {
          settings[row.setting_key] = 'TGVPANEL V3.0';
        } else {
          settings[row.setting_key] = row.setting_value;
        }
      });
    }

    res.json(settings);
  });
});

// Update setting (admin only)
app.post('/api/settings/:key', checkAuth, checkAdmin, (req, res) => {
  const { key } = req.params;
  const { value } = req.body;

  if (value === null || value === undefined) {
    return res.status(400).json({ error: 'Value required' });
  }

  db.run(
    `INSERT OR REPLACE INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`,
    [key, String(value)],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, key, value });
    }
  );
});

// Update multiple settings (admin only)
app.put('/api/settings', checkAuth, checkAdmin, (req, res) => {
  const settings = req.body;
  let completed = 0;
  const total = Object.keys(settings).length;
  const errors = [];

  if (total === 0) {
    return res.status(400).json({ error: 'No settings provided' });
  }

  Object.entries(settings).forEach(([key, value]) => {
    db.run(
      `INSERT OR REPLACE INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`,
      [key, String(value)],
      (err) => {
        completed++;
        if (err) {
          errors.push({ key, error: err.message });
        }
        
        if (completed === total) {
          if (errors.length > 0) {
            res.status(500).json({ success: false, errors, saved: total - errors.length });
          } else {
            res.json({ success: true, saved: total });
          }
        }
      }
    );
  });
});

// ============= DISCORD SETTINGS API =============

// Get Discord settings (admin only)
app.get('/api/admin/discord-settings', checkAuth, checkAdmin, (req, res) => {
  db.get(`SELECT * FROM discord_settings LIMIT 1`, (err, settings) => {
    if (err) return res.status(500).json({ error: err.message });
    
    if (!settings) {
      // Return default empty settings
      return res.json({
        enabled: 0,
        client_id: '',
        client_secret: '',
        redirect_uri: '',
        bot_token: '',
        guild_id: '',
        auto_role_id: '',
        updated_at: null
      });
    }

    // Don't send client_secret to frontend for security
    const safe = { ...settings };
    safe.client_secret = safe.client_secret ? '••••••••' : '';
    safe.bot_token = safe.bot_token ? '••••••••' : '';
    res.json(safe);
  });
});

// Update Discord settings (admin only)
app.put('/api/admin/discord-settings', checkAuth, checkAdmin, (req, res) => {
  const { enabled, client_id, client_secret, redirect_uri, bot_token, guild_id, auto_role_id } = req.body;

  if (!client_id || !client_secret || !redirect_uri) {
    if (enabled) {
      return res.status(400).json({ error: 'Client ID, Client Secret, and Redirect URI are required' });
    }
  }

  // Get current settings to preserve secrets if not being changed
  db.get(`SELECT * FROM discord_settings LIMIT 1`, (err, current) => {
    if (err) return res.status(500).json({ error: err.message });

    const finalClientSecret = (client_secret && client_secret !== '••••••••') ? client_secret : (current?.client_secret || '');
    const finalBotToken = (bot_token && bot_token !== '••••••••') ? bot_token : (current?.bot_token || '');

    if (current) {
      // Update existing
      db.run(
        `UPDATE discord_settings SET 
         enabled = ?, client_id = ?, client_secret = ?, redirect_uri = ?, 
         bot_token = ?, guild_id = ?, auto_role_id = ?, updated_at = datetime('now')
         WHERE id = ?`,
        [enabled ? 1 : 0, client_id || '', finalClientSecret, redirect_uri || '', 
         finalBotToken, guild_id || '', auto_role_id || '', current.id],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          
          const response = { success: true, message: 'Discord settings updated' };
          if (client_secret === '••••••••' || !client_secret) {
            response.message += ' (Client Secret preserved)';
          }
          res.json(response);
        }
      );
    } else {
      // Insert new
      db.run(
        `INSERT INTO discord_settings (enabled, client_id, client_secret, redirect_uri, bot_token, guild_id, auto_role_id) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [enabled ? 1 : 0, client_id || '', finalClientSecret, redirect_uri || '', 
         finalBotToken, guild_id || '', auto_role_id || ''],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true, message: 'Discord settings created' });
        }
      );
    }
  });
});

// ============= USER PROFILE API =============

// Get user profile
app.get('/api/user/profile', checkAuth, (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  db.get(
    `SELECT id, username, email, full_name, role, created_at, last_login FROM users WHERE id = ?`,
    [userId],
    (err, user) => {
      if (err) {
        console.error('[API Error] Failed to load profile:', err);
        // Fallback: try without full_name and last_login columns in case they don't exist yet
        db.get(
          `SELECT id, username, email, role, created_at FROM users WHERE id = ?`,
          [userId],
          (err2, user2) => {
            if (err2 || !user2) {
              return res.status(404).json({ error: 'User not found' });
            }
            // Add null values for missing columns
            user2.full_name = null;
            user2.last_login = null;
            res.json(user2);
          }
        );
        return;
      }
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json(user);
    }
  );
});

// Update user profile (name & email)
app.put('/api/user/profile', checkAuth, (req, res) => {
  const { full_name, email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  db.run(
    `UPDATE users SET full_name = ?, email = ? WHERE id = ?`,
    [full_name || '', email, req.session.userId],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Email already in use' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, message: 'Profile updated successfully' });
    }
  );
});

// Change password
app.put('/api/user/password', checkAuth, (req, res) => {
  const { current_password, new_password } = req.body;
  
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'All password fields are required' });
  }
  
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  
  // Get current password hash
  db.get(`SELECT password FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Verify current password
    if (!bcrypt.compareSync(current_password, user.password)) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const hashedPassword = bcrypt.hashSync(new_password, 10);
    
    // Update password
    db.run(
      `UPDATE users SET password = ? WHERE id = ?`,
      [hashedPassword, req.session.userId],
      function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ success: true, message: 'Password changed successfully' });
      }
    );
  });
});

// ============= SSH CONNECTION API =============

// SSH Connect endpoint - Test SSH connection
app.post('/api/ssh/connect', checkAuth, (req, res) => {
  const { vmId, host, port, username } = req.body;
  const userId = req.session.userId;
  
  if (!vmId || !host || !port || !username) {
    return res.status(400).json({ error: 'Missing connection parameters' });
  }
  
  // Verify VM ownership
  db.get(`SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`, [vmId, userId], (err, vm) => {
    if (err || !vm) {
      return res.status(403).json({ error: 'VM not found or access denied' });
    }
    
    // Generate session ID
    const sessionId = require('crypto').randomBytes(16).toString('hex');
    
    // Store connection info in memory
    global.sshSessions = global.sshSessions || {};
    global.sshSessions[sessionId] = {
      vmId: vmId,
      userId: userId,
      host: host,
      port: parseInt(port),
      username: username,
      password: null,
      createdAt: Date.now(),
      client: null
    };
    
    // Try to create SSH connection to verify it works
    const conn = new Client();
    const connConfig = {
      host: host,
      port: parseInt(port),
      username: username,
      password: '',
      tryKeyboard: true,
      readyTimeout: 5000,
      strict: false
    };
    
    conn.on('ready', () => {
      console.log(`[SSH] Connected to ${host}:${port}`);
      global.sshSessions[sessionId].client = conn;
      res.json({
        success: true,
        sessionId: sessionId,
        message: 'SSH session created and connected'
      });
    });
    
    conn.on('error', (err) => {
      console.log(`[SSH] Connection error: ${err.message}`);
      delete global.sshSessions[sessionId];
      res.status(500).json({ 
        error: 'SSH connection failed: ' + err.message 
      });
    });
    
    conn.connect(connConfig);
  });
});

// SSH Command endpoint - Execute command on VM
app.post('/api/ssh/command', checkAuth, (req, res) => {
  const { vmId, command } = req.body;
  const userId = req.session.userId;
  
  if (!vmId || !command) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  // Find an active session for this VM
  let session = null;
  if (global.sshSessions) {
    for (const [id, s] of Object.entries(global.sshSessions)) {
      if (s.vmId === parseInt(vmId) && s.userId === userId && s.client) {
        session = s;
        break;
      }
    }
  }
  
  if (!session || !session.client) {
    return res.status(404).json({ error: 'SSH session not found. Connect first.' });
  }
  
  // Execute command via SSH
  session.client.exec(command, (err, stream) => {
    if (err) {
      return res.status(500).json({ 
        error: 'Command execution failed: ' + err.message 
      });
    }
    
    let output = '';
    let errorOutput = '';
    
    stream.on('close', () => {
      res.json({
        success: true,
        output: output || errorOutput || '(no output)',
        error: errorOutput || null
      });
    });
    
    stream.on('data', (data) => {
      output += data.toString();
    });
    
    stream.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });
  });
});

// ============= 404 HANDLER =============
app.use((req, res) => {
  res.status(404).render('users/404', {
    title: 'Page Not Found - TGVPANEL',
    message: 'Page not found'
  });
});

// START SERVER
initializeDatabase();

// WebSocket handler for VM console
const vmConsoles = new Map();
const sshSessions = new Map();

wss.on('connection', (ws, req) => {
  const url = req.url;
  console.log(`[WebSocket] New connection: ${url}`);
  
  // SSH Terminal WebSocket - Path: /ssh-terminal
  if (url.startsWith('/ssh-terminal')) {
    console.log(`[SSH-Terminal] New SSH terminal connection`);
    
    ws.on('message', async (message) => {
      try {
        const msg = JSON.parse(message.toString());
        
        if (msg.type === 'connect') {
          const { vmId, host, port, username, password } = msg;
          
          console.log(`[SSH-${vmId}] Initiating SSH connection to ${username}@${host}:${port}`);
          
          // Verify VM ownership
          db.get(`SELECT owner_id FROM vms WHERE vm_id = ?`, [vmId], (err, vm) => {
            if (err || !vm) {
              ws.send(JSON.stringify({ type: 'error', message: 'VM not found' }));
              return;
            }
            
            // Create SSH client
            const sshClient = new Client();
            
            sshClient.on('ready', () => {
              console.log(`[SSH-${vmId}] SSH client ready, opening shell`);
              
              sshClient.shell({ term: 'xterm-256color' }, (err, stream) => {
                if (err) {
                  console.error(`[SSH-${vmId}] Shell error:`, err.message);
                  ws.send(JSON.stringify({ type: 'error', message: 'Failed to open shell' }));
                  sshClient.end();
                  return;
                }
                
                console.log(`[SSH-${vmId}] Shell opened successfully`);
                ws.send(JSON.stringify({ type: 'connected' }));
                
                // Store session
                const sessionId = `${vmId}-${Date.now()}`;
                sshSessions.set(sessionId, { stream, client: sshClient, vmId });
                
                // Send raw data from SSH to WebSocket (binary, not JSON)
                // This preserves ANSI escape codes for proper terminal rendering
                stream.on('data', (data) => {
                  if (ws.readyState === WebSocket.OPEN) {
                    // Send raw binary data directly to xterm.js
                    ws.send(data, { binary: true });
                  }
                });
                
                stream.on('close', () => {
                  console.log(`[SSH-${vmId}] Shell closed`);
                  sshClient.end();
                  sshSessions.delete(sessionId);
                  if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'closed' }));
                  }
                });
                
                stream.on('error', (err) => {
                  console.error(`[SSH-${vmId}] Stream error:`, err.message);
                  sshSessions.delete(sessionId);
                  if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'error', message: err.message }));
                  }
                });
                
                // Store current session for this WebSocket
                ws.sshSessionId = sessionId;
              });
            });
            
            sshClient.on('error', (err) => {
              console.error(`[SSH-${vmId}] Connection error:`, err.message);
              ws.send(JSON.stringify({ type: 'error', message: `SSH Connection failed: ${err.message}` }));
              if (ws.readyState === WebSocket.OPEN) {
                ws.close();
              }
            });
            
            sshClient.on('close', () => {
              console.log(`[SSH-${vmId}] SSH connection closed`);
              if (ws.readyState === WebSocket.OPEN) {
                ws.close();
              }
            });
            
            // Connect to SSH server
            sshClient.connect({
              host: host,
              port: parseInt(port),
              username: username,
              password: password,
              readyTimeout: 30000,
              algorithms: {
                serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519']
              }
            });
          });
        } else if (msg.type === 'input' && ws.sshSessionId) {
          // Send user input to SSH shell (handle binary input)
          const session = sshSessions.get(ws.sshSessionId);
          if (session && session.stream) {
            session.stream.write(msg.data);
          }
        }
      } catch (err) {
        console.error('[SSH-Terminal] Message error:', err.message);
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
      }
    });
    
    ws.on('close', () => {
      console.log(`[SSH-Terminal] WebSocket closed`);
      if (ws.sshSessionId) {
        const session = sshSessions.get(ws.sshSessionId);
        if (session) {
          try {
            session.stream.end();
            session.client.end();
          } catch (e) {
            console.error('[SSH-Terminal] Error closing session:', e.message);
          }
          sshSessions.delete(ws.sshSessionId);
        }
      }
    });
    
    ws.on('error', (err) => {
      console.error(`[SSH-Terminal] WebSocket error:`, err.message);
    });
    
    return;
  }
  
  // Extract vmId from URL path like /console/1 or just /1
  let vmId = null;
  if (url.includes('/console/')) {
    vmId = url.split('/console/')[1].split('?')[0];
  } else {
    vmId = url.split('/').pop().split('?')[0];
  }
  
  if (!vmId || vmId === '' || isNaN(vmId)) {
    console.log(`[WebSocket] Invalid vmId: "${vmId}"`);
    ws.send(JSON.stringify({ type: 'output', data: '\x1b[31m✗ Invalid VM ID\x1b[0m\r\n' }));
    ws.close();
    return;
  }

  console.log(`[Console-${vmId}] Client connected`);
  
  const logFile = path.join(VM_DIR, `vm-${vmId}.log`);
  let lastSize = 0;
  let watchInterval = null;

  // Send initial content
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId], (err, vm) => {
    if (err) {
      console.error(`[Console-${vmId}] DB error:`, err.message);
      ws.send(JSON.stringify({ type: 'output', data: `\x1b[31m✗ Database error\x1b[0m\r\n` }));
      return;
    }

    if (!vm) {
      console.log(`[Console-${vmId}] VM not found`);
      ws.send(JSON.stringify({ type: 'output', data: `\x1b[31m✗ VM ${vmId} not found\x1b[0m\r\n` }));
      return;
    }

    let intro = '';
    if (vm.status === 'running') {
      intro = `\x1b[32m✓ VM ${vmId} is RUNNING\x1b[0m\r\n`;
    } else {
      intro = `\x1b[33m⚠ VM ${vmId} is ${vm.status.toUpperCase()}\x1b[0m\r\n`;
    }

    // Read and send existing log
    if (fs.existsSync(logFile)) {
      try {
        const content = fs.readFileSync(logFile, 'utf8');
        lastSize = content.length;
        ws.send(JSON.stringify({ 
          type: 'output', 
          data: intro + content 
        }));
        console.log(`[Console-${vmId}] Sent ${content.length} bytes of log`);
      } catch (e) {
        console.error(`[Console-${vmId}] Read error:`, e.message);
        ws.send(JSON.stringify({ type: 'output', data: intro + '\x1b[33m(Log file error)\x1b[0m\r\n' }));
      }
    } else {
      ws.send(JSON.stringify({ type: 'output', data: intro + '\x1b[36m[Console ready]\x1b[0m\r\n' }));
    }

    // Start watching for new output (50ms interval for near real-time)
    watchInterval = setInterval(() => {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        if (watchInterval) clearInterval(watchInterval);
        return;
      }

      try {
        if (fs.existsSync(logFile)) {
          const stat = fs.statSync(logFile);
          if (stat.size > lastSize) {
            const fd = fs.openSync(logFile, 'r');
            const buffer = Buffer.alloc(stat.size - lastSize);
            fs.readSync(fd, buffer, 0, stat.size - lastSize, lastSize);
            fs.closeSync(fd);
            
            lastSize = stat.size;
            const newData = buffer.toString('utf8');
            
            // Send to all clients for this VM
            if (vmConsoles.has(vmId)) {
              vmConsoles.get(vmId).forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                  client.send(JSON.stringify({ type: 'output', data: newData }));
                }
              });
            }
          }
        }
      } catch (e) {
        console.error(`[Console-${vmId}] Watch error:`, e.message);
      }
    }, 50);
  });

  // Store client
  if (!vmConsoles.has(vmId)) {
    vmConsoles.set(vmId, []);
  }
  vmConsoles.get(vmId).push(ws);

  // Handle input from terminal (route directly to QEMU serial stdin when running)
  ws.on('message', (message) => {
    try {
      const msg = JSON.parse(message);
      if (msg.type === 'input' && msg.data) {
        const numericVmId = Number(vmId);
        const qemuStdin = qemuStdins.get(numericVmId);
        if (qemuStdin && !qemuStdin.destroyed && qemuStdin.writable) {
          qemuStdin.write(msg.data);
        } else {
          ws.send(JSON.stringify({ type: 'output', data: '\x1b[33m[VM serial stdin is not active — start the VM first]\x1b[0m\r\n' }));
        }
      }
    } catch (e) {
      console.error(`[Console-${vmId}] Message parse error:`, e.message);
    }
  });

  // Handle disconnect
  ws.on('close', () => {
    console.log(`[Console-${vmId}] Client disconnected`);
    
    if (vmConsoles.has(vmId)) {
      const clients = vmConsoles.get(vmId);
      const idx = clients.indexOf(ws);
      if (idx > -1) {
        clients.splice(idx, 1);
      }
      
      // Clean up interval if no more clients
      if (clients.length === 0) {
        vmConsoles.delete(vmId);
      }
    }
  });

  ws.on('error', (error) => {
    console.error(`[Console-${vmId}] WebSocket error:`, error.message);
  });
});

// Authenticated WebSocket Upgrade Multiplexer for KVM (/console/:vmId, /ssh-terminal)
// Note: /ws/lxc/* and /ws/nodes/* are handled by attachUnifiedWebSockets()
server.on('upgrade', (req, socket, head) => {
  const urlPath = (req.url || '').split('?')[0];
  if (urlPath.startsWith('/ws/')) {
    return;
  }

  const dummyRes = new http.ServerResponse(req);
  sessionParser(req, dummyRes, () => {
    if (!req.session || !req.session.userId) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    if (urlPath.startsWith('/ssh-terminal')) {
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.authUser = { id: req.session.userId, role: req.session.role };
        wss.emit('connection', ws, req);
      });
      return;
    }

    let vmId = null;
    if (urlPath.includes('/console/')) {
      vmId = urlPath.split('/console/')[1];
    } else {
      vmId = urlPath.split('/').pop();
    }

    if (!vmId || isNaN(Number(vmId))) {
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      socket.destroy();
      return;
    }

    db.get(`SELECT owner_id, shared_with FROM vms WHERE vm_id = ?`, [Number(vmId)], (err, vm) => {
      if (err || !vm) {
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
        socket.destroy();
        return;
      }
      let shared = [];
      try { shared = JSON.parse(vm.shared_with || '[]'); } catch (e) {}
      if (
        req.session.role !== 'admin' &&
        req.session.role !== 'subadmin' &&
        vm.owner_id !== req.session.userId &&
        !shared.includes(req.session.userId)
      ) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.authUser = { id: req.session.userId, role: req.session.role };
        wss.emit('connection', ws, req);
      });
    });
  });
});

async function bootstrapHkvmV3() {
  hkvmV3Context = await initializeUnifiedHkvmRuntime(db, dbPath, {
    startVmById: async (vmId) => {
      const vm = await hkvmV3Context.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
      if (!vm) throw new Error(`VM ${vmId} not found`);
      if (vm.status === 'running') return;
      const result = await startQemuVM(vm);
      if (!result || !result.success) {
        throw new Error('Failed to start QEMU process');
      }
      vmProcesses.set(vm.vm_id, result.pid);
      await hkvmV3Context.db.run(
        `UPDATE vms SET status = 'running', pid = ?, uptime = 0 WHERE vm_id = ?`,
        [result.pid, vm.vm_id]
      );
      logVMAction(vm.vm_id, 'start', 'running', 'VM started via Unified Virtualization Manager');
    },
    stopVmById: async (vmId, force) => {
      const pidFile = path.join(VM_DIR, `vm-${vmId}.pid`);
      if (fs.existsSync(pidFile)) {
        const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
        try {
          process.kill(-pid, force ? 'SIGKILL' : 'SIGTERM');
        } catch (e) {
          try { process.kill(pid, force ? 'SIGKILL' : 'SIGTERM'); } catch (e2) {}
        }
      }
      vmProcesses.delete(vmId);
      qemuStdins.delete(vmId);
      await hkvmV3Context.db.run(`UPDATE vms SET status = 'stopped', pid = NULL WHERE vm_id = ?`, [vmId]);
      logVMAction(vmId, 'stop', 'stopped', 'VM stopped via Unified Virtualization Manager');
    },
    deleteVmById: async (vmId) => {
      const vm = await hkvmV3Context.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
      if (!vm) return;
      await performFullVmDelete(vm, null);
    }
  });

  v3PrincipalMiddleware = createUnifiedAuthMiddleware(hkvmV3Context.db);
  v3ApiRouter = createApiV1Router(hkvmV3Context);
  // ---------------------------------------------------------------------
  // Own-node KVM selling hook.
  //
  // A `local` reseller provider sells capacity from nodes we control. Creating
  // a KVM guest means driving the same qcow2/cloud-init pipeline the admin VM
  // form uses, so the reseller service is handed a creator rather than
  // duplicating that logic in TypeScript.
  // ---------------------------------------------------------------------
  if (hkvmV3Context.reseller && hkvmV3Context.reseller.local) {
    hkvmV3Context.reseller.local.setKvmCreateHook(async (spec) => {
      const {
        userId, name, cores, memoryMb, diskGb, templateKey, templateLabel, expirationDays,
      } = spec;

      // Validate the template before creating anything.
      const builtIn = templateKey && OS_TEMPLATES[templateKey];
      let template = builtIn || null;
      let isCloudInit = true;
      if (!builtIn && templateKey) {
        template = await new Promise((resolve) => {
          db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [templateKey], (e, row) =>
            resolve(e ? null : row)
          );
        });
        if (!template) {
          throw new Error(
            `Unknown OS template "${templateKey}". Add it under Admin → Templates first.`
          );
        }
        isCloudInit = template.template_type === 'cloud-init';
      }
      if (!template) {
        throw new Error(
          'KVM plans must reference an OS template (cloud-init image or installer ISO).'
        );
      }

      const sshUser = template.username || 'ubuntu';
      const plainPassword = require('crypto').randomBytes(16).toString('hex');
      const vmName = String(name).slice(0, 60);

      // Reuse the same shape the admin creation route writes.
      const vmId = await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO vms (
             vm_name, os_type, template_type, hostname, username, password,
             memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model,
             machine_type, board_name, product_name,
             disk_size, img_file, seed_file, disk_file,
             status, uptime, node_name,
             network_type, ssh_port, ssh_port_static, http_port,
             mac_address, bridge_device, owner_id
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 1, 'host',
             'pc', 'Main-Board', 'Virtual Machine',
             ?, '', '', '',
             'stopped', 0, 'localhost',
             'nat', 22, 22, 80,
             ?, 'vmbr0', ?)`,
          [
            vmName, templateKey, isCloudInit ? 'cloud-init' : 'iso-installer',
            vmName, sshUser, encryptSecret(String(plainPassword)),
            memoryMb, cores, cores,
            `${Math.max(5, Number(diskGb))}G`,
            generateMACAddress(), userId,
          ],
          function (err) {
            if (err) return reject(err);
            resolve(this.lastID);
          }
        );
      });

      const imgFile = path.join(isCloudInit ? CLOUDVM_DIR : ISO_DIR, `${templateKey}-${vmId}.qcow2`);
      const diskFile = path.join(VM_DIR, `vm-${vmId}-disk.qcow2`);
      const seedFile = path.join(VM_DIR, `vm-${vmId}-seed.iso`);
      await hkvmV3Context.db.run(
        `UPDATE vms SET img_file = ?, seed_file = ?, disk_file = ? WHERE vm_id = ?`,
        [imgFile, seedFile, diskFile, vmId]
      );

      const expiresAt = Number(expirationDays) > 0
        ? new Date(Date.now() + Number(expirationDays) * 86400000).toISOString()
        : null;

      // Register in the unified instance registry so the customer's dashboard
      // and the fleet view both see it.
      const instance = {
        uid: `kvm:${vmId}`,
        engine: 'kvm',
        refId: vmId,
        name: vmName,
        hostname: vmName,
        ownerId: userId,
        nodeId: 1,
        status: 'stopped',
        suspended: false,
        osLabel: templateLabel || templateKey,
        cpuCores: cores,
        ramMb: memoryMb,
        swapMb: 0,
        diskGb: Number(diskGb),
        primaryIp: null,
        sharedWith: [],
        expiresAt,
        createdAt: new Date().toISOString(),
        capabilities: hkvmV3Context.virtManager
          ? hkvmV3Context.virtManager.kvm.getCapabilityProfile()
          : { engine: 'kvm' },
      };

      // Build disks + seed and boot the guest asynchronously; the customer sees
      // "provisioning" until it comes up, exactly like an upstream order.
      setImmediate(async () => {
        try {
          const raw = await hkvmV3Context.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
          if (!raw) return;
          if (isCloudInit) {
            await createCloudInitSeed(vmId, raw);
          }
          const started = await startQemuVM(raw);
          if (started && started.success) {
            vmProcesses.set(vmId, started.pid);
            await hkvmV3Context.db.run(
              `UPDATE vms SET status = 'running', pid = ? WHERE vm_id = ?`,
              [started.pid, vmId]
            );
          }
        } catch (e) {
          console.error(`[own-node] VM ${vmId} boot failed:`, e && e.message);
        }
      });

      return { instance, rootPassword: plainPassword };
    });
    // The built-in KVM image catalogue lives in this file, so hand it to the
    // reseller engine: only images that can actually boot should be sellable.
    hkvmV3Context.reseller.local.setKvmTemplateHook(() =>
      Object.entries(OS_TEMPLATES).map(([key, tpl]) => ({
        id: key,
        name: tpl.name || key,
        family: tpl.type === 'iso-installer' ? 'iso' : 'linux',
        arch: 'amd64',
      }))
    );
    console.log('[own-node] KVM provisioning hook registered');
  }

  v3WebRouter = createUnifiedWebRouter(hkvmV3Context);
  attachUnifiedWebSockets(server, sessionParser, hkvmV3Context);
  return hkvmV3Context;
}

const hkvmReadyPromise = bootstrapHkvmV3()
  .then(() => {
    if (process.env.TGVPANEL_NO_LISTEN !== '1' && process.env.HKVM_NO_LISTEN !== '1') {
      server.listen(Number(PORT), '0.0.0.0', async () => {
        console.log('[License] Free Edition active');

        const validCpuModels = Object.keys(CPU_MODELS);
        db.all(
          `SELECT vm_id, cpu_model FROM vms WHERE cpu_model NOT IN (${validCpuModels.map(() => '?').join(',')})`,
          validCpuModels,
          (err, vms) => {
            if (!err && vms && vms.length > 0) {
              vms.forEach((vm) => {
                db.run(`UPDATE vms SET cpu_model = 'host' WHERE vm_id = ?`, [vm.vm_id]);
              });
            }
          }
        );

        console.log(`
╔════════════════════════════════════════════════════════════╗
║         TGVPANEL UNIFIED VIRTUALIZATION PANEL V3.0         ║
║       QEMU/KVM Virtual Machines + LXC Containers           ║
╚════════════════════════════════════════════════════════════╝

✓ Server:   http://0.0.0.0:${PORT}
✓ Database: ${dbPath}
✓ VM Dir:   ${VM_DIR}
        `);
      });
    }
  })
  .catch((err) => {
    console.error('[TGVPANEL Bootstrap Fatal Error]:', err);
    process.exit(1);
  });

app.server = server;
app.getHkvmV3Context = () => hkvmV3Context;
app.hkvmReadyPromise = hkvmReadyPromise;
app.proxmoxHelpers = {
  OS_TEMPLATES,
  isProxmoxTemplate,
  getProxmoxWebUiPort,
  enrichVmTemplateMetadata,
  generateProxmoxCloudInitConfig,
  buildQemuNatNetdevSpec,
  createCloudInitSeed,
  writeNoCloudIso9660,
};

module.exports = app;
