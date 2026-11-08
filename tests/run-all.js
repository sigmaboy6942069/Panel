#!/usr/bin/env node
/**
 * TGVPANEL — End-to-End Integration, Security & Acceptance Test Suite
 *
 * Runs against an isolated temporary clone of data/tgvpanel.db so live database state
 * is never polluted. Exercises real SQLite, real Express + WebSocket server,
 * real standalone Node Agent HTTP/HMAC server, real AES-256-GCM/TOTP/CSRF/RBAC,
 * real Werkzeug pbkdf2/scrypt legacy HVM importer, and real node-pty restricted shell.
 */
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const sqlite3 = require('sqlite3');
const WebSocket = require('ws');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'tgvpanel-acceptance-'));
const testDbPath = path.join(tmpRoot, 'tgvpanel.db');
const primaryRepoDb = path.resolve(__dirname, '../data/tgvpanel.db');
fs.copyFileSync(primaryRepoDb, testDbPath);

const TEST_PORT = 18940 + Math.floor(Math.random() * 500);
const AGENT_PORT = 19540 + Math.floor(Math.random() * 500);

const seededLegacySessionSecret = crypto.randomBytes(32).toString('hex');
fs.writeFileSync(
  path.join(tmpRoot, '.hkvm-secret'),
  JSON.stringify(
    {
      sessionSecret: seededLegacySessionSecret,
      credentialKeyHex: crypto.randomBytes(32).toString('hex'),
      csrfSecret: crypto.randomBytes(32).toString('hex'),
    },
    null,
    2
  ),
  { mode: 0o600 }
);

process.env.TGVPANEL_DATA_DIR = tmpRoot;
process.env.TGVPANEL_DB_PATH = testDbPath;
process.env.TGVPANEL_SECRET_FILE = path.join(tmpRoot, '.tgvpanel-secret');
process.env.TGVPANEL_LXC_PATH = path.join(tmpRoot, 'local-lxc');
process.env.TGVPANEL_BACKUP_DIR = path.join(tmpRoot, 'local-backups');
process.env.PORT = String(TEST_PORT);
process.env.TGVPANEL_DISABLE_BACKGROUND_POLLER = 'true';
process.env.TGVPANEL_ENABLE_NODE_SHELL = 'true';

const {
  getSecretBundle,
  getSecretVaultPath,
  encryptSecret,
  decryptSecret,
  isEncryptedSecret,
  generateApiKeyPair,
  hashApiKey,
  signAgentRequest,
  computeTotpCode,
  verifyTotpCode,
} = require('../lib/security/crypto-vault');
const { UnifiedDatabase, resolveAndMigrateDatabasePath } = require('../lib/db/database');
const { runMigrations } = require('../lib/db/migrations');
const { importHvmDatabase } = require('../lib/db/hvm-importer');
const { createNodeAgentServer } = require('../lib/node-agent/agent');
const { runAllowlistedCommand, buildSafeSpawnEnv } = require('../lib/node-agent/command-runner');
const {
  LxcContainerManager,
  resolveDownloadReleaseCandidates,
  computeIpv4SubnetCidr,
  resolveGuestDnsServers,
} = require('../lib/node-agent/container-manager');

const results = [];
async function runStep(name, fn) {
  const start = Date.now();
  try {
    await fn();
    const ms = Date.now() - start;
    results.push({ name, status: 'PASS', ms });
    console.log(`  \x1b[32m✓ PASS\x1b[0m  ${name} (${ms}ms)`);
  } catch (err) {
    const ms = Date.now() - start;
    results.push({ name, status: 'FAIL', ms, error: err.stack || err.message });
    console.error(`  \x1b[31m✗ FAIL\x1b[0m  ${name} (${ms}ms)\n    ${err.stack || err.message}`);
  }
}

class SessionClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookie = '';
    this.csrfToken = '';
  }

  async request(method, urlPath, body = undefined, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (this.cookie) headers['Cookie'] = this.cookie;
    if (this.csrfToken && !headers['X-CSRF-Token'] && !headers['Authorization']) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }
    let payload;
    if (body !== undefined) {
      if (Buffer.isBuffer(body)) {
        payload = body;
        headers['Content-Length'] = payload.length;
      } else {
        payload = typeof body === 'string' ? body : JSON.stringify(body);
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        headers['Content-Length'] = Buffer.byteLength(payload);
      }
    }

    return new Promise((resolve, reject) => {
      const u = new URL(urlPath, this.baseUrl);
      const req = http.request(
        {
          hostname: u.hostname,
          port: u.port,
          path: u.pathname + u.search,
          method,
          headers,
        },
        (res) => {
          const setCookie = res.headers['set-cookie'];
          if (setCookie && setCookie.length > 0) {
            this.cookie = setCookie.map((c) => c.split(';')[0]).join('; ');
          }
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            const csrfMatch = text.match(/meta name="csrf-token" content="([^"]+)"/);
            if (csrfMatch) this.csrfToken = csrfMatch[1];
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (_) {}
            resolve({ status: res.statusCode, headers: res.headers, text, json });
          });
        }
      );
      req.on('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }
}

function makeWerkzeugPbkdf2Hash(password, salt = 'testsalt1234', iterations = 600000) {
  const dk = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256').toString('hex');
  return `pbkdf2:sha256:${iterations}$${salt}$${dk}`;
}

(async () => {
  console.log('\n====================================================================');
  console.log('  TGVPANEL — Unified Virtualization Panel Acceptance Test Suite');
  console.log('====================================================================\n');

  let agentServer = null;
  let httpsAgentServer = null;
  let app = null;
  let remoteNodeId = null;
  const installedLxcShims = [];
  const rootOwnedCleanupDirs = [];

  try {
    // 1. Pre-boot migration & schema preservation test on a clean HKVM V2 baseline DB
    await runStep('T01: Transactional SQLite backup & migrations v001..v009 preserve legacy data & cascade VM FKs', async () => {
      const v2ScratchPath = path.join(tmpRoot, 'v2_scratch.db');
      const v2Raw = new sqlite3.Database(v2ScratchPath);
      const v2Db = new UnifiedDatabase(v2Raw, v2ScratchPath);
      await v2Db.exec(`
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, email TEXT, full_name TEXT, role TEXT DEFAULT 'user', is_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        INSERT INTO users (username, password, email, role) VALUES ('admin', '$2a$10$legacyhashplaceholder123456789012345678901234567', 'admin@hopingboyz.local', 'admin');
        CREATE TABLE vms (vm_id INTEGER PRIMARY KEY AUTOINCREMENT, vm_name TEXT, hostname TEXT, owner_id INTEGER, memory INTEGER DEFAULT 1024, cpus INTEGER DEFAULT 1, disk_size TEXT DEFAULT '20G', status TEXT DEFAULT 'stopped', password TEXT);
        INSERT INTO vms (vm_name, hostname, owner_id) VALUES ('legacy-fk-vm', 'legacy-fk', 1);
        CREATE TABLE vm_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, action TEXT, status TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(vm_id) REFERENCES vms(vm_id));
        INSERT INTO vm_logs (vm_id, action, status, message) VALUES (1, 'create', 'pending', 'Legacy VM created');
        CREATE TABLE vm_snapshots (snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, snapshot_name TEXT, size_gb REAL, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(vm_id) REFERENCES vms(vm_id));
        INSERT INTO vm_snapshots (vm_id, snapshot_name, size_gb, description) VALUES (1, 'snap-legacy', 1.2, 'Before upgrade');
        CREATE TABLE os_templates (template_id INTEGER PRIMARY KEY AUTOINCREMENT, template_key TEXT UNIQUE, template_name TEXT, password TEXT);
        CREATE TABLE settings (setting_key TEXT PRIMARY KEY, setting_value TEXT, updated_at DATETIME);
        INSERT INTO settings (setting_key, setting_value, updated_at) VALUES ('site_name', 'HKVM', datetime('now'));
        INSERT INTO settings (setting_key, setting_value, updated_at) VALUES ('panel_title', 'HKVM Panel V2.0', datetime('now'));
        CREATE TABLE discord_settings (id INTEGER PRIMARY KEY, enabled INTEGER DEFAULT 0);
        CREATE TABLE user_discord_accounts (id INTEGER PRIMARY KEY, user_id INTEGER, discord_id TEXT);
      `);

      const migRes = await runMigrations(v2Db);
      assert.ok(migRes.applied.length >= 9, 'Expected v001..v009 migrations to apply');
      assert.ok(migRes.backupPath && fs.existsSync(migRes.backupPath), 'Expected pre-migration backup');

      // Verify v009 upgraded vm_logs & vm_snapshots to ON DELETE CASCADE while preserving rows,
      // and deleting from vms with PRAGMA foreign_keys = ON succeeds cleanly!
      assert.strictEqual((await v2Db.all(`SELECT * FROM vm_logs WHERE vm_id = 1`)).length, 1);
      assert.strictEqual((await v2Db.all(`SELECT * FROM vm_snapshots WHERE vm_id = 1`)).length, 1);
      await v2Db.run(`DELETE FROM vms WHERE vm_id = 1`);
      assert.strictEqual((await v2Db.all(`SELECT * FROM vms WHERE vm_id = 1`)).length, 0);
      assert.strictEqual((await v2Db.all(`SELECT * FROM vm_logs WHERE vm_id = 1`)).length, 0);
      assert.strictEqual((await v2Db.all(`SELECT * FROM vm_snapshots WHERE vm_id = 1`)).length, 0);

      const lxcCols = await v2Db.all(`PRAGMA table_info(lxc_instances)`);
      assert.ok(lxcCols.some((c) => c.name === 'kvm_nesting'), 'Expected kvm_nesting column on lxc_instances');

      const adminUser = await v2Db.get(`SELECT * FROM users WHERE username = 'admin'`);
      assert.ok(adminUser, 'Legacy admin user preserved');
      assert.strictEqual(adminUser.email, 'admin@shadowgamerind.local', 'Expected default email rebranded to ShadowGamerIND');
      const siteNameSetting = await v2Db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_name'`);
      assert.strictEqual(siteNameSetting.setting_value, 'TGVPANEL', 'Expected legacy site_name HKVM migrated to TGVPANEL');
      const panelTitleSetting = await v2Db.get(`SELECT setting_value FROM settings WHERE setting_key = 'panel_title'`);
      assert.strictEqual(panelTitleSetting.setting_value, 'TGVPANEL V3.0', 'Expected legacy panel_title migrated to TGVPANEL V3.0');
      const maintMsgSetting = await v2Db.get(`SELECT setting_value FROM settings WHERE setting_key = 'maintenance_message'`);
      assert.ok(maintMsgSetting.setting_value.startsWith('TGVPANEL'), 'Expected maintenance_message branded as TGVPANEL');
      const templates = await v2Db.all(`SELECT * FROM lxc_templates`);
      assert.ok(templates.length >= 15, 'Seeded LXC OS template catalog');
      await v2Db.close();

      // Verify automatic zero-data-loss file migration: hkvm.db (+ -wal/-shm) -> tgvpanel.db (+ -wal/-shm)
      const legacyDbDir = path.join(tmpRoot, 'legacy-db-migration-check');
      fs.mkdirSync(legacyDbDir, { recursive: true });
      fs.writeFileSync(path.join(legacyDbDir, 'hkvm.db'), 'sqlite-main-bytes');
      fs.writeFileSync(path.join(legacyDbDir, 'hkvm.db-wal'), 'sqlite-wal-bytes');
      fs.writeFileSync(path.join(legacyDbDir, 'hkvm.db-shm'), 'sqlite-shm-bytes');
      const resolvedMigratedDb = resolveAndMigrateDatabasePath(legacyDbDir);
      assert.strictEqual(resolvedMigratedDb, path.join(legacyDbDir, 'tgvpanel.db'));
      assert.strictEqual(fs.readFileSync(path.join(legacyDbDir, 'tgvpanel.db'), 'utf8'), 'sqlite-main-bytes');
      assert.strictEqual(fs.readFileSync(path.join(legacyDbDir, 'tgvpanel.db-wal'), 'utf8'), 'sqlite-wal-bytes');
      assert.strictEqual(fs.readFileSync(path.join(legacyDbDir, 'tgvpanel.db-shm'), 'utf8'), 'sqlite-shm-bytes');
      assert.strictEqual(fs.existsSync(path.join(legacyDbDir, 'hkvm.db')), false, 'Expected legacy hkvm.db renamed');
      assert.strictEqual(fs.existsSync(path.join(legacyDbDir, 'hkvm.db-wal')), false, 'Expected legacy hkvm.db-wal renamed');
      assert.strictEqual(fs.existsSync(path.join(legacyDbDir, 'hkvm.db-shm')), false, 'Expected legacy hkvm.db-shm renamed');

      // Ensure testDbPath also has all migrations applied cleanly
      const rawSqlite = new sqlite3.Database(testDbPath);
      const udb = new UnifiedDatabase(rawSqlite, testDbPath);
      await runMigrations(udb);
      await udb.close();
    });

    // 2. Cryptographic Vault & API Key Hashing
    await runStep('T02: Secret vault (.tgvpanel-secret + legacy .hkvm-secret migration), AES-256-GCM & tamper rejection', async () => {
      const legacyVaultFile = path.join(tmpRoot, '.hkvm-secret');
      const bundle = getSecretBundle();
      assert.strictEqual(bundle.sessionSecret, seededLegacySessionSecret, 'Expected legacy .hkvm-secret secrets preserved');
      assert.ok(getSecretVaultPath().endsWith('.tgvpanel-secret'), 'Expected .tgvpanel-secret vault path');
      assert.strictEqual(fs.existsSync(getSecretVaultPath()), true, 'Expected .tgvpanel-secret to exist');
      assert.strictEqual(fs.existsSync(legacyVaultFile), false, 'Expected legacy .hkvm-secret renamed to .tgvpanel-secret');
      const ct = encryptSecret('super-secret-kvm-pass-99!');
      assert.ok(isEncryptedSecret(ct));
      assert.strictEqual(decryptSecret(ct), 'super-secret-kvm-pass-99!');
      const tampered = ct.slice(0, -4) + 'ffff';
      assert.strictEqual(decryptSecret(tampered), '', 'Tampered GCM ciphertext must never return plaintext');

      const apiKey = generateApiKeyPair('hkvm');
      assert.ok(apiKey.rawKey.startsWith('hkvm_'));
      assert.strictEqual(hashApiKey(apiKey.rawKey), apiKey.keyHash);
    });

    // 3. Boot full HKVM V3 Express + WebSocket Server
    app = require('../app');
    await app.hkvmReadyPromise;
    await new Promise((r) => setTimeout(r, 250));
    const baseUrl = `http://127.0.0.1:${TEST_PORT}`;
    const ctx = app.getHkvmV3Context();
    assert.ok(ctx, 'HKVM V3 context initialized');

    const bcrypt = require('bcryptjs');
    await ctx.db.run(`UPDATE users SET password = ? WHERE username = 'admin'`, [
      bcrypt.hashSync('AdminTestPass!2026', 10),
    ]);

    // 4. Legacy HVM V9 Importer + Transparent Werkzeug Password Upgrade
    await runStep('T03: Legacy HVM V9 importer (Werkzeug pbkdf2:sha256 + nodes + LXC + port forwards) & login rehash', async () => {
      const legacyDbFile = path.join(tmpRoot, 'legacy_hvm_v9.db');
      const ldb = new sqlite3.Database(legacyDbFile);
      const execSql = (sql, params = []) =>
        new Promise((res, rej) => ldb.run(sql, params, (e) => (e ? rej(e) : res())));

      await execSql(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password_hash TEXT, is_admin INTEGER)`);
      await execSql(`CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT, url TEXT, api_key TEXT, location TEXT, status TEXT)`);
      await execSql(`CREATE TABLE vps (id INTEGER PRIMARY KEY, container_name TEXT, hostname TEXT, user_id INTEGER, node_id INTEGER, cpu INTEGER, ram INTEGER, disk INTEGER, ip_address TEXT, os_image TEXT, status TEXT, suspended INTEGER)`);
      await execSql(`CREATE TABLE port_forwards (id INTEGER PRIMARY KEY, vps_id INTEGER, protocol TEXT, host_port INTEGER, container_port INTEGER)`);

      const wkHash = makeWerkzeugPbkdf2Hash('LegacyHvmPass#42');
      await execSql(`INSERT INTO users VALUES (10, 'hvm_alice', 'alice@example.org', ?, 0)`, [wkHash]);
      await execSql(`INSERT INTO nodes VALUES (2, 'eu-fra-lxc-1', 'https://10.99.0.10:8443', 'old-plaintext-node-key', 'Frankfurt', 'online')`);
      await execSql(`INSERT INTO vps VALUES (5, 'ct-alice-01', 'alice-web', 10, 2, 2, 2048, 25, '10.0.3.55', 'ubuntu:24.04', 'stopped', 0)`);
      await execSql(`INSERT INTO port_forwards VALUES (1, 5, 'tcp', 22055, 22)`);
      await new Promise((res) => ldb.close(() => res()));

      const report = await importHvmDatabase(ctx.db, legacyDbFile);
      assert.strictEqual(report.usersCreated, 1);
      assert.strictEqual(report.nodesImported, 1);
      assert.strictEqual(report.vpsImported, 1);

      const nodeCred = await ctx.db.get(
        `SELECT nc.api_key_enc FROM node_credentials nc JOIN nodes n ON n.id = nc.node_id WHERE n.name = 'eu-fra-lxc-1'`
      );
      assert.ok(nodeCred && isEncryptedSecret(nodeCred.api_key_enc));

      const aliceClient = new SessionClient(baseUrl);
      const loginRes = await aliceClient.request('POST', '/api/login', {
        username: 'hvm_alice',
        password: 'LegacyHvmPass#42',
      });
      assert.strictEqual(loginRes.status, 200);
      assert.strictEqual(loginRes.json.success, true);

      const aliceRow = await ctx.db.get(`SELECT password FROM users WHERE username = 'hvm_alice'`);
      assert.ok(aliceRow.password.startsWith('$2'), 'Expected upgraded bcrypt hash');
    });

    // 5. Session Auth, CSRF Enforcement & Scoped API Keys
    const adminClient = new SessionClient(baseUrl);
    let scopedApiKeyRaw = '';
    await runStep('T04: Admin login, CSRF token protection on mutations & scoped Bearer API keys', async () => {
      const login = await adminClient.request('POST', '/api/login', {
        username: 'admin',
        password: 'AdminTestPass!2026',
      });
      assert.strictEqual(login.status, 200);

      const dash = await adminClient.request('GET', '/admin/instances');
      assert.strictEqual(dash.status, 200);
      assert.ok(adminClient.csrfToken.length > 20, 'Extracted CSRF token from EJS header');

      // Attempt POST /api/v1/api-keys WITHOUT CSRF token -> must reject 403!
      const savedCsrf = adminClient.csrfToken;
      adminClient.csrfToken = '';
      const blocked = await adminClient.request('POST', '/api/v1/api-keys', { name: 'should-fail' });
      assert.strictEqual(blocked.status, 403, 'Expected 403 CSRF rejection without token');

      // Restore CSRF token -> succeeds!
      adminClient.csrfToken = savedCsrf;
      const createdKey = await adminClient.request('POST', '/api/v1/api-keys', {
        name: 'ci-automation-key',
        permissions: ['read', 'write', 'admin'],
      });
      assert.strictEqual(createdKey.status, 201, `API key create failed: ${createdKey.text}`);
      assert.ok(createdKey.json.rawApiKey.startsWith('hkvm_pat_'));
      scopedApiKeyRaw = createdKey.json.rawApiKey;

      // Stateless API key call without cookies or CSRF succeeds!
      const apiClient = new SessionClient(baseUrl);
      const apiInstances = await apiClient.request('GET', '/api/v1/instances', undefined, {
        Authorization: `Bearer ${scopedApiKeyRaw}`,
      });
      assert.strictEqual(apiInstances.status, 200);
      assert.ok(Array.isArray(apiInstances.json.instances));
    });

    // 6. TOTP 2FA End-to-End Flow
    await runStep('T05: RFC 6238 TOTP 2FA setup, QR provisioning & 2-step login verification', async () => {
      const userClient = new SessionClient(baseUrl);
      await userClient.request('POST', '/api/login', {
        username: 'hvm_alice',
        password: 'LegacyHvmPass#42',
      });
      const secPage = await userClient.request('GET', '/security');
      assert.strictEqual(secPage.status, 200);

      const setup = await userClient.request('POST', '/api/v1/auth/2fa/setup', {});
      assert.strictEqual(setup.status, 200, `2FA setup failed: ${setup.text}`);
      assert.ok(setup.json.qrDataUrl.startsWith('data:image/png;base64,'));
      assert.ok(setup.json.otpauthUrl.includes('issuer=TGVPANEL'), 'Expected TOTP issuer=TGVPANEL');
      const secret = setup.json.secret;
      const validCode = computeTotpCode(secret);
      assert.strictEqual(verifyTotpCode(secret, validCode), true);

      const verify = await userClient.request('POST', '/api/v1/auth/2fa/enable', { code: validCode });
      assert.strictEqual(verify.status, 200, `2FA enable failed: ${verify.text}`);

      const freshAlice = new SessionClient(baseUrl);
      const step1 = await freshAlice.request('POST', '/api/login', {
        username: 'hvm_alice',
        password: 'LegacyHvmPass#42',
      });
      assert.strictEqual(step1.status, 200);
      assert.strictEqual(step1.json.requires2FA, true);
      assert.strictEqual(step1.json.redirectTo, '/login/2fa');

      const premature = await freshAlice.request('GET', '/api/v1/instances');
      assert.strictEqual(premature.status, 401);

      const step2 = await freshAlice.request('POST', '/api/login/2fa', {
        code: computeTotpCode(secret),
      });
      assert.strictEqual(step2.status, 200);
      assert.strictEqual(step2.json.success, true);

      const postAuth = await freshAlice.request('GET', '/api/v1/instances');
      assert.strictEqual(postAuth.status, 200);
    });

    // 7. RBAC, Non-Admin Ownership Fixes & VPS Sharing
    await runStep('T06: RBAC enforcement, KVM V2 ownership bugfixes & VPS sharing permissions', async () => {
      const insVm = await ctx.db.run(
        `INSERT INTO vms (vm_name, hostname, owner_id, memory, cpus, disk_size, status, password)
         VALUES ('admin-core-vm', 'admin-core', 1, 2048, 2, '20G', 'stopped', ?)`,
        [encryptSecret('KvmSecretPass!')]
      );
      const adminVmId = insVm.lastID;
      await ctx.kvmAdapter.syncRegistryRow(adminVmId);

      await ctx.db.run(
        `INSERT INTO users (username, password, email, role, is_active) VALUES ('bob_user', ?, 'bob@example.org', 'user', 1)`,
        [bcrypt.hashSync('BobPass!123', 10)]
      );
      const bobRow = await ctx.db.get(`SELECT id FROM users WHERE username = 'bob_user'`);

      const bobClient = new SessionClient(baseUrl);
      await bobClient.request('POST', '/api/login', { username: 'bob_user', password: 'BobPass!123' });
      await bobClient.request('GET', '/instances');

      assert.strictEqual((await bobClient.request('GET', '/api/v1/nodes')).status, 403);
      assert.strictEqual((await bobClient.request('GET', `/api/vms/${adminVmId}/edit`)).status, 403);
      assert.strictEqual((await bobClient.request('GET', `/api/vms/${adminVmId}/logs`)).status, 403);
      assert.strictEqual((await bobClient.request('GET', `/api/vms/${adminVmId}/stats`)).status, 403);
      assert.strictEqual((await bobClient.request('DELETE', `/api/vms/${adminVmId}`)).status, 403);

      const aliceLxc = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ct-alice-01'`);
      const shareRes = await adminClient.request('PUT', `/api/v1/lxc/${aliceLxc.id}/sharing`, {
        userIds: [bobRow.id],
      });
      assert.strictEqual(shareRes.status, 200, `Share failed: ${shareRes.text}`);

      const bobList = await bobClient.request('GET', '/api/v1/instances');
      assert.ok(
        bobList.json.instances.some((i) => i.engine === 'lxc' && i.refId === aliceLxc.id),
        'Shared LXC visible to Bob'
      );
    });

    // 8. Standalone Node Agent + HMAC Auth + Replay Defense
    await runStep('T07: Standalone Node Agent HTTP/HMAC server, capability sync & replay rejection', async () => {
      const regRes = await adminClient.request('POST', '/api/v1/nodes', {
        name: 'local-loopback-agent',
        hostname: '127.0.0.1',
        ipAddress: '127.0.0.1',
        url: `http://127.0.0.1:${AGENT_PORT}`,
        location: 'Loopback DC',
        verifySsl: false,
      });
      assert.strictEqual(regRes.status, 201, `Node register failed: ${regRes.text}`);
      remoteNodeId = regRes.json.node.id;
      const { apiKey, hmacSecret } = regRes.json.bootstrapCredentials;

      const agentInst = createNodeAgentServer({
        host: '127.0.0.1',
        port: AGENT_PORT,
        nodeId: 'local-loopback-agent',
        apiKey,
        hmacSecret,
        lxcBaseDir: path.join(tmpRoot, 'agent-lxc'),
        backupDir: path.join(tmpRoot, 'agent-backups'),
      });
      agentServer = agentInst.server;
      await new Promise((resolve) => agentServer.listen(AGENT_PORT, '127.0.0.1', resolve));

      const syncRes = await adminClient.request('POST', `/api/v1/nodes/${remoteNodeId}/check`, {});
      assert.strictEqual(syncRes.status, 200, `Node check failed: ${syncRes.text}`);

      // Test replay attack rejection directly against standalone Node Agent!
      const signedHeaders = signAgentRequest({
        nodeId: 'local-loopback-agent',
        apiKey,
        hmacSecret,
        method: 'GET',
        pathWithQuery: '/api/v1/health',
      });
      const callAgent = () =>
        new Promise((resolve, reject) => {
          const r = http.request(
            {
              hostname: '127.0.0.1',
              port: AGENT_PORT,
              path: '/api/v1/health',
              method: 'GET',
              headers: signedHeaders,
            },
            (res) => resolve(res.statusCode)
          );
          r.on('error', reject);
          r.end();
        });
      assert.strictEqual(await callAgent(), 200, 'First signed request accepted');
      assert.strictEqual(await callAgent(), 409, 'Replayed nonce rejected with 409 Conflict');
    });

    // 9. Unified Virtualization Capabilities, Telemetry & Honest Binary Checks
    await runStep('T08: Unified Virtualization Manager, Linux /proc telemetry & honest hypervisor checks', async () => {
      const kvmCap = ctx.kvmAdapter.getCapabilityProfile();
      const lxcCap = ctx.lxcAdapter.getCapabilityProfile();
      assert.strictEqual(kvmCap.supportsFreeze, false);
      assert.strictEqual(lxcCap.supportsFreeze, true);

      const vm = await ctx.db.get(`SELECT vm_id FROM vms LIMIT 1`);
      await ctx.db.run(`UPDATE vms SET pid = ?, status = 'running' WHERE vm_id = ?`, [
        process.pid,
        vm.vm_id,
      ]);
      const tel = await ctx.kvmAdapter.getTelemetry(vm.vm_id);
      assert.strictEqual(tel.pid, process.pid);
      assert.ok(tel.ramUsedMb > 10, `Expected real RSS > 10MB from /proc/${process.pid}/status`);
      await ctx.db.run(`UPDATE vms SET pid = NULL, status = 'stopped' WHERE vm_id = ?`, [vm.vm_id]);

      const freezeKvm = await adminClient.request('POST', `/api/v1/instances/kvm/${vm.vm_id}/action`, {
        action: 'freeze',
      });
      assert.strictEqual(freezeKvm.status, 400);
      assert.match(freezeKvm.json.error, /only supported for LXC/i);
    });

    // 10. Rootfs Path Traversal Defense & Command Runner Allowlist
    await runStep('T09: Container rootfs traversal confinement & command-runner allowlist enforcement', async () => {
      await assert.rejects(
        () => runAllowlistedCommand('bash', ['-c', 'id']),
        /not in the allowlist/i
      );
      await assert.rejects(
        () => runAllowlistedCommand('sudo', ['-n', 'id']),
        /not in the allowlist/i
      );
      await assert.rejects(
        () => runAllowlistedCommand('rm', ['-rf', '/tmp/x']),
        /not in the allowlist/i
      );
      await assert.rejects(
        () => runAllowlistedCommand('uname', ['-a\0evil']),
        /Null byte|invalid/i
      );

      // Regression guard for liblxc "//.local/" permission denied bug when HOME was missing or "/"
      const rootEnv = buildSafeSpawnEnv(true, { HOME: '/' });
      assert.strictEqual(rootEnv.HOME, '/root');
      assert.strictEqual(rootEnv.USER, 'root');
      const userEnv = buildSafeSpawnEnv(false, { HOME: '/' });
      assert.notStrictEqual(userEnv.HOME, '/');
      assert.ok(userEnv.HOME && userEnv.HOME.startsWith('/'));

      // Verify images.linuxcontainers.org release codename normalization
      assert.strictEqual(resolveDownloadReleaseCandidates('ubuntu', '24.04').releases[0], 'noble');
      assert.strictEqual(resolveDownloadReleaseCandidates('ubuntu', '22.04').releases[0], 'jammy');
      assert.strictEqual(resolveDownloadReleaseCandidates('debian', '12').releases[0], 'bookworm');
      assert.strictEqual(resolveDownloadReleaseCandidates('kali', 'rolling').releases[0], 'current');
      assert.strictEqual(resolveDownloadReleaseCandidates('centos', '9').releases[0], '9-Stream');

      const fakeLxcBase = path.join(tmpRoot, 'lxc-jail');
      const ctDir = path.join(fakeLxcBase, 'ct-jail-test');
      const ctRoot = path.join(ctDir, 'rootfs');
      fs.mkdirSync(path.join(ctRoot, 'etc'), { recursive: true });
      fs.writeFileSync(path.join(ctRoot, 'etc', 'hostname'), 'ct-jail-test\n');
      fs.writeFileSync(
        path.join(ctDir, 'config'),
        'lxc.rootfs.path = dir:' + ctRoot + '\nlxc.net.0.type = veth\nlxc.net.0.link = oldbr0\nlxc.apparmor.profile = generated\n'
      );

      const cm = new LxcContainerManager(fakeLxcBase);
      await cm.writeManagedConfigSection('ct-jail-test', {
        hostname: 'ct-jail-test',
        cpuCores: 2,
        ramMb: 1024,
        swapMb: 512,
        nesting: true,
        bridge: 'lxcbr0',
      });
      const updatedCfg = fs.readFileSync(path.join(ctDir, 'config'), 'utf8');
      assert.ok(!updatedCfg.includes('oldbr0'), 'Stale template lxc.net.0.link should be stripped');
      assert.ok(updatedCfg.includes('lxc.net.0.link = lxcbr0'));
      assert.strictEqual(
        (updatedCfg.match(/lxc\.apparmor\.profile\s*=/g) || []).length,
        1,
        'Should contain exactly one authoritative lxc.apparmor.profile directive'
      );

      const listing = cm.listRootfsDirectory('ct-jail-test', '/etc');
      assert.ok(listing.some((e) => e.name === 'hostname'));

      assert.throws(
        () => cm.readRootfsFile('ct-jail-test', '/../../../etc/passwd'),
        /traversal|escapes|outside|ENOENT/i
      );
    });

    // 11. Storage, Templates, Networking, IPv4/IPv6 Pools, Ports & Firewall
    await runStep('T10: Storage pools, LXC template catalog, Network IP pools, Port forwards & Firewall', async () => {
      const pools = await adminClient.request('GET', '/api/v1/storage/pools');
      assert.strictEqual(pools.status, 200);
      assert.ok(pools.json.pools.length >= 2);

      const tplRes = await adminClient.request('POST', '/api/v1/lxc/templates', {
        slug: 'alpine-3-20-custom',
        name: 'Alpine 3.20 Minimal Custom',
        distro: 'alpine',
        release: '3.20',
      });
      assert.ok(tplRes.status === 200 || tplRes.status === 201, `Template create failed: ${tplRes.text}`);

      const netPool = await adminClient.request('POST', '/api/v1/network/pools', {
        nodeId: 1,
        name: 'hkvm-nat-net',
        networkType: 'nat',
        bridgeName: 'lxcbr0',
        cidr: '10.88.10.0/29',
        gateway: '10.88.10.1',
      });
      assert.strictEqual(netPool.status, 201, `Net pool failed: ${netPool.text}`);

      const addIps = await adminClient.request(
        'POST',
        `/api/v1/network/pools/${netPool.json.pool.id}/ips`,
        { ips: ['10.88.10.2', '10.88.10.3'] }
      );
      assert.strictEqual(addIps.status, 200);

      const listPools = await adminClient.request('GET', '/api/v1/network/pools');
      assert.strictEqual(listPools.status, 200);
      assert.ok(listPools.json.ips.some((i) => i.ip_address === '10.88.10.2'));

      const aliceLxc = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ct-alice-01'`);
      const portAlloc = await adminClient.request('POST', '/api/v1/network/ports', {
        instanceType: 'lxc',
        instanceRefId: aliceLxc.id,
        hostPort: 30443,
        guestPort: 443,
        protocol: 'tcp',
        description: 'HTTPS Ingress',
      });
      assert.strictEqual(portAlloc.status, 201, `Port alloc failed: ${portAlloc.text}`);

      const fwRes = await adminClient.request('POST', '/api/v1/network/firewall', {
        nodeId: 1,
        direction: 'in',
        action: 'ACCEPT',
        protocol: 'tcp',
        sourceCidr: '0.0.0.0/0',
        destPort: '8080',
        comment: 'Allow Panel HTTP',
      });
      assert.strictEqual(fwRes.status, 201, `Firewall rule failed: ${fwRes.text}`);
    });

    // 12. Backups SHA-256, Monitoring, Alerts, Audit Logs & Impersonation
    await runStep('T11: KVM QCOW2 disk backup + SHA-256 verify, Monitoring poll, Audit & Impersonation', async () => {
      const vm = await ctx.db.get(`SELECT vm_id FROM vms LIMIT 1`);
      const dummyDisk = path.join(tmpRoot, `vm-${vm.vm_id}-disk.qcow2`);
      fs.writeFileSync(dummyDisk, crypto.randomBytes(65536));
      await ctx.db.run(`UPDATE vms SET disk_file = ? WHERE vm_id = ?`, [dummyDisk, vm.vm_id]);

      const bkRes = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'kvm',
        refId: vm.vm_id,
      });
      assert.strictEqual(bkRes.status, 201, `Backup failed: ${bkRes.text}`);
      const bkId = bkRes.json.backup.backupId || bkRes.json.backup.id;
      assert.strictEqual(bkRes.json.backup.checksumSha256.length, 64);

      const verRes = await adminClient.request('POST', `/api/v1/backups/${bkId}/verify`, {});
      assert.strictEqual(verRes.status, 200, `Verify failed: ${verRes.text}`);
      assert.strictEqual(verRes.json.valid, true);

      await ctx.monitoringService.collectCycle();
      const monRes = await adminClient.request('GET', '/api/v1/monitoring/overview');
      assert.strictEqual(monRes.status, 200);
      assert.ok(monRes.json.nodeMetrics.length >= 1);

      const bobRow = await ctx.db.get(`SELECT id FROM users WHERE username = 'bob_user'`);
      const impStart = await adminClient.request(
        'POST',
        `/api/v1/auth/impersonate/${bobRow.id}`,
        {}
      );
      assert.strictEqual(impStart.status, 200, `Impersonate failed: ${impStart.text}`);

      await adminClient.request('GET', '/instances');
      const impStop = await adminClient.request('POST', '/api/v1/auth/stop-impersonation', {});
      assert.strictEqual(impStop.status, 200, `Stop impersonate failed: ${impStop.text}`);

      const logs = await adminClient.request('GET', '/api/v1/audit-logs');
      assert.strictEqual(logs.status, 200);
      assert.ok(logs.json.logs.length > 0);
    });

    // 13. All 23 Admin Pages + User Pages + Authenticated WebSocket Node PTY Shell
    await runStep('T12: All 23 Admin Sidebar EJS views, User EJS views & real node-pty WebSocket Admin Shell', async () => {
      await adminClient.request('GET', '/admin/instances');
      const adminPages = [
        '/admin/dashboard',
        '/admin/instances',
        '/admin/vms',
        '/admin/lxc',
        '/admin/instances/create',
        '/admin/nodes',
        '/admin/storage',
        '/admin/isos',
        '/admin/templates',
        '/admin/lxc-templates',
        '/admin/networking',
        '/admin/ports',
        '/admin/firewall',
        '/admin/snapshots',
        '/admin/backups',
        '/admin/migrations',
        '/admin/monitoring',
        '/admin/users',
        '/admin/api-keys',
        '/admin/audit-logs',
        '/admin/node-console',
        '/admin/license',
        '/admin/settings',
      ];
      for (const p of adminPages) {
        const r = await adminClient.request('GET', p);
        assert.strictEqual(r.status, 200, `Expected 200 OK on admin route ${p}, got ${r.status}`);
        assert.ok(r.text.includes('TGVPANEL'), `Expected TGVPANEL branding on admin route ${p}`);
        assert.ok(!/HKVM\s*PANEL/i.test(r.text), `Unexpected visible HKVM Panel branding on admin route ${p}`);
      }

      const healthRes = await adminClient.request('GET', '/api/v1/health');
      assert.strictEqual(healthRes.status, 200);
      assert.strictEqual(healthRes.json.panel, 'TGVPANEL', 'Expected /api/v1/health panel === TGVPANEL');

      const unauthLogin = await new SessionClient(baseUrl).request('GET', '/login');
      assert.strictEqual(unauthLogin.status, 200);
      assert.ok(unauthLogin.text.includes('TGVPANEL'), 'Expected TGVPANEL branding on /login');
      assert.ok(!/HKVM\s*PANEL/i.test(unauthLogin.text), 'Unexpected HKVM Panel branding on /login');

      const aliceLxc = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ct-alice-01'`);
      const userPages = ['/dashboard', '/instances', '/lxc', `/lxc/${aliceLxc.id}`, `/lxc/${aliceLxc.id}/console`, '/ports', '/security', '/profile'];
      for (const p of userPages) {
        const r = await adminClient.request('GET', p);
        assert.strictEqual(r.status, 200, `Expected 200 OK on user route ${p}, got ${r.status}`);
        assert.ok(r.text.includes('TGVPANEL'), `Expected TGVPANEL branding on user route ${p}`);
        assert.ok(!/HKVM\s*PANEL/i.test(r.text), `Unexpected visible HKVM Panel branding on user route ${p}`);
      }

      await new Promise((resolve, reject) => {
        const unauthWs = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/ws/nodes/1/shell`);
        unauthWs.on('unexpected-response', (_req, res) => {
          assert.strictEqual(res.statusCode, 401);
          resolve();
        });
        unauthWs.on('open', () => reject(new Error('Unauthenticated WS should not open')));
        unauthWs.on('error', () => resolve());
      });

      const ptyOutput = await new Promise((resolve, reject) => {
        let buf = '';
        const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/ws/nodes/1/shell`, {
          headers: { Cookie: adminClient.cookie },
        });
        const timer = setTimeout(() => {
          ws.close();
          reject(new Error(`Timed out waiting for PTY output. Got so far: ${buf}`));
        }, 6000);
        ws.on('open', () => {
          setTimeout(() => {
            ws.send(JSON.stringify({ type: 'input', data: 'uname\n' }));
          }, 250);
        });
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'output') {
              buf += msg.data;
              if (buf.includes('Linux')) {
                clearTimeout(timer);
                ws.close();
                resolve(buf);
              }
            }
          } catch (_) {}
        });
        ws.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      assert.ok(ptyOutput.includes('Linux'), `Expected Linux in PTY output, got: ${ptyOutput}`);

      // Also verify Safe Diagnostic Preset API + redesigned Node Console Studio UI
      const ncHtmlRes = await adminClient.request('GET', '/admin/node-console');
      assert.strictEqual(ncHtmlRes.status, 200);
      assert.ok(ncHtmlRes.text.includes('nc-workbench'), 'Expected redesigned Node Console Workbench');
      assert.ok(ncHtmlRes.text.includes('nc-telemetry-grid'), 'Expected live 4-card Node Telemetry Strip');
      assert.ok(ncHtmlRes.text.includes('runNodeHealthSuite'), 'Expected 7-point Full Health Check button');

      const diagRes = await adminClient.request('POST', '/api/v1/nodes/1/diagnostics/uname', {});
      assert.strictEqual(diagRes.status, 200, `Diag preset failed: ${diagRes.text}`);
      assert.strictEqual(diagRes.json.command, 'uname -a');
      assert.strictEqual(typeof diagRes.json.durationMs, 'number');

      const sysctlDiag = await adminClient.request('POST', '/api/v1/nodes/1/diagnostics/sysctl_net', {});
      assert.strictEqual(sysctlDiag.status, 200, `sysctl_net diag failed: ${sysctlDiag.text}`);
      assert.strictEqual(sysctlDiag.json.command, 'sysctl net.ipv4.ip_forward');

      // Verify upgraded Nodes, Storage, Monitoring & License Studio views + live statfs/sample behavior
      const [nodesHtml, storageHtml, monHtml, licHtml] = await Promise.all([
        adminClient.request('GET', '/admin/nodes'),
        adminClient.request('GET', '/admin/storage'),
        adminClient.request('GET', '/admin/monitoring'),
        adminClient.request('GET', '/admin/license'),
      ]);
      assert.strictEqual(nodesHtml.status, 200);
      assert.ok(nodesHtml.text.includes('nodesKpiGrid'), 'Expected Nodes KPI Strip');
      assert.strictEqual(storageHtml.status, 200);
      assert.ok(storageHtml.text.includes('storageKpiGrid'), 'Expected Storage KPI Strip');
      assert.strictEqual(monHtml.status, 200);
      assert.ok(monHtml.text.includes('monChartCompute'), 'Expected Monitoring SVG Telemetry Charts');
      assert.strictEqual(licHtml.status, 200);
      assert.ok(licHtml.text.includes('lic-hero-banner'), 'Expected License Edition Hero Banner');

      const syncPoolsRes = await adminClient.request('GET', '/api/v1/storage/pools?sync=1');
      assert.strictEqual(syncPoolsRes.status, 200);
      const localKvmPool = (syncPoolsRes.json.pools || []).find((p) => p.name === 'local-kvm');
      assert.ok(localKvmPool && Number(localKvmPool.total_bytes) > 0, 'Expected non-zero statfs capacity on local-kvm pool');

      const beforeSamples = await adminClient.request('GET', '/api/v1/nodes/1/metrics?hours=1');
      await adminClient.request('POST', '/api/v1/nodes/1/check', {});
      const afterSamples = await adminClient.request('GET', '/api/v1/nodes/1/metrics?hours=1');
      assert.ok(
        (afterSamples.json.history || []).length >= (beforeSamples.json.history || []).length + 1,
        'Expected POST /api/v1/nodes/1/check to record an immediate telemetry sample'
      );
    });

    // 14. End-to-End LXC VPS Provisioning, Root-Owned Confinement, Lifecycle, Resize, Credentials & Host Sync
    let e2eUbuntuId = null;
    let e2eCustomId = null;
    let e2eOrphanId = null;
    await runStep('T13: End-to-end LXC VPS creation (template + custom archive + orphan/cgroup/GPG + sync-host), 0700 rootfs & full operations', async () => {
      const { execFileSync } = require('child_process');
      const { canPasswordlessSudo, privilegedFs } = require('../lib/node-agent/command-runner');

      // 13a. Honest host guard BEFORE LXC binaries exist on host: must fail cleanly AND roll back DB row
      const nativeLxcPresent =
        fs.existsSync('/usr/bin/lxc-create') || fs.existsSync('/usr/local/bin/lxc-create');
      if (!nativeLxcPresent) {
        const failProv = await adminClient.request('POST', '/api/v1/lxc', {
          containerName: 'unshimmed-guard-ct',
          templateSlug: 'ubuntu:24.04',
          cpuCores: 1,
          ramMb: 512,
          diskGb: 10,
          provisionOnHost: true,
        });
        assert.strictEqual(failProv.status, 500, 'Expected honest 500 when lxc-* is absent');
        assert.match(failProv.json.error, /not installed/i);
        const zombieRow = await ctx.db.get(
          `SELECT id FROM lxc_instances WHERE container_name = 'unshimmed-guard-ct'`
        );
        assert.strictEqual(zombieRow, undefined, 'Failed host provisioning must roll back DB row');

        const metaOnly = await adminClient.request('POST', '/api/v1/lxc', {
          containerName: 'meta-only-ct',
          templateSlug: 'ubuntu:24.04',
          cpuCores: 1,
          ramMb: 512,
          diskGb: 10,
          provisionOnHost: false,
        });
        assert.strictEqual(metaOnly.status, 201, `Meta-only LXC failed: ${metaOnly.text}`);
        assert.strictEqual(metaOnly.json.instance.status, 'stopped');
        const delMeta = await adminClient.request(
          'POST',
          `/api/v1/instances/lxc/${metaOnly.json.instance.refId}/action`,
          { action: 'delete' }
        );
        assert.strictEqual(delMeta.status, 200);
      }

      // 13b. Real 0700 root:root container directory confinement + multi-level & broken symlink escape blocking
      if (canPasswordlessSudo() && process.getuid && process.getuid() !== 0) {
        const rootJail = path.join(tmpRoot, 'root-owned-lxc-0700');
        rootOwnedCleanupDirs.push(rootJail);
        const ctRootfs = path.join(rootJail, 'ct-root-jail', 'rootfs');
        execFileSync('sudo', ['-n', 'mkdir', '-p', `${ctRootfs}/etc`, `${ctRootfs}/root`, `${ctRootfs}/tmp`]);
        execFileSync('sudo', ['-n', 'tee', `${ctRootfs}/etc/hostname`], { input: 'ct-root-jail\n' });
        execFileSync('sudo', ['-n', 'tee', `${ctRootfs}/etc/shadow`], {
          input: 'root:*:19000:0:99999:7:::\n',
        });
        execFileSync('sudo', ['-n', 'tee', `${rootJail}/ct-root-jail/config`], {
          input: `lxc.rootfs.path = dir:${ctRootfs}\nlxc.uts.name = ct-root-jail\n`,
        });
        execFileSync('sudo', ['-n', 'ln', '-s', '/etc', `${ctRootfs}/tmp/escape_dir`]);
        execFileSync('sudo', ['-n', 'ln', '-s', '/etc/nonexistent_host_secret_xyz', `${ctRootfs}/tmp/broken_sym`]);
        execFileSync('sudo', ['-n', 'chmod', '0700', rootJail]);

        assert.throws(() => fs.readdirSync(rootJail), /EACCES|EPERM/);

        const rootCm = new LxcContainerManager(rootJail);
        const etcList = rootCm.listRootfsDirectory('ct-root-jail', '/etc');
        assert.ok(etcList.some((e) => e.name === 'hostname'), 'privilegedFs listed 0700 root:root /etc');
        assert.strictEqual(
          rootCm.readRootfsFile('ct-root-jail', '/etc/hostname').toString('utf8').trim(),
          'ct-root-jail'
        );

        await rootCm.setRootPassword('ct-root-jail', 'RootOfflinePass!88');
        const shadowAfter = rootCm.readRootfsFile('ct-root-jail', '/etc/shadow').toString('utf8');
        assert.match(shadowAfter, /^root:\$6\$/m, 'Offline SHA-512 password written into 0700 /etc/shadow');

        await rootCm.injectSshPublicKey(
          'ct-root-jail',
          'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRootJailKeyTest00001 root@hkvm'
        );
        const authKeys = rootCm
          .readRootfsFile('ct-root-jail', '/root/.ssh/authorized_keys')
          .toString('utf8');
        assert.ok(authKeys.includes('IRootJailKeyTest00001'));

        // Multi-level intermediate symlink escape (<rootfs>/tmp/escape_dir -> /etc + nested new subdir) MUST fail!
        assert.throws(
          () => rootCm.writeRootfsFile('ct-root-jail', '/tmp/escape_dir/hkvm_never_create/pwn', 'x'),
          /Symlink escape/i
        );
        // Broken symlink escape MUST fail!
        assert.throws(
          () => rootCm.readRootfsFile('ct-root-jail', '/tmp/broken_sym'),
          /Symlink escape|not a regular file/i
        );
      }

      // 13c. Install stateful POSIX LXC test harness for any missing lxc-* binaries on sandbox host
      const shims = {
        'lxc-create': `#!/bin/sh
set -e
BASE="/var/lib/lxc"; NAME=""; DISTRO="ubuntu"; REL="noble"; NOVAL="0"
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
while [ $# -gt 0 ]; do
  case "$1" in
    -d) DISTRO="$2"; shift 2 ;;
    -r) REL="$2"; shift 2 ;;
    --no-validate) NOVAL="1"; shift ;;
    *) shift ;;
  esac
done
if [ "$DISTRO" = "gpgtest" ] && [ "$NOVAL" = "0" ]; then
  echo "ERROR: Unable to fetch GPG key from keyserver" >&2
  exit 1
fi
CT="$BASE/$NAME"
mkdir -p "$CT/rootfs/etc/netplan" "$CT/rootfs/etc/systemd" "$CT/rootfs/root" "$CT/rootfs/var/log" "$CT/rootfs/tmp"
printf '%s\\n' "$NAME" > "$CT/rootfs/etc/hostname"
printf 'ID=%s\\nVERSION_ID="%s"\\n' "$DISTRO" "$REL" > "$CT/rootfs/etc/os-release"
printf 'root:*:19000:0:99999:7:::\\n' > "$CT/rootfs/etc/shadow"
chmod 0640 "$CT/rootfs/etc/shadow"
ln -sf ../run/systemd/resolve/stub-resolv.conf "$CT/rootfs/etc/resolv.conf"
cat > "$CT/rootfs/etc/nsswitch.conf" <<EOF
passwd:         files systemd
group:          files systemd
hosts:          files resolve [!UNAVAIL=return] dns
networks:       files
EOF
cat > "$CT/rootfs/etc/netplan/10-lxc.yaml" <<EOF
network:
  version: 2
  ethernets:
    eth0: {dhcp4: true}
EOF
cat > "$CT/config" <<EOF
lxc.rootfs.path = dir:$CT/rootfs
lxc.uts.name = $NAME
lxc.net.0.type = veth
lxc.net.0.link = lxcbr0
lxc.apparmor.profile = generated
EOF
printf 'STOPPED\\n' > "$CT/.state"
`,
        'lxc-start': `#!/bin/sh
set -e
BASE="/var/lib/lxc"; NAME=""; LOG=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    -o) LOG="$2"; shift 2 ;;
    *) shift ;;
  esac
done
CT="$BASE/$NAME"
[ -f "$CT/config" ] || { echo "Container $NAME config missing" >&2; exit 1; }
if [ -f "$CT/.fail_cgroup_once" ] && grep -q "lxc.cgroup" "$CT/config"; then
  rm -f "$CT/.fail_cgroup_once"
  [ -n "$LOG" ] && printf 'lxc-start %s ERROR cgfsng - Failed to setup cgroup limits\\n' "$NAME" >> "$LOG"
  echo "lxc-start: $NAME: Failed to setup cgroup limits" >&2
  exit 1
fi
nohup sleep 300 >/dev/null 2>&1 </dev/null &
echo $! > "$CT/.pid"
printf 'RUNNING\\n' > "$CT/.state"
[ -n "$LOG" ] && printf 'lxc-start %s NOTICE start - Container started (pid=%s)\\n' "$NAME" "$(cat "$CT/.pid")" >> "$LOG"
exit 0
`,
        'lxc-stop': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    *) shift ;;
  esac
done
CT="$BASE/$NAME"
if [ -f "$CT/.pid" ]; then
  PID="$(cat "$CT/.pid" 2>/dev/null || true)"
  [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null || true
  rm -f "$CT/.pid"
fi
[ -d "$CT" ] && printf 'STOPPED\\n' > "$CT/.state"
exit 0
`,
        'lxc-freeze': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; -n) NAME="$2"; shift 2 ;; *) shift ;; esac
done
[ -f "$BASE/$NAME/config" ] || exit 1
printf 'FROZEN\\n' > "$BASE/$NAME/.state"
`,
        'lxc-unfreeze': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; -n) NAME="$2"; shift 2 ;; *) shift ;; esac
done
[ -f "$BASE/$NAME/config" ] || exit 1
printf 'RUNNING\\n' > "$BASE/$NAME/.state"
`,
        'lxc-destroy': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; -n) NAME="$2"; shift 2 ;; *) shift ;; esac
done
CT="$BASE/$NAME"
if [ -f "$CT/.pid" ]; then
  PID="$(cat "$CT/.pid" 2>/dev/null || true)"
  [ -n "$PID" ] && kill -KILL "$PID" 2>/dev/null || true
fi
[ -n "$NAME" ] && rm -rf "$CT"
exit 0
`,
        'lxc-ls': `#!/bin/sh
BASE="/var/lib/lxc"
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; *) shift ;; esac
done
[ -d "$BASE" ] || exit 0
for d in "$BASE"/*; do
  [ -f "$d/config" ] && basename "$d"
done
exit 0
`,
        'lxc-info': `#!/bin/sh
if [ "$1" = "--version" ]; then echo "5.0.3"; exit 0; fi
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; -n) NAME="$2"; shift 2 ;; *) shift ;; esac
done
CT="$BASE/$NAME"
[ -f "$CT/config" ] || exit 1
STATE="STOPPED"
[ -f "$CT/.state" ] && STATE="$(cat "$CT/.state" | tr -d '\\r\\n')"
PID=""
[ -f "$CT/.pid" ] && PID="$(cat "$CT/.pid" | tr -d '\\r\\n')"
if [ "$STATE" = "RUNNING" ] || [ "$STATE" = "FROZEN" ]; then
  if [ -z "$PID" ] || ! kill -0 "$PID" 2>/dev/null; then
    STATE="STOPPED"
    PID=""
  fi
fi
echo "Name:           $NAME"
echo "State:          $STATE"
if [ "$STATE" = "RUNNING" ] || [ "$STATE" = "FROZEN" ]; then
  echo "PID:            $PID"
  CFG_IP="$(grep -E '^[[:space:]]*lxc\\.net\\.0\\.ipv4\\.address' "$CT/config" 2>/dev/null | tail -n 1 | awk -F= '{print $2}' | tr -d ' ' | cut -d/ -f1)"
  echo "IP:             \${CFG_IP:-10.88.10.200}"
  if [ ! -f "$CT/.omit_mem_use" ]; then
    if [ ! -f "$CT/.omit_cpu_use" ]; then
      echo "CPU use:        1.35 seconds"
    fi
    echo "Memory use:     64.25 MiB"
  fi
  echo "TX bytes:       18.00 KiB"
  echo "RX bytes:       42.00 KiB"
fi
exit 0
`,
        'lxc-cgroup': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""; KEY=""; VAL=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    *) if [ -z "$KEY" ]; then KEY="$1"; else VAL="$1"; fi; shift ;;
  esac
done
printf '%s=%s\\n' "$KEY" "$VAL" >> "$BASE/$NAME/.live_cgroup"
exit 0
`,
        'lxc-snapshot': `#!/bin/sh
set -e
BASE="/var/lib/lxc"; NAME=""; MODE="create"; TARGET=""; CFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    -L) MODE="list"; shift ;;
    -C) shift ;;
    -c) CFILE="$2"; shift 2 ;;
    -r) MODE="restore"; TARGET="$2"; shift 2 ;;
    -d) MODE="delete"; TARGET="$2"; shift 2 ;;
    *) shift ;;
  esac
done
CT="$BASE/$NAME"
mkdir -p "$CT/.snaps"
META="$CT/.snaps/meta.txt"
touch "$META"
if [ "$MODE" = "list" ]; then
  cat "$META"
  exit 0
elif [ "$MODE" = "create" ]; then
  IDX="$(wc -l < "$META" | tr -d ' ')"
  SNAME="snap$IDX"
  COMMENT=""
  [ -n "$CFILE" ] && [ -f "$CFILE" ] && COMMENT="$(tr '\\n' ' ' < "$CFILE")"
  tar --numeric-owner -czpf "$CT/.snaps/$SNAME.tar.gz" -C "$CT" rootfs
  printf '%s - 2026:10:31 12:00:00 %s\\n' "$SNAME" "$COMMENT" >> "$META"
  exit 0
elif [ "$MODE" = "restore" ]; then
  [ -f "$CT/.snaps/$TARGET.tar.gz" ] || exit 1
  rm -rf "$CT/rootfs"
  tar --numeric-owner -xzpf "$CT/.snaps/$TARGET.tar.gz" -C "$CT"
  exit 0
elif [ "$MODE" = "delete" ]; then
  rm -f "$CT/.snaps/$TARGET.tar.gz"
  grep -v "^$TARGET " "$META" > "$META.tmp" || true
  mv "$META.tmp" "$META"
  exit 0
fi
`,
        'lxc-attach': `#!/bin/sh
set -e
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    --clear-env) shift ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
CT="$BASE/$NAME"
[ -f "$CT/config" ] || { echo "Container $NAME does not exist" >&2; exit 1; }
if [ "$1" = "chpasswd" ]; then
  IFS=: read -r USR PW
  HASH="$(printf '%s\\n' "$PW" | openssl passwd -6 -stdin)"
  awk -F: -v OFS=: -v h="$HASH" '$1=="root"{$2=h}{print}' "$CT/rootfs/etc/shadow" > "$CT/rootfs/etc/shadow.new"
  mv "$CT/rootfs/etc/shadow.new" "$CT/rootfs/etc/shadow"
  chmod 0640 "$CT/rootfs/etc/shadow"
  exit 0
fi
if [ "$1" = "ps" ]; then
  printf '1 root 0.1 0.5 /sbin/init\\n48 www-data 0.4 1.8 nginx\\n'
  exit 0
fi
if [ "$1" = "ip" ] || [ "$1" = "resolvectl" ]; then
  printf '%s\\n' "$*" >> "$CT/.live_net"
  exit 0
fi
if [ "$1" = "rm" ] && [ "$3" = "/etc/resolv.conf" ]; then
  rm -f "$CT/rootfs/etc/resolv.conf"
  exit 0
fi
if [ "$1" = "tee" ] && [ "$2" = "/etc/resolv.conf" ]; then
  cat > "$CT/rootfs/etc/resolv.conf"
  exit 0
fi
export CONTAINER_NAME="$NAME"
exec "$@"
`,
      };

      for (const [bin, script] of Object.entries(shims)) {
        const usrBin = `/usr/bin/${bin}`;
        const localBin = `/usr/local/bin/${bin}`;
        if (!fs.existsSync(usrBin) && !fs.existsSync(localBin)) {
          execFileSync('sudo', ['-n', 'tee', localBin], { input: script, stdio: ['pipe', 'ignore', 'pipe'] });
          execFileSync('sudo', ['-n', 'chmod', '0755', localBin]);
          installedLxcShims.push(localBin);
        }
      }

      // Re-sync node #1 (localhost) and remoteNodeId capabilities now that LXC runtime is active
      const checkLocal = await adminClient.request('POST', '/api/v1/nodes/1/check', {});
      assert.strictEqual(checkLocal.status, 200);
      assert.strictEqual(checkLocal.json.health.capabilities.lxcAvailable, true);
      const checkRemote = await adminClient.request('POST', `/api/v1/nodes/${remoteNodeId}/check`, {});
      assert.strictEqual(checkRemote.status, 200);
      assert.strictEqual(checkRemote.json.health.capabilities.lxcAvailable, true);

      // 13d. Provision LXC VPS #1 from Ubuntu 24.04 template (codename 'noble', SSH key, static IP, encrypted password)
      const createRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'e2e-ubuntu-01',
        hostname: 'e2e-ubuntu-01.hkvm.local',
        templateSlug: 'ubuntu:24.04',
        nodeId: 1,
        cpuCores: 2,
        cpuShares: 1024,
        cpuLimitPercent: 90,
        ramMb: 2048,
        swapMb: 512,
        diskGb: 25,
        bridge: 'lxcbr0',
        ipv4Address: '10.88.10.25/24',
        ipv4Gateway: '10.88.10.1',
        sshPublicKeys: ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkvmE2ePubKey00001 admin@hkvm'],
        autostart: true,
        nesting: true,
        provisionOnHost: true,
      });
      assert.strictEqual(createRes.status, 201, `LXC create #1 failed: ${createRes.text}`);
      assert.strictEqual(createRes.json.instance.status, 'running');
      assert.ok(createRes.json.generatedRootPassword.length >= 16);
      e2eUbuntuId = createRes.json.instance.refId;

      const dbRow1 = await ctx.db.get(`SELECT * FROM lxc_instances WHERE id = ?`, [e2eUbuntuId]);
      assert.ok(isEncryptedSecret(dbRow1.root_password_enc), 'Root password encrypted with AES-256-GCM');
      assert.strictEqual(decryptSecret(dbRow1.root_password_enc), createRes.json.generatedRootPassword);
      const regRow1 = await ctx.db.get(
        `SELECT * FROM instances WHERE engine = 'lxc' AND ref_id = ?`,
        [e2eUbuntuId]
      );
      assert.ok(regRow1 && regRow1.status === 'running', 'Unified instances registry synced');

      const ct1Shadow = privilegedFs.readTextSync(
        path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-ubuntu-01', 'rootfs', 'etc', 'shadow')
      );
      assert.match(ct1Shadow, /^root:\$6\$/m, 'Container /etc/shadow updated with SHA-512 hash');

      // Duplicate name rejection
      const dupRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'e2e-ubuntu-01',
        templateSlug: 'ubuntu:24.04',
        provisionOnHost: true,
      });
      assert.ok(dupRes.status >= 400, 'Duplicate container name must be rejected');

      // 13e. Upload a real custom .tar.gz LXC rootfs archive via multipart/form-data & provision LXC VPS #2
      const customBuildDir = path.join(tmpRoot, 'custom-rootfs-src');
      fs.mkdirSync(path.join(customBuildDir, 'etc'), { recursive: true });
      fs.mkdirSync(path.join(customBuildDir, 'root'), { recursive: true });
      fs.writeFileSync(path.join(customBuildDir, 'etc', 'custom-release'), 'HKVM-Custom-OS-3.0\n');
      fs.writeFileSync(path.join(customBuildDir, 'etc', 'shadow'), 'root:*:19000:0:99999:7:::\n');
      const customTarPath = path.join(tmpRoot, 'hkvm-custom-os.tar.gz');
      execFileSync('tar', ['-czf', customTarPath, '-C', customBuildDir, '.']);
      const tarBytes = fs.readFileSync(customTarPath);

      const boundary = '----HkvmMultipartBoundary' + Date.now();
      const mpParts = [];
      const addField = (k, v) => {
        mpParts.push(
          Buffer.from(
            `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`
          )
        );
      };
      addField('slug', 'custom:hkvm-os-3');
      addField('name', 'HKVM Custom OS 3.0');
      addField('distro', 'debian');
      addField('release', 'bookworm');
      mpParts.push(
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="archive"; filename="hkvm-custom-os.tar.gz"\r\nContent-Type: application/gzip\r\n\r\n`
        )
      );
      mpParts.push(tarBytes);
      mpParts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
      const mpBody = Buffer.concat(mpParts);

      const uploadTpl = await adminClient.request('POST', '/api/v1/lxc/templates', mpBody, {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
      });
      assert.strictEqual(uploadTpl.status, 201, `Custom archive upload failed: ${uploadTpl.text}`);
      assert.strictEqual(uploadTpl.json.template.checksum_sha256.length, 64);

      const createCustom = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'e2e-custom-02',
        templateSlug: 'custom:hkvm-os-3',
        nodeId: 1,
        cpuCores: 1,
        ramMb: 512,
        diskGb: 10,
        provisionOnHost: true,
      });
      assert.strictEqual(createCustom.status, 201, `Custom archive LXC failed: ${createCustom.text}`);
      e2eCustomId = createCustom.json.instance.refId;

      const customStamp = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eCustomId}/files/content?path=${encodeURIComponent('/etc/custom-release')}`
      );
      assert.strictEqual(customStamp.status, 200);
      assert.strictEqual(customStamp.json.content.trim(), 'HKVM-Custom-OS-3.0');

      // 13f. Orphan host directory auto-recovery + GPG --no-validate fallback + WSL2 cgroup retry + sync-host
      const orphanDir = path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-orphan-03');
      fs.mkdirSync(path.join(orphanDir, 'rootfs'), { recursive: true });
      fs.writeFileSync(path.join(orphanDir, 'config'), 'lxc.uts.name = e2e-orphan-03\n');

      const gpgTpl = await adminClient.request('POST', '/api/v1/lxc/templates', {
        slug: 'gpgtest:1.0',
        name: 'GPG Fallback Test Template',
        distro: 'gpgtest',
        release: 'current',
      });
      assert.strictEqual(gpgTpl.status, 201);

      const createOrphanAndGpg = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'e2e-orphan-03',
        templateSlug: 'gpgtest:1.0',
        nodeId: 1,
        cpuCores: 1,
        ramMb: 512,
        diskGb: 8,
        provisionOnHost: true,
      });
      assert.strictEqual(
        createOrphanAndGpg.status,
        201,
        `Orphan replacement + GPG fallback failed: ${createOrphanAndGpg.text}`
      );
      e2eOrphanId = createOrphanAndGpg.json.instance.refId;

      // Test automatic WSL2 cgroup failure strip-and-retry during startContainer
      await adminClient.request('POST', `/api/v1/instances/lxc/${e2eOrphanId}/action`, {
        action: 'stop',
      });
      privilegedFs.writeFileSync(
        path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-orphan-03', '.fail_cgroup_once'),
        '1'
      );
      const retryStart = await adminClient.request(
        'POST',
        `/api/v1/instances/lxc/${e2eOrphanId}/action`,
        { action: 'start' }
      );
      assert.strictEqual(retryStart.status, 200, `WSL2 cgroup retry failed: ${retryStart.text}`);
      assert.strictEqual(retryStart.json.instance.status, 'running');

      // Create an unmanaged container directly via lxc-create and import via POST /api/v1/lxc/sync-host
      execFileSync('sudo', [
        '-n',
        '/usr/local/bin/lxc-create',
        '-P',
        process.env.TGVPANEL_LXC_PATH,
        '-n',
        'ext-host-ct-04',
        '--',
        '-d',
        'debian',
        '-r',
        'bookworm',
      ]);
      const syncHostRes = await adminClient.request('POST', '/api/v1/lxc/sync-host', {});
      assert.strictEqual(syncHostRes.status, 200, `sync-host failed: ${syncHostRes.text}`);
      assert.ok(
        syncHostRes.json.imported.includes('ext-host-ct-04'),
        `Expected ext-host-ct-04 in imported: ${JSON.stringify(syncHostRes.json)}`
      );

      // 13g. Full Lifecycle + Suspension Bypass Protection + Live Resize + Password + SSH + File Manager + Logs/Processes/Telemetry/Renew + UI Contrast Check
      for (const [act, expectedStatus] of [
        ['freeze', 'frozen'],
        ['unfreeze', 'running'],
        ['stop', 'stopped'],
        ['start', 'running'],
        ['restart', 'running'],
        ['suspend', 'suspended'],
      ]) {
        const r = await adminClient.request(
          'POST',
          `/api/v1/instances/lxc/${e2eUbuntuId}/action`,
          { action: act, reason: 'E2E test' }
        );
        assert.strictEqual(r.status, 200, `Action ${act} failed: ${r.text}`);
        assert.strictEqual(r.json.instance.status, expectedStatus);
      }

      // Starting OR reinstalling while suspended MUST be blocked with HTTP 400!
      const startWhileSusp = await adminClient.request(
        'POST',
        `/api/v1/instances/lxc/${e2eUbuntuId}/action`,
        { action: 'start' }
      );
      assert.strictEqual(startWhileSusp.status, 400, 'Cannot start suspended LXC');
      const reinstallWhileSusp = await adminClient.request(
        'POST',
        `/api/v1/lxc/${e2eUbuntuId}/reinstall`,
        { templateSlug: 'ubuntu:24.04' }
      );
      assert.strictEqual(reinstallWhileSusp.status, 400, 'Cannot bypass suspension via reinstall');

      // Unsuspend & start back up
      await adminClient.request('POST', `/api/v1/instances/lxc/${e2eUbuntuId}/action`, {
        action: 'unsuspend',
      });
      const afterUnsusp = await adminClient.request(
        'POST',
        `/api/v1/instances/lxc/${e2eUbuntuId}/action`,
        { action: 'start' }
      );
      assert.strictEqual(afterUnsusp.status, 200);
      assert.strictEqual(afterUnsusp.json.instance.status, 'running');

      // Live resize & network update via PATCH /api/v1/lxc/:id
      const patchRes = await adminClient.request('PATCH', `/api/v1/lxc/${e2eUbuntuId}`, {
        cpuCores: 4,
        cpuLimitPercent: 80,
        cpuShares: 2048,
        ramMb: 4096,
        swapMb: 1024,
        diskGb: 40,
        bridge: 'lxcbr0',
        ipAddress: '10.88.10.26/24',
        gateway: '10.88.10.1',
        nesting: true,
        autostart: true,
      });
      assert.strictEqual(patchRes.status, 200, `Resize PATCH failed: ${patchRes.text}`);
      assert.strictEqual(patchRes.json.instance.cpuCores, 4);
      assert.strictEqual(patchRes.json.instance.ramMb, 4096);
      const liveCg = privilegedFs.readTextSync(
        path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-ubuntu-01', '.live_cgroup')
      );
      assert.ok(liveCg.includes('4096M'), 'Live lxc-cgroup memory limit applied while running');

      // Root password reset (online via lxc-attach chpasswd) & SSH key injection
      const pwRes = await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/password`, {
        password: 'UpdatedLivePass!2026',
      });
      assert.strictEqual(pwRes.status, 200, `Password reset failed: ${pwRes.text}`);
      assert.strictEqual(pwRes.json.rootPassword, 'UpdatedLivePass!2026');

      const sshRes = await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/ssh-key`, {
        publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISecondKeyInjected99999 ops@hkvm',
      });
      assert.strictEqual(sshRes.status, 200, `SSH key inject failed: ${sshRes.text}`);

      // Confined Rootfs File Manager CRUD + traversal block
      const writeF = await adminClient.request(
        'POST',
        `/api/v1/lxc/${e2eUbuntuId}/files/content`,
        { path: '/var/www/index.html', content: '<h1>HKVM LXC OK</h1>' }
      );
      assert.strictEqual(writeF.status, 200);
      const listF = await adminClient.request('GET', `/api/v1/lxc/${e2eUbuntuId}/files?path=/var/www`);
      assert.strictEqual(listF.status, 200);
      assert.ok(listF.json.entries.some((e) => e.name === 'index.html'));
      const readF = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/var/www/index.html`
      );
      assert.strictEqual(readF.json.content, '<h1>HKVM LXC OK</h1>');
      const delF = await adminClient.request(
        'DELETE',
        `/api/v1/lxc/${e2eUbuntuId}/files?path=/var/www/index.html`
      );
      assert.strictEqual(delF.status, 200);
      const travF = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=${encodeURIComponent('/../../etc/passwd')}`
      );
      assert.strictEqual(travF.status, 400);

      // Processes, Logs, Telemetry, Expiration Renewal & Detail EJS Regression Check
      const procRes = await adminClient.request('GET', `/api/v1/lxc/${e2eUbuntuId}/processes`);
      assert.strictEqual(procRes.status, 200);
      assert.ok(procRes.json.processes.some((p) => p.command.includes('nginx')));

      const logRes = await adminClient.request('GET', `/api/v1/lxc/${e2eUbuntuId}/logs`);
      assert.strictEqual(logRes.status, 200);
      assert.match(logRes.json.logs, /Container started/);

      const telRes = await adminClient.request(
        'GET',
        `/api/v1/instances/lxc/${e2eUbuntuId}/telemetry`
      );
      assert.strictEqual(telRes.status, 200);
      assert.strictEqual(telRes.json.telemetry.status, 'running');
      assert.ok(telRes.json.telemetry.ramUsedMb >= 60);

      const renewRes = await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/renew`, {
        days: 30,
      });
      assert.strictEqual(renewRes.status, 200);
      assert.ok(renewRes.json.instance.expiresAt);

      const detailPage = await adminClient.request('GET', `/lxc/${e2eUbuntuId}`);
      assert.strictEqual(detailPage.status, 200);
      assert.ok(
        !detailPage.text.includes('background: var(--accent-primary'),
        'Regression guard: .lxc-tab.active must not use white --accent-primary background'
      );
      assert.ok(detailPage.text.includes('id="pane-resources"'), 'Staff resize pane rendered');
    });

    // 15. LXC Snapshots, SHA-256 Archive Backup + Clean Restore, 7-Stage Offline Migration (+ Rollback) & Local/Remote WebSocket PTY Console
    await runStep('T14: LXC snapshots, SHA-256 backup + clean restore, 7-stage offline migration + rollback & WebSocket PTY console', async () => {
      // 14a. LXC Snapshots (create, list, mutate, restore, limit enforcement, delete)
      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/app-version.txt',
        content: 'release-v1.0-stable\n',
      });
      const snapCreate = await adminClient.request(
        'POST',
        `/api/v1/snapshots/lxc/${e2eUbuntuId}`,
        { description: 'Before risky upgrade' }
      );
      assert.strictEqual(snapCreate.status, 201, `Snapshot create failed: ${snapCreate.text}`);
      const snapId = snapCreate.json.snapshot.id;

      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/app-version.txt',
        content: 'release-v2.0-broken\n',
      });
      const snapRestore = await adminClient.request(
        'POST',
        `/api/v1/snapshots/lxc/${e2eUbuntuId}/${snapId}/restore`,
        {}
      );
      assert.strictEqual(snapRestore.status, 200, `Snapshot restore failed: ${snapRestore.text}`);
      const revertedVer = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/app-version.txt`
      );
      assert.strictEqual(revertedVer.json.content.trim(), 'release-v1.0-stable');

      // Enforce snapshot_limit
      await ctx.db.run(`UPDATE lxc_instances SET snapshot_limit = 1 WHERE id = ?`, [e2eUbuntuId]);
      const overLimit = await adminClient.request(
        'POST',
        `/api/v1/snapshots/lxc/${e2eUbuntuId}`,
        { description: 'Should hit limit' }
      );
      assert.ok(overLimit.status >= 400 && /Snapshot limit reached/i.test(overLimit.json.error));
      const snapDel = await adminClient.request(
        'DELETE',
        `/api/v1/snapshots/lxc/${e2eUbuntuId}/${snapId}`
      );
      assert.strictEqual(snapDel.status, 200);

      // 14b. SHA-256 Archive Backup + Integrity Verify + Clean Rootfs Restore
      const bkpCreate = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'lxc',
        refId: e2eUbuntuId,
        label: 'pre_mig_gold',
      });
      assert.strictEqual(bkpCreate.status, 201, `LXC backup failed: ${bkpCreate.text}`);
      const lxcBkpId = bkpCreate.json.backup.backupId;
      assert.strictEqual(bkpCreate.json.backup.checksumSha256.length, 64);

      const bkpVerify = await adminClient.request('POST', `/api/v1/backups/${lxcBkpId}/verify`, {});
      assert.strictEqual(bkpVerify.status, 200);
      assert.strictEqual(bkpVerify.json.valid, true);

      // Mutate existing file AND add post-backup junk file, then restore archive backup!
      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/app-version.txt',
        content: 'corrupted-state\n',
      });
      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/post-backup-stale.txt',
        content: 'should-be-wiped-on-restore\n',
      });

      const bkpRestore = await adminClient.request(
        'POST',
        `/api/v1/backups/${lxcBkpId}/restore`,
        {}
      );
      assert.strictEqual(bkpRestore.status, 200, `LXC backup restore failed: ${bkpRestore.text}`);
      assert.strictEqual(bkpRestore.json.restored, true);
      assert.strictEqual(bkpRestore.json.status, 'running');

      const afterBkpVer = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/app-version.txt`
      );
      assert.strictEqual(afterBkpVer.json.content.trim(), 'release-v1.0-stable');
      const staleCheck = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/post-backup-stale.txt`
      );
      assert.strictEqual(staleCheck.status, 400, 'Post-backup stale file must be wiped by clean restore');

      // 14c. Local WebSocket LXC PTY Console (/ws/lxc/:id/console) + Unauth Rejection
      await new Promise((resolve, reject) => {
        const unauthWs = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/ws/lxc/${e2eCustomId}/console`);
        unauthWs.on('unexpected-response', (_req, res) => {
          assert.strictEqual(res.statusCode, 401);
          resolve();
        });
        unauthWs.on('open', () => reject(new Error('Unauthenticated LXC console WS must not open')));
        unauthWs.on('error', () => resolve());
      });

      const localConsoleOut = await new Promise((resolve, reject) => {
        let out = '';
        const ws = new WebSocket(
          `ws://127.0.0.1:${TEST_PORT}/ws/lxc/${e2eCustomId}/console?cols=110&rows=32`,
          { headers: { Cookie: adminClient.cookie } }
        );
        const timer = setTimeout(() => {
          ws.close();
          reject(new Error(`Timed out waiting for local LXC PTY output. Got: ${out}`));
        }, 6000);
        ws.on('open', () => {
          ws.send(JSON.stringify({ type: 'resize', cols: 120, rows: 36 }));
          setTimeout(() => {
            ws.send(
              JSON.stringify({
                type: 'input',
                data: 'echo LXC_LOCAL_PTY_$CONTAINER_NAME:$((19+23))\n',
              })
            );
          }, 200);
        });
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'output') {
              out += msg.data;
              if (out.includes('LXC_LOCAL_PTY_e2e-custom-02:42')) {
                clearTimeout(timer);
                ws.close();
                resolve(out);
              }
            }
          } catch (_) {}
        });
        ws.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      assert.ok(localConsoleOut.includes('LXC_LOCAL_PTY_e2e-custom-02:42'));

      // 14d. Reinstall LXC Container (#2 custom -> ubuntu:24.04)
      const reinstRes = await adminClient.request('POST', `/api/v1/lxc/${e2eCustomId}/reinstall`, {
        templateSlug: 'ubuntu:24.04',
      });
      assert.strictEqual(reinstRes.status, 200, `Reinstall failed: ${reinstRes.text}`);
      assert.strictEqual(reinstRes.json.instance.status, 'running');
      assert.ok(reinstRes.json.rootPassword.length >= 16);

      // 14e. 7-Stage Verified Offline Migration: First test automatic pre-commit ROLLBACK on target conflict!
      const conflictDir = path.join(tmpRoot, 'agent-lxc', 'e2e-ubuntu-01');
      fs.mkdirSync(conflictDir, { recursive: true });
      fs.writeFileSync(path.join(conflictDir, 'config'), 'lxc.uts.name = e2e-ubuntu-01\n');

      const failedMig = await adminClient.request('POST', '/api/v1/migrations', {
        lxcId: e2eUbuntuId,
        targetNodeId: remoteNodeId,
      });
      assert.strictEqual(failedMig.status, 500, 'Expected migration conflict failure');
      assert.match(failedMig.json.error, /safely rolled back/i);

      const migJobsAfterRollback = await adminClient.request('GET', '/api/v1/migrations');
      assert.strictEqual(migJobsAfterRollback.json.migrations[0].status, 'rolled_back');
      assert.strictEqual(migJobsAfterRollback.json.migrations[0].rollback_performed, 1);

      // Verify source container on localhost is STILL running and intact after rollback!
      const postRollbackTel = await adminClient.request(
        'GET',
        `/api/v1/instances/lxc/${e2eUbuntuId}/telemetry`
      );
      assert.strictEqual(postRollbackTel.json.telemetry.status, 'running');
      fs.rmSync(conflictDir, { recursive: true, force: true });

      // Now execute full 7-stage verified offline migration (localhost -> local-loopback-agent)!
      const okMig = await adminClient.request('POST', '/api/v1/migrations', {
        lxcId: e2eUbuntuId,
        targetNodeId: remoteNodeId,
        targetBridge: 'lxcbr0',
        targetIpv4: '10.88.20.50/24',
        targetGateway: '10.88.20.1',
      });
      assert.strictEqual(okMig.status, 201, `Offline migration failed: ${okMig.text}`);
      assert.strictEqual(okMig.json.migration.status, 'completed');
      assert.strictEqual(okMig.json.migration.progress, 100);
      assert.strictEqual(okMig.json.migration.checksum_sha256.length, 64);

      assert.ok(
        !fs.existsSync(path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-ubuntu-01')),
        'Source container cleaned up after verified target cutover'
      );
      assert.ok(
        fs.existsSync(path.join(tmpRoot, 'agent-lxc', 'e2e-ubuntu-01', 'config')),
        'Target container active on remote Node Agent'
      );

      // Verify remote Node Agent file read, remote backup + SHA-256 verify + restore, remote reinstall & remote proxied WebSocket PTY console!
      const remoteFile = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/app-version.txt`
      );
      assert.strictEqual(remoteFile.status, 200);
      assert.strictEqual(remoteFile.json.content.trim(), 'release-v1.0-stable');

      const remoteBkp = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'lxc',
        refId: e2eUbuntuId,
        label: 'remote_agent_bkp',
      });
      assert.strictEqual(remoteBkp.status, 201, `Remote node backup failed: ${remoteBkp.text}`);
      const remoteBkpId = remoteBkp.json.backup.backupId;

      const remoteBkpVer = await adminClient.request(
        'POST',
        `/api/v1/backups/${remoteBkpId}/verify`,
        {}
      );
      assert.strictEqual(remoteBkpVer.status, 200);
      assert.strictEqual(remoteBkpVer.json.valid, true);

      const remoteBkpRestore = await adminClient.request(
        'POST',
        `/api/v1/backups/${remoteBkpId}/restore`,
        {}
      );
      assert.strictEqual(remoteBkpRestore.status, 200, `Remote restore failed: ${remoteBkpRestore.text}`);
      assert.strictEqual(remoteBkpRestore.json.status, 'running');

      // Remote Node Agent proxied WebSocket LXC PTY Console (testing early buffered frames on CONNECTING!)
      const remoteConsoleOut = await new Promise((resolve, reject) => {
        let out = '';
        const ws = new WebSocket(
          `ws://127.0.0.1:${TEST_PORT}/ws/lxc/${e2eUbuntuId}/console?cols=100&rows=30`,
          { headers: { Cookie: adminClient.cookie } }
        );
        const timer = setTimeout(() => {
          ws.close();
          reject(new Error(`Timed out waiting for remote proxied LXC PTY output. Got: ${out}`));
        }, 6000);
        ws.on('open', () => {
          // Immediately send input frame to exercise bridgeWebSockets CONNECTING queue!
          ws.send(
            JSON.stringify({
              type: 'input',
              data: 'echo REMOTE_AGENT_PTY_$CONTAINER_NAME:$((50+49))\n',
            })
          );
        });
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'output') {
              out += msg.data;
              if (out.includes('REMOTE_AGENT_PTY_e2e-ubuntu-01:99')) {
                clearTimeout(timer);
                ws.close();
                resolve(out);
              }
            }
          } catch (_) {}
        });
        ws.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      assert.ok(remoteConsoleOut.includes('REMOTE_AGENT_PTY_e2e-ubuntu-01:99'));

      // Remote Node Agent Reinstall -> must preserve 'running' state cleanly
      const remoteReinst = await adminClient.request(
        'POST',
        `/api/v1/lxc/${e2eUbuntuId}/reinstall`,
        { templateSlug: 'ubuntu:24.04' }
      );
      assert.strictEqual(remoteReinst.status, 200, `Remote reinstall failed: ${remoteReinst.text}`);
      assert.strictEqual(
        remoteReinst.json.instance.status,
        'running',
        'Remote reinstalled container must accurately report running status'
      );

      // Cleanly delete backups & all E2E LXC containers via API and verify DB + disk cleanup
      await adminClient.request('DELETE', `/api/v1/backups/${lxcBkpId}`);
      await adminClient.request('DELETE', `/api/v1/backups/${remoteBkpId}`);
      for (const id of [e2eUbuntuId, e2eCustomId, e2eOrphanId]) {
        const del = await adminClient.request('POST', `/api/v1/instances/lxc/${id}/action`, {
          action: 'delete',
        });
        assert.strictEqual(del.status, 200, `Delete LXC #${id} failed: ${del.text}`);
        const gone = await ctx.db.get(`SELECT id FROM lxc_instances WHERE id = ?`, [id]);
        assert.strictEqual(gone, undefined);
      }
      const extRow = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ext-host-ct-04'`);
      if (extRow) {
        await adminClient.request('POST', `/api/v1/instances/lxc/${extRow.id}/action`, {
          action: 'delete',
        });
      }
    });

    // 15. KVM Nesting (/dev/kvm passthrough), WSL2 /proc telemetry fallback & redesigned LXC Detail Control Center
    await runStep('T15: LXC KVM Nesting (/dev/kvm passthrough), /proc RSS fallback & redesigned LXC Detail UI', async () => {
      const ctx = app.getHkvmV3Context();
      const { privilegedFs } = require('../lib/node-agent/command-runner');

      // Verify LXC Create Studio renders the KVM Nesting toggle (#cKvmNest)
      const createPage = await adminClient.request('GET', '/admin/instances/create?engine=lxc');
      assert.strictEqual(createPage.status, 200);
      assert.ok(createPage.text.includes('id="cKvmNest"'), 'Expected #cKvmNest toggle in LXC Create Studio');
      assert.ok(createPage.text.includes('/dev/kvm'), 'Expected /dev/kvm explanation in LXC Create Studio');

      // Provision a real LXC container with kvmNesting: true
      const createRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'kvm-nested-lxc-01',
        hostname: 'kvm-nested-01.hkvm.local',
        nodeId: 1,
        templateSlug: 'ubuntu-22.04',
        cpuCores: 4,
        ramMb: 4096,
        swapMb: 512,
        diskGb: 30,
        nesting: true,
        kvmNesting: true,
        autostart: true,
        provisionOnHost: true,
      });
      assert.strictEqual(createRes.status, 201, `Create KVM-nested LXC failed: ${createRes.text}`);
      const kvmCtId = createRes.json.instance.refId;

      const dbRow = await ctx.db.get(`SELECT kvm_nesting, nesting, autostart FROM lxc_instances WHERE id = ?`, [kvmCtId]);
      assert.strictEqual(dbRow.kvm_nesting, 1, 'Expected kvm_nesting=1 persisted in SQLite');

      const cfgPath = path.join(process.env.TGVPANEL_LXC_PATH, 'kvm-nested-lxc-01', 'config');
      const cfgTextOn = privilegedFs.readTextSync(cfgPath);
      assert.ok(
        cfgTextOn.includes('lxc.mount.entry = /dev/kvm dev/kvm none bind,optional,create=file 0 0'),
        'Expected /dev/kvm bind mount in container config'
      );
      assert.ok(
        cfgTextOn.includes('lxc.mount.entry = /dev/net/tun dev/net/tun none bind,optional,create=file 0 0'),
        'Expected /dev/net/tun bind mount in container config'
      );
      assert.ok(
        cfgTextOn.includes('devices.allow = c 10:232 rwm') && cfgTextOn.includes('devices.allow = c 10:200 rwm'),
        'Expected /dev/kvm (10:232) and /dev/net/tun (10:200) device allow rules'
      );
      assert.ok(
        cfgTextOn.includes('lxc.apparmor.profile = unconfined'),
        'Expected unconfined AppArmor profile when KVM nesting is enabled'
      );

      // Render redesigned LXC Detail Control Center (/lxc/:id)
      const detailPage = await adminClient.request('GET', `/lxc/${kvmCtId}`);
      assert.strictEqual(detailPage.status, 200, `GET /lxc/${kvmCtId} failed`);
      assert.ok(detailPage.text.includes('class="lxc-hero"'), 'Expected redesigned .lxc-hero header');
      assert.ok(detailPage.text.includes('id="pane-overview"'), 'Expected Overview & Specs pane');
      assert.ok(detailPage.text.includes('id="pane-resources"'), 'Expected Staff Resources & KVM pane');
      assert.ok(detailPage.text.includes('id="resKvmNesting" checked'), 'Expected #resKvmNesting checked for KVM-nested container');
      assert.ok(detailPage.text.includes('Enabled (/dev/kvm + /dev/net/tun)'), 'Expected KVM status badge on Overview pane');

      // Test WSL2 / undelegated cgroup-v2 /proc VmRSS telemetry fallback when lxc-info omits "Memory use:"
      const { execFileSync } = require('child_process');
      const omitMarker = path.join(process.env.TGVPANEL_LXC_PATH, 'kvm-nested-lxc-01', '.omit_mem_use');
      execFileSync('sudo', ['-n', 'touch', omitMarker]);
      const localCm = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
      const inspected = await localCm.inspectContainer('kvm-nested-lxc-01');
      assert.strictEqual(inspected.state, 'running');
      assert.ok(inspected.pid > 0, 'Expected live container init PID');
      assert.ok(
        inspected.memoryBytes > 0,
        `Expected /proc descendant VmRSS fallback to report >0 bytes when lxc-info omits Memory use (got ${inspected.memoryBytes})`
      );
      const telFallback = await adminClient.request('GET', `/api/v1/instances/lxc/${kvmCtId}/telemetry`);
      assert.strictEqual(telFallback.status, 200);
      assert.strictEqual(telFallback.json.telemetry.status, 'running');
      execFileSync('sudo', ['-n', 'rm', '-f', omitMarker]);

      // Toggle kvmNesting OFF via PATCH /api/v1/lxc/:id -> verify rules cleanly stripped from config & DB
      const patchOff = await adminClient.request('PATCH', `/api/v1/lxc/${kvmCtId}`, {
        kvmNesting: false,
      });
      assert.strictEqual(patchOff.status, 200, `PATCH kvmNesting=false failed: ${patchOff.text}`);
      const dbRowOff = await ctx.db.get(`SELECT kvm_nesting FROM lxc_instances WHERE id = ?`, [kvmCtId]);
      assert.strictEqual(dbRowOff.kvm_nesting, 0);
      const cfgTextOff = privilegedFs.readTextSync(cfgPath);
      assert.ok(!cfgTextOff.includes('/dev/kvm'), 'Expected /dev/kvm mount removed when kvmNesting=false');
      assert.ok(!cfgTextOff.includes('10:232'), 'Expected c 10:232 rwm removed when kvmNesting=false');

      // Toggle kvmNesting back ON and reinstall -> verify reinstall preserves kvmNesting!
      const patchOn = await adminClient.request('PATCH', `/api/v1/lxc/${kvmCtId}`, {
        kvmNesting: true,
      });
      assert.strictEqual(patchOn.status, 200);
      const reinst = await adminClient.request('POST', `/api/v1/lxc/${kvmCtId}/reinstall`, {
        templateSlug: 'ubuntu:24.04',
      });
      assert.strictEqual(reinst.status, 200, `Reinstall failed: ${reinst.text}`);
      const cfgAfterReinst = privilegedFs.readTextSync(cfgPath);
      assert.ok(
        cfgAfterReinst.includes('lxc.mount.entry = /dev/kvm dev/kvm none bind,optional,create=file 0 0'),
        'Expected reinstall to preserve KVM nesting /dev/kvm passthrough'
      );

      // Cleanup container
      const del = await adminClient.request('POST', `/api/v1/instances/lxc/${kvmCtId}/action`, {
        action: 'delete',
      });
      assert.strictEqual(del.status, 200);
    });

    // 16. LXC Networking, Dangling stub-resolv.conf + WSL2 Tunnel DNS Fix, Netplan Sync & Live Repair API
    await runStep('T16: LXC Networking, stub-resolv.conf/WSL2 DNS fix, Netplan sync, Auto-IP & live repair-network API', async () => {
      const { execFileSync } = require('child_process');
      const { privilegedFs } = require('../lib/node-agent/command-runner');

      // Unit-verify subnet calculation & guest DNS resolver filtering (127.0.0.53 + WSL2 10.255.255.254 excluded!)
      assert.strictEqual(computeIpv4SubnetCidr('10.0.3.1', 24), '10.0.3.0/24');
      const filteredDns = resolveGuestDnsServers(
        '# systemd-resolved stub\nnameserver 127.0.0.53\nnameserver 10.255.255.254\nnameserver 192.168.50.1\n'
      );
      assert.ok(!filteredDns.includes('127.0.0.53'), 'Must strip host loopback stub 127.0.0.53');
      assert.ok(!filteredDns.includes('10.255.255.254'), 'Must strip non-bridge-routable WSL2 tunnel 10.255.255.254');
      assert.ok(filteredDns.includes('1.1.1.1') && filteredDns.includes('8.8.8.8'));
      assert.strictEqual(filteredDns.length, 3, 'Must respect glibc MAXNS=3 limit');

      // Verify built-in host BridgeDnsRelay (UDP + TCP + OS getaddrinfo synthesis for localhost!)
      const dgram = require('dgram');
      const { BridgeDnsRelay, parseDnsQuestion, synthesizeDnsFromOsLookup } = require('../lib/node-agent/dns-relay');
      // Build a real RFC 1035 query for "localhost" IN A (txId=0x4242)
      const qHeader = Buffer.from([0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const qBody = Buffer.concat([
        Buffer.from([9]),
        Buffer.from('localhost', 'ascii'),
        Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01]),
      ]);
      const localhostQuery = Buffer.concat([qHeader, qBody]);
      const parsedQ = parseDnsQuestion(localhostQuery);
      assert.strictEqual(parsedQ.qname, 'localhost');
      assert.strictEqual(parsedQ.qtype, 1);

      const synthAns = await synthesizeDnsFromOsLookup(localhostQuery);
      assert.ok(synthAns && synthAns.length > localhostQuery.length, 'Expected synthesized A record for localhost');
      assert.strictEqual(synthAns.readUInt16BE(0), 0x4242);
      assert.strictEqual(synthAns.readUInt16BE(2) & 0x000f, 0, 'Expected NOERROR rcode');
      assert.ok(synthAns.readUInt16BE(6) >= 1, 'Expected ANCOUNT >= 1');

      const testRelay = new BridgeDnsRelay();
      // Point upstream to closed local port via env so relay exercises OS lookup fallback deterministically
      const prevDnsEnv = process.env.TGVPANEL_LXC_DNS;
      process.env.TGVPANEL_LXC_DNS = '127.0.0.254';
      const relayPort = await testRelay.ensureStarted();
      assert.ok(relayPort > 0, 'Expected BridgeDnsRelay to bind UDP+TCP port');
      const relayReply = await new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');
        const t = setTimeout(() => {
          client.close();
          reject(new Error('BridgeDnsRelay UDP query timed out'));
        }, 4000);
        client.on('message', (msg) => {
          clearTimeout(t);
          client.close();
          resolve(msg);
        });
        client.send(localhostQuery, relayPort, '127.0.0.1');
      });
      assert.strictEqual(relayReply.readUInt16BE(0), 0x4242);
      assert.ok(relayReply.readUInt16BE(6) >= 1, 'BridgeDnsRelay resolved localhost over live UDP');
      testRelay.stop();
      if (prevDnsEnv === undefined) delete process.env.TGVPANEL_LXC_DNS;
      else process.env.TGVPANEL_LXC_DNS = prevDnsEnv;

      // Create an Ubuntu 22.04 container with static IP WITHOUT explicit gateway -> verify auto-gateway (.1),
      // dangling stub-resolv.conf symlink replacement, systemd-resolved drop-in, and Netplan 10-lxc.yaml sync!
      const createNetRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'net-fix-ubuntu-01',
        hostname: 'net-fix-01.hkvm.local',
        nodeId: 1,
        templateSlug: 'ubuntu-22.04',
        cpuCores: 2,
        ramMb: 1024,
        swapMb: 256,
        diskGb: 15,
        ipv4Address: '10.88.55.25/24',
        provisionOnHost: true,
      });
      assert.strictEqual(createNetRes.status, 201, `Create net-fix LXC failed: ${createNetRes.text}`);
      const netCtId = createNetRes.json.instance.refId;

      const ctDir = path.join(process.env.TGVPANEL_LXC_PATH, 'net-fix-ubuntu-01');
      const cfgTxt = privilegedFs.readTextSync(path.join(ctDir, 'config'));
      assert.ok(cfgTxt.includes('lxc.net.0.name = eth0'), 'Expected explicit eth0 interface name');
      assert.ok(cfgTxt.includes('lxc.net.0.ipv4.address = 10.88.55.25/24'), 'Expected static IPv4 CIDR');
      assert.ok(cfgTxt.includes('lxc.net.0.ipv4.gateway = 10.88.55.1'), 'Expected inferred .1 gateway when omitted');

      // Verify dangling ../run/systemd/resolve/stub-resolv.conf symlink was replaced by a real regular file!
      const resolvPath = path.join(ctDir, 'rootfs/etc/resolv.conf');
      const resolvMeta = privilegedFs.lstatMetaSync(resolvPath);
      assert.strictEqual(resolvMeta.isSymbolicLink, false, 'resolv.conf must be a regular file, not a dangling stub symlink');
      const resolvTxt = privilegedFs.readTextSync(resolvPath);
      assert.ok(resolvTxt.includes('nameserver 1.1.1.1') && resolvTxt.includes('nameserver 8.8.8.8'));
      assert.ok(!resolvTxt.includes('127.0.0.53'));

      // Verify systemd-resolved drop-in & Netplan 10-lxc.yaml were synchronized (so systemd-networkd never flushes eth0!)
      const dropinTxt = privilegedFs.readTextSync(
        path.join(ctDir, 'rootfs/etc/systemd/resolved.conf.d/99-hkvm-dns.conf')
      );
      assert.ok(dropinTxt.includes('DNS=1.1.1.1 8.8.8.8'));

      const netplanTxt = privilegedFs.readTextSync(path.join(ctDir, 'rootfs/etc/netplan/10-lxc.yaml'));
      assert.ok(netplanTxt.includes('dhcp4: false'), 'Netplan must disable dhcp4 when static/auto IP is set');
      assert.ok(netplanTxt.includes('10.88.55.25/24'), 'Netplan must match assigned IPv4 CIDR');
      assert.ok(netplanTxt.includes('via: 10.88.55.1'), 'Netplan must configure default route gateway');

      const nssTxt = privilegedFs.readTextSync(path.join(ctDir, 'rootfs/etc/nsswitch.conf'));
      assert.ok(!nssTxt.includes('[!UNAVAIL=return]'), 'nsswitch.conf must remove [!UNAVAIL=return] trap');
      assert.ok(nssTxt.includes('hosts:          files dns'), 'nsswitch.conf must prioritize direct files dns');

      // Verify collision-free auto-IP allocation helper
      const localCm = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
      const autoIp1 = await localCm.allocateAutoBridgeIpv4('auto-ip-test-a', 'lxcbr0', '10.88.55.1', 24);
      assert.ok(autoIp1 && autoIp1.startsWith('10.88.55.') && autoIp1 !== '10.88.55.1/24' && autoIp1 !== '10.88.55.25/24');

      // Simulate broken DNS inside running container & invoke live POST /api/v1/lxc/:id/repair-network!
      execFileSync('sudo', ['-n', 'ln', '-sf', '../run/systemd/resolve/stub-resolv.conf', resolvPath]);
      const repairRes = await adminClient.request('POST', `/api/v1/lxc/${netCtId}/repair-network`, {});
      assert.strictEqual(repairRes.status, 200, `POST repair-network failed: ${repairRes.text}`);
      assert.strictEqual(repairRes.json.success, true);
      assert.strictEqual(repairRes.json.repair.ipv4Address, '10.88.55.25');
      assert.strictEqual(repairRes.json.repair.gateway, '10.88.55.1');
      assert.strictEqual(repairRes.json.repair.liveApplied, true);

      const liveNetLog = privilegedFs.readTextSync(path.join(ctDir, '.live_net'));
      assert.ok(liveNetLog.includes('ip link set eth0 up'), 'Expected live eth0 link up via lxc-attach');
      assert.ok(liveNetLog.includes('ip addr replace 10.88.55.25/24 dev eth0'), 'Expected live IPv4 injection');
      assert.ok(liveNetLog.includes('ip route replace default via 10.88.55.1 dev eth0'), 'Expected live default route injection');
      assert.ok(liveNetLog.includes('resolvectl dns eth0'), 'Expected live systemd-resolved DNS update via resolvectl');

      const repairedResolv = privilegedFs.readTextSync(resolvPath);
      assert.ok(repairedResolv.includes('nameserver 1.1.1.1'), 'Expected live repaired /etc/resolv.conf');

      // Also test remote Node Agent POST /api/v1/lxc/:id/repair-network via migrated/remote container
      const remoteCreate = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'net-fix-remote-02',
        nodeId: remoteNodeId,
        templateSlug: 'ubuntu-22.04',
        cpuCores: 1,
        ramMb: 512,
        diskGb: 10,
        ipv4Address: '10.88.66.30/24',
        provisionOnHost: true,
      });
      assert.strictEqual(remoteCreate.status, 201);
      const remoteCtId = remoteCreate.json.instance.refId;
      const remoteRepair = await adminClient.request('POST', `/api/v1/lxc/${remoteCtId}/repair-network`, {});
      assert.strictEqual(remoteRepair.status, 200, `Remote repair-network failed: ${remoteRepair.text}`);
      assert.strictEqual(remoteRepair.json.repair.ipv4Address, '10.88.66.30');

      // Cleanup both test containers
      await adminClient.request('POST', `/api/v1/instances/lxc/${netCtId}/action`, { action: 'delete' });
      await adminClient.request('POST', `/api/v1/instances/lxc/${remoteCtId}/action`, { action: 'delete' });
    });

    await runStep('T17: WSL2 BridgeDnsRelay TCP/AAAA fast-path, loop prevention & iptables-legacy/modprobe allowlist', async () => {
      const net = require('net');
      const { BridgeDnsRelay, synthesizeDnsFromOsLookup } = require('../lib/node-agent/dns-relay');
      const { isAllowlistedBinary } = require('../lib/node-agent/command-runner');

      // 1. Verify dual iptables-legacy & modprobe allowlist without weakening shell restrictions
      assert.ok(isAllowlistedBinary('iptables-legacy'), 'Expected iptables-legacy in allowlist');
      assert.ok(isAllowlistedBinary('ip6tables-legacy'), 'Expected ip6tables-legacy in allowlist');
      assert.ok(isAllowlistedBinary('modprobe'), 'Expected modprobe in allowlist');
      assert.ok(!isAllowlistedBinary('sh') && !isAllowlistedBinary('bash') && !isAllowlistedBinary('sudo'));

      // 2. Verify AAAA (qtype=28) synthesis returns instant empty NOERROR (rcode=0) instead of timing out when IPv4 exists
      const aaaaHeader = Buffer.from([0x51, 0x52, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const ipv4OnlyHost = '127.0.0.1';
      const labels = ipv4OnlyHost.split('.').map((lbl) => Buffer.concat([Buffer.from([lbl.length]), Buffer.from(lbl, 'ascii')]));
      const aaaaQuery = Buffer.concat([aaaaHeader, ...labels, Buffer.from([0x00, 0x00, 0x1c, 0x00, 0x01])]);
      const aaaaSynth = await synthesizeDnsFromOsLookup(aaaaQuery);
      assert.ok(aaaaSynth && aaaaSynth.length >= 12);
      assert.strictEqual(aaaaSynth.readUInt16BE(0), 0x5152);
      assert.strictEqual(aaaaSynth.readUInt16BE(2) & 0x000f, 0, 'AAAA for IPv4-only host must return instant NOERROR');
      assert.strictEqual(aaaaSynth.readUInt16BE(6), 0, 'AAAA for IPv4-only host must have 0 answers');

      // 3. Verify live RFC 1035 DNS-over-TCP framing (2-byte big-endian length prefix) + bridge IP loop exclusion
      const relay = new BridgeDnsRelay();
      relay.addExcludedLoopIp('10.0.3.1');
      const port = await relay.ensureStarted();
      assert.ok(port > 0);

      const tcpQ = Buffer.concat([
        Buffer.from([0x77, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Buffer.from([9]),
        Buffer.from('localhost', 'ascii'),
        Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01]),
      ]);
      const framed = Buffer.alloc(2 + tcpQ.length);
      framed.writeUInt16BE(tcpQ.length, 0);
      tcpQ.copy(framed, 2);

      const tcpReply = await new Promise((resolve, reject) => {
        const sock = net.createConnection({ host: '127.0.0.1', port }, () => {
          sock.write(framed);
        });
        let buf = Buffer.alloc(0);
        const timer = setTimeout(() => {
          sock.destroy();
          reject(new Error('TCP DNS relay query timed out'));
        }, 4000);
        sock.on('data', (chunk) => {
          buf = Buffer.concat([buf, chunk]);
          if (buf.length >= 2) {
            const len = buf.readUInt16BE(0);
            if (buf.length >= 2 + len) {
              clearTimeout(timer);
              sock.end();
              resolve(buf.subarray(2, 2 + len));
            }
          }
        });
        sock.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });

      assert.strictEqual(tcpReply.readUInt16BE(0), 0x7788);
      assert.strictEqual(tcpReply.readUInt16BE(2) & 0x000f, 0);
      assert.ok(tcpReply.readUInt16BE(6) >= 1, 'Expected TCP DNS relay to return >=1 A record for localhost');
      relay.stop();
    });

    await runStep('T18: LXC hard disk quota (sparse ext4 loop volume + live resize), cpuset isolation & cgroup preservation', async () => {
      const { execFileSync } = require('child_process');
      const {
        LxcContainerManager,
        parseCpuListSpec,
        selectContainerCpuset,
      } = require('../lib/node-agent/container-manager');
      const { findActiveMountSource, privilegedFs, canPasswordlessSudo, isRunningAsRoot } =
        require('../lib/node-agent/command-runner');

      // 1. Verify CPU list parser & deterministic vCPU pinning
      assert.deepStrictEqual(parseCpuListSpec('0-2,5'), [0, 1, 2, 5]);
      const pin1 = selectContainerCpuset('test', 1, [0, 1, 2, 3]);
      assert.strictEqual(pin1.split(',').length, 1, '1 vCPU must pin to 1 CPU');
      const pin2 = selectContainerCpuset('test', 2, [0, 1, 2, 3]);
      assert.strictEqual(pin2.split(',').length, 2, '2 vCPUs must pin to 2 distinct CPUs');
      assert.strictEqual(selectContainerCpuset('test', 2, [0, 1, 2, 3], '1-2'), '1-2');

      // 2. Verify writeManagedConfigSection writes memory.max, cpu.max, and cpuset.cpus
      const quotaStore = path.join(tmpRoot, 'quota-lxc-store');
      const ctName = 'quota-disk-e2e';
      const ctDir = path.join(quotaStore, ctName);
      const rootfsDir = path.join(ctDir, 'rootfs');
      fs.mkdirSync(path.join(rootfsDir, 'etc'), { recursive: true });
      fs.mkdirSync(path.join(rootfsDir, 'root'), { recursive: true });
      fs.writeFileSync(path.join(rootfsDir, 'etc', 'hostname'), `${ctName}\n`);
      fs.writeFileSync(path.join(rootfsDir, 'root', 'keep.txt'), 'HKVM_QUOTA_PRESERVED_DATA\n');
      fs.writeFileSync(
        path.join(ctDir, 'config'),
        `lxc.rootfs.path = dir:${rootfsDir}\nlxc.uts.name = ${ctName}\n`
      );

      const qCm = new LxcContainerManager(quotaStore);
      await qCm.writeManagedConfigSection(ctName, {
        hostname: ctName,
        cpuCores: 1,
        ramMb: 1024,
        swapMb: 512,
        nesting: true,
        kvmNesting: true,
        bridge: 'lxcbr0',
      });
      const cfgWritten = privilegedFs.readTextSync(path.join(ctDir, 'config'));
      assert.ok(cfgWritten.includes('memory.max = 1024M') || cfgWritten.includes('memory.limit_in_bytes = 1024M'));
      assert.ok(cfgWritten.includes('cpuset.cpus ='));

      // 3. Test real sparse ext4 loop quota volume creation (1 GB) + live online resize (2 GB)
      if (isRunningAsRoot() || canPasswordlessSudo()) {
        try {
          const mounted1G = await qCm.ensureContainerQuotaDisk(ctName, 1, { allowNonSystemStore: true });
          assert.strictEqual(mounted1G, true, 'Expected 1 GB sparse ext4 loop quota disk to mount');
          assert.ok(findActiveMountSource(rootfsDir), 'Expected active /dev/loopX mount on rootfs');

          const preserved = privilegedFs.readTextSync(path.join(rootfsDir, 'root', 'keep.txt'));
          assert.strictEqual(preserved.trim(), 'HKVM_QUOTA_PRESERVED_DATA');

          const df1Out = execFileSync('df', ['-B1', '--output=size', rootfsDir], { encoding: 'utf8' });
          const size1Bytes = parseInt(df1Out.trim().split('\n').pop().trim(), 10);
          assert.ok(
            size1Bytes > 850 * 1024 * 1024 && size1Bytes < 1150 * 1024 * 1024,
            `Expected ~1 GB filesystem in df (not host 32G!), got ${size1Bytes} bytes`
          );

          // Live online resize from 1 GB -> 2 GB while mounted!
          const resized2G = await qCm.ensureContainerQuotaDisk(ctName, 2, { allowNonSystemStore: true });
          assert.strictEqual(resized2G, true, 'Expected online live resize to 2 GB to succeed');
          const df2Out = execFileSync('df', ['-B1', '--output=size', rootfsDir], { encoding: 'utf8' });
          const size2Bytes = parseInt(df2Out.trim().split('\n').pop().trim(), 10);
          assert.ok(
            size2Bytes > 1800 * 1024 * 1024 && size2Bytes < 2200 * 1024 * 1024,
            `Expected ~2 GB filesystem after live resize, got ${size2Bytes} bytes`
          );
          assert.strictEqual(
            privilegedFs.readTextSync(path.join(rootfsDir, 'root', 'keep.txt')).trim(),
            'HKVM_QUOTA_PRESERVED_DATA'
          );
        } finally {
          await qCm.unmountQuotaDiskIfMounted(ctName, true);
          assert.strictEqual(findActiveMountSource(rootfsDir), null, 'Expected loop mount cleanly detached');
        }
      }
    });

    await runStep('T19: Real kernel cgroup v2 delegation (init.scope + hkvm.lxc), legacy hkvm.host migration & live RAM/CPU enforcement', async () => {
      const { spawn, execFileSync } = require('child_process');
      const {
        LxcContainerManager,
        resolveHostBaseCgroupV2Dir,
        ensureCgroupV2SubtreeDelegation,
        resolveLiveContainerCgroupV2Dir,
        readCgroupV2Type,
        isUsableDomainCgroupDir,
      } = require('../lib/node-agent/container-manager');
      const { privilegedFs, canPasswordlessSudo, isRunningAsRoot } =
        require('../lib/node-agent/command-runner');

      // 1. Verify `/init.scope` and legacy `/hkvm.host` stripping for liblxc & lxcfs `prune_init_scope` parity
      assert.strictEqual(resolveHostBaseCgroupV2Dir('0::/init.scope\n'), '/sys/fs/cgroup');
      assert.strictEqual(resolveHostBaseCgroupV2Dir('0::/hkvm.host\n'), '/sys/fs/cgroup');

      // 2. Verify granular `startContainer` cgroup fallback NEVER wipes `memory.max` or `cpuset.cpus`
      // when `devices.allow` fails on first start attempt!
      const stageCtRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'cgroup-stage-preserve-01',
        nodeId: 1,
        templateSlug: 'ubuntu-22.04',
        cpuCores: 1,
        ramMb: 1024,
        swapMb: 512,
        diskGb: 10,
        kvmNesting: true,
        provisionOnHost: true,
      });
      assert.strictEqual(stageCtRes.status, 201, `Create stage test LXC failed: ${stageCtRes.text}`);
      const stageCtId = stageCtRes.json.instance.refId;
      await adminClient.request('POST', `/api/v1/instances/lxc/${stageCtId}/action`, { action: 'stop' });

      const stageCtDir = path.join(process.env.TGVPANEL_LXC_PATH, 'cgroup-stage-preserve-01');
      privilegedFs.writeFileSync(path.join(stageCtDir, '.fail_cgroup_once'), '1');
      const stageStartRes = await adminClient.request('POST', `/api/v1/instances/lxc/${stageCtId}/action`, {
        action: 'start',
      });
      assert.strictEqual(stageStartRes.status, 200, `Staged start failed: ${stageStartRes.text}`);
      const postStageCfg = privilegedFs.readTextSync(path.join(stageCtDir, 'config'));
      assert.ok(
        postStageCfg.includes('memory.max = 1024M') || postStageCfg.includes('memory.limit_in_bytes = 1024M'),
        'Stage 1 devices strip must preserve memory.max = 1024M!'
      );
      assert.ok(postStageCfg.includes('cpuset.cpus ='), 'Stage 1 devices strip must preserve cpuset.cpus!');
      assert.ok(postStageCfg.includes('# hkvm.limits: ram_mb=1024'), 'Expected # hkvm.limits metadata comment');
      await adminClient.request('POST', `/api/v1/instances/lxc/${stageCtId}/action`, { action: 'delete' });

      // 3. Real Linux 6.8 cgroup v2 hierarchy test: legacy `/hkvm.host` evacuation -> `/init.scope`,
      // `/hkvm.lxc` controller delegation, live `memory.max` (1024 MiB -> 2048 MiB), `cpu.max`, & `nproc=1`!
      if ((isRunningAsRoot() || canPasswordlessSudo()) && fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
        let sleeper = null;
        const payloadCg = '/sys/fs/cgroup/hkvm.lxc/lxc.payload.cgroup-e2e-01';
        const legacyHostCg = '/sys/fs/cgroup/hkvm.host';
        const legacyBrokenPayload = '/sys/fs/cgroup/hkvm.host/lxc.payload.broken-01';
        try {
          sleeper = spawn('sleep', ['30'], { stdio: 'ignore' });
          assert.ok(sleeper.pid > 1);

          // Simulate PR #13 broken state: process placed in `/sys/fs/cgroup/hkvm.host`
          execFileSync('sudo', ['-n', 'mkdir', '-p', legacyBrokenPayload]);
          privilegedFs.writeFileSync(path.join(legacyHostCg, 'cgroup.procs'), `${sleeper.pid}\n`);
          ensureCgroupV2SubtreeDelegation();

          const migratedCg = resolveLiveContainerCgroupV2Dir(sleeper.pid);
          assert.strictEqual(
            migratedCg,
            '/sys/fs/cgroup/init.scope',
            `Expected PID migrated from /hkvm.host into /init.scope, got ${migratedCg}`
          );

          const hkvmLxcSub = fs.readFileSync('/sys/fs/cgroup/hkvm.lxc/cgroup.subtree_control', 'utf8');
          assert.ok(hkvmLxcSub.includes('memory'), 'Expected +memory delegated on /sys/fs/cgroup/hkvm.lxc');
          assert.ok(hkvmLxcSub.includes('cpu'), 'Expected +cpu delegated on /sys/fs/cgroup/hkvm.lxc');
          assert.ok(hkvmLxcSub.includes('cpuset'), 'Expected +cpuset delegated on /sys/fs/cgroup/hkvm.lxc');

          // Verify `needsContainerCgroupRestartOrHeal` flags processes trapped in `/hkvm.host/lxc.payload.*`
          privilegedFs.writeFileSync(path.join(legacyBrokenPayload, 'cgroup.procs'), `${sleeper.pid}\n`);
          const cmTest = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
          const brokenDiag = cmTest.needsContainerCgroupRestartOrHeal('broken-01', sleeper.pid, {
            ramMb: 1024,
            cpuCores: 1,
          });
          assert.strictEqual(brokenDiag.requiresRestart, true, 'Trapped /hkvm.host container must trigger restart');

          // Move sleeper into real `/sys/fs/cgroup/hkvm.lxc/lxc.payload.cgroup-e2e-01` and enforce 1024 MB + 1 vCPU!
          execFileSync('sudo', ['-n', 'mkdir', '-p', payloadCg]);
          privilegedFs.writeFileSync(path.join(payloadCg, 'cgroup.procs'), `${sleeper.pid}\n`);
          const enforced = await cmTest.enforceLiveContainerCgroups('cgroup-e2e-01', {
            ramMb: 1024,
            swapMb: 512,
            cpuCores: 1,
            cpuLimitPercent: 100,
            pid: sleeper.pid,
          });
          assert.strictEqual(enforced, true, 'Expected live cgroup v2 enforcement to succeed');
          assert.strictEqual(
            fs.readFileSync(path.join(payloadCg, 'memory.max'), 'utf8').trim(),
            String(1024 * 1024 * 1024),
            'Expected exact 1073741824 bytes (1024 MiB) in memory.max'
          );
          assert.strictEqual(
            fs.readFileSync(path.join(payloadCg, 'cpu.max'), 'utf8').trim(),
            '100000 100000',
            'Expected exact 1 vCPU CFS quota in cpu.max'
          );
          const cpusetAssigned = fs.readFileSync(path.join(payloadCg, 'cpuset.cpus'), 'utf8').trim();
          assert.strictEqual(cpusetAssigned.split(',').length, 1, 'Expected 1 CPU core pinned in cpuset.cpus');

          // Spawn a real subshell inside `payloadCg` and verify kernel `nproc` reports `1`!
          const nprocOut = execFileSync(
            'sudo',
            ['-n', 'sh', '-c', `echo $$ > ${payloadCg}/cgroup.procs && nproc`],
            { encoding: 'utf8' }
          ).trim();
          assert.strictEqual(nprocOut, '1', `Expected guest nproc inside 1-vCPU cgroup to be 1, got ${nprocOut}`);

          // Live hot-scale RAM to 2048 MiB without restart!
          await cmTest.enforceLiveContainerCgroups('cgroup-e2e-01', {
            ramMb: 2048,
            cpuCores: 1,
            pid: sleeper.pid,
          });
          assert.strictEqual(
            fs.readFileSync(path.join(payloadCg, 'memory.max'), 'utf8').trim(),
            String(2048 * 1024 * 1024),
            'Expected live RAM hot-scale to 2048 MiB in memory.max'
          );
        } finally {
          if (sleeper) {
            try { sleeper.kill('SIGKILL'); } catch (_) {}
            await new Promise((r) => setTimeout(r, 80));
          }
          for (const cg of [payloadCg, legacyBrokenPayload, legacyHostCg]) {
            try { execFileSync('sudo', ['-n', 'rmdir', cg]); } catch (_) {}
          }
        }

        // 4. Real Linux 6.8 cgroup-namespace `"domain threaded"` -> `"domain invalid"` (`ENOTSUP` / `-95`)
        // reproduction & live self-heal regression test (exact `cgfsng.c:3341` + `cgfsng.c:1539` fix)!
        const simCgnsRoot = '/sys/fs/cgroup/tgv_t19_cgns_root';
        const simInitScope = path.join(simCgnsRoot, 'init.scope');
        const simHkvmLxc = path.join(simCgnsRoot, 'hkvm.lxc');
        const simMonitor = path.join(simHkvmLxc, 'lxc.monitor.test');
        const simPayload = path.join(simHkvmLxc, 'lxc.payload.test');
        let hostPid1Sim = null;
        let monPidSim = null;
        let payPidSim = null;
        try {
          // Ensure parent `/sys/fs/cgroup` delegates all available controllers into `simCgnsRoot`
          ensureCgroupV2SubtreeDelegation('/sys/fs/cgroup');
          execFileSync('sudo', ['-n', 'mkdir', '-p', simCgnsRoot]);

          hostPid1Sim = spawn('sleep', ['30'], { stdio: 'ignore' });
          monPidSim = spawn('sleep', ['30'], { stdio: 'ignore' });
          payPidSim = spawn('sleep', ['30'], { stdio: 'ignore' });

          // Reproduce broken cgroup-namespace state: host task inside `simCgnsRoot/cgroup.procs`
          // while threaded controllers (`+cpu +cpuset +pids`) were enabled BEFORE evacuating `cgroup.procs`!
          privilegedFs.writeFileSync(path.join(simCgnsRoot, 'cgroup.procs'), `${hostPid1Sim.pid}\n`);
          privilegedFs.writeFileSync(path.join(simCgnsRoot, 'cgroup.subtree_control'), '+cpu +cpuset +pids');
          execFileSync('sudo', ['-n', 'mkdir', '-p', simInitScope, simHkvmLxc, simMonitor]);

          assert.strictEqual(readCgroupV2Type(simCgnsRoot), 'domain threaded');
          assert.strictEqual(readCgroupV2Type(simInitScope), 'domain invalid');
          assert.strictEqual(readCgroupV2Type(simHkvmLxc), 'domain invalid');
          assert.strictEqual(isUsableDomainCgroupDir(simHkvmLxc), false);

          // Confirm exact `liblxc` `cgfsng.c:3341` + `cgfsng.c:1539` `ENOTSUP` failures BEFORE heal
          const simAvailCtrls = fs
            .readFileSync(path.join(simCgnsRoot, 'cgroup.controllers'), 'utf8')
            .trim()
            .split(/\s+/)
            .filter(Boolean);
          const liblxcDelegateStr = simAvailCtrls.map((c) => `+${c}`).join(' ');
          assert.throws(
            () => privilegedFs.writeFileSync(path.join(simCgnsRoot, 'cgroup.subtree_control'), liblxcDelegateStr),
            /Operation not supported|ENOTSUP/i
          );
          assert.throws(
            () => privilegedFs.writeFileSync(path.join(simMonitor, 'cgroup.procs'), `${monPidSim.pid}\n`),
            /Operation not supported|ENOTSUP/i
          );

          // Now run `ensureCgroupV2SubtreeDelegation(simCgnsRoot)` — must heal `domain threaded` -> `domain`,
          // evacuate `hostPid1Sim` into `simCgnsRoot/init.scope`, and delegate ALL controllers on `hkvm.lxc`!
          ensureCgroupV2SubtreeDelegation(simCgnsRoot);

          assert.strictEqual(readCgroupV2Type(simCgnsRoot), 'domain');
          assert.strictEqual(fs.readFileSync(path.join(simCgnsRoot, 'cgroup.procs'), 'utf8').trim(), '');
          assert.strictEqual(readCgroupV2Type(simInitScope), 'domain');
          assert.ok(
            fs.readFileSync(path.join(simInitScope, 'cgroup.procs'), 'utf8').includes(String(hostPid1Sim.pid)),
            'Expected host process evacuated into simCgnsRoot/init.scope'
          );
          assert.strictEqual(readCgroupV2Type(simHkvmLxc), 'domain');
          assert.strictEqual(isUsableDomainCgroupDir(simHkvmLxc), true);

          // Verify `liblxc` `__cgfsng_delegate_controllers` + `cgfsng_monitor_enter` + payload limits now SUCCEED!
          privilegedFs.writeFileSync(path.join(simCgnsRoot, 'cgroup.subtree_control'), liblxcDelegateStr);
          privilegedFs.writeFileSync(path.join(simHkvmLxc, 'cgroup.subtree_control'), liblxcDelegateStr);
          execFileSync('sudo', ['-n', 'mkdir', '-p', simMonitor, simPayload]);
          privilegedFs.writeFileSync(path.join(simMonitor, 'cgroup.procs'), `${monPidSim.pid}\n`);
          privilegedFs.writeFileSync(path.join(simPayload, 'cgroup.procs'), `${payPidSim.pid}\n`);
          privilegedFs.writeFileSync(path.join(simPayload, 'memory.max'), `${512 * 1024 * 1024}\n`);
          assert.strictEqual(
            fs.readFileSync(path.join(simPayload, 'memory.max'), 'utf8').trim(),
            String(512 * 1024 * 1024)
          );

          // 5. Verify `restoreStrippedCgroupDirectivesIfReady()` heals a container `config` whose
          // `lxc.cgroup.dir = hkvm.lxc` and `lxc.cgroup2.memory.max` were stripped during an earlier failed start!
          const healCfgDir = path.join(process.env.TGVPANEL_LXC_PATH, 'stripped-test-heal');
          fs.mkdirSync(healCfgDir, { recursive: true });
          fs.writeFileSync(
            path.join(healCfgDir, 'config'),
            [
              '# --- BEGIN HKVM MANAGED CONFIG ---',
              '# hkvm.limits: ram_mb=1024 swap_mb=256 cpu_cores=2 cpu_pct=100 pinning=',
              'lxc.uts.name = stripped-test-heal',
              '# --- END HKVM MANAGED CONFIG ---',
              '',
            ].join('\n')
          );
          const cmHeal = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
          const didRestore = cmHeal.restoreStrippedCgroupDirectivesIfReady('stripped-test-heal');
          assert.strictEqual(didRestore, true, 'Expected stripped cgroup directives to be restored');
          const restoredCfgTxt = fs.readFileSync(path.join(healCfgDir, 'config'), 'utf8');
          assert.ok(restoredCfgTxt.includes('lxc.cgroup.dir = hkvm.lxc'), 'Expected lxc.cgroup.dir = hkvm.lxc restored');
          assert.ok(restoredCfgTxt.includes('lxc.cgroup2.memory.max = 1024M'), 'Expected memory.max = 1024M restored');
          assert.ok(restoredCfgTxt.includes('lxc.cgroup2.cpu.max = 200000 100000'), 'Expected cpu.max = 200000 100000 restored');
          fs.rmSync(healCfgDir, { recursive: true, force: true });
        } finally {
          for (const p of [hostPid1Sim, monPidSim, payPidSim]) {
            if (p) {
              try { p.kill('SIGKILL'); } catch (_) {}
            }
          }
          await new Promise((r) => setTimeout(r, 80));
          for (const cg of [simPayload, simMonitor, simHkvmLxc, simInitScope, simCgnsRoot]) {
            try { execFileSync('sudo', ['-n', 'rmdir', cg]); } catch (_) {}
          }
        }
      }
    });

    await runStep('T20: KVM VM deletion (DELETE /api/vms/:id & Unified /api/v1/instances) permanently removes VM across page refreshes', async () => {
      const vmDir = path.join(os.homedir(), 'vms');
      fs.mkdirSync(vmDir, { recursive: true });

      // 1. Test `DELETE /api/vms/:vm_id` on a VM with active `vm_logs`, `vm_snapshots`, disk/seed files & `instances` registry row
      const disk1 = path.join(tmpRoot, 'vm-del-test-1.qcow2');
      const seed1 = path.join(tmpRoot, 'vm-del-test-1-seed.iso');
      fs.writeFileSync(disk1, 'qcow2-test-bytes');
      fs.writeFileSync(seed1, 'seed-test-bytes');

      const ins1 = await ctx.db.run(
        `INSERT INTO vms (vm_name, hostname, owner_id, memory, cpus, disk_size, disk_file, seed_file, status, password)
         VALUES ('delete-persist-vm-01', 'del-vm-01', 1, 2048, 2, '20G', ?, ?, 'stopped', ?)`,
        [disk1, seed1, encryptSecret('DelPass1!')]
      );
      const delVmId1 = ins1.lastID;
      await ctx.db.run(
        `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, 'create', 'pending', 'VM created')`,
        [delVmId1]
      );
      await ctx.db.run(
        `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, 'start', 'running', 'VM started')`,
        [delVmId1]
      );
      await ctx.db.run(
        `INSERT INTO vm_snapshots (vm_id, snapshot_name, size_gb, description) VALUES (?, 'pre-delete-snap', 0.5, 'test snap')`,
        [delVmId1]
      );
      await ctx.kvmAdapter.syncRegistryRow(delVmId1);

      // Verify VM appears in all 3 refresh endpoints BEFORE deletion
      const beforeAdminList = await adminClient.request('GET', '/api/admin/vms');
      assert.strictEqual(beforeAdminList.status, 200);
      assert.ok(beforeAdminList.json.some((v) => v.vm_id === delVmId1), 'Expected VM in /api/admin/vms before delete');

      const beforeUserList = await adminClient.request('GET', '/api/vms');
      assert.strictEqual(beforeUserList.status, 200);
      assert.ok(beforeUserList.json.some((v) => v.vm_id === delVmId1), 'Expected VM in /api/vms before delete');

      const beforeUnifiedList = await adminClient.request('GET', '/api/v1/instances?engine=kvm');
      assert.strictEqual(beforeUnifiedList.status, 200);
      assert.ok(
        beforeUnifiedList.json.instances.some((i) => i.engine === 'kvm' && i.refId === delVmId1),
        'Expected VM in /api/v1/instances before delete'
      );

      // Delete via `DELETE /api/vms/:vm_id` (used by `/admin/vms`, `/admin/vm/:id`, `/vm/:id`)
      const delRes1 = await adminClient.request('DELETE', `/api/vms/${delVmId1}`);
      assert.strictEqual(delRes1.status, 200, `DELETE /api/vms/${delVmId1} failed: ${delRes1.text}`);
      assert.strictEqual(delRes1.json.success, true);

      // Simulate page refresh immediately after delete — VM must NOT reappear anywhere!
      const afterAdminList = await adminClient.request('GET', '/api/admin/vms');
      assert.strictEqual(afterAdminList.status, 200);
      assert.ok(
        String(afterAdminList.headers['cache-control'] || '').includes('no-store'),
        'Expected Cache-Control: no-store on /api/admin/vms'
      );
      assert.strictEqual(
        afterAdminList.json.some((v) => v.vm_id === delVmId1),
        false,
        'Deleted VM must NOT reappear in /api/admin/vms on refresh!'
      );

      const afterUserList = await adminClient.request('GET', '/api/vms');
      assert.strictEqual(
        afterUserList.json.some((v) => v.vm_id === delVmId1),
        false,
        'Deleted VM must NOT reappear in /api/vms on refresh!'
      );

      const afterUnifiedList = await adminClient.request('GET', '/api/v1/instances?engine=kvm');
      assert.strictEqual(
        afterUnifiedList.json.instances.some((i) => i.engine === 'kvm' && i.refId === delVmId1),
        false,
        'Deleted VM must NOT reappear in /api/v1/instances on refresh!'
      );

      assert.strictEqual((await adminClient.request('GET', `/api/vms/${delVmId1}`)).status, 404);
      assert.strictEqual(fs.existsSync(disk1), false, 'Expected VM disk file removed');
      assert.strictEqual(fs.existsSync(seed1), false, 'Expected VM seed file removed');
      assert.strictEqual((await ctx.db.all(`SELECT * FROM vm_logs WHERE vm_id = ?`, [delVmId1])).length, 0);
      assert.strictEqual((await ctx.db.all(`SELECT * FROM vm_snapshots WHERE vm_id = ?`, [delVmId1])).length, 0);

      // 2. Test Unified Instance delete (`POST /api/v1/instances/kvm/:id/action` `{ action: 'delete' }`)
      const ins2 = await ctx.db.run(
        `INSERT INTO vms (vm_name, hostname, owner_id, memory, cpus, disk_size, status, password)
         VALUES ('delete-persist-vm-02', 'del-vm-02', 1, 1024, 1, '10G', 'stopped', ?)`,
        [encryptSecret('DelPass2!')]
      );
      const delVmId2 = ins2.lastID;
      await ctx.db.run(
        `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, 'create', 'pending', 'VM 2 created')`,
        [delVmId2]
      );
      await ctx.db.run(
        `INSERT INTO vm_snapshots (vm_id, snapshot_name, size_gb, description) VALUES (?, 'snap-2', 0.2, 'snap')`,
        [delVmId2]
      );
      await ctx.kvmAdapter.syncRegistryRow(delVmId2);

      const delRes2 = await adminClient.request('POST', `/api/v1/instances/kvm/${delVmId2}/action`, {
        action: 'delete',
      });
      assert.strictEqual(delRes2.status, 200, `Unified KVM delete failed: ${delRes2.text}`);

      const afterAdminList2 = await adminClient.request('GET', '/api/admin/vms');
      assert.strictEqual(
        afterAdminList2.json.some((v) => v.vm_id === delVmId2),
        false,
        'Unified-deleted KVM VM must NOT reappear in /api/admin/vms!'
      );
      const afterUnifiedList2 = await adminClient.request('GET', '/api/v1/instances');
      assert.strictEqual(
        afterUnifiedList2.json.instances.some((i) => i.engine === 'kvm' && i.refId === delVmId2),
        false,
        'Unified-deleted KVM VM must NOT reappear in /api/v1/instances!'
      );
    });

    // 21. Advanced Node Studio Features (Pre-flight Probe, Inspector, Tags/Quotas, Cordon & Placement Advisor, Circuit Reset)
    await runStep('T21: Cluster Node Studio features (pre-flight probe, inspector detail, tags/quotas, cordon & placement advisor, circuit reset)', async () => {
      // 21a. Pre-flight connection probe against live loopback agent AND closed port
      const okProbe = await adminClient.request('POST', '/api/v1/nodes/test-connection', {
        url: `http://127.0.0.1:${AGENT_PORT}`,
        verifySsl: false,
      });
      assert.strictEqual(okProbe.status, 200, `Expected 200 from test-connection: ${okProbe.text}`);
      assert.strictEqual(okProbe.json.reachable, true);
      assert.strictEqual(okProbe.json.agentDetected, true);
      assert.ok(Number(okProbe.json.latencyMs) >= 1);

      const failProbe = await adminClient.request('POST', '/api/v1/nodes/test-connection', {
        url: 'http://127.0.0.1:59999',
        verifySsl: false,
        timeoutMs: 1200,
      });
      assert.strictEqual(failProbe.status, 200);
      assert.strictEqual(failProbe.json.reachable, false);
      assert.ok(String(failProbe.json.message || '').includes('Unreachable'));

      // 21b. Enriched /api/v1/nodes & /api/v1/nodes/1/detail
      const listRes = await adminClient.request('GET', '/api/v1/nodes');
      assert.strictEqual(listRes.status, 200);
      const localNode = listRes.json.nodes.find((n) => n.id === 1);
      assert.ok(localNode, 'Expected localhost node #1');
      assert.strictEqual(typeof localNode.total_instances, 'number');
      assert.strictEqual(typeof localNode.allocated_vcpus, 'number');
      assert.strictEqual(typeof localNode.allocated_ram_mb, 'number');

      const detailRes = await adminClient.request('GET', '/api/v1/nodes/1/detail');
      assert.strictEqual(detailRes.status, 200, `Node detail failed: ${detailRes.text}`);
      assert.strictEqual(detailRes.json.node.id, 1);
      assert.ok(Array.isArray(detailRes.json.instances), 'Expected hosted instances array in node detail');
      assert.ok(Array.isArray(detailRes.json.storagePools), 'Expected storagePools array in node detail');
      assert.ok(detailRes.json.liveStats && typeof detailRes.json.liveStats.cpuPercent === 'number');

      // 21c. Update tags, notes, maxInstances & Cordon (maintenanceMode), then verify Placement Advisor
      const patchCordon = await adminClient.request('PATCH', '/api/v1/nodes/1', {
        tags: 'nvme, production, controller',
        notes: 'Primary bare-metal NVMe controller',
        maxInstances: 250,
        maintenanceMode: true,
      });
      assert.strictEqual(patchCordon.status, 200, `PATCH node failed: ${patchCordon.text}`);
      assert.strictEqual(patchCordon.json.node.maintenance_mode, 1);
      assert.strictEqual(patchCordon.json.node.max_instances, 250);
      assert.deepStrictEqual(JSON.parse(patchCordon.json.node.tags), ['nvme', 'production', 'controller']);

      const placeCordoned = await adminClient.request('GET', '/api/v1/nodes/placement');
      assert.strictEqual(placeCordoned.status, 200);
      const localKvmRank = placeCordoned.json.kvm.find((c) => c.nodeId === 1);
      assert.strictEqual(localKvmRank.eligible, false, 'Cordoned node must be ineligible in Placement Advisor');

      const patchUncordon = await adminClient.request('PATCH', '/api/v1/nodes/1', {
        maintenanceMode: false,
      });
      assert.strictEqual(patchUncordon.status, 200);
      assert.strictEqual(patchUncordon.json.node.maintenance_mode, 0);

      const placeActive = await adminClient.request('GET', '/api/v1/nodes/placement');
      const localKvmRankAfter = placeActive.json.kvm.find((c) => c.nodeId === 1);
      assert.strictEqual(localKvmRankAfter.eligible, true, 'Uncordoned online node must be eligible in Placement Advisor');

      // 21d. Reset Circuit Breaker endpoint & UI markup verification
      const rstRes = await adminClient.request('POST', '/api/v1/nodes/1/reset-circuit', { probe: true });
      assert.strictEqual(rstRes.status, 200);
      assert.strictEqual(rstRes.json.node.circuit_state, 'closed');

      const nodesPage = await adminClient.request('GET', '/admin/nodes');
      assert.strictEqual(nodesPage.status, 200);
      assert.ok(nodesPage.text.includes('nodeInspectorModal'), 'Expected Node Inspector Modal on /admin/nodes');
      assert.ok(nodesPage.text.includes('placementAdvisorPanel'), 'Expected Smart Placement Advisor on /admin/nodes');
      assert.ok(nodesPage.text.includes('testNodeConnBtn'), 'Expected Test Reachability button on /admin/nodes');
      assert.ok(nodesPage.text.includes('nodesCardsWrap'), 'Expected Cards View container on /admin/nodes');
    });

    // 22. Multi-Node End-to-End Acceptance Suite (Self-Signed HTTPS Node Agent, 1-Command Join Token, TOFU TLS Pinning,
    //     Active Push Heartbeat, Stale Rotated-Cred Recovery, Remote Custom Template Staging, Remote LXC Lifecycle,
    //     Remote Storage statfs, Remote Port-Forward/Firewall, Multi-Node Sync-Host, Cross-Node Backup Restore & Remote WSS PTY)
    await runStep('T22: Multi-Node HTTPS self-signed pairing, TOFU TLS pinning, push heartbeat, remote LXC/storage/network/sync/migration & WSS PTY', async () => {
      const { execFileSync } = require('child_process');
      const { createNodeAgentServer } = require('../lib/node-agent/agent');
      const { NodeAgentAuthenticator } = require('../lib/node-agent/authentication');

      const HTTPS_AGENT_PORT = AGENT_PORT + 51;
      const sslDir = path.join(tmpRoot, 'https-agent-ssl');
      const httpsLxcDir = path.join(tmpRoot, 'https-agent-lxc');
      const httpsBackupDir = path.join(tmpRoot, 'https-agent-backups');
      const httpsDataDir = path.join(tmpRoot, 'https-agent-data');
      fs.mkdirSync(sslDir, { recursive: true });
      fs.mkdirSync(httpsLxcDir, { recursive: true });
      fs.mkdirSync(httpsBackupDir, { recursive: true });
      fs.mkdirSync(httpsDataDir, { recursive: true });
      rootOwnedCleanupDirs.push(httpsLxcDir);

      // 22a. Verify stale persisted node-agent-credentials.json is automatically superseded when .env bootstrap keys change!
      const staleCredsFile = path.join(httpsDataDir, 'node-agent-credentials.json');
      fs.writeFileSync(
        staleCredsFile,
        JSON.stringify({
          nodeId: 'stale-node',
          apiKeyHash: hashApiKey('old_dead_key'),
          hmacSecret: 'old_dead_hmac',
          envBootstrapHash: hashApiKey('old_dead_key:old_dead_hmac'),
        }),
        { mode: 0o600 }
      );
      const freshAuth = new NodeAgentAuthenticator({
        nodeId: 'fresh-node',
        rawApiKey: '  "new_env_key_123" \r\n',
        apiKeyHash: '',
        hmacSecret: " 'new_env_hmac_456' \r\n",
        envBootstrapHash: hashApiKey('new_env_key_123:new_env_hmac_456'),
        requireMtls: false,
        credentialsFilePath: staleCredsFile,
        loadPersistedCredentials: true,
      });
      assert.strictEqual(
        fs.existsSync(staleCredsFile),
        false,
        'Stale node-agent-credentials.json must be removed when .env bootstrap keys are updated'
      );
      const validFreshHdrs = signAgentRequest({
        nodeId: 'fresh-node',
        apiKey: 'new_env_key_123',
        hmacSecret: 'new_env_hmac_456',
        method: 'GET',
        pathWithQuery: '/api/v1/health',
      });
      const authVerify = freshAuth.verifyRawHeaders({
        method: 'GET',
        pathWithQuery: '/reverse-proxy-prefix/api/v1/health',
        rawBody: '',
        apiKeyHeader: validFreshHdrs['X-API-Key'],
        timestampHeader: validFreshHdrs['X-HKVM-Timestamp'],
        nonceHeader: validFreshHdrs['X-HKVM-Nonce'],
        signatureHeader: validFreshHdrs['X-HKVM-Signature'],
      });
      assert.strictEqual(authVerify.ok, true, `Expected sanitized env key + reverse-proxy path verification to pass: ${authVerify.reason}`);

      // Verify specific clock-skew diagnostic message (>300s drift)
      const skewedCheck = freshAuth.verifyRawHeaders({
        method: 'GET',
        pathWithQuery: '/api/v1/health',
        rawBody: '',
        apiKeyHeader: 'new_env_key_123',
        timestampHeader: String(Math.floor(Date.now() / 1000) - 900),
        nonceHeader: crypto.randomBytes(16).toString('hex'),
        signatureHeader: 'deadbeef',
      });
      assert.strictEqual(skewedCheck.ok, false);
      assert.match(skewedCheck.reason || '', /clock skew too large/i);

      // 22b. Generate a real self-signed X.509 TLS certificate (intentionally WITHOUT IP SAN to prove TOFU leaf pinning works even without SAN!)
      const certPath = path.join(sslDir, 'agent.crt');
      const keyPath = path.join(sslDir, 'agent.key');
      execFileSync('openssl', [
        'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '365',
        '-keyout', keyPath, '-out', certPath,
        '-subj', '/CN=eu-https-node-03.internal',
      ], { stdio: 'ignore' });
      const certPem = fs.readFileSync(certPath, 'utf8');

      // Register remote node initially pointing at an unreachable port with strict Verify SSL = true
      const regHttpsNode = await adminClient.request('POST', '/api/v1/nodes', {
        name: 'eu-https-node-03',
        hostname: 'eu-https-node-03.internal',
        ipAddress: '127.0.0.1',
        url: '127.0.0.1:59997', // schemeless URL auto-normalized!
        location: 'Amsterdam, NL',
        verifySsl: true,
      });
      assert.strictEqual(regHttpsNode.status, 201, `Register node failed: ${regHttpsNode.text}`);
      const httpsNodeId = regHttpsNode.json.node.id;
      assert.strictEqual(regHttpsNode.json.node.url, 'http://127.0.0.1:59997', 'Schemeless URL normalized cleanly');

      // Retrieve non-destructive bootstrap credentials (.env)
      const bootRes = await adminClient.request('GET', `/api/v1/nodes/${httpsNodeId}/bootstrap`);
      assert.strictEqual(bootRes.status, 200, `Bootstrap endpoint failed: ${bootRes.text}`);
      assert.strictEqual(bootRes.json.apiKey, regHttpsNode.json.bootstrapCredentials.apiKey);
      assert.ok(bootRes.json.envSnippet.includes('TGVPANEL_NODE_API_KEY='));

      // Generate a 1-Command Single-Use Join Token & redeem it with the HTTPS agent's self-signed PEM!
      const joinTokRes = await adminClient.request('POST', `/api/v1/nodes/${httpsNodeId}/join-token`, {
        controllerUrl: baseUrl,
        ttlMinutes: 30,
      });
      assert.strictEqual(joinTokRes.status, 201, `Join token generation failed: ${joinTokRes.text}`);
      assert.ok(joinTokRes.json.token.startsWith('tgv_join_'));
      assert.ok(joinTokRes.json.curlJoinCommand.includes('--join'));

      // Redeem join token without session cookie (simulating remote server running `menu.sh --join`)
      const bareNodeClient = new SessionClient(baseUrl);
      const redeemRes = await bareNodeClient.request('POST', `/api/v1/nodes/join/${joinTokRes.json.token}`, {
        endpointUrl: `https://127.0.0.1:${HTTPS_AGENT_PORT}`,
        ipAddress: '127.0.0.1',
        hostname: 'eu-https-node-03.internal',
        agentPort: HTTPS_AGENT_PORT,
        tlsCertPem: certPem,
        verifySsl: true,
      });
      assert.strictEqual(redeemRes.status, 200, `Join token redemption failed: ${redeemRes.text}`);
      assert.strictEqual(redeemRes.json.nodeId, httpsNodeId);
      assert.strictEqual(redeemRes.json.apiKey, regHttpsNode.json.bootstrapCredentials.apiKey);

      // Single-use enforcement: second redemption of the same join token MUST be rejected!
      const replayJoin = await bareNodeClient.request('POST', `/api/v1/nodes/join/${joinTokRes.json.token}`, {
        endpointUrl: `https://127.0.0.1:${HTTPS_AGENT_PORT}`,
      });
      assert.strictEqual(replayJoin.status, 400, 'Redeemed join token must reject reuse');
      assert.match(replayJoin.json.error || '', /already been redeemed/i);

      // Start the real standalone HTTPS Node Agent with self-signed TLS + interactiveHostShell + controllerUrl
      const httpsAgentInst = createNodeAgentServer({
        host: '127.0.0.1',
        port: HTTPS_AGENT_PORT,
        nodeId: String(httpsNodeId),
        apiKey: redeemRes.json.apiKey,
        hmacSecret: redeemRes.json.hmacSecret,
        tlsCertPath: certPath,
        tlsKeyPath: keyPath,
        lxcBaseDir: httpsLxcDir,
        backupDir: httpsBackupDir,
        dataDir: httpsDataDir,
        interactiveHostShell: true,
        controllerUrl: baseUrl,
        heartbeatIntervalMs: 120_000,
      });
      httpsAgentServer = httpsAgentInst.server;
      await new Promise((resolve) => httpsAgentServer.listen(HTTPS_AGENT_PORT, '127.0.0.1', resolve));

      // Pre-flight probe WITH strict verifySsl=true (unpinned probe) detects self-signed TGVPANEL agent & extracts PEM!
      const strictProbe = await adminClient.request('POST', '/api/v1/nodes/test-connection', {
        url: `https://127.0.0.1:${HTTPS_AGENT_PORT}`,
        verifySsl: true,
      });
      assert.strictEqual(strictProbe.status, 200);
      assert.strictEqual(strictProbe.json.reachable, false);
      assert.strictEqual(strictProbe.json.selfSignedAgentDetected, true, `Expected selfSignedAgentDetected: ${strictProbe.text}`);
      assert.ok(strictProbe.json.tls && strictProbe.json.tls.certPem.includes('BEGIN CERTIFICATE'));

      // 22c. Verify Active Outbound Agent -> Controller Push Heartbeat wakes node to ONLINE!
      const hbSent = await httpsAgentInst.sendHeartbeatOnce();
      assert.strictEqual(hbSent, true, 'Expected outbound HMAC push-heartbeat to succeed');
      const afterHbDetail = await adminClient.request('GET', `/api/v1/nodes/${httpsNodeId}/detail?live=0`);
      assert.strictEqual(afterHbDetail.status, 200);
      assert.strictEqual(afterHbDetail.json.node.status, 'online', 'Push-heartbeat must mark node online');
      assert.strictEqual(afterHbDetail.json.node.tls_pinned, 1, 'Join token cert must set tls_pinned=1');

      // Also verify Controller -> HTTPS Node Agent live check & TOFU trust-tls over pinned self-signed cert!
      const trustRes = await adminClient.request('POST', `/api/v1/nodes/${httpsNodeId}/trust-tls`, {});
      assert.strictEqual(trustRes.status, 200, `trust-tls failed: ${trustRes.text}`);
      assert.strictEqual(trustRes.json.probeOk, true, 'Expected live HTTPS probe after TOFU pin to succeed');

      // Verify all fixed Node Inspector diagnostic presets against the remote HTTPS node!
      for (const preset of ['uptime', 'uname', 'memory', 'disk', 'network_links', 'bridges', 'lxc_list', 'sysctl_net']) {
        const dRes = await adminClient.request('POST', `/api/v1/nodes/${httpsNodeId}/diagnostics/${preset}`, {});
        assert.strictEqual(dRes.status, 200, `Remote diagnostic preset ${preset} failed: ${dRes.text}`);
        assert.strictEqual(typeof dRes.json.output, 'string');
        assert.ok(dRes.json.output.length > 0);
      }

      // 22d. Remote Storage Pool statfs, Remote NAT Port Forwarding & Remote Firewall Rule
      const remotePoolPath = path.join(httpsDataDir, 'remote-nvme-pool');
      const createRemotePool = await adminClient.request('POST', '/api/v1/storage/pools', {
        nodeId: httpsNodeId,
        name: 'amsterdam-nvme-lxc',
        poolType: 'dir',
        engineScope: 'lxc',
        path: remotePoolPath,
      });
      assert.strictEqual(createRemotePool.status, 201, `Remote storage pool create failed: ${createRemotePool.text}`);
      assert.strictEqual(fs.existsSync(remotePoolPath), true, 'Remote Node Agent must create storage pool directory');
      const syncedPools = await adminClient.request('GET', '/api/v1/storage/pools?sync=1');
      const amsPool = (syncedPools.json.pools || []).find((p) => p.name === 'amsterdam-nvme-lxc');
      assert.ok(amsPool && Number(amsPool.total_bytes) > 0, 'Remote storage pool must report real remote statfs total_bytes');

      // 22e. Deploy LXC container onto Remote HTTPS Node using Controller-hosted Custom Template Archive!
      const remoteCustomCt = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'ct-https-remote-01',
        hostname: 'ct-https-remote-01.tgv.local',
        nodeId: httpsNodeId,
        templateSlug: 'custom:hkvm-os-3',
        cpuCores: 2,
        ramMb: 512,
        diskGb: 8,
        ipv4Address: '10.0.3.188/24',
        ipv4Gateway: '10.0.3.1',
        provisionOnHost: true,
      });
      assert.strictEqual(remoteCustomCt.status, 201, `Remote custom template LXC create failed: ${remoteCustomCt.text}`);
      const remoteCtId = remoteCustomCt.json.instance.refId;
      assert.strictEqual(remoteCustomCt.json.instance.nodeId, httpsNodeId);
      assert.strictEqual(
        fs.existsSync(path.join(httpsLxcDir, 'ct-https-remote-01', 'rootfs', 'etc', 'custom-release')),
        true,
        'Custom template archive must be auto-staged & unpacked on remote HTTPS Node Agent!'
      );

      // Attach a NAT Port Forward & Firewall Rule on the remote HTTPS node
      const remotePf = await adminClient.request('POST', '/api/v1/network/ports', {
        instanceType: 'lxc',
        instanceRefId: remoteCtId,
        guestPort: 22,
        hostPort: 24222,
        protocol: 'tcp',
        description: 'Remote SSH forward',
      });
      assert.strictEqual(remotePf.status, 201, `Remote port-forward failed: ${remotePf.text}`);

      const remoteFw = await adminClient.request('POST', '/api/v1/network/firewall', {
        nodeId: httpsNodeId,
        direction: 'in',
        action: 'ACCEPT',
        protocol: 'tcp',
        destPort: '24222',
        comment: 'Allow remote SSH forward',
      });
      assert.strictEqual(remoteFw.status, 201, `Remote firewall rule failed: ${remoteFw.text}`);

      // Create backup of ct-https-remote-01 on httpsNodeId, then migrate to remoteNodeId & restore cross-node!
      const remoteBkp = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'lxc',
        refId: remoteCtId,
        label: 'pre-crossnode-mig',
      });
      assert.strictEqual(remoteBkp.status, 201, `Remote backup failed: ${remoteBkp.text}`);
      const remoteBkpId = remoteBkp.json.backup.backupId;

      const migCross = await adminClient.request('POST', '/api/v1/migrations', {
        lxcId: remoteCtId,
        targetNodeId: remoteNodeId,
        targetBridge: 'lxcbr0',
      });
      assert.strictEqual(migCross.status, 201, `Cross-agent migration failed: ${migCross.text}`);
      assert.strictEqual(migCross.json.migration.status, 'completed');

      // Verify port forward automatically relocated to target remoteNodeId!
      const pfAfterMig = await ctx.db.get(`SELECT * FROM port_forwards WHERE id = ?`, [
        remotePf.json.portForward.id,
      ]);
      assert.strictEqual(
        Number(pfAfterMig.node_id),
        Number(remoteNodeId),
        'Port forward must relocate to target node after LXC migration!'
      );

      // Restore backup (stored on httpsNodeId!) onto migrated container (now on remoteNodeId!)
      const crossRestore = await adminClient.request('POST', `/api/v1/backups/${remoteBkpId}/restore`, {});
      assert.strictEqual(crossRestore.status, 200, `Cross-node backup restore failed: ${crossRestore.text}`);
      assert.strictEqual(crossRestore.json.restored, true);

      // 22f. Multi-Node `sync-host`: create an untracked container directly on httpsNodeId and verify /api/v1/lxc/sync-host imports it with node_id = httpsNodeId!
      const untrackedDir = path.join(httpsLxcDir, 'untracked-remote-ct99');
      fs.mkdirSync(path.join(untrackedDir, 'rootfs', 'etc'), { recursive: true });
      fs.writeFileSync(
        path.join(untrackedDir, 'config'),
        'lxc.uts.name = untracked-remote-ct99\nlxc.rootfs.path = dir:' + path.join(untrackedDir, 'rootfs') + '\n'
      );
      const syncRemoteRes = await adminClient.request('POST', '/api/v1/lxc/sync-host', {});
      assert.strictEqual(syncRemoteRes.status, 200, `Multi-node sync-host failed: ${syncRemoteRes.text}`);
      assert.ok(
        (syncRemoteRes.json.imported || []).includes('untracked-remote-ct99'),
        `Expected untracked-remote-ct99 in imported list: ${syncRemoteRes.text}`
      );
      const importedRow = await ctx.db.get(
        `SELECT node_id FROM lxc_instances WHERE container_name = 'untracked-remote-ct99'`
      );
      assert.strictEqual(Number(importedRow.node_id), Number(httpsNodeId), 'Synced remote container must belong to remote node_id');

      // 22g. Bridged WSS Interactive Host PTY Shell to Remote HTTPS Node Agent (`/ws/nodes/:id/shell`)!
      const ptyOutput = await new Promise((resolve, reject) => {
        const ws = new WebSocket(
          `ws://127.0.0.1:${TEST_PORT}/ws/nodes/${httpsNodeId}/shell?cols=90&rows=24`,
          { headers: { Cookie: adminClient.cookie } }
        );
        let collected = '';
        const timer = setTimeout(() => {
          try { ws.close(); } catch (_) {}
          reject(new Error(`Timed out waiting for remote HTTPS PTY output (got: ${collected})`));
        }, 8000);
        ws.on('open', () => {
          ws.send(JSON.stringify({ type: 'input', data: 'echo MULTI_NODE_WSS_PTY_OK\r' }));
        });
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'output') {
              collected += msg.data;
              if (collected.includes('MULTI_NODE_WSS_PTY_OK')) {
                clearTimeout(timer);
                ws.close();
                resolve(collected);
              }
            } else if (msg.type === 'error') {
              clearTimeout(timer);
              ws.close();
              reject(new Error(`Remote PTY error: ${msg.message}`));
            }
          } catch (_) {}
        });
        ws.on('error', (e) => {
          clearTimeout(timer);
          reject(e);
        });
      });
      assert.ok(ptyOutput.includes('MULTI_NODE_WSS_PTY_OK'), 'Expected live PTY output bridged over WSS from remote node');
    });

    await runStep('T23: LXC VPS live CPU Load telemetry (systemd init.scope cgroup v2, cold first-load sample, memory>0 /proc cutime fallback & remote HTTPS node)', async () => {
      const { spawn, execFileSync } = require('child_process');
      const {
        resolveContainerPayloadCgroupV2Dir,
        readContainerCgroupResourceStats,
        ensureCgroupV2SubtreeDelegation,
        LxcContainerManager,
      } = require('../lib/node-agent/container-manager');
      const { privilegedFs, isRunningAsRoot, canPasswordlessSudo } =
        require('../lib/node-agent/command-runner');

      await adminClient.request('GET', '/lxc');

      // Provision a dedicated 1-vCPU LXC container for CPU telemetry verification
      const ctName = 'cpu-load-e2e-01';
      const createRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: ctName,
        hostname: 'cpu-load-e2e.tgvpanel.local',
        templateSlug: 'ubuntu:24.04',
        nodeId: 1,
        cpuCores: 1,
        cpuLimitPercent: 100,
        ramMb: 1024,
        swapMb: 256,
        diskGb: 10,
        startAfterCreate: true,
      });
      assert.strictEqual(createRes.status, 201, `Create ${ctName} failed: ${createRes.text}`);
      const lxcId = createRes.json.instance.refId;
      const ctDir = path.join(process.env.TGVPANEL_LXC_PATH, ctName);

      // Verify /lxc/:id UI template includes live formatCpuLoadPercent & 4s polling
      const detailHtml = await adminClient.request('GET', `/lxc/${lxcId}`);
      assert.strictEqual(detailHtml.status, 200);
      assert.ok(detailHtml.text.includes('formatCpuLoadPercent'), 'Expected formatCpuLoadPercent in /lxc/:id view');

      // Scenario 1: Real cgroup v2 `systemd` layout (`lxc.payload.<ct>/init.scope` idle PID 1
      // + `lxc.payload.<ct>/system.slice/worker.service` busy CPU worker) + cold first-load telemetry!
      if ((isRunningAsRoot() || canPasswordlessSudo()) && fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
        ensureCgroupV2SubtreeDelegation();
        const payloadCg = `/sys/fs/cgroup/hkvm.lxc/lxc.payload.${ctName}`;
        const guestInitScope = `${payloadCg}/init.scope`;
        const guestWorkerSvc = `${payloadCg}/system.slice/worker.service`;
        let busyWorker = null;
        try {
          const ctInitPid = parseInt(fs.readFileSync(path.join(ctDir, '.pid'), 'utf8').trim(), 10);
          assert.ok(ctInitPid > 1, 'Expected running container init PID');

          execFileSync('sudo', ['-n', 'mkdir', '-p', guestInitScope, guestWorkerSvc]);
          // Move idle container PID 1 into `<payload>/init.scope` just like systemd does on boot
          privilegedFs.writeFileSync(path.join(guestInitScope, 'cgroup.procs'), `${ctInitPid}\n`);

          // Spawn a real CPU-burning worker inside `<payload>/system.slice/worker.service`
          busyWorker = spawn(process.execPath, ['-e', 'const end = Date.now() + 8000; while (Date.now() < end) { Math.sqrt(Math.random()); }'], {
            stdio: 'ignore',
          });
          privilegedFs.writeFileSync(path.join(guestWorkerSvc, 'cgroup.procs'), `${busyWorker.pid}\n`);

          const resolvedPayloadDir = resolveContainerPayloadCgroupV2Dir(ctName, ctInitPid);
          assert.strictEqual(
            resolvedPayloadDir,
            payloadCg,
            `Expected resolveContainerPayloadCgroupV2Dir to strip /init.scope and return ${payloadCg}, got ${resolvedPayloadDir}`
          );

          const cgStat1 = readContainerCgroupResourceStats(ctName, ctInitPid);
          assert.strictEqual(cgStat1.source, 'cgroup-v2');
          assert.ok(cgStat1.cpuUseSeconds !== null && cgStat1.cpuUseSeconds >= 0);

          // Cold first-visit telemetry request MUST immediately return > 5% CPU (not 0%!)
          const coldTel = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/telemetry`);
          assert.strictEqual(coldTel.status, 200, `Cold telemetry failed: ${coldTel.text}`);
          assert.ok(
            coldTel.json.telemetry.cpuPercent > 5,
            `Expected cold first-visit LXC CPU Load > 5%, got ${coldTel.json.telemetry.cpuPercent}%`
          );

          // Warm second telemetry poll after 250ms MUST also return > 5% CPU
          await new Promise((r) => setTimeout(r, 260));
          const warmTel = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/telemetry`);
          assert.strictEqual(warmTel.status, 200);
          assert.ok(
            warmTel.json.telemetry.cpuPercent > 5,
            `Expected warm LXC CPU Load > 5%, got ${warmTel.json.telemetry.cpuPercent}%`
          );
        } finally {
          if (busyWorker) {
            try { busyWorker.kill('SIGKILL'); } catch (_) {}
          }
          // Evacuate container init PID back to /sys/fs/cgroup/init.scope so we can cleanly rmdir test cgroups
          try {
            const ctInitPid = parseInt(fs.readFileSync(path.join(ctDir, '.pid'), 'utf8').trim(), 10);
            if (ctInitPid > 1) {
              privilegedFs.writeFileSync('/sys/fs/cgroup/init.scope/cgroup.procs', `${ctInitPid}\n`);
            }
          } catch (_) {}
          await new Promise((r) => setTimeout(r, 80));
          for (const d of [
            `${payloadCg}/system.slice/worker.service`,
            `${payloadCg}/system.slice`,
            `${payloadCg}/init.scope`,
            payloadCg,
          ]) {
            try { execFileSync('sudo', ['-n', 'rmdir', d]); } catch (_) {}
          }
        }
      }

      // Scenario 2: Undelegated /proc fallback when `Memory use:` > 0 AND `CPU use:` is missing,
      // PLUS monotonic `cutime + cstime` preservation across exited & reaped child processes!
      const parentProc = spawn(
        process.execPath,
        [
          '-e',
          `
          const { spawnSync } = require('child_process');
          // 1) Burn CPU in a short-lived child that exits and is immediately reaped
          spawnSync(process.execPath, ['-e', 'const t = Date.now() + 180; while (Date.now() < t) { Math.imul(12345, 67890); }']);
          process.stdout.write('REAPED\\n');
          // 2) Spawn a live busy child for live /proc telemetry measurement
          const { spawn } = require('child_process');
          const c = spawn(process.execPath, ['-e', 'const t = Date.now() + 5000; while (Date.now() < t) { Math.sqrt(987654321); }'], { stdio: 'ignore' });
          setTimeout(() => { try { c.kill('SIGKILL'); } catch (_) {} process.exit(0); }, 5000);
          `,
        ],
        { stdio: ['ignore', 'pipe', 'ignore'] }
      );
      try {
        await new Promise((resolve, reject) => {
          const t = setTimeout(() => reject(new Error('Timed out waiting for REAPED signal')), 4000);
          parentProc.stdout.on('data', (d) => {
            if (d.toString().includes('REAPED')) {
              clearTimeout(t);
              resolve();
            }
          });
        });

        const localCm = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
        const procAfterReap = localCm.measureContainerProcTree(parentProc.pid);
        assert.ok(
          procAfterReap.cpuUseSeconds >= 0.05,
          `Expected reaped child CPU ticks (cutime+cstime) preserved >= 0.05s, got ${procAfterReap.cpuUseSeconds}s`
        );

        // Point container `.pid` at `parentProc.pid` (which lives in shared host cgroup, NOT lxc.payload.*)
        // AND touch `.omit_cpu_use` so `lxc-info` emits `Memory use: 64.25 MiB` (>0) while omitting `CPU use:`!
        const origPid = privilegedFs.readTextSync(path.join(ctDir, '.pid'));
        const omitCpuMarker = path.join(ctDir, '.omit_cpu_use');
        execFileSync('sudo', ['-n', 'touch', omitCpuMarker]);
        privilegedFs.writeFileSync(path.join(ctDir, '.pid'), `${parentProc.pid}\n`);
        try {
          const procTel = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/telemetry`);
          assert.strictEqual(procTel.status, 200);
          assert.ok(
            procTel.json.telemetry.ramUsedMb >= 60,
            `Expected Memory use > 60 MB preserved, got ${procTel.json.telemetry.ramUsedMb} MB`
          );
          assert.ok(
            procTel.json.telemetry.cpuPercent > 3,
            `Expected /proc CPU Load > 3% even when Memory use > 0 and lxc-info omits CPU use, got ${procTel.json.telemetry.cpuPercent}%`
          );
        } finally {
          privilegedFs.writeFileSync(path.join(ctDir, '.pid'), origPid);
          execFileSync('sudo', ['-n', 'rm', '-f', omitCpuMarker]);
        }
      } finally {
        try { execFileSync('pkill', ['-KILL', '-P', String(parentProc.pid)]); } catch (_) {}
        try { parentProc.kill('SIGKILL'); } catch (_) {}
      }

      // Scenario 3: Remote Node Agent live CPU Load telemetry (`?telemetry=1` over HMAC HTTP)
      if ((isRunningAsRoot() || canPasswordlessSudo()) && fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
        const remCtName = 'cpu-rem-e2e-01';
        const remCreate = await adminClient.request('POST', '/api/v1/lxc', {
          containerName: remCtName,
          hostname: 'cpu-rem-e2e.tgvpanel.local',
          templateSlug: 'ubuntu:24.04',
          nodeId: remoteNodeId,
          cpuCores: 2,
          cpuLimitPercent: 100,
          ramMb: 1024,
          swapMb: 256,
          diskGb: 10,
          startAfterCreate: true,
        });
        assert.strictEqual(remCreate.status, 201, `Remote create failed: ${remCreate.text}`);
        const remLxcId = remCreate.json.instance.refId;
        const remCtDir = path.join(tmpRoot, 'agent-lxc', remCtName);
        const remPayloadCg = `/sys/fs/cgroup/hkvm.lxc/lxc.payload.${remCtName}`;
        let remWorker = null;
        try {
          const remInitPid = parseInt(privilegedFs.readTextSync(path.join(remCtDir, '.pid')).trim(), 10);
          execFileSync('sudo', ['-n', 'mkdir', '-p', `${remPayloadCg}/init.scope`]);
          privilegedFs.writeFileSync(`${remPayloadCg}/init.scope/cgroup.procs`, `${remInitPid}\n`);
          remWorker = spawn(process.execPath, ['-e', 'const end = Date.now() + 8000; while (Date.now() < end) { Math.sqrt(Math.random()); }'], {
            stdio: 'ignore',
          });
          privilegedFs.writeFileSync(`${remPayloadCg}/cgroup.procs`, `${remWorker.pid}\n`);

          const remColdTel = await adminClient.request('GET', `/api/v1/instances/lxc/${remLxcId}/telemetry`);
          assert.strictEqual(remColdTel.status, 200, `Remote cold telemetry failed: ${remColdTel.text}`);
          assert.ok(
            remColdTel.json.telemetry.cpuPercent > 5,
            `Expected remote LXC CPU Load > 5% on cold first open, got ${remColdTel.json.telemetry.cpuPercent}%`
          );
        } finally {
          if (remWorker) {
            try { remWorker.kill('SIGKILL'); } catch (_) {}
          }
          try {
            const remInitPid = parseInt(privilegedFs.readTextSync(path.join(remCtDir, '.pid')).trim(), 10);
            if (remInitPid > 1) {
              privilegedFs.writeFileSync('/sys/fs/cgroup/init.scope/cgroup.procs', `${remInitPid}\n`);
            }
          } catch (_) {}
          await new Promise((r) => setTimeout(r, 80));
          for (const d of [`${remPayloadCg}/init.scope`, remPayloadCg]) {
            try { execFileSync('sudo', ['-n', 'rmdir', d]); } catch (_) {}
          }
        }
      }
    });

    // 24. Proxmox VE 8 & 9 OS Templates on QEMU/KVM Virtual Machine Creation
    await runStep('T24: Proxmox VE 8 & 9 QEMU/KVM OS templates, Cloud-Init ISO bootstrap, NAT :8006 forwarding, reinstall & UI', async () => {
      const { isEncryptedSecret } = require('../lib/security/crypto-vault');
      const vmDir = path.join(os.homedir(), 'vms');
      const templatesDir = path.join(vmDir, 'templates');
      const cloudVmDir = path.join(os.homedir(), 'cloudvm');
      fs.mkdirSync(templatesDir, { recursive: true });
      fs.mkdirSync(cloudVmDir, { recursive: true });

      // 24a. Verify all built-in OS templates use local /images/os/*.svg icons & Proxmox VE 8/9 metadata
      const osTplRes = await adminClient.request('GET', '/api/os-templates');
      assert.strictEqual(osTplRes.status, 200);
      assert.strictEqual(osTplRes.json.ubuntu_22_cloud.icon, '/images/os/ubuntu.svg');
      assert.strictEqual(osTplRes.json.ubuntu_24_cloud.icon, '/images/os/ubuntu.svg');
      assert.strictEqual(osTplRes.json.debian_12_cloud.icon, '/images/os/debian.svg');
      assert.strictEqual(osTplRes.json.fedora_40_cloud.icon, '/images/os/fedora.svg');
      assert.strictEqual(osTplRes.json.centos_9_cloud.icon, '/images/os/centos.svg');
      assert.strictEqual(osTplRes.json.almalinux_9_cloud.icon, '/images/os/almalinux.svg');
      assert.ok(osTplRes.json.proxmox_ve_8, 'Expected proxmox_ve_8 in /api/os-templates');
      assert.ok(osTplRes.json.proxmox_ve_9, 'Expected proxmox_ve_9 in /api/os-templates');
      assert.strictEqual(osTplRes.json.proxmox_ve_8.name, 'Proxmox VE 8');
      assert.strictEqual(osTplRes.json.proxmox_ve_8.memory, 4096);
      assert.strictEqual(osTplRes.json.proxmox_ve_8.cpus, 4);
      assert.strictEqual(osTplRes.json.proxmox_ve_8.disk_size, '40G');
      assert.strictEqual(osTplRes.json.proxmox_ve_8.username, 'root');
      assert.strictEqual(osTplRes.json.proxmox_ve_8.web_port, 8006);
      assert.strictEqual(osTplRes.json.proxmox_ve_8.icon, '/images/os/proxmox.svg');
      assert.strictEqual(osTplRes.json.proxmox_ve_9.name, 'Proxmox VE 9');
      assert.strictEqual(osTplRes.json.proxmox_ve_9.proxmox_codename, 'trixie');
      assert.strictEqual(
        osTplRes.json.proxmox_ve_9.proxmox_gpg_url,
        'https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg'
      );
      assert.strictEqual(osTplRes.json.proxmox_ve_9.icon, '/images/os/proxmox.svg');
      for (const [k, tpl] of Object.entries(osTplRes.json)) {
        assert.strictEqual(
          String(tpl.icon || '').includes('imgur.com'),
          false,
          `Template ${k} must not use external imgur.com icon`
        );
      }

      const adminTplRes = await adminClient.request('GET', '/api/admin/templates');
      assert.strictEqual(adminTplRes.status, 200);
      const adminTplList = Array.isArray(adminTplRes.json) ? adminTplRes.json : (adminTplRes.json.templates || []);
      assert.ok(
        adminTplList.some((t) => t.template_key === 'proxmox_ve_8' && t.web_port === 8006),
        'Expected proxmox_ve_8 in /api/admin/templates'
      );
      assert.ok(
        adminTplList.some((t) => t.template_key === 'proxmox_ve_9' && t.web_port === 8006),
        'Expected proxmox_ve_9 in /api/admin/templates'
      );

      for (const svgName of ['proxmox.svg', 'ubuntu.svg', 'debian.svg', 'fedora.svg', 'centos.svg', 'almalinux.svg', 'linux.svg']) {
        const svgRes = await adminClient.request('GET', `/images/os/${svgName}`);
        assert.strictEqual(svgRes.status, 200, `Expected /images/os/${svgName} to return 200`);
        assert.ok(svgRes.text.includes('<svg'), `Expected valid SVG payload for ${svgName}`);
      }

      const builtinView8 = await adminClient.request('GET', '/admin/templates/builtin/proxmox_ve_8/edit');
      assert.strictEqual(builtinView8.status, 200);
      assert.ok(builtinView8.text.includes('Proxmox VE 8'));

      const vmCreateHtml = await adminClient.request('GET', '/admin/vm-create');
      assert.strictEqual(vmCreateHtml.status, 200);
      assert.ok(vmCreateHtml.text.includes('proxmoxWebPortGroup'), 'Expected Proxmox Web UI Port field in /admin/vm-create');
      assert.ok(vmCreateHtml.text.includes('isProxmoxTemplateKey'), 'Expected Proxmox template detection in /admin/vm-create');

      // 24b. Prepare cached cloud images & temporary qemu-img shim if host lacks qemu-img binary
      const origPath = process.env.PATH || '';
      const createdTemplateFiles = [];
      const createdVmIds = [];
      const deb12Cache = path.join(templatesDir, 'debian_12_cloud-template.qcow2');
      const pve9Cache = path.join(templatesDir, 'proxmox_ve_9-template.qcow2');
      const ubu22Cache = path.join(templatesDir, 'ubuntu_22_cloud-template.qcow2');
      for (const f of [deb12Cache, pve9Cache, ubu22Cache]) {
        if (!fs.existsSync(f)) {
          fs.writeFileSync(f, Buffer.from('QFI\xfb\x00\x00\x00\x03test-qcow2-template'));
          createdTemplateFiles.push(f);
        }
      }

      let hasRealQemuImg = false;
      try {
        require('child_process').execSync('command -v qemu-img', { stdio: 'pipe' });
        hasRealQemuImg = true;
      } catch (_) {}

      if (!hasRealQemuImg) {
        const fakeBinDir = path.join(tmpRoot, 'qemu-test-bin');
        fs.mkdirSync(fakeBinDir, { recursive: true });
        const fakeQemuImg = path.join(fakeBinDir, 'qemu-img');
        fs.writeFileSync(
          fakeQemuImg,
          `#!/bin/bash
set -e
CMD="$1"
shift
if [ "$CMD" = "convert" ]; then
  while [ "$#" -gt 2 ]; do shift; done
  cp "$1" "$2"
elif [ "$CMD" = "resize" ]; then
  exit 0
elif [ "$CMD" = "create" ]; then
  while [ "$#" -gt 2 ]; do shift; done
  printf 'QFI\\xfb' > "$1"
fi
`,
          { mode: 0o755 }
        );
        process.env.PATH = `${fakeBinDir}:${origPath}`;
      }

      try {
        // 24c. Create Proxmox VE 8 VM in NAT mode (verifies shared debian_12_cloud cache reuse, defaults & seed ISO)
        const createPve8 = await adminClient.request('POST', '/api/vms', {
          vm_name: 'pve8-hypervisor-01',
          os_template: 'proxmox_ve_8',
          hostname: 'pve8-node1',
          network_type: 'nat',
          ssh_port: 22806,
          custom_password: 'Pve8Root!Secret',
        });
        assert.strictEqual(createPve8.status, 200, `Proxmox VE 8 create failed: ${createPve8.text}`);
        assert.strictEqual(createPve8.json.success, true);
        assert.strictEqual(createPve8.json.config.memory, 4096);
        assert.strictEqual(createPve8.json.config.cpus, 4);
        assert.strictEqual(createPve8.json.config.disk_size, '40G');
        assert.strictEqual(createPve8.json.config.http_port, 8006);
        assert.strictEqual(createPve8.json.config.is_proxmox, true);
        const pve8VmId = createPve8.json.vm_id;
        createdVmIds.push(pve8VmId);

        // Verify password encrypted at rest in SQLite
        const rawPve8Row = await ctx.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [pve8VmId]);
        assert.ok(rawPve8Row, 'Expected pve8 VM row in vms table');
        assert.strictEqual(isEncryptedSecret(rawPve8Row.password), true, 'Proxmox VM password must be encrypted at rest');
        assert.strictEqual(rawPve8Row.username, 'root');
        assert.strictEqual(rawPve8Row.http_port, 8006);

        // Verify binary seed ISO exists, has CD001 + cidata PVD, and embeds valid 2-space Cloud-Init user-data
        assert.strictEqual(fs.existsSync(rawPve8Row.seed_file), true, 'Expected Proxmox seed ISO file on disk');
        const isoBytes = fs.readFileSync(rawPve8Row.seed_file);
        assert.strictEqual(isoBytes.subarray(16 * 2048 + 1, 16 * 2048 + 6).toString('ascii'), 'CD001');
        assert.strictEqual(isoBytes.subarray(16 * 2048 + 40, 16 * 2048 + 46).toString('ascii'), 'cidata');
        const isoText = isoBytes.toString('utf8');
        assert.ok(isoText.includes('#cloud-config'), 'Seed ISO must embed #cloud-config');
        assert.ok(isoText.includes('hostname: pve8-node1'), 'Seed ISO must configure short hostname');
        assert.ok(isoText.includes('fqdn: pve8-node1.proxmox.local'), 'Seed ISO must configure FQDN for pve-cluster');
        assert.ok(isoText.includes('root:Pve8Root!Secret'), 'Seed ISO must configure root@pam password');
        assert.ok(isoText.includes('CODENAME="bookworm"'), 'PVE 8 seed ISO must target bookworm repository');
        assert.ok(isoText.includes('pve-no-subscription'), 'Seed ISO must configure pve-no-subscription APT repo');
        assert.ok(isoText.includes('proxmox-default-kernel'), 'Seed ISO must install proxmox-default-kernel');
        assert.ok(isoText.includes('proxmox-ve postfix open-iscsi chrony'), 'Seed ISO must install proxmox-ve packages');
        assert.ok(isoText.includes('DPkg::Lock::Timeout "180"'), 'Seed ISO must configure global APT lock timeout');
        assert.ok(isoText.includes('tgvpanel-proxmox-status.sh'), 'Seed ISO must install SSH login status banner');
        assert.ok(isoText.includes('systemctl stop apt-daily.timer'), 'Seed ISO must stop apt-daily timers during bootstrap');
        assert.ok(isoText.includes('address 10.10.10.1/24'), 'NAT Proxmox seed ISO must configure internal vmbr0 bridge');
        assert.ok(isoText.includes('console=tty0 console=ttyS0,115200n8'), 'Seed ISO must preserve serial console in GRUB');

        // Verify generator produces 0 YAML indentation/tab warnings & valid bash syntax for both PVE 8 & PVE 9
        for (const tplKey of ['proxmox_ve_8', 'proxmox_ve_9']) {
          const generatedCfg = app.proxmoxHelpers.generateProxmoxCloudInitConfig({
            os_template: tplKey,
            hostname: 'pve-node1',
            username: 'root',
            password: 'PveRoot!Secret',
            network_type: 'nat',
          });
          for (const [idx, line] of generatedCfg.split('\n').entries()) {
            assert.strictEqual(line.includes('\t'), false, `${tplKey} line ${idx + 1} must not contain tabs`);
            const indent = line.match(/^ */)[0].length;
            assert.strictEqual(indent % 2, 0, `${tplKey} line ${idx + 1} indentation (${indent}) must be a multiple of 2`);
          }
          // Extract /usr/local/sbin/tgvpanel-install-proxmox.sh block and validate with bash -n
          const markerStart = '  - path: /usr/local/sbin/tgvpanel-install-proxmox.sh\n    permissions: \'0755\'\n    content: |\n';
          const markerEnd = '\n  - path: /etc/systemd/system/tgvpanel-proxmox-setup.service';
          const sIdx = generatedCfg.indexOf(markerStart);
          const eIdx = generatedCfg.indexOf(markerEnd);
          assert.ok(sIdx > 0 && eIdx > sIdx, `Expected installer script block in ${tplKey} cloud-config`);
          const extractedScript = generatedCfg
            .slice(sIdx + markerStart.length, eIdx)
            .split('\n')
            .map((l) => (l.startsWith('      ') ? l.slice(6) : l))
            .join('\n');
          const tmpScriptPath = path.join(tmpRoot, `check-${tplKey}.sh`);
          fs.writeFileSync(tmpScriptPath, extractedScript, 'utf8');
          require('child_process').execFileSync('/bin/bash', ['-n', tmpScriptPath]);
        }

        // Verify QEMU NAT netdev forwards BOTH SSH and Proxmox HTTPS :8006
        const natSpec8 = app.proxmoxHelpers.buildQemuNatNetdevSpec(rawPve8Row, 'n0');
        assert.strictEqual(
          natSpec8.netdevArg,
          'user,id=n0,hostfwd=tcp::22806-:22,hostfwd=tcp::8006-:8006'
        );

        // 24d. Second NAT Proxmox VE 9 VM auto-avoids port 8006 collision (-> 8007)
        const createPve9Nat = await adminClient.request('POST', '/api/vms', {
          vm_name: 'pve9-hypervisor-02',
          os_template: 'proxmox_ve_9',
          hostname: 'pve9-node2.lab.internal',
          network_type: 'nat',
          ssh_port: 22807,
          custom_password: 'Pve9Root!Secret',
        });
        assert.strictEqual(createPve9Nat.status, 200, `Proxmox VE 9 NAT create failed: ${createPve9Nat.text}`);
        assert.strictEqual(createPve9Nat.json.config.http_port, 8007, 'Second NAT Proxmox VM must auto-increment Web UI port to 8007');
        createdVmIds.push(createPve9Nat.json.vm_id);
        const rawPve9NatRow = await ctx.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [createPve9Nat.json.vm_id]);
        const natSpec9 = app.proxmoxHelpers.buildQemuNatNetdevSpec(rawPve9NatRow, 'n0');
        assert.strictEqual(
          natSpec9.netdevArg,
          'user,id=n0,hostfwd=tcp::22807-:22,hostfwd=tcp::8007-:8006'
        );

        // 24e. Static Public IPv4 Proxmox VE 9 VM configures bridged vmbr0 + trixie repository
        const createPve9Static = await adminClient.request('POST', '/api/vms', {
          vm_name: 'pve9-bridged-03',
          os_template: 'proxmox_ve_9',
          hostname: 'pve9-static',
          network_type: 'static_public',
          bridge_device: 'vmbr0',
          ipv4_address: '203.0.113.50',
          ipv4_gateway: '203.0.113.1',
          ipv4_netmask: '24',
          dns_servers: '1.1.1.1,8.8.8.8',
          custom_password: 'Pve9Static!Pass',
        });
        assert.strictEqual(createPve9Static.status, 200, `Proxmox VE 9 static create failed: ${createPve9Static.text}`);
        assert.strictEqual(createPve9Static.json.config.http_port, 8006);
        createdVmIds.push(createPve9Static.json.vm_id);
        const staticSeedText = fs.readFileSync(path.join(vmDir, `vm-${createPve9Static.json.vm_id}-seed.iso`), 'utf8');
        assert.ok(staticSeedText.includes('CODENAME="trixie"'), 'PVE 9 seed ISO must target trixie repository');
        assert.ok(
          staticSeedText.includes('proxmox-archive-keyring-trixie.gpg'),
          'PVE 9 seed ISO must use official proxmox-archive-keyring-trixie.gpg URL'
        );
        assert.ok(
          staticSeedText.includes('/etc/apt/sources.list.d/pve-install-repo.sources'),
          'PVE 9 seed ISO must configure DEB822 pve-install-repo.sources'
        );
        assert.ok(staticSeedText.includes('STATIC_IP="203.0.113.50"'), 'Static PVE seed ISO must embed static IPv4');
        assert.ok(staticSeedText.includes('bridge-ports ${PRIMARY_IFACE}'), 'Static PVE seed ISO must bridge primary NIC into vmbr0');

        // 24f. Verify enriched icon & metadata in /api/vms, /api/admin/vms, /api/vms/:id & detail views
        const detailPve8 = await adminClient.request('GET', `/api/vms/${pve8VmId}`);
        assert.strictEqual(detailPve8.status, 200);
        assert.strictEqual(detailPve8.json.template_icon, '/images/os/proxmox.svg');
        assert.strictEqual(detailPve8.json.template_name, 'Proxmox VE 8');
        assert.strictEqual(detailPve8.json.is_proxmox, true);
        assert.strictEqual(detailPve8.json.web_ui_port, 8006);
        assert.strictEqual(detailPve8.json.password, 'Pve8Root!Secret');

        const adminVmList = await adminClient.request('GET', '/api/admin/vms');
        const listedPve8 = adminVmList.json.find((v) => v.vm_id === pve8VmId);
        assert.ok(listedPve8, 'Expected Proxmox VM in /api/admin/vms');
        assert.strictEqual(listedPve8.template_icon, '/images/os/proxmox.svg');
        assert.strictEqual(listedPve8.is_proxmox, true);

        const adminDetailPage = await adminClient.request('GET', `/admin/vm/${pve8VmId}`);
        assert.strictEqual(adminDetailPage.status, 200);
        assert.ok(adminDetailPage.text.includes('Proxmox VE Web Console'), 'Expected Proxmox Web Console card in /admin/vm/:id');

        const userDetailPage = await adminClient.request('GET', `/vm/${pve8VmId}`);
        assert.strictEqual(userDetailPage.status, 200);
        assert.ok(userDetailPage.text.includes('Proxmox VE Web Console'), 'Expected Proxmox Web Console card in /vm/:id');

        // 24g. Verify reinstalling a standard Linux VM into Proxmox VE encrypts password & upgrades Web UI port
        const createUbu = await adminClient.request('POST', '/api/vms', {
          vm_name: 'reinstall-to-pve',
          os_template: 'ubuntu_22_cloud',
          hostname: 'reinstall-pve',
          network_type: 'nat',
          ssh_port: 22809,
          custom_password: 'InitialUbuntuPass!1',
        });
        assert.strictEqual(createUbu.status, 200, `Ubuntu VM create failed: ${createUbu.text}`);
        const reinstallVmId = createUbu.json.vm_id;
        createdVmIds.push(reinstallVmId);
        assert.strictEqual(createUbu.json.config.http_port, 80);

        const reinstallRes = await adminClient.request('POST', `/api/vms/${reinstallVmId}/reinstall`, {
          new_os_template: 'proxmox_ve_8',
          new_username: 'root',
          new_password: 'ReinstallPvePass!99',
          confirm: true,
        });
        assert.strictEqual(reinstallRes.status, 200, `Reinstall into Proxmox failed: ${reinstallRes.text}`);
        const afterReinstallRow = await ctx.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [reinstallVmId]);
        assert.strictEqual(afterReinstallRow.template_type, 'proxmox_ve_8');
        assert.strictEqual(isEncryptedSecret(afterReinstallRow.password), true, 'Reinstall must encrypt password at rest');
        assert.ok(afterReinstallRow.http_port >= 8006, `Expected Proxmox Web UI port >= 8006 after reinstall, got ${afterReinstallRow.http_port}`);
        const reinstallIsoText = fs.readFileSync(afterReinstallRow.seed_file, 'utf8');
        assert.ok(reinstallIsoText.includes('root:ReinstallPvePass!99'), 'Reinstalled Proxmox seed ISO must embed decrypted root password');
        assert.ok(reinstallIsoText.includes('proxmox-ve postfix open-iscsi chrony'), 'Reinstalled Proxmox seed ISO must include Proxmox bootstrap');
      } finally {
        process.env.PATH = origPath;
        for (const id of createdVmIds) {
          await adminClient.request('DELETE', `/api/vms/${id}`).catch(() => {});
        }
        for (const f of createdTemplateFiles) {
          try { fs.unlinkSync(f); } catch (_) {}
        }
      }
    });

    // 26. Cloudflare Tunnel / Domain-Only Node Registration (No Public IPv4 IP)
    await runStep('T25: Cloudflare Tunnel / domain-only node registration without IPv4 IP & --join domain preservation', async () => {
      const tls = require('tls');
      const {
        normalizeNodeEndpointUrl,
        isDomainHostname,
      } = require('../lib/services/nodes/NodeClient');

      // Bare domain defaults to https:// (Cloudflare Tunnel port 443)
      assert.strictEqual(isDomainHostname('cf-node01.example.com'), true);
      assert.strictEqual(isDomainHostname('203.0.113.10'), false);
      assert.strictEqual(isDomainHostname('localhost'), false);
      assert.strictEqual(
        normalizeNodeEndpointUrl('cf-node01.example.com'),
        'https://cf-node01.example.com'
      );
      assert.strictEqual(
        normalizeNodeEndpointUrl('https://cf-node01.example.com/api/v1/health'),
        'https://cf-node01.example.com'
      );

      // Admin UI renders #nIp as optional (no HTML5 required attribute blocking empty IPv4)
      const nodesPage = await adminClient.request('GET', '/admin/nodes');
      assert.strictEqual(nodesPage.status, 200);
      assert.ok(
        !/id="nIp"[^>]*\brequired\b/i.test(nodesPage.text),
        '#nIp must be optional so Cloudflare Tunnel / IPv6-only nodes without IPv4 can submit'
      );

      // Create node with blank ipAddress & blank hostname (Cloudflare Tunnel URL only)
      const createCfNode = await adminClient.request('POST', '/api/v1/nodes', {
        name: 'cf-tunnel-mumbai',
        hostname: '',
        ipAddress: '',
        url: 'cf-node01.example.com',
        location: 'Mumbai (Cloudflare Tunnel)',
        verifySsl: true,
      });
      assert.strictEqual(
        createCfNode.status,
        201,
        `Domain-only node create failed: ${createCfNode.text}`
      );
      const cfNodeId = createCfNode.json.node.id;
      try {
        assert.strictEqual(createCfNode.json.node.url, 'https://cf-node01.example.com');
        assert.strictEqual(createCfNode.json.node.hostname, 'cf-node01.example.com');
        assert.strictEqual(createCfNode.json.node.ip_address, 'cf-node01.example.com');
        assert.strictEqual(createCfNode.json.node.verify_ssl, 1);

        // Generated 1-command join script preserves TGVPANEL_ADVERTISE_URL for Tunnel domain
        const joinTokRes = await adminClient.request(
          'POST',
          `/api/v1/nodes/${cfNodeId}/join-token`,
          {
            controllerUrl: 'https://panel.example.com',
            ttlMinutes: 15,
          }
        );
        assert.strictEqual(joinTokRes.status, 201, `Join token create failed: ${joinTokRes.text}`);
        assert.ok(
          joinTokRes.json.curlJoinCommand.includes(
            'TGVPANEL_ADVERTISE_URL="https://cf-node01.example.com"'
          ),
          'Join command must embed TGVPANEL_ADVERTISE_URL when node uses a Tunnel/domain URL'
        );

        // Even if a CGNAT host runs --join without TGVPANEL_ADVERTISE_URL and posts its private LAN IP,
        // redeemJoinToken MUST NOT clobber the configured Cloudflare Tunnel domain!
        const dummySelfSignedPem =
          '-----BEGIN CERTIFICATE-----\nMIIB+TCCAWICAQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDEwMTAwMDAw\nMFoXDTM2MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAE1111111111111111111111111111111111111111\n111111111111111111111111111111111111111111111TAAMAoGCCqGSM49BAMC\nA0cAMEQCIB111111111111111111111111111111111111111111AiB222222222\n222222222222222222222222222222222w==\n-----END CERTIFICATE-----';
        const bareNodeClient = new SessionClient(baseUrl);
        const redeemRes = await bareNodeClient.request(
          'POST',
          `/api/v1/nodes/join/${encodeURIComponent(joinTokRes.json.token)}`,
          {
            endpointUrl: 'https://192.168.88.50:8443',
            ipAddress: '192.168.88.50',
            hostname: 'cgnat-box.lan',
            agentPort: 8443,
            tlsCertPem: dummySelfSignedPem,
            verifySsl: true,
          }
        );
        assert.strictEqual(redeemRes.status, 200, `Join redeem failed: ${redeemRes.text}`);
        assert.strictEqual(
          redeemRes.json.url,
          'https://cf-node01.example.com',
          'Configured Cloudflare Tunnel domain must not be overwritten by private LAN IP during --join'
        );

        const afterNode = await ctx.nodeManager.getNodeById(cfNodeId);
        assert.strictEqual(afterNode.url, 'https://cf-node01.example.com');
        assert.strictEqual(afterNode.hostname, 'cf-node01.example.com');

        // Verify buildTlsOptionsForNode merges Mozilla rootCertificates + pinned PEM so Cloudflare Edge CA validates
        const tlsOpts = ctx.nodeManager.buildTlsOptionsForNode(afterNode, {
          tls_ca_pem: dummySelfSignedPem,
        });
        assert.strictEqual(tlsOpts.rejectUnauthorized, true);
        assert.ok(
          Array.isArray(tlsOpts.ca) &&
            tlsOpts.ca.length > tls.rootCertificates.length &&
            tlsOpts.ca.includes(dummySelfSignedPem),
          'TLS CA bundle must include both system root CAs (for Cloudflare Edge) and pinned node cert'
        );
      } finally {
        await adminClient.request('DELETE', `/api/v1/nodes/${cfNodeId}`).catch(() => {});
      }
    });
  } finally {
    const { execFileSync } = require('child_process');
    for (const storeDir of [
      path.join(tmpRoot, 'local-lxc'),
      path.join(tmpRoot, 'agent-lxc'),
      path.join(tmpRoot, 'https-agent-lxc'),
    ]) {
      try {
        if (fs.existsSync(storeDir)) {
          for (const entry of fs.readdirSync(storeDir)) {
            const pidFile = path.join(storeDir, entry, '.pid');
            if (fs.existsSync(pidFile)) {
              const p = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
              if (p > 0) {
                try { execFileSync('sudo', ['-n', 'kill', '-KILL', String(p)]); } catch (_) {}
              }
            }
          }
        }
      } catch (_) {}
    }
    for (const d of rootOwnedCleanupDirs) {
      try { execFileSync('sudo', ['-n', 'rm', '-rf', d]); } catch (_) {}
    }
    for (const shimPath of installedLxcShims) {
      try { execFileSync('sudo', ['-n', 'rm', '-f', shimPath]); } catch (_) {}
    }
    if (httpsAgentServer) await new Promise((r) => httpsAgentServer.close(() => r()));
    if (agentServer) await new Promise((r) => agentServer.close(() => r()));
    if (app && app.getHkvmV3Context()) {
      app.getHkvmV3Context().monitoringService.stopBackgroundLoop();
      await app.getHkvmV3Context().db.close().catch(() => {});
    }
    if (app && app.server) {
      await new Promise((r) => app.server.close(() => r()));
    }
    try {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    } catch {
      try { execFileSync('sudo', ['-n', 'rm', '-rf', tmpRoot]); } catch (_) {}
    }
  }

  const failed = results.filter((r) => r.status === 'FAIL');
  console.log('\n--------------------------------------------------------------------');
  console.log(`  Summary: ${results.length - failed.length}/${results.length} Acceptance Suites Passed`);
  console.log('--------------------------------------------------------------------\n');
  process.exit(failed.length > 0 ? 1 : 0);
})();
