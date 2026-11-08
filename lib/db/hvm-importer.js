"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyPasswordWithLegacySupport = verifyPasswordWithLegacySupport;
exports.importHvmDatabase = importHvmDatabase;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const sqlite3_1 = __importDefault(require("sqlite3"));
const database_1 = require("./database");
const crypto_vault_1 = require("../security/crypto-vault");
/**
 * Verifies legacy Werkzeug hashes (pbkdf2:sha256 / scrypt) or bcrypt hashes
 * so imported HVM accounts can authenticate safely and upgrade to HKVM bcrypt.
 */
function verifyPasswordWithLegacySupport(plaintext, storedHash) {
    if (!storedHash || !plaintext)
        return { valid: false, needsRehash: false };
    // Standard HKVM / Node bcryptjs hash
    if (storedHash.startsWith('$2a$') || storedHash.startsWith('$2b$') || storedHash.startsWith('$2y$')) {
        const normalized = storedHash.startsWith('$2y$')
            ? '$2a$' + storedHash.slice(4)
            : storedHash;
        return {
            valid: bcryptjs_1.default.compareSync(plaintext, normalized),
            needsRehash: false,
        };
    }
    // Werkzeug pbkdf2:sha256[:iterations]$salt$hash
    if (storedHash.startsWith('pbkdf2:sha256')) {
        try {
            const [methodPart, salt, expectedHex] = storedHash.split('$');
            const methodTokens = methodPart.split(':');
            const iterations = methodTokens[2] ? parseInt(methodTokens[2], 10) : 260000;
            const derived = crypto_1.default
                .pbkdf2Sync(plaintext, salt, iterations, expectedHex.length / 2, 'sha256')
                .toString('hex');
            const valid = derived.length === expectedHex.length &&
                crypto_1.default.timingSafeEqual(Buffer.from(derived, 'utf8'), Buffer.from(expectedHex, 'utf8'));
            return { valid, needsRehash: valid };
        }
        catch {
            return { valid: false, needsRehash: false };
        }
    }
    // Werkzeug scrypt:N:r:p$salt$hash
    if (storedHash.startsWith('scrypt:')) {
        try {
            const [methodPart, salt, expectedHex] = storedHash.split('$');
            const [, nStr, rStr, pStr] = methodPart.split(':');
            const N = parseInt(nStr, 10) || 32768;
            const r = parseInt(rStr, 10) || 8;
            const p = parseInt(pStr, 10) || 1;
            const derived = crypto_1.default
                .scryptSync(plaintext, salt, expectedHex.length / 2, {
                N,
                r,
                p,
                maxmem: 128 * 1024 * 1024,
            })
                .toString('hex');
            const valid = derived.length === expectedHex.length &&
                crypto_1.default.timingSafeEqual(Buffer.from(derived, 'utf8'), Buffer.from(expectedHex, 'utf8'));
            return { valid, needsRehash: valid };
        }
        catch {
            return { valid: false, needsRehash: false };
        }
    }
    return { valid: false, needsRehash: false };
}
async function importHvmDatabase(hkvmDb, hvmDbFilePath) {
    if (!fs_1.default.existsSync(hvmDbFilePath)) {
        throw new Error(`HVM database file not found: ${hvmDbFilePath}`);
    }
    const backup = await hkvmDb.createBackup('pre_hvm_import');
    const rawSource = new sqlite3_1.default.Database(hvmDbFilePath, sqlite3_1.default.OPEN_READONLY);
    const srcDb = new database_1.UnifiedDatabase(rawSource, hvmDbFilePath);
    const report = {
        backupPath: backup.backupPath,
        usersMappedExisting: 0,
        usersCreated: 0,
        nodesImported: 0,
        vpsImported: 0,
        portsImported: 0,
        snapshotsImported: 0,
        backupsImported: 0,
        notificationsImported: 0,
        apiKeysImported: 0,
        warnings: [],
    };
    try {
        const srcTables = new Set((await srcDb.all(`SELECT name FROM sqlite_master WHERE type='table'`)).map((t) => t.name));
        const userMap = new Map(); // HVM user.id -> HKVM user.id
        const nodeMap = new Map(); // HVM node.id -> HKVM node.id
        const vpsMap = new Map(); // HVM vps.id  -> HKVM lxc_instances.id
        await hkvmDb.transaction(async () => {
            // 1. Map / Migrate Users without creating duplicates or clobbering HKVM passwords
            if (srcTables.has('users')) {
                const hvmUsers = await srcDb.all(`SELECT * FROM users`);
                for (const u of hvmUsers) {
                    const existing = await hkvmDb.get(`SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR (email IS NOT NULL AND email != '' AND LOWER(email) = LOWER(?)) LIMIT 1`, [u.username, u.email || '']);
                    if (existing) {
                        userMap.set(u.id, existing.id);
                        await hkvmDb.run(`UPDATE users SET hvm_legacy_id = COALESCE(hvm_legacy_id, ?) WHERE id = ?`, [u.id, existing.id]);
                        report.usersMappedExisting++;
                    }
                    else {
                        // Preserve compatible hash or store Werkzeug hash (verified via verifyPasswordWithLegacySupport)
                        let storedPassword = u.password_hash || '';
                        if (!storedPassword.startsWith('$2') &&
                            !storedPassword.startsWith('pbkdf2:') &&
                            !storedPassword.startsWith('scrypt:')) {
                            storedPassword = bcryptjs_1.default.hashSync((0, crypto_vault_1.generateStrongPassword)(24), 10);
                            report.warnings.push(`User "${u.username}" had unrecognized password hash format; assigned random hash (use password reset).`);
                        }
                        const twoFactorEnc = u.two_factor_secret
                            ? (0, crypto_vault_1.encryptSecret)(String(u.two_factor_secret))
                            : null;
                        const ins = await hkvmDb.run(`INSERT INTO users (username, password, email, full_name, role, is_active, two_factor_secret_enc, two_factor_enabled, preferences, hvm_legacy_id)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`, [
                            u.username,
                            storedPassword,
                            u.email || null,
                            u.username,
                            u.is_admin ? 'admin' : 'user',
                            twoFactorEnc,
                            u.two_factor_enabled ? 1 : 0,
                            u.preferences || '{}',
                            u.id,
                        ]);
                        userMap.set(u.id, ins.lastID);
                        report.usersCreated++;
                    }
                }
            }
            // 2. Map / Migrate Nodes
            const defaultLocalNode = await hkvmDb.get(`SELECT id FROM nodes WHERE is_local = 1 ORDER BY id ASC LIMIT 1`);
            const fallbackNodeId = defaultLocalNode?.id || 1;
            if (srcTables.has('nodes')) {
                const hvmNodes = await srcDb.all(`SELECT * FROM nodes`);
                for (const n of hvmNodes) {
                    if (n.is_local) {
                        nodeMap.set(n.id, fallbackNodeId);
                        continue;
                    }
                    const existingNode = await hkvmDb.get(`SELECT id FROM nodes WHERE LOWER(name) = LOWER(?) LIMIT 1`, [n.name]);
                    if (existingNode) {
                        nodeMap.set(n.id, existingNode.id);
                        continue;
                    }
                    let primaryIp = '127.0.0.1';
                    try {
                        const parsedIps = JSON.parse(n.ip_addresses || '[]');
                        if (Array.isArray(parsedIps) && parsedIps.length > 0)
                            primaryIp = parsedIps[0];
                    }
                    catch {
                        // Ignore malformed JSON
                    }
                    const ins = await hkvmDb.run(`INSERT INTO nodes
             (name, hostname, ip_address, location, url, is_local, verify_ssl, status, cpu_cores, ram_total_mb, disk_total_gb, max_instances, ip_aliases, tags)
             VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                        n.name,
                        n.name,
                        primaryIp,
                        n.location || 'Remote Node',
                        n.url || `http://${primaryIp}:5000`,
                        n.verify_ssl ? 1 : 0,
                        n.status || 'unknown',
                        n.cpu_cores || 0,
                        n.ram_total || 0,
                        n.disk_total || 0,
                        n.total_vps || 50,
                        n.ip_aliases || '[]',
                        n.tags || '[]',
                    ]);
                    const newNodeId = ins.lastID;
                    nodeMap.set(n.id, newNodeId);
                    const rawKey = n.api_key || (0, crypto_vault_1.generateApiKeyPair)('hkvm_node').rawKey;
                    const hmacSecret = crypto_1.default.randomBytes(32).toString('hex');
                    await hkvmDb.run(`INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc)
             VALUES (?, ?, ?, ?, ?)`, [
                        newNodeId,
                        String(rawKey).slice(0, 12),
                        (0, crypto_vault_1.hashApiKey)(String(rawKey)),
                        (0, crypto_vault_1.encryptSecret)(String(rawKey)),
                        (0, crypto_vault_1.encryptSecret)(hmacSecret),
                    ]);
                    await hkvmDb.run(`INSERT INTO node_capabilities (node_id, supports_kvm, supports_lxc, kvm_available, lxc_available)
             VALUES (?, 0, 1, 0, 1)`, [newNodeId]);
                    report.nodesImported++;
                }
            }
            // 3. Migrate LXC VPS records -> lxc_instances + instances
            if (srcTables.has('vps')) {
                const hvmVpsRows = await srcDb.all(`SELECT * FROM vps`);
                for (const v of hvmVpsRows) {
                    const exists = await hkvmDb.get(`SELECT id FROM lxc_instances WHERE container_name = ? LIMIT 1`, [v.container_name]);
                    if (exists) {
                        vpsMap.set(v.id, exists.id);
                        continue;
                    }
                    const mappedUserId = userMap.get(v.user_id) || 1;
                    const mappedNodeId = nodeMap.get(v.node_id) || fallbackNodeId;
                    const ramStr = String(v.ram || '1GB').toUpperCase();
                    const ramNum = parseFloat(ramStr.replace(/[^0-9.]/g, '')) || 1;
                    const ramMb = ramStr.includes('MB') ? Math.round(ramNum) : Math.round(ramNum * 1024);
                    const cpuCores = parseInt(String(v.cpu || '1'), 10) || 1;
                    const diskGb = parseInt(String(v.storage || '10').replace(/[^0-9]/g, ''), 10) || 10;
                    const swapMb = (parseInt(String(v.swap || '0'), 10) || 0) * 1024;
                    const osFamily = String(v.os_version || '').toLowerCase().match(/centos|alma|rocky|fedora|rhel/)
                        ? 'rhel'
                        : 'debian';
                    // Map shared_with user IDs
                    let mappedShared = [];
                    try {
                        const rawShared = JSON.parse(v.shared_with || '[]');
                        if (Array.isArray(rawShared)) {
                            mappedShared = rawShared
                                .map((oldUid) => userMap.get(Number(oldUid)))
                                .filter((id) => Boolean(id));
                        }
                    }
                    catch {
                        mappedShared = [];
                    }
                    const encryptedRootPass = v.root_password
                        ? (0, crypto_vault_1.encryptSecret)(String(v.root_password))
                        : (0, crypto_vault_1.encryptSecret)((0, crypto_vault_1.generateStrongPassword)(20));
                    const ins = await hkvmDb.run(`INSERT INTO lxc_instances (
              user_id, node_id, container_name, hostname, os_template, os_family,
              cpu_cores, ram_mb, swap_mb, disk_gb, privileged, nesting,
              root_password_enc, ip_address, ip_alias, status, suspended, suspended_reason,
              suspension_history, whitelisted, shared_with, bandwidth_quota_gb, bandwidth_used_gb,
              network_ingress_mbps, network_egress_mbps, network_priority, snapshot_limit,
              notes, metadata, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                        mappedUserId,
                        mappedNodeId,
                        v.container_name,
                        v.hostname || v.container_name,
                        v.os_version || 'ubuntu:22.04',
                        osFamily,
                        cpuCores,
                        ramMb,
                        swapMb,
                        diskGb,
                        encryptedRootPass,
                        v.ip_address || null,
                        v.ip_alias || null,
                        v.status || 'stopped',
                        v.suspended ? 1 : 0,
                        v.suspended_reason || null,
                        v.suspension_history || '[]',
                        v.whitelisted ? 1 : 0,
                        JSON.stringify(mappedShared),
                        v.bandwidth_quota_gb || 0,
                        v.bandwidth_used_gb || 0,
                        v.network_limit_ingress || 0,
                        v.network_limit_egress || 0,
                        v.network_priority || 5,
                        v.snapshot_limit || 5,
                        v.notes || null,
                        v.metadata || '{}',
                        v.expires_at || null,
                        v.expiration_days || 0,
                        v.auto_suspend_enabled ? 1 : 0,
                        v.last_renewed_at || null,
                    ]);
                    const newLxcId = ins.lastID;
                    vpsMap.set(v.id, newLxcId);
                    await hkvmDb.run(`INSERT OR REPLACE INTO instances
             (engine, ref_id, name, hostname, owner_id, node_id, status, suspended, os_label, cpu_cores, ram_mb, disk_gb, primary_ip, shared_with)
             VALUES ('lxc', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                        newLxcId,
                        v.container_name,
                        v.hostname || v.container_name,
                        mappedUserId,
                        mappedNodeId,
                        v.status || 'stopped',
                        v.suspended ? 1 : 0,
                        v.os_version || 'ubuntu:22.04',
                        cpuCores,
                        ramMb,
                        diskGb,
                        v.ip_address || null,
                        JSON.stringify(mappedShared),
                    ]);
                    if (v.expires_at || v.expiration_days) {
                        await hkvmDb.run(`INSERT OR REPLACE INTO vps_expiration (lxc_id, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at)
               VALUES (?, ?, ?, ?, ?)`, [
                            newLxcId,
                            v.expires_at || null,
                            v.expiration_days || 0,
                            v.auto_suspend_enabled ? 1 : 0,
                            v.last_renewed_at || null,
                        ]);
                    }
                    report.vpsImported++;
                }
            }
            // 4. Port Allocations & Port Forwards
            if (srcTables.has('port_allocations')) {
                const allocs = await srcDb.all(`SELECT * FROM port_allocations`);
                for (const a of allocs) {
                    const uid = userMap.get(a.user_id);
                    if (!uid)
                        continue;
                    await hkvmDb.run(`INSERT OR REPLACE INTO port_allocations (user_id, allocated_ports, used_ports, updated_at)
             VALUES (?, ?, ?, datetime('now'))`, [uid, a.allocated_ports || 0, a.used_ports || 0]);
                }
            }
            if (srcTables.has('port_forwards')) {
                const forwards = await srcDb.all(`SELECT * FROM port_forwards`);
                for (const f of forwards) {
                    const uid = userMap.get(f.user_id) || 1;
                    const lxc = await hkvmDb.get(`SELECT id, node_id FROM lxc_instances WHERE container_name = ? LIMIT 1`, [f.vps_container]);
                    await hkvmDb.run(`INSERT OR IGNORE INTO port_forwards
             (user_id, node_id, instance_type, instance_ref_id, container_name, guest_port, host_port, protocol, description, is_custom, is_bulk, bulk_range_id, created_by_admin, hits)
             VALUES (?, ?, 'lxc', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                        uid,
                        lxc?.node_id || fallbackNodeId,
                        lxc?.id || null,
                        f.vps_container,
                        f.vps_port,
                        f.host_port,
                        f.protocol || 'tcp,udp',
                        f.description || '',
                        f.is_custom ? 1 : 0,
                        f.is_bulk ? 1 : 0,
                        f.bulk_range_id || null,
                        f.created_by_admin ? 1 : 0,
                        f.hits || 0,
                    ]);
                    report.portsImported++;
                }
            }
            // 5. Snapshots & Backups
            if (srcTables.has('vps_snapshots')) {
                const snaps = await srcDb.all(`SELECT * FROM vps_snapshots`);
                for (const s of snaps) {
                    const lxcId = vpsMap.get(s.vps_id);
                    if (!lxcId)
                        continue;
                    await hkvmDb.run(`INSERT INTO container_snapshots
             (lxc_id, snapshot_name, description, size_bytes, snapshot_type, stateful, status, created_by, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                        lxcId,
                        s.snapshot_name,
                        s.description || null,
                        s.size_bytes || 0,
                        s.snapshot_type || 'manual',
                        s.stateful ? 1 : 0,
                        s.status || 'completed',
                        s.created_by ? userMap.get(s.created_by) || null : null,
                        s.created_at || new Date().toISOString(),
                    ]);
                    report.snapshotsImported++;
                }
            }
            if (srcTables.has('backups')) {
                const bkps = await srcDb.all(`SELECT * FROM backups`);
                for (const b of bkps) {
                    const lxcId = vpsMap.get(b.vps_id);
                    if (!lxcId)
                        continue;
                    await hkvmDb.run(`INSERT INTO container_backups
             (instance_type, instance_ref_id, node_id, backup_name, file_path, size_bytes, status, created_at)
             VALUES ('lxc', ?, ?, ?, ?, ?, ?, ?)`, [
                        lxcId,
                        fallbackNodeId,
                        b.name,
                        b.path,
                        b.size || 0,
                        b.status || 'completed',
                        b.created_at || new Date().toISOString(),
                    ]);
                    report.backupsImported++;
                }
            }
            // 6. Notifications & API keys (hashed, never stored plaintext)
            if (srcTables.has('notifications')) {
                const notifs = await srcDb.all(`SELECT * FROM notifications`);
                for (const n of notifs) {
                    const uid = userMap.get(n.user_id);
                    if (!uid)
                        continue;
                    await hkvmDb.run(`INSERT INTO notifications (user_id, type, title, message, is_read, data, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
                        uid,
                        n.type || 'info',
                        n.title || 'Notification',
                        n.message || '',
                        n.read ? 1 : 0,
                        n.data || null,
                        n.created_at || new Date().toISOString(),
                        n.expires_at || null,
                    ]);
                    report.notificationsImported++;
                }
            }
            if (srcTables.has('api_keys')) {
                const keys = await srcDb.all(`SELECT * FROM api_keys`);
                for (const k of keys) {
                    const uid = userMap.get(k.user_id);
                    if (!uid || !k.key)
                        continue;
                    await hkvmDb.run(`INSERT OR IGNORE INTO api_keys
             (user_id, name, description, key_prefix, key_hash, permissions, is_active, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
                        uid,
                        k.name || 'Imported HVM Key',
                        k.description || '',
                        String(k.key).slice(0, 12),
                        (0, crypto_vault_1.hashApiKey)(String(k.key)),
                        k.permissions || '["read","write"]',
                        k.is_active ? 1 : 0,
                        k.created_at || new Date().toISOString(),
                    ]);
                    report.apiKeysImported++;
                }
            }
        });
        await hkvmDb.logActivity({
            action: 'hvm_database_imported',
            resourceType: 'database',
            resourceId: hvmDbFilePath,
            details: report,
        });
        return report;
    }
    finally {
        rawSource.close();
    }
}
