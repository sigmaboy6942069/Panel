"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BackupSnapshotManager = void 0;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const middleware_1 = require("../../security/middleware");
class BackupSnapshotManager {
    db;
    nodeManager;
    virt;
    constructor(db, nodeManager, virt) {
        this.db = db;
        this.nodeManager = nodeManager;
        this.virt = virt;
    }
    // --- Unified Snapshots (KVM QCOW2 + LXC) ---
    async listSnapshots(engine, refId) {
        if (engine === 'kvm') {
            return this.db.all(`SELECT snapshot_id AS id, vm_id AS ref_id, 'kvm' AS engine, snapshot_name, description, created_at
         FROM vm_snapshots WHERE vm_id = ? ORDER BY snapshot_id DESC`, [refId]);
        }
        return this.db.all(`SELECT id, lxc_id AS ref_id, 'lxc' AS engine, snapshot_name, description, size_bytes, snapshot_type, status, created_at
       FROM container_snapshots WHERE lxc_id = ? ORDER BY id DESC`, [refId]);
    }
    async createSnapshot(params) {
        if (params.engine === 'kvm') {
            const snapName = params.name
                ? middleware_1.SafeValidators.snapshotName(params.name)
                : `snap_${Date.now()}`;
            return this.virt.kvm.createQcow2Snapshot(params.refId, snapName, params.description || '');
        }
        const row = await this.virt.lxc.getRawLxcRow(params.refId);
        if (!row)
            throw new Error(`LXC container #${params.refId} not found.`);
        const countRow = await this.db.get(`SELECT COUNT(*) AS cnt FROM container_snapshots WHERE lxc_id = ?`, [params.refId]);
        const limit = Number(row.snapshot_limit || 5);
        if ((countRow?.cnt || 0) >= limit) {
            throw new Error(`Snapshot limit reached (${countRow?.cnt}/${limit}). Delete an older snapshot first.`);
        }
        let snapInfo;
        if (row.is_local) {
            snapInfo = await this.nodeManager.localRuntime.snapshotManager.createSnapshot(row.container_name, params.description || '');
        }
        else {
            const resp = await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots`, { comment: params.description || '' });
            snapInfo = resp.snapshot;
        }
        const ins = await this.db.run(`INSERT INTO container_snapshots
         (lxc_id, snapshot_name, description, snapshot_type, status, created_by)
       VALUES (?, ?, ?, 'manual', 'completed', ?)`, [params.refId, snapInfo.name, params.description || null, params.actorId || null]);
        return { id: ins.lastID, name: snapInfo.name };
    }
    async restoreSnapshot(engine, refId, snapshotId) {
        if (engine === 'kvm') {
            await this.virt.kvm.restoreQcow2Snapshot(refId, snapshotId);
            return;
        }
        const row = await this.virt.lxc.getRawLxcRow(refId);
        const snap = await this.db.get(`SELECT * FROM container_snapshots WHERE id = ? AND lxc_id = ?`, [snapshotId, refId]);
        if (!row || !snap)
            throw new Error('Container or snapshot not found.');
        if (row.is_local) {
            await this.nodeManager.localRuntime.snapshotManager.restoreSnapshot(row.container_name, snap.snapshot_name);
        }
        else {
            await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots/${encodeURIComponent(snap.snapshot_name)}/restore`);
        }
    }
    async deleteSnapshot(engine, refId, snapshotId) {
        if (engine === 'kvm') {
            await this.virt.kvm.deleteQcow2Snapshot(refId, snapshotId);
            return;
        }
        const row = await this.virt.lxc.getRawLxcRow(refId);
        const snap = await this.db.get(`SELECT * FROM container_snapshots WHERE id = ? AND lxc_id = ?`, [snapshotId, refId]);
        if (!row || !snap)
            throw new Error('Container or snapshot not found.');
        if (row.is_local) {
            await this.nodeManager.localRuntime.snapshotManager
                .deleteSnapshot(row.container_name, snap.snapshot_name)
                .catch(() => undefined);
        }
        else {
            await this.nodeManager
                .requestRemoteNode(row.node_id, 'DELETE', `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots/${encodeURIComponent(snap.snapshot_name)}`)
                .catch(() => undefined);
        }
        await this.db.run(`DELETE FROM container_snapshots WHERE id = ?`, [snapshotId]);
    }
    // --- Unified Archive Backups with SHA-256 Integrity ---
    async listBackups(filter) {
        if (filter?.engine && filter?.refId !== undefined) {
            return this.db.all(`SELECT b.*, n.name AS node_name
         FROM container_backups b
         LEFT JOIN nodes n ON n.id = b.node_id
         WHERE b.instance_type = ? AND b.instance_ref_id = ?
         ORDER BY b.id DESC`, [filter.engine, filter.refId]);
        }
        return this.db.all(`SELECT b.*, n.name AS node_name
       FROM container_backups b
       LEFT JOIN nodes n ON n.id = b.node_id
       ORDER BY b.id DESC`);
    }
    async createBackup(params) {
        if (params.engine === 'kvm') {
            return this.virt.kvm.createDiskBackup(params.refId);
        }
        const row = await this.virt.lxc.getRawLxcRow(params.refId);
        if (!row)
            throw new Error(`LXC container #${params.refId} not found.`);
        let artifact;
        if (row.is_local) {
            artifact = await this.nodeManager.localRuntime.snapshotManager.createTarBackup(row.container_name, params.label);
        }
        else {
            const resp = await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups`, { label: params.label }, 900_000);
            artifact = resp.backup;
        }
        const ins = await this.db.run(`INSERT INTO container_backups
         (instance_type, instance_ref_id, node_id, backup_name, file_path, size_bytes, checksum_sha256, status, created_by)
       VALUES ('lxc', ?, ?, ?, ?, ?, ?, 'completed', ?)`, [
            params.refId,
            row.node_id,
            artifact.backupName,
            artifact.filePath,
            artifact.sizeBytes,
            artifact.checksumSha256,
            params.actorId || null,
        ]);
        return {
            backupId: ins.lastID,
            ...artifact,
        };
    }
    async getBackupRecord(backupId) {
        return this.db.get(`SELECT b.*, n.is_local
       FROM container_backups b
       LEFT JOIN nodes n ON n.id = b.node_id
       WHERE b.id = ?`, [backupId]);
    }
    async verifyBackupIntegrity(backupId) {
        const bkp = await this.getBackupRecord(backupId);
        if (!bkp)
            throw new Error('Backup record not found.');
        if (bkp.node_id && bkp.is_local === 0) {
            return this.nodeManager.requestRemoteNode(bkp.node_id, 'POST', '/api/v1/backups/verify', {
                filePath: bkp.file_path,
                expectedSha256: bkp.checksum_sha256,
            });
        }
        if (!fs_1.default.existsSync(bkp.file_path)) {
            return { valid: false, expectedSha256: bkp.checksum_sha256, actualSha256: null };
        }
        const actual = await this.nodeManager.localRuntime.snapshotManager.computeFileSha256(bkp.file_path);
        const valid = !bkp.checksum_sha256 || bkp.checksum_sha256.toLowerCase() === actual.toLowerCase();
        return { valid, expectedSha256: bkp.checksum_sha256, actualSha256: actual };
    }
    async restoreBackup(backupId, actorId) {
        const bkp = await this.getBackupRecord(backupId);
        if (!bkp)
            throw new Error('Backup record not found.');
        if (bkp.instance_type !== 'lxc') {
            throw new Error('Archive live restore is currently supported for LXC container backups (use QCOW2 Snapshots for KVM instant revert).');
        }
        const row = await this.virt.lxc.getRawLxcRow(Number(bkp.instance_ref_id));
        if (!row)
            throw new Error(`LXC container #${bkp.instance_ref_id} not found.`);
        const backupOnDifferentNode = Boolean(bkp.node_id) && Number(bkp.node_id) !== Number(row.node_id);
        let crossNodeBase64 = null;
        if (backupOnDifferentNode) {
            if (Number(bkp.is_local || 0) === 1 || Number(bkp.node_id) === 1) {
                if (!fs_1.default.existsSync(bkp.file_path)) {
                    throw new Error('Backup archive file no longer exists on source node.');
                }
                crossNodeBase64 = fs_1.default.readFileSync(bkp.file_path).toString('base64');
            }
            else {
                const dl = await this.nodeManager.requestRemoteNode(Number(bkp.node_id), 'POST', '/api/v1/backups/download', {
                    filePath: bkp.file_path,
                    expectedSha256: bkp.checksum_sha256 || undefined,
                }, 600_000);
                crossNodeBase64 = dl.archiveBase64;
            }
        }
        let postState = 'stopped';
        if (row.is_local) {
            let localTargetFile = String(bkp.file_path);
            let tempLocalFile = null;
            if (crossNodeBase64) {
                tempLocalFile = this.nodeManager.localRuntime.snapshotManager.resolveConfinedBackupPath(path_1.default.join(this.nodeManager.localRuntime.snapshotManager.getBackupDir(), `crossnode_restore_${Date.now()}_${crypto_1.default.randomBytes(4).toString('hex')}.tar.gz`));
                fs_1.default.mkdirSync(path_1.default.dirname(tempLocalFile), { recursive: true });
                fs_1.default.writeFileSync(tempLocalFile, Buffer.from(crossNodeBase64, 'base64'), { mode: 0o600 });
                localTargetFile = tempLocalFile;
            }
            try {
                const before = await this.nodeManager.localRuntime.containerManager.inspectContainer(row.container_name);
                const wasRunning = before.state === 'running' || before.state === 'frozen';
                if (wasRunning) {
                    await this.nodeManager.localRuntime.containerManager.stopContainer(row.container_name, false);
                }
                await this.nodeManager.localRuntime.snapshotManager.restoreTarBackup(localTargetFile, bkp.checksum_sha256 || undefined, row.container_name);
                if (wasRunning) {
                    await this.nodeManager.localRuntime.containerManager.startContainer(row.container_name);
                }
                const after = await this.nodeManager.localRuntime.containerManager.inspectContainer(row.container_name);
                postState = after.state === 'running' ? 'running' : 'stopped';
            }
            finally {
                if (tempLocalFile && fs_1.default.existsSync(tempLocalFile)) {
                    try {
                        fs_1.default.unlinkSync(tempLocalFile);
                    }
                    catch {
                        // ignore
                    }
                }
            }
        }
        else {
            const resp = await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups/restore`, crossNodeBase64
                ? {
                    archiveBase64: crossNodeBase64,
                    expectedSha256: bkp.checksum_sha256 || undefined,
                }
                : {
                    filePath: bkp.file_path,
                    expectedSha256: bkp.checksum_sha256 || undefined,
                }, 900_000);
            postState = resp.container?.state === 'running' ? 'running' : 'stopped';
        }
        await this.db.run(`UPDATE lxc_instances SET status = ?, updated_at = datetime('now') WHERE id = ?`, [postState, row.id]);
        await this.virt.lxc.syncRegistryRow(row.id);
        await this.db.logActivity({
            userId: actorId,
            action: 'lxc_backup_restored',
            resourceType: 'lxc',
            resourceId: String(row.id),
            details: {
                backupId,
                backupName: bkp.backup_name,
                checksumSha256: bkp.checksum_sha256,
            },
        });
        return { restored: true, status: postState };
    }
    async deleteBackup(backupId) {
        const bkp = await this.getBackupRecord(backupId);
        if (!bkp)
            throw new Error('Backup record not found.');
        if (bkp.node_id && bkp.is_local === 0) {
            await this.nodeManager
                .requestRemoteNode(bkp.node_id, 'DELETE', '/api/v1/backups/file', {
                filePath: bkp.file_path,
            })
                .catch(() => undefined);
        }
        else if (bkp.file_path && fs_1.default.existsSync(bkp.file_path)) {
            fs_1.default.unlinkSync(bkp.file_path);
        }
        await this.db.run(`DELETE FROM container_backups WHERE id = ?`, [backupId]);
    }
}
exports.BackupSnapshotManager = BackupSnapshotManager;
