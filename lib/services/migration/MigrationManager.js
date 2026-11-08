"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MigrationManager = void 0;
const fs_1 = __importDefault(require("fs"));
/**
 * Honest Offline Snapshot-Transfer VPS Migration Manager (Part 15).
 *
 * Never claims zero-downtime CRIU live migration. Executes a verified 7-stage pipeline:
 *   1. Preflight check (target node online, not in maintenance, LXC supported, storage capacity available)
 *   2. Stop container cleanly on source node & export `.tar.gz` bundle with SHA-256 digest
 *   3. Stream bundle to target node
 *   4. Verify SHA-256 checksum on target node & unpack into `/var/lib/lxc/<name>`
 *   5. Apply target node network config & verify container starts cleanly
 *   6. Atomically commit node_id / IP cutover in SQLite
 *   7. Destroy source container copy (ONLY after step 5 & 6 succeed; otherwise automatic rollback restarts source!)
 */
class MigrationManager {
    db;
    nodeManager;
    storageManager;
    lxcAdapter;
    networkManager;
    constructor(db, nodeManager, storageManager, lxcAdapter, networkManager) {
        this.db = db;
        this.nodeManager = nodeManager;
        this.storageManager = storageManager;
        this.lxcAdapter = lxcAdapter;
        this.networkManager = networkManager;
    }
    async listMigrations() {
        return this.db.all(`SELECT m.*,
              sn.name AS source_node_name,
              tn.name AS target_node_name
       FROM vps_migrations m
       LEFT JOIN nodes sn ON sn.id = m.source_node_id
       LEFT JOIN nodes tn ON tn.id = m.target_node_id
       ORDER BY m.id DESC`);
    }
    async getMigration(jobId) {
        return this.db.get(`SELECT m.*,
              sn.name AS source_node_name,
              tn.name AS target_node_name
       FROM vps_migrations m
       LEFT JOIN nodes sn ON sn.id = m.source_node_id
       LEFT JOIN nodes tn ON tn.id = m.target_node_id
       WHERE m.id = ?`, [jobId]);
    }
    async updateJob(jobId, fields) {
        await this.db.run(`UPDATE vps_migrations SET
         status = COALESCE(?, status),
         progress = COALESCE(?, progress),
         checksum_sha256 = COALESCE(?, checksum_sha256),
         bytes_transferred = COALESCE(?, bytes_transferred),
         error_message = COALESCE(?, error_message),
         rollback_performed = COALESCE(?, rollback_performed),
         completed_at = CASE WHEN ? = 1 THEN datetime('now') ELSE completed_at END
       WHERE id = ?`, [
            fields.status ?? null,
            fields.progress ?? null,
            fields.checksum_sha256 ?? null,
            fields.bytes_transferred ?? null,
            fields.error_message ?? null,
            fields.rollback_performed ?? null,
            fields.completed ? 1 : 0,
            jobId,
        ]);
    }
    async startOfflineLxcMigration(params) {
        const lxcRow = await this.lxcAdapter.getRawLxcRow(params.lxcId);
        if (!lxcRow)
            throw new Error(`LXC container #${params.lxcId} not found.`);
        if (lxcRow.node_id === params.targetNodeId) {
            throw new Error('Source and target nodes are identical.');
        }
        const sourceNode = await this.nodeManager.getNodeById(lxcRow.node_id);
        const targetNode = await this.nodeManager.getNodeById(params.targetNodeId);
        if (!sourceNode || !targetNode) {
            throw new Error('Source or target node does not exist.');
        }
        if (targetNode.maintenance_mode) {
            throw new Error(`Target node "${targetNode.name}" is in maintenance mode.`);
        }
        if (targetNode.supports_lxc === 0) {
            throw new Error(`Target node "${targetNode.name}" does not have LXC enabled.`);
        }
        // Live preflight probe BEFORE stopping the running container on sourceNode
        if (!sourceNode.is_local) {
            await this.nodeManager.checkNodeHealthAndStats(sourceNode.id, { bypassCircuit: true });
        }
        if (!targetNode.is_local) {
            const targetProbe = await this.nodeManager.checkNodeHealthAndStats(targetNode.id, {
                bypassCircuit: true,
            });
            if (!targetProbe.health.capabilities.lxcAvailable) {
                throw new Error(`Target node "${targetNode.name}" does not currently have native LXC utilities installed.`);
            }
        }
        const capCheck = await this.storageManager.verifyCapacityAvailable(targetNode.id, 'lxc', Number(lxcRow.disk_gb || 10));
        if (!capCheck.ok) {
            throw new Error(capCheck.reason || 'Insufficient disk space on target node.');
        }
        const ins = await this.db.run(`INSERT INTO vps_migrations
         (lxc_id, instance_type, instance_ref_id, container_name, source_node_id, target_node_id, strategy, migration_mode, status, progress, initiated_by)
       VALUES (?, 'lxc', ?, ?, ?, ?, 'offline_snapshot_transfer', 'offline_snapshot', 'preflight', 10, ?)`, [
            params.lxcId,
            params.lxcId,
            lxcRow.container_name,
            sourceNode.id,
            targetNode.id,
            params.initiatedByUserId,
        ]);
        const jobId = ins.lastID;
        let wasRunningOnSource = false;
        let exportedArchivePath;
        try {
            // Stage 2: Stop & Export on source node
            await this.updateJob(jobId, { status: 'exporting', progress: 25 });
            let archiveBase64;
            let checksumSha256;
            let sizeBytes;
            if (sourceNode.is_local) {
                const bundle = await this.nodeManager.localRuntime.transferManager.prepareOfflineExport(lxcRow.container_name);
                wasRunningOnSource = bundle.wasRunning;
                exportedArchivePath = bundle.archivePath;
                checksumSha256 = bundle.checksumSha256;
                sizeBytes = bundle.sizeBytes;
                archiveBase64 = fs_1.default.readFileSync(bundle.archivePath).toString('base64');
            }
            else {
                const bundle = await this.nodeManager.requestRemoteNode(sourceNode.id, 'POST', '/api/v1/transfers/export', { containerName: lxcRow.container_name }, 900_000);
                wasRunningOnSource = bundle.wasRunning;
                exportedArchivePath = bundle.archivePath;
                checksumSha256 = bundle.checksumSha256;
                sizeBytes = bundle.sizeBytes;
                archiveBase64 = bundle.archiveBase64;
            }
            await this.updateJob(jobId, {
                status: 'transferring',
                progress: 55,
                checksum_sha256: checksumSha256,
                bytes_transferred: sizeBytes,
            });
            // Stage 3 & 4 & 5: Import, SHA-256 Verify, Configure Network, and Verify Startup on Target Node
            await this.updateJob(jobId, { status: 'verifying', progress: 80 });
            if (targetNode.is_local) {
                await this.nodeManager.localRuntime.transferManager.importAndVerifyBundle({
                    containerName: lxcRow.container_name,
                    archiveBufferOrPath: Buffer.from(archiveBase64, 'base64'),
                    expectedChecksumSha256: checksumSha256,
                    targetBridge: params.targetBridge || lxcRow.bridge || 'lxcbr0',
                    targetIpv4: params.targetIpv4 !== undefined ? params.targetIpv4 : lxcRow.ip_address,
                    targetGateway: params.targetGateway !== undefined ? params.targetGateway : lxcRow.gateway,
                    startAfterImport: wasRunningOnSource,
                });
            }
            else {
                await this.nodeManager.requestRemoteNode(targetNode.id, 'POST', '/api/v1/transfers/import', {
                    containerName: lxcRow.container_name,
                    archiveBase64,
                    expectedChecksumSha256: checksumSha256,
                    targetBridge: params.targetBridge || lxcRow.bridge || 'lxcbr0',
                    targetIpv4: params.targetIpv4 !== undefined ? params.targetIpv4 : lxcRow.ip_address,
                    targetGateway: params.targetGateway !== undefined ? params.targetGateway : lxcRow.gateway,
                    startAfterImport: wasRunningOnSource,
                }, 900_000);
            }
            // Stage 6: Commit DB cutover
            await this.db.run(`UPDATE lxc_instances
         SET node_id = ?,
             bridge = COALESCE(?, bridge),
             ip_address = COALESCE(?, ip_address),
             gateway = COALESCE(?, gateway),
             status = ?,
             updated_at = datetime('now')
         WHERE id = ?`, [
                targetNode.id,
                params.targetBridge || null,
                params.targetIpv4 || null,
                params.targetGateway || null,
                wasRunningOnSource ? 'running' : 'stopped',
                params.lxcId,
            ]);
            await this.lxcAdapter.syncRegistryRow(params.lxcId);
            // Relocate any NAT port-forwarding rules attached to this container onto targetNode
            if (this.networkManager) {
                const effectiveGuestIp = params.targetIpv4 !== undefined ? params.targetIpv4 : lxcRow.ip_address;
                await this.networkManager
                    .relocateInstancePortForwards('lxc', params.lxcId, targetNode.id, effectiveGuestIp)
                    .catch(() => undefined);
            }
            // Stage 7: Clean up source copy AFTER target verified & DB committed
            if (sourceNode.is_local) {
                await this.nodeManager.localRuntime.transferManager
                    .finalizeSourceCleanup(lxcRow.container_name, exportedArchivePath)
                    .catch(() => undefined);
            }
            else {
                await this.nodeManager
                    .requestRemoteNode(sourceNode.id, 'POST', `/api/v1/containers/${encodeURIComponent(lxcRow.container_name)}/action`, { action: 'destroy' })
                    .catch(() => undefined);
            }
            await this.updateJob(jobId, { status: 'completed', progress: 100, completed: true });
            await this.db.logActivity({
                userId: params.initiatedByUserId,
                action: 'vps_migration_completed',
                resourceType: 'lxc',
                resourceId: String(params.lxcId),
                details: {
                    containerName: lxcRow.container_name,
                    sourceNodeId: sourceNode.id,
                    targetNodeId: targetNode.id,
                    checksumSha256,
                    bytesTransferred: sizeBytes,
                },
            });
        }
        catch (err) {
            // Automatic pre-commit rollback on source node so source VPS remains intact and running
            let rolledBack = 0;
            try {
                if (sourceNode.is_local) {
                    await this.nodeManager.localRuntime.transferManager.rollbackSourceAfterFailure(lxcRow.container_name, wasRunningOnSource, exportedArchivePath);
                    rolledBack = 1;
                }
                else if (wasRunningOnSource) {
                    await this.nodeManager.requestRemoteNode(sourceNode.id, 'POST', `/api/v1/containers/${encodeURIComponent(lxcRow.container_name)}/action`, { action: 'start' });
                    rolledBack = 1;
                }
            }
            catch {
                // log below
            }
            await this.updateJob(jobId, {
                status: rolledBack ? 'rolled_back' : 'failed',
                error_message: err.message,
                rollback_performed: rolledBack,
                completed: true,
            });
            throw new Error(`Offline migration failed (${rolledBack ? 'source safely rolled back' : 'check node state'}): ${err.message}`);
        }
        return (await this.getMigration(jobId));
    }
}
exports.MigrationManager = MigrationManager;
