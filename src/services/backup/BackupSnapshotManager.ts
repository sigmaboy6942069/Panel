import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
import { VirtualizationManager } from '../virtualization/VirtualizationManager';
import { SafeValidators } from '../../security/middleware';

export class BackupSnapshotManager {
  private db: UnifiedDatabase;
  private nodeManager: NodeManager;
  private virt: VirtualizationManager;

  constructor(
    db: UnifiedDatabase,
    nodeManager: NodeManager,
    virt: VirtualizationManager
  ) {
    this.db = db;
    this.nodeManager = nodeManager;
    this.virt = virt;
  }

  // --- Unified Snapshots (KVM QCOW2 + LXC) ---
  public async listSnapshots(engine: 'kvm' | 'lxc', refId: number) {
    if (engine === 'kvm') {
      return this.db.all<any>(
        `SELECT snapshot_id AS id, vm_id AS ref_id, 'kvm' AS engine, snapshot_name, description, created_at
         FROM vm_snapshots WHERE vm_id = ? ORDER BY snapshot_id DESC`,
        [refId]
      );
    }
    return this.db.all<any>(
      `SELECT id, lxc_id AS ref_id, 'lxc' AS engine, snapshot_name, description, size_bytes, snapshot_type, status, created_at
       FROM container_snapshots WHERE lxc_id = ? ORDER BY id DESC`,
      [refId]
    );
  }

  public async createSnapshot(params: {
    engine: 'kvm' | 'lxc';
    refId: number;
    name?: string;
    description?: string;
    actorId?: number;
  }) {
    if (params.engine === 'kvm') {
      const snapName = params.name
        ? SafeValidators.snapshotName(params.name)
        : `snap_${Date.now()}`;
      return this.virt.kvm.createQcow2Snapshot(
        params.refId,
        snapName,
        params.description || ''
      );
    }

    const row = await this.virt.lxc.getRawLxcRow(params.refId);
    if (!row) throw new Error(`LXC container #${params.refId} not found.`);

    const countRow = await this.db.get<{ cnt: number }>(
      `SELECT COUNT(*) AS cnt FROM container_snapshots WHERE lxc_id = ?`,
      [params.refId]
    );
    const limit = Number(row.snapshot_limit || 5);
    if ((countRow?.cnt || 0) >= limit) {
      throw new Error(`Snapshot limit reached (${countRow?.cnt}/${limit}). Delete an older snapshot first.`);
    }

    let snapInfo: { name: string };
    if (row.is_local) {
      snapInfo = await this.nodeManager.localRuntime.snapshotManager.createSnapshot(
        row.container_name,
        params.description || ''
      );
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{ snapshot: { name: string } }>(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots`,
        { comment: params.description || '' }
      );
      snapInfo = resp.snapshot;
    }

    const ins = await this.db.run(
      `INSERT INTO container_snapshots
         (lxc_id, snapshot_name, description, snapshot_type, status, created_by)
       VALUES (?, ?, ?, 'manual', 'completed', ?)`,
      [params.refId, snapInfo.name, params.description || null, params.actorId || null]
    );

    return { id: ins.lastID, name: snapInfo.name };
  }

  public async restoreSnapshot(
    engine: 'kvm' | 'lxc',
    refId: number,
    snapshotId: number
  ): Promise<void> {
    if (engine === 'kvm') {
      await this.virt.kvm.restoreQcow2Snapshot(refId, snapshotId);
      return;
    }

    const row = await this.virt.lxc.getRawLxcRow(refId);
    const snap = await this.db.get<any>(
      `SELECT * FROM container_snapshots WHERE id = ? AND lxc_id = ?`,
      [snapshotId, refId]
    );
    if (!row || !snap) throw new Error('Container or snapshot not found.');

    if (row.is_local) {
      await this.nodeManager.localRuntime.snapshotManager.restoreSnapshot(
        row.container_name,
        snap.snapshot_name
      );
    } else {
      await this.nodeManager.requestRemoteNode(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots/${encodeURIComponent(snap.snapshot_name)}/restore`
      );
    }
  }

  public async deleteSnapshot(
    engine: 'kvm' | 'lxc',
    refId: number,
    snapshotId: number
  ): Promise<void> {
    if (engine === 'kvm') {
      await this.virt.kvm.deleteQcow2Snapshot(refId, snapshotId);
      return;
    }

    const row = await this.virt.lxc.getRawLxcRow(refId);
    const snap = await this.db.get<any>(
      `SELECT * FROM container_snapshots WHERE id = ? AND lxc_id = ?`,
      [snapshotId, refId]
    );
    if (!row || !snap) throw new Error('Container or snapshot not found.');

    if (row.is_local) {
      await this.nodeManager.localRuntime.snapshotManager
        .deleteSnapshot(row.container_name, snap.snapshot_name)
        .catch(() => undefined);
    } else {
      await this.nodeManager
        .requestRemoteNode(
          row.node_id,
          'DELETE',
          `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots/${encodeURIComponent(snap.snapshot_name)}`
        )
        .catch(() => undefined);
    }
    await this.db.run(`DELETE FROM container_snapshots WHERE id = ?`, [snapshotId]);
  }

  // --- Unified Archive Backups with SHA-256 Integrity ---
  public async listBackups(filter?: { engine?: 'kvm' | 'lxc'; refId?: number }) {
    if (filter?.engine && filter?.refId !== undefined) {
      return this.db.all<any>(
        `SELECT b.*, n.name AS node_name
         FROM container_backups b
         LEFT JOIN nodes n ON n.id = b.node_id
         WHERE b.instance_type = ? AND b.instance_ref_id = ?
         ORDER BY b.id DESC`,
        [filter.engine, filter.refId]
      );
    }
    return this.db.all<any>(
      `SELECT b.*, n.name AS node_name
       FROM container_backups b
       LEFT JOIN nodes n ON n.id = b.node_id
       ORDER BY b.id DESC`
    );
  }

  public async createBackup(params: {
    engine: 'kvm' | 'lxc';
    refId: number;
    label?: string;
    actorId?: number;
  }) {
    if (params.engine === 'kvm') {
      return this.virt.kvm.createDiskBackup(params.refId);
    }

    const row = await this.virt.lxc.getRawLxcRow(params.refId);
    if (!row) throw new Error(`LXC container #${params.refId} not found.`);

    let artifact: {
      backupName: string;
      filePath: string;
      sizeBytes: number;
      checksumSha256: string;
    };

    if (row.is_local) {
      artifact = await this.nodeManager.localRuntime.snapshotManager.createTarBackup(
        row.container_name,
        params.label
      );
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{ backup: typeof artifact }>(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups`,
        { label: params.label },
        900_000
      );
      artifact = resp.backup;
    }

    const ins = await this.db.run(
      `INSERT INTO container_backups
         (instance_type, instance_ref_id, node_id, backup_name, file_path, size_bytes, checksum_sha256, status, created_by)
       VALUES ('lxc', ?, ?, ?, ?, ?, ?, 'completed', ?)`,
      [
        params.refId,
        row.node_id,
        artifact.backupName,
        artifact.filePath,
        artifact.sizeBytes,
        artifact.checksumSha256,
        params.actorId || null,
      ]
    );

    return {
      backupId: ins.lastID,
      ...artifact,
    };
  }

  public async getBackupRecord(backupId: number): Promise<any | undefined> {
    return this.db.get<any>(
      `SELECT b.*, n.is_local
       FROM container_backups b
       LEFT JOIN nodes n ON n.id = b.node_id
       WHERE b.id = ?`,
      [backupId]
    );
  }

  public async verifyBackupIntegrity(backupId: number): Promise<{
    valid: boolean;
    expectedSha256: string | null;
    actualSha256: string | null;
  }> {
    const bkp = await this.getBackupRecord(backupId);
    if (!bkp) throw new Error('Backup record not found.');

    if (bkp.node_id && bkp.is_local === 0) {
      return this.nodeManager.requestRemoteNode<{
        valid: boolean;
        expectedSha256: string | null;
        actualSha256: string | null;
      }>(bkp.node_id, 'POST', '/api/v1/backups/verify', {
        filePath: bkp.file_path,
        expectedSha256: bkp.checksum_sha256,
      });
    }

    if (!fs.existsSync(bkp.file_path)) {
      return { valid: false, expectedSha256: bkp.checksum_sha256, actualSha256: null };
    }
    const actual = await this.nodeManager.localRuntime.snapshotManager.computeFileSha256(
      bkp.file_path
    );
    const valid = !bkp.checksum_sha256 || bkp.checksum_sha256.toLowerCase() === actual.toLowerCase();
    return { valid, expectedSha256: bkp.checksum_sha256, actualSha256: actual };
  }

  public async restoreBackup(
    backupId: number,
    actorId?: number
  ): Promise<{ restored: boolean; status: string }> {
    const bkp = await this.getBackupRecord(backupId);
    if (!bkp) throw new Error('Backup record not found.');

    if (bkp.instance_type !== 'lxc') {
      throw new Error('Archive live restore is currently supported for LXC container backups (use QCOW2 Snapshots for KVM instant revert).');
    }

    const row = await this.virt.lxc.getRawLxcRow(Number(bkp.instance_ref_id));
    if (!row) throw new Error(`LXC container #${bkp.instance_ref_id} not found.`);

    const backupOnDifferentNode =
      Boolean(bkp.node_id) && Number(bkp.node_id) !== Number(row.node_id);

    let crossNodeBase64: string | null = null;
    if (backupOnDifferentNode) {
      if (Number(bkp.is_local || 0) === 1 || Number(bkp.node_id) === 1) {
        if (!fs.existsSync(bkp.file_path)) {
          throw new Error('Backup archive file no longer exists on source node.');
        }
        crossNodeBase64 = fs.readFileSync(bkp.file_path).toString('base64');
      } else {
        const dl = await this.nodeManager.requestRemoteNode<{
          archiveBase64: string;
          checksumSha256: string;
        }>(
          Number(bkp.node_id),
          'POST',
          '/api/v1/backups/download',
          {
            filePath: bkp.file_path,
            expectedSha256: bkp.checksum_sha256 || undefined,
          },
          600_000
        );
        crossNodeBase64 = dl.archiveBase64;
      }
    }

    let postState = 'stopped';
    if (row.is_local) {
      let localTargetFile = String(bkp.file_path);
      let tempLocalFile: string | null = null;
      if (crossNodeBase64) {
        tempLocalFile = this.nodeManager.localRuntime.snapshotManager.resolveConfinedBackupPath(
          path.join(
            this.nodeManager.localRuntime.snapshotManager.getBackupDir(),
            `crossnode_restore_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.tar.gz`
          )
        );
        fs.mkdirSync(path.dirname(tempLocalFile), { recursive: true });
        fs.writeFileSync(tempLocalFile, Buffer.from(crossNodeBase64, 'base64'), { mode: 0o600 });
        localTargetFile = tempLocalFile;
      }
      try {
        const before = await this.nodeManager.localRuntime.containerManager.inspectContainer(
          row.container_name
        );
        const wasRunning = before.state === 'running' || before.state === 'frozen';
        if (wasRunning) {
          await this.nodeManager.localRuntime.containerManager.stopContainer(
            row.container_name,
            false
          );
        }
        await this.nodeManager.localRuntime.snapshotManager.restoreTarBackup(
          localTargetFile,
          bkp.checksum_sha256 || undefined,
          row.container_name
        );
        if (wasRunning) {
          await this.nodeManager.localRuntime.containerManager.startContainer(row.container_name);
        }
        const after = await this.nodeManager.localRuntime.containerManager.inspectContainer(
          row.container_name
        );
        postState = after.state === 'running' ? 'running' : 'stopped';
      } finally {
        if (tempLocalFile && fs.existsSync(tempLocalFile)) {
          try {
            fs.unlinkSync(tempLocalFile);
          } catch {
            // ignore
          }
        }
      }
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{
        success: boolean;
        container?: { state?: string };
      }>(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups/restore`,
        crossNodeBase64
          ? {
              archiveBase64: crossNodeBase64,
              expectedSha256: bkp.checksum_sha256 || undefined,
            }
          : {
              filePath: bkp.file_path,
              expectedSha256: bkp.checksum_sha256 || undefined,
            },
        900_000
      );
      postState = resp.container?.state === 'running' ? 'running' : 'stopped';
    }

    await this.db.run(
      `UPDATE lxc_instances SET status = ?, updated_at = datetime('now') WHERE id = ?`,
      [postState, row.id]
    );
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

  public async deleteBackup(backupId: number): Promise<void> {
    const bkp = await this.getBackupRecord(backupId);
    if (!bkp) throw new Error('Backup record not found.');
    if (bkp.node_id && bkp.is_local === 0) {
      await this.nodeManager
        .requestRemoteNode(bkp.node_id, 'DELETE', '/api/v1/backups/file', {
          filePath: bkp.file_path,
        })
        .catch(() => undefined);
    } else if (bkp.file_path && fs.existsSync(bkp.file_path)) {
      fs.unlinkSync(bkp.file_path);
    }
    await this.db.run(`DELETE FROM container_backups WHERE id = ?`, [backupId]);
  }
}
