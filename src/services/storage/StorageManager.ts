import fs from 'fs';
import path from 'path';
import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';

/**
 * Unified Storage Pool & LXC OS Template Manager for TGVPANEL V3.
 * Supports directory, RAW, QCOW2, LVM, ZFS, and Btrfs storage pools across both
 * local and remote Node Agents, plus centralized LXC OS template catalog management.
 */
export class StorageManager {
  constructor(
    private readonly db: UnifiedDatabase,
    private readonly nodeManager?: NodeManager
  ) {}

  public async listPools(): Promise<any[]> {
    return this.db.all(
      `SELECT sp.*,
              n.name AS node_name,
              COALESCE(n.is_local, 0) AS node_is_local,
              (SELECT COUNT(*) FROM storage_volumes sv WHERE sv.pool_id = sp.id) AS volume_count
       FROM storage_pools sp
       LEFT JOIN nodes n ON n.id = sp.node_id
       ORDER BY sp.id ASC`
    );
  }

  private resolveNearestExistingAncestor(targetPath: string): string | null {
    let cur = path.resolve(targetPath);
    while (true) {
      if (fs.existsSync(cur)) return cur;
      const parent = path.dirname(cur);
      if (!parent || parent === cur) break;
      cur = parent;
    }
    return null;
  }

  public async syncPoolCapacities(): Promise<any[]> {
    const pools = await this.listPools();
    for (const p of pools) {
      if (!p.path) continue;
      const isLocal = Number(p.node_is_local || 0) === 1 || Number(p.node_id) === 1;
      let effectivePath = String(p.path);

      // Heal legacy seeded sandbox path (/home/user/vms) on local-kvm when running elsewhere
      if (
        isLocal &&
        p.name === 'local-kvm' &&
        effectivePath === '/home/user/vms' &&
        !fs.existsSync(effectivePath)
      ) {
        const appVmsDir = path.resolve(process.cwd(), 'vms');
        try {
          fs.mkdirSync(appVmsDir, { recursive: true });
        } catch {
          // ignore if read-only
        }
        if (fs.existsSync(appVmsDir)) {
          effectivePath = appVmsDir;
          await this.db.run(`UPDATE storage_pools SET path = ? WHERE id = ?`, [
            effectivePath,
            p.id,
          ]);
        }
      }

      if (isLocal) {
        const statTarget = this.resolveNearestExistingAncestor(effectivePath);
        if (statTarget) {
          try {
            const st = fs.statfsSync(statTarget);
            const totalBytes = Number(st.blocks) * Number(st.bsize);
            const availBytes = Number(st.bavail) * Number(st.bsize);
            const usedBytes = Math.max(0, totalBytes - availBytes);
            const poolState = fs.existsSync(effectivePath) ? 'online' : 'ready';
            await this.db.run(
              `UPDATE storage_pools
               SET total_bytes = ?, used_bytes = ?, available_bytes = ?, status = ?, updated_at = datetime('now')
               WHERE id = ?`,
              [totalBytes, usedBytes, availBytes, poolState, p.id]
            );
          } catch {
            // Retain cached values when filesystem statfs is restricted
          }
        }
      } else if (this.nodeManager) {
        try {
          const remote = await this.nodeManager.requestRemoteNode<{
            exists: boolean;
            totalBytes: number;
            availableBytes: number;
            usedBytes: number;
          }>(Number(p.node_id), 'POST', '/api/v1/storage/statfs', { path: effectivePath }, 12_000);
          const poolState = remote.exists ? 'online' : 'ready';
          await this.db.run(
            `UPDATE storage_pools
             SET total_bytes = ?, used_bytes = ?, available_bytes = ?, status = ?, updated_at = datetime('now')
             WHERE id = ?`,
            [
              Number(remote.totalBytes || 0),
              Number(remote.usedBytes || 0),
              Number(remote.availableBytes || 0),
              poolState,
              p.id,
            ]
          );
        } catch {
          await this.db
            .run(`UPDATE storage_pools SET status = 'offline', updated_at = datetime('now') WHERE id = ?`, [
              p.id,
            ])
            .catch(() => undefined);
        }
      }
    }
    return this.listPools();
  }

  public async createPool(input: {
    nodeId?: number;
    name: string;
    poolType?: string;
    engineScope?: string;
    path?: string;
    poolPath?: string;
    overcommitRatio?: number;
  }): Promise<any> {
    const nodeId = Number(input.nodeId || 1);
    const name = String(input.name || '').trim();
    const rawPath = String(input.path || input.poolPath || '').trim();
    if (!name || !rawPath) {
      throw new Error('Storage pool name and path are required.');
    }
    const cleanPath = path.resolve(rawPath);
    const poolType = String(input.poolType || 'dir').trim();
    const engineScope = String(input.engineScope || 'both').trim();
    const overcommit = Math.max(0.5, Math.min(10, Number(input.overcommitRatio || 1.5)));

    const nodeRow = await this.db.get<{ is_local?: number }>(
      `SELECT is_local FROM nodes WHERE id = ?`,
      [nodeId]
    );
    const isLocal = nodeId === 1 || Number(nodeRow?.is_local || 0) === 1;
    if (isLocal) {
      try {
        fs.mkdirSync(cleanPath, { recursive: true });
      } catch {
        // Directory may require root or manual mount; statfs will probe nearest ancestor
      }
    } else if (this.nodeManager) {
      await this.nodeManager
        .requestRemoteNode(nodeId, 'POST', '/api/v1/storage/statfs', {
          path: cleanPath,
          ensureDir: true,
        })
        .catch(() => undefined);
    }

    const ins = await this.db.run(
      `INSERT INTO storage_pools (node_id, name, engine, pool_type, engine_scope, path, overcommit_ratio, enabled, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1)`,
      [
        nodeId,
        name,
        engineScope,
        poolType,
        engineScope,
        cleanPath,
        overcommit,
      ]
    );
    await this.syncPoolCapacities().catch(() => undefined);
    return this.db.get(`SELECT * FROM storage_pools WHERE id = ?`, [ins.lastID]);
  }

  public async deletePool(poolId: number): Promise<void> {
    const inUse = await this.db.get<{ cnt: number }>(
      `SELECT COUNT(*) AS cnt FROM storage_volumes WHERE pool_id = ?`,
      [poolId]
    );
    if ((inUse?.cnt || 0) > 0) {
      throw new Error('Cannot delete a storage pool that still contains active volumes.');
    }
    await this.db.run(`DELETE FROM storage_pools WHERE id = ?`, [poolId]);
  }

  public async verifyCapacityAvailable(
    nodeId: number,
    engine: 'kvm' | 'lxc',
    requestedGb: number
  ): Promise<{ ok: boolean; reason?: string }> {
    const pools = await this.db.all<any>(
      `SELECT * FROM storage_pools
       WHERE node_id = ? AND COALESCE(enabled, 1) = 1
         AND (COALESCE(engine_scope, engine, 'both') IN ('both', ?))`,
      [nodeId, engine]
    );
    if (pools.length === 0) return { ok: true };

    const reqBytes = Math.max(1, requestedGb) * 1024 ** 3;
    for (const p of pools) {
      const avail = Number(p.available_bytes || 0);
      if (avail === 0 || avail * Number(p.overcommit_ratio || 1.5) >= reqBytes) {
        return { ok: true };
      }
    }
    return {
      ok: false,
      reason: `Insufficient available storage capacity on node #${nodeId}.`,
    };
  }

  public async listLxcTemplates(includeDisabled = false): Promise<any[]> {
    const where = includeDisabled ? '' : 'WHERE COALESCE(enabled, is_active, 1) = 1';
    return this.db.all(
      `SELECT * FROM lxc_templates ${where} ORDER BY distro ASC, release DESC, id ASC`
    );
  }

  public async upsertLxcTemplate(input: {
    slug: string;
    name: string;
    distro: string;
    release: string;
    arch?: string;
    variant?: string;
    family?: string;
    minDiskGb?: number;
    minRamMb?: number;
    isCustom?: boolean;
    filePath?: string | null;
    checksumSha256?: string | null;
    enabled?: boolean;
  }): Promise<any> {
    const cleanSlug = String(input.slug || `${input.distro}-${input.release}`)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '-');
    if (!cleanSlug || !input.name?.trim()) {
      throw new Error('Template slug and display name are required.');
    }

    const distro = input.distro.trim().toLowerCase();
    const release = input.release.trim();
    const alias = `${distro}:${release}`;

    await this.db.run(
      `INSERT INTO lxc_templates
         (template_key, label, image_alias, slug, name, distro, release, arch, variant, family, min_disk_gb, min_ram_mb, is_custom, local_path, file_path, sha256, checksum_sha256, is_active, enabled)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(slug) DO UPDATE SET
         label = excluded.label,
         name = excluded.name,
         distro = excluded.distro,
         release = excluded.release,
         arch = excluded.arch,
         variant = excluded.variant,
         family = excluded.family,
         min_disk_gb = excluded.min_disk_gb,
         min_ram_mb = excluded.min_ram_mb,
         file_path = COALESCE(excluded.file_path, lxc_templates.file_path),
         checksum_sha256 = COALESCE(excluded.checksum_sha256, lxc_templates.checksum_sha256),
         is_active = excluded.is_active,
         enabled = excluded.enabled`,
      [
        cleanSlug,
        input.name.trim(),
        alias,
        cleanSlug,
        input.name.trim(),
        distro,
        release,
        input.arch?.trim() || 'amd64',
        input.variant?.trim() || 'default',
        input.family?.trim() || 'debian',
        Number(input.minDiskGb || 5),
        Number(input.minRamMb || 256),
        input.isCustom ? 1 : 0,
        input.filePath || null,
        input.filePath || null,
        input.checksumSha256 || null,
        input.checksumSha256 || null,
        input.enabled !== false ? 1 : 0,
        input.enabled !== false ? 1 : 0,
      ]
    );
    return this.db.get(`SELECT * FROM lxc_templates WHERE slug = ?`, [cleanSlug]);
  }

  public async toggleLxcTemplate(id: number, enabled: boolean): Promise<void> {
    const v = enabled ? 1 : 0;
    await this.db.run(`UPDATE lxc_templates SET enabled = ?, is_active = ? WHERE id = ?`, [
      v,
      v,
      id,
    ]);
  }

  public async deleteLxcTemplate(id: number): Promise<void> {
    const row = await this.db.get<any>(`SELECT * FROM lxc_templates WHERE id = ?`, [id]);
    if (row?.is_custom && row?.file_path && fs.existsSync(row.file_path)) {
      try {
        fs.unlinkSync(row.file_path);
      } catch {
        // ignore
      }
    }
    await this.db.run(`DELETE FROM lxc_templates WHERE id = ?`, [id]);
  }
}
