import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { UnifiedDatabase } from '../../db/database';
import {
  decryptSecret,
  encryptSecret,
  generateStrongPassword,
} from '../../security/crypto-vault';
import { SafeValidators } from '../../security/middleware';
import { NodeManager } from '../nodes/NodeClient';
import { privilegedFs } from '../../node-agent/command-runner';
import {
  LxcContainerRuntimeInfo,
  LxcCreateSpec,
  LxcNetworkRepairResult,
} from '../../node-agent/container-manager';
import {
  InstanceCapabilityProfile,
  InstanceTelemetry,
  LifecycleAction,
  UnifiedInstanceRecord,
  VirtualizationAdapter,
} from './VirtualizationAdapter';

export interface CreateLxcInstanceInput {
  userId: number;
  nodeId?: number;
  containerName: string;
  hostname?: string;
  templateSlug?: string;
  distro?: string;
  release?: string;
  arch?: string;
  cpuCores: number;
  cpuShares?: number;
  cpuLimitPercent?: number;
  cpuPinning?: string | null;
  ramMb: number;
  swapMb?: number;
  diskGb: number;
  backingStore?: 'dir' | 'lvm' | 'zfs' | 'btrfs';
  privileged?: boolean;
  nesting?: boolean;
  kvmNesting?: boolean;
  bridge?: string;
  ipv4Address?: string | null;
  ipv4Gateway?: string | null;
  ipv6Address?: string | null;
  macAddress?: string | null;
  vlanId?: number | null;
  rootPassword?: string;
  sshPublicKeys?: string[];
  autostart?: boolean;
  bandwidthQuotaGb?: number;
  expirationDays?: number;
  autoSuspendEnabled?: boolean;
  notes?: string;
  provisionOnHost?: boolean;
}

export class LXCAdapter implements VirtualizationAdapter {
  public readonly engine = 'lxc' as const;
  private db: UnifiedDatabase;
  private nodeManager: NodeManager;
  private prevContainerCpu = new Map<number, { cpuSec: number; tsMs: number }>();
  private inFlightPanelCreations = new Set<string>();

  constructor(db: UnifiedDatabase, nodeManager: NodeManager) {
    this.db = db;
    this.nodeManager = nodeManager;
  }

  public getCapabilityProfile(): InstanceCapabilityProfile {
    return {
      engine: 'lxc',
      supportsFreeze: true,
      supportsSuspend: true,
      supportsSnapshots: true,
      supportsBackups: true,
      supportsOfflineMigration: true,
      supportsIsoMount: false,
      supportsBootOrder: false,
      supportsSmbios: false,
      supportsCloudInit: false,
      supportsSerialConsole: false,
      supportsPtyConsole: true,
      supportsSshBridge: true,
      supportsRootfsFileBrowser: true,
      supportsContainerProcessList: true,
    };
  }

  private mapRowToUnified(row: any): UnifiedInstanceRecord {
    let shared: number[] = [];
    try {
      const parsed = JSON.parse(row.shared_with || '[]');
      if (Array.isArray(parsed)) shared = parsed.map(Number).filter(Boolean);
    } catch {
      shared = [];
    }

    return {
      uid: `lxc:${row.id}`,
      engine: 'lxc',
      refId: row.id,
      name: row.container_name,
      hostname: row.hostname || row.container_name,
      ownerId: row.user_id,
      ownerUsername: row.owner_username || undefined,
      nodeId: row.node_id,
      nodeName: row.node_name || 'localhost',
      status: row.suspended ? 'suspended' : row.status || 'stopped',
      suspended: Boolean(row.suspended),
      suspendedReason: row.suspended_reason || null,
      osLabel: row.os_template || 'ubuntu:24.04',
      cpuCores: Number(row.cpu_cores || 1),
      ramMb: Number(row.ram_mb || 1024),
      swapMb: Number(row.swap_mb || 512),
      diskGb: Number(row.disk_gb || 20),
      primaryIp: row.ip_address || null,
      sshPort: 22,
      sharedWith: shared,
      expiresAt: row.expires_at || null,
      createdAt: row.created_at,
      capabilities: this.getCapabilityProfile(),
    };
  }

  public async syncRegistryRow(lxcId: number): Promise<void> {
    const row = await this.db.get<any>(`SELECT * FROM lxc_instances WHERE id = ?`, [lxcId]);
    if (!row) {
      await this.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [lxcId]);
      return;
    }

    await this.db.run(
      `INSERT INTO instances
         (engine, ref_id, name, hostname, owner_id, node_id, status, suspended, os_label, cpu_cores, ram_mb, disk_gb, primary_ip, shared_with, updated_at)
       VALUES ('lxc', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(engine, ref_id) DO UPDATE SET
         name = excluded.name,
         hostname = excluded.hostname,
         owner_id = excluded.owner_id,
         node_id = excluded.node_id,
         status = excluded.status,
         suspended = excluded.suspended,
         os_label = excluded.os_label,
         cpu_cores = excluded.cpu_cores,
         ram_mb = excluded.ram_mb,
         disk_gb = excluded.disk_gb,
         primary_ip = excluded.primary_ip,
         shared_with = excluded.shared_with,
         updated_at = datetime('now')`,
      [
        row.id,
        row.container_name,
        row.hostname || row.container_name,
        row.user_id,
        row.node_id,
        row.status || 'stopped',
        row.suspended ? 1 : 0,
        row.os_template || 'ubuntu:24.04',
        row.cpu_cores || 1,
        row.ram_mb || 1024,
        row.disk_gb || 20,
        row.ip_address || null,
        row.shared_with || '[]',
      ]
    );
  }

  public async listInstances(filter?: {
    ownerId?: number;
    nodeId?: number;
  }): Promise<UnifiedInstanceRecord[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];

    if (filter?.ownerId !== undefined) {
      clauses.push(`(l.user_id = ? OR l.shared_with LIKE ?)`);
      params.push(filter.ownerId, `%${filter.ownerId}%`);
    }
    if (filter?.nodeId !== undefined) {
      clauses.push(`l.node_id = ?`);
      params.push(filter.nodeId);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = await this.db.all<any>(
      `SELECT l.*, u.username AS owner_username, n.name AS node_name
       FROM lxc_instances l
       LEFT JOIN users u ON u.id = l.user_id
       LEFT JOIN nodes n ON n.id = l.node_id
       ${whereSql}
       ORDER BY l.id DESC`,
      params
    );

    const mapped = rows.map((r) => this.mapRowToUnified(r));
    if (filter?.ownerId !== undefined) {
      return mapped.filter(
        (m) => m.ownerId === filter.ownerId || m.sharedWith.includes(filter.ownerId!)
      );
    }
    return mapped;
  }

  public async getInstance(refId: number): Promise<UnifiedInstanceRecord | undefined> {
    const row = await this.db.get<any>(
      `SELECT l.*, u.username AS owner_username, n.name AS node_name
       FROM lxc_instances l
       LEFT JOIN users u ON u.id = l.user_id
       LEFT JOIN nodes n ON n.id = l.node_id
       WHERE l.id = ?`,
      [refId]
    );
    return row ? this.mapRowToUnified(row) : undefined;
  }

  public async getRawLxcRow(refId: number): Promise<any | undefined> {
    return this.db.get<any>(
      `SELECT l.*, u.username AS owner_username, n.name AS node_name, n.is_local
       FROM lxc_instances l
       LEFT JOIN users u ON u.id = l.user_id
       LEFT JOIN nodes n ON n.id = l.node_id
       WHERE l.id = ?`,
      [refId]
    );
  }

  private async resolveCatalogTemplate(rawIdentifier: string): Promise<any | undefined> {
    const trimmed = String(rawIdentifier || '').trim();
    if (!trimmed) return undefined;
    const normalizedSlug = trimmed.toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
    return this.db.get<any>(
      `SELECT * FROM lxc_templates
       WHERE (LOWER(slug) = LOWER(?) OR slug = ? OR LOWER(COALESCE(image_alias, '')) = LOWER(?))
         AND COALESCE(enabled, is_active, 1) = 1
       ORDER BY COALESCE(is_custom, 0) DESC, id ASC
       LIMIT 1`,
      [trimmed, normalizedSlug, trimmed]
    );
  }

  public async createLxcInstance(input: CreateLxcInstanceInput): Promise<{
    instance: UnifiedInstanceRecord;
    generatedRootPassword: string;
    hostProvisioned: boolean;
    warning?: string;
  }> {
    const safeName = SafeValidators.containerName(input.containerName);
    const lockKey = safeName.toLowerCase();
    if (this.inFlightPanelCreations.has(lockKey)) {
      throw new Error(
        `LXC container "${safeName}" is currently being provisioned (downloading OS template). Please wait for it to finish.`
      );
    }

    const existing = await this.db.get<{ id: number }>(
      `SELECT id FROM lxc_instances WHERE LOWER(container_name) = LOWER(?)`,
      [safeName]
    );
    if (existing) {
      throw new Error(`An LXC container named "${safeName}" already exists.`);
    }

    const node = input.nodeId
      ? await this.nodeManager.getNodeById(input.nodeId)
      : await this.nodeManager.getDefaultNodeForEngine('lxc');
    if (!node) throw new Error('Target node not found.');
    if (node.maintenance_mode) {
      throw new Error(`Node "${node.name}" is currently in maintenance mode.`);
    }
    const maxInst = Number(node.max_instances || 0);
    if (maxInst > 0 && Number(node.total_instances || 0) >= maxInst) {
      throw new Error(
        `Node "${node.name}" has reached its maximum instance quota (${node.total_instances}/${maxInst}).`
      );
    }

    this.inFlightPanelCreations.add(lockKey);
    try {
      // Resolve template metadata from lxc_templates catalog
      let distro = input.distro || 'ubuntu';
      let release = input.release || '24.04';
      let fallbackRelease: string | null = null;
      let templateArchivePath: string | null = null;
      let arch = input.arch || 'amd64';
      let osTemplateLabel = input.templateSlug || `${distro}:${release}`;
      let osFamily = 'debian';

      if (input.templateSlug) {
        const tpl = await this.resolveCatalogTemplate(input.templateSlug);
        if (!tpl && !input.distro) {
          throw new Error(`Enabled LXC template "${input.templateSlug}" not found in catalog.`);
        }
        if (tpl) {
          distro = tpl.distro;
          release = tpl.release;
          fallbackRelease = tpl.fallback_alias || null;
          templateArchivePath = tpl.file_path || tpl.local_path || null;
          arch = tpl.arch || 'amd64';
          osTemplateLabel = tpl.slug;
          osFamily = tpl.family || 'debian';
        }
      }

      const plainPassword = input.rootPassword?.trim() || generateStrongPassword(18);
      const encryptedPass = encryptSecret(plainPassword);
      const mac =
        input.macAddress ||
        `00:16:3e:${[0, 1, 2]
          .map(() => Math.floor(Math.random() * 256).toString(16).padStart(2, '0'))
          .join(':')}`;

      const expDays = Math.max(0, Number(input.expirationDays || 0));
      const expiresAt =
        expDays > 0
          ? new Date(Date.now() + expDays * 86_400_000).toISOString()
          : null;

      const spec: LxcCreateSpec = {
        containerName: safeName,
        hostname: input.hostname || safeName,
        distro,
        release,
        fallbackRelease,
        templateArchivePath,
        arch,
        cpuCores: Math.max(1, Number(input.cpuCores || 1)),
        cpuShares: Number(input.cpuShares || 1024),
        cpuLimitPercent: Number(input.cpuLimitPercent || 100),
        cpuPinning: input.cpuPinning || null,
        ramMb: Math.max(128, Number(input.ramMb || 1024)),
        swapMb: Math.max(0, Number(input.swapMb ?? 512)),
        diskGb: Math.max(2, Number(input.diskGb || 20)),
        backingStore: input.backingStore || 'dir',
        privileged: input.privileged !== false,
        nesting: input.nesting !== false,
        kvmNesting: Boolean(input.kvmNesting),
        bridge: input.bridge || 'lxcbr0',
        ipv4Address: input.ipv4Address || null,
        ipv4Gateway: input.ipv4Gateway || null,
        ipv6Address: input.ipv6Address || null,
        macAddress: mac,
        vlanId: input.vlanId || null,
        rootPassword: plainPassword,
        sshPublicKeys: input.sshPublicKeys || [],
        autostart: Boolean(input.autostart),
        replaceOrphanOnHost: true,
      };

      let runtimeState = 'stopped';
      let detectedIp = input.ipv4Address || null;
      let detectedGw = spec.ipv4Gateway || null;
      let effectiveBackingStore: string = spec.backingStore || 'dir';
      let hostProvisioned = false;
      let warning: string | undefined;

      if (input.provisionOnHost !== false) {
        if (node.is_local) {
          const info = await this.nodeManager.localRuntime.containerManager.createContainer(spec);
          runtimeState = info.state === 'running' ? 'running' : 'stopped';
          if (info.backingStore) effectiveBackingStore = info.backingStore;
          if (!detectedIp && (info.ips.length > 0 || info.configuredIpv4)) {
            detectedIp = info.ips[0] || info.configuredIpv4 || null;
          }
          if (!detectedGw && info.configuredGateway && info.configuredGateway !== 'auto') {
            detectedGw = info.configuredGateway;
          }
          if (info.startupWarning) warning = info.startupWarning;
          hostProvisioned = true;
        } else {
          if (spec.templateArchivePath && fs.existsSync(spec.templateArchivePath)) {
            spec.templateArchivePath = await this.ensureTemplateStagedOnRemoteNode(
              node.id,
              spec.templateArchivePath
            );
          }
          const info = await this.nodeManager.requestRemoteNode<LxcContainerRuntimeInfo>(
            node.id,
            'POST',
            '/api/v1/containers',
            spec,
            600_000
          );
          runtimeState = info.state === 'running' ? 'running' : 'stopped';
          if (info.backingStore) effectiveBackingStore = info.backingStore;
          if (!detectedIp && (info.ips?.length > 0 || info.configuredIpv4)) {
            detectedIp = info.ips?.[0] || info.configuredIpv4 || null;
          }
          if (!detectedGw && info.configuredGateway && info.configuredGateway !== 'auto') {
            detectedGw = info.configuredGateway;
          }
          if (info.startupWarning) warning = info.startupWarning;
          hostProvisioned = true;
        }
      } else {
        warning = 'Registered in database without immediate host provisioning.';
      }

      const ins = await this.db.run(
        `INSERT INTO lxc_instances (
          user_id, node_id, container_name, hostname, os_template, os_family, arch,
          cpu_cores, cpu_shares, cpu_limit_pct, cpu_pinning, ram_mb, swap_mb, disk_gb,
          rootfs_storage_type, privileged, nesting, kvm_nesting, autostart, root_password_enc,
          bridge, ip_address, gateway, ipv6_address, mac_address, vlan_id,
          status, bandwidth_quota_gb, notes, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          input.userId,
          node.id,
          safeName,
          spec.hostname,
          osTemplateLabel,
          osFamily,
          arch,
          spec.cpuCores,
          spec.cpuShares,
          spec.cpuLimitPercent,
          spec.cpuPinning,
          spec.ramMb,
          spec.swapMb,
          spec.diskGb,
          effectiveBackingStore,
          spec.privileged ? 1 : 0,
          spec.nesting ? 1 : 0,
          spec.kvmNesting ? 1 : 0,
          spec.autostart ? 1 : 0,
          encryptedPass,
          spec.bridge,
          detectedIp,
          detectedGw,
          spec.ipv6Address,
          mac,
          spec.vlanId,
          runtimeState,
          Number(input.bandwidthQuotaGb || 0),
          input.notes || null,
          expiresAt,
          expDays,
          input.autoSuspendEnabled !== false ? 1 : 0,
        ]
      );

      if (expiresAt || expDays > 0) {
        await this.db.run(
          `INSERT OR REPLACE INTO vps_expiration (lxc_id, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at)
           VALUES (?, ?, ?, ?, datetime('now'))`,
          [ins.lastID, expiresAt, expDays, input.autoSuspendEnabled !== false ? 1 : 0]
        );
      }

      await this.syncRegistryRow(ins.lastID);
      const created = (await this.getInstance(ins.lastID))!;

      return {
        instance: created,
        generatedRootPassword: plainPassword,
        hostProvisioned,
        warning,
      };
    } finally {
      this.inFlightPanelCreations.delete(lockKey);
    }
  }

  private async ensureTemplateStagedOnRemoteNode(
    nodeId: number,
    localArchivePath: string
  ): Promise<string> {
    const buf = fs.readFileSync(localArchivePath);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const safeName = `${sha256.slice(0, 12)}_${path.basename(localArchivePath)}`;

    try {
      const status = await this.nodeManager.requestRemoteNode<{
        cached: boolean;
        filePath: string;
      }>(
        nodeId,
        'GET',
        `/api/v1/templates/status?name=${encodeURIComponent(safeName)}&sha256=${encodeURIComponent(sha256)}`
      );
      if (status?.cached && status.filePath) {
        return status.filePath;
      }
    } catch {
      // Proceed to stage upload
    }

    const staged = await this.nodeManager.requestRemoteNode<{
      staged: boolean;
      filePath: string;
    }>(
      nodeId,
      'POST',
      '/api/v1/templates/stage',
      {
        name: safeName,
        archiveBase64: buf.toString('base64'),
        expectedSha256: sha256,
      },
      300_000
    );
    return staged.filePath;
  }

  /**
   * Discovers any existing native LXC containers across the local node and all online remote
   * Node Agents (or a specific target `nodeId`) that are not yet tracked in `lxc_instances`
   * and imports them cleanly with accurate `node_id` ownership.
   */
  public async syncHostContainers(
    defaultUserId = 1,
    targetNodeId?: number
  ): Promise<{ imported: string[]; count: number; byNode?: Record<number, string[]> }> {
    const allNodes = await this.nodeManager.listNodes();
    const candidates =
      targetNodeId !== undefined
        ? allNodes.filter((n) => n.id === Number(targetNodeId))
        : allNodes.filter((n) => n.is_local || n.status === 'online');

    const imported: string[] = [];
    const byNode: Record<number, string[]> = {};
    const cm = this.nodeManager.localRuntime.containerManager;

    for (const node of candidates) {
      let hostList: LxcContainerRuntimeInfo[] = [];
      try {
        if (node.is_local) {
          hostList = await cm.listContainers();
        } else {
          const resp = await this.nodeManager.requestRemoteNode<{
            containers: LxcContainerRuntimeInfo[];
          }>(node.id, 'GET', '/api/v1/containers', undefined, 15_000);
          hostList = Array.isArray(resp?.containers) ? resp.containers : [];
        }
      } catch {
        continue;
      }

      for (const ct of hostList) {
        const lockKey = ct.name.toLowerCase();
        if (
          this.inFlightPanelCreations.has(lockKey) ||
          (node.is_local && cm.isCreationInFlight(ct.name))
        ) {
          continue;
        }
        const existing = await this.db.get<{ id: number }>(
          `SELECT id FROM lxc_instances WHERE node_id = ? AND LOWER(container_name) = LOWER(?)`,
          [node.id, ct.name]
        );
        if (existing) {
          // Keep live runtime status & IP synchronized on already-tracked containers
          const liveState =
            ct.state === 'running' ? 'running' : ct.state === 'frozen' ? 'frozen' : 'stopped';
          const liveIp = ct.ips && ct.ips.length > 0 ? ct.ips[0] : null;
          await this.db
            .run(
              `UPDATE lxc_instances
               SET status = CASE WHEN suspended = 1 THEN status ELSE ? END,
                   ip_address = COALESCE(ip_address, ?)
               WHERE id = ?`,
              [liveState, liveIp, existing.id]
            )
            .catch(() => undefined);
          await this.syncRegistryRow(existing.id).catch(() => undefined);
          continue;
        }

        // Also avoid duplicate global name collisions if same name was registered before node_id scoping
        const anyNameMatch = await this.db.get<{ id: number }>(
          `SELECT id FROM lxc_instances WHERE LOWER(container_name) = LOWER(?)`,
          [ct.name]
        );
        if (anyNameMatch) continue;

        const status =
          ct.state === 'running' ? 'running' : ct.state === 'frozen' ? 'frozen' : 'stopped';
        const detectedIp = ct.ips && ct.ips.length > 0 ? ct.ips[0] : null;
        const ins = await this.db.run(
          `INSERT INTO lxc_instances (
            user_id, node_id, container_name, hostname, os_template, os_family, arch,
            cpu_cores, ram_mb, swap_mb, disk_gb, privileged, nesting, bridge, ip_address, status, notes
          ) VALUES (?, ?, ?, ?, 'imported', 'linux', 'amd64', 2, 1024, 512, 20, 1, 1, 'lxcbr0', ?, ?, ?)`,
          [
            defaultUserId,
            node.id,
            ct.name,
            ct.name,
            detectedIp,
            status,
            `Imported from node "${node.name}"`,
          ]
        );
        await this.syncRegistryRow(ins.lastID);
        imported.push(ct.name);
        if (!byNode[node.id]) byNode[node.id] = [];
        byNode[node.id].push(ct.name);
      }
    }

    return { imported, count: imported.length, byNode };
  }

  private async dispatchNodeContainerAction(
    nodeId: number,
    isLocal: boolean,
    containerName: string,
    action: string,
    extra: Record<string, unknown> = {}
  ): Promise<LxcContainerRuntimeInfo | null> {
    if (isLocal) {
      const mgr = this.nodeManager.localRuntime.containerManager;
      switch (action) {
        case 'start':
          await mgr.startContainer(containerName);
          break;
        case 'stop':
          await mgr.stopContainer(containerName, Boolean(extra.force));
          break;
        case 'restart':
          await mgr.restartContainer(containerName);
          break;
        case 'freeze':
          await mgr.freezeContainer(containerName);
          break;
        case 'unfreeze':
          await mgr.unfreezeContainer(containerName);
          break;
        case 'destroy':
          await mgr.destroyContainer(containerName);
          return null;
        case 'password':
          await mgr.setRootPassword(containerName, String(extra.password || ''));
          break;
        case 'ssh_key':
          await mgr.injectSshPublicKey(containerName, String(extra.sshPublicKey || ''));
          break;
      }
      return mgr.inspectContainer(containerName);
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{ container: LxcContainerRuntimeInfo }>(
        nodeId,
        'POST',
        `/api/v1/containers/${encodeURIComponent(containerName)}/action`,
        { action, ...extra }
      );
      return resp.container || null;
    }
  }

  public async performLifecycleAction(
    refId: number,
    action: LifecycleAction,
    options?: { reason?: string; actorId?: number; force?: boolean }
  ): Promise<UnifiedInstanceRecord> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);

    const isLocal = Boolean(row.is_local);
    const cname = row.container_name;

    if (action === 'start') {
      if (row.suspended) {
        throw new Error('This LXC VPS is suspended and cannot be started until unsuspended.');
      }
      const info = await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'start');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'running', ip_address = COALESCE(?, ip_address), updated_at = datetime('now') WHERE id = ?`,
        [info?.ips?.[0] || null, refId]
      );
    } else if (action === 'stop') {
      await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'stop', {
        force: options?.force,
      });
      await this.db.run(
        `UPDATE lxc_instances SET status = 'stopped', updated_at = datetime('now') WHERE id = ?`,
        [refId]
      );
    } else if (action === 'restart') {
      if (row.suspended) {
        throw new Error('This LXC VPS is suspended and cannot be restarted.');
      }
      await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'restart');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'running', updated_at = datetime('now') WHERE id = ?`,
        [refId]
      );
    } else if (action === 'freeze') {
      await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'freeze');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'frozen', updated_at = datetime('now') WHERE id = ?`,
        [refId]
      );
    } else if (action === 'unfreeze') {
      if (row.suspended) {
        throw new Error('This LXC VPS is suspended and cannot be unfrozen until unsuspended.');
      }
      await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'unfreeze');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'running', updated_at = datetime('now') WHERE id = ?`,
        [refId]
      );
    } else if (action === 'suspend') {
      await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'stop', { force: true }).catch(
        () => undefined
      );
      let history: any[] = [];
      try {
        history = JSON.parse(row.suspension_history || '[]');
      } catch {
        history = [];
      }
      history.push({
        event: 'suspended',
        reason: options?.reason || 'Administrative suspension',
        actorId: options?.actorId || null,
        at: new Date().toISOString(),
      });
      await this.db.run(
        `UPDATE lxc_instances
         SET suspended = 1, suspended_reason = ?, suspension_history = ?, status = 'stopped', updated_at = datetime('now')
         WHERE id = ?`,
        [options?.reason || 'Administrative suspension', JSON.stringify(history), refId]
      );
    } else if (action === 'unsuspend') {
      let history: any[] = [];
      try {
        history = JSON.parse(row.suspension_history || '[]');
      } catch {
        history = [];
      }
      history.push({
        event: 'unsuspended',
        actorId: options?.actorId || null,
        at: new Date().toISOString(),
      });
      await this.db.run(
        `UPDATE lxc_instances
         SET suspended = 0, suspended_reason = NULL, suspension_history = ?, updated_at = datetime('now')
         WHERE id = ?`,
        [JSON.stringify(history), refId]
      );
    } else if (action === 'delete') {
      await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'destroy').catch(
        () => undefined
      );
      await this.db
        .run(
          `UPDATE ip_allocations
           SET instance_type = NULL, instance_ref_id = NULL, assigned_user_id = NULL
           WHERE instance_type = 'lxc' AND instance_ref_id = ?`,
          [refId]
        )
        .catch(() => undefined);
      await this.db
        .run(`DELETE FROM port_forwards WHERE instance_type = 'lxc' AND instance_ref_id = ?`, [
          refId,
        ])
        .catch(() => undefined);
      await this.db
        .run(`DELETE FROM metrics_history WHERE target_type = 'lxc' AND target_id = ?`, [refId])
        .catch(() => undefined);
      await this.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [refId]);
      await this.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [refId]);
      return this.mapRowToUnified({ ...row, status: 'deleted' });
    }

    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async resizeAndUpdateConfig(
    refId: number,
    patch: {
      hostname?: string;
      cpuCores?: number;
      cpuShares?: number;
      cpuLimitPercent?: number;
      cpuPinning?: string | null;
      ramMb?: number;
      swapMb?: number;
      diskGb?: number;
      nesting?: boolean;
      kvmNesting?: boolean;
      autostart?: boolean;
      bridge?: string;
      ipAddress?: string | null;
      gateway?: string | null;
      ipv6Address?: string | null;
      bandwidthQuotaGb?: number;
      notes?: string;
    },
    applyToHost = true
  ): Promise<UnifiedInstanceRecord> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);

    if (applyToHost) {
      const resourcePayload = {
        cpuCores: patch.cpuCores ?? row.cpu_cores,
        cpuShares: patch.cpuShares ?? row.cpu_shares,
        cpuLimitPercent: patch.cpuLimitPercent ?? row.cpu_limit_pct,
        cpuPinning: patch.cpuPinning !== undefined ? patch.cpuPinning : row.cpu_pinning,
        ramMb: patch.ramMb ?? row.ram_mb,
        swapMb: patch.swapMb ?? row.swap_mb,
        diskGb: patch.diskGb ?? row.disk_gb,
        nesting: patch.nesting !== undefined ? patch.nesting : Boolean(row.nesting),
        kvmNesting: patch.kvmNesting !== undefined ? patch.kvmNesting : Boolean(row.kvm_nesting),
        autostart: patch.autostart !== undefined ? patch.autostart : Boolean(row.autostart),
        bridge: patch.bridge ?? row.bridge,
        ipv4Address: patch.ipAddress !== undefined ? patch.ipAddress : row.ip_address,
        ipv4Gateway: patch.gateway !== undefined ? patch.gateway : row.gateway,
        ipv6Address: patch.ipv6Address !== undefined ? patch.ipv6Address : row.ipv6_address,
      };

      if (row.is_local) {
        const cfgFileExists =
          this.nodeManager.localRuntime.containerManager.getContainerDir(row.container_name);
        try {
          await this.nodeManager.localRuntime.containerManager.updateContainerResources(
            row.container_name,
            resourcePayload
          );
          const refreshed = await this.nodeManager.localRuntime.containerManager
            .inspectContainer(row.container_name)
            .catch(() => null);
          if (refreshed?.diskQuotaEnforced && row.rootfs_storage_type !== 'loop') {
            await this.db.run(
              `UPDATE lxc_instances SET rootfs_storage_type = 'loop' WHERE id = ?`,
              [refId]
            );
          }
        } catch (err: any) {
          // If container dir exists on disk, surface real error; otherwise allow DB config edit when host is in controller-only mode
          if (!String(err.message).includes('Container config not found') || !cfgFileExists) {
            throw err;
          }
        }
      } else {
        await this.nodeManager.requestRemoteNode(
          row.node_id,
          'PATCH',
          `/api/v1/containers/${encodeURIComponent(row.container_name)}/resources`,
          resourcePayload
        );
      }
    }

    await this.db.run(
      `UPDATE lxc_instances SET
         hostname = COALESCE(?, hostname),
         cpu_cores = COALESCE(?, cpu_cores),
         cpu_shares = COALESCE(?, cpu_shares),
         cpu_limit_pct = COALESCE(?, cpu_limit_pct),
         cpu_pinning = CASE WHEN ? = '__KEEP__' THEN cpu_pinning ELSE ? END,
         ram_mb = COALESCE(?, ram_mb),
         swap_mb = COALESCE(?, swap_mb),
         disk_gb = COALESCE(?, disk_gb),
         nesting = COALESCE(?, nesting),
         kvm_nesting = COALESCE(?, kvm_nesting),
         autostart = COALESCE(?, autostart),
         bridge = COALESCE(?, bridge),
         ip_address = CASE WHEN ? = '__KEEP__' THEN ip_address ELSE ? END,
         gateway = CASE WHEN ? = '__KEEP__' THEN gateway ELSE ? END,
         ipv6_address = CASE WHEN ? = '__KEEP__' THEN ipv6_address ELSE ? END,
         bandwidth_quota_gb = COALESCE(?, bandwidth_quota_gb),
         notes = COALESCE(?, notes),
         updated_at = datetime('now')
       WHERE id = ?`,
      [
        patch.hostname ?? null,
        patch.cpuCores ?? null,
        patch.cpuShares ?? null,
        patch.cpuLimitPercent ?? null,
        patch.cpuPinning === undefined ? '__KEEP__' : 'SET',
        patch.cpuPinning ?? null,
        patch.ramMb ?? null,
        patch.swapMb ?? null,
        patch.diskGb ?? null,
        patch.nesting !== undefined ? (patch.nesting ? 1 : 0) : null,
        patch.kvmNesting !== undefined ? (patch.kvmNesting ? 1 : 0) : null,
        patch.autostart !== undefined ? (patch.autostart ? 1 : 0) : null,
        patch.bridge ?? null,
        patch.ipAddress === undefined ? '__KEEP__' : 'SET',
        patch.ipAddress ?? null,
        patch.gateway === undefined ? '__KEEP__' : 'SET',
        patch.gateway ?? null,
        patch.ipv6Address === undefined ? '__KEEP__' : 'SET',
        patch.ipv6Address ?? null,
        patch.bandwidthQuotaGb ?? null,
        patch.notes ?? null,
        refId,
      ]
    );

    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async reinstallLxcInstance(
    refId: number,
    templateSlug: string,
    newRootPassword?: string
  ): Promise<{ instance: UnifiedInstanceRecord; rootPassword: string }> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.suspended) {
      throw Object.assign(
        new Error('This LXC VPS is suspended and cannot be reinstalled until unsuspended.'),
        { statusCode: 400 }
      );
    }

    const tpl = await this.resolveCatalogTemplate(templateSlug);
    if (!tpl) throw new Error(`Enabled LXC template "${templateSlug}" not found.`);

    const plainPassword = newRootPassword?.trim() || generateStrongPassword(18);
    const reinstallSpec: LxcCreateSpec = {
      containerName: row.container_name,
      hostname: row.hostname || row.container_name,
      distro: tpl.distro,
      release: tpl.release,
      fallbackRelease: tpl.fallback_alias || null,
      templateArchivePath: tpl.file_path || tpl.local_path || null,
      arch: tpl.arch || 'amd64',
      cpuCores: row.cpu_cores,
      cpuShares: row.cpu_shares,
      cpuLimitPercent: row.cpu_limit_pct,
      ramMb: row.ram_mb,
      swapMb: row.swap_mb,
      diskGb: row.disk_gb,
      backingStore: row.rootfs_storage_type || 'dir',
      privileged: Boolean(row.privileged),
      nesting: Boolean(row.nesting),
      kvmNesting: Boolean(row.kvm_nesting),
      bridge: row.bridge || 'lxcbr0',
      ipv4Address: row.ip_address || null,
      ipv4Gateway: row.gateway || null,
      rootPassword: plainPassword,
    };

    let reinstallState = 'running';
    if (row.is_local) {
      const info = await this.nodeManager.localRuntime.containerManager.reinstallContainer(reinstallSpec);
      reinstallState = info.state === 'running' ? 'running' : 'stopped';
    } else {
      if (reinstallSpec.templateArchivePath && fs.existsSync(reinstallSpec.templateArchivePath)) {
        reinstallSpec.templateArchivePath = await this.ensureTemplateStagedOnRemoteNode(
          row.node_id,
          reinstallSpec.templateArchivePath
        );
      }
      const resp = await this.nodeManager.requestRemoteNode<
        LxcContainerRuntimeInfo | { success?: boolean; container?: LxcContainerRuntimeInfo }
      >(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/reinstall`,
        reinstallSpec,
        600_000
      );
      const info = (resp as any)?.container || resp;
      reinstallState = info?.state === 'running' ? 'running' : 'stopped';
    }

    await this.db.run(
      `UPDATE lxc_instances
       SET os_template = ?, os_family = ?, root_password_enc = ?, status = ?, updated_at = datetime('now')
       WHERE id = ?`,
      [tpl.slug, tpl.family || 'debian', encryptSecret(plainPassword), reinstallState, refId]
    );

    await this.syncRegistryRow(refId);
    return { instance: (await this.getInstance(refId))!, rootPassword: plainPassword };
  }

  public async resetRootPassword(refId: number, newPassword?: string): Promise<string> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    const password = newPassword?.trim() || generateStrongPassword(18);

    await this.dispatchNodeContainerAction(
      row.node_id,
      Boolean(row.is_local),
      row.container_name,
      'password',
      { password }
    );

    await this.db.run(
      `UPDATE lxc_instances SET root_password_enc = ?, updated_at = datetime('now') WHERE id = ?`,
      [encryptSecret(password), refId]
    );
    return password;
  }

  public async getDecryptedRootPassword(refId: number): Promise<string> {
    const row = await this.db.get<{ root_password_enc: string | null }>(
      `SELECT root_password_enc FROM lxc_instances WHERE id = ?`,
      [refId]
    );
    if (!row?.root_password_enc) return '';
    return decryptSecret(row.root_password_enc);
  }

  public async injectSshKey(refId: number, publicKey: string): Promise<void> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    await this.dispatchNodeContainerAction(
      row.node_id,
      Boolean(row.is_local),
      row.container_name,
      'ssh_key',
      { sshPublicKey: publicKey }
    );
  }

  public async renewExpiration(refId: number, additionalDays: number): Promise<UnifiedInstanceRecord> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    const days = Math.max(1, Number(additionalDays || 30));
    const baseMs =
      row.expires_at && new Date(row.expires_at).getTime() > Date.now()
        ? new Date(row.expires_at).getTime()
        : Date.now();
    const nextIso = new Date(baseMs + days * 86_400_000).toISOString();

    await this.db.run(
      `UPDATE lxc_instances
       SET expires_at = ?, expiration_days = ?, last_renewed_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?`,
      [nextIso, days, refId]
    );
    await this.db.run(
      `INSERT OR REPLACE INTO vps_expiration (lxc_id, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at)
       VALUES (?, ?, ?, COALESCE((SELECT auto_suspend_enabled FROM vps_expiration WHERE lxc_id = ?), 1), datetime('now'))`,
      [refId, nextIso, days, refId]
    );
    return (await this.getInstance(refId))!;
  }

  public async transferOwnership(refId: number, newUserId: number): Promise<UnifiedInstanceRecord> {
    const user = await this.db.get<{ id: number }>(`SELECT id FROM users WHERE id = ?`, [newUserId]);
    if (!user) throw new Error(`Target user #${newUserId} not found.`);
    await this.db.run(
      `UPDATE lxc_instances SET user_id = ?, updated_at = datetime('now') WHERE id = ?`,
      [newUserId, refId]
    );
    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async updateSharing(refId: number, sharedUserIds: number[]): Promise<UnifiedInstanceRecord> {
    const clean = Array.from(new Set(sharedUserIds.map(Number).filter((n) => Number.isInteger(n) && n > 0)));
    await this.db.run(
      `UPDATE lxc_instances SET shared_with = ?, updated_at = datetime('now') WHERE id = ?`,
      [JSON.stringify(clean), refId]
    );
    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async setWhitelist(refId: number, whitelisted: boolean): Promise<void> {
    await this.db.run(
      `UPDATE lxc_instances SET whitelisted = ?, updated_at = datetime('now') WHERE id = ?`,
      [whitelisted ? 1 : 0, refId]
    );
  }

  public async getProcesses(refId: number) {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.getContainerProcesses(row.container_name);
    }
    const resp = await this.nodeManager.requestRemoteNode<{ processes: any[] }>(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/processes`
    );
    return resp.processes || [];
  }

  public async getLogs(refId: number): Promise<string> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.getContainerLogs(row.container_name);
    }
    const resp = await this.nodeManager.requestRemoteNode<{ logs: string }>(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/logs`
    );
    return resp.logs || '';
  }

  public async listFiles(refId: number, subPath = '/') {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.listRootfsDirectory(
        row.container_name,
        subPath
      );
    }
    const resp = await this.nodeManager.requestRemoteNode<{ entries: any[] }>(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/files?path=${encodeURIComponent(subPath)}`
    );
    return resp.entries || [];
  }

  public async readFile(refId: number, subPath: string): Promise<Buffer> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.readRootfsFile(
        row.container_name,
        subPath
      );
    }
    const resp = await this.nodeManager.requestRemoteNode<{ contentBase64: string }>(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/files/content?path=${encodeURIComponent(subPath)}`
    );
    return Buffer.from(resp.contentBase64 || '', 'base64');
  }

  public async writeFile(refId: number, subPath: string, content: Buffer | string): Promise<void> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    if (row.is_local) {
      this.nodeManager.localRuntime.containerManager.writeRootfsFile(
        row.container_name,
        subPath,
        buf
      );
      return;
    }
    await this.nodeManager.requestRemoteNode(
      row.node_id,
      'POST',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/files/content`,
      { path: subPath, contentBase64: buf.toString('base64') }
    );
  }

  public async deleteFile(refId: number, subPath: string): Promise<void> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      this.nodeManager.localRuntime.containerManager.deleteRootfsEntry(row.container_name, subPath);
      return;
    }
    await this.nodeManager.requestRemoteNode(
      row.node_id,
      'DELETE',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/files?path=${encodeURIComponent(subPath)}`
    );
  }

  public async getTelemetry(refId: number): Promise<InstanceTelemetry> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);

    let runtime: LxcContainerRuntimeInfo;
    if (row.is_local) {
      runtime = await this.nodeManager.localRuntime.containerManager.inspectContainer(
        row.container_name,
        { sampleCpu: true }
      );
    } else {
      runtime = await this.nodeManager.requestRemoteNode<LxcContainerRuntimeInfo>(
        row.node_id,
        'GET',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}?telemetry=1`
      );
    }

    const nowMs = Date.now();
    const cores = Math.max(1, Number(row.cpu_cores || 1));
    let cpuPercent = 0;

    if (runtime.state !== 'running') {
      cpuPercent = 0;
      this.prevContainerCpu.delete(refId);
    } else if (
      typeof runtime.cpuCoresUsed === 'number' &&
      Number.isFinite(runtime.cpuCoresUsed)
    ) {
      cpuPercent = Number(
        Math.min(100, Math.max(0, (runtime.cpuCoresUsed / cores) * 100)).toFixed(2)
      );
      this.prevContainerCpu.set(refId, { cpuSec: runtime.cpuUseSeconds, tsMs: nowMs });
    } else {
      // Backward-compatible fallback for older remote Node Agents without `cpuCoresUsed`
      const prev = this.prevContainerCpu.get(refId);
      if (prev && nowMs > prev.tsMs && runtime.cpuUseSeconds >= prev.cpuSec) {
        const elapsedMs = nowMs - prev.tsMs;
        if (elapsedMs >= 200 && elapsedMs <= 60_000) {
          const elapsedSec = elapsedMs / 1000;
          const deltaCpuSec = runtime.cpuUseSeconds - prev.cpuSec;
          cpuPercent = Number(
            Math.min(100, Math.max(0, ((deltaCpuSec / elapsedSec) / cores) * 100)).toFixed(2)
          );
          this.prevContainerCpu.set(refId, { cpuSec: runtime.cpuUseSeconds, tsMs: nowMs });
        } else if (elapsedMs > 60_000) {
          this.prevContainerCpu.set(refId, { cpuSec: runtime.cpuUseSeconds, tsMs: nowMs });
        }
      } else {
        this.prevContainerCpu.set(refId, { cpuSec: runtime.cpuUseSeconds, tsMs: nowMs });
      }
    }

    const ramUsedMb = Math.round(runtime.memoryBytes / (1024 * 1024));
    const ramTotalMb = Math.max(1, Number(row.ram_mb || 1024));
    const diskUsedGb = Number((runtime.diskUsedBytes / (1024 * 1024 * 1024)).toFixed(2));
    const status =
      runtime.state === 'missing'
        ? row.suspended
          ? 'suspended'
          : row.status || 'stopped'
        : runtime.state;

    const liveIp = runtime.ips?.[0] || runtime.configuredIpv4 || row.ip_address || null;
    if (liveIp && !row.ip_address) {
      await this.db
        .run(
          `UPDATE lxc_instances SET ip_address = ?, gateway = COALESCE(gateway, ?), updated_at = datetime('now') WHERE id = ?`,
          [
            liveIp,
            runtime.configuredGateway && runtime.configuredGateway !== 'auto'
              ? runtime.configuredGateway
              : null,
            refId,
          ]
        )
        .catch(() => undefined);
      await this.syncRegistryRow(refId).catch(() => undefined);
    }

    return {
      engine: 'lxc',
      refId,
      status,
      pid: runtime.pid,
      cpuPercent,
      ramUsedMb,
      ramTotalMb,
      ramPercent: Number(Math.min(100, (ramUsedMb / ramTotalMb) * 100).toFixed(2)),
      diskUsedGb,
      diskTotalGb: Number(row.disk_gb || 20),
      netRxBytes: runtime.rxBytes,
      netTxBytes: runtime.txBytes,
      primaryIp: liveIp,
      measuredAt: new Date().toISOString(),
    };
  }

  public async repairLxcNetworking(refId: number): Promise<{
    repair: LxcNetworkRepairResult;
    instance: UnifiedInstanceRecord;
  }> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);

    let repair: LxcNetworkRepairResult;
    const desiredBridge = row.bridge || 'lxcbr0';
    if (row.is_local) {
      repair = await this.nodeManager.localRuntime.containerManager.repairContainerNetworking(
        row.container_name,
        desiredBridge
      );
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{ repair: LxcNetworkRepairResult }>(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/repair-network`,
        { bridge: desiredBridge }
      );
      repair = resp.repair;
    }

    if (repair.ipv4Address || repair.gateway) {
      await this.db.run(
        `UPDATE lxc_instances
         SET ip_address = COALESCE(?, ip_address),
             gateway = COALESCE(?, gateway),
             updated_at = datetime('now')
         WHERE id = ?`,
        [repair.ipv4Address || null, repair.gateway || null, refId]
      );
      await this.syncRegistryRow(refId);
    }

    return {
      repair,
      instance: (await this.getInstance(refId))!,
    };
  }

  /**
   * Automatically heals bridge NAT/FORWARD/DNS-relay rules, cgroup RAM/CPU limits, `lxcfs`
   * `/proc` virtualization, and sparse `ext4` loop disk quotas on active local LXC containers
   * during HKVM server startup.
   */
  public async healLocalContainersNetworking(): Promise<void> {
    const localNode = await this.db.get<{ id: number }>(
      `SELECT id FROM nodes WHERE is_local = 1 LIMIT 1`
    );
    if (!localNode) return;

    const rows = await this.db.all<{
      id: number;
      container_name: string;
      hostname: string;
      bridge: string | null;
      cpu_cores: number;
      cpu_shares: number;
      cpu_limit_pct: number;
      cpu_pinning: string | null;
      ram_mb: number;
      swap_mb: number;
      disk_gb: number;
      rootfs_storage_type: string;
      nesting: number;
      kvm_nesting: number;
      autostart: number;
      ip_address: string | null;
      gateway: string | null;
      ipv6_address: string | null;
    }>(
      `SELECT id, container_name, hostname, bridge, cpu_cores, cpu_shares, cpu_limit_pct, cpu_pinning,
              ram_mb, swap_mb, disk_gb, rootfs_storage_type, nesting, kvm_nesting, autostart,
              ip_address, gateway, ipv6_address
       FROM lxc_instances WHERE node_id = ? AND suspended = 0`,
      [localNode.id]
    );
    const cm = this.nodeManager.localRuntime.containerManager;
    const isSystemStore = path.resolve(cm.getBaseDir()) === '/var/lib/lxc';
    if (isSystemStore) {
      await cm.ensureHostIsolationReady().catch(() => undefined);
    }

    for (const r of rows) {
      try {
        let info = await cm.inspectContainer(r.container_name);
        if (info.state === 'missing') continue;

        if (isSystemStore) {
          const needsLoopUpgrade = !info.diskQuotaEnforced && r.disk_gb >= 1;
          const cgHeal = cm.needsContainerCgroupRestartOrHeal(
            r.container_name,
            info.state === 'running' ? info.pid : null,
            {
              ramMb: r.ram_mb,
              swapMb: r.swap_mb,
              cpuCores: r.cpu_cores,
              cpuLimitPercent: r.cpu_limit_pct,
              cpuPinning: r.cpu_pinning,
            }
          );

          if (needsLoopUpgrade || cgHeal.rewriteConfig || cgHeal.requiresRestart) {
            const wasRunning = info.state === 'running';
            if (wasRunning && needsLoopUpgrade) {
              await cm.stopContainer(r.container_name).catch(() => undefined);
            }
            await cm.writeManagedConfigSection(r.container_name, {
              hostname: r.hostname || r.container_name,
              cpuCores: r.cpu_cores,
              cpuShares: r.cpu_shares,
              cpuLimitPercent: r.cpu_limit_pct,
              cpuPinning: r.cpu_pinning,
              ramMb: r.ram_mb,
              swapMb: r.swap_mb,
              nesting: Boolean(r.nesting),
              kvmNesting: Boolean(r.kvm_nesting),
              autostart: Boolean(r.autostart),
              bridge: r.bridge || 'lxcbr0',
              ipv4Address: r.ip_address,
              ipv4Gateway: r.gateway,
              ipv6Address: r.ipv6_address,
            });
            if (needsLoopUpgrade) {
              const converted = await cm
                .ensureContainerQuotaDisk(r.container_name, r.disk_gb)
                .catch(() => false);
              if (converted) {
                await this.db.run(
                  `UPDATE lxc_instances SET rootfs_storage_type = 'loop', updated_at = datetime('now') WHERE id = ?`,
                  [r.id]
                );
              }
              if (wasRunning) {
                await cm.startContainer(r.container_name).catch(() => undefined);
              }
            } else if (wasRunning && cgHeal.requiresRestart) {
              await cm.restartContainer(r.container_name).catch(() => undefined);
            } else if (wasRunning) {
              await cm
                .enforceLiveContainerCgroups(r.container_name, {
                  ramMb: r.ram_mb,
                  swapMb: r.swap_mb,
                  cpuCores: r.cpu_cores,
                  cpuLimitPercent: r.cpu_limit_pct,
                  cpuPinning: r.cpu_pinning,
                })
                .catch(() => false);
            }
            info = await cm.inspectContainer(r.container_name);
          } else {
            await cm.ensureExistingQuotaDiskMounted(r.container_name).catch(() => false);
            if (info.state === 'running' && cgHeal.enforceLive) {
              await cm
                .enforceLiveContainerCgroups(r.container_name, {
                  ramMb: r.ram_mb,
                  swapMb: r.swap_mb,
                  cpuCores: r.cpu_cores,
                  cpuLimitPercent: r.cpu_limit_pct,
                  cpuPinning: r.cpu_pinning,
                })
                .catch(() => false);
            }
          }
        }

        // Ensure bridge NAT/FORWARD/DNS-relay + guest DNS + auto-IP if missing
        const repair = await cm.repairContainerNetworking(r.container_name, r.bridge || 'lxcbr0');
        if (repair.ipv4Address || repair.gateway) {
          await this.db.run(
            `UPDATE lxc_instances
             SET ip_address = COALESCE(ip_address, ?),
                 gateway = COALESCE(gateway, ?),
                 updated_at = datetime('now')
             WHERE id = ?`,
            [repair.ipv4Address || null, repair.gateway || null, r.id]
          );
          await this.syncRegistryRow(r.id);
        }
      } catch {
        // non-fatal per-container self-heal
      }
    }
  }
}
