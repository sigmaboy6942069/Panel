import { UnifiedDatabase } from '../../db/database';
import { AuthenticatedPrincipal } from '../../security/middleware';
import { VirtualizationManager } from './VirtualizationManager';
import {
  InstanceTelemetry,
  LifecycleAction,
  UnifiedInstanceRecord,
  VirtualizationEngine,
} from './VirtualizationAdapter';

export { VirtualizationManager };

/**
 * High-level Unified Instance Manager handling cross-engine queries, RBAC/ownership/sharing
 * checks, bulk actions, and automated expiration enforcement.
 */
export class InstanceManager {
  private db: UnifiedDatabase;
  public readonly virt: VirtualizationManager;

  constructor(db: UnifiedDatabase, virt: VirtualizationManager) {
    this.db = db;
    this.virt = virt;
  }

  public isStaff(principal: AuthenticatedPrincipal): boolean {
    return (
      principal.role === 'admin' ||
      principal.role === 'subadmin' ||
      principal.role === 'operator'
    );
  }

  public async listAccessibleInstances(
    principal: AuthenticatedPrincipal,
    filter?: { engine?: VirtualizationEngine; nodeId?: number; status?: string; search?: string }
  ): Promise<UnifiedInstanceRecord[]> {
    const ownerFilter = this.isStaff(principal) ? undefined : principal.userId;

    const lists: UnifiedInstanceRecord[] = [];
    if (!filter?.engine || filter.engine === 'kvm') {
      lists.push(
        ...(await this.virt.kvm.listInstances({
          ownerId: ownerFilter,
          nodeId: filter?.nodeId,
        }))
      );
    }
    if (!filter?.engine || filter.engine === 'lxc') {
      lists.push(
        ...(await this.virt.lxc.listInstances({
          ownerId: ownerFilter,
          nodeId: filter?.nodeId,
        }))
      );
    }

    let combined = lists.sort(
      (a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime()
    );

    if (filter?.status) {
      const s = filter.status.toLowerCase();
      combined = combined.filter((i) => i.status.toLowerCase() === s);
    }

    if (filter?.search) {
      const q = filter.search.toLowerCase();
      combined = combined.filter(
        (i) =>
          i.name.toLowerCase().includes(q) ||
          i.hostname.toLowerCase().includes(q) ||
          (i.primaryIp || '').toLowerCase().includes(q) ||
          (i.ownerUsername || '').toLowerCase().includes(q)
      );
    }

    return combined;
  }

  public async getAuthorizedInstance(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    requireOwnerOrStaff = false
  ): Promise<UnifiedInstanceRecord> {
    const inst = await this.virt.getAdapter(engine).getInstance(refId);
    if (!inst) {
      throw Object.assign(new Error(`${engine.toUpperCase()} instance #${refId} not found.`), {
        statusCode: 404,
      });
    }

    if (this.isStaff(principal)) {
      return inst;
    }

    const isOwner = inst.ownerId === principal.userId;
    const isShared = inst.sharedWith.includes(principal.userId);

    if (requireOwnerOrStaff && !isOwner) {
      throw Object.assign(new Error('Only the instance owner or an administrator may perform this action.'), {
        statusCode: 403,
      });
    }

    if (!isOwner && !isShared) {
      throw Object.assign(new Error('Access denied to this instance.'), {
        statusCode: 403,
      });
    }

    return inst;
  }

  public async executeAction(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    action: LifecycleAction,
    reason?: string,
    force = false
  ): Promise<UnifiedInstanceRecord> {
    const adminOnlyActions: LifecycleAction[] = ['suspend', 'unsuspend', 'delete'];
    if (adminOnlyActions.includes(action) && !this.isStaff(principal)) {
      if (action === 'delete') {
        // Non-staff cannot delete unless explicitly owner AND setting permits; default admin-protected
        throw Object.assign(new Error(`Action "${action}" requires administrator privileges.`), {
          statusCode: 403,
        });
      }
      throw Object.assign(new Error(`Action "${action}" requires administrator privileges.`), {
        statusCode: 403,
      });
    }

    await this.getAuthorizedInstance(principal, engine, refId);
    const updated = await this.virt
      .getAdapter(engine)
      .performLifecycleAction(refId, action, {
        reason,
        actorId: principal.userId,
        force,
      });

    await this.db.logActivity({
      userId: principal.userId,
      action: `instance_${action}`,
      resourceType: engine,
      resourceId: String(refId),
      details: { name: updated.name, actorRole: principal.role, reason: reason || null },
    });

    return updated;
  }

  public async bulkAction(
    principal: AuthenticatedPrincipal,
    targets: Array<{ engine: VirtualizationEngine; refId: number }>,
    action: 'start' | 'stop' | 'restart'
  ): Promise<Array<{ uid: string; ok: boolean; error?: string }>> {
    const results: Array<{ uid: string; ok: boolean; error?: string }> = [];
    for (const t of targets) {
      const uid = `${t.engine}:${t.refId}`;
      try {
        await this.executeAction(principal, t.engine, t.refId, action);
        results.push({ uid, ok: true });
      } catch (err: any) {
        results.push({ uid, ok: false, error: err.message });
      }
    }
    return results;
  }

  public async getTelemetry(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number
  ): Promise<InstanceTelemetry> {
    await this.getAuthorizedInstance(principal, engine, refId);
    return this.virt.getAdapter(engine).getTelemetry(refId);
  }

  /**
   * Background check that suspends expired LXC instances when `auto_suspend_enabled = 1`
   * and `whitelisted = 0`.
   */
  public async processExpiredInstances(): Promise<number> {
    const expired = await this.db.all<{ id: number; container_name: string; user_id: number }>(
      `SELECT id, container_name, user_id
       FROM lxc_instances
       WHERE suspended = 0
         AND whitelisted = 0
         AND auto_suspend_enabled = 1
         AND expires_at IS NOT NULL
         AND datetime(expires_at) <= datetime('now')`
    );

    let count = 0;
    for (const item of expired) {
      try {
        await this.virt.lxc.performLifecycleAction(item.id, 'suspend', {
          reason: 'Instance billing/expiration period reached',
        });
        await this.db.run(
          `INSERT INTO notifications (user_id, type, title, message)
           VALUES (?, 'warning', 'VPS Auto-Suspended (Expired)', ?)`,
          [
            item.user_id,
            `Your LXC VPS "${item.container_name}" reached its expiration date and was automatically suspended.`,
          ]
        );
        count++;
      } catch {
        // continue processing remaining instances
      }
    }
    return count;
  }
}
