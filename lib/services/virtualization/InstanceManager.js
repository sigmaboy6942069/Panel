"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InstanceManager = exports.VirtualizationManager = void 0;
const VirtualizationManager_1 = require("./VirtualizationManager");
Object.defineProperty(exports, "VirtualizationManager", { enumerable: true, get: function () { return VirtualizationManager_1.VirtualizationManager; } });
/**
 * High-level Unified Instance Manager handling cross-engine queries, RBAC/ownership/sharing
 * checks, bulk actions, and automated expiration enforcement.
 */
class InstanceManager {
    db;
    virt;
    constructor(db, virt) {
        this.db = db;
        this.virt = virt;
    }
    isStaff(principal) {
        return (principal.role === 'admin' ||
            principal.role === 'subadmin' ||
            principal.role === 'operator');
    }
    async listAccessibleInstances(principal, filter) {
        const ownerFilter = this.isStaff(principal) ? undefined : principal.userId;
        const lists = [];
        if (!filter?.engine || filter.engine === 'kvm') {
            lists.push(...(await this.virt.kvm.listInstances({
                ownerId: ownerFilter,
                nodeId: filter?.nodeId,
            })));
        }
        if (!filter?.engine || filter.engine === 'lxc') {
            lists.push(...(await this.virt.lxc.listInstances({
                ownerId: ownerFilter,
                nodeId: filter?.nodeId,
            })));
        }
        let combined = lists.sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());
        if (filter?.status) {
            const s = filter.status.toLowerCase();
            combined = combined.filter((i) => i.status.toLowerCase() === s);
        }
        if (filter?.search) {
            const q = filter.search.toLowerCase();
            combined = combined.filter((i) => i.name.toLowerCase().includes(q) ||
                i.hostname.toLowerCase().includes(q) ||
                (i.primaryIp || '').toLowerCase().includes(q) ||
                (i.ownerUsername || '').toLowerCase().includes(q));
        }
        return combined;
    }
    async getAuthorizedInstance(principal, engine, refId, requireOwnerOrStaff = false) {
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
    async executeAction(principal, engine, refId, action, reason, force = false) {
        const adminOnlyActions = ['suspend', 'unsuspend', 'delete'];
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
    async bulkAction(principal, targets, action) {
        const results = [];
        for (const t of targets) {
            const uid = `${t.engine}:${t.refId}`;
            try {
                await this.executeAction(principal, t.engine, t.refId, action);
                results.push({ uid, ok: true });
            }
            catch (err) {
                results.push({ uid, ok: false, error: err.message });
            }
        }
        return results;
    }
    async getTelemetry(principal, engine, refId) {
        await this.getAuthorizedInstance(principal, engine, refId);
        return this.virt.getAdapter(engine).getTelemetry(refId);
    }
    /**
     * Background check that suspends expired LXC instances when `auto_suspend_enabled = 1`
     * and `whitelisted = 0`.
     */
    async processExpiredInstances() {
        const expired = await this.db.all(`SELECT id, container_name, user_id
       FROM lxc_instances
       WHERE suspended = 0
         AND whitelisted = 0
         AND auto_suspend_enabled = 1
         AND expires_at IS NOT NULL
         AND datetime(expires_at) <= datetime('now')`);
        let count = 0;
        for (const item of expired) {
            try {
                await this.virt.lxc.performLifecycleAction(item.id, 'suspend', {
                    reason: 'Instance billing/expiration period reached',
                });
                await this.db.run(`INSERT INTO notifications (user_id, type, title, message)
           VALUES (?, 'warning', 'VPS Auto-Suspended (Expired)', ?)`, [
                    item.user_id,
                    `Your LXC VPS "${item.container_name}" reached its expiration date and was automatically suspended.`,
                ]);
                count++;
            }
            catch {
                // continue processing remaining instances
            }
        }
        return count;
    }
}
exports.InstanceManager = InstanceManager;
