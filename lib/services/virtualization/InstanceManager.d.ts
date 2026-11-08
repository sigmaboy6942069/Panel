import { UnifiedDatabase } from '../../db/database';
import { AuthenticatedPrincipal } from '../../security/middleware';
import { VirtualizationManager } from './VirtualizationManager';
import { InstanceTelemetry, LifecycleAction, UnifiedInstanceRecord, VirtualizationEngine } from './VirtualizationAdapter';
export { VirtualizationManager };
/**
 * High-level Unified Instance Manager handling cross-engine queries, RBAC/ownership/sharing
 * checks, bulk actions, and automated expiration enforcement.
 */
export declare class InstanceManager {
    private db;
    readonly virt: VirtualizationManager;
    constructor(db: UnifiedDatabase, virt: VirtualizationManager);
    isStaff(principal: AuthenticatedPrincipal): boolean;
    listAccessibleInstances(principal: AuthenticatedPrincipal, filter?: {
        engine?: VirtualizationEngine;
        nodeId?: number;
        status?: string;
        search?: string;
    }): Promise<UnifiedInstanceRecord[]>;
    getAuthorizedInstance(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number, requireOwnerOrStaff?: boolean): Promise<UnifiedInstanceRecord>;
    executeAction(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number, action: LifecycleAction, reason?: string, force?: boolean): Promise<UnifiedInstanceRecord>;
    bulkAction(principal: AuthenticatedPrincipal, targets: Array<{
        engine: VirtualizationEngine;
        refId: number;
    }>, action: 'start' | 'stop' | 'restart'): Promise<Array<{
        uid: string;
        ok: boolean;
        error?: string;
    }>>;
    getTelemetry(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number): Promise<InstanceTelemetry>;
    /**
     * Background check that suspends expired LXC instances when `auto_suspend_enabled = 1`
     * and `whitelisted = 0`.
     */
    processExpiredInstances(): Promise<number>;
}
