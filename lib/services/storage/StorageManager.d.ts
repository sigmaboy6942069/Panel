import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
/**
 * Unified Storage Pool & LXC OS Template Manager for TGVPANEL V3.
 * Supports directory, RAW, QCOW2, LVM, ZFS, and Btrfs storage pools across both
 * local and remote Node Agents, plus centralized LXC OS template catalog management.
 */
export declare class StorageManager {
    private readonly db;
    private readonly nodeManager?;
    constructor(db: UnifiedDatabase, nodeManager?: NodeManager | undefined);
    listPools(): Promise<any[]>;
    private resolveNearestExistingAncestor;
    syncPoolCapacities(): Promise<any[]>;
    createPool(input: {
        nodeId?: number;
        name: string;
        poolType?: string;
        engineScope?: string;
        path?: string;
        poolPath?: string;
        overcommitRatio?: number;
    }): Promise<any>;
    deletePool(poolId: number): Promise<void>;
    verifyCapacityAvailable(nodeId: number, engine: 'kvm' | 'lxc', requestedGb: number): Promise<{
        ok: boolean;
        reason?: string;
    }>;
    listLxcTemplates(includeDisabled?: boolean): Promise<any[]>;
    upsertLxcTemplate(input: {
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
    }): Promise<any>;
    toggleLxcTemplate(id: number, enabled: boolean): Promise<void>;
    deleteLxcTemplate(id: number): Promise<void>;
}
