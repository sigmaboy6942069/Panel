import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
import { StorageManager } from '../storage/StorageManager';
import { NetworkManager } from '../network/NetworkManager';
import { LXCAdapter } from '../virtualization/LXCAdapter';
export interface MigrationJobRecord {
    id: number;
    instance_type: 'lxc' | 'kvm';
    instance_ref_id: number;
    container_name: string;
    source_node_id: number;
    target_node_id: number;
    migration_mode: string;
    status: string;
    progress: number;
    checksum_sha256: string | null;
    bytes_transferred: number;
    error_message: string | null;
    rollback_performed: number;
    initiated_by: number | null;
    started_at: string;
    completed_at: string | null;
}
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
export declare class MigrationManager {
    private db;
    private nodeManager;
    private storageManager;
    private lxcAdapter;
    private networkManager?;
    constructor(db: UnifiedDatabase, nodeManager: NodeManager, storageManager: StorageManager, lxcAdapter: LXCAdapter, networkManager?: NetworkManager);
    listMigrations(): Promise<MigrationJobRecord[]>;
    getMigration(jobId: number): Promise<MigrationJobRecord | undefined>;
    private updateJob;
    startOfflineLxcMigration(params: {
        lxcId: number;
        targetNodeId: number;
        targetBridge?: string;
        targetIpv4?: string | null;
        targetGateway?: string | null;
        initiatedByUserId: number;
    }): Promise<MigrationJobRecord>;
}
