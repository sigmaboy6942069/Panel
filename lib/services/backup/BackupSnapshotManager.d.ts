import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
import { VirtualizationManager } from '../virtualization/VirtualizationManager';
export declare class BackupSnapshotManager {
    private db;
    private nodeManager;
    private virt;
    constructor(db: UnifiedDatabase, nodeManager: NodeManager, virt: VirtualizationManager);
    listSnapshots(engine: 'kvm' | 'lxc', refId: number): Promise<any[]>;
    createSnapshot(params: {
        engine: 'kvm' | 'lxc';
        refId: number;
        name?: string;
        description?: string;
        actorId?: number;
    }): Promise<{
        id: number;
        name: string;
    }>;
    restoreSnapshot(engine: 'kvm' | 'lxc', refId: number, snapshotId: number): Promise<void>;
    deleteSnapshot(engine: 'kvm' | 'lxc', refId: number, snapshotId: number): Promise<void>;
    listBackups(filter?: {
        engine?: 'kvm' | 'lxc';
        refId?: number;
    }): Promise<any[]>;
    createBackup(params: {
        engine: 'kvm' | 'lxc';
        refId: number;
        label?: string;
        actorId?: number;
    }): Promise<{
        backupId: number;
        filePath: string;
        sizeBytes: number;
        checksumSha256: string;
    }>;
    getBackupRecord(backupId: number): Promise<any | undefined>;
    verifyBackupIntegrity(backupId: number): Promise<{
        valid: boolean;
        expectedSha256: string | null;
        actualSha256: string | null;
    }>;
    restoreBackup(backupId: number, actorId?: number): Promise<{
        restored: boolean;
        status: string;
    }>;
    deleteBackup(backupId: number): Promise<void>;
}
