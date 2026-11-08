import { LxcContainerManager } from './container-manager';
import { LxcSnapshotAndBackupManager } from './snapshot-manager';
export interface MigrationExportBundle {
    containerName: string;
    wasRunning: boolean;
    archivePath: string;
    sizeBytes: number;
    checksumSha256: string;
}
/**
 * Implements the node-side operations for HKVM Offline Verified VPS Migration:
 * 1. Stop container cleanly on source node
 * 2. Export verified `.tar.gz` archive with SHA-256 digest
 * 3. Stream archive to target node & verify SHA-256 before extraction
 * 4. Apply target node network config & verify container starts cleanly
 * 5. Rollback cleanly on either source or target if verification fails
 */
export declare class LxcTransferManager {
    private containerManager;
    private snapshotManager;
    private stagingDir;
    constructor(containerManager: LxcContainerManager, snapshotManager: LxcSnapshotAndBackupManager, stagingDir?: string);
    prepareOfflineExport(containerName: string): Promise<MigrationExportBundle>;
    importAndVerifyBundle(params: {
        containerName: string;
        archiveBufferOrPath: Buffer | string;
        expectedChecksumSha256: string;
        targetBridge?: string;
        targetIpv4?: string | null;
        targetGateway?: string | null;
        startAfterImport?: boolean;
    }): Promise<{
        verified: boolean;
        state: string;
        archivePath: string;
    }>;
    rollbackSourceAfterFailure(containerName: string, wasRunning: boolean, archivePath?: string): Promise<void>;
    finalizeSourceCleanup(containerName: string, archivePath?: string): Promise<void>;
}
