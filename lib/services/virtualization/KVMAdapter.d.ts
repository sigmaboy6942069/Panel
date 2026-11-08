import { UnifiedDatabase } from '../../db/database';
import { InstanceCapabilityProfile, InstanceTelemetry, LifecycleAction, UnifiedInstanceRecord, VirtualizationAdapter } from './VirtualizationAdapter';
export interface LegacyKvmHooks {
    startVmById?: (vmId: number) => Promise<void>;
    stopVmById?: (vmId: number, force?: boolean) => Promise<void>;
    restartVmById?: (vmId: number) => Promise<void>;
    deleteVmById?: (vmId: number) => Promise<void>;
}
/**
 * Real QEMU/KVM hypervisor adapter wrapping HKVM's `vms` (`vm_id`, `vm_name`, `owner_id`, `disk_file`)
 * records, Linux `/proc/<pid>` telemetry, and real `qemu-img` snapshot/backup operations.
 */
export declare class KVMAdapter implements VirtualizationAdapter {
    readonly engine: 'kvm';
    private db;
    private hooks;
    private prevPidTicks;
    constructor(db: UnifiedDatabase, hooks?: LegacyKvmHooks);
    setLegacyHooks(hooks: LegacyKvmHooks): void;
    getCapabilityProfile(): InstanceCapabilityProfile;
    private resolveVmDiskPath;
    private parseDiskGb;
    private mapRowToUnified;
    listInstances(filter?: {
        ownerId?: number;
        nodeId?: number;
    }): Promise<UnifiedInstanceRecord[]>;
    getInstance(refId: number): Promise<UnifiedInstanceRecord | undefined>;
    syncRegistryRow(vmId: number): Promise<void>;
    performLifecycleAction(refId: number, action: LifecycleAction, options?: {
        reason?: string;
        actorId?: number;
        force?: boolean;
    }): Promise<UnifiedInstanceRecord>;
    getTelemetry(refId: number): Promise<InstanceTelemetry>;
    createQcow2Snapshot(vmId: number, snapshotName: string, description?: string): Promise<{
        id: number;
        name: string;
    }>;
    restoreQcow2Snapshot(vmId: number, snapshotId: number): Promise<void>;
    deleteQcow2Snapshot(vmId: number, snapshotId: number): Promise<void>;
    createDiskBackup(vmId: number, backupDir?: string): Promise<{
        backupId: number;
        filePath: string;
        sizeBytes: number;
        checksumSha256: string;
    }>;
}
