export type VirtualizationEngine = 'kvm' | 'lxc';
export type LifecycleAction = 'start' | 'stop' | 'restart' | 'freeze' | 'unfreeze' | 'suspend' | 'unsuspend' | 'delete';
export interface InstanceCapabilityProfile {
    engine: VirtualizationEngine;
    supportsFreeze: boolean;
    supportsSuspend: boolean;
    supportsSnapshots: boolean;
    supportsBackups: boolean;
    supportsOfflineMigration: boolean;
    supportsIsoMount: boolean;
    supportsBootOrder: boolean;
    supportsSmbios: boolean;
    supportsCloudInit: boolean;
    supportsSerialConsole: boolean;
    supportsPtyConsole: boolean;
    supportsSshBridge: boolean;
    supportsRootfsFileBrowser: boolean;
    supportsContainerProcessList: boolean;
}
export interface UnifiedInstanceRecord {
    uid: string;
    engine: VirtualizationEngine;
    refId: number;
    name: string;
    hostname: string;
    ownerId: number;
    ownerUsername?: string;
    nodeId: number;
    nodeName?: string;
    status: string;
    suspended: boolean;
    suspendedReason?: string | null;
    osLabel: string;
    cpuCores: number;
    ramMb: number;
    swapMb: number;
    diskGb: number;
    primaryIp: string | null;
    sshPort?: number | null;
    sharedWith: number[];
    expiresAt?: string | null;
    createdAt: string;
    capabilities: InstanceCapabilityProfile;
}
export interface InstanceTelemetry {
    engine: VirtualizationEngine;
    refId: number;
    status: string;
    pid: number | null;
    cpuPercent: number;
    ramUsedMb: number;
    ramTotalMb: number;
    ramPercent: number;
    diskUsedGb: number;
    diskTotalGb: number;
    netRxBytes: number;
    netTxBytes: number;
    primaryIp?: string | null;
    measuredAt: string;
}
export interface VirtualizationAdapter {
    readonly engine: VirtualizationEngine;
    getCapabilityProfile(): InstanceCapabilityProfile;
    listInstances(filter?: {
        ownerId?: number;
        nodeId?: number;
    }): Promise<UnifiedInstanceRecord[]>;
    getInstance(refId: number): Promise<UnifiedInstanceRecord | undefined>;
    performLifecycleAction(refId: number, action: LifecycleAction, options?: {
        reason?: string;
        actorId?: number;
        force?: boolean;
    }): Promise<UnifiedInstanceRecord>;
    getTelemetry(refId: number): Promise<InstanceTelemetry>;
}
