import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
import { LxcNetworkRepairResult } from '../../node-agent/container-manager';
import { InstanceCapabilityProfile, InstanceTelemetry, LifecycleAction, UnifiedInstanceRecord, VirtualizationAdapter } from './VirtualizationAdapter';
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
export declare class LXCAdapter implements VirtualizationAdapter {
    readonly engine: 'lxc';
    private db;
    private nodeManager;
    private prevContainerCpu;
    private inFlightPanelCreations;
    constructor(db: UnifiedDatabase, nodeManager: NodeManager);
    getCapabilityProfile(): InstanceCapabilityProfile;
    private mapRowToUnified;
    syncRegistryRow(lxcId: number): Promise<void>;
    listInstances(filter?: {
        ownerId?: number;
        nodeId?: number;
    }): Promise<UnifiedInstanceRecord[]>;
    getInstance(refId: number): Promise<UnifiedInstanceRecord | undefined>;
    getRawLxcRow(refId: number): Promise<any | undefined>;
    private resolveCatalogTemplate;
    createLxcInstance(input: CreateLxcInstanceInput): Promise<{
        instance: UnifiedInstanceRecord;
        generatedRootPassword: string;
        hostProvisioned: boolean;
        warning?: string;
    }>;
    private ensureTemplateStagedOnRemoteNode;
    /**
     * Discovers any existing native LXC containers across the local node and all online remote
     * Node Agents (or a specific target `nodeId`) that are not yet tracked in `lxc_instances`
     * and imports them cleanly with accurate `node_id` ownership.
     */
    syncHostContainers(defaultUserId?: number, targetNodeId?: number): Promise<{
        imported: string[];
        count: number;
        byNode?: Record<number, string[]>;
    }>;
    private dispatchNodeContainerAction;
    performLifecycleAction(refId: number, action: LifecycleAction, options?: {
        reason?: string;
        actorId?: number;
        force?: boolean;
    }): Promise<UnifiedInstanceRecord>;
    resizeAndUpdateConfig(refId: number, patch: {
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
    }, applyToHost?: boolean): Promise<UnifiedInstanceRecord>;
    reinstallLxcInstance(refId: number, templateSlug: string, newRootPassword?: string): Promise<{
        instance: UnifiedInstanceRecord;
        rootPassword: string;
    }>;
    resetRootPassword(refId: number, newPassword?: string): Promise<string>;
    getDecryptedRootPassword(refId: number): Promise<string>;
    injectSshKey(refId: number, publicKey: string): Promise<void>;
    renewExpiration(refId: number, additionalDays: number): Promise<UnifiedInstanceRecord>;
    transferOwnership(refId: number, newUserId: number): Promise<UnifiedInstanceRecord>;
    updateSharing(refId: number, sharedUserIds: number[]): Promise<UnifiedInstanceRecord>;
    setWhitelist(refId: number, whitelisted: boolean): Promise<void>;
    getProcesses(refId: number): Promise<any[]>;
    getLogs(refId: number): Promise<string>;
    listFiles(refId: number, subPath?: string): Promise<any[]>;
    readFile(refId: number, subPath: string): Promise<Buffer>;
    writeFile(refId: number, subPath: string, content: Buffer | string): Promise<void>;
    deleteFile(refId: number, subPath: string): Promise<void>;
    getTelemetry(refId: number): Promise<InstanceTelemetry>;
    repairLxcNetworking(refId: number): Promise<{
        repair: LxcNetworkRepairResult;
        instance: UnifiedInstanceRecord;
    }>;
    /**
     * Automatically heals bridge NAT/FORWARD/DNS-relay rules, cgroup RAM/CPU limits, `lxcfs`
     * `/proc` virtualization, and sparse `ext4` loop disk quotas on active local LXC containers
     * during HKVM server startup.
     */
    healLocalContainersNetworking(): Promise<void>;
}
