/**
 * Own-node ("local") provisioning engine.
 *
 * A provider whose `provider` family is `local` has no upstream reseller API.
 * Instead it sells capacity from nodes this panel controls, and an order is
 * fulfilled by creating a real KVM VM or LXC container through the existing
 * virtualization layer.
 *
 * This class deliberately mirrors the small slice of `ResellerApiClient` that
 * the order pipeline needs (`getAccount`, `listKvmOs`, `orderKvm`), so the rest
 * of `ResellerService` stays engine-agnostic: a plan on a local provider takes
 * the same code path as a plan on a bought API.
 */
import { UnifiedDatabase } from '../../db/database';
import { VirtualizationManager } from '../virtualization/VirtualizationManager';
import { UnifiedInstanceRecord } from '../virtualization/VirtualizationAdapter';
import { UpstreamAccount, UpstreamKvmOrderResult, UpstreamKvmOs, UpstreamKvmPlan, UpstreamKvmServerDetail } from './types';
export declare const LOCAL_PROVIDER_FAMILY = "local";
/**
 * A provisioning failure that retrying cannot fix (missing host tooling, bad
 * template, exhausted capacity). Orders hitting this are failed instead of
 * being left queued forever.
 */
export declare class LocalProvisionError extends Error {
    readonly code: string;
    readonly terminal: boolean;
    constructor(message: string, code?: string, terminal?: boolean);
}
/** Everything the engine needs from the order pipeline. */
export interface LocalOrderRequest {
    orderId: number;
    orderRef: string;
    userId: number;
    serverName: string;
    /** `kvm` or `lxc`. Defaults to the plan's engine, then to `lxc`. */
    engine?: 'kvm' | 'lxc' | string | null;
    nodeId?: number | null;
    cores: number;
    memoryGb: number;
    diskGb: number;
    osId?: string | null;
    osLabel?: string | null;
    /** LXC distro/release, e.g. ubuntu/24.04. Derived from the OS id if absent. */
    distro?: string | null;
    release?: string | null;
    lxcTemplate?: string | null;
    bridge?: string | null;
    /** Days until expiry; 0 means "no expiry". */
    durationDays?: number;
}
export interface LocalNodeSpec {
    id: number;
    name: string;
    engine: 'kvm' | 'lxc';
    cpuCores: number;
    ramMb: number;
    diskGb: number;
    isLocal: boolean;
    status: string;
    location: string | null;
}
/** A single sellable slice of a node, derived from real node capacity. */
export interface LocalCapacityPlan {
    /** Stable id used as `reseller_plans.upstream_plan_id`, e.g. `node3-lxc-2c-4g-40g`. */
    upstreamPlanId: string;
    engine: 'kvm' | 'lxc';
    nodeId: number;
    nodeName: string;
    cores: number;
    memoryGb: number;
    diskGb: number;
    displayName: string;
    cpuLabel: string;
    family: string;
    /** How many of this shape currently fit on the node. */
    available: number;
}
export declare class LocalProvisioningEngine {
    private db;
    private virt;
    constructor(db: UnifiedDatabase, virt: VirtualizationManager);
    /** Nodes that can be sold: not in maintenance, and reachable. */
    listSellableNodes(): Promise<LocalNodeSpec[]>;
    /** How much of a node is already committed to sold servers. */
    private committedOnNode;
    /**
     * Builds sellable plans from real node capacity.
     *
     * Kept intentionally simple and predictable: for each node we offer a few
     * standard shapes that fit within available resources, rather than trying to
     * model every possible configuration. Admins can still hand-edit prices in
     * the catalogue.
     */
    discoverCapacity(shapes?: Array<{
        cores: number;
        memoryGb: number;
        diskGb: number;
        label?: string;
    }>): Promise<LocalCapacityPlan[]>;
    /** OS images sellable on local nodes. Mirrors the upstream shape. */
    /**
     * Every image this provider can actually deploy, across both engines: LXC
     * container templates plus KVM disk images. A single own-node provider may
     * sell both, so the catalogue has to offer both.
     */
    listAllOsImages(): Promise<UpstreamKvmOs[]>;
    listOsImages(engine?: 'kvm' | 'lxc'): Promise<UpstreamKvmOs[]>;
    private titleCase;
    /** Account/health card for a local provider — no upstream balance exists. */
    getAccountCard(): Promise<UpstreamAccount>;
    /**
     * Fulfils an order by creating a real instance on a node we control.
     * Returns the same shape the upstream client returns, so the caller's
     * existing bookkeeping (cloud_servers, wallet, notifications) is reused.
     */
    proviseLocalOrder(req: LocalOrderRequest): Promise<UpstreamKvmOrderResult>;
    private normaliseEngine;
    /** Picks the target node: explicit, else the least-loaded sellable one. */
    private resolveNodeId;
    private safeContainerName;
    private provisionLxc;
    /**
     * KVM creation goes through the legacy `vms` pipeline in `app.js`, which is
     * where the qcow2/cloud-init/ISO orchestration lives. It is injected as a
     * hook so this service stays free of `app.js` internals.
     */
    private provisionKvm;
    /** Hook registered from `app.js` at boot (see `src/context.ts`). */
    kvmCreateHook: ((spec: {
        userId: number;
        nodeId: number;
        name: string;
        cores: number;
        memoryMb: number;
        diskGb: number;
        templateKey: string | null;
        templateLabel: string | null;
        expirationDays: number;
    }) => Promise<{
        instance: UnifiedInstanceRecord;
        rootPassword: string | null;
        warning?: string;
    }>) | null;
    setKvmCreateHook(hook: NonNullable<LocalProvisioningEngine['kvmCreateHook']>): void;
    /**
     * Hook supplying the KVM templates the panel can actually deploy. The
     * built-in catalogue lives in `app.js`, so it is injected rather than
     * duplicated here; without it we fall back to the database table only.
     */
    kvmTemplateHook: (() => Array<{
        id: string;
        name: string;
        family: string;
        arch: string;
    }>) | null;
    setKvmTemplateHook(hook: NonNullable<LocalProvisioningEngine['kvmTemplateHook']>): void;
    private toOrderResult;
    /** Power actions for an own-node server, given its stored engine + ref. */
    powerAction(engine: 'kvm' | 'lxc', refId: number, action: 'start' | 'stop' | 'restart' | 'delete'): Promise<UnifiedInstanceRecord>;
    /** Live detail for an own-node server. */
    describeInstance(engine: 'kvm' | 'lxc', refId: number): Promise<{
        instance?: UnifiedInstanceRecord;
        detail: UpstreamKvmServerDetail;
    }>;
    /** Static catalogue used when an admin syncs a local provider. */
    listPlansForSync(): Promise<UpstreamKvmPlan[]>;
    /** True when this provider row represents own hardware. */
    static isLocalProvider(provider: {
        provider?: string | null;
    } | null | undefined): boolean;
}
