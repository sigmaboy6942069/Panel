import WebSocket from 'ws';
import { UnifiedDatabase } from '../../db/database';
import { LocalNodeRuntime } from '../../node-agent/agent';
import { NodeHealthReport } from '../../node-agent/health';
import { HostResourceStats } from '../../node-agent/host-stats';
export interface NodeRecord {
    id: number;
    name: string;
    hostname: string;
    ip_address: string;
    location: string;
    url: string;
    is_local: number;
    maintenance_mode: number;
    verify_ssl: number;
    mtls_enabled: number;
    tls_pinned?: number;
    status: string;
    agent_version: string | null;
    last_heartbeat: string | null;
    last_error?: string | null;
    last_error_at?: string | null;
    circuit_state: 'closed' | 'open' | 'half-open';
    consecutive_failures: number;
    cpu_cores: number;
    cpu_model: string | null;
    ram_total_mb: number;
    disk_total_gb: number;
    max_instances: number;
    tags: string;
    notes: string | null;
    supports_kvm?: number;
    supports_lxc?: number;
    kvm_available?: number;
    lxc_available?: number;
    nested_virt?: number;
    cgroup_version?: string | null;
    qemu_version?: string | null;
    lxc_version?: string | null;
    kernel_version?: string | null;
    storage_backends?: string | null;
    network_backends?: string | null;
    kvm_count?: number;
    kvm_running?: number;
    lxc_count?: number;
    lxc_running?: number;
    total_instances?: number;
    running_instances?: number;
    allocated_vcpus?: number;
    allocated_ram_mb?: number;
    allocated_disk_gb?: number;
    live_cpu_percent?: number | null;
    live_ram_used_mb?: number | null;
    live_disk_used_gb?: number | null;
    live_load_1?: number | null;
    latency_ms?: number | null;
}
export interface EndpointProbeResult {
    reachable: boolean;
    url: string;
    protocol: 'http' | 'https';
    latencyMs: number;
    httpStatus: number | null;
    agentDetected: boolean;
    selfSignedAgentDetected?: boolean;
    clockSkewSec?: number | null;
    tls?: {
        authorized: boolean;
        authorizationError?: string | null;
        subjectCN?: string | null;
        issuerCN?: string | null;
        validTo?: string | null;
        protocol?: string | null;
        fingerprintSha256?: string | null;
        certPem?: string | null;
    } | null;
    message: string;
}
export declare function isDomainHostname(host: string): boolean;
export declare function normalizeNodeEndpointUrl(rawUrl: string): string;
export declare function buildAgentTargetUrl(baseNodeUrl: string, apiPathWithQuery: string): URL;
/**
 * Communicates with remote Node Agents over HTTPS/HTTP using replay-protected HMAC-SHA256 signatures,
 * optional TOFU certificate pinning / mTLS, active push-heartbeats, single-use join tokens,
 * and per-node circuit breakers, while routing `is_local = 1` requests directly to `LocalNodeRuntime`.
 */
export declare class NodeManager {
    private db;
    readonly localRuntime: LocalNodeRuntime;
    private circuits;
    private latencies;
    private seenAgentHeartbeatNonces;
    private readonly failureThreshold;
    private readonly openCooldownMs;
    constructor(db: UnifiedDatabase, localRuntime?: LocalNodeRuntime);
    private normalizeTagsJson;
    private enrichNodeRow;
    private readonly nodeSelectSql;
    listNodes(): Promise<NodeRecord[]>;
    getNodeById(nodeId: number): Promise<NodeRecord | undefined>;
    getDefaultNodeForEngine(engine: 'kvm' | 'lxc'): Promise<NodeRecord>;
    createNode(input: {
        name: string;
        hostname?: string;
        ipAddress?: string;
        location?: string;
        url: string;
        verifySsl?: boolean;
        tlsCaPem?: string | null;
        mtlsEnabled?: boolean;
        supportsKvm?: boolean;
        supportsLxc?: boolean;
        maxInstances?: number;
        tags?: string[] | string;
        notes?: string;
    }): Promise<{
        node: NodeRecord;
        bootstrapCredentials: {
            apiKey: string;
            hmacSecret: string;
        };
    }>;
    updateNode(nodeId: number, patch: {
        name?: string;
        hostname?: string;
        ipAddress?: string;
        location?: string;
        url?: string;
        maintenanceMode?: boolean;
        verifySsl?: boolean;
        tlsCaPem?: string | null;
        maxInstances?: number;
        supportsKvm?: boolean;
        supportsLxc?: boolean;
        tags?: string[] | string;
        notes?: string;
    }): Promise<NodeRecord>;
    deleteNode(nodeId: number): Promise<void>;
    buildEnvSnippet(params: {
        nodeId: number;
        port: string | number;
        apiKey: string;
        hmacSecret: string;
        controllerUrl?: string | null;
        isHttps?: boolean;
    }): string;
    getBootstrapCredentials(nodeId: number, controllerUrl?: string): Promise<{
        nodeId: number;
        nodeName: string;
        url: string;
        port: number;
        isHttps: boolean;
        apiKey: string;
        hmacSecret: string;
        envSnippet: string;
    }>;
    createJoinToken(params: {
        nodeId: number;
        controllerUrl: string;
        createdByUserId?: number;
        ttlMinutes?: number;
    }): Promise<{
        nodeId: number;
        nodeName: string;
        token: string;
        expiresAt: string;
        ttlMinutes: number;
        controllerUrl: string;
        curlJoinCommand: string;
        localJoinCommand: string;
    }>;
    redeemJoinToken(params: {
        rawToken: string;
        endpointUrl?: string;
        ipAddress?: string;
        hostname?: string;
        agentPort?: number;
        tlsCertPem?: string | null;
        verifySsl?: boolean;
        callerIp?: string;
    }): Promise<{
        nodeId: number;
        nodeName: string;
        apiKey: string;
        hmacSecret: string;
        controllerUrl: string | null;
        url: string;
    }>;
    /**
     * Trust-On-First-Use (TOFU) TLS certificate fetcher & pinner for self-signed HTTPS Node Agents.
     */
    trustNodeTlsCertificate(nodeId: number): Promise<{
        node: NodeRecord;
        fingerprintSha256: string;
        subjectCN: string | null;
        validTo: string | null;
        probeOk: boolean;
    }>;
    /**
     * Authenticates and processes an active outbound push-heartbeat sent by a remote Node Agent.
     */
    receiveAgentHeartbeat(params: {
        headers: Record<string, string | string[] | undefined>;
        rawBody: string;
        body: {
            nodeId?: string | number;
            health?: NodeHealthReport;
            stats?: HostResourceStats;
        };
    }): Promise<{
        ok: boolean;
        nodeId: number;
    }>;
    rotateNodeCredentials(nodeId: number): Promise<{
        apiKey: string;
        hmacSecret: string;
        pushedToAgent: boolean;
        envSnippet?: string;
    }>;
    private persistNodeHealthAndStats;
    /**
     * Refreshes health, capabilities, and real host stats for a node (local or remote).
     */
    checkNodeHealthAndStats(nodeId: number, options?: {
        bypassCircuit?: boolean;
    }): Promise<{
        node: NodeRecord;
        health: NodeHealthReport;
        stats: HostResourceStats;
        latencyMs: number;
    }>;
    resetCircuitBreaker(nodeId: number): Promise<NodeRecord>;
    /**
     * Pre-flight HTTP/HTTPS + TLS reachability & clock-drift probe for remote Node Agent URLs.
     * When strict TLS rejects a self-signed certificate, performs a safe certificate inspection
     * so the UI can offer one-click TOFU certificate pinning.
     */
    probeEndpointConnection(input: {
        url: string;
        verifySsl?: boolean;
        timeoutMs?: number;
    }): Promise<EndpointProbeResult>;
    /**
     * Computes transparent smart placement scores across cluster nodes for KVM or LXC workloads.
     */
    rankPlacementCandidates(engine: 'kvm' | 'lxc'): Promise<{
        nodeId: number;
        name: string;
        location: string;
        isLocal: boolean;
        eligible: boolean;
        hardwareReady: boolean;
        score: number;
        reasons: string[];
    }[]>;
    private checkCircuitAllowed;
    private recordCircuitSuccess;
    private recordCircuitFailure;
    private buildTlsOptionsForNode;
    requestRemoteNode<T = any>(nodeId: number, method: 'GET' | 'POST' | 'PATCH' | 'DELETE', pathWithQuery: string, body?: unknown, timeoutMs?: number, options?: {
        bypassCircuit?: boolean;
    }): Promise<T>;
    openRemoteAgentWebSocket(nodeId: number, wsPath: string, query?: Record<string, string | number>): Promise<WebSocket>;
}
