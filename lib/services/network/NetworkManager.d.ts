import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
export declare class NetworkManager {
    private db;
    private nodeManager?;
    constructor(db: UnifiedDatabase, nodeManager?: NodeManager);
    private isRemoteNode;
    listNetworkPools(nodeId?: number): Promise<any[]>;
    createNetworkPool(input: {
        nodeId: number;
        name: string;
        networkType: 'bridge' | 'nat' | 'routed' | 'vlan';
        bridgeName: string;
        cidr?: string;
        gateway?: string;
        ipv6Cidr?: string;
        ipv6Gateway?: string;
        vlanId?: number | null;
        dnsServers?: string[];
    }): Promise<any>;
    addIpAddressesToPool(poolId: number, addresses: Array<{
        ip: string;
        version?: 4 | 6;
    }>): Promise<number>;
    listIpAllocations(poolId?: number): Promise<any[]>;
    getUserPortAllocation(userId: number): Promise<{
        userId: number;
        allocatedPorts: number;
        usedPorts: number;
        remainingPorts: number;
    }>;
    setUserPortQuota(userId: number, allocatedPorts: number): Promise<void>;
    listPortForwards(filter?: {
        userId?: number;
        nodeId?: number;
    }): Promise<any[]>;
    createPortForward(input: {
        userId: number;
        isAdmin: boolean;
        nodeId: number;
        instanceType: 'lxc' | 'kvm';
        instanceRefId: number;
        containerOrVmName: string;
        guestIp: string;
        guestPort: number;
        hostPort?: number;
        protocol?: 'tcp' | 'udp' | 'tcp,udp';
        description?: string;
    }): Promise<{
        portForward: any;
        kernelNatApplied: boolean;
    }>;
    deletePortForward(forwardId: number, actorUserId: number, isAdmin: boolean): Promise<void>;
    relocateInstancePortForwards(instanceType: 'lxc' | 'kvm', instanceRefId: number, targetNodeId: number, newGuestIp?: string | null): Promise<void>;
    private applyNatRuleForNode;
    private findAvailableHostPort;
    /**
     * Snapshots current `iptables-save` state before mutating NAT rules and restores automatically
     * if any protocol rule fails validation/application.
     */
    private applyNatRuleWithRollback;
    listFirewallRules(nodeId?: number): Promise<any[]>;
    createFirewallRule(input: {
        nodeId: number;
        instanceType?: 'lxc' | 'kvm' | null;
        instanceRefId?: number | null;
        direction: 'in' | 'out';
        action: 'ACCEPT' | 'DROP' | 'REJECT';
        protocol: 'tcp' | 'udp' | 'icmp' | 'all';
        sourceCidr?: string | null;
        destPort?: string | null;
        priority?: number;
        comment?: string;
    }): Promise<any>;
    deleteFirewallRule(ruleId: number): Promise<void>;
    private applyFirewallRuleForNode;
}
