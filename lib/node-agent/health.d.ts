import { HostCapabilities } from './command-runner';
export interface NodeHealthReport {
    status: 'online' | 'degraded';
    agentVersion: string;
    hostname: string;
    uptimeSeconds: number;
    agentUptimeSeconds: number;
    agentTimeEpochSec: number;
    interactiveShellEnabled: boolean;
    timestamp: string;
    capabilities: HostCapabilities;
    warnings: string[];
}
export declare const AGENT_VERSION = "3.0.0";
export declare function getNodeHealthReport(forceRefresh?: boolean, options?: {
    interactiveShellEnabled?: boolean;
}): Promise<NodeHealthReport>;
