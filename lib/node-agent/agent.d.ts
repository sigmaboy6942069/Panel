import http from 'http';
import https from 'https';
import { NodeAgentAuthenticator } from './authentication';
import { HostStatsCollector } from './host-stats';
import { LxcContainerManager } from './container-manager';
import { LxcSnapshotAndBackupManager } from './snapshot-manager';
import { LxcTransferManager } from './transfer-manager';
import { LxcContainerConsoleManager } from './container-console';
import { AdminNodeShellManager } from './shell-manager';
/**
 * In-process runtime combining all Node Agent managers.
 * Used BOTH by the standalone remote Node Agent daemon (`startNodeAgentServer`)
 * AND directly by the HKVM controller for the `localhost` node.
 */
export declare class LocalNodeRuntime {
    readonly statsCollector: HostStatsCollector;
    readonly containerManager: LxcContainerManager;
    readonly snapshotManager: LxcSnapshotAndBackupManager;
    readonly transferManager: LxcTransferManager;
    readonly consoleManager: LxcContainerConsoleManager;
    readonly shellManager: AdminNodeShellManager;
    constructor(options?: {
        lxcBaseDir?: string;
        backupDir?: string;
        interactiveHostShell?: boolean;
        onAuditEvent?: (event: {
            action: string;
            actor: string;
            details: Record<string, unknown>;
        }) => void;
    });
}
export interface StandaloneAgentOptions {
    host?: string;
    port?: number;
    nodeId?: string;
    apiKey?: string;
    hmacSecret?: string;
    tlsCertPath?: string;
    tlsKeyPath?: string;
    tlsCaPath?: string;
    requireMtls?: boolean;
    lxcBaseDir?: string;
    backupDir?: string;
    dataDir?: string;
    interactiveHostShell?: boolean;
    controllerUrl?: string;
    controllerVerifySsl?: boolean;
    heartbeatIntervalMs?: number;
}
export declare function createNodeAgentServer(opts?: StandaloneAgentOptions): {
    app: import("express-serve-static-core").Express;
    server: http.Server<typeof http.IncomingMessage, typeof http.ServerResponse> | https.Server<typeof http.IncomingMessage, typeof http.ServerResponse>;
    runtime: LocalNodeRuntime;
    authenticator: NodeAgentAuthenticator;
    host: string;
    port: number;
    tlsActive: boolean;
    sendHeartbeatOnce: () => Promise<boolean>;
};
