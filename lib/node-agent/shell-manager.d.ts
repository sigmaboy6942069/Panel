import WebSocket from 'ws';
export interface HostDiagnosticResult {
    preset: string;
    description: string;
    command: string;
    exitCode: number;
    durationMs: number;
    output: string;
    executedAt: string;
}
/**
 * Restricted, audited Admin Node Console & Diagnostic Shell Manager.
 *
 * Security model (Part 12 & Part 22):
 * 1. Safe Preset Diagnostic Mode is ALWAYS available to super-admins (`lxc-ls`, `df`, `free`, `uptime`, `ip addr`, `ps`, `lxc-checkconfig`) with zero arbitrary shell execution.
 * 2. Interactive `node-pty` Host Shell requires BOTH `admin` role AND explicit opt-in (`HKVM_ENABLE_NODE_SHELL=true`), and logs every session lifecycle + input line for auditability.
 */
export declare class AdminNodeShellManager {
    private interactiveEnabled;
    private onAuditEvent?;
    constructor(options?: {
        interactiveEnabled?: boolean;
        onAuditEvent?: (event: {
            action: string;
            actor: string;
            details: Record<string, unknown>;
        }) => void;
    });
    isInteractiveShellEnabled(): boolean;
    runDiagnosticPreset(preset: string, actor?: string): Promise<HostDiagnosticResult>;
    attachInteractiveHostPty(ws: WebSocket, actor: string, options?: {
        cols?: number;
        rows?: number;
    }): void;
    private captureCommandAudit;
}
