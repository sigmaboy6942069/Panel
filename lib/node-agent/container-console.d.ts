import WebSocket from 'ws';
export interface ActiveConsoleSession {
    sessionId: string;
    containerName: string;
    startedAt: number;
    cols: number;
    rows: number;
    close: () => void;
}
/**
 * Spawns a real interactive PTY attached to an LXC container (`lxc-attach -P <lxcBaseDir> -n <name> ...`)
 * with automatic `sudo -n` elevation when HKVM runs as a non-root operator user,
 * and bridges stdin/stdout/resize frames over WebSocket. Never fabricates terminal output.
 */
export declare class LxcContainerConsoleManager {
    private sessions;
    private idleTimeoutMs;
    private lxcBaseDir;
    constructor(idleTimeoutMs?: number, lxcBaseDir?: string);
    attachWebSocket(ws: WebSocket, containerName: string, options?: {
        cols?: number;
        rows?: number;
        sessionId?: string;
    }): ActiveConsoleSession;
    listActiveSessions(): Array<Omit<ActiveConsoleSession, 'close'>>;
}
