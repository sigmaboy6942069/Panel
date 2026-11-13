/**
 * Outbound SSH tunnels to compute nodes.
 *
 * A node agent normally listens on a public port (8443) that the controller
 * dials. Exposing that port is the weakest part of a multi-node install: it is
 * internet-reachable, needs a certificate, and is the only inbound hole.
 *
 * When a node is registered with `tunnel_enabled`, the controller instead opens
 * an SSH connection **outbound** to the node and forwards a local ephemeral
 * port to the agent's loopback listener. The node then binds the agent to
 * 127.0.0.1 and exposes nothing at all — the only requirement is SSH, which
 * you already have to administer the box.
 *
 * Everything above the socket is unchanged: requests are still HMAC-signed and
 * can still use TLS, so the tunnel is additive rather than a replacement for
 * the existing authentication.
 */
export interface TunnelConfig {
    /** SSH host (usually the node's public IP). */
    host: string;
    /** SSH port, default 22. */
    port?: number;
    username: string;
    /** Inline private key (PEM/OpenSSH). Takes precedence over `privateKeyPath`. */
    privateKey?: string;
    /** Path to a private key readable by the panel process. */
    privateKeyPath?: string;
    passphrase?: string;
    password?: string;
    /** Where the agent listens **on the node** (target of the forward). */
    targetHost?: string;
    targetPort: number;
    /** SSH handshake/keepalive timeout in ms. */
    readyTimeoutMs?: number;
}
export declare class NodeTunnelManager {
    private tunnels;
    private pending;
    /**
     * Returns a stable loopback URL (http://127.0.0.1:<port>) whose port is
     * forwarded to the node's agent over SSH, creating the tunnel on first use.
     */
    getTunnelUrl(nodeId: number, config: TunnelConfig): Promise<string>;
    /** Tears down the tunnel for a node (no-op when there is none). */
    close(nodeId: number): Promise<void>;
    closeAll(): Promise<void>;
    private open;
    private buildConnectConfig;
}
/** Process-wide instance so tunnels survive across requests. */
export declare const nodeTunnels: NodeTunnelManager;
