import net from 'net';
import { Client, ConnectConfig } from 'ssh2';

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

interface Tunnel {
  nodeId: number;
  server: net.Server;
  client: Client;
  localPort: number;
  configKey: string;
  sockets: Set<net.Socket>;
}

export class NodeTunnelManager {
  private tunnels = new Map<number, Tunnel>();
  private pending = new Map<number, Promise<Tunnel>>();

  /**
   * Returns a stable loopback URL (http://127.0.0.1:<port>) whose port is
   * forwarded to the node's agent over SSH, creating the tunnel on first use.
   */
  public async getTunnelUrl(nodeId: number, config: TunnelConfig): Promise<string> {
    const key = configKey(config);
    const existing = this.tunnels.get(nodeId);
    if (existing && existing.configKey === key) {
      return `http://127.0.0.1:${existing.localPort}`;
    }
    if (existing) await this.close(nodeId);

    // Collapse concurrent requests for the same node onto one attempt.
    const inFlight = this.pending.get(nodeId);
    if (inFlight) {
      const tunnel = await inFlight;
      return `http://127.0.0.1:${tunnel.localPort}`;
    }

    const attempt = this.open(nodeId, config, key).finally(() => this.pending.delete(nodeId));
    this.pending.set(nodeId, attempt);
    const tunnel = await attempt;
    return `http://127.0.0.1:${tunnel.localPort}`;
  }

  /** Tears down the tunnel for a node (no-op when there is none). */
  public async close(nodeId: number): Promise<void> {
    const tunnel = this.tunnels.get(nodeId);
    if (!tunnel) return;
    this.tunnels.delete(nodeId);
    for (const socket of tunnel.sockets) socket.destroy();
    await new Promise<void>((resolve) => tunnel.server.close(() => resolve()));
    try {
      tunnel.client.end();
    } catch {
      // already gone
    }
  }

  public async closeAll(): Promise<void> {
    await Promise.all(Array.from(this.tunnels.keys()).map((id) => this.close(id)));
  }

  private async open(nodeId: number, config: TunnelConfig, key: string): Promise<Tunnel> {
    const client = new Client();
    const sockets = new Set<net.Socket>();

    const connectConfig = await this.buildConnectConfig(config);

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`SSH tunnel to ${config.host} timed out.`)),
        config.readyTimeoutMs || 20_000
      );
      client.once('ready', () => {
        clearTimeout(timer);
        resolve();
      });
      client.once('error', (err) => {
        clearTimeout(timer);
        reject(
          new Error(
            `SSH tunnel to ${config.username}@${config.host}:${config.port || 22} failed: ${err.message}`
          )
        );
      });
      try {
        client.connect(connectConfig);
      } catch (err) {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });

    const server = net.createServer((localSocket) => {
      sockets.add(localSocket);
      localSocket.on('close', () => sockets.delete(localSocket));
      localSocket.on('error', () => localSocket.destroy());

      client.forwardOut(
        localSocket.remoteAddress || '127.0.0.1',
        localSocket.remotePort || 0,
        config.targetHost || '127.0.0.1',
        config.targetPort,
        (err, stream) => {
          if (err) {
            localSocket.destroy();
            return;
          }
          localSocket.pipe(stream).pipe(localSocket);
          stream.on('error', () => localSocket.destroy());
          stream.on('close', () => localSocket.destroy());
          localSocket.on('close', () => stream.destroy());
        }
      );
    });

    const localPort = await new Promise<number>((resolve, reject) => {
      server.once('error', reject);
      // Port 0 = OS picks a free ephemeral port on loopback.
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') resolve(addr.port);
        else reject(new Error('Could not allocate a loopback port for the SSH tunnel.'));
      });
    });

    const tunnel: Tunnel = { nodeId, server, client, localPort, configKey: key, sockets };
    // A dropped SSH connection invalidates the forwarding, so forget the tunnel
    // and let the next request rebuild it.
    client.on('close', () => {
      if (this.tunnels.get(nodeId) === tunnel) this.tunnels.delete(nodeId);
    });
    client.on('error', () => {
      if (this.tunnels.get(nodeId) === tunnel) this.tunnels.delete(nodeId);
    });

    this.tunnels.set(nodeId, tunnel);
    return tunnel;
  }

  private async buildConnectConfig(config: TunnelConfig): Promise<ConnectConfig> {
    const base: ConnectConfig = {
      host: config.host,
      port: config.port || 22,
      username: config.username,
      readyTimeout: config.readyTimeoutMs || 20_000,
      // Keeps NAT/firewall state alive and detects dead peers.
      keepaliveInterval: 15_000,
      keepaliveCountMax: 4,
    };

    let privateKey: string | Buffer | undefined = config.privateKey;
    if (!privateKey && config.privateKeyPath) {
      const fs = await import('fs');
      privateKey = await fs.promises.readFile(config.privateKeyPath);
    }
    if (privateKey) {
      base.privateKey = privateKey;
      if (config.passphrase) base.passphrase = config.passphrase;
    } else if (config.password) {
      base.password = config.password;
    } else {
      throw new Error('SSH tunnel requires a private key or a password.');
    }
    return base;
  }
}

function configKey(config: TunnelConfig): string {
  // Identifies the connection; a change forces a fresh tunnel.
  return [
    config.host,
    config.port || 22,
    config.username,
    config.privateKeyPath || '',
    config.privateKey ? String(config.privateKey).length : 0,
    config.targetHost || '127.0.0.1',
    config.targetPort,
  ].join('|');
}

/** Process-wide instance so tunnels survive across requests. */
export const nodeTunnels = new NodeTunnelManager();
