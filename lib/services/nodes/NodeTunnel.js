"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.nodeTunnels = exports.NodeTunnelManager = void 0;
const net_1 = __importDefault(require("net"));
const ssh2_1 = require("ssh2");
class NodeTunnelManager {
    tunnels = new Map();
    pending = new Map();
    /**
     * Returns a stable loopback URL (http://127.0.0.1:<port>) whose port is
     * forwarded to the node's agent over SSH, creating the tunnel on first use.
     */
    async getTunnelUrl(nodeId, config) {
        const key = configKey(config);
        const existing = this.tunnels.get(nodeId);
        if (existing && existing.configKey === key) {
            return `http://127.0.0.1:${existing.localPort}`;
        }
        if (existing)
            await this.close(nodeId);
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
    async close(nodeId) {
        const tunnel = this.tunnels.get(nodeId);
        if (!tunnel)
            return;
        this.tunnels.delete(nodeId);
        for (const socket of tunnel.sockets)
            socket.destroy();
        await new Promise((resolve) => tunnel.server.close(() => resolve()));
        try {
            tunnel.client.end();
        }
        catch {
            // already gone
        }
    }
    async closeAll() {
        await Promise.all(Array.from(this.tunnels.keys()).map((id) => this.close(id)));
    }
    async open(nodeId, config, key) {
        const client = new ssh2_1.Client();
        const sockets = new Set();
        const connectConfig = await this.buildConnectConfig(config);
        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`SSH tunnel to ${config.host} timed out.`)), config.readyTimeoutMs || 20_000);
            client.once('ready', () => {
                clearTimeout(timer);
                resolve();
            });
            client.once('error', (err) => {
                clearTimeout(timer);
                reject(new Error(`SSH tunnel to ${config.username}@${config.host}:${config.port || 22} failed: ${err.message}`));
            });
            try {
                client.connect(connectConfig);
            }
            catch (err) {
                clearTimeout(timer);
                reject(err instanceof Error ? err : new Error(String(err)));
            }
        });
        const server = net_1.default.createServer((localSocket) => {
            sockets.add(localSocket);
            localSocket.on('close', () => sockets.delete(localSocket));
            localSocket.on('error', () => localSocket.destroy());
            client.forwardOut(localSocket.remoteAddress || '127.0.0.1', localSocket.remotePort || 0, config.targetHost || '127.0.0.1', config.targetPort, (err, stream) => {
                if (err) {
                    localSocket.destroy();
                    return;
                }
                localSocket.pipe(stream).pipe(localSocket);
                stream.on('error', () => localSocket.destroy());
                stream.on('close', () => localSocket.destroy());
                localSocket.on('close', () => stream.destroy());
            });
        });
        const localPort = await new Promise((resolve, reject) => {
            server.once('error', reject);
            // Port 0 = OS picks a free ephemeral port on loopback.
            server.listen(0, '127.0.0.1', () => {
                const addr = server.address();
                if (addr && typeof addr === 'object')
                    resolve(addr.port);
                else
                    reject(new Error('Could not allocate a loopback port for the SSH tunnel.'));
            });
        });
        const tunnel = { nodeId, server, client, localPort, configKey: key, sockets };
        // A dropped SSH connection invalidates the forwarding, so forget the tunnel
        // and let the next request rebuild it.
        client.on('close', () => {
            if (this.tunnels.get(nodeId) === tunnel)
                this.tunnels.delete(nodeId);
        });
        client.on('error', () => {
            if (this.tunnels.get(nodeId) === tunnel)
                this.tunnels.delete(nodeId);
        });
        this.tunnels.set(nodeId, tunnel);
        return tunnel;
    }
    async buildConnectConfig(config) {
        const base = {
            host: config.host,
            port: config.port || 22,
            username: config.username,
            readyTimeout: config.readyTimeoutMs || 20_000,
            // Keeps NAT/firewall state alive and detects dead peers.
            keepaliveInterval: 15_000,
            keepaliveCountMax: 4,
        };
        let privateKey = config.privateKey;
        if (!privateKey && config.privateKeyPath) {
            const fs = await Promise.resolve().then(() => __importStar(require('fs')));
            privateKey = await fs.promises.readFile(config.privateKeyPath);
        }
        if (privateKey) {
            base.privateKey = privateKey;
            if (config.passphrase)
                base.passphrase = config.passphrase;
        }
        else if (config.password) {
            base.password = config.password;
        }
        else {
            throw new Error('SSH tunnel requires a private key or a password.');
        }
        return base;
    }
}
exports.NodeTunnelManager = NodeTunnelManager;
function configKey(config) {
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
exports.nodeTunnels = new NodeTunnelManager();
