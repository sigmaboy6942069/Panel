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
exports.initializeUnifiedHkvmRuntime = initializeUnifiedHkvmRuntime;
exports.getHkvmRuntimeContext = getHkvmRuntimeContext;
exports.attachUnifiedWebSockets = attachUnifiedWebSockets;
const crypto_1 = __importDefault(require("crypto"));
const ws_1 = __importStar(require("ws"));
const database_1 = require("./db/database");
const migrations_1 = require("./db/migrations");
const crypto_vault_1 = require("./security/crypto-vault");
const NodeClient_1 = require("./services/nodes/NodeClient");
const KVMAdapter_1 = require("./services/virtualization/KVMAdapter");
const LXCAdapter_1 = require("./services/virtualization/LXCAdapter");
const VirtualizationManager_1 = require("./services/virtualization/VirtualizationManager");
const InstanceManager_1 = require("./services/virtualization/InstanceManager");
const StorageManager_1 = require("./services/storage/StorageManager");
const NetworkManager_1 = require("./services/network/NetworkManager");
const BackupSnapshotManager_1 = require("./services/backup/BackupSnapshotManager");
const MigrationManager_1 = require("./services/migration/MigrationManager");
const MonitoringService_1 = require("./services/monitoring/MonitoringService");
const ResellerService_1 = require("./services/reseller/ResellerService");
const middleware_1 = require("./security/middleware");
let activeContext = null;
async function initializeUnifiedHkvmRuntime(rawDb, dbPath, legacyKvmHooks = {}) {
    const db = (0, database_1.registerUnifiedDatabase)(rawDb, dbPath);
    await (0, migrations_1.runMigrations)(db);
    // Ensure local node credentials decrypt cleanly with this host's .tgvpanel-secret
    // (e.g. after cloning a repository whose initial DB was seeded on another host)
    const localNodes = await db.all(`SELECT id FROM nodes WHERE is_local = 1`);
    for (const ln of localNodes) {
        const cred = await db.get(`SELECT api_key_enc, hmac_secret_enc FROM node_credentials WHERE node_id = ?`, [ln.id]);
        if (!cred || !(0, crypto_vault_1.decryptSecret)(cred.api_key_enc) || !(0, crypto_vault_1.decryptSecret)(cred.hmac_secret_enc)) {
            const pair = (0, crypto_vault_1.generateApiKeyPair)('hkvm_node');
            const hmac = crypto_1.default.randomBytes(32).toString('hex');
            await db.run(`INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc, rotated_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(node_id) DO UPDATE SET
           api_key_prefix = excluded.api_key_prefix,
           api_key_hash = excluded.api_key_hash,
           api_key_enc = excluded.api_key_enc,
           hmac_secret_enc = excluded.hmac_secret_enc,
           rotated_at = datetime('now')`, [ln.id, pair.keyPrefix, pair.keyHash, (0, crypto_vault_1.encryptSecret)(pair.rawKey), (0, crypto_vault_1.encryptSecret)(hmac)]);
        }
    }
    const nodeManager = new NodeClient_1.NodeManager(db);
    const kvmAdapter = new KVMAdapter_1.KVMAdapter(db, legacyKvmHooks);
    const lxcAdapter = new LXCAdapter_1.LXCAdapter(db, nodeManager);
    const virtManager = new VirtualizationManager_1.VirtualizationManager(kvmAdapter, lxcAdapter);
    const instanceManager = new InstanceManager_1.InstanceManager(db, virtManager);
    const storageManager = new StorageManager_1.StorageManager(db, nodeManager);
    const networkManager = new NetworkManager_1.NetworkManager(db, nodeManager);
    const backupManager = new BackupSnapshotManager_1.BackupSnapshotManager(db, nodeManager, virtManager);
    const migrationManager = new MigrationManager_1.MigrationManager(db, nodeManager, storageManager, lxcAdapter, networkManager);
    const monitoringService = new MonitoringService_1.MonitoringService(db, nodeManager, instanceManager);
    // A local (own-node) provider needs the virtualization layer to create real
    // instances when a customer orders.
    const reseller = new ResellerService_1.ResellerService(db, virtManager);
    if (process.env.TGVPANEL_DISABLE_BACKGROUND_POLLER !== 'true' &&
        process.env.HKVM_DISABLE_BACKGROUND_POLLER !== 'true') {
        monitoringService.startBackgroundLoop(60_000);
        // Drains queued upstream orders and reconciles cloud server states/IPs.
        reseller.startBackgroundJobs();
        lxcAdapter.healLocalContainersNetworking().catch((err) => {
            console.warn('[LXC Network Self-Heal]', err?.message || err);
        });
    }
    activeContext = {
        db,
        nodeManager,
        kvmAdapter,
        lxcAdapter,
        virtManager,
        instanceManager,
        storageManager,
        networkManager,
        backupManager,
        migrationManager,
        monitoringService,
        reseller,
    };
    return activeContext;
}
function getHkvmRuntimeContext() {
    if (!activeContext) {
        throw new Error('TGVPANEL Unified Runtime has not been initialized.');
    }
    return activeContext;
}
/**
 * Attaches session-authenticated WebSocket endpoints for:
 *  - `/ws/lxc/:id/console` (Real LXC container PTY console via LocalNodeRuntime or remote Node Agent)
 *  - `/ws/nodes/:id/shell` (Restricted, audited Admin Node Console)
 */
function attachUnifiedWebSockets(server, sessionMiddleware, ctx) {
    const wss = new ws_1.WebSocketServer({ noServer: true });
    server.on('upgrade', (req, socket, head) => {
        const pathname = (req.url || '').split('?')[0];
        const lxcMatch = pathname.match(/^\/ws\/lxc\/(\d+)\/console$/);
        const nodeShellMatch = pathname.match(/^\/ws\/nodes\/(\d+)\/shell$/);
        if (!lxcMatch && !nodeShellMatch) {
            // Leave `/console/:vmId` and `/ssh/:vmId` for existing HKVM V2 handlers
            return;
        }
        const dummyRes = {
            getHeader: () => undefined,
            setHeader: () => undefined,
            writeHead: () => undefined,
            end: () => undefined,
        };
        sessionMiddleware(req, dummyRes, async () => {
            try {
                const sessUid = req.session?.userId || req.session?.user?.id;
                if (!sessUid) {
                    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                    socket.destroy();
                    return;
                }
                const dbUser = await ctx.db.get(`SELECT id, username, role, is_active FROM users WHERE id = ?`, [sessUid]);
                if (!dbUser || dbUser.is_active === 0) {
                    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                    socket.destroy();
                    return;
                }
                const principal = {
                    userId: dbUser.id,
                    username: dbUser.username,
                    role: (0, middleware_1.normalizeRole)(dbUser.role),
                };
                const urlObj = new URL(req.url || '/', 'http://localhost');
                const cols = Number(urlObj.searchParams.get('cols') || 100);
                const rows = Number(urlObj.searchParams.get('rows') || 30);
                if (lxcMatch) {
                    const lxcId = parseInt(lxcMatch[1], 10);
                    await ctx.instanceManager.getAuthorizedInstance(principal, 'lxc', lxcId);
                    const rawRow = await ctx.lxcAdapter.getRawLxcRow(lxcId);
                    if (!rawRow) {
                        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
                        socket.destroy();
                        return;
                    }
                    wss.handleUpgrade(req, socket, head, async (clientWs) => {
                        const earlyFrames = [];
                        const captureEarly = (raw) => {
                            if (earlyFrames.length < 64)
                                earlyFrames.push(raw.toString());
                        };
                        clientWs.on('message', captureEarly);
                        await ctx.db.logActivity({
                            userId: principal.userId,
                            action: 'lxc_console_opened',
                            resourceType: 'lxc',
                            resourceId: String(lxcId),
                            details: { containerName: rawRow.container_name },
                        });
                        if (rawRow.is_local) {
                            clientWs.off('message', captureEarly);
                            try {
                                ctx.nodeManager.localRuntime.consoleManager.attachWebSocket(clientWs, rawRow.container_name, { cols, rows });
                                for (const frame of earlyFrames) {
                                    clientWs.emit('message', Buffer.from(frame, 'utf8'), false);
                                }
                            }
                            catch {
                                // error message already sent on clientWs
                            }
                        }
                        else {
                            try {
                                const agentWs = await ctx.nodeManager.openRemoteAgentWebSocket(rawRow.node_id, `/ws/containers/${encodeURIComponent(rawRow.container_name)}/console`, { cols, rows });
                                clientWs.off('message', captureEarly);
                                bridgeWebSockets(clientWs, agentWs, earlyFrames);
                            }
                            catch (err) {
                                clientWs.off('message', captureEarly);
                                if (clientWs.readyState === ws_1.default.OPEN) {
                                    clientWs.send(JSON.stringify({ type: 'error', message: err.message }));
                                    clientWs.close();
                                }
                            }
                        }
                    });
                    return;
                }
                if (nodeShellMatch) {
                    if (principal.role !== 'admin') {
                        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
                        socket.destroy();
                        return;
                    }
                    const nodeId = parseInt(nodeShellMatch[1], 10);
                    const node = await ctx.nodeManager.getNodeById(nodeId);
                    if (!node) {
                        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
                        socket.destroy();
                        return;
                    }
                    wss.handleUpgrade(req, socket, head, async (clientWs) => {
                        if (node.is_local) {
                            ctx.nodeManager.localRuntime.shellManager.attachInteractiveHostPty(clientWs, principal.username, { cols, rows });
                        }
                        else {
                            const earlyFrames = [];
                            const captureEarly = (raw) => {
                                if (earlyFrames.length < 64)
                                    earlyFrames.push(raw.toString());
                            };
                            clientWs.on('message', captureEarly);
                            try {
                                const agentWs = await ctx.nodeManager.openRemoteAgentWebSocket(nodeId, `/ws/host/shell`, { cols, rows });
                                clientWs.off('message', captureEarly);
                                bridgeWebSockets(clientWs, agentWs, earlyFrames);
                            }
                            catch (err) {
                                clientWs.off('message', captureEarly);
                                if (clientWs.readyState === ws_1.default.OPEN) {
                                    clientWs.send(JSON.stringify({ type: 'error', message: err.message }));
                                    clientWs.close();
                                }
                            }
                        }
                    });
                }
            }
            catch {
                socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
                socket.destroy();
            }
        });
    });
}
function bridgeWebSockets(clientWs, upstreamWs, initialFrames = []) {
    const pendingToUpstream = [...initialFrames];
    const flushUpstream = () => {
        while (pendingToUpstream.length > 0 && upstreamWs.readyState === ws_1.default.OPEN) {
            const next = pendingToUpstream.shift();
            if (next !== undefined)
                upstreamWs.send(next);
        }
    };
    if (upstreamWs.readyState === ws_1.default.OPEN) {
        flushUpstream();
    }
    else {
        upstreamWs.once('open', flushUpstream);
    }
    clientWs.on('message', (data) => {
        const str = data.toString();
        if (upstreamWs.readyState === ws_1.default.OPEN) {
            upstreamWs.send(str);
        }
        else if (upstreamWs.readyState === ws_1.default.CONNECTING && pendingToUpstream.length < 64) {
            pendingToUpstream.push(str);
        }
    });
    upstreamWs.on('message', (data) => {
        if (clientWs.readyState === ws_1.default.OPEN) {
            clientWs.send(data.toString());
        }
    });
    clientWs.on('close', () => {
        try {
            upstreamWs.close();
        }
        catch {
            // ignore
        }
    });
    upstreamWs.on('close', () => {
        try {
            clientWs.close();
        }
        catch {
            // ignore
        }
    });
    upstreamWs.on('error', (err) => {
        if (clientWs.readyState === ws_1.default.OPEN) {
            clientWs.send(JSON.stringify({ type: 'error', message: err.message }));
            clientWs.close();
        }
    });
}
