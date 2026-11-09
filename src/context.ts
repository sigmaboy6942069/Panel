import crypto from 'crypto';
import http from 'http';
import sqlite3 from 'sqlite3';
import WebSocket, { WebSocketServer } from 'ws';
import { registerUnifiedDatabase, UnifiedDatabase } from './db/database';
import { runMigrations } from './db/migrations';
import { decryptSecret, encryptSecret, generateApiKeyPair } from './security/crypto-vault';
import { NodeManager } from './services/nodes/NodeClient';
import { KVMAdapter, LegacyKvmHooks } from './services/virtualization/KVMAdapter';
import { LXCAdapter } from './services/virtualization/LXCAdapter';
import { VirtualizationManager } from './services/virtualization/VirtualizationManager';
import { InstanceManager } from './services/virtualization/InstanceManager';
import { StorageManager } from './services/storage/StorageManager';
import { NetworkManager } from './services/network/NetworkManager';
import { BackupSnapshotManager } from './services/backup/BackupSnapshotManager';
import { MigrationManager } from './services/migration/MigrationManager';
import { MonitoringService } from './services/monitoring/MonitoringService';
import { ResellerService } from './services/reseller/ResellerService';
import { normalizeRole } from './security/middleware';

export interface HkvmRuntimeContext {
  db: UnifiedDatabase;
  nodeManager: NodeManager;
  kvmAdapter: KVMAdapter;
  lxcAdapter: LXCAdapter;
  virtManager: VirtualizationManager;
  instanceManager: InstanceManager;
  storageManager: StorageManager;
  networkManager: NetworkManager;
  backupManager: BackupSnapshotManager;
  migrationManager: MigrationManager;
  monitoringService: MonitoringService;
  /** Upstream reseller integration (Bukkit-Hosting KVM provisioning). */
  reseller: ResellerService;
}

let activeContext: HkvmRuntimeContext | null = null;

export async function initializeUnifiedHkvmRuntime(
  rawDb: sqlite3.Database,
  dbPath: string,
  legacyKvmHooks: LegacyKvmHooks = {}
): Promise<HkvmRuntimeContext> {
  const db = registerUnifiedDatabase(rawDb, dbPath);
  await runMigrations(db);

  // Ensure local node credentials decrypt cleanly with this host's .tgvpanel-secret
  // (e.g. after cloning a repository whose initial DB was seeded on another host)
  const localNodes = await db.all<{ id: number }>(
    `SELECT id FROM nodes WHERE is_local = 1`
  );
  for (const ln of localNodes) {
    const cred = await db.get<{ api_key_enc: string; hmac_secret_enc: string }>(
      `SELECT api_key_enc, hmac_secret_enc FROM node_credentials WHERE node_id = ?`,
      [ln.id]
    );
    if (!cred || !decryptSecret(cred.api_key_enc) || !decryptSecret(cred.hmac_secret_enc)) {
      const pair = generateApiKeyPair('hkvm_node');
      const hmac = crypto.randomBytes(32).toString('hex');
      await db.run(
        `INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc, rotated_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(node_id) DO UPDATE SET
           api_key_prefix = excluded.api_key_prefix,
           api_key_hash = excluded.api_key_hash,
           api_key_enc = excluded.api_key_enc,
           hmac_secret_enc = excluded.hmac_secret_enc,
           rotated_at = datetime('now')`,
        [ln.id, pair.keyPrefix, pair.keyHash, encryptSecret(pair.rawKey), encryptSecret(hmac)]
      );
    }
  }

  const nodeManager = new NodeManager(db);
  const kvmAdapter = new KVMAdapter(db, legacyKvmHooks);
  const lxcAdapter = new LXCAdapter(db, nodeManager);
  const virtManager = new VirtualizationManager(kvmAdapter, lxcAdapter);
  const instanceManager = new InstanceManager(db, virtManager);
  const storageManager = new StorageManager(db, nodeManager);
  const networkManager = new NetworkManager(db, nodeManager);
  const backupManager = new BackupSnapshotManager(db, nodeManager, virtManager);
  const migrationManager = new MigrationManager(
    db,
    nodeManager,
    storageManager,
    lxcAdapter,
    networkManager
  );
  const monitoringService = new MonitoringService(db, nodeManager, instanceManager);
  const reseller = new ResellerService(db);

  if (
    process.env.TGVPANEL_DISABLE_BACKGROUND_POLLER !== 'true' &&
    process.env.HKVM_DISABLE_BACKGROUND_POLLER !== 'true'
  ) {
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

export function getHkvmRuntimeContext(): HkvmRuntimeContext {
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
export function attachUnifiedWebSockets(
  server: http.Server,
  sessionMiddleware: any,
  ctx: HkvmRuntimeContext
): void {
  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (req: any, socket, head) => {
    const pathname = (req.url || '').split('?')[0];
    const lxcMatch = pathname.match(/^\/ws\/lxc\/(\d+)\/console$/);
    const nodeShellMatch = pathname.match(/^\/ws\/nodes\/(\d+)\/shell$/);

    if (!lxcMatch && !nodeShellMatch) {
      // Leave `/console/:vmId` and `/ssh/:vmId` for existing HKVM V2 handlers
      return;
    }

    const dummyRes: any = {
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

        const dbUser = await ctx.db.get<{ id: number; username: string; role: string; is_active: number }>(
          `SELECT id, username, role, is_active FROM users WHERE id = ?`,
          [sessUid]
        );
        if (!dbUser || dbUser.is_active === 0) {
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
          socket.destroy();
          return;
        }

        const principal = {
          userId: dbUser.id,
          username: dbUser.username,
          role: normalizeRole(dbUser.role),
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

          wss.handleUpgrade(req, socket, head, async (clientWs: WebSocket) => {
            const earlyFrames: string[] = [];
            const captureEarly = (raw: WebSocket.RawData) => {
              if (earlyFrames.length < 64) earlyFrames.push(raw.toString());
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
                ctx.nodeManager.localRuntime.consoleManager.attachWebSocket(
                  clientWs,
                  rawRow.container_name,
                  { cols, rows }
                );
                for (const frame of earlyFrames) {
                  clientWs.emit('message', Buffer.from(frame, 'utf8'), false);
                }
              } catch {
                // error message already sent on clientWs
              }
            } else {
              try {
                const agentWs = await ctx.nodeManager.openRemoteAgentWebSocket(
                  rawRow.node_id,
                  `/ws/containers/${encodeURIComponent(rawRow.container_name)}/console`,
                  { cols, rows }
                );
                clientWs.off('message', captureEarly);
                bridgeWebSockets(clientWs, agentWs, earlyFrames);
              } catch (err: any) {
                clientWs.off('message', captureEarly);
                if (clientWs.readyState === WebSocket.OPEN) {
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

          wss.handleUpgrade(req, socket, head, async (clientWs: WebSocket) => {
            if (node.is_local) {
              ctx.nodeManager.localRuntime.shellManager.attachInteractiveHostPty(
                clientWs,
                principal.username,
                { cols, rows }
              );
            } else {
              const earlyFrames: string[] = [];
              const captureEarly = (raw: WebSocket.RawData) => {
                if (earlyFrames.length < 64) earlyFrames.push(raw.toString());
              };
              clientWs.on('message', captureEarly);
              try {
                const agentWs = await ctx.nodeManager.openRemoteAgentWebSocket(
                  nodeId,
                  `/ws/host/shell`,
                  { cols, rows }
                );
                clientWs.off('message', captureEarly);
                bridgeWebSockets(clientWs, agentWs, earlyFrames);
              } catch (err: any) {
                clientWs.off('message', captureEarly);
                if (clientWs.readyState === WebSocket.OPEN) {
                  clientWs.send(JSON.stringify({ type: 'error', message: err.message }));
                  clientWs.close();
                }
              }
            }
          });
        }
      } catch {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
      }
    });
  });
}

function bridgeWebSockets(
  clientWs: WebSocket,
  upstreamWs: WebSocket,
  initialFrames: string[] = []
): void {
  const pendingToUpstream: string[] = [...initialFrames];

  const flushUpstream = () => {
    while (pendingToUpstream.length > 0 && upstreamWs.readyState === WebSocket.OPEN) {
      const next = pendingToUpstream.shift();
      if (next !== undefined) upstreamWs.send(next);
    }
  };

  if (upstreamWs.readyState === WebSocket.OPEN) {
    flushUpstream();
  } else {
    upstreamWs.once('open', flushUpstream);
  }

  clientWs.on('message', (data) => {
    const str = data.toString();
    if (upstreamWs.readyState === WebSocket.OPEN) {
      upstreamWs.send(str);
    } else if (upstreamWs.readyState === WebSocket.CONNECTING && pendingToUpstream.length < 64) {
      pendingToUpstream.push(str);
    }
  });
  upstreamWs.on('message', (data) => {
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(data.toString());
    }
  });
  clientWs.on('close', () => {
    try {
      upstreamWs.close();
    } catch {
      // ignore
    }
  });
  upstreamWs.on('close', () => {
    try {
      clientWs.close();
    } catch {
      // ignore
    }
  });
  upstreamWs.on('error', (err) => {
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(JSON.stringify({ type: 'error', message: err.message }));
      clientWs.close();
    }
  });
}
