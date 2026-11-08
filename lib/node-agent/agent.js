"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalNodeRuntime = void 0;
exports.createNodeAgentServer = createNodeAgentServer;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const path_1 = __importDefault(require("path"));
const dotenv_1 = __importDefault(require("dotenv"));
const express_1 = __importDefault(require("express"));
const ws_1 = require("ws");
const authentication_1 = require("./authentication");
const health_1 = require("./health");
const host_stats_1 = require("./host-stats");
const container_manager_1 = require("./container-manager");
const snapshot_manager_1 = require("./snapshot-manager");
const transfer_manager_1 = require("./transfer-manager");
const container_console_1 = require("./container-console");
const shell_manager_1 = require("./shell-manager");
const command_runner_1 = require("./command-runner");
const crypto_vault_1 = require("../security/crypto-vault");
const middleware_1 = require("../security/middleware");
/**
 * In-process runtime combining all Node Agent managers.
 * Used BOTH by the standalone remote Node Agent daemon (`startNodeAgentServer`)
 * AND directly by the HKVM controller for the `localhost` node.
 */
class LocalNodeRuntime {
    statsCollector;
    containerManager;
    snapshotManager;
    transferManager;
    consoleManager;
    shellManager;
    constructor(options) {
        this.statsCollector = new host_stats_1.HostStatsCollector();
        this.containerManager = new container_manager_1.LxcContainerManager(options?.lxcBaseDir);
        this.snapshotManager = new snapshot_manager_1.LxcSnapshotAndBackupManager(options?.backupDir, options?.lxcBaseDir);
        this.transferManager = new transfer_manager_1.LxcTransferManager(this.containerManager, this.snapshotManager);
        this.consoleManager = new container_console_1.LxcContainerConsoleManager(undefined, options?.lxcBaseDir);
        this.shellManager = new shell_manager_1.AdminNodeShellManager({
            interactiveEnabled: options?.interactiveHostShell,
            onAuditEvent: options?.onAuditEvent,
        });
    }
}
exports.LocalNodeRuntime = LocalNodeRuntime;
function resolveNearestExistingAncestorPath(targetPath) {
    let cur = path_1.default.resolve(targetPath);
    while (true) {
        if (fs_1.default.existsSync(cur))
            return cur;
        const parent = path_1.default.dirname(cur);
        if (!parent || parent === cur)
            break;
        cur = parent;
    }
    return null;
}
function createNodeAgentServer(opts = {}) {
    // Always load .env from both repository root (relative to compiled lib/node-agent/) and cwd
    // without overriding already-set process.env keys, so TLS/LXC/Shell flags are never skipped.
    if (!opts.apiKey) {
        const repoEnv = path_1.default.resolve(__dirname, '../../.env');
        if (fs_1.default.existsSync(repoEnv)) {
            dotenv_1.default.config({ path: repoEnv });
        }
        dotenv_1.default.config();
    }
    const host = (0, authentication_1.sanitizeAgentEnvValue)(opts.host || process.env.TGVPANEL_AGENT_HOST || process.env.HKVM_AGENT_HOST) || '0.0.0.0';
    const port = Number(opts.port ||
        process.env.TGVPANEL_AGENT_PORT ||
        process.env.AGENT_PORT ||
        process.env.HKVM_AGENT_PORT ||
        8443);
    const nodeId = (0, authentication_1.sanitizeAgentEnvValue)(opts.nodeId || process.env.TGVPANEL_NODE_ID || process.env.HKVM_NODE_ID) || 'remote-node';
    const rawApiKey = (0, authentication_1.sanitizeAgentEnvValue)(opts.apiKey || process.env.TGVPANEL_NODE_API_KEY || process.env.HKVM_NODE_API_KEY);
    const hmacSecret = (0, authentication_1.sanitizeAgentEnvValue)(opts.hmacSecret ||
        process.env.TGVPANEL_NODE_HMAC_SECRET ||
        process.env.HKVM_NODE_HMAC_SECRET);
    const dataDir = opts.dataDir ||
        (0, authentication_1.sanitizeAgentEnvValue)(process.env.TGVPANEL_DATA_DIR || process.env.HKVM_DATA_DIR) ||
        path_1.default.resolve(__dirname, '../../data');
    const credsFile = path_1.default.join(dataDir, 'node-agent-credentials.json');
    const templateCacheDir = path_1.default.join(dataDir, 'lxc-templates');
    const hasPersistedCreds = !opts.apiKey && fs_1.default.existsSync(credsFile);
    if ((!rawApiKey || !hmacSecret) && !hasPersistedCreds) {
        throw new Error('TGVPANEL Node Agent requires TGVPANEL_NODE_API_KEY and TGVPANEL_NODE_HMAC_SECRET to start securely.');
    }
    const allowedIpsRaw = (0, authentication_1.sanitizeAgentEnvValue)(process.env.TGVPANEL_ALLOWED_CONTROLLER_IPS || process.env.HKVM_ALLOWED_CONTROLLER_IPS);
    const allowedControllerIps = allowedIpsRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    const runtime = new LocalNodeRuntime({
        lxcBaseDir: opts.lxcBaseDir ||
            (0, authentication_1.sanitizeAgentEnvValue)(process.env.TGVPANEL_LXC_DIR || process.env.HKVM_LXC_PATH) ||
            undefined,
        backupDir: opts.backupDir || (0, authentication_1.sanitizeAgentEnvValue)(process.env.TGVPANEL_BACKUP_DIR) || undefined,
        interactiveHostShell: opts.interactiveHostShell ??
            ((0, authentication_1.sanitizeAgentEnvValue)(process.env.TGVPANEL_ENABLE_NODE_SHELL) === 'true' ||
                (0, authentication_1.sanitizeAgentEnvValue)(process.env.HKVM_ENABLE_NODE_SHELL) === 'true'),
    });
    const envBootstrapHash = rawApiKey && hmacSecret ? (0, crypto_vault_1.hashApiKey)(`${rawApiKey}:${hmacSecret}`) : undefined;
    const authenticator = new authentication_1.NodeAgentAuthenticator({
        nodeId,
        rawApiKey,
        apiKeyHash: rawApiKey ? (0, crypto_vault_1.hashApiKey)(rawApiKey) : '',
        hmacSecret,
        envBootstrapHash,
        requireMtls: Boolean(opts.requireMtls ||
            (0, authentication_1.sanitizeAgentEnvValue)(process.env.TGVPANEL_NODE_MTLS) === 'true' ||
            (0, authentication_1.sanitizeAgentEnvValue)(process.env.HKVM_NODE_MTLS) === 'true'),
        allowedControllerIps: allowedControllerIps.length > 0 ? allowedControllerIps : undefined,
        credentialsFilePath: credsFile,
        loadPersistedCredentials: !opts.apiKey,
    });
    const certPath = (0, authentication_1.sanitizeAgentEnvValue)(opts.tlsCertPath ||
        process.env.TGVPANEL_AGENT_TLS_CERT ||
        process.env.HKVM_AGENT_TLS_CERT);
    const keyPath = (0, authentication_1.sanitizeAgentEnvValue)(opts.tlsKeyPath || process.env.TGVPANEL_AGENT_TLS_KEY || process.env.HKVM_AGENT_TLS_KEY);
    const caPath = (0, authentication_1.sanitizeAgentEnvValue)(opts.tlsCaPath || process.env.TGVPANEL_AGENT_TLS_CA || process.env.HKVM_AGENT_TLS_CA);
    const tlsActive = Boolean(certPath && keyPath && fs_1.default.existsSync(certPath) && fs_1.default.existsSync(keyPath));
    const app = (0, express_1.default)();
    app.use(express_1.default.json({
        limit: '128mb',
        verify: (req, _res, buf) => {
            req.rawBody = buf.toString('utf8');
        },
    }));
    // Public unauthenticated zero-info reachability & clock-sync discovery endpoint
    app.get('/api/v1/ping', (_req, res) => {
        const nowSec = Math.floor(Date.now() / 1000);
        res.setHeader('X-TGVPANEL-Agent-Time', String(nowSec));
        res.json({
            ok: true,
            service: 'tgvpanel-node-agent',
            agentVersion: health_1.AGENT_VERSION,
            tls: tlsActive,
            agentTimeEpochSec: nowSec,
        });
    });
    // Authenticated REST endpoints
    app.use('/api/v1', authenticator.expressMiddleware());
    app.get('/api/v1/health', async (req, res) => {
        const report = await (0, health_1.getNodeHealthReport)(req.query.refresh === '1', {
            interactiveShellEnabled: runtime.shellManager.isInteractiveShellEnabled(),
        });
        res.json(report);
    });
    app.get('/api/v1/stats', async (_req, res) => {
        const stats = await runtime.statsCollector.collect();
        res.json(stats);
    });
    app.get('/api/v1/containers', async (_req, res) => {
        const list = await runtime.containerManager.listContainers();
        res.json({ containers: list });
    });
    app.get('/api/v1/containers/:name', async (req, res) => {
        try {
            const sampleCpu = String(req.query.telemetry || '') === '1';
            const info = await runtime.containerManager.inspectContainer(req.params.name, {
                sampleCpu,
            });
            res.json(info);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers', async (req, res) => {
        try {
            const info = await runtime.containerManager.createContainer(req.body);
            res.status(201).json(info);
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/action', async (req, res) => {
        try {
            const { action, force, password, sshPublicKey } = req.body || {};
            const name = req.params.name;
            switch (action) {
                case 'start':
                    await runtime.containerManager.startContainer(name);
                    break;
                case 'stop':
                    await runtime.containerManager.stopContainer(name, Boolean(force));
                    break;
                case 'restart':
                    await runtime.containerManager.restartContainer(name);
                    break;
                case 'freeze':
                    await runtime.containerManager.freezeContainer(name);
                    break;
                case 'unfreeze':
                    await runtime.containerManager.unfreezeContainer(name);
                    break;
                case 'destroy':
                    await runtime.containerManager.destroyContainer(name);
                    break;
                case 'password':
                    await runtime.containerManager.setRootPassword(name, String(password || ''));
                    break;
                case 'ssh_key':
                    await runtime.containerManager.injectSshPublicKey(name, String(sshPublicKey || ''));
                    break;
                default:
                    return res.status(400).json({ error: `Unsupported container action: ${action}` });
            }
            const updated = await runtime.containerManager.inspectContainer(name);
            return res.json({ success: true, container: updated });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    app.patch('/api/v1/containers/:name/resources', async (req, res) => {
        try {
            await runtime.containerManager.updateContainerResources(req.params.name, req.body || {});
            const info = await runtime.containerManager.inspectContainer(req.params.name);
            res.json({ success: true, container: info });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/reinstall', async (req, res) => {
        try {
            const info = await runtime.containerManager.reinstallContainer({
                ...req.body,
                containerName: req.params.name,
            });
            res.json({ success: true, container: info });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/repair-network', async (req, res) => {
        try {
            const fallbackBridge = req.body?.bridge ? String(req.body.bridge) : 'lxcbr0';
            const repair = await runtime.containerManager.repairContainerNetworking(req.params.name, fallbackBridge);
            res.json({ success: true, repair });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.get('/api/v1/containers/:name/processes', async (req, res) => {
        try {
            const processes = await runtime.containerManager.getContainerProcesses(req.params.name);
            res.json({ processes });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.get('/api/v1/containers/:name/logs', async (req, res) => {
        try {
            const logs = await runtime.containerManager.getContainerLogs(req.params.name);
            res.json({ logs });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    // Confined container file browser
    app.get('/api/v1/containers/:name/files', (req, res) => {
        try {
            const subPath = String(req.query.path || '/');
            const entries = runtime.containerManager.listRootfsDirectory(req.params.name, subPath);
            res.json({ path: subPath, entries });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    app.get('/api/v1/containers/:name/files/content', (req, res) => {
        try {
            const subPath = String(req.query.path || '/');
            const buf = runtime.containerManager.readRootfsFile(req.params.name, subPath);
            res.json({ path: subPath, contentBase64: buf.toString('base64'), size: buf.length });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/files/content', (req, res) => {
        try {
            const { path: subPath, contentBase64, content } = req.body || {};
            const data = typeof contentBase64 === 'string'
                ? Buffer.from(contentBase64, 'base64')
                : Buffer.from(String(content ?? ''), 'utf8');
            runtime.containerManager.writeRootfsFile(req.params.name, String(subPath || '/'), data);
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    app.delete('/api/v1/containers/:name/files', (req, res) => {
        try {
            const subPath = String(req.query.path || '');
            runtime.containerManager.deleteRootfsEntry(req.params.name, subPath);
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // Snapshots & Backups
    app.get('/api/v1/containers/:name/snapshots', async (req, res) => {
        try {
            const snapshots = await runtime.snapshotManager.listSnapshots(req.params.name);
            res.json({ snapshots });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/snapshots', async (req, res) => {
        try {
            const snap = await runtime.snapshotManager.createSnapshot(req.params.name, String(req.body?.comment || ''));
            res.status(201).json({ snapshot: snap });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/snapshots/:snap/restore', async (req, res) => {
        try {
            await runtime.snapshotManager.restoreSnapshot(req.params.name, req.params.snap);
            res.json({ success: true });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.delete('/api/v1/containers/:name/snapshots/:snap', async (req, res) => {
        try {
            await runtime.snapshotManager.deleteSnapshot(req.params.name, req.params.snap);
            res.json({ success: true });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/backups', async (req, res) => {
        try {
            const artifact = await runtime.snapshotManager.createTarBackup(req.params.name, req.body?.label);
            res.status(201).json({ backup: artifact });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/backups/restore', async (req, res) => {
        let tempStagedFile = null;
        try {
            const name = req.params.name;
            const { filePath, archiveBase64, expectedSha256 } = req.body || {};
            let targetBackupPath;
            if (archiveBase64) {
                const buf = Buffer.from(String(archiveBase64), 'base64');
                const tmpName = `crossnode_restore_${Date.now()}_${crypto_1.default.randomBytes(4).toString('hex')}.tar.gz`;
                targetBackupPath = runtime.snapshotManager.resolveConfinedBackupPath(path_1.default.join(runtime.snapshotManager.getBackupDir(), tmpName));
                fs_1.default.mkdirSync(path_1.default.dirname(targetBackupPath), { recursive: true });
                fs_1.default.writeFileSync(targetBackupPath, buf, { mode: 0o600 });
                tempStagedFile = targetBackupPath;
            }
            else {
                targetBackupPath = runtime.snapshotManager.resolveConfinedBackupPath(String(filePath || ''));
            }
            const before = await runtime.containerManager.inspectContainer(name);
            const wasRunning = before.state === 'running' || before.state === 'frozen';
            if (wasRunning) {
                await runtime.containerManager.stopContainer(name, false);
            }
            await runtime.snapshotManager.restoreTarBackup(targetBackupPath, expectedSha256 ? String(expectedSha256) : undefined, name);
            if (wasRunning) {
                await runtime.containerManager.startContainer(name);
            }
            const after = await runtime.containerManager.inspectContainer(name);
            res.json({ success: true, container: after });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
        finally {
            if (tempStagedFile && fs_1.default.existsSync(tempStagedFile)) {
                try {
                    fs_1.default.unlinkSync(tempStagedFile);
                }
                catch {
                    // ignore
                }
            }
        }
    });
    app.post('/api/v1/backups/download', async (req, res) => {
        try {
            const { filePath, expectedSha256 } = req.body || {};
            const confined = runtime.snapshotManager.resolveConfinedBackupPath(String(filePath || ''));
            if (!fs_1.default.existsSync(confined)) {
                return res.status(404).json({ error: 'Backup archive not found on remote node.' });
            }
            const actualSha256 = await runtime.snapshotManager.computeFileSha256(confined);
            if (expectedSha256 && String(expectedSha256).toLowerCase() !== actualSha256.toLowerCase()) {
                return res.status(409).json({
                    error: `Backup SHA-256 mismatch on source node (expected ${expectedSha256}, got ${actualSha256})`,
                });
            }
            const archiveBase64 = fs_1.default.readFileSync(confined).toString('base64');
            return res.json({ archiveBase64, checksumSha256: actualSha256 });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    app.post('/api/v1/backups/verify', async (req, res) => {
        try {
            const { filePath, expectedSha256 } = req.body || {};
            const confined = runtime.snapshotManager.resolveConfinedBackupPath(String(filePath || ''));
            if (!fs_1.default.existsSync(confined)) {
                return res.json({ valid: false, expectedSha256: expectedSha256 || null, actualSha256: null });
            }
            const actual = await runtime.snapshotManager.computeFileSha256(confined);
            const valid = !expectedSha256 || String(expectedSha256).toLowerCase() === actual.toLowerCase();
            return res.json({ valid, expectedSha256: expectedSha256 || null, actualSha256: actual });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    app.delete('/api/v1/backups/file', (req, res) => {
        try {
            const filePath = String(req.body?.filePath || req.query.filePath || '');
            const confined = runtime.snapshotManager.resolveConfinedBackupPath(filePath);
            if (fs_1.default.existsSync(confined)) {
                fs_1.default.unlinkSync(confined);
            }
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // Remote Storage Pool capacity & directory provisioning
    app.post('/api/v1/storage/statfs', (req, res) => {
        try {
            const rawPath = String(req.body?.path || '').trim();
            if (!rawPath) {
                return res.status(400).json({ error: 'Storage path is required.' });
            }
            const cleanPath = path_1.default.resolve(rawPath);
            if (req.body?.ensureDir) {
                try {
                    fs_1.default.mkdirSync(cleanPath, { recursive: true });
                }
                catch {
                    // Directory may require root or manual mount; statfs falls back to nearest ancestor
                }
            }
            const statTarget = resolveNearestExistingAncestorPath(cleanPath);
            if (!statTarget) {
                return res.status(404).json({ error: `Unable to statfs path "${cleanPath}".` });
            }
            const st = fs_1.default.statfsSync(statTarget);
            const totalBytes = Number(st.blocks) * Number(st.bsize);
            const availableBytes = Number(st.bavail) * Number(st.bsize);
            const usedBytes = Math.max(0, totalBytes - availableBytes);
            return res.json({
                exists: fs_1.default.existsSync(cleanPath),
                path: cleanPath,
                statTarget,
                totalBytes,
                availableBytes,
                usedBytes,
            });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    // Remote Custom LXC Template Archive cache & SHA-256 verified staging
    app.get('/api/v1/templates/status', async (req, res) => {
        try {
            const safeName = path_1.default.basename(String(req.query.name || '').trim()).replace(/[^a-zA-Z0-9._-]+/g, '_');
            const expectedSha256 = String(req.query.sha256 || '').trim().toLowerCase();
            if (!safeName) {
                return res.status(400).json({ error: 'Template filename is required.' });
            }
            const targetFile = path_1.default.join(templateCacheDir, safeName);
            if (!fs_1.default.existsSync(targetFile)) {
                return res.json({ cached: false, filePath: targetFile, sha256: null });
            }
            const actualSha = await runtime.snapshotManager.computeFileSha256(targetFile);
            const cached = !expectedSha256 || actualSha.toLowerCase() === expectedSha256;
            return res.json({ cached, filePath: targetFile, sha256: actualSha });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/templates/stage', async (req, res) => {
        try {
            const safeName = path_1.default.basename(String(req.body?.name || '').trim()).replace(/[^a-zA-Z0-9._-]+/g, '_');
            const archiveBase64 = String(req.body?.archiveBase64 || '');
            const expectedSha256 = String(req.body?.expectedSha256 || '').trim().toLowerCase();
            if (!safeName || !archiveBase64) {
                return res.status(400).json({ error: 'Template name and archiveBase64 are required.' });
            }
            fs_1.default.mkdirSync(templateCacheDir, { recursive: true });
            const buf = Buffer.from(archiveBase64, 'base64');
            const actualSha = crypto_1.default.createHash('sha256').update(buf).digest('hex');
            if (expectedSha256 && actualSha.toLowerCase() !== expectedSha256) {
                return res.status(409).json({
                    error: `Template archive SHA-256 mismatch (expected ${expectedSha256}, got ${actualSha})`,
                });
            }
            const targetFile = path_1.default.join(templateCacheDir, safeName);
            fs_1.default.writeFileSync(targetFile, buf, { mode: 0o644 });
            return res.status(201).json({
                staged: true,
                filePath: targetFile,
                sizeBytes: buf.length,
                sha256: actualSha,
            });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    // Remote NAT Port Forwarding (iptables DNAT with automatic rollback)
    app.post('/api/v1/network/port-forwards', async (req, res) => {
        try {
            const mode = req.body?.mode === 'remove' ? 'remove' : 'add';
            const guestIp = middleware_1.SafeValidators.ipv4(req.body?.guestIp);
            const guestPort = middleware_1.SafeValidators.portNumber(req.body?.guestPort, 1, 65535);
            const hostPort = middleware_1.SafeValidators.portNumber(req.body?.hostPort, 1, 65535);
            const protocol = String(req.body?.protocol || 'tcp,udp');
            if (!(0, command_runner_1.isBinaryAvailable)('iptables')) {
                return res.json({ applied: false, reason: 'iptables binary not installed on remote node' });
            }
            const saveRes = await (0, command_runner_1.runAllowlistedCommand)('iptables-save', [], {
                asRoot: true,
                timeoutMs: 5000,
            });
            const previousState = saveRes.exitCode === 0 ? saveRes.stdout : null;
            const protos = protocol.includes(',') ? ['tcp', 'udp'] : [protocol];
            const flag = mode === 'add' ? '-A' : '-D';
            try {
                for (const proto of protos) {
                    if (proto !== 'tcp' && proto !== 'udp')
                        continue;
                    const dnatRes = await (0, command_runner_1.runAllowlistedCommand)('iptables', [
                        '-t',
                        'nat',
                        flag,
                        'PREROUTING',
                        '-p',
                        proto,
                        '--dport',
                        String(hostPort),
                        '-j',
                        'DNAT',
                        '--to-destination',
                        `${guestIp}:${guestPort}`,
                    ], { asRoot: true, timeoutMs: 5000 });
                    if (dnatRes.exitCode !== 0 && mode === 'add') {
                        if (dnatRes.stderr.includes('Permission denied') ||
                            dnatRes.stderr.includes("can't initialize iptables") ||
                            dnatRes.stderr.includes('Operation not permitted')) {
                            return res.json({ applied: false, reason: 'CAP_NET_ADMIN unavailable on remote node' });
                        }
                        throw new Error(dnatRes.stderr || 'Remote iptables DNAT command failed');
                    }
                }
                return res.json({ applied: true });
            }
            catch (err) {
                if (previousState && (0, command_runner_1.isBinaryAvailable)('iptables-restore')) {
                    await (0, command_runner_1.runAllowlistedCommand)('iptables-restore', [], {
                        asRoot: true,
                        stdinData: previousState,
                        timeoutMs: 5000,
                    });
                }
                throw err;
            }
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    // Remote Host Firewall Rule enforcement (iptables INPUT/OUTPUT)
    app.post('/api/v1/network/firewall', async (req, res) => {
        try {
            const mode = req.body?.mode === 'remove' ? 'remove' : 'add';
            const direction = req.body?.direction === 'out' ? 'OUTPUT' : 'INPUT';
            const action = String(req.body?.action || 'ACCEPT').toUpperCase();
            const protocol = String(req.body?.protocol || 'tcp').toLowerCase();
            const sourceCidr = req.body?.sourceCidr ? String(req.body.sourceCidr).trim() : '';
            const destPort = req.body?.destPort ? String(req.body.destPort).trim() : '';
            if (!['ACCEPT', 'DROP', 'REJECT'].includes(action)) {
                return res.status(400).json({ error: 'Invalid firewall action.' });
            }
            if (!['tcp', 'udp', 'icmp', 'all'].includes(protocol)) {
                return res.status(400).json({ error: 'Invalid firewall protocol.' });
            }
            if (destPort && !/^\d{1,5}(:\d{1,5})?$/.test(destPort)) {
                return res.status(400).json({ error: 'Invalid destination port or range.' });
            }
            if (sourceCidr && !/^[0-9a-fA-F.:/]+$/.test(sourceCidr)) {
                return res.status(400).json({ error: 'Invalid source CIDR.' });
            }
            if (!(0, command_runner_1.isBinaryAvailable)('iptables')) {
                return res.json({ applied: false });
            }
            const args = [mode === 'add' ? '-A' : '-D', direction];
            if (protocol !== 'all') {
                args.push('-p', protocol);
            }
            if (sourceCidr) {
                args.push(direction === 'OUTPUT' ? '-d' : '-s', sourceCidr);
            }
            if (destPort && (protocol === 'tcp' || protocol === 'udp')) {
                args.push('--dport', destPort);
            }
            args.push('-j', action);
            const fwRes = await (0, command_runner_1.runAllowlistedCommand)('iptables', args, {
                asRoot: true,
                timeoutMs: 5000,
            });
            if (fwRes.exitCode !== 0) {
                return res.json({ applied: false });
            }
            return res.json({ applied: true });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    // Offline migration export/import endpoints
    app.post('/api/v1/transfers/export', async (req, res) => {
        try {
            const bundle = await runtime.transferManager.prepareOfflineExport(String(req.body?.containerName || ''));
            const dataBase64 = fs_1.default.readFileSync(bundle.archivePath).toString('base64');
            res.json({ ...bundle, archiveBase64: dataBase64 });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/transfers/import', async (req, res) => {
        try {
            const { containerName, archiveBase64, expectedChecksumSha256, targetBridge, targetIpv4, targetGateway, startAfterImport, } = req.body || {};
            const buf = Buffer.from(String(archiveBase64 || ''), 'base64');
            const result = await runtime.transferManager.importAndVerifyBundle({
                containerName,
                archiveBufferOrPath: buf,
                expectedChecksumSha256,
                targetBridge,
                targetIpv4,
                targetGateway,
                startAfterImport,
            });
            res.json(result);
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/diagnostics/:preset', async (req, res) => {
        try {
            const out = await runtime.shellManager.runDiagnosticPreset(req.params.preset, 'controller');
            res.json(out);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // Credential rotation
    app.post('/api/v1/credentials/rotate', (req, res) => {
        const { newApiKey, newHmacSecret } = req.body || {};
        if (!newApiKey || !newHmacSecret) {
            return res.status(400).json({ error: 'newApiKey and newHmacSecret are required' });
        }
        authenticator.rotateCredentials(String(newApiKey), String(newHmacSecret));
        return res.json({ success: true, rotatedAt: new Date().toISOString() });
    });
    // Build HTTP or HTTPS server (with optional mTLS)
    let server;
    if (tlsActive) {
        const httpsOpts = {
            cert: fs_1.default.readFileSync(certPath),
            key: fs_1.default.readFileSync(keyPath),
        };
        if (caPath && fs_1.default.existsSync(caPath)) {
            httpsOpts.ca = fs_1.default.readFileSync(caPath);
            httpsOpts.requestCert = true;
            httpsOpts.rejectUnauthorized = Boolean(opts.requireMtls);
        }
        server = https_1.default.createServer(httpsOpts, app);
    }
    else {
        server = http_1.default.createServer(app);
    }
    // Optional active outbound push-heartbeat to TGVPANEL Controller
    const controllerUrl = (0, authentication_1.sanitizeAgentEnvValue)(opts.controllerUrl ||
        process.env.TGVPANEL_CONTROLLER_URL ||
        process.env.HKVM_CONTROLLER_URL).replace(/\/+$/, '');
    const controllerVerifySsl = opts.controllerVerifySsl ??
        (0, authentication_1.sanitizeAgentEnvValue)(process.env.TGVPANEL_CONTROLLER_VERIFY_SSL) === 'true';
    const sendHeartbeatOnce = async () => {
        if (!controllerUrl)
            return false;
        const creds = authenticator.getOutboundSigningCredentials();
        if (!creds)
            return false;
        try {
            const [health, stats] = await Promise.all([
                (0, health_1.getNodeHealthReport)(false, {
                    interactiveShellEnabled: runtime.shellManager.isInteractiveShellEnabled(),
                }),
                runtime.statsCollector.collect(),
            ]);
            const hbPath = '/api/v1/nodes/agent-heartbeat';
            const rawBody = JSON.stringify({ nodeId: creds.nodeId, health, stats });
            const signed = (0, crypto_vault_1.signAgentRequest)({
                nodeId: creds.nodeId,
                apiKey: creds.apiKey,
                hmacSecret: creds.hmacSecret,
                method: 'POST',
                pathWithQuery: hbPath,
                bodyBuffer: rawBody,
            });
            const base = controllerUrl.endsWith('/') ? controllerUrl : `${controllerUrl}/`;
            const targetUrl = new URL(hbPath.replace(/^\/+/, ''), base);
            const isHttps = targetUrl.protocol === 'https:';
            const transport = isHttps ? https_1.default : http_1.default;
            return await new Promise((resolve) => {
                const req = transport.request({
                    method: 'POST',
                    hostname: targetUrl.hostname,
                    port: targetUrl.port || (isHttps ? 443 : 80),
                    path: targetUrl.pathname + targetUrl.search,
                    timeout: 8000,
                    rejectUnauthorized: controllerVerifySsl,
                    headers: {
                        Accept: 'application/json',
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(rawBody),
                        'X-HKVM-Node-Key': creds.apiKey,
                        ...signed,
                    },
                }, (res) => {
                    res.resume();
                    res.on('end', () => resolve((res.statusCode || 500) >= 200 && (res.statusCode || 500) < 300));
                });
                req.on('timeout', () => {
                    req.destroy();
                    resolve(false);
                });
                req.on('error', () => resolve(false));
                req.write(rawBody);
                req.end();
            });
        }
        catch {
            return false;
        }
    };
    let heartbeatTimer = null;
    if (controllerUrl) {
        const hbInterval = Math.max(5000, Number(opts.heartbeatIntervalMs || 45_000));
        server.on('listening', () => {
            sendHeartbeatOnce().catch(() => undefined);
            if (!heartbeatTimer) {
                heartbeatTimer = setInterval(() => {
                    sendHeartbeatOnce().catch(() => undefined);
                }, hbInterval);
                if (typeof heartbeatTimer.unref === 'function')
                    heartbeatTimer.unref();
            }
        });
        server.on('close', () => {
            if (heartbeatTimer) {
                clearInterval(heartbeatTimer);
                heartbeatTimer = null;
            }
        });
    }
    const wss = new ws_1.WebSocketServer({ noServer: true });
    server.on('upgrade', (req, socket, head) => {
        const authRes = authenticator.verifyWebSocketUpgrade(req);
        if (!authRes.ok) {
            const errBody = JSON.stringify({ error: authRes.reason || 'Unauthorized WebSocket upgrade' });
            socket.write(`HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(errBody)}\r\nConnection: close\r\n\r\n${errBody}`);
            socket.destroy();
            return;
        }
        const urlObj = new URL(req.url || '/', 'http://localhost');
        const pathname = (() => {
            const wsIdx = urlObj.pathname.indexOf('/ws/');
            return wsIdx > 0 ? urlObj.pathname.slice(wsIdx) : urlObj.pathname;
        })();
        const consoleMatch = pathname.match(/^\/ws\/containers\/([^/]+)\/console$/);
        if (consoleMatch) {
            wss.handleUpgrade(req, socket, head, (ws) => {
                try {
                    runtime.consoleManager.attachWebSocket(ws, decodeURIComponent(consoleMatch[1]), {
                        cols: Number(urlObj.searchParams.get('cols') || 100),
                        rows: Number(urlObj.searchParams.get('rows') || 30),
                    });
                }
                catch {
                    // handled inside attachWebSocket
                }
            });
            return;
        }
        if (pathname === '/ws/host/shell') {
            wss.handleUpgrade(req, socket, head, (ws) => {
                runtime.shellManager.attachInteractiveHostPty(ws, 'controller-admin', {
                    cols: Number(urlObj.searchParams.get('cols') || 100),
                    rows: Number(urlObj.searchParams.get('rows') || 30),
                });
            });
            return;
        }
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
        socket.destroy();
    });
    return { app, server, runtime, authenticator, host, port, tlsActive, sendHeartbeatOnce };
}
if (require.main === module) {
    const instance = createNodeAgentServer();
    instance.server.listen(instance.port, instance.host, () => {
        console.log(`[TGVPANEL Node Agent v${health_1.AGENT_VERSION}] Listening on ${instance.tlsActive ? 'https' : 'http'}://${instance.host}:${instance.port}`);
    });
}
