"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeManager = void 0;
exports.isDomainHostname = isDomainHostname;
exports.normalizeNodeEndpointUrl = normalizeNodeEndpointUrl;
exports.buildAgentTargetUrl = buildAgentTargetUrl;
const crypto_1 = __importDefault(require("crypto"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const net_1 = __importDefault(require("net"));
const tls_1 = __importDefault(require("tls"));
const ws_1 = __importDefault(require("ws"));
const crypto_vault_1 = require("../../security/crypto-vault");
const agent_1 = require("../../node-agent/agent");
const health_1 = require("../../node-agent/health");
function derToPemCertificate(rawDer) {
    const b64 = rawDer.toString('base64');
    const lines = b64.match(/.{1,64}/g) || [b64];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}
function extractPemSha256Fingerprints(pemText) {
    const set = new Set();
    const matches = pemText.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
    for (const block of matches) {
        const b64 = block
            .replace(/-----BEGIN CERTIFICATE-----/g, '')
            .replace(/-----END CERTIFICATE-----/g, '')
            .replace(/\s+/g, '');
        if (!b64)
            continue;
        const der = Buffer.from(b64, 'base64');
        if (der.length > 0) {
            set.add(crypto_1.default.createHash('sha256').update(der).digest('hex'));
        }
    }
    return set;
}
function stripIpv6Brackets(host) {
    return String(host || '').trim().replace(/^\[|\]$/g, '');
}
function isDomainHostname(host) {
    const clean = stripIpv6Brackets(host).toLowerCase();
    if (!clean || clean === 'localhost')
        return false;
    return net_1.default.isIP(clean) === 0;
}
function normalizeNodeEndpointUrl(rawUrl) {
    let clean = String(rawUrl || '').trim();
    if (!clean)
        throw new Error('Agent endpoint URL is required.');
    if (!/^https?:\/\//i.test(clean)) {
        const hostPortPart = clean.split('/')[0] || '';
        const hasExplicitHttpPort = /:5055$|:80$|:8080$/i.test(hostPortPart);
        const hasExplicitHttpsPort = /:8443$|:443$/i.test(hostPortPart);
        const bareHost = hostPortPart.replace(/:\d+$/, '');
        const defaultHttps = hasExplicitHttpsPort || (!hasExplicitHttpPort && isDomainHostname(bareHost));
        clean = `${defaultHttps ? 'https' : 'http'}://${clean}`;
    }
    let parsed;
    try {
        parsed = new URL(clean);
    }
    catch {
        throw new Error('Invalid URL format. Expected https://node.example.com, https://host:8443, or http://host:5055');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('Only http:// and https:// agent endpoints are supported.');
    }
    // Strip accidental API suffixes if user pasted /api/v1/health into Node URL
    let pathname = parsed.pathname || '';
    const apiIdx = pathname.indexOf('/api/v1');
    if (apiIdx >= 0)
        pathname = pathname.slice(0, apiIdx);
    const wsIdx = pathname.indexOf('/ws/');
    if (wsIdx >= 0)
        pathname = pathname.slice(0, wsIdx);
    pathname = pathname.replace(/\/+$/, '');
    return `${parsed.origin}${pathname}`;
}
function buildAgentTargetUrl(baseNodeUrl, apiPathWithQuery) {
    const normalizedBase = normalizeNodeEndpointUrl(baseNodeUrl);
    const baseWithSlash = normalizedBase.endsWith('/') ? normalizedBase : `${normalizedBase}/`;
    const relativePath = String(apiPathWithQuery || '/').replace(/^\/+/, '');
    return new URL(relativePath, baseWithSlash);
}
function formatTransportError(err, targetUrl, verifySsl) {
    const code = String(err?.code || '');
    const msg = String(err?.message || 'Connection failed');
    if (code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
        code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
        code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
        /self[- ]signed certificate/i.test(msg)) {
        return `TLS self-signed certificate rejected (${code || 'SELF_SIGNED'}). Click "Trust Node TLS Cert" to pin the node certificate or uncheck Strict CA Verify.`;
    }
    if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
        return `TLS certificate hostname/IP mismatch (${code}). Click "Trust Node TLS Cert" to pin this node's certificate or uncheck Strict CA Verify.`;
    }
    if (code === 'EPROTO' || /wrong version number|unknown protocol/i.test(msg)) {
        const usingHttps = targetUrl.startsWith('https://');
        return usingHttps
            ? `TLS handshake failed (EPROTO): remote Node Agent appears to be serving plain HTTP while Panel URL uses https://. Enable TLS on the node or switch URL to http://.`
            : `Protocol mismatch: remote Node Agent requires https://.`;
    }
    if (code === 'ECONNREFUSED') {
        return `Connection refused at ${targetUrl} (ECONNREFUSED). Ensure tgvpanel-node-agent is running and listening on 0.0.0.0 with port open in firewall.`;
    }
    if (code === 'ETIMEDOUT' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH' || /timed out/i.test(msg)) {
        return `Connection timed out reaching ${targetUrl}${code ? ` (${code})` : ''}. Check cloud security group / UFW port (default TCP 8443) and node IP.`;
    }
    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
        return `DNS lookup failed for ${targetUrl} (${code}). Verify hostname or use the node's direct IPv4 address.`;
    }
    if (verifySsl && /certificate/i.test(msg)) {
        return `TLS certificate error: ${msg}. Click "Trust Node TLS Cert" or uncheck Strict CA Verify.`;
    }
    return code && !msg.includes(code) ? `${msg} (${code})` : msg;
}
/**
 * Communicates with remote Node Agents over HTTPS/HTTP using replay-protected HMAC-SHA256 signatures,
 * optional TOFU certificate pinning / mTLS, active push-heartbeats, single-use join tokens,
 * and per-node circuit breakers, while routing `is_local = 1` requests directly to `LocalNodeRuntime`.
 */
class NodeManager {
    db;
    localRuntime;
    circuits = new Map();
    latencies = new Map();
    seenAgentHeartbeatNonces = new Map();
    failureThreshold = 3;
    openCooldownMs = 30_000;
    constructor(db, localRuntime) {
        this.db = db;
        this.localRuntime =
            localRuntime ||
                new agent_1.LocalNodeRuntime({
                    onAuditEvent: (evt) => {
                        this.db
                            .logActivity({
                            action: evt.action,
                            resourceType: 'node_shell',
                            resourceId: 'localhost',
                            details: { actor: evt.actor, ...evt.details },
                        })
                            .catch(() => undefined);
                    },
                });
    }
    normalizeTagsJson(raw) {
        if (!raw)
            return '[]';
        const items = Array.isArray(raw)
            ? raw
            : (() => {
                const str = String(raw).trim();
                if (str.startsWith('[')) {
                    try {
                        const parsed = JSON.parse(str);
                        if (Array.isArray(parsed))
                            return parsed;
                    }
                    catch {
                        // treat as comma-separated
                    }
                }
                return str.split(',');
            })();
        const cleaned = Array.from(new Set(items
            .map((t) => String(t || '').trim().toLowerCase().replace(/[^a-z0-9._:-]+/g, '-'))
            .filter((t) => t.length > 0))).slice(0, 16);
        return JSON.stringify(cleaned);
    }
    enrichNodeRow(r) {
        const kvmCount = Number(r.kvm_count || 0);
        const lxcCount = Number(r.lxc_count || 0);
        const kvmRunning = Number(r.kvm_running || 0);
        const lxcRunning = Number(r.lxc_running || 0);
        return {
            ...r,
            tls_pinned: Number(r.tls_pinned || 0),
            kvm_count: kvmCount,
            kvm_running: kvmRunning,
            lxc_count: lxcCount,
            lxc_running: lxcRunning,
            total_instances: kvmCount + lxcCount,
            running_instances: kvmRunning + lxcRunning,
            allocated_vcpus: Number(r.allocated_vcpus || 0),
            allocated_ram_mb: Number(r.allocated_ram_mb || 0),
            allocated_disk_gb: Number(Number(r.allocated_disk_gb || 0).toFixed(1)),
            latency_ms: this.latencies.get(r.id) ?? (r.is_local ? 1 : null),
        };
    }
    nodeSelectSql = `
    SELECT n.*,
           CASE WHEN nc.tls_ca_pem IS NOT NULL AND LENGTH(nc.tls_ca_pem) > 0 THEN 1 ELSE 0 END AS tls_pinned,
           c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available,
           c.nested_virt, c.cgroup_version, c.qemu_version, c.lxc_version,
           c.kernel_version, c.storage_backends, c.network_backends,
           COALESCE(vk.kvm_count, 0) AS kvm_count,
           COALESCE(vk.kvm_running, 0) AS kvm_running,
           COALESCE(lx.lxc_count, 0) AS lxc_count,
           COALESCE(lx.lxc_running, 0) AS lxc_running,
           COALESCE(vk.kvm_cpus, 0) + COALESCE(lx.lxc_cpus, 0) AS allocated_vcpus,
           COALESCE(vk.kvm_ram, 0) + COALESCE(lx.lxc_ram, 0) AS allocated_ram_mb,
           COALESCE(vk.kvm_disk, 0) + COALESCE(lx.lxc_disk, 0) AS allocated_disk_gb,
           mh.cpu_percent AS live_cpu_percent,
           mh.ram_used_mb AS live_ram_used_mb,
           mh.disk_used_gb AS live_disk_used_gb,
           mh.load_avg_1 AS live_load_1
    FROM nodes n
    LEFT JOIN node_credentials nc ON nc.node_id = n.id
    LEFT JOIN node_capabilities c ON c.node_id = n.id
    LEFT JOIN (
      SELECT COALESCE(node_id, 1) AS nid,
             COUNT(*) AS kvm_count,
             SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS kvm_running,
             SUM(COALESCE(cpus, cpu_cores, 1)) AS kvm_cpus,
             SUM(COALESCE(memory, 0)) AS kvm_ram,
             SUM(CAST(REPLACE(REPLACE(COALESCE(disk_size, '0'), 'G', ''), 'g', '') AS REAL)) AS kvm_disk
      FROM vms
      GROUP BY COALESCE(node_id, 1)
    ) vk ON vk.nid = n.id
    LEFT JOIN (
      SELECT COALESCE(node_id, 1) AS nid,
             COUNT(*) AS lxc_count,
             SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS lxc_running,
             SUM(COALESCE(cpu_cores, 1)) AS lxc_cpus,
             SUM(COALESCE(ram_mb, 0)) AS lxc_ram,
             SUM(COALESCE(disk_gb, 0)) AS lxc_disk
      FROM lxc_instances
      GROUP BY COALESCE(node_id, 1)
    ) lx ON lx.nid = n.id
    LEFT JOIN metrics_history mh ON mh.id = (
      SELECT m2.id FROM metrics_history m2
      WHERE m2.target_type = 'node' AND m2.target_id = n.id
      ORDER BY m2.id DESC LIMIT 1
    )
  `;
    async listNodes() {
        const rows = await this.db.all(`${this.nodeSelectSql} ORDER BY n.is_local DESC, n.id ASC`);
        return rows.map((r) => this.enrichNodeRow(r));
    }
    async getNodeById(nodeId) {
        const row = await this.db.get(`${this.nodeSelectSql} WHERE n.id = ?`, [nodeId]);
        return row ? this.enrichNodeRow(row) : undefined;
    }
    async getDefaultNodeForEngine(engine) {
        const capCol = engine === 'kvm' ? 'supports_kvm' : 'supports_lxc';
        const preferred = await this.db.get(`SELECT n.*, c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available
       FROM nodes n
       LEFT JOIN node_capabilities c ON c.node_id = n.id
       WHERE n.maintenance_mode = 0 AND COALESCE(c.${capCol}, 1) = 1
       ORDER BY CASE WHEN n.status = 'online' THEN 0 ELSE 1 END, n.is_local DESC, n.id ASC
       LIMIT 1`);
        if (preferred)
            return preferred;
        const fallback = await this.db.get(`SELECT * FROM nodes ORDER BY is_local DESC, id ASC LIMIT 1`);
        if (!fallback) {
            throw new Error('No nodes registered in TGVPANEL database.');
        }
        return fallback;
    }
    async createNode(input) {
        const cleanName = String(input.name || '').trim();
        if (!cleanName) {
            throw new Error('Node name is required.');
        }
        const cleanUrl = normalizeNodeEndpointUrl(input.url);
        const endpointHost = stripIpv6Brackets(new URL(cleanUrl).hostname);
        const cleanHostname = String(input.hostname || '').trim() || endpointHost;
        // Allow Cloudflare Tunnel / Reverse Proxy / IPv6-only nodes with no public IPv4 IP
        const cleanIpAddress = String(input.ipAddress || '').trim() || endpointHost;
        const keyPair = (0, crypto_vault_1.generateApiKeyPair)('tgv_node');
        const hmacSecret = crypto_1.default.randomBytes(32).toString('hex');
        const tagsJson = this.normalizeTagsJson(input.tags);
        const cleanCaPem = input.tlsCaPem?.trim() || null;
        let createdId = 0;
        await this.db.transaction(async () => {
            const ins = await this.db.run(`INSERT INTO nodes
         (name, hostname, ip_address, location, url, is_local, verify_ssl, mtls_enabled, status, max_instances, tags, notes)
         VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'provisioning', ?, ?, ?)`, [
                cleanName,
                cleanHostname,
                cleanIpAddress,
                input.location?.trim() || 'Remote Datacenter',
                cleanUrl,
                input.verifySsl !== false ? 1 : 0,
                input.mtlsEnabled ? 1 : 0,
                Math.max(1, Number(input.maxInstances || 100)),
                tagsJson,
                input.notes || null,
            ]);
            createdId = ins.lastID;
            await this.db.run(`INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc, tls_ca_pem)
         VALUES (?, ?, ?, ?, ?, ?)`, [
                createdId,
                keyPair.keyPrefix,
                keyPair.keyHash,
                (0, crypto_vault_1.encryptSecret)(keyPair.rawKey),
                (0, crypto_vault_1.encryptSecret)(hmacSecret),
                cleanCaPem,
            ]);
            await this.db.run(`INSERT INTO node_capabilities (node_id, supports_kvm, supports_lxc)
         VALUES (?, ?, ?)`, [
                createdId,
                input.supportsKvm !== false ? 1 : 0,
                input.supportsLxc !== false ? 1 : 0,
            ]);
        });
        const node = (await this.getNodeById(createdId));
        return {
            node,
            bootstrapCredentials: {
                apiKey: keyPair.rawKey,
                hmacSecret,
            },
        };
    }
    async updateNode(nodeId, patch) {
        const existing = await this.getNodeById(nodeId);
        if (!existing)
            throw new Error(`Node #${nodeId} not found.`);
        const tagsVal = patch.tags !== undefined ? this.normalizeTagsJson(patch.tags) : null;
        const normalizedUrl = patch.url !== undefined && !existing.is_local
            ? normalizeNodeEndpointUrl(patch.url)
            : patch.url?.trim().replace(/\/+$/, '') ?? null;
        await this.db.run(`UPDATE nodes SET
         name = COALESCE(?, name),
         hostname = COALESCE(?, hostname),
         ip_address = COALESCE(?, ip_address),
         location = COALESCE(?, location),
         url = COALESCE(?, url),
         maintenance_mode = COALESCE(?, maintenance_mode),
         verify_ssl = COALESCE(?, verify_ssl),
         max_instances = COALESCE(?, max_instances),
         tags = COALESCE(?, tags),
         notes = COALESCE(?, notes),
         updated_at = datetime('now')
       WHERE id = ?`, [
            patch.name?.trim() ?? null,
            patch.hostname?.trim() ?? null,
            patch.ipAddress?.trim() ?? null,
            patch.location?.trim() ?? null,
            normalizedUrl,
            patch.maintenanceMode !== undefined ? (patch.maintenanceMode ? 1 : 0) : null,
            patch.verifySsl !== undefined ? (patch.verifySsl ? 1 : 0) : null,
            patch.maxInstances !== undefined ? Math.max(1, Number(patch.maxInstances)) : null,
            tagsVal,
            patch.notes !== undefined ? patch.notes : null,
            nodeId,
        ]);
        if (patch.tlsCaPem !== undefined) {
            await this.db.run(`UPDATE node_credentials SET tls_ca_pem = ? WHERE node_id = ?`, [patch.tlsCaPem ? patch.tlsCaPem.trim() : null, nodeId]);
        }
        if (patch.supportsKvm !== undefined || patch.supportsLxc !== undefined) {
            await this.db.run(`UPDATE node_capabilities SET
           supports_kvm = COALESCE(?, supports_kvm),
           supports_lxc = COALESCE(?, supports_lxc),
           updated_at = datetime('now')
         WHERE node_id = ?`, [
                patch.supportsKvm !== undefined ? (patch.supportsKvm ? 1 : 0) : null,
                patch.supportsLxc !== undefined ? (patch.supportsLxc ? 1 : 0) : null,
                nodeId,
            ]);
        }
        // Automatically reset open circuit breaker when connection settings change
        if (patch.url !== undefined ||
            patch.ipAddress !== undefined ||
            patch.hostname !== undefined ||
            patch.verifySsl !== undefined ||
            patch.tlsCaPem !== undefined) {
            this.circuits.set(nodeId, { state: 'closed', failures: 0, openedAt: 0 });
            await this.db.run(`UPDATE nodes SET circuit_state = 'closed', consecutive_failures = 0 WHERE id = ?`, [nodeId]);
        }
        return (await this.getNodeById(nodeId));
    }
    async deleteNode(nodeId) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        if (node.is_local) {
            throw new Error('Cannot delete the built-in localhost controller node.');
        }
        const activeCount = await this.db.get(`SELECT COUNT(*) AS cnt FROM instances WHERE node_id = ?`, [nodeId]);
        if ((activeCount?.cnt || 0) > 0) {
            throw new Error(`Cannot remove node "${node.name}" while ${activeCount?.cnt} instance(s) are still assigned to it.`);
        }
        this.circuits.delete(nodeId);
        this.latencies.delete(nodeId);
        await this.db.run(`DELETE FROM nodes WHERE id = ?`, [nodeId]);
    }
    buildEnvSnippet(params) {
        const lines = [
            `# TGVPANEL Remote Node Bootstrap (.env — chmod 600 /opt/tgvpanel/.env)`,
            `TGVPANEL_NODE_ID=${params.nodeId}`,
            `TGVPANEL_AGENT_HOST=0.0.0.0`,
            `TGVPANEL_AGENT_PORT=${params.port}`,
            `TGVPANEL_NODE_API_KEY=${params.apiKey}`,
            `TGVPANEL_NODE_HMAC_SECRET=${params.hmacSecret}`,
        ];
        if (params.controllerUrl) {
            lines.push(`TGVPANEL_CONTROLLER_URL=${params.controllerUrl.replace(/\/+$/, '')}`);
        }
        if (params.isHttps) {
            lines.push(`TGVPANEL_AGENT_TLS_CERT=/etc/tgvpanel/ssl/agent.crt`);
            lines.push(`TGVPANEL_AGENT_TLS_KEY=/etc/tgvpanel/ssl/agent.key`);
        }
        return lines.join('\n');
    }
    async getBootstrapCredentials(nodeId, controllerUrl) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        if (node.is_local) {
            throw new Error('Localhost controller node uses in-process runtime and does not require remote .env bootstrap.');
        }
        const creds = await this.db.get(`SELECT api_key_enc, hmac_secret_enc FROM node_credentials WHERE node_id = ?`, [nodeId]);
        if (!creds)
            throw new Error(`Credentials missing for node #${nodeId}.`);
        const apiKey = (0, crypto_vault_1.decryptSecret)(creds.api_key_enc);
        const hmacSecret = (0, crypto_vault_1.decryptSecret)(creds.hmac_secret_enc);
        if (!apiKey || !hmacSecret) {
            throw new Error(`Unable to decrypt stored credentials for node #${nodeId}; rotate credentials to issue a new pair.`);
        }
        let port = 8443;
        let isHttps = true;
        try {
            const u = new URL(node.url);
            isHttps = u.protocol === 'https:';
            port = Number(u.port || (isHttps ? 443 : 80));
        }
        catch {
            // default 8443
        }
        return {
            nodeId: node.id,
            nodeName: node.name,
            url: node.url,
            port,
            isHttps,
            apiKey,
            hmacSecret,
            envSnippet: this.buildEnvSnippet({
                nodeId: node.id,
                port,
                apiKey,
                hmacSecret,
                controllerUrl,
                isHttps,
            }),
        };
    }
    async createJoinToken(params) {
        const node = await this.getNodeById(params.nodeId);
        if (!node)
            throw new Error(`Node #${params.nodeId} not found.`);
        if (node.is_local) {
            throw new Error('Cannot generate a remote join token for the localhost node.');
        }
        const cleanControllerUrl = String(params.controllerUrl || '').trim().replace(/\/+$/, '');
        if (!/^https?:\/\//i.test(cleanControllerUrl)) {
            throw new Error('Valid Controller URL (http:// or https://) is required to build the join command.');
        }
        const ttlMinutes = Math.min(1440, Math.max(5, Number(params.ttlMinutes || 30)));
        const rawToken = `tgv_join_${crypto_1.default.randomBytes(24).toString('hex')}`;
        const tokenPrefix = rawToken.slice(0, 14);
        const tokenHash = (0, crypto_vault_1.hashApiKey)(rawToken);
        const expiresAt = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
        await this.db.run(`INSERT INTO node_join_tokens (node_id, token_prefix, token_hash, controller_url, expires_at, created_by)
       VALUES (?, ?, ?, ?, ?, ?)`, [node.id, tokenPrefix, tokenHash, cleanControllerUrl, expiresAt, params.createdByUserId || null]);
        const safeCtrl = cleanControllerUrl.replace(/"/g, '');
        let advertisePrefix = '';
        try {
            const nodeUrlHost = stripIpv6Brackets(new URL(node.url).hostname);
            if (isDomainHostname(nodeUrlHost)) {
                const safeNodeUrl = node.url.replace(/"/g, '');
                advertisePrefix = `TGVPANEL_ADVERTISE_URL="${safeNodeUrl}" `;
            }
        }
        catch {
            // Ignore malformed legacy URL
        }
        const curlJoinCommand = `curl -fsSL https://raw.githubusercontent.com/ShadowGamerIND37/TGVPANEL/main/menu.sh -o menu.sh && chmod +x menu.sh && sudo ${advertisePrefix}bash menu.sh --join "${safeCtrl}" "${rawToken}"`;
        const localJoinCommand = `sudo ${advertisePrefix}bash menu.sh --join "${safeCtrl}" "${rawToken}"`;
        return {
            nodeId: node.id,
            nodeName: node.name,
            token: rawToken,
            expiresAt,
            ttlMinutes,
            controllerUrl: cleanControllerUrl,
            curlJoinCommand,
            localJoinCommand,
        };
    }
    async redeemJoinToken(params) {
        const cleanToken = String(params.rawToken || '').trim();
        if (!cleanToken.startsWith('tgv_join_')) {
            throw new Error('Invalid node join token format.');
        }
        const tokenHash = (0, crypto_vault_1.hashApiKey)(cleanToken);
        const row = await this.db.get(`SELECT * FROM node_join_tokens WHERE token_hash = ?`, [tokenHash]);
        if (!row) {
            throw new Error('Join token is invalid or unknown.');
        }
        if (row.used_at) {
            throw new Error('This single-use join token has already been redeemed. Generate a new join token in the Panel.');
        }
        if (new Date(row.expires_at).getTime() <= Date.now()) {
            throw new Error('Join token has expired. Generate a fresh join token in the Panel.');
        }
        const node = await this.getNodeById(row.node_id);
        if (!node || node.is_local) {
            throw new Error('Target remote node no longer exists.');
        }
        const creds = await this.db.get(`SELECT api_key_enc, hmac_secret_enc FROM node_credentials WHERE node_id = ?`, [node.id]);
        if (!creds)
            throw new Error('Node credentials record missing.');
        let apiKey = (0, crypto_vault_1.decryptSecret)(creds.api_key_enc);
        let hmacSecret = (0, crypto_vault_1.decryptSecret)(creds.hmac_secret_enc);
        if (!apiKey || !hmacSecret) {
            const freshPair = (0, crypto_vault_1.generateApiKeyPair)('tgv_node');
            apiKey = freshPair.rawKey;
            hmacSecret = crypto_1.default.randomBytes(32).toString('hex');
            await this.db.run(`UPDATE node_credentials
         SET api_key_prefix = ?, api_key_hash = ?, api_key_enc = ?, hmac_secret_enc = ?, rotated_at = datetime('now')
         WHERE node_id = ?`, [
                freshPair.keyPrefix,
                freshPair.keyHash,
                (0, crypto_vault_1.encryptSecret)(apiKey),
                (0, crypto_vault_1.encryptSecret)(hmacSecret),
                node.id,
            ]);
        }
        const detectedIp = (params.ipAddress || params.callerIp || node.ip_address || '')
            .replace(/^::ffff:/, '')
            .trim();
        const detectedHostname = (params.hostname || node.hostname || detectedIp).trim();
        const cleanCertPem = params.tlsCertPem && params.tlsCertPem.includes('BEGIN CERTIFICATE')
            ? params.tlsCertPem.trim()
            : null;
        const existingUrlHost = (() => {
            try {
                return stripIpv6Brackets(new URL(node.url).hostname);
            }
            catch {
                return '';
            }
        })();
        const existingUsesDomain = isDomainHostname(existingUrlHost);
        let effectiveUrl = node.url;
        if (params.endpointUrl) {
            const candidateUrl = normalizeNodeEndpointUrl(params.endpointUrl);
            const candidateHost = (() => {
                try {
                    return stripIpv6Brackets(new URL(candidateUrl).hostname);
                }
                catch {
                    return '';
                }
            })();
            // Preserve a configured Cloudflare Tunnel / domain endpoint if the joining host
            // reported an auto-detected raw LAN/NAT IP instead of a domain URL.
            if (!existingUsesDomain || isDomainHostname(candidateHost)) {
                effectiveUrl = candidateUrl;
            }
        }
        else if (!existingUsesDomain && detectedIp && params.agentPort) {
            const proto = cleanCertPem || params.verifySsl ? 'https' : 'http';
            effectiveUrl = `${proto}://${detectedIp}:${Number(params.agentPort)}`;
        }
        const effectiveHostname = existingUsesDomain
            ? node.hostname || existingUrlHost
            : detectedHostname || null;
        const effectiveIp = detectedIp || node.ip_address || existingUrlHost || null;
        // If the node supplied its X.509 PEM certificate, pin it AND keep verify_ssl = 1;
        // otherwise respect explicit verifySsl or default to 0 for unpinned self-signed IP endpoints.
        const nextVerifySsl = cleanCertPem
            ? 1
            : params.verifySsl !== undefined
                ? params.verifySsl
                    ? 1
                    : 0
                : node.verify_ssl;
        await this.db.transaction(async () => {
            await this.db.run(`UPDATE node_join_tokens SET used_at = datetime('now'), used_from_ip = ? WHERE id = ?`, [params.callerIp?.replace(/^::ffff:/, '') || null, row.id]);
            await this.db.run(`UPDATE nodes SET
           hostname = COALESCE(?, hostname),
           ip_address = COALESCE(?, ip_address),
           url = ?,
           verify_ssl = ?,
           circuit_state = 'closed',
           consecutive_failures = 0,
           last_error = NULL,
           last_error_at = NULL,
           updated_at = datetime('now')
         WHERE id = ?`, [
                effectiveHostname,
                effectiveIp,
                effectiveUrl,
                nextVerifySsl,
                node.id,
            ]);
            if (cleanCertPem) {
                await this.db.run(`UPDATE node_credentials SET tls_ca_pem = ? WHERE node_id = ?`, [cleanCertPem, node.id]);
            }
        });
        this.circuits.set(node.id, { state: 'closed', failures: 0, openedAt: 0 });
        return {
            nodeId: node.id,
            nodeName: node.name,
            apiKey,
            hmacSecret,
            controllerUrl: row.controller_url,
            url: effectiveUrl,
        };
    }
    /**
     * Trust-On-First-Use (TOFU) TLS certificate fetcher & pinner for self-signed HTTPS Node Agents.
     */
    async trustNodeTlsCertificate(nodeId) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        if (node.is_local)
            throw new Error('Localhost node does not use remote TLS.');
        const targetUrl = buildAgentTargetUrl(node.url, '/api/v1/ping');
        if (targetUrl.protocol !== 'https:') {
            throw new Error(`Node "${node.name}" URL (${node.url}) uses plain http://, not https://.`);
        }
        const certDetails = await new Promise((resolve, reject) => {
            const sock = tls_1.default.connect({
                host: targetUrl.hostname,
                port: Number(targetUrl.port || 443),
                servername: netIsIp(targetUrl.hostname) ? undefined : targetUrl.hostname,
                rejectUnauthorized: false,
                timeout: 6000,
            }, () => {
                const cert = sock.getPeerCertificate(true);
                sock.end();
                if (!cert || !cert.raw || cert.raw.length === 0) {
                    return reject(new Error('Remote endpoint did not present an X.509 TLS certificate.'));
                }
                const pem = derToPemCertificate(cert.raw);
                const fingerprintSha256 = crypto_1.default.createHash('sha256').update(cert.raw).digest('hex');
                const subjectCN = Array.isArray(cert.subject?.CN)
                    ? cert.subject.CN[0] || null
                    : cert.subject?.CN || null;
                resolve({
                    pem,
                    fingerprintSha256,
                    subjectCN,
                    validTo: cert.valid_to || null,
                });
            });
            sock.on('timeout', () => {
                sock.destroy(new Error(`TLS connection timed out reaching ${targetUrl.host}`));
            });
            sock.on('error', (err) => reject(err));
        });
        await this.db.run(`UPDATE node_credentials SET tls_ca_pem = ? WHERE node_id = ?`, [
            certDetails.pem,
            nodeId,
        ]);
        await this.db.run(`UPDATE nodes SET verify_ssl = 1, circuit_state = 'closed', consecutive_failures = 0, last_error = NULL, last_error_at = NULL, updated_at = datetime('now') WHERE id = ?`, [nodeId]);
        this.circuits.set(nodeId, { state: 'closed', failures: 0, openedAt: 0 });
        let probeOk = false;
        try {
            await this.checkNodeHealthAndStats(nodeId, { bypassCircuit: true });
            probeOk = true;
        }
        catch {
            probeOk = false;
        }
        return {
            node: (await this.getNodeById(nodeId)),
            fingerprintSha256: certDetails.fingerprintSha256,
            subjectCN: certDetails.subjectCN,
            validTo: certDetails.validTo,
            probeOk,
        };
    }
    /**
     * Authenticates and processes an active outbound push-heartbeat sent by a remote Node Agent.
     */
    async receiveAgentHeartbeat(params) {
        const h = (name) => {
            const v = params.headers[name.toLowerCase()];
            return Array.isArray(v) ? v[0] || '' : v || '';
        };
        const providedKey = (h('x-hkvm-node-key') || h('x-api-key')).trim();
        const ts = Number(h('x-hkvm-timestamp') || '0');
        const nonce = h('x-hkvm-nonce').trim();
        const sig = h('x-hkvm-signature').trim();
        const headerNodeId = h('x-hkvm-node-id').trim();
        if (!providedKey || !ts || !nonce || !sig) {
            throw new Error('Missing node heartbeat authentication headers.');
        }
        const keyHash = (0, crypto_vault_1.hashApiKey)(providedKey);
        let credRow = await this.db.get(`SELECT node_id, api_key_hash, hmac_secret_enc FROM node_credentials WHERE api_key_hash = ?`, [
            keyHash,
        ]);
        if (!credRow && headerNodeId && /^\d+$/.test(headerNodeId)) {
            const candidate = await this.db.get(`SELECT node_id, api_key_hash, hmac_secret_enc FROM node_credentials WHERE node_id = ?`, [Number(headerNodeId)]);
            if (candidate &&
                candidate.api_key_hash.length === keyHash.length &&
                crypto_1.default.timingSafeEqual(Buffer.from(candidate.api_key_hash, 'utf8'), Buffer.from(keyHash, 'utf8'))) {
                credRow = candidate;
            }
        }
        if (!credRow) {
            throw new Error('Unknown node API key on heartbeat.');
        }
        // Prune replay cache older than 10 minutes
        const cutoff = Date.now() - 10 * 60_000;
        for (const [n, seenAt] of this.seenAgentHeartbeatNonces.entries()) {
            if (seenAt < cutoff)
                this.seenAgentHeartbeatNonces.delete(n);
        }
        const replayKey = `${credRow.node_id}:${nonce}`;
        if (this.seenAgentHeartbeatNonces.has(replayKey)) {
            throw new Error('Replay detected on agent heartbeat.');
        }
        const hmacSecret = (0, crypto_vault_1.decryptSecret)(credRow.hmac_secret_enc);
        const valid = (0, crypto_vault_1.verifyAgentRequestSignature)({
            hmacSecret,
            method: 'POST',
            pathWithQuery: '/api/v1/nodes/agent-heartbeat',
            timestampSec: ts,
            nonce,
            rawBody: params.rawBody,
            signatureHex: sig,
            maxSkewSec: 300,
        });
        if (!valid) {
            throw new Error('Invalid HMAC signature or skewed clock on agent heartbeat.');
        }
        this.seenAgentHeartbeatNonces.set(replayKey, Date.now());
        const nodeId = credRow.node_id;
        const health = params.body?.health;
        const stats = params.body?.stats;
        if (health && stats) {
            await this.persistNodeHealthAndStats(nodeId, health, stats);
            await this.db
                .run(`INSERT INTO metrics_history
             (target_type, target_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, net_rx_bytes, net_tx_bytes, load_avg_1)
           VALUES ('node', ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                nodeId,
                stats.cpuPercent,
                stats.ramUsedMb,
                stats.ramTotalMb,
                stats.diskUsedGb,
                stats.diskTotalGb,
                stats.netRxBytes,
                stats.netTxBytes,
                stats.loadAvg1,
            ])
                .catch(() => undefined);
        }
        else {
            this.recordCircuitSuccess(nodeId);
            await this.db.run(`UPDATE nodes
         SET status = 'online',
             last_heartbeat = datetime('now'),
             circuit_state = 'closed',
             consecutive_failures = 0,
             last_error = NULL,
             last_error_at = NULL,
             updated_at = datetime('now')
         WHERE id = ?`, [nodeId]);
        }
        return { ok: true, nodeId };
    }
    async rotateNodeCredentials(nodeId) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        const newPair = (0, crypto_vault_1.generateApiKeyPair)('tgv_node');
        const newHmac = crypto_1.default.randomBytes(32).toString('hex');
        let pushedToAgent = false;
        if (!node.is_local) {
            try {
                await this.requestRemoteNode(nodeId, 'POST', '/api/v1/credentials/rotate', {
                    newApiKey: newPair.rawKey,
                    newHmacSecret: newHmac,
                }, 15_000, { bypassCircuit: true });
                pushedToAgent = true;
            }
            catch {
                pushedToAgent = false;
            }
        }
        else {
            pushedToAgent = true;
        }
        await this.db.run(`UPDATE node_credentials
       SET api_key_prefix = ?, api_key_hash = ?, api_key_enc = ?, hmac_secret_enc = ?, rotated_at = datetime('now')
       WHERE node_id = ?`, [
            newPair.keyPrefix,
            newPair.keyHash,
            (0, crypto_vault_1.encryptSecret)(newPair.rawKey),
            (0, crypto_vault_1.encryptSecret)(newHmac),
            nodeId,
        ]);
        this.circuits.set(nodeId, { state: 'closed', failures: 0, openedAt: 0 });
        await this.db.run(`UPDATE nodes SET circuit_state = 'closed', consecutive_failures = 0 WHERE id = ?`, [nodeId]);
        let port = 8443;
        let isHttps = true;
        try {
            const u = new URL(node.url);
            isHttps = u.protocol === 'https:';
            port = Number(u.port || (isHttps ? 443 : 80));
        }
        catch {
            // default 8443
        }
        return {
            apiKey: newPair.rawKey,
            hmacSecret: newHmac,
            pushedToAgent,
            envSnippet: node.is_local
                ? undefined
                : this.buildEnvSnippet({
                    nodeId: node.id,
                    port,
                    apiKey: newPair.rawKey,
                    hmacSecret: newHmac,
                    isHttps,
                }),
        };
    }
    async persistNodeHealthAndStats(nodeId, health, stats) {
        await this.db.run(`UPDATE nodes SET
         status = 'online',
         agent_version = ?,
         last_heartbeat = datetime('now'),
         circuit_state = 'closed',
         consecutive_failures = 0,
         last_error = NULL,
         last_error_at = NULL,
         cpu_cores = ?,
         cpu_model = ?,
         ram_total_mb = ?,
         disk_total_gb = ?,
         updated_at = datetime('now')
       WHERE id = ?`, [
            health.agentVersion,
            stats.cpuCores,
            stats.cpuModel,
            stats.ramTotalMb,
            stats.diskTotalGb,
            nodeId,
        ]);
        await this.db.run(`INSERT INTO node_capabilities
         (node_id, supports_kvm, supports_lxc, kvm_available, lxc_available, nested_virt, cgroup_version, storage_backends, network_backends, qemu_version, lxc_version, kernel_version, updated_at)
       VALUES (?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(node_id) DO UPDATE SET
         kvm_available = excluded.kvm_available,
         lxc_available = excluded.lxc_available,
         nested_virt = excluded.nested_virt,
         cgroup_version = excluded.cgroup_version,
         storage_backends = excluded.storage_backends,
         network_backends = excluded.network_backends,
         qemu_version = excluded.qemu_version,
         lxc_version = excluded.lxc_version,
         kernel_version = excluded.kernel_version,
         updated_at = datetime('now')`, [
            nodeId,
            health.capabilities.kvmAvailable ? 1 : 0,
            health.capabilities.lxcAvailable ? 1 : 0,
            health.capabilities.kvmDevicePresent ? 1 : 0,
            health.capabilities.cgroupVersion,
            JSON.stringify(health.capabilities.storageBackends),
            JSON.stringify(health.capabilities.networkBackends),
            health.capabilities.qemuVersion,
            health.capabilities.lxcVersion,
            health.capabilities.kernelVersion,
        ]);
        this.recordCircuitSuccess(nodeId);
    }
    /**
     * Refreshes health, capabilities, and real host stats for a node (local or remote).
     */
    async checkNodeHealthAndStats(nodeId, options) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        const t0 = Date.now();
        let health;
        let stats;
        if (node.is_local) {
            health = await (0, health_1.getNodeHealthReport)(true, {
                interactiveShellEnabled: this.localRuntime.shellManager.isInteractiveShellEnabled(),
            });
            stats = await this.localRuntime.statsCollector.collect();
        }
        else {
            health = await this.requestRemoteNode(nodeId, 'GET', '/api/v1/health?refresh=1', undefined, 15_000, { bypassCircuit: options?.bypassCircuit });
            stats = await this.requestRemoteNode(nodeId, 'GET', '/api/v1/stats', undefined, 15_000, { bypassCircuit: true });
        }
        const latencyMs = Math.max(1, Date.now() - t0);
        this.latencies.set(nodeId, latencyMs);
        await this.persistNodeHealthAndStats(nodeId, health, stats);
        const updatedNode = (await this.getNodeById(nodeId));
        return { node: updatedNode, health, stats, latencyMs };
    }
    async resetCircuitBreaker(nodeId) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        this.circuits.set(nodeId, { state: 'closed', failures: 0, openedAt: 0 });
        await this.db.run(`UPDATE nodes SET circuit_state = 'closed', consecutive_failures = 0, last_error = NULL, last_error_at = NULL, updated_at = datetime('now') WHERE id = ?`, [nodeId]);
        return (await this.getNodeById(nodeId));
    }
    /**
     * Pre-flight HTTP/HTTPS + TLS reachability & clock-drift probe for remote Node Agent URLs.
     * When strict TLS rejects a self-signed certificate, performs a safe certificate inspection
     * so the UI can offer one-click TOFU certificate pinning.
     */
    async probeEndpointConnection(input) {
        const cleanBaseUrl = normalizeNodeEndpointUrl(input.url);
        const parsed = new URL(cleanBaseUrl);
        const isHttps = parsed.protocol === 'https:';
        const verifySsl = input.verifySsl !== false;
        const timeoutMs = Math.min(10_000, Math.max(1000, Number(input.timeoutMs || 4000)));
        const executeSingleProbe = (probePath, rejectUnauthorized) => {
            const probeUrl = buildAgentTargetUrl(cleanBaseUrl, probePath);
            const t0 = Date.now();
            return new Promise((resolve) => {
                const reqOpts = {
                    method: 'GET',
                    hostname: probeUrl.hostname,
                    port: probeUrl.port || (isHttps ? 443 : 80),
                    path: probeUrl.pathname + probeUrl.search,
                    timeout: timeoutMs,
                    headers: { Accept: 'application/json', 'User-Agent': 'TGVPANEL-Controller-Probe/3.0' },
                };
                if (isHttps) {
                    reqOpts.rejectUnauthorized = rejectUnauthorized;
                }
                const mod = isHttps ? https_1.default : http_1.default;
                const req = mod.request(reqOpts, (res) => {
                    let tlsInfo = null;
                    const sock = res.socket || req.socket;
                    if (isHttps && sock && typeof sock.getPeerCertificate === 'function') {
                        try {
                            const cert = sock.getPeerCertificate(true);
                            tlsInfo = {
                                authorized: Boolean(sock.authorized),
                                authorizationError: sock.authorizationError
                                    ? String(sock.authorizationError)
                                    : null,
                                subjectCN: Array.isArray(cert?.subject?.CN)
                                    ? cert.subject.CN[0] || null
                                    : cert?.subject?.CN || null,
                                issuerCN: Array.isArray(cert?.issuer?.CN)
                                    ? cert.issuer.CN[0] || null
                                    : cert?.issuer?.CN || null,
                                validTo: cert?.valid_to || null,
                                protocol: typeof sock.getProtocol === 'function' ? sock.getProtocol() || null : null,
                                fingerprintSha256: cert?.raw && cert.raw.length > 0
                                    ? crypto_1.default.createHash('sha256').update(cert.raw).digest('hex')
                                    : null,
                                certPem: cert?.raw && cert.raw.length > 0 ? derToPemCertificate(cert.raw) : null,
                            };
                        }
                        catch {
                            tlsInfo = null;
                        }
                    }
                    let body = '';
                    res.on('data', (c) => {
                        if (body.length < 4096)
                            body += c.toString('utf8');
                    });
                    res.on('end', () => {
                        const latencyMs = Math.max(1, Date.now() - t0);
                        resolve({
                            ok: true,
                            latencyMs,
                            status: res.statusCode || 0,
                            body,
                            headers: res.headers,
                            tlsInfo,
                        });
                    });
                });
                req.on('timeout', () => {
                    req.destroy(new Error(`Connection timed out after ${timeoutMs}ms`));
                });
                req.on('error', (err) => {
                    resolve({
                        ok: false,
                        latencyMs: Math.max(1, Date.now() - t0),
                        status: null,
                        body: '',
                        headers: {},
                        tlsInfo: null,
                        err,
                    });
                });
                req.end();
            });
        };
        let primary = await executeSingleProbe('/api/v1/ping', verifySsl);
        if (primary.ok && primary.status === 404) {
            primary = await executeSingleProbe('/api/v1/health', verifySsl);
        }
        const extractClockSkew = (body, headers) => {
            const nowSec = Math.floor(Date.now() / 1000);
            const hdr = headers['x-tgvpanel-agent-time'];
            if (hdr && /^\d+$/.test(String(hdr))) {
                return Number(hdr) - nowSec;
            }
            try {
                const j = JSON.parse(body);
                if (typeof j?.agentTimeEpochSec === 'number') {
                    return j.agentTimeEpochSec - nowSec;
                }
            }
            catch {
                // ignore
            }
            return null;
        };
        if (primary.ok) {
            const status = primary.status || 0;
            const lower = primary.body.toLowerCase();
            const agentDetected = status === 200 ||
                status === 401 ||
                lower.includes('tgvpanel') ||
                lower.includes('hmac') ||
                lower.includes('node') ||
                lower.includes('capabilities');
            const clockSkewSec = extractClockSkew(primary.body, primary.headers);
            const skewWarn = clockSkewSec !== null && Math.abs(clockSkewSec) > 240
                ? ` Warning: clock skew is ${clockSkewSec}s (sync NTP!).`
                : '';
            return {
                reachable: true,
                url: cleanBaseUrl,
                protocol: isHttps ? 'https' : 'http',
                latencyMs: primary.latencyMs,
                httpStatus: status,
                agentDetected,
                clockSkewSec,
                tls: primary.tlsInfo,
                message: (agentDetected
                    ? `Reachable in ${primary.latencyMs}ms — TGVPANEL Node Agent online & ready.`
                    : `Endpoint reachable in ${primary.latencyMs}ms (HTTP ${status}).`) + skewWarn,
            };
        }
        // If strict TLS failed on a self-signed certificate, inspect with rejectUnauthorized=false
        // so we can confirm the Node Agent is alive and return its PEM for 1-click pinning!
        const errCode = String(primary.err?.code || '');
        const errMsg = String(primary.err?.message || '');
        if (isHttps &&
            verifySsl &&
            (errCode === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
                errCode === 'SELF_SIGNED_CERT_IN_CHAIN' ||
                errCode === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
                errCode === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
                /self[- ]signed|cert/i.test(errMsg))) {
            const inspect = await executeSingleProbe('/api/v1/ping', false);
            if (inspect.ok) {
                const lower = inspect.body.toLowerCase();
                const agentDetected = inspect.status === 200 ||
                    inspect.status === 401 ||
                    lower.includes('tgvpanel') ||
                    lower.includes('hmac');
                const clockSkewSec = extractClockSkew(inspect.body, inspect.headers);
                return {
                    reachable: false,
                    url: cleanBaseUrl,
                    protocol: 'https',
                    latencyMs: inspect.latencyMs,
                    httpStatus: inspect.status,
                    agentDetected,
                    selfSignedAgentDetected: agentDetected,
                    clockSkewSec,
                    tls: inspect.tlsInfo,
                    message: agentDetected
                        ? `TGVPANEL Node Agent is online (${inspect.latencyMs}ms) using a self-signed TLS certificate (${errCode || 'SELF_SIGNED'}). Click "Pin & Trust Self-Signed Cert" below or uncheck Strict CA Verify.`
                        : `HTTPS endpoint responded (${inspect.latencyMs}ms) with a self-signed TLS certificate (${errCode || 'SELF_SIGNED'}).`,
                };
            }
        }
        return {
            reachable: false,
            url: cleanBaseUrl,
            protocol: isHttps ? 'https' : 'http',
            latencyMs: primary.latencyMs,
            httpStatus: null,
            agentDetected: false,
            tls: null,
            message: `Unreachable: ${formatTransportError(primary.err, cleanBaseUrl, verifySsl)}`,
        };
    }
    /**
     * Computes transparent smart placement scores across cluster nodes for KVM or LXC workloads.
     */
    async rankPlacementCandidates(engine) {
        const nodes = await this.listNodes();
        return nodes
            .map((n) => {
            const reasons = [];
            let eligible = true;
            if (n.status !== 'online') {
                eligible = false;
                reasons.push(`Status is ${n.status}`);
            }
            if (n.maintenance_mode) {
                eligible = false;
                reasons.push('Cordoned (Maintenance Mode)');
            }
            if (n.circuit_state === 'open') {
                eligible = false;
                reasons.push('Circuit breaker open');
            }
            const maxInst = Number(n.max_instances || 100);
            const curInst = Number(n.total_instances || 0);
            if (maxInst > 0 && curInst >= maxInst) {
                eligible = false;
                reasons.push(`Instance quota full (${curInst}/${maxInst})`);
            }
            if (engine === 'kvm' && Number(n.supports_kvm ?? 1) === 0) {
                eligible = false;
                reasons.push('KVM scheduling disabled on node');
            }
            if (engine === 'lxc' && Number(n.supports_lxc ?? 1) === 0) {
                eligible = false;
                reasons.push('LXC scheduling disabled on node');
            }
            const hwReady = engine === 'kvm' ? Boolean(n.kvm_available) : Boolean(n.lxc_available);
            const cpuPct = Number(n.live_cpu_percent ?? 10);
            const ramTot = Math.max(1, Number(n.ram_total_mb || 1024));
            const ramUsed = Number(n.live_ram_used_mb ?? Math.min(ramTot, Number(n.allocated_ram_mb || 0)));
            const freeRamRatio = Math.max(0, 1 - ramUsed / ramTot);
            const slotRatio = maxInst > 0 ? Math.max(0, 1 - curInst / maxInst) : 1;
            const cpuHeadroom = Math.max(0, 1 - cpuPct / 100);
            let score = eligible
                ? Math.round(freeRamRatio * 45 + cpuHeadroom * 35 + slotRatio * 20 + (hwReady ? 10 : -25))
                : 0;
            score = Math.max(0, Math.min(100, score));
            if (eligible) {
                reasons.push(hwReady ? `${engine.toUpperCase()} hypervisor ready` : `${engine.toUpperCase()} binary not detected yet`);
                reasons.push(`${Math.round(freeRamRatio * 100)}% free RAM headroom`);
                reasons.push(`${curInst}/${maxInst} instance slots used`);
            }
            return {
                nodeId: n.id,
                name: n.name,
                location: n.location,
                isLocal: Boolean(n.is_local),
                eligible,
                hardwareReady: hwReady,
                score,
                reasons,
            };
        })
            .sort((a, b) => Number(b.eligible) - Number(a.eligible) || b.score - a.score || a.nodeId - b.nodeId);
    }
    checkCircuitAllowed(nodeId, bypass = false) {
        if (bypass)
            return;
        const entry = this.circuits.get(nodeId);
        if (!entry || entry.state === 'closed')
            return;
        if (entry.state === 'open') {
            if (Date.now() - entry.openedAt >= this.openCooldownMs) {
                entry.state = 'half-open';
                return;
            }
            throw new Error(`Circuit breaker OPEN for node #${nodeId}: remote node is unreachable. Click "Probe" or "Reset Circuit" to retry immediately.`);
        }
    }
    recordCircuitSuccess(nodeId) {
        this.circuits.set(nodeId, { state: 'closed', failures: 0, openedAt: 0 });
    }
    async recordCircuitFailure(nodeId, errorMessage, tripCircuit = true) {
        const prev = this.circuits.get(nodeId) || { state: 'closed', failures: 0, openedAt: 0 };
        const failures = tripCircuit ? prev.failures + 1 : prev.failures;
        const state = tripCircuit && failures >= this.failureThreshold ? 'open' : prev.state === 'open' && !tripCircuit ? 'open' : 'closed';
        this.circuits.set(nodeId, {
            state,
            failures,
            openedAt: state === 'open' ? (prev.openedAt || Date.now()) : 0,
        });
        const cleanErr = errorMessage ? String(errorMessage).slice(0, 500) : null;
        await this.db.run(`UPDATE nodes
       SET status = 'offline',
           circuit_state = ?,
           consecutive_failures = ?,
           last_error = COALESCE(?, last_error),
           last_error_at = CASE WHEN ? IS NOT NULL THEN datetime('now') ELSE last_error_at END,
           updated_at = datetime('now')
       WHERE id = ?`, [state, failures, cleanErr, cleanErr, nodeId]);
    }
    buildTlsOptionsForNode(node, creds) {
        const out = {
            rejectUnauthorized: Boolean(node.verify_ssl),
        };
        if (creds.tls_ca_pem) {
            // Combine Mozilla/system Root CAs with the node's pinned X.509 cert/CA so BOTH
            // direct self-signed Node Agent TLS AND public Edge CAs (Cloudflare Tunnel / Let's Encrypt) validate.
            out.ca = [...tls_1.default.rootCertificates, creds.tls_ca_pem];
            const pinnedPrints = extractPemSha256Fingerprints(creds.tls_ca_pem);
            if (pinnedPrints.size > 0) {
                out.checkServerIdentity = (hostname, cert) => {
                    if (cert?.raw && cert.raw.length > 0) {
                        const leafSha = crypto_1.default.createHash('sha256').update(cert.raw).digest('hex');
                        if (pinnedPrints.has(leafSha)) {
                            return undefined;
                        }
                    }
                    return tls_1.default.checkServerIdentity(hostname, cert);
                };
            }
        }
        if (creds.tls_client_cert_pem && creds.tls_client_key_enc) {
            out.cert = creds.tls_client_cert_pem;
            out.key = (0, crypto_vault_1.decryptSecret)(creds.tls_client_key_enc);
        }
        return out;
    }
    async requestRemoteNode(nodeId, method, pathWithQuery, body, timeoutMs = 30_000, options) {
        this.checkCircuitAllowed(nodeId, Boolean(options?.bypassCircuit));
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        if (node.is_local) {
            throw new Error('Use localRuntime directly for localhost node operations.');
        }
        const creds = await this.db.get(`SELECT * FROM node_credentials WHERE node_id = ?`, [nodeId]);
        if (!creds) {
            throw new Error(`Credentials missing for node #${nodeId}.`);
        }
        const rawApiKey = (0, crypto_vault_1.decryptSecret)(creds.api_key_enc);
        const hmacSecret = (0, crypto_vault_1.decryptSecret)(creds.hmac_secret_enc);
        if (!rawApiKey || !hmacSecret) {
            const msg = `Credentials for node #${nodeId} cannot be decrypted with current .tgvpanel-secret. Rotate credentials in Node Settings.`;
            await this.recordCircuitFailure(nodeId, msg, false);
            throw new Error(msg);
        }
        const rawBody = body !== undefined ? JSON.stringify(body) : '';
        const targetUrl = buildAgentTargetUrl(node.url, pathWithQuery);
        const fullPathWithQuery = targetUrl.pathname + targetUrl.search;
        const signed = (0, crypto_vault_1.signAgentRequest)({
            nodeId,
            apiKey: rawApiKey,
            hmacSecret,
            method,
            pathWithQuery: fullPathWithQuery,
            bodyBuffer: rawBody,
        });
        const isHttps = targetUrl.protocol === 'https:';
        return new Promise((resolve, reject) => {
            const reqOpts = {
                method,
                hostname: targetUrl.hostname,
                port: targetUrl.port || (isHttps ? 443 : 80),
                path: fullPathWithQuery,
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(rawBody),
                    'X-HKVM-Node-Key': rawApiKey,
                    ...signed,
                },
                timeout: timeoutMs,
            };
            if (isHttps) {
                Object.assign(reqOpts, this.buildTlsOptionsForNode(node, creds));
            }
            const transport = isHttps ? https_1.default : http_1.default;
            const req = transport.request(reqOpts, (res) => {
                let respData = '';
                res.on('data', (chunk) => {
                    respData += chunk.toString('utf8');
                });
                res.on('end', async () => {
                    const code = res.statusCode || 500;
                    if (code >= 200 && code < 300) {
                        this.recordCircuitSuccess(nodeId);
                        if (node.last_error) {
                            this.db
                                .run(`UPDATE nodes SET last_error = NULL, last_error_at = NULL WHERE id = ?`, [
                                nodeId,
                            ])
                                .catch(() => undefined);
                        }
                        try {
                            resolve((respData ? JSON.parse(respData) : {}));
                        }
                        catch {
                            resolve(respData);
                        }
                    }
                    else {
                        let errMsg = `Remote node HTTP ${code}`;
                        try {
                            const parsed = JSON.parse(respData);
                            if (parsed?.error)
                                errMsg = parsed.error;
                        }
                        catch {
                            if (respData)
                                errMsg = respData.slice(0, 300);
                        }
                        // Auth failures (401/403) should surface clearly on the node without opening transport circuit
                        if (code === 401 || code === 403) {
                            await this.recordCircuitFailure(nodeId, `Auth HTTP ${code}: ${errMsg}`, false).catch(() => undefined);
                        }
                        reject(new Error(errMsg));
                    }
                });
            });
            req.on('timeout', () => {
                req.destroy(new Error(`Remote node #${nodeId} request timed out after ${timeoutMs}ms`));
            });
            req.on('error', async (err) => {
                const friendly = formatTransportError(err, node.url, Boolean(node.verify_ssl));
                const isTlsConfigErr = /TLS self-signed|TLS certificate|TLS handshake|Protocol mismatch/i.test(friendly);
                await this.recordCircuitFailure(nodeId, friendly, !isTlsConfigErr).catch(() => undefined);
                const wrapped = new Error(friendly);
                wrapped.code = err?.code;
                reject(wrapped);
            });
            if (rawBody) {
                req.write(rawBody);
            }
            req.end();
        });
    }
    async openRemoteAgentWebSocket(nodeId, wsPath, query = {}) {
        const node = await this.getNodeById(nodeId);
        if (!node || node.is_local) {
            throw new Error(`Node #${nodeId} is not a remote node.`);
        }
        const creds = await this.db.get(`SELECT * FROM node_credentials WHERE node_id = ?`, [nodeId]);
        if (!creds)
            throw new Error(`Credentials missing for node #${nodeId}.`);
        const rawApiKey = (0, crypto_vault_1.decryptSecret)(creds.api_key_enc);
        const hmacSecret = (0, crypto_vault_1.decryptSecret)(creds.hmac_secret_enc);
        if (!rawApiKey || !hmacSecret) {
            throw new Error(`Unable to decrypt credentials for node #${nodeId}.`);
        }
        const httpTarget = buildAgentTargetUrl(node.url, wsPath);
        const signed = (0, crypto_vault_1.signAgentRequest)({
            nodeId,
            apiKey: rawApiKey,
            hmacSecret,
            method: 'GET',
            pathWithQuery: httpTarget.pathname,
            bodyBuffer: '',
        });
        const wsUrl = new URL(httpTarget.toString());
        wsUrl.protocol = httpTarget.protocol === 'https:' ? 'wss:' : 'ws:';
        for (const [k, v] of Object.entries(query)) {
            wsUrl.searchParams.set(k, String(v));
        }
        const tlsOpts = httpTarget.protocol === 'https:'
            ? this.buildTlsOptionsForNode(node, creds)
            : { rejectUnauthorized: false };
        return new Promise((resolve, reject) => {
            let settled = false;
            const ws = new ws_1.default(wsUrl.toString(), {
                ...tlsOpts,
                handshakeTimeout: 10_000,
                headers: {
                    'X-HKVM-Node-Key': rawApiKey,
                    ...signed,
                },
            });
            const finishErr = (msg) => {
                if (settled)
                    return;
                settled = true;
                try {
                    ws.terminate();
                }
                catch {
                    // ignore
                }
                reject(new Error(msg));
            };
            ws.once('open', () => {
                if (settled)
                    return;
                settled = true;
                this.recordCircuitSuccess(nodeId);
                resolve(ws);
            });
            ws.once('unexpected-response', (_req, res) => {
                let body = '';
                res.on('data', (c) => {
                    if (body.length < 2048)
                        body += c.toString('utf8');
                });
                res.on('end', () => {
                    let detail = `Remote WebSocket upgrade rejected (HTTP ${res.statusCode || 500})`;
                    try {
                        const parsed = JSON.parse(body);
                        if (parsed?.error)
                            detail = parsed.error;
                    }
                    catch {
                        // keep default
                    }
                    finishErr(detail);
                });
            });
            ws.once('error', (err) => {
                finishErr(formatTransportError(err, node.url, Boolean(node.verify_ssl)));
            });
        });
    }
}
exports.NodeManager = NodeManager;
function netIsIp(host) {
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
}
