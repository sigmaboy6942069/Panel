"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeAgentAuthenticator = void 0;
exports.sanitizeAgentEnvValue = sanitizeAgentEnvValue;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const crypto_vault_1 = require("../security/crypto-vault");
function sanitizeAgentEnvValue(raw) {
    if (!raw)
        return '';
    let val = String(raw).replace(/\r/g, '').trim();
    if ((val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
        (val.startsWith("'") && val.endsWith("'") && val.length >= 2)) {
        val = val.slice(1, -1).trim();
    }
    return val;
}
/**
 * Replay-protection nonce cache + HMAC/API-Key/mTLS authenticator for the TGVPANEL Node Agent.
 */
class NodeAgentAuthenticator {
    config;
    activeRawApiKey;
    seenNonces = new Map();
    cleanupTimer;
    maxSkewSec = 300;
    constructor(config) {
        const cleanHmac = sanitizeAgentEnvValue(config.hmacSecret);
        const cleanRawKey = sanitizeAgentEnvValue(config.rawApiKey);
        this.config = {
            ...config,
            rawApiKey: cleanRawKey || undefined,
            apiKeyHash: cleanRawKey ? (0, crypto_vault_1.hashApiKey)(cleanRawKey) : String(config.apiKeyHash || '').trim(),
            hmacSecret: cleanHmac,
        };
        this.activeRawApiKey = cleanRawKey || undefined;
        if (config.loadPersistedCredentials &&
            config.credentialsFilePath &&
            fs_1.default.existsSync(config.credentialsFilePath)) {
            try {
                const persisted = JSON.parse(fs_1.default.readFileSync(config.credentialsFilePath, 'utf8'));
                const bootstrapMatches = !this.config.envBootstrapHash ||
                    !persisted?.envBootstrapHash ||
                    persisted.envBootstrapHash === this.config.envBootstrapHash;
                if (bootstrapMatches && persisted?.apiKeyHash && persisted?.hmacSecret) {
                    this.config.apiKeyHash = String(persisted.apiKeyHash).trim();
                    this.config.hmacSecret = sanitizeAgentEnvValue(persisted.hmacSecret);
                    // Raw API key is never written to disk; if credentials were rotated earlier, outbound
                    // push-heartbeat pauses until next controller-initiated check or fresh rotation unless in memory.
                    if (this.activeRawApiKey && (0, crypto_vault_1.hashApiKey)(this.activeRawApiKey) !== this.config.apiKeyHash) {
                        this.activeRawApiKey = undefined;
                    }
                }
                else if (!bootstrapMatches) {
                    // Admin updated .env with fresh bootstrap credentials — supersede stale rotation cache
                    try {
                        fs_1.default.unlinkSync(config.credentialsFilePath);
                    }
                    catch {
                        // ignore read-only fs
                    }
                }
            }
            catch {
                // fall back to env bootstrap credentials
            }
        }
        this.cleanupTimer = setInterval(() => {
            const cutoff = Date.now() - 10 * 60_000;
            for (const [nonce, ts] of this.seenNonces.entries()) {
                if (ts < cutoff)
                    this.seenNonces.delete(nonce);
            }
        }, 60_000);
        if (typeof this.cleanupTimer.unref === 'function')
            this.cleanupTimer.unref();
    }
    getOutboundSigningCredentials() {
        if (!this.activeRawApiKey || !this.config.hmacSecret)
            return null;
        return {
            nodeId: this.config.nodeId,
            apiKey: this.activeRawApiKey,
            hmacSecret: this.config.hmacSecret,
        };
    }
    rotateCredentials(newRawApiKey, newHmacSecret) {
        const cleanKey = sanitizeAgentEnvValue(newRawApiKey);
        const cleanHmac = sanitizeAgentEnvValue(newHmacSecret);
        this.activeRawApiKey = cleanKey;
        this.config.apiKeyHash = (0, crypto_vault_1.hashApiKey)(cleanKey);
        this.config.hmacSecret = cleanHmac;
        if (this.config.credentialsFilePath) {
            const dir = path_1.default.dirname(this.config.credentialsFilePath);
            fs_1.default.mkdirSync(dir, { recursive: true, mode: 0o700 });
            fs_1.default.writeFileSync(this.config.credentialsFilePath, JSON.stringify({
                nodeId: this.config.nodeId,
                apiKeyHash: this.config.apiKeyHash,
                hmacSecret: this.config.hmacSecret,
                envBootstrapHash: this.config.envBootstrapHash || null,
                requireMtls: this.config.requireMtls,
                rotatedAt: new Date().toISOString(),
            }, null, 2), { mode: 0o600 });
        }
    }
    candidateCanonicalPaths(pathWithQuery) {
        const out = [pathWithQuery];
        const apiIdx = pathWithQuery.indexOf('/api/v1/');
        if (apiIdx > 0)
            out.push(pathWithQuery.slice(apiIdx));
        const wsIdx = pathWithQuery.indexOf('/ws/');
        if (wsIdx > 0)
            out.push(pathWithQuery.slice(wsIdx));
        return Array.from(new Set(out));
    }
    verifyRawHeaders(params) {
        if (this.config.requireMtls && !params.tlsAuthorized) {
            return { ok: false, status: 403, reason: 'Mutual TLS client certificate required' };
        }
        if (this.config.allowedControllerIps &&
            this.config.allowedControllerIps.length > 0 &&
            params.remoteAddress) {
            const cleanIp = params.remoteAddress.replace(/^::ffff:/, '');
            if (!this.config.allowedControllerIps.includes(cleanIp) &&
                !this.config.allowedControllerIps.includes('*')) {
                return { ok: false, status: 403, reason: `Controller IP ${cleanIp} not allowlisted` };
            }
        }
        const providedKey = sanitizeAgentEnvValue(params.apiKeyHeader);
        if (!providedKey) {
            return { ok: false, status: 401, reason: 'Missing X-HKVM-Node-Key header' };
        }
        const providedHash = (0, crypto_vault_1.hashApiKey)(providedKey);
        if (providedHash.length !== this.config.apiKeyHash.length ||
            !crypto_1.default.timingSafeEqual(Buffer.from(providedHash, 'utf8'), Buffer.from(this.config.apiKeyHash, 'utf8'))) {
            return {
                ok: false,
                status: 401,
                reason: 'Invalid node API key (controller credentials do not match /opt/tgvpanel/.env on remote node)',
            };
        }
        const ts = Number(params.timestampHeader || '0');
        const nonce = (params.nonceHeader || '').trim();
        const sig = (params.signatureHeader || '').trim();
        if (!ts || !nonce || !sig) {
            return {
                ok: false,
                status: 401,
                reason: 'Missing HMAC timestamp, nonce, or signature headers',
            };
        }
        const nowSec = Math.floor(Date.now() / 1000);
        const skewSec = nowSec - ts;
        if (!Number.isFinite(ts) || Math.abs(skewSec) > this.maxSkewSec) {
            return {
                ok: false,
                status: 401,
                reason: `Node clock skew too large (${skewSec >= 0 ? '+' : ''}${skewSec}s drift; max ±${this.maxSkewSec}s). Sync NTP clock on both hosts (timedatectl set-ntp true).`,
            };
        }
        if (this.seenNonces.has(nonce)) {
            return { ok: false, status: 409, reason: 'Replay detected: nonce already used' };
        }
        const candidates = this.candidateCanonicalPaths(params.pathWithQuery);
        if (params.signedPathHint && !candidates.includes(params.signedPathHint)) {
            candidates.push(params.signedPathHint);
        }
        let validSig = false;
        for (const candidatePath of candidates) {
            if ((0, crypto_vault_1.verifyAgentRequestSignature)({
                hmacSecret: this.config.hmacSecret,
                method: params.method,
                pathWithQuery: candidatePath,
                timestampSec: ts,
                nonce,
                rawBody: params.rawBody,
                signatureHex: sig,
                maxSkewSec: this.maxSkewSec,
            })) {
                validSig = true;
                break;
            }
        }
        if (!validSig) {
            return {
                ok: false,
                status: 401,
                reason: 'HMAC signature verification failed (check TGVPANEL_NODE_HMAC_SECRET on remote node)',
            };
        }
        this.seenNonces.set(nonce, Date.now());
        return { ok: true, status: 200 };
    }
    expressMiddleware() {
        return (req, res, next) => {
            res.setHeader('X-TGVPANEL-Agent-Time', String(Math.floor(Date.now() / 1000)));
            const rawBody = typeof req.rawBody === 'string'
                ? req.rawBody
                : req.body && Object.keys(req.body).length > 0
                    ? JSON.stringify(req.body)
                    : '';
            const tlsSock = req.socket;
            const result = this.verifyRawHeaders({
                method: req.method,
                pathWithQuery: req.originalUrl,
                rawBody,
                apiKeyHeader: req.headers['x-hkvm-node-key'] ||
                    req.headers['x-api-key'],
                timestampHeader: req.headers['x-hkvm-timestamp'],
                nonceHeader: req.headers['x-hkvm-nonce'],
                signatureHeader: req.headers['x-hkvm-signature'],
                remoteAddress: req.socket.remoteAddress,
                tlsAuthorized: Boolean(tlsSock?.authorized),
            });
            if (!result.ok) {
                return res.status(result.status).json({ error: result.reason });
            }
            return next();
        };
    }
    verifyWebSocketUpgrade(req) {
        const urlObj = new URL(req.url || '/', 'http://localhost');
        const apiKey = req.headers['x-hkvm-node-key'] || urlObj.searchParams.get('key') || '';
        const ts = req.headers['x-hkvm-timestamp'] || urlObj.searchParams.get('ts') || '';
        const nonce = req.headers['x-hkvm-nonce'] || urlObj.searchParams.get('nonce') || '';
        const sig = req.headers['x-hkvm-signature'] || urlObj.searchParams.get('sig') || '';
        const tlsSock = req.socket;
        const res = this.verifyRawHeaders({
            method: 'GET',
            pathWithQuery: urlObj.pathname,
            rawBody: '',
            apiKeyHeader: apiKey,
            timestampHeader: ts,
            nonceHeader: nonce,
            signatureHeader: sig,
            remoteAddress: req.socket.remoteAddress,
            tlsAuthorized: Boolean(tlsSock?.authorized),
        });
        return { ok: res.ok, reason: res.reason };
    }
}
exports.NodeAgentAuthenticator = NodeAgentAuthenticator;
