"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SafeValidators = void 0;
exports.createRateLimiter = createRateLimiter;
exports.securityHeadersAndCsrfMiddleware = securityHeadersAndCsrfMiddleware;
exports.verifyCsrfMiddleware = verifyCsrfMiddleware;
exports.createUnifiedAuthMiddleware = createUnifiedAuthMiddleware;
exports.normalizeRole = normalizeRole;
exports.requirePrincipal = requirePrincipal;
exports.requireRole = requireRole;
const crypto_vault_1 = require("./crypto-vault");
/**
 * Sliding-window in-memory rate limiter for auth, terminal, and mutation endpoints.
 */
function createRateLimiter(options) {
    const buckets = new Map();
    const cleanupTimer = setInterval(() => {
        const now = Date.now();
        for (const [k, v] of buckets.entries()) {
            if (v.resetAt <= now)
                buckets.delete(k);
        }
    }, Math.max(options.windowMs, 60_000));
    if (typeof cleanupTimer.unref === 'function')
        cleanupTimer.unref();
    return (req, res, next) => {
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
            req.socket.remoteAddress ||
            'unknown';
        const key = `${options.keyPrefix}:${ip}`;
        const now = Date.now();
        const entry = buckets.get(key);
        if (!entry || entry.resetAt <= now) {
            buckets.set(key, { count: 1, resetAt: now + options.windowMs });
            return next();
        }
        entry.count += 1;
        if (entry.count > options.max) {
            const retryAfterSec = Math.ceil((entry.resetAt - now) / 1000);
            res.setHeader('Retry-After', String(retryAfterSec));
            return res.status(429).json({
                error: options.message || 'Too many requests. Please slow down and retry shortly.',
                retry_after_seconds: retryAfterSec,
            });
        }
        return next();
    };
}
/**
 * Security response headers & CSRF token injection into `res.locals.csrfToken`.
 */
function securityHeadersAndCsrfMiddleware(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    // The panel ships a handful of inline handlers and CDN assets, so the policy
    // has to allow them; everything else is locked to our own origin.
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com",
        "img-src 'self' data: blob:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ].join('; '));
    // Only meaningful (and only safe) once the request arrived over TLS. Behind a
    // reverse proxy the browser-facing hop is HTTPS even though this one is not.
    if (req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    const sess = req.session;
    const sessUid = sess?.userId || sess?.user?.id;
    const sessionAnchor = req.sessionID ||
        (sessUid ? `uid:${sessUid}` : 'anonymous-hkvm-session');
    const token = (0, crypto_vault_1.generateCsrfToken)(sessionAnchor);
    req.csrfTokenValue = token;
    res.locals.csrfToken = token;
    res.locals.impersonating = Boolean(sess?.impersonatorAdminId);
    // Expose CSRF token header for SPA/AJAX helpers inside EJS views
    res.setHeader('X-CSRF-Token', token);
    next();
}
/**
 * Enforces CSRF token validation on state-mutating browser session requests.
 * Requests authenticated via `Authorization: Bearer <api_key>` or `X-API-Key` are exempt from cookie CSRF,
 * and standard XMLHttpRequest / fetch calls from HKVM's EJS templates pass either `X-CSRF-Token`, `_csrf`,
 * or same-origin JSON `Content-Type: application/json` + verified Origin/Referer.
 */
function verifyCsrfMiddleware(req, res, next) {
    const method = req.method.toUpperCase();
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
        return next();
    }
    // API key authenticated calls do not rely on ambient browser cookies
    if (req.headers.authorization?.startsWith('Bearer ') || req.headers['x-api-key']) {
        return next();
    }
    // Node agent HMAC & single-use join endpoints handle their own replay-protected verification
    if (req.path.startsWith('/api/v1/agent-callback') ||
        req.originalUrl.startsWith('/api/v1/nodes/agent-heartbeat') ||
        req.originalUrl.startsWith('/api/v1/nodes/join/')) {
        return next();
    }
    const sess = req.session;
    const sessUid = sess?.userId || sess?.user?.id;
    if (!sessUid) {
        // Login / public reset forms before session establishment
        return next();
    }
    const sessionAnchor = req.sessionID || `uid:${sessUid}`;
    const candidateToken = req.headers['x-csrf-token'] ||
        (req.body && typeof req.body === 'object' ? req.body._csrf : undefined) ||
        req.query?._csrf;
    if (candidateToken && (0, crypto_vault_1.verifyCsrfToken)(sessionAnchor, String(candidateToken))) {
        return next();
    }
    return res.status(403).json({
        error: 'CSRF verification failed. Refresh the page and retry.',
    });
}
/**
 * Resolves either an active Express session OR a scoped API key (`Authorization: Bearer <key>` / `X-API-Key`).
 */
function createUnifiedAuthMiddleware(db) {
    return async (req, res, next) => {
        try {
            const sess = req.session;
            const sessUid = sess?.userId || sess?.user?.id;
            if (sessUid) {
                const dbUser = await db.get(`SELECT id, username, role, is_active FROM users WHERE id = ?`, [sessUid]);
                if (dbUser && dbUser.is_active !== 0) {
                    req.principal = {
                        userId: dbUser.id,
                        username: dbUser.username,
                        role: normalizeRole(dbUser.role),
                        viaApiKey: false,
                        impersonatedBy: sess.impersonatorAdminId || undefined,
                    };
                    return next();
                }
            }
            // Check API key header (skip for self-authenticated Node Agent HMAC / join routes)
            if (req.originalUrl.startsWith('/api/v1/nodes/agent-heartbeat') ||
                req.originalUrl.startsWith('/api/v1/nodes/join/')) {
                return next();
            }
            let rawKey = '';
            const authHeader = String(req.headers.authorization || '');
            if (authHeader.startsWith('Bearer ')) {
                rawKey = authHeader.slice(7).trim();
            }
            else if (typeof req.headers['x-api-key'] === 'string') {
                rawKey = req.headers['x-api-key'].trim();
            }
            if (rawKey) {
                const hashed = (0, crypto_vault_1.hashApiKey)(rawKey);
                const keyRow = await db.get(`SELECT k.id, k.user_id, k.permissions, k.ip_whitelist, k.expires_at, k.is_active,
                  u.username, u.role, u.is_active AS user_active
           FROM api_keys k
           JOIN users u ON u.id = k.user_id
           WHERE k.key_hash = ?`, [hashed]);
                if (!keyRow || !keyRow.is_active || !keyRow.user_active) {
                    return res.status(401).json({ error: 'Invalid or inactive API key' });
                }
                if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
                    return res.status(401).json({ error: 'API key has expired' });
                }
                if (keyRow.ip_whitelist) {
                    try {
                        const allowedIps = JSON.parse(keyRow.ip_whitelist);
                        if (Array.isArray(allowedIps) && allowedIps.length > 0) {
                            const reqIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                                req.socket.remoteAddress ||
                                '';
                            if (!allowedIps.includes(reqIp) && !allowedIps.includes('*')) {
                                return res.status(403).json({ error: 'IP address not authorized for this API key' });
                            }
                        }
                    }
                    catch {
                        // Ignore malformed whitelist
                    }
                }
                let perms = ['read'];
                try {
                    const parsed = JSON.parse(keyRow.permissions || '["read"]');
                    if (Array.isArray(parsed))
                        perms = parsed;
                }
                catch {
                    perms = ['read'];
                }
                await db.run(`UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?`, [keyRow.id]);
                req.principal = {
                    userId: keyRow.user_id,
                    username: keyRow.username,
                    role: normalizeRole(keyRow.role),
                    viaApiKey: true,
                    apiKeyId: keyRow.id,
                    apiPermissions: perms,
                };
            }
            return next();
        }
        catch (err) {
            return next(err);
        }
    };
}
function normalizeRole(role) {
    switch ((role || '').toLowerCase()) {
        case 'admin':
            return 'admin';
        case 'subadmin':
            return 'subadmin';
        case 'operator':
            return 'operator';
        case 'readonly':
            return 'readonly';
        default:
            return 'user';
    }
}
function requirePrincipal(req, res, next) {
    const isApiReq = (req.originalUrl || req.path).startsWith('/api/') ||
        req.headers.accept?.includes('application/json');
    if (!req.principal) {
        if (isApiReq) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        return res.redirect('/login');
    }
    // Enforce API key scope on mutations
    if (req.principal.viaApiKey && req.method !== 'GET' && req.method !== 'HEAD') {
        const perms = req.principal.apiPermissions || [];
        if (!perms.includes('write') && !perms.includes('admin') && !perms.includes('*')) {
            return res.status(403).json({ error: 'API key lacks write permission' });
        }
    }
    if (req.principal.role === 'readonly' && req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(403).json({ error: 'Read-only account cannot perform mutations' });
    }
    return next();
}
function requireRole(allowedRoles) {
    return (req, res, next) => {
        const isApiReq = (req.originalUrl || req.path).startsWith('/api/') ||
            req.headers.accept?.includes('application/json');
        if (!req.principal) {
            if (isApiReq) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            return res.redirect('/login');
        }
        if (!allowedRoles.includes(req.principal.role)) {
            if (isApiReq) {
                return res.status(403).json({ error: 'Insufficient role permissions' });
            }
            return res.status(403).send('Forbidden: insufficient privileges');
        }
        if (req.principal.viaApiKey &&
            (allowedRoles.includes('admin') || allowedRoles.includes('subadmin')) &&
            allowedRoles.length <= 2) {
            const perms = req.principal.apiPermissions || [];
            if (!perms.includes('admin') && !perms.includes('*') && req.principal.role !== 'admin') {
                return res.status(403).json({ error: 'API key lacks admin scope' });
            }
        }
        return next();
    };
}
/**
 * Strict input validators preventing shell metacharacters, path traversal, and invalid identifiers.
 */
exports.SafeValidators = {
    containerName(name) {
        const val = String(name || '').trim();
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,62}$/.test(val)) {
            throw new Error('Invalid instance/container name: must be 2-63 alphanumeric, dash, underscore, or dot characters.');
        }
        return val;
    },
    snapshotName(name) {
        const val = String(name || '').trim();
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$/.test(val)) {
            throw new Error('Invalid snapshot name: use 1-48 alphanumeric, dash, or underscore characters.');
        }
        return val;
    },
    bridgeOrIface(name) {
        const val = String(name || '').trim();
        if (!/^[a-zA-Z0-9_.-]{1,15}$/.test(val)) {
            throw new Error('Invalid Linux network interface name (max 15 safe characters).');
        }
        return val;
    },
    ipv4(ip) {
        const val = String(ip || '').trim();
        const parts = val.split('.');
        if (parts.length !== 4 ||
            !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255)) {
            throw new Error(`Invalid IPv4 address: ${val}`);
        }
        return val;
    },
    ipv6OrCidr(ip) {
        const val = String(ip || '').trim();
        if (!/^[0-9a-fA-F:/]{2,45}$/.test(val)) {
            throw new Error(`Invalid IPv6 address: ${val}`);
        }
        return val;
    },
    portNumber(port, min = 1, max = 65535) {
        const n = Number(port);
        if (!Number.isInteger(n) || n < min || n > max) {
            throw new Error(`Port must be an integer between ${min} and ${max}.`);
        }
        return n;
    },
    safeContainerSubpath(relPath) {
        const raw = String(relPath || '/').trim() || '/';
        if (raw.includes('\0')) {
            throw new Error('Null bytes are forbidden in file paths.');
        }
        const normalized = raw.startsWith('/') ? raw : '/' + raw;
        const segments = normalized.split('/').filter(Boolean);
        for (const seg of segments) {
            if (seg === '..') {
                throw new Error('Directory traversal ("..") is forbidden.');
            }
        }
        return '/' + segments.join('/');
    },
};
