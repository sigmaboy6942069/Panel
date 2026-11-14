import { Request, Response, NextFunction } from 'express';
import { UnifiedDatabase } from '../db/database';
import {
  generateCsrfToken,
  hashApiKey,
  verifyCsrfToken,
} from './crypto-vault';

export interface AuthenticatedPrincipal {
  userId: number;
  username: string;
  role: 'admin' | 'subadmin' | 'operator' | 'user' | 'readonly';
  viaApiKey?: boolean;
  apiKeyId?: number;
  apiPermissions?: string[];
  impersonatedBy?: number;
}

declare global {
  namespace Express {
    interface Request {
      principal?: AuthenticatedPrincipal;
      csrfTokenValue?: string;
    }
  }
}

/**
 * Sliding-window in-memory rate limiter for auth, terminal, and mutation endpoints.
 */
export function createRateLimiter(options: {
  windowMs: number;
  max: number;
  keyPrefix: string;
  message?: string;
}) {
  const buckets = new Map<string, { count: number; resetAt: number }>();

  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of buckets.entries()) {
      if (v.resetAt <= now) buckets.delete(k);
    }
  }, Math.max(options.windowMs, 60_000));
  if (typeof cleanupTimer.unref === 'function') cleanupTimer.unref();

  return (req: Request, res: Response, next: NextFunction) => {
    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
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
export function securityHeadersAndCsrfMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  // The panel ships a handful of inline handlers and CDN assets, so the policy
  // has to allow them; everything else is locked to our own origin.
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
      "font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ')
  );

  // Only meaningful (and only safe) once the request arrived over TLS. Behind a
  // reverse proxy the browser-facing hop is HTTPS even though this one is not.
  if (req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  const sess: any = (req as any).session;
  const sessUid = sess?.userId || sess?.user?.id;
  const sessionAnchor =
    (req as any).sessionID ||
    (sessUid ? `uid:${sessUid}` : 'anonymous-hkvm-session');
  const token = generateCsrfToken(sessionAnchor);
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
export function verifyCsrfMiddleware(req: Request, res: Response, next: NextFunction) {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return next();
  }

  // API key authenticated calls do not rely on ambient browser cookies
  if (req.headers.authorization?.startsWith('Bearer ') || req.headers['x-api-key']) {
    return next();
  }

  // Node agent HMAC & single-use join endpoints handle their own replay-protected verification
  if (
    req.path.startsWith('/api/v1/agent-callback') ||
    req.originalUrl.startsWith('/api/v1/nodes/agent-heartbeat') ||
    req.originalUrl.startsWith('/api/v1/nodes/join/')
  ) {
    return next();
  }

  const sess: any = (req as any).session;
  const sessUid = sess?.userId || sess?.user?.id;
  if (!sessUid) {
    // Login / public reset forms before session establishment
    return next();
  }

  const sessionAnchor = (req as any).sessionID || `uid:${sessUid}`;
  const candidateToken =
    (req.headers['x-csrf-token'] as string) ||
    (req.body && typeof req.body === 'object' ? req.body._csrf : undefined) ||
    (req.query?._csrf as string | undefined);

  if (candidateToken && verifyCsrfToken(sessionAnchor, String(candidateToken))) {
    return next();
  }

  return res.status(403).json({
    error: 'CSRF verification failed. Refresh the page and retry.',
  });
}

/**
 * Resolves either an active Express session OR a scoped API key (`Authorization: Bearer <key>` / `X-API-Key`).
 */
export function createUnifiedAuthMiddleware(db: UnifiedDatabase) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const sess: any = (req as any).session;
      const sessUid = sess?.userId || sess?.user?.id;
      if (sessUid) {
        const dbUser = await db.get<{
          id: number;
          username: string;
          role: string;
          is_active: number;
        }>(`SELECT id, username, role, is_active FROM users WHERE id = ?`, [sessUid]);

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
      if (
        req.originalUrl.startsWith('/api/v1/nodes/agent-heartbeat') ||
        req.originalUrl.startsWith('/api/v1/nodes/join/')
      ) {
        return next();
      }

      let rawKey = '';
      const authHeader = String(req.headers.authorization || '');
      if (authHeader.startsWith('Bearer ')) {
        rawKey = authHeader.slice(7).trim();
      } else if (typeof req.headers['x-api-key'] === 'string') {
        rawKey = req.headers['x-api-key'].trim();
      }

      if (rawKey) {
        const hashed = hashApiKey(rawKey);
        const keyRow = await db.get<{
          id: number;
          user_id: number;
          permissions: string;
          ip_whitelist: string | null;
          expires_at: string | null;
          is_active: number;
          username: string;
          role: string;
          user_active: number;
        }>(
          `SELECT k.id, k.user_id, k.permissions, k.ip_whitelist, k.expires_at, k.is_active,
                  u.username, u.role, u.is_active AS user_active
           FROM api_keys k
           JOIN users u ON u.id = k.user_id
           WHERE k.key_hash = ?`,
          [hashed]
        );

        if (!keyRow || !keyRow.is_active || !keyRow.user_active) {
          return res.status(401).json({ error: 'Invalid or inactive API key' });
        }

        if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
          return res.status(401).json({ error: 'API key has expired' });
        }

        if (keyRow.ip_whitelist) {
          try {
            const allowedIps: string[] = JSON.parse(keyRow.ip_whitelist);
            if (Array.isArray(allowedIps) && allowedIps.length > 0) {
              const reqIp =
                (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
                req.socket.remoteAddress ||
                '';
              if (!allowedIps.includes(reqIp) && !allowedIps.includes('*')) {
                return res.status(403).json({ error: 'IP address not authorized for this API key' });
              }
            }
          } catch {
            // Ignore malformed whitelist
          }
        }

        let perms: string[] = ['read'];
        try {
          const parsed = JSON.parse(keyRow.permissions || '["read"]');
          if (Array.isArray(parsed)) perms = parsed;
        } catch {
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
    } catch (err) {
      return next(err);
    }
  };
}

export function normalizeRole(
  role?: string | null
): 'admin' | 'subadmin' | 'operator' | 'user' | 'readonly' {
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

export function requirePrincipal(req: Request, res: Response, next: NextFunction) {
  const isApiReq =
    (req.originalUrl || req.path).startsWith('/api/') ||
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

export function requireRole(
  allowedRoles: Array<'admin' | 'subadmin' | 'operator' | 'user' | 'readonly'>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    const isApiReq =
      (req.originalUrl || req.path).startsWith('/api/') ||
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

    if (
      req.principal.viaApiKey &&
      (allowedRoles.includes('admin') || allowedRoles.includes('subadmin')) &&
      allowedRoles.length <= 2
    ) {
      const perms = req.principal.apiPermissions || [];
      if (!perms.includes('admin') && !perms.includes('*') && req.principal.role !== 'admin') {
        return res.status(403).json({ error: 'API key lacks admin scope' });
      }
    }

    return next();
  };
}

/**
 * Requires that the signed-in principal has actually satisfied a second factor.
 *
 * Node join approval is the highest-value action in the panel: approving it
 * hands out credentials for a machine that will run customer servers. A stolen
 * session cookie or a leaked API key must not be enough.
 *
 * Rules:
 *  - API-key principals are always rejected. A key cannot prove possession of a
 *    TOTP device, so it must never authorise this class of action.
 *  - Password sessions must have passed 2FA. Rows written before this check
 *    existed (no `twoFactorVerifiedAt`) are rejected, which forces a re-login
 *    rather than trusting an old session.
 */
export function requireSecondFactor(req: Request, res: Response, next: NextFunction) {
  const isApiReq =
    (req.originalUrl || req.path).startsWith('/api/') ||
    req.headers.accept?.includes('application/json');
  const deny = (status: number, code: string, error: string) => {
    if (isApiReq) return res.status(status).json({ error, code, requires2FA: true });
    return res.redirect(`/login/2fa?next=${encodeURIComponent(req.originalUrl || '/admin/nodes')}`);
  };

  if (!req.principal) {
    return isApiReq
      ? res.status(401).json({ error: 'Authentication required', code: 'auth_required' })
      : res.redirect('/login');
  }

  if (req.principal.viaApiKey) {
    return deny(
      403,
      'second_factor_required',
      'This action requires a browser session with two-factor authentication. API keys cannot approve node joins.'
    );
  }

  const sess: any = (req as any).session;
  const verifiedAt = Number(sess?.twoFactorVerifiedAt || 0);
  const enrolled = Boolean(sess?.twoFactorEnrolled);
  const userId = Number(sess?.userId || 0);
  const verifiedFor = Number(sess?.twoFactorVerifiedFor || 0);

  if (!userId) {
    return deny(
      403,
      'second_factor_required',
      'Two-factor authentication is required for this action. Sign in again.'
    );
  }

  if (!enrolled) {
    // No authenticator on this account. Refuse with a message that says how to
    // fix it rather than a bare 403. Enrolling is one page and takes a minute.
    return deny(
      403,
      'enrol_2fa_first',
      'Set up two-factor authentication on your account before approving nodes. ' +
        'Go to Profile → Two-Factor Authentication to enrol, then sign in again.'
    );
  }

  // A session that belongs to a different user than the one that verified is
  // a session-fixation smell; refuse rather than guess.
  if (!verifiedAt || verifiedFor !== userId) {
    return deny(
      403,
      'second_factor_required',
      'Two-factor authentication is required for this action. Sign in again and complete the 2FA step.'
    );
  }

  // Bound the window: a session verified last week should not silently approve
  // a machine today. Matches the typical re-auth expectation for privileged acts.
  const maxAgeMs = Number(process.env.TGVPANEL_2FA_REAUTH_MINUTES || 60) * 60_000;
  if (Date.now() - verifiedAt > maxAgeMs) {
    return deny(
      403,
      'second_factor_stale',
      'Your two-factor verification has expired. Confirm your code again to continue.'
    );
  }

  return next();
}

/**
 * Strict input validators preventing shell metacharacters, path traversal, and invalid identifiers.
 */
export const SafeValidators = {
  containerName(name: unknown): string {
    const val = String(name || '').trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,62}$/.test(val)) {
      throw new Error(
        'Invalid instance/container name: must be 2-63 alphanumeric, dash, underscore, or dot characters.'
      );
    }
    return val;
  },

  snapshotName(name: unknown): string {
    const val = String(name || '').trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$/.test(val)) {
      throw new Error('Invalid snapshot name: use 1-48 alphanumeric, dash, or underscore characters.');
    }
    return val;
  },

  bridgeOrIface(name: unknown): string {
    const val = String(name || '').trim();
    if (!/^[a-zA-Z0-9_.-]{1,15}$/.test(val)) {
      throw new Error('Invalid Linux network interface name (max 15 safe characters).');
    }
    return val;
  },

  ipv4(ip: unknown): string {
    const val = String(ip || '').trim();
    const parts = val.split('.');
    if (
      parts.length !== 4 ||
      !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255)
    ) {
      throw new Error(`Invalid IPv4 address: ${val}`);
    }
    return val;
  },

  ipv6OrCidr(ip: unknown): string {
    const val = String(ip || '').trim();
    if (!/^[0-9a-fA-F:/]{2,45}$/.test(val)) {
      throw new Error(`Invalid IPv6 address: ${val}`);
    }
    return val;
  },

  portNumber(port: unknown, min = 1, max = 65535): number {
    const n = Number(port);
    if (!Number.isInteger(n) || n < min || n > max) {
      throw new Error(`Port must be an integer between ${min} and ${max}.`);
    }
    return n;
  },

  safeContainerSubpath(relPath: unknown): string {
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
