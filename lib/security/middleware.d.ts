import { Request, Response, NextFunction } from 'express';
import { UnifiedDatabase } from '../db/database';
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
export declare function createRateLimiter(options: {
    windowMs: number;
    max: number;
    keyPrefix: string;
    message?: string;
}): (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
/**
 * Security response headers & CSRF token injection into `res.locals.csrfToken`.
 */
export declare function securityHeadersAndCsrfMiddleware(req: Request, res: Response, next: NextFunction): void;
/**
 * Enforces CSRF token validation on state-mutating browser session requests.
 * Requests authenticated via `Authorization: Bearer <api_key>` or `X-API-Key` are exempt from cookie CSRF,
 * and standard XMLHttpRequest / fetch calls from HKVM's EJS templates pass either `X-CSRF-Token`, `_csrf`,
 * or same-origin JSON `Content-Type: application/json` + verified Origin/Referer.
 */
export declare function verifyCsrfMiddleware(req: Request, res: Response, next: NextFunction): void | Response<any, Record<string, any>>;
/**
 * Resolves either an active Express session OR a scoped API key (`Authorization: Bearer <key>` / `X-API-Key`).
 */
export declare function createUnifiedAuthMiddleware(db: UnifiedDatabase): (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
export declare function normalizeRole(role?: string | null): 'admin' | 'subadmin' | 'operator' | 'user' | 'readonly';
export declare function requirePrincipal(req: Request, res: Response, next: NextFunction): void | Response<any, Record<string, any>>;
export declare function requireRole(allowedRoles: Array<'admin' | 'subadmin' | 'operator' | 'user' | 'readonly'>): (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
/**
 * Strict input validators preventing shell metacharacters, path traversal, and invalid identifiers.
 */
export declare const SafeValidators: {
    containerName(name: unknown): string;
    snapshotName(name: unknown): string;
    bridgeOrIface(name: unknown): string;
    ipv4(ip: unknown): string;
    ipv6OrCidr(ip: unknown): string;
    portNumber(port: unknown, min?: number, max?: number): number;
    safeContainerSubpath(relPath: unknown): string;
};
