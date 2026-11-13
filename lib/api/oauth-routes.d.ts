/**
 * Third-party sign-in routes: /auth/:provider and /auth/:provider/callback.
 *
 * These use their own tables (oauth_identities, oauth_provider_settings) and
 * their own 2FA handshake. The older Discord-specific routes in app.js remain
 * for backwards compatibility but are superseded by these: Discord is served by
 * this generic code path once it is enabled in the admin UI.
 *
 * Flow:
 *   1. GET /auth/:provider        -> mint state + PKCE, stash in session, redirect out
 *   2. GET /auth/:provider/callback -> constant-time state check, exchange code,
 *                                      normalise profile, decide link/login/create
 *   3. If the user has 2FA, park in pending2faUser and go to /login/2fa
 */
import { Router, Request, Response } from 'express';
import { HkvmRuntimeContext } from '../context';
import { OAuthProviderId } from '../security/oauth-providers';
export interface OAuthRouteDeps {
    ctx: HkvmRuntimeContext;
    /** Absolute redirect URI per provider, e.g. https://panel.example/auth/google/callback */
    resolveRedirectUri: (provider: OAuthProviderId, req: Request) => string;
}
export declare function createOAuthRouter(deps: OAuthRouteDeps): Router;
/**
 * Complete a sign-in: fresh session id, then the standard session keys.
 * Shared by every provider so no path can forget the regenerate step.
 */
export declare function finishLogin(req: Request, res: Response, user: any, provider: OAuthProviderId | 'password'): void;
