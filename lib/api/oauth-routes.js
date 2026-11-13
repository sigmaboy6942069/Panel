"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createOAuthRouter = createOAuthRouter;
exports.finishLogin = finishLogin;
const crypto_1 = __importDefault(require("crypto"));
const express_1 = require("express");
const crypto_vault_1 = require("../security/crypto-vault");
const oauth_providers_1 = require("../security/oauth-providers");
const STATE_TTL_MS = 10 * 60 * 1000;
function createOAuthRouter(deps) {
    const router = (0, express_1.Router)();
    const { ctx } = deps;
    // The OAuth router is mounted ahead of the web router, so the shared view
    // locals have not been set yet. Provide them here too, otherwise these
    // templates render with undefined branding on an error page.
    router.use((_req, res, next) => {
        if (res.locals.siteLogo === undefined)
            res.locals.siteLogo = '/images/logo.png';
        if (res.locals.siteName === undefined)
            res.locals.siteName = 'TGVPANEL';
        next();
    });
    async function loadProvider(provider) {
        const row = await ctx.db.get(`SELECT * FROM oauth_provider_settings WHERE provider = ?`, [provider]);
        if (!row || !row.enabled || !row.client_id || !row.client_secret_enc)
            return null;
        return row;
    }
    // --- Step 1: send the user to the provider ---
    router.get('/auth/:provider', async (req, res) => {
        const provider = String(req.params.provider || '').toLowerCase();
        if (!(0, oauth_providers_1.isOAuthProviderId)(provider))
            return res.status(404).send('Unknown sign-in provider.');
        try {
            const settings = await loadProvider(provider);
            if (!settings) {
                return res.status(404).render('users/oauth-error', {
                    title: 'Sign-in unavailable',
                    message: `Signing in with ${provider} is not enabled on this panel.`,
                });
            }
            const state = (0, oauth_providers_1.createOAuthState)();
            const pkce = (0, oauth_providers_1.createPkcePair)();
            const sess = req.session;
            sess.oauthPending = {
                provider,
                state,
                codeVerifier: pkce.verifier,
                createdAt: Date.now(),
            };
            const url = (0, oauth_providers_1.buildAuthorizeUrl)({
                provider,
                config: {
                    clientId: settings.client_id,
                    clientSecret: '',
                    redirectUri: settings.redirect_uri || deps.resolveRedirectUri(provider, req),
                },
                state,
                codeChallenge: pkce.challenge,
            });
            return res.redirect(url);
        }
        catch (err) {
            console.error(`[OAuth] start failed for ${provider}:`, err.message);
            return res.status(500).render('users/oauth-error', {
                title: 'Sign-in failed',
                message: 'Could not start the sign-in flow. Please try again.',
            });
        }
    });
    // --- Step 2: the provider sends the user back ---
    router.get('/auth/:provider/callback', async (req, res) => {
        const provider = String(req.params.provider || '').toLowerCase();
        const fail = (msg) => res.redirect(`/login?error=${encodeURIComponent(msg)}`);
        if (!(0, oauth_providers_1.isOAuthProviderId)(provider))
            return fail('Unknown sign-in provider.');
        const sess = req.session;
        const pending = sess?.oauthPending;
        // Consume immediately: a state value is single-use even on failure.
        delete sess.oauthPending;
        if (!pending || pending.provider !== provider) {
            return fail('Your sign-in session expired. Please try again.');
        }
        if (Date.now() - Number(pending.createdAt || 0) > STATE_TTL_MS) {
            return fail('Sign-in took too long. Please try again.');
        }
        if (!(0, oauth_providers_1.oauthStateMatches)(pending.state, req.query.state)) {
            console.warn(`[OAuth] state mismatch for ${provider} from ${req.ip}`);
            return fail('Security check failed. Please try again.');
        }
        // The user pressed "cancel" at the provider.
        if (req.query.error) {
            return fail(`Sign-in cancelled (${String(req.query.error)}).`);
        }
        const code = typeof req.query.code === 'string' ? req.query.code : '';
        if (!code)
            return fail('The provider did not return an authorisation code.');
        try {
            const settings = await loadProvider(provider);
            if (!settings)
                return fail('This sign-in method is no longer enabled.');
            const clientSecret = (0, crypto_vault_1.decryptSecret)(settings.client_secret_enc);
            const config = {
                clientId: settings.client_id,
                clientSecret,
                redirectUri: settings.redirect_uri || deps.resolveRedirectUri(provider, req),
            };
            const token = await (0, oauth_providers_1.exchangeCodeForToken)({
                provider,
                config,
                code,
                codeVerifier: pending.codeVerifier,
            });
            const profile = await (0, oauth_providers_1.fetchNormalizedProfile)({
                provider,
                accessToken: token.accessToken,
            });
            // --- Who is this? ---
            const identity = await ctx.db.get(`SELECT user_id FROM oauth_identities WHERE provider = ? AND subject = ?`, [provider, profile.subject]);
            let matchingEmailUserId = null;
            if (!identity && profile.email) {
                const byEmail = await ctx.db.get(`SELECT id FROM users WHERE lower(email) = lower(?) AND is_active = 1`, [profile.email]);
                if (byEmail)
                    matchingEmailUserId = byEmail.id;
            }
            const decision = (0, oauth_providers_1.decideAccountLink)({
                linkedUserId: identity ? identity.user_id : null,
                matchingEmailUserId,
                emailVerified: profile.emailVerified && Boolean(settings.auto_link_verified_email),
                email: profile.email,
                autoCreateUsers: Boolean(settings.allow_signup),
            });
            const redirectFor = (role) => role === 'admin' ? '/admin/dashboard' : '/dashboard';
            if (decision.action === 'login') {
                const user = await ctx.db.get(`SELECT * FROM users WHERE id = ?`, [decision.userId]);
                if (!user || !user.is_active)
                    return fail('That account is disabled.');
                await touchIdentity(provider, profile.subject, profile);
                // A linked account with 2FA must still satisfy the second factor.
                if (user.two_factor_enabled && user.two_factor_secret_enc) {
                    sess.pending2faUser = {
                        id: user.id,
                        username: user.username,
                        role: user.role,
                        email: user.email,
                    };
                    return res.redirect('/login/2fa');
                }
                return finishLogin(req, res, user, provider);
            }
            if (decision.action === 'link' && !decision.requiresProof) {
                const user = await ctx.db.get(`SELECT * FROM users WHERE id = ?`, [decision.userId]);
                if (!user || !user.is_active)
                    return fail('That account is disabled.');
                await linkIdentity(user.id, profile);
                if (user.two_factor_enabled && user.two_factor_secret_enc) {
                    sess.pending2faUser = {
                        id: user.id,
                        username: user.username,
                        role: user.role,
                        email: user.email,
                    };
                    return res.redirect('/login/2fa');
                }
                return finishLogin(req, res, user, provider);
            }
            if (decision.action === 'link' && decision.requiresProof) {
                // The provider does not vouch for the address. Make the user prove they
                // own the account by entering its password before we attach this identity.
                sess.pendingOAuthLink = {
                    provider,
                    subject: profile.subject,
                    email: profile.email,
                    displayName: profile.username,
                    avatarUrl: profile.avatarUrl,
                    userId: decision.userId,
                };
                return res.redirect('/link-oauth-account');
            }
            if (decision.action === 'refuse') {
                return res.redirect(`/login?error=${encodeURIComponent(decision.reason)}`);
            }
            // --- create ---
            const created = await createUserFromProfile(profile);
            if (!created)
                return fail('Could not create an account for you.');
            // New accounts never have 2FA yet, but run them through the same path.
            return finishLogin(req, res, created, provider);
        }
        catch (err) {
            console.error(`[OAuth] callback failed for ${provider}:`, err.message);
            return fail('Sign-in failed. Please try again.');
        }
    });
    async function touchIdentity(provider, subject, profile) {
        await ctx.db.run(`UPDATE oauth_identities
       SET last_login_at = CURRENT_TIMESTAMP, email = ?, email_verified = ?,
           display_name = ?, avatar_url = ?
       WHERE provider = ? AND subject = ?`, [
            profile.email,
            profile.emailVerified ? 1 : 0,
            profile.username,
            profile.avatarUrl,
            provider,
            subject,
        ]);
    }
    async function linkIdentity(userId, profile) {
        await ctx.db.run(`INSERT INTO oauth_identities
         (user_id, provider, subject, email, email_verified, display_name, avatar_url, last_login_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(provider, subject) DO UPDATE SET
         user_id = excluded.user_id,
         email = excluded.email,
         email_verified = excluded.email_verified,
         display_name = excluded.display_name,
         avatar_url = excluded.avatar_url,
         last_login_at = CURRENT_TIMESTAMP`, [
            userId,
            profile.provider,
            profile.subject,
            profile.email,
            profile.emailVerified ? 1 : 0,
            profile.username,
            profile.avatarUrl,
        ]);
    }
    async function createUserFromProfile(profile) {
        // The password is random and never disclosed: this account is intended to
        // be used through the provider. A user can still set a real password later.
        const randomPassword = crypto_1.default.randomBytes(32).toString('base64url');
        const bcrypt = require('bcryptjs');
        const hash = bcrypt.hashSync(randomPassword, 12);
        // Username collisions are expected (two "alex" on different providers).
        let username = String(profile.username || 'user')
            .replace(/[^A-Za-z0-9._-]/g, '')
            .slice(0, 32) || 'user';
        const taken = await ctx.db.get(`SELECT id FROM users WHERE username = ?`, [
            username,
        ]);
        if (taken)
            username = `${username}-${crypto_1.default.randomBytes(2).toString('hex')}`;
        const result = await ctx.db.run(`INSERT INTO users (username, password, email, full_name, role, is_active)
       VALUES (?, ?, ?, ?, 'user', 1)`, [username, hash, profile.email, profile.username]);
        const userId = Number(result?.lastID || 0);
        if (!userId)
            return null;
        await linkIdentity(userId, profile);
        await ctx.db.logActivity({
            userId,
            action: `auth.signup.${profile.provider}`,
            resourceType: 'user',
            resourceId: String(userId),
        });
        return ctx.db.get(`SELECT * FROM users WHERE id = ?`, [userId]);
    }
    return router;
}
/**
 * Complete a sign-in: fresh session id, then the standard session keys.
 * Shared by every provider so no path can forget the regenerate step.
 */
function finishLogin(req, res, user, provider) {
    const sess = req.session;
    const target = user.two_factor_enabled
        ? '/login/2fa'
        : user.role === 'admin'
            ? '/admin/dashboard'
            : '/dashboard';
    sess.regenerate((err) => {
        if (err)
            console.error('[OAuth] session regenerate failed:', err);
        const fresh = req.session;
        fresh.userId = user.id;
        fresh.username = user.username;
        fresh.role = user.role;
        fresh.user = { id: user.id, username: user.username, role: user.role };
        res.redirect(target);
    });
}
