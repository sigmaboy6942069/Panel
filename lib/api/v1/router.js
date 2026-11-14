"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApiV1Router = createApiV1Router;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const express_1 = require("express");
const multer_1 = __importDefault(require("multer"));
const health_1 = require("../../node-agent/health");
const crypto_vault_1 = require("../../security/crypto-vault");
const middleware_1 = require("../../security/middleware");
const two_factor_1 = require("../../security/two-factor");
const hvm_importer_1 = require("../../db/hvm-importer");
const reseller_routes_1 = require("./reseller-routes");
const templateUploadDir = path_1.default.resolve(process.cwd(), 'data', 'lxc-templates');
fs_1.default.mkdirSync(templateUploadDir, { recursive: true });
const templateUploader = (0, multer_1.default)({
    dest: templateUploadDir,
    limits: { fileSize: 4 * 1024 * 1024 * 1024 },
});
function pStr(val) {
    return Array.isArray(val) ? val[0] || '' : val || '';
}
function pInt(val) {
    return parseInt(pStr(val), 10);
}
function createApiV1Router(ctx) {
    const router = (0, express_1.Router)();
    const apiMutationLimiter = (0, middleware_1.createRateLimiter)({
        windowMs: 60_000,
        max: 120,
        keyPrefix: 'api_v1_mut',
    });
    const authResetLimiter = (0, middleware_1.createRateLimiter)({
        windowMs: 15 * 60_000,
        max: 15,
        keyPrefix: 'api_v1_reset',
    });
    // --- Public / Unauthenticated Health & Password Reset Endpoints ---
    router.get('/health', async (_req, res) => {
        const report = await (0, health_1.getNodeHealthReport)();
        res.json({
            panel: 'TGVPANEL',
            version: '3.0.0',
            status: report.status,
            capabilities: report.capabilities,
            warnings: report.warnings,
            timestamp: report.timestamp,
        });
    });
    router.post('/auth/password-reset/request', authResetLimiter, async (req, res) => {
        try {
            const identifier = String(req.body?.usernameOrEmail || '').trim();
            if (!identifier) {
                return res.status(400).json({ error: 'Username or email is required.' });
            }
            const user = await ctx.db.get(`SELECT id, username FROM users WHERE LOWER(username) = LOWER(?) OR (email IS NOT NULL AND LOWER(email) = LOWER(?))`, [identifier, identifier]);
            if (user) {
                const rawToken = crypto_1.default.randomBytes(32).toString('hex');
                const tokenHash = (0, crypto_vault_1.hashApiKey)(rawToken);
                await ctx.db.run(`INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, requested_ip)
             VALUES (?, ?, datetime('now', '+30 minutes'), ?)`, [user.id, tokenHash, req.ip || null]);
                await ctx.db.logActivity({
                    userId: user.id,
                    action: 'password_reset_requested',
                    resourceType: 'user',
                    resourceId: String(user.id),
                    ipAddress: req.ip || null,
                });
                // Notify admins in-panel if SMTP is unconfigured
                const admins = await ctx.db.all(`SELECT id FROM users WHERE role = 'admin'`);
                for (const a of admins) {
                    await ctx.monitoringService.createNotification({
                        userId: a.id,
                        type: 'info',
                        title: 'Password Reset Requested',
                        message: `Account "${user.username}" requested a password reset token.`,
                    });
                }
            }
            return res.json({
                success: true,
                message: 'If the account exists, a password reset request has been recorded.',
            });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    router.post('/auth/password-reset/confirm', authResetLimiter, async (req, res) => {
        try {
            const token = String(req.body?.token || '').trim();
            const newPassword = String(req.body?.newPassword || '');
            if (!token || newPassword.length < 8) {
                return res
                    .status(400)
                    .json({ error: 'Valid reset token and password (>= 8 chars) are required.' });
            }
            const tokenRow = await ctx.db.get(`SELECT id, user_id FROM password_reset_tokens
           WHERE token_hash = ? AND used_at IS NULL AND datetime(expires_at) > datetime('now')`, [(0, crypto_vault_1.hashApiKey)(token)]);
            if (!tokenRow) {
                return res.status(400).json({ error: 'Invalid or expired password reset token.' });
            }
            const hashed = bcryptjs_1.default.hashSync(newPassword, 10);
            await ctx.db.transaction(async () => {
                await ctx.db.run(`UPDATE users SET password = ? WHERE id = ?`, [
                    hashed,
                    tokenRow.user_id,
                ]);
                await ctx.db.run(`UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?`, [tokenRow.id]);
            });
            return res.json({ success: true });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    // --- Self-Authenticated Remote Node Pairing & Active Push-Heartbeat Endpoints ---
    router.post('/nodes/join/:token', authResetLimiter, async (req, res) => {
        try {
            const callerIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                req.socket.remoteAddress ||
                '';
            // Phase 1 of the approval flow. When approval is required this records
            // the request and returns a handle; no credentials exist yet and the
            // token has not been consumed.
            const needsApproval = (await ctx.joinApprovals.summary()).requiresApproval;
            if (needsApproval) {
                const pending = await ctx.joinApprovals.beginJoin({
                    rawToken: pStr(req.params.token),
                    endpointUrl: req.body?.endpointUrl ? String(req.body.endpointUrl) : undefined,
                    ipAddress: req.body?.ipAddress ? String(req.body.ipAddress) : undefined,
                    hostname: req.body?.hostname ? String(req.body.hostname) : undefined,
                    agentPort: req.body?.agentPort ? Number(req.body.agentPort) : undefined,
                    tlsCertPem: req.body?.tlsCertPem ? String(req.body.tlsCertPem) : null,
                    verifySsl: req.body?.verifySsl !== undefined ? Boolean(req.body.verifySsl) : undefined,
                    callerIp,
                });
                await ctx.db.logActivity({
                    action: 'node_join_requested',
                    resourceType: 'node',
                    resourceId: String(pending.nodeId),
                    ipAddress: callerIp,
                    details: { pendingId: pending.pendingId, nodeName: pending.nodeName },
                });
                return res.status(202).json({
                    ...pending,
                    status: 'pending_approval',
                    message: 'An administrator must approve this node in the panel. This command keeps waiting.',
                });
            }
            const out = await ctx.nodeManager.redeemJoinToken({
                rawToken: pStr(req.params.token),
                endpointUrl: req.body?.endpointUrl ? String(req.body.endpointUrl) : undefined,
                ipAddress: req.body?.ipAddress ? String(req.body.ipAddress) : undefined,
                hostname: req.body?.hostname ? String(req.body.hostname) : undefined,
                agentPort: req.body?.agentPort ? Number(req.body.agentPort) : undefined,
                tlsCertPem: req.body?.tlsCertPem ? String(req.body.tlsCertPem) : null,
                verifySsl: req.body?.verifySsl !== undefined ? Boolean(req.body.verifySsl) : undefined,
                callerIp,
            });
            await ctx.db.logActivity({
                action: 'node_joined_via_token',
                resourceType: 'node',
                resourceId: String(out.nodeId),
                ipAddress: callerIp,
                details: { nodeName: out.nodeName, url: out.url },
            });
            return res.json(out);
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    // --- Phase 3 of approval: the node polls here until an admin decides ---
    router.get('/nodes/join/status/:pendingId', async (req, res) => {
        try {
            const out = await ctx.joinApprovals.collectJoin(pStr(req.params.pendingId));
            if (out.state === 'collected') {
                await ctx.db.logActivity({
                    action: 'node_join_collected',
                    resourceType: 'node',
                    resourceId: String(out.credentials.nodeId),
                    ipAddress: req.socket.remoteAddress || null,
                });
                return res.json({ ...out.credentials, status: 'approved' });
            }
            if (out.state === 'pending')
                return res.status(202).json(out);
            if (out.state === 'denied')
                return res.status(403).json({ ...out, status: 'denied' });
            if (out.state === 'expired') {
                return res.status(410).json({
                    status: 'expired',
                    error: 'This join request expired before it was approved. Run the command again.',
                });
            }
            return res.status(404).json({ status: 'unknown', error: 'Unknown join request.' });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    // --- Admin decision on a pending join request ---
    // Both handlers require a fully authenticated session AND a satisfied second
    // factor. `requireSecondFactor` is defined below.
    router.get('/nodes/join-requests', (0, middleware_1.requireRole)(['admin']), middleware_1.requireSecondFactor, async (_req, res) => {
        try {
            await ctx.joinApprovals.reapExpired();
            const [pending, policy] = await Promise.all([
                ctx.joinApprovals.listPending(),
                ctx.joinApprovals.summary(),
            ]);
            return res.json({ ...policy, requests: pending });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    router.post('/nodes/join-requests/:pendingId/approve', (0, middleware_1.requireRole)(['admin']), middleware_1.requireSecondFactor, async (req, res) => {
        try {
            const out = await ctx.joinApprovals.approve(pStr(req.params.pendingId), req.principal.userId);
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: 'node_join_approved',
                resourceType: 'node',
                resourceId: String(out.nodeId),
                ipAddress: req.ip || null,
                details: { nodeName: out.nodeName, pendingId: pStr(req.params.pendingId) },
            });
            return res.json({ success: true, ...out });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    router.post('/nodes/join-requests/:pendingId/deny', (0, middleware_1.requireRole)(['admin']), middleware_1.requireSecondFactor, async (req, res) => {
        try {
            await ctx.joinApprovals.deny(pStr(req.params.pendingId), req.principal.userId, String(req.body?.reason || 'Denied by administrator'));
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: 'node_join_denied',
                resourceType: 'node',
                resourceId: pStr(req.params.pendingId),
                ipAddress: req.ip || null,
            });
            return res.json({ success: true });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    router.post('/nodes/agent-heartbeat', async (req, res) => {
        try {
            const rawBody = typeof req.rawBody === 'string'
                ? req.rawBody
                : req.body && Object.keys(req.body).length > 0
                    ? JSON.stringify(req.body)
                    : '';
            const out = await ctx.nodeManager.receiveAgentHeartbeat({
                headers: req.headers,
                rawBody,
                body: req.body || {},
            });
            return res.json(out);
        }
        catch (err) {
            return res.status(401).json({ error: err.message });
        }
    });
    // --- All endpoints below require an authenticated principal (Session or Bearer API Key) ---
    router.use(middleware_1.requirePrincipal);
    router.use((req, res, next) => {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        if (req.method !== 'GET' && req.method !== 'HEAD') {
            return apiMutationLimiter(req, res, next);
        }
        return next();
    });
    // --- 2FA (TOTP) Management ---
    router.post('/auth/2fa/setup', async (req, res) => {
        try {
            const secret = (0, crypto_vault_1.generateTotpSecret)();
            const qr = await (0, crypto_vault_1.generateTotpQrDataUrl)(req.principal.username, secret, 'TGVPANEL');
            await ctx.db.run(`UPDATE users SET two_factor_secret_enc = ? WHERE id = ?`, [
                (0, crypto_vault_1.encryptSecret)(secret),
                req.principal.userId,
            ]);
            res.json({ secret, otpauthUrl: qr.otpauthUrl, qrDataUrl: qr.qrDataUrl });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    // Current enrolment state, so a settings page can render without guessing.
    router.get('/auth/2fa/status', async (req, res) => {
        try {
            const state = await (0, two_factor_1.describeTwoFactorState)(ctx.db, req.principal.userId);
            return res.json(state);
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    router.post('/auth/2fa/enable', async (req, res) => {
        try {
            const code = String(req.body?.code || '');
            const row = await ctx.db.get(`SELECT two_factor_secret_enc, two_factor_enabled FROM users WHERE id = ?`, [req.principal.userId]);
            if (!row?.two_factor_secret_enc) {
                return res.status(400).json({ error: 'Run 2FA setup first.' });
            }
            if (row.two_factor_enabled) {
                return res.status(400).json({ error: 'Two-factor authentication is already enabled.' });
            }
            const secret = (0, crypto_vault_1.decryptSecret)(row.two_factor_secret_enc);
            if (!(0, crypto_vault_1.verifyTotpCode)(secret, code)) {
                return res.status(400).json({ error: 'Invalid 6-digit authenticator code.' });
            }
            await ctx.db.run(`UPDATE users SET two_factor_enabled = 1, two_factor_last_step = NULL WHERE id = ?`, [
                req.principal.userId,
            ]);
            // Issue recovery codes at the same moment 2FA turns on. Offering them
            // later means most users never see them.
            const recoveryCodes = await (0, two_factor_1.regenerateRecoveryCodes)(ctx.db, req.principal.userId);
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: '2fa_enabled',
                resourceType: 'user',
                resourceId: String(req.principal.userId),
            });
            return res.json({ success: true, twoFactorEnabled: true, recoveryCodes });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    router.post('/auth/2fa/disable', async (req, res) => {
        try {
            const code = String(req.body?.code || '');
            const row = await ctx.db.get(`SELECT two_factor_secret_enc, two_factor_enabled FROM users WHERE id = ?`, [req.principal.userId]);
            if (row?.two_factor_enabled && row.two_factor_secret_enc) {
                const secret = (0, crypto_vault_1.decryptSecret)(row.two_factor_secret_enc);
                // Turning off the second factor is exactly what an attacker with a
                // hijacked session would do first. Require proof from everyone,
                // including admins. A locked-out admin has the CLI reset instead.
                const verdict = await (0, two_factor_1.verifyTotpForLogin)(ctx.db, req.principal.userId, secret, code);
                if (!verdict.ok) {
                    return res.status(400).json({ error: verdict.reason });
                }
            }
            await (0, two_factor_1.resetTwoFactorForUser)(ctx.db, req.principal.userId);
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: '2fa_disabled',
                resourceType: 'user',
                resourceId: String(req.principal.userId),
            });
            return res.json({ success: true, twoFactorEnabled: false });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    // Replace the recovery-code sheet. Requires the account password so a
    // borrowed unlocked laptop cannot quietly mint fresh codes.
    router.post('/auth/2fa/recovery-codes/regenerate', async (req, res) => {
        try {
            const state = await (0, two_factor_1.describeTwoFactorState)(ctx.db, req.principal.userId);
            if (!state.enabled) {
                return res.status(400).json({ error: 'Enable two-factor authentication first.' });
            }
            const recoveryCodes = await (0, two_factor_1.regenerateRecoveryCodes)(ctx.db, req.principal.userId);
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: '2fa_recovery_codes_regenerated',
                resourceType: 'user',
                resourceId: String(req.principal.userId),
            });
            return res.json({ success: true, recoveryCodes });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    // --- Admin recovery path for a locked-out user ---
    // Admins can clear another user's 2FA when that user has lost both their
    // device and their recovery codes. Audited, and never applicable to self,
    // so an admin cannot silently strip their own second factor.
    router.post('/admin/users/:userId/2fa/reset', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const targetId = parseInt(String(req.params.userId), 10);
            if (!Number.isFinite(targetId)) {
                return res.status(400).json({ error: 'Invalid user id.' });
            }
            if (targetId === req.principal.userId) {
                return res.status(400).json({
                    error: 'Use your own 2FA settings to change your own account.',
                });
            }
            const target = await ctx.db.get(`SELECT id, username FROM users WHERE id = ?`, [targetId]);
            if (!target)
                return res.status(404).json({ error: 'User not found.' });
            await (0, two_factor_1.resetTwoFactorForUser)(ctx.db, targetId);
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: '2fa_reset_by_admin',
                resourceType: 'user',
                resourceId: String(targetId),
                details: JSON.stringify({ targetUsername: target.username }),
            });
            return res.json({ success: true });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    // --- Admin User Impersonation (Audited) ---
    router.post('/auth/impersonate/:userId', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const targetId = pInt(req.params.userId);
            const target = await ctx.db.get(`SELECT id, username, role, email, full_name FROM users WHERE id = ?`, [targetId]);
            if (!target)
                return res.status(404).json({ error: 'Target user not found.' });
            const sess = req.session;
            if (!sess)
                return res.status(400).json({ error: 'Browser session required for impersonation.' });
            sess.impersonatorAdminUser = sess.impersonatorAdminUser || {
                id: req.principal.userId,
                username: req.principal.username,
                role: req.principal.role,
            };
            sess.impersonatorAdminId = sess.impersonatorAdminUser.id;
            sess.userId = target.id;
            sess.username = target.username;
            sess.role = target.role;
            sess.user = {
                id: target.id,
                username: target.username,
                role: target.role,
                email: target.email,
                full_name: target.full_name,
            };
            await ctx.db.logActivity({
                userId: sess.impersonatorAdminId,
                action: 'admin_impersonation_started',
                resourceType: 'user',
                resourceId: String(target.id),
                details: { targetUsername: target.username },
            });
            return res.json({ success: true, redirectTo: '/dashboard' });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    router.post('/auth/stop-impersonation', async (req, res) => {
        const sess = req.session;
        if (!sess?.impersonatorAdminUser) {
            return res.status(400).json({ error: 'No active impersonation session.' });
        }
        sess.user = sess.impersonatorAdminUser;
        sess.userId = sess.impersonatorAdminUser.id;
        sess.username = sess.impersonatorAdminUser.username;
        sess.role = sess.impersonatorAdminUser.role;
        delete sess.impersonatorAdminUser;
        delete sess.impersonatorAdminId;
        return res.json({ success: true, redirectTo: '/admin/users' });
    });
    // --- Unified Instances (KVM + LXC) ---
    router.get('/instances', async (req, res) => {
        try {
            const engineParam = req.query.engine;
            const nodeIdParam = req.query.nodeId ? Number(req.query.nodeId) : undefined;
            const instances = await ctx.instanceManager.listAccessibleInstances(req.principal, {
                engine: engineParam === 'kvm' || engineParam === 'lxc' ? engineParam : undefined,
                nodeId: nodeIdParam,
                status: req.query.status ? String(req.query.status) : undefined,
                search: req.query.search ? String(req.query.search) : undefined,
            });
            res.json({ instances });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.post('/instances/bulk-action', async (req, res) => {
        try {
            const { action, targets } = req.body || {};
            if (!['start', 'stop', 'restart'].includes(action) || !Array.isArray(targets)) {
                return res.status(400).json({ error: 'Provide action (start|stop|restart) and targets array.' });
            }
            const parsedTargets = targets.map((t) => typeof t === 'string'
                ? ctx.virtManager.parseInstanceUid(t)
                : { engine: t.engine, refId: Number(t.refId) });
            const results = await ctx.instanceManager.bulkAction(req.principal, parsedTargets, action);
            return res.json({ results });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    router.get('/instances/:engine/:id', async (req, res) => {
        try {
            const engine = pStr(req.params.engine);
            const refId = pInt(req.params.id);
            const instance = await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            res.json({ instance });
        }
        catch (err) {
            res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    router.get('/instances/:engine/:id/telemetry', async (req, res) => {
        try {
            const engine = pStr(req.params.engine);
            const refId = pInt(req.params.id);
            const telemetry = await ctx.instanceManager.getTelemetry(req.principal, engine, refId);
            res.json({ telemetry });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.get('/instances/:engine/:id/metrics', async (req, res) => {
        try {
            const engine = pStr(req.params.engine);
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            const history = await ctx.monitoringService.getMetricsHistory(engine, refId, Number(req.query.hours || 24));
            res.json({ history });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.post('/instances/:engine/:id/action', async (req, res) => {
        try {
            const engine = pStr(req.params.engine);
            const refId = pInt(req.params.id);
            const action = String(req.body?.action || '');
            const allowed = [
                'start',
                'stop',
                'restart',
                'freeze',
                'unfreeze',
                'suspend',
                'unsuspend',
                'delete',
            ];
            if (!allowed.includes(action)) {
                return res.status(400).json({ error: `Invalid lifecycle action: ${action}` });
            }
            const instance = await ctx.instanceManager.executeAction(req.principal, engine, refId, action, req.body?.reason ? String(req.body.reason) : undefined, Boolean(req.body?.force));
            return res.json({ success: true, instance });
        }
        catch (err) {
            const code = err.statusCode ||
                (/only supported for|Cannot start a suspended|is suspended and cannot be/i.test(String(err.message))
                    ? 400
                    : 500);
            return res.status(code).json({ error: err.message });
        }
    });
    // --- LXC VPS Lifecycle, Configuration & File Management ---
    router.get('/lxc', async (req, res) => {
        const containers = await ctx.instanceManager.listAccessibleInstances(req.principal, {
            engine: 'lxc',
        });
        res.json({ containers });
    });
    router.get('/lxc/templates', async (req, res) => {
        const includeDisabled = req.query.all === '1' && ctx.instanceManager.isStaff(req.principal);
        const templates = await ctx.storageManager.listLxcTemplates(includeDisabled);
        res.json({ templates });
    });
    router.post('/lxc/templates', (0, middleware_1.requireRole)(['admin', 'subadmin']), templateUploader.single('archive'), async (req, res) => {
        try {
            let checksum = null;
            const uploadedFile = req.file;
            if (uploadedFile?.path) {
                checksum = await ctx.nodeManager.localRuntime.snapshotManager.computeFileSha256(uploadedFile.path);
            }
            const tpl = await ctx.storageManager.upsertLxcTemplate({
                slug: String(req.body?.slug || ''),
                name: String(req.body?.name || ''),
                distro: String(req.body?.distro || 'ubuntu'),
                release: String(req.body?.release || '24.04'),
                arch: String(req.body?.arch || 'amd64'),
                variant: String(req.body?.variant || 'default'),
                family: String(req.body?.family || 'debian'),
                minDiskGb: Number(req.body?.minDiskGb || 5),
                minRamMb: Number(req.body?.minRamMb || 256),
                isCustom: Boolean(uploadedFile || req.body?.isCustom),
                filePath: uploadedFile?.path || null,
                checksumSha256: checksum,
                enabled: req.body?.enabled !== 'false' && req.body?.enabled !== false,
            });
            res.status(201).json({ template: tpl });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.patch('/lxc/templates/:id', (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        await ctx.storageManager.toggleLxcTemplate(pInt(req.params.id), Boolean(req.body?.enabled));
        res.json({ success: true });
    });
    router.delete('/lxc/templates/:id', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        await ctx.storageManager.deleteLxcTemplate(pInt(req.params.id));
        res.json({ success: true });
    });
    router.post('/lxc/sync-host', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (req, res) => {
        try {
            const targetNodeId = req.body?.nodeId !== undefined && req.body?.nodeId !== ''
                ? Number(req.body.nodeId)
                : undefined;
            const result = await ctx.lxcAdapter.syncHostContainers(req.principal.userId, targetNodeId);
            res.json({ success: true, ...result });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    router.post('/lxc', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (req, res) => {
        req.setTimeout(660_000);
        res.setTimeout(660_000);
        try {
            const b = req.body || {};
            const created = await ctx.lxcAdapter.createLxcInstance({
                userId: Number(b.userId || req.principal.userId),
                nodeId: b.nodeId ? Number(b.nodeId) : undefined,
                containerName: String(b.containerName || ''),
                hostname: b.hostname ? String(b.hostname) : undefined,
                templateSlug: b.templateSlug ? String(b.templateSlug) : 'ubuntu-24.04',
                cpuCores: Number(b.cpuCores || 1),
                cpuShares: Number(b.cpuShares || 1024),
                cpuLimitPercent: Number(b.cpuLimitPercent || 100),
                cpuPinning: b.cpuPinning ? String(b.cpuPinning) : null,
                ramMb: Number(b.ramMb || 1024),
                swapMb: Number(b.swapMb ?? 512),
                diskGb: Number(b.diskGb || 20),
                backingStore: b.backingStore || 'dir',
                privileged: b.privileged !== false,
                nesting: b.nesting !== false,
                kvmNesting: Boolean(b.kvmNesting),
                bridge: b.bridge ? String(b.bridge) : 'lxcbr0',
                ipv4Address: b.ipv4Address ? String(b.ipv4Address) : null,
                ipv4Gateway: b.ipv4Gateway ? String(b.ipv4Gateway) : null,
                ipv6Address: b.ipv6Address ? String(b.ipv6Address) : null,
                vlanId: b.vlanId ? Number(b.vlanId) : null,
                rootPassword: b.rootPassword ? String(b.rootPassword) : undefined,
                sshPublicKeys: Array.isArray(b.sshPublicKeys) ? b.sshPublicKeys : [],
                autostart: Boolean(b.autostart),
                bandwidthQuotaGb: Number(b.bandwidthQuotaGb || 0),
                expirationDays: Number(b.expirationDays || 0),
                autoSuspendEnabled: b.autoSuspendEnabled !== false,
                notes: b.notes ? String(b.notes) : undefined,
                provisionOnHost: b.provisionOnHost !== false,
            });
            await ctx.db
                .logActivity({
                userId: req.principal.userId,
                action: 'lxc_created',
                resourceType: 'lxc',
                resourceId: String(created.instance.refId),
                details: {
                    containerName: created.instance.name,
                    nodeId: created.instance.nodeId,
                    template: created.instance.osLabel,
                },
            })
                .catch(() => undefined);
            res.status(201).json(created);
        }
        catch (err) {
            const msg = String(err?.message || 'Failed to create LXC container');
            const status = /currently being provisioned|already exists/i.test(msg) ? 409 : 500;
            res.status(status).json({ error: msg });
        }
    });
    router.patch('/lxc/:id', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            const updated = await ctx.lxcAdapter.resizeAndUpdateConfig(refId, req.body || {}, req.body?.applyToHost !== false);
            res.json({ success: true, instance: updated });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    router.post('/lxc/:id/reinstall', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId, true);
            const out = await ctx.lxcAdapter.reinstallLxcInstance(refId, String(req.body?.templateSlug || 'ubuntu-24.04'), req.body?.rootPassword ? String(req.body.rootPassword) : undefined);
            res.json(out);
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.post('/lxc/:id/repair-network', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId, true);
            const out = await ctx.lxcAdapter.repairLxcNetworking(refId);
            await ctx.db
                .logActivity({
                userId: req.principal.userId,
                action: 'lxc_network_repaired',
                resourceType: 'lxc',
                resourceId: String(refId),
                details: out.repair,
            })
                .catch(() => undefined);
            res.json({ success: true, ...out });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.post('/lxc/:id/password', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId, true);
            const newPassword = await ctx.lxcAdapter.resetRootPassword(refId, req.body?.password ? String(req.body.password) : undefined);
            res.json({ success: true, rootPassword: newPassword });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.post('/lxc/:id/ssh-key', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId);
            await ctx.lxcAdapter.injectSshKey(refId, String(req.body?.publicKey || ''));
            res.json({ success: true });
        }
        catch (err) {
            res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    router.post('/lxc/:id/renew', (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        try {
            const updated = await ctx.lxcAdapter.renewExpiration(pInt(req.params.id), Number(req.body?.days || 30));
            res.json({ success: true, instance: updated });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.post('/lxc/:id/transfer-owner', (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        try {
            const updated = await ctx.lxcAdapter.transferOwnership(pInt(req.params.id), Number(req.body?.userId));
            res.json({ success: true, instance: updated });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.put('/lxc/:id/sharing', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId, true);
            const userIds = Array.isArray(req.body?.userIds) ? req.body.userIds.map(Number) : [];
            const updated = await ctx.lxcAdapter.updateSharing(refId, userIds);
            res.json({ success: true, instance: updated });
        }
        catch (err) {
            res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    router.get('/lxc/:id/processes', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId);
            const processes = await ctx.lxcAdapter.getProcesses(refId);
            res.json({ processes });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.get('/lxc/:id/logs', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId);
            const logs = await ctx.lxcAdapter.getLogs(refId);
            res.json({ logs });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.get('/lxc/:id/files', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId);
            const subPath = String(req.query.path || '/');
            const entries = await ctx.lxcAdapter.listFiles(refId, subPath);
            res.json({ path: subPath, entries });
        }
        catch (err) {
            res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    router.get('/lxc/:id/files/content', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId);
            const subPath = String(req.query.path || '/');
            const buf = await ctx.lxcAdapter.readFile(refId, subPath);
            res.json({
                path: subPath,
                content: buf.toString('utf8'),
                contentBase64: buf.toString('base64'),
            });
        }
        catch (err) {
            res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    router.post('/lxc/:id/files/content', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId);
            const subPath = String(req.body?.path || '');
            const buf = typeof req.body?.contentBase64 === 'string'
                ? Buffer.from(req.body.contentBase64, 'base64')
                : Buffer.from(String(req.body?.content ?? ''), 'utf8');
            await ctx.lxcAdapter.writeFile(refId, subPath, buf);
            res.json({ success: true });
        }
        catch (err) {
            res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    router.delete('/lxc/:id/files', async (req, res) => {
        try {
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', refId);
            await ctx.lxcAdapter.deleteFile(refId, String(req.query.path || ''));
            res.json({ success: true });
        }
        catch (err) {
            res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    // --- Nodes Management (Admin / Staff) ---
    router.get('/nodes', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (_req, res) => {
        const nodes = await ctx.nodeManager.listNodes();
        res.json({ nodes });
    });
    router.post('/nodes/test-connection', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const result = await ctx.nodeManager.probeEndpointConnection({
                url: String(req.body?.url || ''),
                verifySsl: req.body?.verifySsl !== false,
                timeoutMs: Number(req.body?.timeoutMs || 4000),
            });
            res.json(result);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.get('/nodes/placement', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (_req, res) => {
        const [kvm, lxc] = await Promise.all([
            ctx.nodeManager.rankPlacementCandidates('kvm'),
            ctx.nodeManager.rankPlacementCandidates('lxc'),
        ]);
        res.json({ kvm, lxc });
    });
    router.post('/nodes', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const out = await ctx.nodeManager.createNode(req.body || {});
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: 'node_created',
                resourceType: 'node',
                resourceId: String(out.node.id),
                details: { name: out.node.name, url: out.node.url },
            });
            res.status(201).json(out);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.get('/nodes/:id/detail', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (req, res) => {
        try {
            const nodeId = pInt(req.params.id);
            let node = await ctx.nodeManager.getNodeById(nodeId);
            if (!node)
                return res.status(404).json({ error: 'Node not found.' });
            let liveHealth = null;
            let liveStats = null;
            let latencyMs = node.latency_ms ?? null;
            if (req.query.live !== '0') {
                try {
                    const probe = await ctx.nodeManager.checkNodeHealthAndStats(nodeId);
                    node = probe.node;
                    liveHealth = probe.health;
                    liveStats = probe.stats;
                    latencyMs = probe.latencyMs;
                }
                catch {
                    node = (await ctx.nodeManager.getNodeById(nodeId)) || node;
                }
            }
            const [kvmRows, lxcRows, storagePools, recentMigrations] = await Promise.all([
                ctx.db
                    .all(`SELECT vm_id AS id, vm_name AS name, os_type, status,
                      COALESCE(cpus, cpu_cores, 1) AS cpu_cores,
                      COALESCE(memory, 0) AS ram_mb,
                      CAST(REPLACE(REPLACE(COALESCE(disk_size, '0'), 'G', ''), 'g', '') AS REAL) AS disk_gb,
                      ipv4_address AS ip_address
               FROM vms WHERE COALESCE(node_id, 1) = ? ORDER BY vm_id DESC`, [nodeId])
                    .catch(() => []),
                ctx.db
                    .all(`SELECT id, container_name AS name, hostname, os_template, distro, release, status,
                      COALESCE(cpu_cores, 1) AS cpu_cores,
                      COALESCE(ram_mb, 0) AS ram_mb,
                      COALESCE(disk_gb, 0) AS disk_gb,
                      ipv4_address AS ip_address
               FROM lxc_instances WHERE COALESCE(node_id, 1) = ? ORDER BY id DESC`, [nodeId])
                    .catch(() => []),
                ctx.db
                    .all(`SELECT * FROM storage_pools WHERE node_id = ? ORDER BY id ASC`, [nodeId])
                    .catch(() => []),
                ctx.db
                    .all(`SELECT m.*, sn.name AS source_node_name, tn.name AS target_node_name
               FROM vps_migrations m
               LEFT JOIN nodes sn ON sn.id = m.source_node_id
               LEFT JOIN nodes tn ON tn.id = m.target_node_id
               WHERE m.source_node_id = ? OR m.target_node_id = ?
               ORDER BY m.id DESC LIMIT 10`, [nodeId, nodeId])
                    .catch(() => []),
            ]);
            const instances = [
                ...kvmRows.map((v) => ({
                    id: v.id,
                    engine: 'kvm',
                    name: v.name,
                    osLabel: v.os_type || 'KVM Guest',
                    status: v.status || 'stopped',
                    cpuCores: Number(v.cpu_cores || 1),
                    ramMb: Number(v.ram_mb || 0),
                    diskGb: Number(v.disk_gb || 0),
                    ipAddress: v.ip_address || null,
                    manageUrl: `/admin/vm/${v.id}`,
                })),
                ...lxcRows.map((c) => ({
                    id: c.id,
                    engine: 'lxc',
                    name: c.name,
                    osLabel: c.os_template || `${c.distro || 'linux'}:${c.release || ''}`,
                    status: c.status || 'stopped',
                    cpuCores: Number(c.cpu_cores || 1),
                    ramMb: Number(c.ram_mb || 0),
                    diskGb: Number(c.disk_gb || 0),
                    ipAddress: c.ip_address || null,
                    manageUrl: `/lxc/${c.id}`,
                })),
            ];
            const parseJsonArr = (raw) => {
                if (!raw)
                    return [];
                try {
                    const p = JSON.parse(String(raw));
                    return Array.isArray(p) ? p.map(String) : [];
                }
                catch {
                    return [];
                }
            };
            return res.json({
                node: {
                    ...node,
                    parsedTags: parseJsonArr(node.tags),
                    parsedStorageBackends: parseJsonArr(node.storage_backends),
                    parsedNetworkBackends: parseJsonArr(node.network_backends),
                },
                latencyMs,
                liveHealth,
                liveStats,
                instances,
                storagePools,
                recentMigrations,
            });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    router.patch('/nodes/:id', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const nodeId = pInt(req.params.id);
            const updated = await ctx.nodeManager.updateNode(nodeId, req.body || {});
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: 'node_updated',
                resourceType: 'node',
                resourceId: String(nodeId),
                details: {
                    name: updated.name,
                    maintenanceMode: Boolean(updated.maintenance_mode),
                    maxInstances: updated.max_instances,
                },
            });
            res.json({ node: updated });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.post('/nodes/:id/reset-circuit', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const nodeId = pInt(req.params.id);
            let node = await ctx.nodeManager.resetCircuitBreaker(nodeId);
            let probeOk = false;
            if (req.body?.probe !== false) {
                try {
                    const checked = await ctx.nodeManager.checkNodeHealthAndStats(nodeId, {
                        bypassCircuit: true,
                    });
                    node = checked.node;
                    probeOk = true;
                }
                catch {
                    node = (await ctx.nodeManager.getNodeById(nodeId)) || node;
                }
            }
            res.json({ node, probeOk });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.get('/nodes/:id/bootstrap', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const nodeId = pInt(req.params.id);
            const defaultOrigin = `${req.protocol}://${req.get('host') || 'localhost:8080'}`;
            const controllerUrl = req.query.controllerUrl
                ? pStr(req.query.controllerUrl)
                : defaultOrigin;
            const out = await ctx.nodeManager.getBootstrapCredentials(nodeId, controllerUrl);
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: 'node_bootstrap_viewed',
                resourceType: 'node',
                resourceId: String(nodeId),
            });
            res.json(out);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.post('/nodes/:id/join-token', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const nodeId = pInt(req.params.id);
            const defaultOrigin = `${req.protocol}://${req.get('host') || 'localhost:8080'}`;
            const controllerUrl = String(req.body?.controllerUrl || defaultOrigin).trim();
            const ttlMinutes = req.body?.ttlMinutes ? Number(req.body.ttlMinutes) : 30;
            const out = await ctx.nodeManager.createJoinToken({
                nodeId,
                controllerUrl,
                createdByUserId: req.principal.userId,
                ttlMinutes,
            });
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: 'node_join_token_created',
                resourceType: 'node',
                resourceId: String(nodeId),
                details: { expiresAt: out.expiresAt, controllerUrl: out.controllerUrl },
            });
            res.status(201).json(out);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.post('/nodes/:id/trust-tls', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const nodeId = pInt(req.params.id);
            const out = await ctx.nodeManager.trustNodeTlsCertificate(nodeId);
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: 'node_tls_trusted',
                resourceType: 'node',
                resourceId: String(nodeId),
                details: {
                    fingerprintSha256: out.fingerprintSha256,
                    subjectCN: out.subjectCN,
                    probeOk: out.probeOk,
                },
            });
            res.json(out);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.post('/nodes/:id/evacuate-lxc', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const sourceNodeId = pInt(req.params.id);
            const targetNodeId = Number(req.body?.targetNodeId || 0);
            const targetBridge = String(req.body?.targetBridge || 'lxcbr0').trim() || 'lxcbr0';
            const cordonSource = req.body?.cordonSource !== false;
            if (!targetNodeId || targetNodeId === sourceNodeId) {
                return res.status(400).json({ error: 'Select a valid distinct target node for evacuation.' });
            }
            if (cordonSource) {
                await ctx.nodeManager.updateNode(sourceNodeId, { maintenanceMode: true });
            }
            const requestedIds = Array.isArray(req.body?.lxcIds)
                ? req.body.lxcIds.map((x) => Number(x)).filter((x) => x > 0)
                : null;
            const lxcOnSource = await ctx.db.all(`SELECT id, container_name FROM lxc_instances WHERE COALESCE(node_id, 1) = ? ORDER BY id ASC`, [sourceNodeId]);
            const targets = requestedIds
                ? lxcOnSource.filter((c) => requestedIds.includes(c.id))
                : lxcOnSource;
            const results = [];
            for (const ct of targets) {
                try {
                    const job = await ctx.migrationManager.startOfflineLxcMigration({
                        lxcId: ct.id,
                        targetNodeId,
                        targetBridge,
                        initiatedByUserId: req.principal.userId,
                    });
                    results.push({ lxcId: ct.id, name: ct.container_name, ok: job.status === 'completed', jobId: job.id });
                }
                catch (err) {
                    results.push({ lxcId: ct.id, name: ct.container_name, ok: false, error: err.message });
                }
            }
            await ctx.db.logActivity({
                userId: req.principal.userId,
                action: 'node_evacuate_lxc',
                resourceType: 'node',
                resourceId: String(sourceNodeId),
                details: {
                    targetNodeId,
                    attempted: targets.length,
                    succeeded: results.filter((r) => r.ok).length,
                },
            });
            return res.json({
                sourceNodeId,
                targetNodeId,
                cordonApplied: cordonSource,
                attempted: targets.length,
                succeeded: results.filter((r) => r.ok).length,
                failed: results.filter((r) => !r.ok).length,
                results,
            });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    router.delete('/nodes/:id', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            await ctx.nodeManager.deleteNode(pInt(req.params.id));
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.post('/nodes/:id/check', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (req, res) => {
        try {
            const nodeId = pInt(req.params.id);
            const report = await ctx.nodeManager.checkNodeHealthAndStats(nodeId, {
                bypassCircuit: true,
            });
            if (report?.stats) {
                const s = report.stats;
                await ctx.db
                    .run(`INSERT INTO metrics_history
                 (target_type, target_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, net_rx_bytes, net_tx_bytes, load_avg_1)
               VALUES ('node', ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                    nodeId,
                    s.cpuPercent,
                    s.ramUsedMb,
                    s.ramTotalMb,
                    s.diskUsedGb,
                    s.diskTotalGb,
                    s.netRxBytes,
                    s.netTxBytes,
                    s.loadAvg1,
                ])
                    .catch(() => undefined);
            }
            res.json(report);
        }
        catch (err) {
            res.status(502).json({ error: err.message });
        }
    });
    router.post('/nodes/:id/rotate-credentials', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const rotated = await ctx.nodeManager.rotateNodeCredentials(pInt(req.params.id));
            res.json(rotated);
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    router.post('/nodes/:id/diagnostics/:preset', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const nodeId = pInt(req.params.id);
            const node = await ctx.nodeManager.getNodeById(nodeId);
            if (!node)
                return res.status(404).json({ error: 'Node not found.' });
            const out = node.is_local
                ? await ctx.nodeManager.localRuntime.shellManager.runDiagnosticPreset(pStr(req.params.preset), req.principal.username)
                : await ctx.nodeManager.requestRemoteNode(nodeId, 'POST', `/api/v1/diagnostics/${encodeURIComponent(pStr(req.params.preset))}`);
            return res.json(out);
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    router.get('/nodes/:id/metrics', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (req, res) => {
        const history = await ctx.monitoringService.getMetricsHistory('node', pInt(req.params.id), Number(req.query.hours || 24));
        res.json({ history });
    });
    // --- Storage Pools ---
    router.get('/storage/pools', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (req, res) => {
        const pools = req.query.sync === '1'
            ? await ctx.storageManager.syncPoolCapacities()
            : await ctx.storageManager.listPools();
        res.json({ pools });
    });
    router.post('/storage/pools', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const pool = await ctx.storageManager.createPool(req.body || {});
            res.status(201).json({ pool });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.delete('/storage/pools/:id', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            await ctx.storageManager.deletePool(pInt(req.params.id));
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // --- Networking, Port Forwarding & Firewall ---
    router.get('/network/pools', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (_req, res) => {
        const pools = await ctx.networkManager.listNetworkPools();
        const ips = await ctx.networkManager.listIpAllocations();
        res.json({ pools, ips });
    });
    router.post('/network/pools', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const pool = await ctx.networkManager.createNetworkPool(req.body || {});
            res.status(201).json({ pool });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.post('/network/pools/:id/ips', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const rawList = Array.isArray(req.body?.ips)
                ? req.body.ips
                : String(req.body?.ips || '')
                    .split(/[\s,]+/)
                    .filter(Boolean);
            const added = await ctx.networkManager.addIpAddressesToPool(pInt(req.params.id), rawList.map((ip) => ({ ip })));
            res.json({ success: true, added });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.get('/network/ports', async (req, res) => {
        const isStaff = ctx.instanceManager.isStaff(req.principal);
        const forwards = await ctx.networkManager.listPortForwards({
            userId: isStaff && req.query.all === '1' ? undefined : req.principal.userId,
        });
        const quota = await ctx.networkManager.getUserPortAllocation(req.principal.userId);
        res.json({ forwards, quota });
    });
    router.post('/network/ports', async (req, res) => {
        try {
            const b = req.body || {};
            const engine = (b.instanceType === 'kvm' ? 'kvm' : 'lxc');
            const refId = Number(b.instanceRefId);
            const inst = await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            if (!inst.primaryIp) {
                return res
                    .status(400)
                    .json({ error: 'Instance does not have an assigned internal IPv4 address yet.' });
            }
            const result = await ctx.networkManager.createPortForward({
                userId: inst.ownerId,
                isAdmin: ctx.instanceManager.isStaff(req.principal),
                nodeId: inst.nodeId,
                instanceType: engine,
                instanceRefId: refId,
                containerOrVmName: inst.name,
                guestIp: inst.primaryIp.split('/')[0],
                guestPort: Number(b.guestPort),
                hostPort: b.hostPort ? Number(b.hostPort) : undefined,
                protocol: b.protocol || 'tcp,udp',
                description: b.description ? String(b.description) : '',
            });
            return res.status(201).json(result);
        }
        catch (err) {
            return res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    router.delete('/network/ports/:id', async (req, res) => {
        try {
            await ctx.networkManager.deletePortForward(pInt(req.params.id), req.principal.userId, ctx.instanceManager.isStaff(req.principal));
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.put('/network/port-quota/:userId', (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        await ctx.networkManager.setUserPortQuota(pInt(req.params.userId), Number(req.body?.allocatedPorts || 0));
        res.json({ success: true });
    });
    router.get('/network/firewall', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (_req, res) => {
        const rules = await ctx.networkManager.listFirewallRules();
        res.json({ rules });
    });
    router.post('/network/firewall', (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        try {
            const rule = await ctx.networkManager.createFirewallRule(req.body || {});
            res.status(201).json({ rule });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.delete('/network/firewall/:id', (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        await ctx.networkManager.deleteFirewallRule(pInt(req.params.id));
        res.json({ success: true });
    });
    // --- Unified Snapshots & Backups ---
    router.get('/snapshots/:engine/:id', async (req, res) => {
        try {
            const engine = pStr(req.params.engine);
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            const snapshots = await ctx.backupManager.listSnapshots(engine, refId);
            res.json({ snapshots });
        }
        catch (err) {
            res.status(err.statusCode || 400).json({ error: err.message });
        }
    });
    router.post('/snapshots/:engine/:id', async (req, res) => {
        try {
            const engine = pStr(req.params.engine);
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            const snapshot = await ctx.backupManager.createSnapshot({
                engine,
                refId,
                name: req.body?.name,
                description: req.body?.description,
                actorId: req.principal.userId,
            });
            res.status(201).json({ snapshot });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.post('/snapshots/:engine/:id/:snapId/restore', async (req, res) => {
        try {
            const engine = pStr(req.params.engine);
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            await ctx.backupManager.restoreSnapshot(engine, refId, pInt(req.params.snapId));
            res.json({ success: true });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.delete('/snapshots/:engine/:id/:snapId', async (req, res) => {
        try {
            const engine = pStr(req.params.engine);
            const refId = pInt(req.params.id);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            await ctx.backupManager.deleteSnapshot(engine, refId, pInt(req.params.snapId));
            res.json({ success: true });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.get('/backups', async (req, res) => {
        const engine = req.query.engine;
        const refId = req.query.refId ? Number(req.query.refId) : undefined;
        if (engine && refId) {
            await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            const backups = await ctx.backupManager.listBackups({ engine, refId });
            return res.json({ backups });
        }
        if (!ctx.instanceManager.isStaff(req.principal)) {
            return res.status(403).json({ error: 'Specify engine and refId or use staff account.' });
        }
        const backups = await ctx.backupManager.listBackups();
        return res.json({ backups });
    });
    router.post('/backups', async (req, res) => {
        try {
            const engine = (req.body?.engine === 'kvm' ? 'kvm' : 'lxc');
            const refId = Number(req.body?.refId);
            await ctx.instanceManager.getAuthorizedInstance(req.principal, engine, refId);
            const backup = await ctx.backupManager.createBackup({
                engine,
                refId,
                label: req.body?.label,
                actorId: req.principal.userId,
            });
            res.status(201).json({ backup });
        }
        catch (err) {
            res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.post('/backups/:id/verify', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (req, res) => {
        try {
            const out = await ctx.backupManager.verifyBackupIntegrity(pInt(req.params.id));
            res.json(out);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    router.post('/backups/:id/restore', async (req, res) => {
        try {
            const backupId = pInt(req.params.id);
            const bkp = await ctx.backupManager.getBackupRecord(backupId);
            if (!bkp) {
                return res.status(404).json({ error: 'Backup record not found.' });
            }
            await ctx.instanceManager.getAuthorizedInstance(req.principal, bkp.instance_type, Number(bkp.instance_ref_id));
            const out = await ctx.backupManager.restoreBackup(backupId, req.principal.userId);
            return res.json({ success: true, ...out });
        }
        catch (err) {
            return res.status(err.statusCode || 500).json({ error: err.message });
        }
    });
    router.delete('/backups/:id', (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        try {
            await ctx.backupManager.deleteBackup(pInt(req.params.id));
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // --- Offline Verified VPS Migrations ---
    router.get('/migrations', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (_req, res) => {
        const migrations = await ctx.migrationManager.listMigrations();
        res.json({ migrations });
    });
    router.post('/migrations', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const job = await ctx.migrationManager.startOfflineLxcMigration({
                lxcId: Number(req.body?.lxcId),
                targetNodeId: Number(req.body?.targetNodeId),
                targetBridge: req.body?.targetBridge,
                targetIpv4: req.body?.targetIpv4,
                targetGateway: req.body?.targetGateway,
                initiatedByUserId: req.principal.userId,
            });
            res.status(201).json({ migration: job });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    // --- Notifications, API Keys, Webhooks, Alerts & Audit Logs ---
    router.get('/notifications', async (req, res) => {
        const notifications = await ctx.monitoringService.listUserNotifications(req.principal.userId, req.query.unread === '1');
        res.json({ notifications });
    });
    router.post('/notifications/read', async (req, res) => {
        await ctx.monitoringService.markNotificationsRead(req.principal.userId, req.body?.id ? Number(req.body.id) : undefined);
        res.json({ success: true });
    });
    router.get('/api-keys', async (req, res) => {
        const isAdmin = req.principal.role === 'admin' && req.query.all === '1';
        const keys = isAdmin
            ? await ctx.db.all(`SELECT k.id, k.user_id, u.username, k.name, k.description, k.key_prefix, k.permissions, k.ip_whitelist, k.is_active, k.last_used_at, k.expires_at, k.created_at
           FROM api_keys k JOIN users u ON u.id = k.user_id ORDER BY k.id DESC`)
            : await ctx.db.all(`SELECT id, user_id, name, description, key_prefix, permissions, ip_whitelist, is_active, last_used_at, expires_at, created_at
           FROM api_keys WHERE user_id = ? ORDER BY id DESC`, [req.principal.userId]);
        res.json({ apiKeys: keys });
    });
    router.post('/api-keys', async (req, res) => {
        try {
            const name = String(req.body?.name || '').trim();
            if (!name)
                return res.status(400).json({ error: 'API key name is required.' });
            const requestedPerms = Array.isArray(req.body?.permissions)
                ? req.body.permissions
                : ['read'];
            const safePerms = requestedPerms.filter((p) => p === 'read' || p === 'write' || (p === 'admin' && req.principal.role === 'admin'));
            const pair = (0, crypto_vault_1.generateApiKeyPair)('hkvm_pat');
            const ins = await ctx.db.run(`INSERT INTO api_keys (user_id, name, description, key_prefix, key_hash, permissions, ip_whitelist, expires_at, is_active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`, [
                req.principal.userId,
                name,
                String(req.body?.description || ''),
                pair.keyPrefix,
                pair.keyHash,
                JSON.stringify(safePerms.length ? safePerms : ['read']),
                req.body?.ipWhitelist ? JSON.stringify(req.body.ipWhitelist) : null,
                req.body?.expiresAt || null,
            ]);
            return res.status(201).json({
                id: ins.lastID,
                name,
                keyPrefix: pair.keyPrefix,
                rawApiKey: pair.rawKey, // Returned ONCE at creation time
                permissions: safePerms,
            });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    router.delete('/api-keys/:id', async (req, res) => {
        const id = pInt(req.params.id);
        if (req.principal.role === 'admin') {
            await ctx.db.run(`DELETE FROM api_keys WHERE id = ?`, [id]);
        }
        else {
            await ctx.db.run(`DELETE FROM api_keys WHERE id = ? AND user_id = ?`, [
                id,
                req.principal.userId,
            ]);
        }
        res.json({ success: true });
    });
    router.get('/webhooks', (0, middleware_1.requireRole)(['admin']), async (_req, res) => {
        const webhooks = await ctx.db.all(`SELECT id, name, url, events, is_active, last_triggered_at, last_status_code, created_at FROM webhooks ORDER BY id DESC`);
        res.json({ webhooks });
    });
    router.post('/webhooks', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const name = String(req.body?.name || '').trim();
            const url = String(req.body?.url || '').trim();
            if (!name || !url.startsWith('http')) {
                return res.status(400).json({ error: 'Valid webhook name and HTTP(S) URL are required.' });
            }
            const events = Array.isArray(req.body?.events) ? req.body.events : ['*'];
            const secret = req.body?.secret ? String(req.body.secret) : crypto_1.default.randomBytes(24).toString('hex');
            const ins = await ctx.db.run(`INSERT INTO webhooks (user_id, name, url, secret_enc, events, is_active) VALUES (?, ?, ?, ?, ?, 1)`, [req.principal.userId, name, url, (0, crypto_vault_1.encryptSecret)(secret), JSON.stringify(events)]);
            return res.status(201).json({ id: ins.lastID, name, url, signingSecret: secret });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    router.delete('/webhooks/:id', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        await ctx.db.run(`DELETE FROM webhooks WHERE id = ?`, [pInt(req.params.id)]);
        res.json({ success: true });
    });
    router.get('/monitoring/overview', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (_req, res) => {
        const nodeMetrics = await ctx.db.all(`SELECT * FROM metrics_history WHERE target_type = 'node' ORDER BY id DESC LIMIT 60`);
        const alertRules = await ctx.db.all(`SELECT * FROM alert_rules ORDER BY id DESC`);
        res.json({ nodeMetrics, alertRules });
    });
    router.get('/monitoring/alerts', (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (_req, res) => {
        const rules = await ctx.db.all(`SELECT * FROM alert_rules ORDER BY id DESC`);
        res.json({ rules });
    });
    router.post('/monitoring/alerts', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        const b = req.body || {};
        const ins = await ctx.db.run(`INSERT INTO alert_rules (name, target_scope, metric, operator, threshold, severity, enabled)
         VALUES (?, ?, ?, ?, ?, ?, 1)`, [
            String(b.name || 'High Resource Alert'),
            b.targetScope === 'instance' ? 'instance' : 'node',
            String(b.metric || 'cpu_percent'),
            String(b.operator || '>='),
            Number(b.threshold || 90),
            String(b.severity || 'warning'),
        ]);
        res.status(201).json({ id: ins.lastID });
    });
    router.delete('/monitoring/alerts/:id', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        await ctx.db.run(`DELETE FROM alert_rules WHERE id = ?`, [pInt(req.params.id)]);
        res.json({ success: true });
    });
    router.get('/audit-logs', (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        const limit = Math.min(500, Math.max(10, Number(req.query.limit || 100)));
        const logs = await ctx.db.all(`SELECT a.*, u.username
         FROM activity_logs a
         LEFT JOIN users u ON u.id = a.user_id
         ORDER BY a.id DESC
         LIMIT ?`, [limit]);
        res.json({ logs });
    });
    router.post('/database/backup', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        const out = await ctx.db.createBackup('manual_admin');
        await ctx.db.logActivity({
            userId: req.principal.userId,
            action: 'database_manual_backup',
            resourceType: 'database',
            details: out,
        });
        res.json({ success: true, ...out });
    });
    router.post('/database/import-hvm', (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        try {
            const dbFilePath = path_1.default.resolve(String(req.body?.hvmDbPath || ''));
            const report = await (0, hvm_importer_1.importHvmDatabase)(ctx.db, dbFilePath);
            res.json({ success: true, report });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // --- Upstream reseller integration (Bukkit-Hosting KVM provisioning) ---
    router.use('/reseller', (0, reseller_routes_1.createResellerApiRouter)(ctx.reseller));
    return router;
}
