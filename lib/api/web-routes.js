"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createUnifiedWebRouter = createUnifiedWebRouter;
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
const express_1 = require("express");
const health_1 = require("../node-agent/health");
const crypto_vault_1 = require("../security/crypto-vault");
const middleware_1 = require("../security/middleware");
function createUnifiedWebRouter(ctx, getLicenseSummary) {
    const router = (0, express_1.Router)();
    const pInt = (v) => parseInt(Array.isArray(v) ? v[0] || '0' : v || '0', 10);
    router.use(async (_req, res, next) => {
        res.locals.panelVersion = process.env.PANEL_VERSION || 'V3.0';
        res.locals.siteLogo = res.locals.siteLogo || '/images/logo.png';
        res.locals.siteName =
            res.locals.siteName && !/^hkvm(\s+panel)?(\s+v[\d.]+)?$/i.test(String(res.locals.siteName).trim())
                ? res.locals.siteName
                : 'TGVPANEL';
        try {
            const logoRow = await ctx.db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_logo'`);
            if (logoRow?.setting_value)
                res.locals.siteLogo = logoRow.setting_value;
            const nameRow = await ctx.db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_name'`);
            if (nameRow?.setting_value) {
                const dbSiteName = String(nameRow.setting_value).trim();
                res.locals.siteName = /^hkvm(\s+panel)?(\s+v[\d.]+)?$/i.test(dbSiteName)
                    ? 'TGVPANEL'
                    : nameRow.setting_value;
            }
        }
        catch {
            // fallback defaults
        }
        next();
    });
    // --- 2FA Login Step (Session has pending2faUser set during /api/login) ---
    router.get('/login/2fa', (req, res) => {
        const sess = req.session;
        if (!sess?.pending2faUser) {
            return res.redirect('/login');
        }
        return res.render('users/login-2fa', {
            title: 'Two-Factor Verification - TGVPANEL',
            username: sess.pending2faUser.username,
        });
    });
    router.post('/api/login/2fa', async (req, res) => {
        try {
            const sess = req.session;
            const pending = sess?.pending2faUser;
            if (!pending?.id) {
                return res.status(400).json({ error: 'No pending 2FA login session. Please log in again.' });
            }
            const row = await ctx.db.get(`SELECT * FROM users WHERE id = ?`, [pending.id]);
            if (!row?.two_factor_secret_enc) {
                return res.status(400).json({ error: '2FA configuration missing on account.' });
            }
            const secret = (0, crypto_vault_1.decryptSecret)(row.two_factor_secret_enc);
            if (!(0, crypto_vault_1.verifyTotpCode)(secret, String(req.body?.code || ''))) {
                return res.status(401).json({ error: 'Invalid 6-digit verification code.' });
            }
            delete sess.pending2faUser;
            sess.user = pending;
            sess.userId = pending.id;
            sess.username = pending.username;
            sess.role = pending.role;
            await ctx.db.logActivity({
                userId: row.id,
                action: 'user_login_2fa_verified',
                resourceType: 'user',
                resourceId: String(row.id),
                ipAddress: req.ip || null,
            });
            const redirectUrl = row.role === 'admin' ? '/admin/dashboard' : '/dashboard';
            return res.json({ success: true, user: sess.user, redirectUrl });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    // --- Compatibility Endpoints Expected by Existing HKVM V2 Admin Dashboard ---
    router.get('/api/admin/activity', middleware_1.requirePrincipal, (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']), async (_req, res) => {
        const rows = await ctx.db.all(`SELECT a.*, u.username
         FROM activity_logs a
         LEFT JOIN users u ON u.id = a.user_id
         ORDER BY a.id DESC
         LIMIT 20`);
        const activities = rows.map((r) => ({
            id: r.id,
            type: String(r.action || '').includes('start')
                ? 'start'
                : String(r.action || '').includes('stop')
                    ? 'stop'
                    : String(r.action || '').includes('delete')
                        ? 'delete'
                        : String(r.action || '').includes('login')
                            ? 'login'
                            : 'create',
            title: r.action.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
            description: `${r.username || 'System'} • ${r.resource_type || 'system'} ${r.resource_id || ''}`.trim(),
            timestamp: r.created_at,
        }));
        res.json({ activities });
    });
    router.get('/api/system/status', middleware_1.requirePrincipal, async (_req, res) => {
        const stats = await ctx.nodeManager.localRuntime.statsCollector.collect();
        const health = await (0, health_1.getNodeHealthReport)();
        res.json({
            status: health.status,
            cpu: `${stats.cpuPercent}% (${stats.cpuCores} cores)`,
            memory: `${stats.ramUsedMb} / ${stats.ramTotalMb} MB (${stats.ramPercent}%)`,
            disk: `${stats.diskUsedGb} / ${stats.diskTotalGb} GB (${stats.diskPercent}%)`,
            uptime: stats.uptimeSeconds,
            capabilities: health.capabilities,
            warnings: health.warnings,
        });
    });
    // --- ISO Library Management API ---
    router.get('/api/isos', middleware_1.requirePrincipal, (_req, res) => {
        const isoDir = path_1.default.join(os_1.default.homedir(), 'vms', 'iso');
        fs_1.default.mkdirSync(isoDir, { recursive: true });
        const files = fs_1.default
            .readdirSync(isoDir)
            .filter((f) => f.toLowerCase().endsWith('.iso'))
            .map((name) => {
            const st = fs_1.default.statSync(path_1.default.join(isoDir, name));
            return { name, size: st.size, modifiedAt: st.mtime.toISOString() };
        });
        res.json({ isos: files });
    });
    router.delete('/api/isos/:name', middleware_1.requirePrincipal, (0, middleware_1.requireRole)(['admin', 'subadmin']), (req, res) => {
        const rawName = Array.isArray(req.params.name) ? req.params.name[0] : req.params.name || '';
        const cleanName = path_1.default.basename(rawName);
        if (!cleanName.toLowerCase().endsWith('.iso')) {
            return res.status(400).json({ error: 'Invalid ISO filename.' });
        }
        const target = path_1.default.join(os_1.default.homedir(), 'vms', 'iso', cleanName);
        if (fs_1.default.existsSync(target))
            fs_1.default.unlinkSync(target);
        return res.json({ success: true });
    });
    // --- Unified Admin Pages (23-Item Sidebar) ---
    const adminStaffGuard = [
        middleware_1.requirePrincipal,
        (0, middleware_1.requireRole)(['admin', 'subadmin', 'operator']),
    ];
    router.get('/admin/instances', ...adminStaffGuard, async (req, res) => {
        const nodes = await ctx.nodeManager.listNodes();
        res.render('admin/unified-page', {
            title: 'Unified Instances - TGVPANEL',
            currentPage: 'instances',
            section: 'instances',
            user: res.locals.user || req.session?.user,
            nodes,
        });
    });
    router.get('/admin/lxc', ...adminStaffGuard, async (req, res) => {
        const [nodes, templates, users] = await Promise.all([
            ctx.nodeManager.listNodes(),
            ctx.storageManager.listLxcTemplates(false),
            ctx.db.all(`SELECT id, username, role FROM users ORDER BY username ASC`),
        ]);
        res.render('admin/unified-page', {
            title: 'LXC Containers - TGVPANEL',
            currentPage: 'lxc',
            section: 'lxc',
            user: res.locals.user || req.session?.user,
            nodes,
            templates,
            users,
        });
    });
    router.get('/admin/instances/create', middleware_1.requirePrincipal, (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        const [nodes, templates, users, health, networkPools] = await Promise.all([
            ctx.nodeManager.listNodes(),
            ctx.storageManager.listLxcTemplates(false),
            ctx.db.all(`SELECT id, username FROM users ORDER BY username ASC`),
            (0, health_1.getNodeHealthReport)(),
            ctx.networkManager.listNetworkPools().catch(() => []),
        ]);
        res.render('admin/unified-page', {
            title: 'Deploy LXC Container - TGVPANEL',
            currentPage: 'instances-create',
            section: 'instances-create',
            user: res.locals.user || req.session?.user,
            nodes,
            templates,
            users,
            networkPools,
            capabilities: health.capabilities,
        });
    });
    router.get('/admin/nodes', ...adminStaffGuard, async (req, res) => {
        const health = await (0, health_1.getNodeHealthReport)();
        res.render('admin/unified-page', {
            title: 'Nodes Management - TGVPANEL',
            currentPage: 'nodes',
            section: 'nodes',
            user: res.locals.user || req.session?.user,
            capabilities: health.capabilities,
        });
    });
    router.get('/admin/storage', ...adminStaffGuard, async (req, res) => {
        const nodes = await ctx.nodeManager.listNodes();
        res.render('admin/unified-page', {
            title: 'Storage Pools & Volumes - TGVPANEL',
            currentPage: 'storage',
            section: 'storage',
            user: res.locals.user || req.session?.user,
            nodes,
        });
    });
    router.get('/admin/isos', ...adminStaffGuard, async (req, res) => {
        res.render('admin/unified-page', {
            title: 'ISO Library - TGVPANEL',
            currentPage: 'isos',
            section: 'isos',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/admin/lxc-templates', ...adminStaffGuard, async (req, res) => {
        res.render('admin/unified-page', {
            title: 'LXC OS Templates - TGVPANEL',
            currentPage: 'lxc-templates',
            section: 'lxc-templates',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/admin/networking', ...adminStaffGuard, async (req, res) => {
        const nodes = await ctx.nodeManager.listNodes();
        res.render('admin/unified-page', {
            title: 'Networking & IP Pools - TGVPANEL',
            currentPage: 'networking',
            section: 'networking',
            user: res.locals.user || req.session?.user,
            nodes,
        });
    });
    router.get('/admin/ports', ...adminStaffGuard, async (req, res) => {
        const users = await ctx.db.all(`SELECT u.id, u.username, COALESCE(p.allocated_ports, 10) AS allocated_ports, COALESCE(p.used_ports, 0) AS used_ports
       FROM users u LEFT JOIN port_allocations p ON p.user_id = u.id ORDER BY u.id ASC`);
        res.render('admin/unified-page', {
            title: 'Port Forwarding & Quotas - TGVPANEL',
            currentPage: 'ports',
            section: 'ports',
            user: res.locals.user || req.session?.user,
            users,
        });
    });
    router.get('/admin/firewall', ...adminStaffGuard, async (req, res) => {
        const nodes = await ctx.nodeManager.listNodes();
        res.render('admin/unified-page', {
            title: 'Firewall Rules - TGVPANEL',
            currentPage: 'firewall',
            section: 'firewall',
            user: res.locals.user || req.session?.user,
            nodes,
        });
    });
    router.get('/admin/snapshots', ...adminStaffGuard, async (req, res) => {
        res.render('admin/unified-page', {
            title: 'Unified Snapshots - TGVPANEL',
            currentPage: 'snapshots',
            section: 'snapshots',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/admin/backups', ...adminStaffGuard, async (req, res) => {
        res.render('admin/unified-page', {
            title: 'Backups & Integrity - TGVPANEL',
            currentPage: 'backups',
            section: 'backups',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/admin/migrations', ...adminStaffGuard, async (req, res) => {
        const nodes = await ctx.nodeManager.listNodes();
        res.render('admin/unified-page', {
            title: 'VPS Migrations (Offline Verified) - TGVPANEL',
            currentPage: 'migrations',
            section: 'migrations',
            user: res.locals.user || req.session?.user,
            nodes,
        });
    });
    router.get('/admin/monitoring', ...adminStaffGuard, async (req, res) => {
        const nodes = await ctx.nodeManager.listNodes();
        res.render('admin/unified-page', {
            title: 'Live & Historical Monitoring - TGVPANEL',
            currentPage: 'monitoring',
            section: 'monitoring',
            user: res.locals.user || req.session?.user,
            nodes,
        });
    });
    router.get('/admin/api-keys', middleware_1.requirePrincipal, (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        res.render('admin/unified-page', {
            title: 'API Keys & Webhooks - TGVPANEL',
            currentPage: 'api-keys',
            section: 'api-keys',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/admin/audit-logs', middleware_1.requirePrincipal, (0, middleware_1.requireRole)(['admin', 'subadmin']), async (req, res) => {
        res.render('admin/unified-page', {
            title: 'Security & Activity Audit Logs - TGVPANEL',
            currentPage: 'audit-logs',
            section: 'audit-logs',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/admin/node-console', middleware_1.requirePrincipal, (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        const nodes = await ctx.nodeManager.listNodes();
        res.render('admin/unified-page', {
            title: 'Node Diagnostic & Host Console - TGVPANEL',
            currentPage: 'node-console',
            section: 'node-console',
            user: res.locals.user || req.session?.user,
            nodes,
            interactiveEnabled: ctx.nodeManager.localRuntime.shellManager.isInteractiveShellEnabled(),
        });
    });
    router.get('/admin/license', middleware_1.requirePrincipal, (0, middleware_1.requireRole)(['admin']), async (req, res) => {
        const [nodeAgg, kvmRow, lxcRow, userRow, poolRow, keyRow, hookRow, migVerRow,] = await Promise.all([
            ctx.db.get(`SELECT COUNT(*) AS total, SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS online FROM nodes`),
            ctx.db.get(`SELECT COUNT(*) AS cnt FROM vms`).catch(() => ({ cnt: 0 })),
            ctx.db.get(`SELECT COUNT(*) AS cnt FROM lxc_instances`).catch(() => ({ cnt: 0 })),
            ctx.db.get(`SELECT COUNT(*) AS cnt FROM users`).catch(() => ({ cnt: 0 })),
            ctx.db.get(`SELECT COUNT(*) AS cnt FROM storage_pools`).catch(() => ({ cnt: 0 })),
            ctx.db.get(`SELECT COUNT(*) AS cnt FROM api_keys`).catch(() => ({ cnt: 0 })),
            ctx.db.get(`SELECT COUNT(*) AS cnt FROM webhooks WHERE is_active = 1`).catch(() => ({ cnt: 0 })),
            ctx.db.get(`SELECT MAX(version) AS max_v FROM schema_migrations`).catch(() => ({ max_v: 10 })),
        ]);
        const licenseStats = {
            nodesTotal: Number(nodeAgg?.total || 1),
            nodesOnline: Number(nodeAgg?.online || 0),
            kvmCount: Number(kvmRow?.cnt || 0),
            lxcCount: Number(lxcRow?.cnt || 0),
            usersCount: Number(userRow?.cnt || 0),
            poolsCount: Number(poolRow?.cnt || 0),
            apiKeysCount: Number(keyRow?.cnt || 0),
            webhooksCount: Number(hookRow?.cnt || 0),
            schemaVersion: `v${String(migVerRow?.max_v || 10).padStart(3, '0')}`,
            nodeJsVersion: process.version,
            platformArch: `${process.platform} / ${process.arch}`,
            uptimeSec: Math.floor(process.uptime()),
        };
        res.render('admin/unified-page', {
            title: 'Edition & License Status - TGVPANEL',
            currentPage: 'license',
            section: 'license',
            user: res.locals.user || req.session?.user,
            licenseInfo: getLicenseSummary ? getLicenseSummary() : { edition: 'TGVPANEL V3 Free Unified Edition', valid: true },
            licenseStats,
        });
    });
    // --- Unified User Panel Pages (Part 18) ---
    router.get('/instances', middleware_1.requirePrincipal, async (req, res) => {
        res.render('users/unified-user-page', {
            title: 'My Instances (KVM & LXC) - TGVPANEL',
            currentPage: 'instances',
            section: 'instances',
            defaultEngine: '',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/lxc', middleware_1.requirePrincipal, async (req, res) => {
        res.render('users/unified-user-page', {
            title: 'My LXC Containers - TGVPANEL',
            currentPage: 'lxc',
            section: 'instances',
            defaultEngine: 'lxc',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/ports', middleware_1.requirePrincipal, async (req, res) => {
        res.render('users/unified-user-page', {
            title: 'NAT Port Forwarding - TGVPANEL',
            currentPage: 'ports',
            section: 'ports',
            user: res.locals.user || req.session?.user,
        });
    });
    router.get('/security', middleware_1.requirePrincipal, async (req, res) => {
        const dbUser = await ctx.db.get(`SELECT two_factor_enabled FROM users WHERE id = ?`, [req.principal.userId]);
        res.render('users/unified-user-page', {
            title: 'Security, 2FA & API Keys - TGVPANEL',
            currentPage: 'security',
            section: 'security',
            user: res.locals.user || req.session?.user,
            twoFactorEnabled: Boolean(dbUser?.two_factor_enabled),
        });
    });
    router.get('/lxc/:id', middleware_1.requirePrincipal, async (req, res) => {
        try {
            const lxcId = pInt(req.params.id);
            const instance = await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', lxcId);
            const templates = await ctx.storageManager.listLxcTemplates(false);
            const rawRow = await ctx.lxcAdapter.getRawLxcRow(lxcId);
            const lxcConfig = rawRow
                ? {
                    arch: rawRow.arch || 'amd64',
                    osFamily: rawRow.os_family || 'linux',
                    backingStore: rawRow.rootfs_storage_type || 'dir',
                    cpuLimitPercent: Number(rawRow.cpu_limit_pct || 100),
                    cpuShares: Number(rawRow.cpu_shares || 1024),
                    cpuPinning: rawRow.cpu_pinning || '',
                    bridge: rawRow.bridge || 'lxcbr0',
                    ipAddress: rawRow.ip_address || '',
                    gateway: rawRow.gateway || '',
                    ipv6Address: rawRow.ipv6_address || '',
                    macAddress: rawRow.mac_address || '',
                    vlanId: rawRow.vlan_id || null,
                    bandwidthQuotaGb: Number(rawRow.bandwidth_quota_gb || 0),
                    snapshotLimit: Number(rawRow.snapshot_limit || 5),
                    privileged: Boolean(rawRow.privileged),
                    nesting: Boolean(rawRow.nesting),
                    kvmNesting: Boolean(rawRow.kvm_nesting),
                    autostart: Boolean(rawRow.autostart),
                    notes: rawRow.notes || '',
                }
                : null;
            return res.render('users/lxc-detail', {
                title: `${instance.name} (LXC VPS) - TGVPANEL`,
                currentPage: 'instances',
                user: res.locals.user || req.session?.user,
                instance,
                lxcConfig,
                hostKvmAvailable: fs_1.default.existsSync('/dev/kvm'),
                templates,
                isStaff: ctx.instanceManager.isStaff(req.principal),
            });
        }
        catch (err) {
            return res.status(err.statusCode || 404).render('users/404', {
                message: err.message || 'LXC Container not found',
            });
        }
    });
    router.get('/lxc/:id/console', middleware_1.requirePrincipal, async (req, res) => {
        try {
            const lxcId = pInt(req.params.id);
            const instance = await ctx.instanceManager.getAuthorizedInstance(req.principal, 'lxc', lxcId);
            return res.render('users/lxc-console', {
                title: `Console: ${instance.name} - TGVPANEL`,
                currentPage: 'instances',
                user: res.locals.user || req.session?.user,
                instance,
            });
        }
        catch (err) {
            return res.status(err.statusCode || 404).render('users/404', {
                message: err.message || 'LXC Console unavailable',
            });
        }
    });
    // ===========================================================================
    // Upstream Reseller (Bukkit-Hosting) — storefront, customer cloud, admin
    // ===========================================================================
    /**
     * Customer storefront: browse enabled plans grouped by CPU family, pick an
     * OS and order. The actual purchase happens client-side against
     * POST /api/v1/reseller/store/order so the buyer sees live pricing first.
     */
    router.get('/store', middleware_1.requirePrincipal, async (req, res) => {
        try {
            const sess = req.session;
            const principal = req.principal;
            const [catalogue, balanceCents] = await Promise.all([
                ctx.reseller.getStoreCatalogue(),
                principal
                    ? ctx.reseller.getWalletBalance(principal.userId).catch(() => 0)
                    : Promise.resolve(0),
            ]);
            return res.render('users/store', {
                title: 'Server Store - TGVPANEL',
                currentPage: 'store',
                user: res.locals.user || sess?.user || { username: sess?.username, role: sess?.role },
                catalogue,
                balanceCents,
                resellerReady: catalogue.enabled && catalogue.groups.length > 0,
            });
        }
        catch (err) {
            return res.status(500).render('users/404', {
                message: err?.message || 'Store unavailable',
            });
        }
    });
    /** Customer's upstream (cloud) servers. */
    router.get('/cloud', middleware_1.requirePrincipal, async (req, res) => {
        const sess = req.session;
        const principal = req.principal;
        const servers = principal
            ? await ctx.reseller.listCloudServers({ userId: principal.userId })
            : [];
        const balanceCents = principal ? await ctx.reseller.getWalletBalance(principal.userId) : 0;
        return res.render('users/cloud', {
            title: 'My Cloud Servers - TGVPANEL',
            currentPage: 'cloud',
            user: res.locals.user || sess?.user || { username: sess?.username, role: sess?.role },
            servers: servers.map((s) => ctx.reseller.serializeServer(s)),
            balanceCents,
        });
    });
    /** Single upstream server: power, console, credentials, network, renewal. */
    router.get('/cloud/:id', middleware_1.requirePrincipal, async (req, res) => {
        const sess = req.session;
        const principal = req.principal;
        const id = parseInt(String(req.params.id), 10);
        try {
            if (!Number.isFinite(id) || id <= 0)
                throw Object.assign(new Error('Not found'), { statusCode: 404 });
            const server = await ctx.reseller.getAuthorizedCloudServer(principal, id);
            const osImages = await ctx.reseller.listOsImages({ enabledOnly: true });
            const balanceCents = await ctx.reseller.getWalletBalance(server.user_id);
            const isOwner = principal?.userId === server.user_id;
            return res.render('users/cloud-detail', {
                title: `${server.name} - TGVPANEL`,
                currentPage: 'cloud',
                user: res.locals.user || sess?.user || { username: sess?.username, role: sess?.role },
                // The stored root password is embedded in the page only for the owner;
                // staff get the management UI but must reveal credentials explicitly.
                server: ctx.reseller.serializeServer(server, { includeCredentials: isOwner }),
                osImages,
                balanceCents,
                isOwner,
            });
        }
        catch (err) {
            return res.status(err.statusCode || 404).render('users/404', {
                message: err.message || 'Cloud server unavailable',
            });
        }
    });
    /**
     * Admin reseller console: provider config, catalogue + pricing, order queue,
     * fleet, customer wallets and the raw upstream API log.
     */
    router.get('/admin/reseller', ...adminStaffGuard, async (req, res) => {
        const sess = req.session;
        const status = await ctx.reseller
            .getStatus({ probeUpstream: req.query.probe !== '0' })
            .catch(() => null);
        const plans = await ctx.reseller.listPlans({ enabledOnly: false }).catch(() => []);
        const osImages = await ctx.reseller.listOsImages({ enabledOnly: false }).catch(() => []);
        const orders = await ctx.reseller.listOrders({ limit: 50 }).catch(() => ({ orders: [], total: 0 }));
        const servers = await ctx.reseller.listCloudServers({ limit: 200 }).catch(() => []);
        const users = await ctx.db
            .all(`SELECT id, username, email, role FROM users WHERE is_active = 1 ORDER BY username`)
            .catch(() => []);
        const wallets = await ctx.db
            .all(`SELECT user_id, COALESCE(SUM(delta_cents), 0) AS balance_cents
         FROM reseller_wallet_ledger GROUP BY user_id`)
            .catch(() => []);
        return res.render('admin/reseller', {
            title: 'Reseller & Upstream Provisioning - TGVPANEL',
            currentPage: 'reseller',
            cp: 'reseller',
            section: 'reseller',
            pageName: 'reseller',
            pageTitle: 'Reseller & Upstream Provisioning - TGVPANEL',
            user: res.locals.user || sess?.user || { username: sess?.username, role: sess?.role },
            status,
            plans,
            osImages,
            orders: orders.orders,
            ordersTotal: orders.total,
            servers: servers.map((s) => ctx.reseller.serializeServer(s)),
            users,
            wallets,
        });
    });
    return router;
}
