/**
 * REST API v1 surface for the upstream reseller integration.
 *
 * Mounted from `createApiV1Router` at `/api/v1/reseller/*`.
 *
 * Two audiences:
 *  - Customers (`requirePrincipal`): browse the store, order a server, manage
 *    the servers attached to their own panel account, see their credit.
 *  - Staff (`requireStaff`): provider configuration, catalogue sync, pricing,
 *    order queue, fleet overview, wallet grants, upstream API log.
 *
 * Every handler funnels failures through `toResellerError`, so upstream
 * provider errors (402 insufficient_balance, 503 out_of_stock, 429 rate
 * limits, ...) reach the UI as stable codes with operator-friendly copy.
 */
import { Request, Response, Router } from 'express';
import {
  ResellerError,
  ResellerService,
  toResellerError,
} from '../../services/reseller/ResellerService';
import { requirePrincipal, requireRole } from '../../security/middleware';

type Principal = { userId: number; username: string; role: string };

function principalOf(req: Request): Principal {
  const p = (req as any).principal as Principal | undefined;
  if (!p) throw new ResellerError('Authentication required.', 401, 'unauthenticated');
  return p;
}

function isStaff(role: string): boolean {
  return ['admin', 'subadmin', 'operator'].includes(String(role || '').toLowerCase());
}

function requireStaff(req: Request, res: Response, next: () => void): void {
  let p: Principal;
  try {
    p = principalOf(req);
  } catch (err) {
    res.status(401).json(toResellerError(err).toJSON());
    return;
  }
  if (!isStaff(p.role)) {
    res.status(403).json({ error: 'Insufficient role permissions', code: 'staff_only' });
    return;
  }
  next();
}

function body(req: Request): Record<string, any> {
  return (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
}

function intParam(value: unknown): number {
  const n = parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new ResellerError('A valid positive numeric id is required.', 400, 'invalid_id');
  }
  return n;
}

/**
 * Optional provider selector. Callers that omit it get the panel's default
 * provider, exactly like before multi-provider support existed.
 */
function providerParam(req: Request): number | null {
  const raw = req.query.providerId ?? (body(req) as Record<string, unknown>).providerId;
  if (raw === undefined || raw === null || raw === '') return null;
  return intParam(raw);
}

/** Wraps an async handler so rejections become consistent JSON errors. */
function wrap(
  fn: (req: Request, res: Response) => Promise<unknown>
): (req: Request, res: Response) => void {
  return (req, res) => {
    fn(req, res).catch((err) => {
      const e = toResellerError(err);
      const status = e.statusCode >= 400 && e.statusCode < 600 ? e.statusCode : 500;
      res.status(status).json(e.toJSON());
    });
  };
}

export function createResellerApiRouter(svc: ResellerService): Router {
  const router = Router();
  router.use(requirePrincipal);

  // -------------------------------------------------------------------------
  // Store & checkout (customers)
  // -------------------------------------------------------------------------

  /** Public-ish catalogue for the logged-in customer. */
  router.get(
    '/store/catalogue',
    wrap(async (_req, res) => {
      const catalogue = await svc.getStoreCatalogue();
      res.json(catalogue);
    })
  );

  /** Prices an order without buying anything (upstream `sandbox: true`). */
  router.post(
    '/store/preview',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const b = body(req);
      const outcome = await svc.previewOrder({
        userId: p.userId,
        planId: b.planId ? intParam(b.planId) : null,
        providerId: providerParam(req),
        config: b.config || null,
        os: String(b.os || ''),
        name: b.name ? String(b.name) : null,
        hostname: b.hostname ? String(b.hostname) : null,
        autoRenew: b.autoRenew === undefined ? null : !!b.autoRenew,
        voucher: b.voucher ? String(b.voucher) : null,
        sandbox: true,
      });
      res.json({
        ok: true,
        retailCents: outcome.retailCents,
        setupCents: outcome.setupCents,
        totalCents: outcome.retailCents + outcome.setupCents,
        costCents: outcome.costCents,
        upstreamPriceCents: outcome.upstreamPriceCents,
        walletBalanceCents: outcome.walletBalanceCents,
        pricing: outcome.pricing || null,
        upstreamBalance: outcome.balancePreview || null,
        requestId: outcome.requestId,
      });
    })
  );

  /**
   * Places a real order and provisions the server onto the caller's account.
   * Requires `tos` and `cancellation` (immediate-execution waiver) to be true.
   */
  router.post(
    '/store/order',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const b = body(req);
      if (!b.os) throw new ResellerError('An operating system is required.', 422, 'invalid_os');
      const outcome = await svc.placeOrder({
        userId: p.userId,
        planId: b.planId ? intParam(b.planId) : null,
        providerId: providerParam(req),
        config: b.config || null,
        os: String(b.os),
        name: b.name ? String(b.name) : null,
        hostname: b.hostname ? String(b.hostname) : null,
        password: b.password ? String(b.password) : null,
        autoRenew: b.autoRenew === undefined ? null : !!b.autoRenew,
        voucher: b.voucher ? String(b.voucher) : null,
        tos: !!b.tos,
        cancellation: !!b.cancellation,
        placedBy: null,
      });
      res.status(201).json({ ok: true, order: outcome });
    })
  );

  // -------------------------------------------------------------------------
  // Wallet (customers)
  // -------------------------------------------------------------------------

  router.get(
    '/wallet',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const balanceCents = await svc.getWalletBalance(p.userId);
      const entries = await svc.getWalletLedger(p.userId, 50);
      res.json({ balanceCents, currency: 'EUR', entries });
    })
  );

  // -------------------------------------------------------------------------
  // Cloud servers (customers + staff)
  // -------------------------------------------------------------------------

  router.get(
    '/servers',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const staff = isStaff(p.role);
      const userId = staff && req.query.userId ? intParam(req.query.userId) : staff && req.query.all === '1' ? undefined : p.userId;
      const servers = await svc.listCloudServers({
        userId,
        state: req.query.state ? String(req.query.state) : undefined,
        search: req.query.search ? String(req.query.search) : undefined,
        providerId: providerParam(req),
      });
      res.json({
        servers: servers.map((s) => svc.serializeServer(s)),
        total: servers.length,
      });
    })
  );

  router.get(
    '/servers/:id',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const server = await svc.getAuthorizedCloudServer(p, intParam(req.params.id));
      // Plaintext root credentials are never returned by default — they would
      // otherwise leak into proxies, logs and browser caches. The owner (or
      // staff) must explicitly opt in with ?credentials=1 to reveal them.
      const reveal = req.query.credentials === '1' || req.query.credentials === 'true';
      const creds = reveal ? svc.revealCredentials(server) : null;
      res.json({
        server: svc.serializeServer(server, { includeCredentials: reveal }),
        credentials: creds,
      });
    })
  );

  router.post(
    '/servers/:id/power',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id);
      const action = String(body(req).action || '').toLowerCase();
      if (!['start', 'stop', 'restart'].includes(action)) {
        throw new ResellerError('action must be start, stop or restart.', 422, 'invalid_action');
      }
      const server = await svc.serverPower(id, action as 'start' | 'stop' | 'restart', p);
      res.json({ ok: true, action, server: svc.serializeServer(server) });
    })
  );

  router.get(
    '/servers/:id/status',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id);
      const status = await svc.serverStatus(id);
      res.json({ ok: true, status });
    })
  );

  router.post(
    '/servers/:id/refresh',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id);
      const { server, status } = await svc.refreshServer(id);
      const reveal = req.query.credentials === '1' || req.query.credentials === 'true';
      res.json({
        ok: true,
        server: svc.serializeServer(server, { includeCredentials: reveal }),
        status,
      });
    })
  );

  router.get(
    '/servers/:id/console',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id);
      const { consoleUrl } = await svc.serverConsoleUrl(id);
      res.json({ ok: true, consoleUrl });
    })
  );

  router.get(
    '/servers/:id/statistics',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id);
      const raw = String(req.query.period || 'hour');
      const period = (['hour', 'day', 'week', 'month', 'year'].includes(raw)
        ? raw
        : 'hour') as 'hour' | 'day' | 'week' | 'month' | 'year';
      const stats = await svc.serverStatistics(id, period);
      res.json({ ok: true, statistics: stats });
    })
  );

  router.get(
    '/servers/:id/network',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id);
      const network = await svc.serverNetwork(id, req.query.rdns === '1');
      res.json({ ok: true, network });
    })
  );

  router.get(
    '/servers/:id/firewall',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id);
      const firewall = await svc.serverFirewall(id);
      res.json({ ok: true, firewall });
    })
  );

  router.post(
    '/servers/:id/reinstall',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id, true);
      const b = body(req);
      if (!b.os) throw new ResellerError('An operating system is required.', 422, 'invalid_os');
      if (b.confirm !== true) {
        throw new ResellerError(
          'Reinstall destroys all data on the server — send confirm: true.',
          422,
          'confirm_required'
        );
      }
      const result = await svc.serverReinstall(
        id,
        { os: String(b.os), password: b.password ? String(b.password) : undefined, confirm: true },
        p
      );
      res.json({ ok: true, ...result });
    })
  );

  router.post(
    '/servers/:id/password',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id, true);
      const password = String(body(req).password || '');
      const credentials = await svc.serverSetPassword(id, password, p);
      res.json({ ok: true, credentials });
    })
  );

  router.put(
    '/servers/:id/autorenew',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id, true);
      const b = body(req);
      const autoRenew = b.autoRenew === true || b.autoRenew === 1 || b.autoRenew === '1';
      const server = await svc.serverSetAutoRenew(id, autoRenew, p);
      res.json({ ok: true, server: svc.serializeServer(server) });
    })
  );

  router.put(
    '/servers/:id/name',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id, true);
      const server = await svc.serverRename(id, String(body(req).name || ''), p);
      res.json({ ok: true, server: svc.serializeServer(server) });
    })
  );

  router.get(
    '/servers/:id/renewal',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id, true);
      const quote = await svc.renewalQuote(id);
      res.json({ ok: true, ...quote });
    })
  );

  router.post(
    '/servers/:id/renew',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      await svc.getAuthorizedCloudServer(p, id, true);
      const result = await svc.renewServer(id, p);
      res.json({ ok: true, ...result, server: svc.serializeServer(result.server) });
    })
  );

  // -------------------------------------------------------------------------
  // Orders (customers see their own; staff see all)
  // -------------------------------------------------------------------------

  router.get(
    '/orders',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const staff = isStaff(p.role);
      const { orders, total } = await svc.listOrders({
        userId: staff && req.query.all === '1' ? undefined : p.userId,
        status: req.query.status ? String(req.query.status) : undefined,
        providerId: providerParam(req),
        limit: req.query.limit ? intParam(req.query.limit) : 50,
      });
      res.json({ orders, total, scope: staff && req.query.all === '1' ? 'all' : 'own' });
    })
  );

  router.get(
    '/orders/:id',
    wrap(async (req, res) => {
      const p = principalOf(req);
      const order = await svc.getOrder(intParam(req.params.id));
      if (!isStaff(p.role) && order.user_id !== p.userId) {
        throw new ResellerError('Access denied to this order.', 403, 'access_denied');
      }
      res.json({ order });
    })
  );

  // -------------------------------------------------------------------------
  // Staff: upstream providers (multiple reseller APIs)
  // -------------------------------------------------------------------------

  /** Every configured upstream provider with its latest health figures. */
  /**
   * Live capacity a local (own-node) provider can sell right now: nodes,
   * engines, and the standard shapes that currently fit.
   */
  router.get(
    '/admin/providers/local-capacity',
    requireStaff,
    wrap(async (_req, res) => {
      const capacity = await svc.getLocalCapacity();
      res.json({
        capacity,
        total: capacity.length,
        engines: Array.from(new Set(capacity.map((c) => c.engine))),
        nodes: Array.from(
          new Map(capacity.map((c) => [c.nodeId, { id: c.nodeId, name: c.nodeName }])).values()
        ),
      });
    })
  );

  router.get(
    '/admin/providers',
    requireStaff,
    wrap(async (req, res) => {
      const providers = await svc.getProviderSummaries({
        probeUpstream: req.query.probe === '1' || req.query.probe === 'true',
      });
      res.json({ providers, total: providers.length });
    })
  );

  router.get(
    '/admin/providers/:id',
    requireStaff,
    wrap(async (req, res) => {
      const provider = await svc.getProvider(intParam(req.params.id));
      // serializeProvider never leaks the encrypted blob or the plaintext key.
      res.json({ provider: svc.serializeProvider(provider) });
    })
  );

  /** Adds another upstream reseller API (a second provider account). */
  router.post(
    '/admin/providers',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const b = body(req);
      const provider = await svc.createProvider({
        name: String(b.name || ''),
        slug: b.slug ? String(b.slug) : null,
        provider: b.provider ? String(b.provider) : undefined,
        baseUrl: String(b.baseUrl || ''),
        apiKey: b.apiKey === undefined || b.apiKey === null ? null : String(b.apiKey),
        enabled: b.enabled === undefined ? undefined : !!b.enabled,
        storeEnabled: b.storeEnabled === undefined ? undefined : !!b.storeEnabled,
        markupPercent:
          b.markupPercent === undefined || b.markupPercent === '' ? null : Number(b.markupPercent),
        requestTimeoutMs: b.requestTimeoutMs === undefined ? undefined : Number(b.requestTimeoutMs),
        notes: b.notes ? String(b.notes) : null,
        makeDefault: b.makeDefault === true,
        actorId: p.userId,
      });
      res.status(201).json({ ok: true, provider: svc.serializeProvider(provider) });
    })
  );

  router.put(
    '/admin/providers/:id',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      const b = body(req);
      const patch: Parameters<ResellerService['updateProvider']>[1] = { actorId: p.userId };
      if (b.name !== undefined) patch.name = String(b.name);
      if (b.baseUrl !== undefined) patch.baseUrl = String(b.baseUrl);
      if (b.provider !== undefined) patch.provider = String(b.provider);
      if (b.enabled !== undefined) patch.enabled = !!b.enabled;
      if (b.storeEnabled !== undefined) patch.storeEnabled = !!b.storeEnabled;
      if (b.markupPercent !== undefined) {
        patch.markupPercent =
          b.markupPercent === null || b.markupPercent === '' ? null : Number(b.markupPercent);
      }
      if (b.requestTimeoutMs !== undefined) patch.requestTimeoutMs = Number(b.requestTimeoutMs);
      if (b.notes !== undefined) patch.notes = b.notes === null ? null : String(b.notes);
      if (b.isDefault !== undefined) patch.isDefault = !!b.isDefault;
      if (b.apiKey !== undefined) patch.apiKey = b.apiKey === null ? null : String(b.apiKey);

      const provider = await svc.updateProvider(id, patch);
      res.json({ ok: true, provider: svc.serializeProvider(provider) });
    })
  );

  /** Removes a provider that no longer has servers or open orders. */
  router.delete(
    '/admin/providers/:id',
    requireRole(['admin']),
    wrap(async (req, res) => {
      const p = principalOf(req);
      await svc.deleteProvider(intParam(req.params.id), p.userId);
      res.json({ ok: true });
    })
  );

  router.post(
    '/admin/providers/:id/default',
    requireStaff,
    wrap(async (req, res) => {
      const provider = await svc.setDefaultProvider(intParam(req.params.id));
      res.json({ ok: true, providerId: provider.id, name: provider.name, provider: svc.serializeProvider(provider) });
    })
  );

  /** Probes one provider against `GET /account` and returns its status card. */
  router.post(
    '/admin/providers/:id/test-connection',
    requireStaff,
    wrap(async (req, res) => {
      const id = intParam(req.params.id);
      const status = await svc.getStatus({ probeUpstream: true, providerId: id });
      res.json({
        ok: status.upstream.reachable,
        providerId: status.providerId,
        providerName: status.providerName,
        reachable: status.upstream.reachable,
        error: status.upstream.error,
        errorCode: status.upstream.errorCode,
        account: status.upstream.account
          ? {
              userId: status.upstream.account.userId,
              username: status.upstream.account.username,
              email: status.upstream.account.email,
              role: status.upstream.account.role,
              state: status.upstream.account.state,
              keyName: status.upstream.account.api?.keyName || null,
            }
          : null,
        balanceCents: status.upstream.balanceCents,
        currency: status.upstream.currency,
        reseller: status.upstream.reseller,
        resellerTier: status.upstream.resellerTier,
        rateLimit: status.upstream.rateLimit,
      });
    })
  );

  /** Pulls the plan/OS catalogue for one provider (or all of them). */
  router.post(
    '/admin/providers/sync',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const target = providerParam(req);
      if (target) {
        const result = await svc.syncCatalogue({ actorId: p.userId, providerId: target });
        res.json({ ok: true, results: [result] });
        return;
      }
      const providers = await svc.listProviders({ enabledOnly: true });
      const results: unknown[] = [];
      const errors: Array<{ providerId: number; name: string; error: string }> = [];
      for (const provider of providers) {
        if (!svc.resolveProviderApiKey(provider)) continue;
        try {
          results.push(await svc.syncCatalogue({ actorId: p.userId, providerId: provider.id }));
        } catch (err) {
          errors.push({
            providerId: provider.id,
            name: provider.name,
            error: toResellerError(err).message,
          });
        }
      }
      res.json({ ok: errors.length === 0, results, errors });
    })
  );

  // -------------------------------------------------------------------------
  // Staff: provider configuration, catalogue, queue, fleet, wallet
  // -------------------------------------------------------------------------

  router.get(
    '/admin/status',
    requireStaff,
    wrap(async (req, res) => {
      const status = await svc.getStatus({
        probeUpstream: req.query.probe !== '0',
        providerId: providerParam(req),
      });
      res.json(status);
    })
  );

  router.get(
    '/admin/config',
    requireStaff,
    wrap(async (_req, res) => {
      const cfg = await svc.getSettings();
      res.json({
        enabled: cfg.reseller_enabled,
        provider: cfg.reseller_provider,
        baseUrl: cfg.reseller_api_base_url,
        keyHint: cfg.reseller_api_key_hint,
        keyConfigured: !!(await svc.resolveApiKey(cfg)),
        storeEnabled: cfg.reseller_store_enabled,
        defaultMarkupPercent: cfg.reseller_default_markup_percent,
        autoRenewDefault: cfg.reseller_auto_renew_default,
        allowConfigurator: cfg.reseller_allow_configurator,
        requestTimeoutMs: cfg.reseller_request_timeout_ms,
        syncIntervalSec: cfg.reseller_sync_interval_sec,
        pollIntervalSec: cfg.reseller_poll_interval_sec,
        lowBalanceAlertCents: cfg.reseller_low_balance_alert_cents,
        tosText: cfg.reseller_tos_text,
        lastSyncAt: cfg.reseller_last_sync_at,
        upstreamAccountId: cfg.reseller_upstream_account_id,
        upstreamBalanceCents: cfg.reseller_upstream_balance_cents,
      });
    })
  );

  router.put(
    '/admin/config',
    requireRole(['admin']),
    wrap(async (req, res) => {
      const b = body(req);
      const p = principalOf(req);
      const applied: string[] = [];

      const setFlag = async (field: string, key: string) => {
        if (b[field] === undefined) return;
        await svc.setSetting(key, b[field] ? '1' : '0');
        applied.push(key);
      };
      const setNum = async (field: string, key: string, min: number, max: number) => {
        if (b[field] === undefined || b[field] === '') return;
        const n = Number(b[field]);
        if (!Number.isFinite(n)) {
          throw new ResellerError(`${field} must be a number.`, 422, 'invalid_number');
        }
        await svc.setSetting(key, String(Math.max(min, Math.min(max, Math.round(n)))));
        applied.push(key);
      };
      const setStr = async (field: string, key: string, maxLen: number) => {
        if (b[field] === undefined) return;
        await svc.setSetting(key, String(b[field] ?? '').slice(0, maxLen));
        applied.push(key);
      };

      await setFlag('enabled', 'reseller_enabled');
      await setFlag('storeEnabled', 'reseller_store_enabled');
      await setFlag('autoRenewDefault', 'reseller_auto_renew_default');
      await setFlag('allowConfigurator', 'reseller_allow_configurator');
      await setNum('defaultMarkupPercent', 'reseller_default_markup_percent', -90, 1000);
      await setNum('requestTimeoutMs', 'reseller_request_timeout_ms', 2000, 120000);
      await setNum('syncIntervalSec', 'reseller_sync_interval_sec', 300, 86400);
      await setNum('pollIntervalSec', 'reseller_poll_interval_sec', 10, 3600);
      await setNum('lowBalanceAlertCents', 'reseller_low_balance_alert_cents', 0, 100000000);
      await setStr('baseUrl', 'reseller_api_base_url', 300);
      await setStr('provider', 'reseller_provider', 60);
      await setStr('tosText', 'reseller_tos_text', 4000);

      if (b.apiKey !== undefined) {
        const key = String(b.apiKey ?? '').trim();
        if (key) {
          const { hint } = await svc.setApiKey(key);
          applied.push(`reseller_api_key_enc (${hint})`);
        } else {
          await svc.setApiKey('');
          applied.push('reseller_api_key_enc (cleared)');
        }
      }

      await svc.db.logActivity({
        userId: p.userId,
        action: 'reseller_config_update',
        resourceType: 'reseller',
        details: { applied },
      });
      res.json({ ok: true, applied });
    })
  );

  /** Verifies the stored key against `GET /account` without persisting. */
  router.post(
    '/admin/test-connection',
    requireStaff,
    wrap(async (_req, res) => {
      const status = await svc.getStatus({ probeUpstream: true });
      res.json({
        ok: status.upstream.reachable,
        reachable: status.upstream.reachable,
        error: status.upstream.error,
        errorCode: status.upstream.errorCode,
        account: status.upstream.account
          ? {
              userId: status.upstream.account.userId,
              username: status.upstream.account.username,
              email: status.upstream.account.email,
              role: status.upstream.account.role,
              state: status.upstream.account.state,
              keyName: status.upstream.account.api?.keyName || null,
            }
          : null,
        balanceCents: status.upstream.balanceCents,
        currency: status.upstream.currency,
        reseller: status.upstream.reseller,
        resellerTier: status.upstream.resellerTier,
        rateLimit: status.upstream.rateLimit,
      });
    })
  );

  router.post(
    '/admin/sync',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const result = await svc.syncCatalogue({ actorId: p.userId, providerId: providerParam(req) });
      res.json({ ok: true, ...result });
    })
  );

  router.get(
    '/admin/plans',
    requireStaff,
    wrap(async (req, res) => {
      const plans = await svc.listPlans({
        enabledOnly: false,
        cpu: req.query.cpu ? String(req.query.cpu) : undefined,
        providerId: providerParam(req),
      });
      res.json({ plans, total: plans.length });
    })
  );

  router.put(
    '/admin/plans/:id',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      const b = body(req);
      const patch: Record<string, unknown> = {};
      const strFields = ['display_name', 'description', 'cpu_label'];
      const numFields = ['retail_cents', 'retail_renew_cents', 'setup_cents', 'sort_order'];
      const boolFields = ['is_enabled', 'is_visible', 'is_popular'];
      for (const f of strFields) if (b[f] !== undefined) patch[f] = b[f] === '' ? null : String(b[f]);
      for (const f of numFields) {
        if (b[f] !== undefined && b[f] !== '') {
          const n = Number(b[f]);
          if (!Number.isFinite(n)) throw new ResellerError(`${f} must be a number.`, 422, 'invalid_number');
          patch[f] = Math.round(n);
        }
      }
      for (const f of boolFields) if (b[f] !== undefined) patch[f] = !!b[f];

      const plan = await svc.updatePlan(id, patch as any);
      await svc.db.logActivity({
        userId: p.userId,
        action: 'reseller_plan_update',
        resourceType: 'reseller_plan',
        resourceId: id,
        details: { patch },
      });
      res.json({ ok: true, plan });
    })
  );

  router.post(
    '/admin/plans/config',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const b = body(req);
      if (!b.cpu) throw new ResellerError('cpu is required.', 422, 'invalid_config');
      const plan = await svc.createConfigPlan({
        providerId: providerParam(req),
        cpu: String(b.cpu),
        cores: Number(b.cores),
        memory: Number(b.memory),
        disk: Number(b.disk),
        ipv4: b.ipv4 === undefined ? undefined : Number(b.ipv4),
        ipv6: b.ipv6 === undefined ? undefined : Number(b.ipv6),
        displayName: b.displayName ? String(b.displayName) : undefined,
        description: b.description ? String(b.description) : undefined,
        markupPercent: b.markupPercent === undefined || b.markupPercent === '' ? null : Number(b.markupPercent),
        setupCents: b.setupCents === undefined ? undefined : Number(b.setupCents),
        enable: b.enable === undefined ? true : !!b.enable,
        actorId: p.userId,
      });
      res.status(201).json({ ok: true, plan });
    })
  );

  router.get(
    '/admin/configurator',
    requireStaff,
    wrap(async (req, res) => {
      const configs = await svc.getConfigurator(
        req.query.cpu ? String(req.query.cpu) : undefined,
        providerParam(req)
      );
      res.json({ configurator: configs });
    })
  );

  router.get(
    '/admin/configurator/price',
    requireStaff,
    wrap(async (req, res) => {
      const q = req.query;
      if (!q.cpu) throw new ResellerError('cpu is required.', 422, 'invalid_config');
      const quote = await svc.getConfiguratorPrice({
        cpu: String(q.cpu),
        cores: Number(q.cores || 0),
        memory: Number(q.memory || 0),
        disk: Number(q.disk || 0),
        ipv4: q.ipv4 === undefined ? undefined : Number(q.ipv4),
        ipv6: q.ipv6 === undefined ? undefined : Number(q.ipv6),
        markupPercent: q.markup === undefined || q.markup === '' ? null : Number(q.markup),
        providerId: providerParam(req),
      });
      res.json(quote);
    })
  );

  router.get(
    '/admin/os-images',
    requireStaff,
    wrap(async (req, res) => {
      const images = await svc.listOsImages({ enabledOnly: false, providerId: providerParam(req) });
      res.json({ osImages: images });
    })
  );

  router.get(
    '/admin/orders',
    requireStaff,
    wrap(async (req, res) => {
      const { orders, total } = await svc.listOrders({
        status: req.query.status ? String(req.query.status) : undefined,
        providerId: providerParam(req),
        limit: req.query.limit ? intParam(req.query.limit) : 100,
        offset: req.query.offset ? Math.max(0, intParam(req.query.offset) - 1) : 0,
      });
      res.json({ orders, total });
    })
  );

  router.post(
    '/admin/orders/:id/retry',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const id = intParam(req.params.id);
      const outcome = await svc.retryOrder(id);
      await svc.db.logActivity({
        userId: p.userId,
        action: 'reseller_order_retry',
        resourceType: 'reseller_order',
        resourceId: id,
        details: { status: outcome.status },
      });
      res.json({ ok: true, order: outcome });
    })
  );

  router.post(
    '/admin/orders/:id/cancel',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      await svc.cancelOrder(intParam(req.params.id), p.userId);
      res.json({ ok: true });
    })
  );

  /** Admin places an order on behalf of a customer (wallet, free or manual). */
  router.post(
    '/admin/orders',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const b = body(req);
      const userId = intParam(b.userId);
      const paymentMode = ['wallet', 'free', 'manual'].includes(String(b.paymentMode))
        ? (String(b.paymentMode) as 'wallet' | 'free' | 'manual')
        : 'wallet';
      const outcome = await svc.placeOrder({
        userId,
        planId: b.planId ? intParam(b.planId) : null,
        providerId: providerParam(req),
        config: b.config || null,
        os: String(b.os || ''),
        name: b.name ? String(b.name) : null,
        hostname: b.hostname ? String(b.hostname) : null,
        password: b.password ? String(b.password) : null,
        autoRenew: b.autoRenew === undefined ? null : !!b.autoRenew,
        tos: true,
        cancellation: true,
        placedBy: p.userId,
        paymentMode,
        notes: b.notes ? String(b.notes) : null,
      });
      res.status(201).json({ ok: true, order: outcome });
    })
  );

  router.get(
    '/admin/servers',
    requireStaff,
    wrap(async (req, res) => {
      const servers = await svc.listCloudServers({
        state: req.query.state ? String(req.query.state) : undefined,
        search: req.query.search ? String(req.query.search) : undefined,
        providerId: providerParam(req),
        limit: req.query.limit ? intParam(req.query.limit) : 200,
      });
      res.json({ servers: servers.map((s) => svc.serializeServer(s)), total: servers.length });
    })
  );

  router.post(
    '/admin/servers/:id/suspend',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const b = body(req);
      const server = await svc.setSuspension(
        intParam(req.params.id),
        b.suspend !== false,
        b.reason ? String(b.reason) : null,
        p
      );
      res.json({ ok: true, server: svc.serializeServer(server) });
    })
  );

  router.post(
    '/admin/servers/:id/unsuspend',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const server = await svc.setSuspension(intParam(req.params.id), false, null, p);
      res.json({ ok: true, server: svc.serializeServer(server) });
    })
  );

  router.post(
    '/admin/servers/:id/renew',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const result = await svc.renewServer(intParam(req.params.id), p);
      res.json({ ok: true, ...result, server: svc.serializeServer(result.server) });
    })
  );

  router.get(
    '/admin/wallet/:userId',
    requireStaff,
    wrap(async (req, res) => {
      const userId = intParam(req.params.userId);
      const balanceCents = await svc.getWalletBalance(userId);
      const entries = await svc.getWalletLedger(userId, 100);
      res.json({ userId, balanceCents, currency: 'EUR', entries });
    })
  );

  router.post(
    '/admin/wallet/:userId/adjust',
    requireStaff,
    wrap(async (req, res) => {
      const p = principalOf(req);
      const userId = intParam(req.params.userId);
      const b = body(req);
      const amountCents = Math.round(Number(b.amountCents));
      if (!Number.isFinite(amountCents) || amountCents === 0) {
        throw new ResellerError('amountCents must be a non-zero integer.', 422, 'invalid_amount');
      }
      const kind = ['credit', 'debit', 'refund', 'adjustment'].includes(String(b.kind))
        ? (String(b.kind) as 'credit' | 'debit' | 'refund' | 'adjustment')
        : amountCents > 0
          ? 'credit'
          : 'debit';
      const result = await svc.adjustWallet({
        userId,
        amountCents,
        kind,
        description: b.description ? String(b.description) : undefined,
        actorId: p.userId,
      });
      res.json({ ok: true, ...result });
    })
  );

  /** Runs one reconciliation pass now (orders queue + server states). */
  router.post(
    '/admin/sync-loop',
    requireStaff,
    wrap(async (_req, res) => {
      const result = await svc.syncLoop();
      res.json({ ok: true, ...result });
    })
  );

  router.get(
    '/admin/logs',
    requireStaff,
    wrap(async (req, res) => {
      const logs = await svc.listApiLogs(
        req.query.limit ? intParam(req.query.limit) : 50,
        providerParam(req)
      );
      res.json({ logs });
    })
  );

  return router;
}
