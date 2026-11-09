/**
 * ResellerService — sells upstream KVM servers (Bukkit-Hosting reseller API)
 * through TGVPANEL and provisions them onto a local panel user instantly.
 *
 * Design notes
 * ------------
 * 1. Money is integer cents everywhere. The provider speaks "12.50" strings;
 *    we convert at the boundary and never do float arithmetic on prices.
 * 2. Ordering is idempotent. The `Idempotency-Key` is generated and persisted
 *    BEFORE the upstream call, so a timeout, a crash or a double-click replays
 *    the stored provider response instead of buying (and charging) twice.
 * 3. The customer wallet is a ledger, not a counter. Balance = SUM(delta),
 *    which makes every cent traceable to a grant or an order and keeps the
 *    debit race-free inside `BEGIN IMMEDIATE`.
 * 4. Provisioning is asynchronous upstream: an order returns `state: install`
 *    with credentials immediately, and IP addresses only appear once the
 *    server reaches `state: active`. A poller reconciles that in the
 *    background and notifies the customer when the server is ready.
 * 5. Nothing in here trusts the network: every upstream failure is classified
 *    as retryable (queued) or terminal (order failed, wallet untouched).
 */
import { UnifiedDatabase } from '../../db/database';
import { decryptSecret, encryptSecret } from '../../security/crypto-vault';
import {
  ResellerApiClient,
  ResellerApiLogEntry,
  UpstreamApiError,
  buildIdempotencyKey,
  centsToMoney,
  emptyRateLimit,
  moneyToCents,
} from './client';
import {
  CloudServerRow,
  ResellerOsRow,
  ResellerPlanRow,
  UpstreamAccount,
  UpstreamFirewall,
  UpstreamKvmConfigurator,
  UpstreamKvmConfiguratorPrice,
  UpstreamKvmNetwork,
  UpstreamKvmOrderInput,
  UpstreamKvmOrderResult,
  UpstreamKvmOs,
  UpstreamKvmPlan,
  UpstreamKvmServerDetail,
  UpstreamKvmStatistics,
  UpstreamKvmStatus,
  UpstreamRateLimitInfo,
  UpstreamRenewQuote,
  UpstreamResellerInfo,
  WalletEntryRow,
} from './types';

// ---------------------------------------------------------------------------
// Errors surfaced to routes / UI
// ---------------------------------------------------------------------------

export class ResellerError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly details: Record<string, unknown>;

  constructor(
    message: string,
    statusCode = 400,
    code = 'reseller_error',
    details: Record<string, unknown> = {}
  ) {
    super(message);
    this.name = 'ResellerError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }

  toJSON() {
    return { error: this.message, code: this.code, ...this.details };
  }
}

/** Converts any thrown value into something a route can render safely. */
export function toResellerError(err: unknown): ResellerError {
  if (err instanceof ResellerError) return err;
  if (err instanceof UpstreamApiError) {
    const status = err.statusCode >= 400 && err.statusCode < 600 ? err.statusCode : 502;
    return new ResellerError(humanizeUpstreamError(err), status, err.code, {
      requestId: err.requestId,
      retryable: err.retryable,
      retryAfterSec: err.retryAfterSec,
      fields: err.fieldErrors(),
      balance:
        err.code === 'insufficient_balance'
          ? {
              required: err.data?.required ?? null,
              available: err.data?.available ?? null,
            }
          : undefined,
    });
  }
  const e = err as Error;
  return new ResellerError(e?.message || 'Unexpected reseller error', 500, 'internal_error');
}

/** Maps stable provider error codes onto operator-friendly English copy. */
export function humanizeUpstreamError(err: UpstreamApiError): string {
  switch (err.code) {
    case 'missing_api_key':
      return 'The upstream reseller API key is not configured yet.';
    case 'unauthorized':
      return 'The upstream provider rejected the API key (401). Check the reseller key.';
    case 'insufficient_balance': {
      const required = err.data?.required ? moneyToCents(String(err.data.required)) : null;
      const available = err.data?.available ? moneyToCents(String(err.data.available)) : null;
      if (required !== null && available !== null) {
        return `Upstream balance too low: the order needs ${centsToMoney(required)} EUR but only ${centsToMoney(available)} EUR is available. Top up the reseller account.`;
      }
      return 'Upstream reseller balance is too low for this order.';
    }
    case 'out_of_stock':
      return 'The provider has no stock right now (e.g. no free IP addresses). Try again shortly.';
    case 'not_available':
      return 'This product is currently not orderable at the provider.';
    case 'rate_limited':
      return `Upstream rate limit reached${err.retryAfterSec ? ` — retry in ${err.retryAfterSec}s` : ''}.`;
    case 'validation_failed': {
      const fields = err.fieldErrors();
      const keys = Object.keys(fields);
      return keys.length
        ? `The provider rejected the request: ${keys.map((k) => `${k} → ${fields[k]}`).join(', ')}`
        : 'The provider rejected the request payload.';
    }
    case 'product_busy':
      return 'The server is busy (e.g. being reinstalled). Try again in a moment.';
    case 'not_provisioned':
      return 'The server is still being built. Please wait until it is active.';
    case 'product_not_active':
      return 'The upstream product is not active, so this action is not possible.';
    case 'already_running':
      return 'The server is already running.';
    case 'already_stopped':
      return 'The server is already stopped.';
    case 'owner_only':
      return 'Only the product owner may perform this action upstream.';
    case 'reseller_only':
      return 'The upstream account is not a reseller account, so this endpoint is unavailable.';
    case 'account_inactive':
      return 'The upstream reseller account is locked.';
    case 'not_found':
      return 'The provider does not know this product, plan or ticket.';
    case 'network_error':
    case 'upstream_timeout':
      return 'Could not reach the upstream provider. The request stays queued and is retried automatically.';
    case 'provider_error':
      return 'The upstream hypervisor or payment provider did not respond.';
    case 'internal_error':
      return `Upstream internal error${err.requestId ? ` (request ${err.requestId})` : ''}.`;
    default:
      return err.upstreamMessage || err.message;
  }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

export interface ResellerSettings {
  reseller_enabled: boolean;
  reseller_provider: string;
  reseller_api_base_url: string;
  reseller_api_key_enc: string;
  reseller_api_key_hint: string;
  reseller_store_enabled: boolean;
  reseller_default_markup_percent: number;
  reseller_auto_renew_default: boolean;
  reseller_allow_configurator: boolean;
  reseller_request_timeout_ms: number;
  reseller_sync_interval_sec: number;
  reseller_poll_interval_sec: number;
  reseller_low_balance_alert_cents: number;
  reseller_tos_text: string;
  reseller_upstream_account_id: string;
  reseller_upstream_balance_cents: string;
  reseller_last_sync_at: string;
}

const SETTING_KEYS: Array<keyof ResellerSettings> = [
  'reseller_enabled',
  'reseller_provider',
  'reseller_api_base_url',
  'reseller_api_key_enc',
  'reseller_api_key_hint',
  'reseller_store_enabled',
  'reseller_default_markup_percent',
  'reseller_auto_renew_default',
  'reseller_allow_configurator',
  'reseller_request_timeout_ms',
  'reseller_sync_interval_sec',
  'reseller_poll_interval_sec',
  'reseller_low_balance_alert_cents',
  'reseller_tos_text',
  'reseller_upstream_account_id',
  'reseller_upstream_balance_cents',
  'reseller_last_sync_at',
];

const BOOL_KEYS = new Set<string>([
  'reseller_enabled',
  'reseller_store_enabled',
  'reseller_auto_renew_default',
  'reseller_allow_configurator',
]);
const NUM_KEYS = new Set<string>([
  'reseller_default_markup_percent',
  'reseller_request_timeout_ms',
  'reseller_sync_interval_sec',
  'reseller_poll_interval_sec',
  'reseller_low_balance_alert_cents',
]);

function toBool(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') return value;
  const s = String(value ?? '').trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(s)) return true;
  if (['0', 'false', 'no', 'off'].includes(s)) return false;
  return fallback;
}

function toNum(value: unknown, fallback: number): number {
  const n = Number(String(value ?? '').trim());
  return Number.isFinite(n) ? n : fallback;
}

// ---------------------------------------------------------------------------
// Time helpers — upstream timestamps are Europe/Berlin local, no offset
// ---------------------------------------------------------------------------

/**
 * Converts a provider timestamp (`YYYY-MM-DD HH:mm:ss`, Europe/Berlin) into
 * `YYYY-MM-DD HH:MM:SS` UTC so it can be compared with SQLite's
 * `CURRENT_TIMESTAMP` / `datetime('now')` values.
 */
export function upstreamTimeToUtc(value: string | null | undefined): string | null {
  const raw = String(value || '').trim();
  const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m;
  const asUtcMs = Date.UTC(+y, +mo - 1, +d, +h, +mi, +s);
  const offsetMs = berlinOffsetMs(asUtcMs);
  // Berlin local = UTC + offset  →  UTC = local - offset
  return new Date(asUtcMs - offsetMs).toISOString().slice(0, 19).replace('T', ' ');
}

/** UTC→Europe/Berlin offset (handles CET/CEST via the IANA database). */
export function berlinOffsetMs(utcMs: number): number {
  try {
    const dtf = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Europe/Berlin',
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    const parts: Record<string, number> = {};
    for (const p of dtf.formatToParts(new Date(utcMs))) {
      if (p.type !== 'literal') parts[p.type] = parseInt(p.value, 10);
    }
    if (!parts.year) return 0;
    const asUtc = Date.UTC(
      parts.year,
      parts.month - 1,
      parts.day,
      parts.hour % 24,
      parts.minute,
      parts.second
    );
    return asUtc - utcMs;
  } catch {
    return 60 * 60 * 1000; // CET fallback
  }
}

/** Formats a stored UTC datetime for display in the panel (still UTC-labelled). */
export function formatUtcForDisplay(utcValue: string | null | undefined): string {
  const v = String(utcValue || '').trim();
  return v ? `${v} UTC` : '—';
}

// ---------------------------------------------------------------------------
// Catalogue presentation helpers
// ---------------------------------------------------------------------------

/**
 * Friendly label for a provider CPU family. The upstream `cpu` key is a short
 * family slug (`epyc`, `ryzen`, `xeon`, ...); the concrete model (EPYC 7543,
 * Ryzen 9 5950X, Ryzen 9 9950X, Xeon E5-2697 v4) is carried in the plan name
 * and surfaced through `cpu_label`.
 */
export function cpuFamilyLabel(family: string | null | undefined, planName?: string | null): string {
  const key = String(family || '').trim().toLowerCase();
  const base: Record<string, string> = {
    epyc: 'AMD EPYC',
    ryzen: 'AMD Ryzen',
    ryzen9: 'AMD Ryzen 9',
    threadripper: 'AMD Threadripper',
    xeon: 'Intel Xeon',
    xeongold: 'Intel Xeon Gold',
    core: 'Intel Core',
    i9: 'Intel Core i9',
    intel: 'Intel',
    amd: 'AMD',
  };
  const label = base[key];
  if (label) return label;
  if (planName && planName.trim()) return planName.trim();
  return key ? key.charAt(0).toUpperCase() + key.slice(1) : 'Unknown CPU';
}

function osFamily(osId: string, name: string, isWindows: boolean): string {
  const hay = `${osId} ${name}`.toLowerCase();
  if (isWindows || hay.includes('windows')) return 'windows';
  if (hay.includes('ubuntu')) return 'ubuntu';
  if (hay.includes('debian')) return 'debian';
  if (hay.includes('alma')) return 'almalinux';
  if (hay.includes('rocky')) return 'rocky';
  if (hay.includes('centos')) return 'centos';
  if (hay.includes('fedora')) return 'fedora';
  if (hay.includes('arch')) return 'arch';
  return 'linux';
}

function osIcon(family: string): string {
  const known = new Set([
    'ubuntu',
    'debian',
    'almalinux',
    'centos',
    'fedora',
    'linux',
    'proxmox',
    'rocky',
  ]);
  return known.has(family) ? `/images/os/${family}.svg` : '/images/os/linux.svg';
}

/** Builds a stable, human slug for a configurator-backed plan. */
export function configPlanSlug(cpu: string, cores: number, memoryGb: number, diskGb: number): string {
  const clean = String(cpu || 'custom').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  return `cfg-${clean}-${cores}c-${memoryGb}g-${diskGb}g`;
}

/** Package plan slug keeps the upstream name recognisable. */
export function packagePlanSlug(name: string, upstreamId: string): string {
  const clean = String(name || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  const short = String(upstreamId || '').replace(/-/g, '').slice(0, 8);
  return clean ? `${clean}-${short}` : `plan-${short}`;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export interface PlaceOrderInput {
  userId: number;
  /** Local `reseller_plans.id`. Required for package plans. */
  planId?: number | null;
  /** Custom configuration (only when the configurator is enabled by the admin). */
  config?: { cpu: string; cores: number; memory: number; disk: number; ipv4?: number; ipv6?: number } | null;
  os: string;
  name?: string | null;
  hostname?: string | null;
  password?: string | null;
  autoRenew?: boolean | null;
  voucher?: string | null;
  tos?: boolean;
  cancellation?: boolean;
  /** Validate + price only, never orders or charges. */
  sandbox?: boolean;
  /** Admin placing the order on behalf of a customer. */
  placedBy?: number | null;
  /** `free` = admin comped the order, `manual` = billed outside the wallet. */
  paymentMode?: 'wallet' | 'free' | 'manual';
  notes?: string | null;
}

export interface OrderOutcome {
  orderId: number;
  orderRef: string;
  status: string;
  sandbox: boolean;
  retailCents: number;
  setupCents: number;
  chargedCents: number;
  costCents: number;
  upstreamPriceCents: number | null;
  walletBalanceCents: number;
  serverId: number | null;
  upstreamProductId: string | null;
  upstreamState: string | null;
  primaryIpv4: string | null;
  primaryIpv6: string | null;
  credentials: { username: string; password: string } | null;
  requestId: string | null;
  replayed: boolean;
  errorCode: string | null;
  error: string | null;
  pricing?: Record<string, unknown> | null;
  balancePreview?: { availableCents: number; afterOrderCents: number } | null;
}

export interface StorePlan {
  id: number;
  slug: string | null;
  kind: 'package' | 'config';
  displayName: string;
  description: string | null;
  cpuFamily: string | null;
  cpuLabel: string | null;
  cores: number;
  memoryGb: number;
  diskGb: number;
  ipv4: number;
  ipv6: number;
  connectionGbit: number;
  durationMonths: number;
  retailCents: number;
  retailRenewCents: number;
  setupCents: number;
  currency: string;
  popular: boolean;
  available: boolean;
  upstreamPlanId: string | null;
  upstreamConfig: Record<string, unknown> | null;
  discountPercent: number;
}

export interface ResellerStatus {
  enabled: boolean;
  configured: boolean;
  storeEnabled: boolean;
  provider: string;
  baseUrl: string;
  keyHint: string;
  upstream: {
    reachable: boolean;
    checkedAt: string | null;
    error: string | null;
    errorCode: string | null;
    account: UpstreamAccount | null;
    balanceCents: number | null;
    currency: string;
    reseller: boolean;
    resellerTier: string | null;
    resellerInfo: UpstreamResellerInfo | null;
    rateLimit: UpstreamRateLimitInfo;
  };
  catalogue: {
    plansTotal: number;
    plansEnabled: number;
    plansVisible: number;
    osImages: number;
    lastSyncAt: string | null;
    cpuFamilies: Array<{ cpu: string; label: string; plans: number }>;
  };
  fleet: {
    serversTotal: number;
    active: number;
    installing: number;
    suspended: number;
    expiringSoon: number;
    monthlyRetailCents: number;
    monthlyCostCents: number;
    monthlyMarginCents: number;
  };
  orders: {
    total: number;
    pending: number;
    provisioning: number;
    provisioned: number;
    failed: number;
    last24h: number;
  };
  wallet: {
    totalBalanceCents: number;
    customersWithCredit: number;
  };
  lowBalanceAlert: boolean;
}

const TERMINAL_ORDER_FAILURES = new Set([
  'insufficient_balance',
  'validation_failed',
  'not_available',
  'out_of_stock',
  'invalid_price',
  'voucher_invalid',
  'unauthorized',
  'forbidden',
  'reseller_only',
  'account_inactive',
  'owner_only',
  'not_found',
  'method_not_allowed',
  'invalid_json',
  'idempotency_mismatch',
  'premium_domain',
  'not_offered',
  'payment_method_unsupported',
]);

const PASSWORD_PATTERN = /^[A-Za-z0-9!#$%&()*+,\-./:;=?@^_{|}~]{8,64}$/;
const PRODUCT_NAME_PATTERN = /^[A-Za-z0-9 ._,:;!?()#&+@/-]{1,50}$/;

export class ResellerService {
  /** Shared panel database — exposed for audit logging from route handlers. */
  public readonly db: UnifiedDatabase;
  private client: ResellerApiClient | null = null;
  private clientFingerprint = '';
  private readonly inFlightOrders = new Map<number, Promise<OrderOutcome>>();
  private pollTimer: NodeJS.Timeout | null = null;
  private syncTimer: NodeJS.Timeout | null = null;
  private pollRunning = false;
  private syncRunning = false;

  constructor(db: UnifiedDatabase) {
    this.db = db;
  }

  // -------------------------------------------------------------------------
  // Configuration
  // -------------------------------------------------------------------------

  public async getSettings(): Promise<ResellerSettings> {
    const rows = await this.db.all<{ setting_key: string; setting_value: string }>(
      `SELECT setting_key, setting_value FROM settings WHERE setting_key IN (${SETTING_KEYS.map(
        () => '?'
      ).join(',')})`,
      SETTING_KEYS as string[]
    );
    const map = new Map(rows.map((r) => [r.setting_key, r.setting_value]));
    const get = (key: string, fallback: string) => {
      const v = map.get(key);
      return v === undefined || v === null ? fallback : String(v);
    };

    const apiKeyEnc = get('reseller_api_key_enc', '');
    return {
      reseller_enabled: toBool(get('reseller_enabled', '0')),
      reseller_provider: get('reseller_provider', 'bukkit-hosting'),
      reseller_api_base_url: get(
        'reseller_api_base_url',
        process.env.RESELLER_API_BASE_URL || 'https://bukkit-hosting.eu/api/v2'
      ),
      reseller_api_key_enc: apiKeyEnc,
      reseller_api_key_hint: get('reseller_api_key_hint', ''),
      reseller_store_enabled: toBool(get('reseller_store_enabled', '1'), true),
      reseller_default_markup_percent: toNum(get('reseller_default_markup_percent', '20'), 20),
      reseller_auto_renew_default: toBool(get('reseller_auto_renew_default', '1'), true),
      reseller_allow_configurator: toBool(get('reseller_allow_configurator', '0')),
      reseller_request_timeout_ms: toNum(get('reseller_request_timeout_ms', '20000'), 20000),
      reseller_sync_interval_sec: toNum(get('reseller_sync_interval_sec', '900'), 900),
      reseller_poll_interval_sec: toNum(get('reseller_poll_interval_sec', '30'), 30),
      reseller_low_balance_alert_cents: toNum(get('reseller_low_balance_alert_cents', '2000'), 2000),
      reseller_tos_text: get('reseller_tos_text', ''),
      reseller_upstream_account_id: get('reseller_upstream_account_id', ''),
      reseller_upstream_balance_cents: get('reseller_upstream_balance_cents', ''),
      reseller_last_sync_at: get('reseller_last_sync_at', ''),
    };
  }

  public async setSetting(key: string, value: string | number | boolean | null): Promise<void> {
    if (!(SETTING_KEYS as string[]).includes(key)) {
      throw new ResellerError(`Unknown reseller setting: ${key}`, 400, 'unknown_setting');
    }
    await this.db.run(
      `INSERT INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = datetime('now')`,
      [key, value === null || value === undefined ? '' : String(value)]
    );
    if (key.startsWith('reseller_api_') || key === 'reseller_enabled') {
      this.client = null;
      this.clientFingerprint = '';
    }
  }

  /**
   * Stores the upstream API key encrypted at rest (AES-256-GCM via the panel
   * secret vault) and keeps only a short hint for display.
   */
  public async setApiKey(rawKey: string): Promise<{ hint: string }> {
    const key = String(rawKey || '').trim();
    if (!key) {
      await this.setSetting('reseller_api_key_enc', '');
      await this.setSetting('reseller_api_key_hint', '');
      return { hint: '' };
    }
    if (key.length > 512) {
      throw new ResellerError('That API key looks too long to be valid.', 422, 'invalid_api_key');
    }
    await this.setSetting('reseller_api_key_enc', encryptSecret(key));
    const hint = `${key.slice(0, Math.min(6, key.length))}…${key.slice(-4)}`;
    await this.setSetting('reseller_api_key_hint', hint);
    return { hint };
  }

  /** Resolves the plaintext API key: encrypted setting first, then `.env`. */
  public async resolveApiKey(settings?: ResellerSettings): Promise<string> {
    const cfg = settings || (await this.getSettings());
    if (cfg.reseller_api_key_enc) {
      try {
        const plain = decryptSecret(cfg.reseller_api_key_enc);
        if (plain) return plain;
      } catch {
        // Fall through to env — e.g. DB copied from another host.
      }
    }
    return String(process.env.RESELLER_API_KEY || '').trim();
  }

  /**
   * Returns a configured client, rebuilding it only when base URL / key /
   * timeout changed. Callers that need to know whether a key exists should
   * check `isConfigured()`.
   */
  public async getClient(): Promise<ResellerApiClient> {
    const cfg = await this.getSettings();
    const apiKey = await this.resolveApiKey(cfg);
    const baseUrl =
      cfg.reseller_api_base_url ||
      process.env.RESELLER_API_BASE_URL ||
      'https://bukkit-hosting.eu/api/v2';
    const fingerprint = `${baseUrl}|${apiKey.length}:${apiKey.slice(-4)}|${cfg.reseller_request_timeout_ms}`;

    if (this.client && this.clientFingerprint === fingerprint) return this.client;

    this.client = new ResellerApiClient({
      baseUrl,
      apiKey,
      timeoutMs: cfg.reseller_request_timeout_ms,
      maxRetries: 2,
      userAgent: 'TGVPANEL/3.0 reseller-integration',
      onLog: (entry) => this.writeApiLog(entry),
    });
    this.clientFingerprint = fingerprint;
    return this.client;
  }

  public async isReady(): Promise<{ ready: boolean; enabled: boolean; reason: string | null }> {
    const cfg = await this.getSettings();
    const key = await this.resolveApiKey(cfg);
    if (!key) {
      return {
        ready: false,
        enabled: cfg.reseller_enabled,
        reason: 'No upstream API key configured.',
      };
    }
    if (!cfg.reseller_enabled) {
      return { ready: false, enabled: false, reason: 'Reseller integration is disabled.' };
    }
    return { ready: true, enabled: true, reason: null };
  }

  /** Guards every upstream-touching operation. */
  private async requireReady(): Promise<ResellerApiClient> {
    const ready = await this.isReady();
    if (!ready.ready) {
      throw new ResellerError(
        ready.reason || 'Reseller integration is not ready.',
        503,
        'reseller_not_configured'
      );
    }
    return this.getClient();
  }

  private async writeApiLog(entry: ResellerApiLogEntry): Promise<void> {
    try {
      await this.db.run(
        `INSERT INTO reseller_api_logs
           (provider, method, endpoint, status_code, state, error_code, duration_ms,
            request_id, idempotency_key, request_body, response_body, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          'bukkit-hosting',
          entry.method,
          entry.endpoint,
          entry.statusCode,
          entry.state,
          entry.errorCode,
          entry.durationMs,
          entry.requestId,
          entry.idempotencyKey,
          entry.requestBody,
          entry.responseBody,
        ]
      );
      // Keep the log bounded.
      await this.db.run(
        `DELETE FROM reseller_api_logs
         WHERE id NOT IN (SELECT id FROM reseller_api_logs ORDER BY id DESC LIMIT 2000)`
      );
    } catch {
      // Never let logging break a request.
    }
  }

  public async listApiLogs(limit = 50): Promise<Record<string, unknown>[]> {
    const rows = await this.db.all(
      `SELECT id, method, endpoint, status_code, state, error_code, duration_ms,
              request_id, idempotency_key, created_at, request_body, response_body
       FROM reseller_api_logs ORDER BY id DESC LIMIT ?`,
      [Math.max(1, Math.min(500, limit))]
    );
    return rows;
  }

  // -------------------------------------------------------------------------
  // Status / health
  // -------------------------------------------------------------------------

  public async getStatus(options: { probeUpstream?: boolean } = {}): Promise<ResellerStatus> {
    const cfg = await this.getSettings();
    const apiKey = await this.resolveApiKey(cfg);

    const status: ResellerStatus = {
      enabled: cfg.reseller_enabled,
      configured: apiKey.length > 0,
      storeEnabled: cfg.reseller_store_enabled,
      provider: cfg.reseller_provider,
      baseUrl: cfg.reseller_api_base_url,
      keyHint: cfg.reseller_api_key_hint || (apiKey ? `${apiKey.slice(0, 6)}…${apiKey.slice(-4)}` : ''),
      upstream: {
        reachable: false,
        checkedAt: null,
        error: null,
        errorCode: null,
        account: null,
        balanceCents: null,
        currency: 'EUR',
        reseller: false,
        resellerTier: null,
        resellerInfo: null,
        rateLimit: emptyRateLimit(),
      },
      catalogue: {
        plansTotal: 0,
        plansEnabled: 0,
        plansVisible: 0,
        osImages: 0,
        lastSyncAt: cfg.reseller_last_sync_at || null,
        cpuFamilies: [],
      },
      fleet: {
        serversTotal: 0,
        active: 0,
        installing: 0,
        suspended: 0,
        expiringSoon: 0,
        monthlyRetailCents: 0,
        monthlyCostCents: 0,
        monthlyMarginCents: 0,
      },
      orders: { total: 0, pending: 0, provisioning: 0, provisioned: 0, failed: 0, last24h: 0 },
      wallet: { totalBalanceCents: 0, customersWithCredit: 0 },
      lowBalanceAlert: false,
    };

    const [planAgg, osAgg, families, serverAgg, orderAgg, walletAgg] = await Promise.all([
      this.db.get<{ total: number; enabled: number; visible: number }>(
        `SELECT COUNT(*) AS total,
                SUM(CASE WHEN is_enabled = 1 THEN 1 ELSE 0 END) AS enabled,
                SUM(CASE WHEN is_enabled = 1 AND is_visible = 1 THEN 1 ELSE 0 END) AS visible
         FROM reseller_plans`
      ),
      this.db.get<{ total: number }>(
        `SELECT COUNT(*) AS total FROM reseller_os_images WHERE is_enabled = 1`
      ),
      this.db.all<{ cpu: string; plans: number }>(
        `SELECT COALESCE(cpu_family, 'other') AS cpu, COUNT(*) AS plans
         FROM reseller_plans WHERE is_enabled = 1 GROUP BY cpu_family ORDER BY plans DESC`
      ),
      this.db.get<{
        total: number;
        active: number;
        installing: number;
        suspended: number;
        expiring: number;
        retail: number;
        cost: number;
      }>(
        `SELECT COUNT(*) AS total,
                SUM(CASE WHEN upstream_state = 'active' AND suspended = 0 THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN upstream_state IN ('install','reinstall') THEN 1 ELSE 0 END) AS installing,
                SUM(CASE WHEN suspended = 1 OR upstream_state = 'suspended' THEN 1 ELSE 0 END) AS suspended,
                SUM(CASE WHEN expires_at IS NOT NULL
                          AND datetime(expires_at) <= datetime('now', '+7 days') THEN 1 ELSE 0 END) AS expiring,
                COALESCE(SUM(retail_cents), 0) AS retail,
                COALESCE(SUM(cost_cents), 0) AS cost
         FROM cloud_servers`
      ),
      this.db.get<{
        total: number;
        pending: number;
        provisioning: number;
        provisioned: number;
        failed: number;
        last24h: number;
      }>(
        `SELECT COUNT(*) AS total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = 'provisioning' THEN 1 ELSE 0 END) AS provisioning,
                SUM(CASE WHEN status = 'provisioned' THEN 1 ELSE 0 END) AS provisioned,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
                SUM(CASE WHEN created_at >= datetime('now', '-1 day') THEN 1 ELSE 0 END) AS last24h
         FROM reseller_orders WHERE sandbox = 0`
      ),
      this.db.get<{ total: number; customers: number }>(
        `SELECT COALESCE(SUM(bal), 0) AS total,
                SUM(CASE WHEN bal > 0 THEN 1 ELSE 0 END) AS customers
         FROM (SELECT user_id, SUM(delta_cents) AS bal FROM reseller_wallet_ledger GROUP BY user_id)`
      ),
    ]);

    status.catalogue.plansTotal = planAgg?.total || 0;
    status.catalogue.plansEnabled = planAgg?.enabled || 0;
    status.catalogue.plansVisible = planAgg?.visible || 0;
    status.catalogue.osImages = osAgg?.total || 0;
    status.catalogue.cpuFamilies = (families || []).map((f) => ({
      cpu: f.cpu,
      label: cpuFamilyLabel(f.cpu),
      plans: f.plans,
    }));

    status.fleet.serversTotal = serverAgg?.total || 0;
    status.fleet.active = serverAgg?.active || 0;
    status.fleet.installing = serverAgg?.installing || 0;
    status.fleet.suspended = serverAgg?.suspended || 0;
    status.fleet.expiringSoon = serverAgg?.expiring || 0;
    status.fleet.monthlyRetailCents = serverAgg?.retail || 0;
    status.fleet.monthlyCostCents = serverAgg?.cost || 0;
    status.fleet.monthlyMarginCents = (serverAgg?.retail || 0) - (serverAgg?.cost || 0);

    status.orders.total = orderAgg?.total || 0;
    status.orders.pending = orderAgg?.pending || 0;
    status.orders.provisioning = orderAgg?.provisioning || 0;
    status.orders.provisioned = orderAgg?.provisioned || 0;
    status.orders.failed = orderAgg?.failed || 0;
    status.orders.last24h = orderAgg?.last24h || 0;

    status.wallet.totalBalanceCents = walletAgg?.total || 0;
    status.wallet.customersWithCredit = walletAgg?.customers || 0;

    if (options.probeUpstream && apiKey) {
      try {
        const client = await this.getClient();
        const account = await client.getAccount();
        status.upstream.reachable = true;
        status.upstream.checkedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
        status.upstream.account = account;
        status.upstream.balanceCents = account.balance ? moneyToCents(account.balance.amount) : null;
        status.upstream.currency = account.balance?.currency || 'EUR';
        status.upstream.rateLimit = client.lastRateLimit;
        await this.setSetting('reseller_upstream_account_id', account.userId || '');
        if (status.upstream.balanceCents !== null) {
          await this.setSetting(
            'reseller_upstream_balance_cents',
            String(status.upstream.balanceCents)
          );
        }
        try {
          const resellerInfo = await client.getResellerInfo();
          status.upstream.reseller = !!resellerInfo.reseller;
          status.upstream.resellerTier = resellerInfo.kvm?.tier || null;
          status.upstream.resellerInfo = resellerInfo;
        } catch (err) {
          // `reseller_only` (403) simply means a non-reseller account.
          if (err instanceof UpstreamApiError && err.code !== 'reseller_only') {
            status.upstream.error = humanizeUpstreamError(err);
            status.upstream.errorCode = err.code;
          }
        }
      } catch (err) {
        const e = toResellerError(err);
        status.upstream.reachable = false;
        status.upstream.checkedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
        status.upstream.error = e.message;
        status.upstream.errorCode = e.code;
      }
    } else if (!apiKey) {
      status.upstream.error = 'No upstream API key configured.';
      status.upstream.errorCode = 'missing_api_key';
    }

    const cachedBalance = cfg.reseller_upstream_balance_cents
      ? parseInt(cfg.reseller_upstream_balance_cents, 10)
      : null;
    const balanceForAlert = status.upstream.balanceCents ?? (Number.isFinite(cachedBalance) ? cachedBalance : null);
    status.lowBalanceAlert =
      balanceForAlert !== null && balanceForAlert < cfg.reseller_low_balance_alert_cents;

    return status;
  }

  // -------------------------------------------------------------------------
  // Catalogue sync
  // -------------------------------------------------------------------------

  /**
   * Pulls `GET /kvm/plans` and `GET /kvm/os` from the provider and upserts the
   * local catalogue.
   *
   * Cost prices always follow upstream. Retail prices are only auto-derived
   * (cost + configured markup) for plans whose retail price has never been
   * edited by hand, so an admin's margin survives a re-sync.
   *
   * Newly discovered plans land **disabled** — enabling what customers can
   * buy is an explicit reseller decision.
   */
  public async syncCatalogue(options: { actorId?: number | null } = {}): Promise<{
    plansUpserted: number;
    plansNew: number;
    plansDisabled: number;
    osUpserted: number;
    cpuFamilies: string[];
    upstreamBalanceCents: number | null;
  }> {
    const client = await this.requireReady();
    const cfg = await this.getSettings();
    const markupPct = cfg.reseller_default_markup_percent;

    const [plans, osList] = await Promise.all([client.listKvmPlans(), client.listKvmOs()]);

    let plansUpserted = 0;
    let plansNew = 0;
    let plansDisabled = 0;
    const families = new Set<string>();

    let sortIndex = 0;
    for (const plan of plans || []) {
      if (!plan || !plan.id) continue;
      families.add(String(plan.cpu || 'other').toLowerCase());
      const costCents = moneyToCents(plan.finalPrice ?? plan.price);
      const listCents = moneyToCents(plan.price);
      const derivedRetail = applyMarkup(costCents, markupPct);
      const slug = packagePlanSlug(plan.name, plan.id);
      sortIndex += 1;

      const existing = await this.db.get<ResellerPlanRow>(
        `SELECT * FROM reseller_plans WHERE upstream_plan_id = ? AND kind = 'package' LIMIT 1`,
        [plan.id]
      );

      if (existing) {
        // Preserve hand-tuned retail pricing; only follow upstream when the
        // stored retail price still equals the previously derived value.
        const previousDerived = applyMarkup(existing.cost_cents, markupPct);
        const retailCents =
          existing.retail_cents === previousDerived ? derivedRetail : existing.retail_cents;
        const renewCents =
          existing.retail_renew_cents === previousDerived ? derivedRetail : existing.retail_renew_cents;

        await this.db.run(
          `UPDATE reseller_plans SET
             display_name = ?, cpu_family = ?, cpu_label = ?, cores = ?, memory_gb = ?, disk_gb = ?,
             ipv4_count = ?, ipv6_count = ?, connection_gbit = ?, duration_months = ?,
             cost_cents = ?, cost_renew_cents = ?, retail_cents = ?, retail_renew_cents = ?,
             currency = ?, is_popular = ?, upstream_available = ?, upstream_exclusive = ?,
             upstream_discount_percent = ?, upstream_discount_ends_at = ?, upstream_raw = ?,
             stock_state = ?, sort_order = ?, last_synced_at = datetime('now'),
             updated_at = datetime('now')
           WHERE id = ?`,
          [
            plan.name,
            String(plan.cpu || '').toLowerCase(),
            cpuFamilyLabel(plan.cpu, plan.name),
            num(plan.cores),
            num(plan.memory),
            num(plan.disk),
            num(plan.ipv4, 1),
            num(plan.ipv6, 1),
            num(plan.connection, 1),
            num(plan.duration, 1),
            costCents,
            costCents,
            retailCents,
            renewCents,
            'EUR',
            plan.popular ? 1 : 0,
            plan.available ? 1 : 0,
            plan.exclusive ? 1 : 0,
            num(plan.discountPercent),
            upstreamTimeToUtc(plan.discountEndsAt),
            JSON.stringify(plan),
            plan.available ? 'available' : 'unavailable',
            existing.sort_order || sortIndex,
            existing.id,
          ]
        );
        plansUpserted += 1;
        if (existing.is_enabled === 1 && !plan.available) plansDisabled += 1;
      } else {
        await this.db.run(
          `INSERT INTO reseller_plans (
             provider, upstream_plan_id, kind, slug, display_name, description,
             cpu_family, cpu_label, cores, memory_gb, disk_gb, ipv4_count, ipv6_count,
             connection_gbit, duration_months, cost_cents, cost_renew_cents,
             retail_cents, retail_renew_cents, setup_cents, currency,
             is_enabled, is_visible, is_popular, sort_order, stock_state,
             upstream_available, upstream_exclusive, upstream_discount_percent,
             upstream_discount_ends_at, upstream_raw, last_synced_at, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,1,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'),datetime('now'))`,
          [
            cfg.reseller_provider,
            plan.id,
            'package',
            slug,
            plan.name,
            describePlan(plan),
            String(plan.cpu || '').toLowerCase(),
            cpuFamilyLabel(plan.cpu, plan.name),
            num(plan.cores),
            num(plan.memory),
            num(plan.disk),
            num(plan.ipv4, 1),
            num(plan.ipv6, 1),
            num(plan.connection, 1),
            num(plan.duration, 1),
            costCents,
            costCents,
            derivedRetail,
            derivedRetail,
            0,
            'EUR',
            plan.popular ? 1 : 0,
            sortIndex,
            plan.available ? 'available' : 'unavailable',
            plan.available ? 1 : 0,
            plan.exclusive ? 1 : 0,
            num(plan.discountPercent),
            upstreamTimeToUtc(plan.discountEndsAt),
            JSON.stringify(plan),
          ]
        );
        plansUpserted += 1;
        plansNew += 1;
      }

      void listCents;
    }

    let osUpserted = 0;
    let osSort = 0;
    for (const image of osList || []) {
      if (!image || !image.id) continue;
      osSort += 1;
      const family = osFamily(image.id, image.name, !!image.windows);
      const existing = await this.db.get<ResellerOsRow>(
        `SELECT * FROM reseller_os_images WHERE provider = ? AND upstream_os_id = ? LIMIT 1`,
        [cfg.reseller_provider, image.id]
      );
      if (existing) {
        await this.db.run(
          `UPDATE reseller_os_images SET display_name = ?, family = ?, is_windows = ?,
             min_disk_gb = ?, icon = ?, sort_order = ?, last_synced_at = datetime('now')
           WHERE id = ?`,
          [
            image.name,
            family,
            image.windows ? 1 : 0,
            image.minDisk === null || image.minDisk === undefined ? null : num(image.minDisk),
            existing.icon || osIcon(family),
            existing.sort_order || osSort,
            existing.id,
          ]
        );
      } else {
        await this.db.run(
          `INSERT INTO reseller_os_images (
             provider, upstream_os_id, display_name, family, is_windows, min_disk_gb,
             is_enabled, icon, sort_order, last_synced_at, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))`,
          [
            cfg.reseller_provider,
            image.id,
            image.name,
            family,
            image.windows ? 1 : 0,
            image.minDisk === null || image.minDisk === undefined ? null : num(image.minDisk),
            1,
            osIcon(family),
            osSort,
          ]
        );
      }
      osUpserted += 1;
    }

    // Cache the upstream balance so the admin dashboard can warn without a
    // live call on every page load.
    let upstreamBalanceCents: number | null = null;
    try {
      const balance = await client.getBalance();
      upstreamBalanceCents = moneyToCents(balance.amount);
      await this.setSetting('reseller_upstream_balance_cents', String(upstreamBalanceCents));
      if (balance.currency) await this.setSetting('reseller_provider', cfg.reseller_provider);
    } catch {
      // Balance is a nice-to-have; catalogue sync already succeeded.
    }

    await this.setSetting('reseller_last_sync_at', new Date().toISOString().slice(0, 19).replace('T', ' '));

    await this.db.logActivity({
      userId: options.actorId ?? null,
      action: 'reseller_catalogue_sync',
      resourceType: 'reseller',
      resourceId: cfg.reseller_provider,
      details: { plansUpserted, plansNew, osUpserted, families: Array.from(families) },
    });

    return {
      plansUpserted,
      plansNew,
      plansDisabled,
      osUpserted,
      cpuFamilies: Array.from(families).sort(),
      upstreamBalanceCents,
    };
  }

  /** Fetches live configurator limits/prices (not persisted; priced on demand). */
  public async getConfigurator(cpu?: string): Promise<UpstreamKvmConfigurator[]> {
    const client = await this.requireReady();
    return client.getKvmConfigurator(cpu);
  }

  public async getConfiguratorPrice(params: {
    cpu: string;
    cores: number;
    memory: number;
    disk: number;
    ipv4?: number;
    ipv6?: number;
    voucher?: string;
    markupPercent?: number | null;
  }): Promise<{ upstream: UpstreamKvmConfiguratorPrice; costCents: number; retailCents: number; retailRenewCents: number }> {
    const client = await this.requireReady();
    const cfg = await this.getSettings();
    const upstream = await client.getKvmConfiguratorPrice({
      cpu: params.cpu,
      cores: params.cores,
      memory: params.memory,
      disk: params.disk,
      ipv4: params.ipv4,
      ipv6: params.ipv6,
      voucher: params.voucher,
    });
    const costCents = moneyToCents(upstream.pricing?.orderPrice ?? upstream.pricing?.price);
    const markup =
      params.markupPercent === null || params.markupPercent === undefined
        ? cfg.reseller_default_markup_percent
        : params.markupPercent;
    const retailCents = applyMarkup(costCents, markup);
    const renewCents = applyMarkup(moneyToCents(upstream.pricing?.renewPrice ?? upstream.pricing?.price), markup);
    return { upstream, costCents, retailCents, retailRenewCents: renewCents };
  }

  public async listOsImages(options: { enabledOnly?: boolean } = {}): Promise<ResellerOsRow[]> {
    const where = options.enabledOnly === false ? '' : 'WHERE is_enabled = 1';
    return this.db.all<ResellerOsRow>(
      `SELECT * FROM reseller_os_images ${where} ORDER BY sort_order, display_name`
    );
  }

  public async listPlans(options: {
    enabledOnly?: boolean;
    visibleOnly?: boolean;
    cpu?: string;
  } = {}): Promise<ResellerPlanRow[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (options.enabledOnly !== false) {
      clauses.push('is_enabled = 1');
    }
    if (options.visibleOnly) {
      clauses.push('is_visible = 1');
    }
    if (options.cpu) {
      clauses.push('LOWER(cpu_family) = LOWER(?)');
      params.push(options.cpu);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    return this.db.all<ResellerPlanRow>(
      `SELECT * FROM reseller_plans ${where} ORDER BY sort_order, retail_cents, id`,
      params
    );
  }

  /** Customer-facing catalogue grouped by CPU family. */
  public async getStoreCatalogue(): Promise<{
    enabled: boolean;
    groups: Array<{ cpu: string; label: string; plans: StorePlan[] }>;
    osImages: Array<{
      id: string;
      name: string;
      family: string;
      windows: boolean;
      minDiskGb: number | null;
      icon: string;
    }>;
    configuratorEnabled: boolean;
    autoRenewDefault: boolean;
    tosText: string;
    currency: string;
  }> {
    const cfg = await this.getSettings();
    const plans = await this.listPlans({ enabledOnly: true, visibleOnly: true });
    const osImages = await this.listOsImages({ enabledOnly: true });

    const groups = new Map<string, StorePlan[]>();
    for (const plan of plans) {
      const cpu = String(plan.cpu_family || 'other').toLowerCase();
      if (!groups.has(cpu)) groups.set(cpu, []);
      groups.get(cpu)!.push(toStorePlan(plan));
    }

    const ordered = Array.from(groups.entries())
      .map(([cpu, list]) => ({ cpu, label: cpuFamilyLabel(cpu, list[0]?.displayName), plans: list }))
      .sort((a, b) => a.label.localeCompare(b.label));

    return {
      enabled: cfg.reseller_enabled && cfg.reseller_store_enabled,
      groups: ordered,
      osImages: osImages.map((o) => ({
        id: o.upstream_os_id,
        name: o.display_name,
        family: o.family,
        windows: !!o.is_windows,
        minDiskGb: o.min_disk_gb,
        icon: o.icon || osIcon(o.family),
      })),
      configuratorEnabled: cfg.reseller_allow_configurator,
      autoRenewDefault: cfg.reseller_auto_renew_default,
      tosText: cfg.reseller_tos_text,
      currency: 'EUR',
    };
  }

  public async getPlan(planId: number): Promise<ResellerPlanRow> {
    const plan = await this.db.get<ResellerPlanRow>(`SELECT * FROM reseller_plans WHERE id = ?`, [
      planId,
    ]);
    if (!plan) throw new ResellerError('Plan not found.', 404, 'plan_not_found');
    return plan;
  }

  public async updatePlan(
    planId: number,
    patch: {
      display_name?: string;
      description?: string | null;
      retail_cents?: number;
      retail_renew_cents?: number;
      setup_cents?: number;
      is_enabled?: boolean;
      is_visible?: boolean;
      is_popular?: boolean;
      sort_order?: number;
      cpu_label?: string | null;
    }
  ): Promise<ResellerPlanRow> {
    const plan = await this.getPlan(planId);
    const sets: string[] = [];
    const params: unknown[] = [];

    const assign = (column: string, value: unknown) => {
      sets.push(`${column} = ?`);
      params.push(value);
    };

    if (patch.display_name !== undefined) assign('display_name', String(patch.display_name).slice(0, 120));
    if (patch.description !== undefined) assign('description', patch.description === null ? null : String(patch.description).slice(0, 1000));
    if (patch.cpu_label !== undefined) assign('cpu_label', patch.cpu_label === null ? null : String(patch.cpu_label).slice(0, 120));
    if (patch.retail_cents !== undefined) assign('retail_cents', Math.max(0, Math.round(patch.retail_cents)));
    if (patch.retail_renew_cents !== undefined)
      assign('retail_renew_cents', Math.max(0, Math.round(patch.retail_renew_cents)));
    if (patch.setup_cents !== undefined) assign('setup_cents', Math.max(0, Math.round(patch.setup_cents)));
    if (patch.is_enabled !== undefined) assign('is_enabled', patch.is_enabled ? 1 : 0);
    if (patch.is_visible !== undefined) assign('is_visible', patch.is_visible ? 1 : 0);
    if (patch.is_popular !== undefined) assign('is_popular', patch.is_popular ? 1 : 0);
    if (patch.sort_order !== undefined) assign('sort_order', Math.round(patch.sort_order));

    if (!sets.length) return plan;
    sets.push(`updated_at = datetime('now')`);
    params.push(planId);
    await this.db.run(`UPDATE reseller_plans SET ${sets.join(', ')} WHERE id = ?`, params);
    return this.getPlan(planId);
  }

  /**
   * Creates a sellable "custom configuration" plan from configurator limits.
   * Prices are taken from the live provider quote so the margin is exact.
   */
  public async createConfigPlan(input: {
    cpu: string;
    cores: number;
    memory: number;
    disk: number;
    ipv4?: number;
    ipv6?: number;
    displayName?: string;
    description?: string;
    markupPercent?: number | null;
    setupCents?: number;
    enable?: boolean;
    actorId?: number | null;
  }): Promise<ResellerPlanRow> {
    const cfg = await this.getSettings();
    const quote = await this.getConfiguratorPrice({
      cpu: input.cpu,
      cores: input.cores,
      memory: input.memory,
      disk: input.disk,
      ipv4: input.ipv4,
      ipv6: input.ipv6,
      markupPercent: input.markupPercent ?? null,
    });

    const slug = configPlanSlug(input.cpu, input.cores, input.memory, input.disk);
    const existing = await this.db.get<ResellerPlanRow>(
      `SELECT * FROM reseller_plans WHERE slug = ? LIMIT 1`,
      [slug]
    );
    if (existing) {
      throw new ResellerError(
        'A custom plan with these specifications already exists. Edit that plan instead.',
        409,
        'plan_exists'
      );
    }

    const name =
      input.displayName?.trim() ||
      `${cpuFamilyLabel(input.cpu)} ${input.cores} vCPU / ${input.memory} GB / ${input.disk} GB`;

    const result = await this.db.run(
      `INSERT INTO reseller_plans (
         provider, upstream_plan_id, kind, slug, display_name, description, cpu_family, cpu_label,
         cores, memory_gb, disk_gb, ipv4_count, ipv6_count, connection_gbit, duration_months,
         cost_cents, cost_renew_cents, retail_cents, retail_renew_cents, setup_cents, currency,
         is_enabled, is_visible, is_popular, sort_order, stock_state, upstream_available,
         upstream_exclusive, upstream_discount_percent, upstream_raw, last_synced_at,
         created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'),datetime('now'))`,
      [
        cfg.reseller_provider,
        null,
        'config',
        slug,
        name.slice(0, 120),
        (input.description || `${input.cores} vCPU, ${input.memory} GB RAM, ${input.disk} GB storage on ${cpuFamilyLabel(input.cpu)}.`).slice(0, 1000),
        String(input.cpu).toLowerCase(),
        cpuFamilyLabel(input.cpu, name),
        Math.round(input.cores),
        Math.round(input.memory),
        Math.round(input.disk),
        Math.round(input.ipv4 ?? 1),
        Math.round(input.ipv6 ?? 1),
        quote.upstream.connection || 1,
        quote.upstream.pricing?.duration || 1,
        quote.costCents,
        quote.costCents,
        quote.retailCents,
        quote.retailRenewCents,
        Math.max(0, Math.round(input.setupCents ?? 0)),
        'EUR',
        input.enable === false ? 0 : 1,
        // is_visible — custom plans are customer-facing straight away.
        1,
        // is_popular
        0,
        // sort_order — after the synced provider packages.
        900,
        quote.upstream.available ? 'available' : 'unavailable',
        quote.upstream.available ? 1 : 0,
        // upstream_exclusive — a config quote is never an account-exclusive offer.
        0,
        num(quote.upstream.pricing?.discountPercent),
        JSON.stringify({
          cpu: input.cpu,
          cores: input.cores,
          memory: input.memory,
          disk: input.disk,
          ipv4: input.ipv4 ?? null,
          ipv6: input.ipv6 ?? null,
          connection: quote.upstream.connection,
          pricing: quote.upstream.pricing,
        }),
      ]
    );

    await this.db.logActivity({
      userId: input.actorId ?? null,
      action: 'reseller_plan_create',
      resourceType: 'reseller_plan',
      resourceId: result.lastID,
      details: { slug, cpu: input.cpu, cores: input.cores, memory: input.memory, disk: input.disk },
    });

    const created = await this.db.get<ResellerPlanRow>(
      `SELECT * FROM reseller_plans WHERE id = ?`,
      [result.lastID]
    );
    if (!created) throw new ResellerError('Failed to store the new plan.', 500, 'plan_create_failed');
    return created;
  }

  // -------------------------------------------------------------------------
  // Wallet (ledger-based)
  // -------------------------------------------------------------------------

  public async getWalletBalance(userId: number): Promise<number> {
    const row = await this.db.get<{ bal: number | null }>(
      `SELECT COALESCE(SUM(delta_cents), 0) AS bal FROM reseller_wallet_ledger WHERE user_id = ?`,
      [userId]
    );
    return Math.round(row?.bal || 0);
  }

  public async getWalletLedger(userId: number, limit = 50): Promise<WalletEntryRow[]> {
    return this.db.all<WalletEntryRow>(
      `SELECT * FROM reseller_wallet_ledger WHERE user_id = ? ORDER BY id DESC LIMIT ?`,
      [userId, Math.max(1, Math.min(500, limit))]
    );
  }

  /**
   * Appends a ledger entry atomically and returns the new balance.
   * `BEGIN IMMEDIATE` serialises concurrent wallet writes so an overdraft
   * cannot slip through between the balance read and the insert.
   */
  private async appendLedger(params: {
    userId: number;
    deltaCents: number;
    kind: string;
    reference?: string | null;
    description?: string | null;
    createdBy?: number | null;
    allowNegative?: boolean;
  }): Promise<number> {
    return this.db.transaction(async () => {
      const balance = await this.getWalletBalance(params.userId);
      const next = balance + Math.round(params.deltaCents);
      if (next < 0 && !params.allowNegative) {
        throw new ResellerError(
          `Insufficient panel credit: this order needs ${centsToMoney(-params.deltaCents + balance)} EUR but only ${centsToMoney(balance)} EUR is available.`,
          402,
          'insufficient_wallet_balance',
          { requiredCents: -params.deltaCents, availableCents: balance, balanceCents: balance }
        );
      }
      await this.db.run(
        `INSERT INTO reseller_wallet_ledger
           (user_id, delta_cents, balance_after_cents, kind, reference, description, created_by, created_at)
         VALUES (?,?,?,?,?,?,?,datetime('now'))`,
        [
          params.userId,
          Math.round(params.deltaCents),
          next,
          params.kind,
          params.reference ?? null,
          params.description ?? null,
          params.createdBy ?? null,
        ]
      );
      return next;
    });
  }

  /** Admin grants (positive) or withdraws (negative) panel credit. */
  public async adjustWallet(params: {
    userId: number;
    amountCents: number;
    kind?: 'credit' | 'debit' | 'refund' | 'adjustment';
    description?: string;
    actorId?: number | null;
  }): Promise<{ balanceCents: number; entryId: number }> {
    const target = await this.db.get<{ id: number; username: string }>(
      `SELECT id, username FROM users WHERE id = ?`,
      [params.userId]
    );
    if (!target) throw new ResellerError('User not found.', 404, 'user_not_found');

    const delta = Math.round(params.amountCents);
    if (!delta) throw new ResellerError('Amount must not be zero.', 422, 'invalid_amount');

    const kind = params.kind || (delta > 0 ? 'credit' : 'debit');
    const balance = await this.appendLedger({
      userId: params.userId,
      deltaCents: delta,
      kind,
      description: params.description || `${kind} by administrator`,
      createdBy: params.actorId ?? null,
      allowNegative: true,
    });

    await this.db.logActivity({
      userId: params.actorId ?? null,
      action: 'reseller_wallet_adjust',
      resourceType: 'user',
      resourceId: params.userId,
      details: { deltaCents: delta, balanceCents: balance, kind },
    });

    await this.notify(params.userId, delta > 0 ? 'success' : 'warning', 
      delta > 0 ? 'Credit added to your account' : 'Credit deducted from your account',
      `${delta > 0 ? '+' : '−'}${centsToMoney(Math.abs(delta))} EUR — new balance ${centsToMoney(balance)} EUR.`
    );

    const entry = await this.db.get<{ id: number }>(
      `SELECT id FROM reseller_wallet_ledger WHERE user_id = ? ORDER BY id DESC LIMIT 1`,
      [params.userId]
    );
    return { balanceCents: balance, entryId: entry?.id || 0 };
  }

  // -------------------------------------------------------------------------
  // Ordering & provisioning
  // -------------------------------------------------------------------------

  /** Validates + prices an order without buying anything (`sandbox: true`). */
  public async previewOrder(input: PlaceOrderInput): Promise<OrderOutcome> {
    return this.placeOrder({ ...input, sandbox: true });
  }

  /**
   * Places an order and provisions the server onto the customer's panel
   * account. Safe to call repeatedly for the same `orderId` via
   * `retryOrder()` — the persisted idempotency key prevents double purchase.
   */
  public async placeOrder(input: PlaceOrderInput): Promise<OrderOutcome> {
    const client = await this.requireReady();
    const cfg = await this.getSettings();

    if (!cfg.reseller_store_enabled && !input.placedBy) {
      throw new ResellerError('The server store is currently closed.', 403, 'store_disabled');
    }

    const customer = await this.db.get<{ id: number; username: string }>(
      `SELECT id, username FROM users WHERE id = ? AND is_active = 1`,
      [input.userId]
    );
    if (!customer) throw new ResellerError('Customer account not found or inactive.', 404, 'user_not_found');

    // --- Resolve what is being bought -------------------------------------
    let plan: ResellerPlanRow | null = null;
    let orderPayload: UpstreamKvmOrderInput;
    let cores = 0;
    let memoryGb = 0;
    let diskGb = 0;
    let ipv4Count = 1;
    let ipv6Count = 1;
    let cpuFamily: string | null = null;
    let connectionGbit = 1;
    let durationMonths = 1;
    let costCents = 0;
    let retailCents = 0;
    let setupCents = 0;

    if (input.config) {
      if (!cfg.reseller_allow_configurator) {
        throw new ResellerError(
          'Custom configurations are not enabled for this store.',
          403,
          'configurator_disabled'
        );
      }
      const c = input.config;
      cpuFamily = String(c.cpu || '').toLowerCase();
      cores = Math.round(Number(c.cores));
      memoryGb = Math.round(Number(c.memory));
      diskGb = Math.round(Number(c.disk));
      ipv4Count = c.ipv4 === undefined ? 1 : Math.round(Number(c.ipv4));
      ipv6Count = c.ipv6 === undefined ? 1 : Math.round(Number(c.ipv6));
      if (!cpuFamily || !cores || !memoryGb || !diskGb) {
        throw new ResellerError('cpu, cores, memory and disk are required.', 422, 'invalid_config');
      }
      const quote = await this.getConfiguratorPrice({
        cpu: cpuFamily,
        cores,
        memory: memoryGb,
        disk: diskGb,
        ipv4: ipv4Count,
        ipv6: ipv6Count,
        voucher: input.voucher || undefined,
      });
      if (!quote.upstream.available) {
        throw new ResellerError('This configuration is not available right now.', 409, 'not_available');
      }
      costCents = quote.costCents;
      retailCents = quote.retailCents;
      connectionGbit = quote.upstream.connection || 1;
      durationMonths = quote.upstream.pricing?.duration || 1;
      orderPayload = {
        config: {
          cpu: cpuFamily,
          cores,
          memory: memoryGb,
          disk: diskGb,
          ipv4: ipv4Count,
          ipv6: ipv6Count,
        },
        os: String(input.os),
      };
    } else {
      if (!input.planId) {
        throw new ResellerError('Either planId or config is required.', 422, 'missing_plan');
      }
      plan = await this.getPlan(input.planId);
      if (!plan.is_enabled) {
        throw new ResellerError('This plan is not available for ordering.', 409, 'plan_disabled');
      }
      if (plan.upstream_available === 0) {
        throw new ResellerError('This plan is currently out of stock upstream.', 409, 'not_available');
      }
      cores = plan.cores;
      memoryGb = plan.memory_gb;
      diskGb = plan.disk_gb;
      ipv4Count = plan.ipv4_count;
      ipv6Count = plan.ipv6_count;
      cpuFamily = plan.cpu_family;
      connectionGbit = plan.connection_gbit;
      durationMonths = plan.duration_months;
      costCents = plan.cost_cents;
      retailCents = plan.retail_cents;
      setupCents = plan.setup_cents;
      orderPayload = plan.kind === 'config'
        ? {
            config: {
              cpu: String(plan.cpu_family || ''),
              cores: plan.cores,
              memory: plan.memory_gb,
              disk: plan.disk_gb,
              ipv4: plan.ipv4_count,
              ipv6: plan.ipv6_count,
            },
            os: String(input.os),
          }
        : { planId: String(plan.upstream_plan_id || ''), os: String(input.os) };
      if (plan.kind === 'package' && !plan.upstream_plan_id) {
        throw new ResellerError('This plan is not linked to an upstream package. Re-sync the catalogue.', 409, 'plan_not_linked');
      }
    }

    // --- Validate OS + naming ---------------------------------------------
    const osImage = await this.db.get<ResellerOsRow>(
      `SELECT * FROM reseller_os_images WHERE upstream_os_id = ? AND is_enabled = 1 LIMIT 1`,
      [String(input.os)]
    );
    if (!osImage) {
      // Fall back to a live check so a freshly published image still works.
      let live: UpstreamKvmOs | undefined;
      try {
        const list = await client.listKvmOs();
        live = (list || []).find((o) => o.id === String(input.os));
      } catch {
        live = undefined;
      }
      if (!live) {
        throw new ResellerError(`Unknown operating system "${input.os}".`, 422, 'invalid_os');
      }
      if (live.windows && live.minDisk && diskGb < live.minDisk) {
        throw new ResellerError(
          `${live.name} needs at least ${live.minDisk} GB of storage (selected: ${diskGb} GB).`,
          422,
          'disk_too_small'
        );
      }
    } else if (osImage.is_windows && osImage.min_disk_gb && diskGb < osImage.min_disk_gb) {
      throw new ResellerError(
        `${osImage.display_name} needs at least ${osImage.min_disk_gb} GB of storage (selected: ${diskGb} GB).`,
        422,
        'disk_too_small'
      );
    }

    const serverName = sanitizeProductName(input.name) || `${cpuFamilyLabel(cpuFamily)} ${cores}vCPU`;
    const hostname = sanitizeHostname(input.hostname) || null;
    if (input.password && !PASSWORD_PATTERN.test(input.password)) {
      throw new ResellerError(
        'Password must be 8-64 characters using letters, digits and !#$%&()*+,-./:;=?@^_{|}~',
        422,
        'invalid_password'
      );
    }

    const autoRenew =
      input.autoRenew === null || input.autoRenew === undefined
        ? cfg.reseller_auto_renew_default
        : !!input.autoRenew;

    orderPayload.name = serverName;
    orderPayload.autoRenew = autoRenew;
    if (input.password) orderPayload.password = input.password;
    if (input.voucher) orderPayload.voucher = String(input.voucher).slice(0, 64);

    const totalCents = retailCents + setupCents;
    const paymentMode = input.paymentMode || 'wallet';

    // --- Sandbox: price + validate, order nothing --------------------------
    if (input.sandbox) {
      orderPayload.sandbox = true;
      // Terms do not need confirming for a sandbox run.
      const preview = await client.orderKvm(orderPayload, null);
      const data = preview.preview as Record<string, unknown> | undefined;
      const pricing = (data?.pricing || null) as Record<string, unknown> | null;
      const balance = (data?.balance || null) as Record<string, unknown> | null;
      const upstreamPriceCents = pricing ? moneyToCents(String(pricing.orderPrice ?? pricing.price ?? '0')) : costCents;
      return {
        orderId: 0,
        orderRef: '',
        status: 'preview',
        sandbox: true,
        retailCents: totalCents,
        setupCents,
        chargedCents: 0,
        costCents: upstreamPriceCents,
        upstreamPriceCents,
        walletBalanceCents: await this.getWalletBalance(input.userId),
        serverId: null,
        upstreamProductId: null,
        upstreamState: null,
        primaryIpv4: null,
        primaryIpv6: null,
        credentials: null,
        requestId: preview.requestId,
        replayed: preview.replayed,
        errorCode: null,
        error: null,
        pricing,
        balancePreview: balance
          ? {
              availableCents: moneyToCents(String(balance.available ?? '0')),
              afterOrderCents: moneyToCents(String(balance.afterOrder ?? '0')),
            }
          : null,
      };
    }

    // --- Real order ---------------------------------------------------------
    if (!input.tos || !input.cancellation) {
      throw new ResellerError(
        'The terms of service and the waiver of withdrawal (immediate provisioning) must be accepted.',
        422,
        'tos_required'
      );
    }
    orderPayload.tos = true;
    orderPayload.cancellation = true;

    const orderRef = generateOrderRef();
    const idempotencyKey = buildIdempotencyKey('tgv', orderRef);

    const inserted = await this.db.run(
      `INSERT INTO reseller_orders (
         order_ref, user_id, plan_id, provider, server_name, hostname, os_id,
         cores, memory_gb, disk_gb, ipv4_count, ipv6_count, cpu_family, duration_months,
         auto_renew, retail_cents, setup_cents, charged_cents, cost_cents, currency,
         payment_mode, status, idempotency_key, sandbox, placed_by, notes,
         created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?,0,?,?,datetime('now'),datetime('now'))`,
      [
        orderRef,
        input.userId,
        plan ? plan.id : null,
        cfg.reseller_provider,
        serverName,
        hostname,
        String(input.os),
        cores,
        memoryGb,
        diskGb,
        ipv4Count,
        ipv6Count,
        cpuFamily,
        durationMonths,
        autoRenew ? 1 : 0,
        retailCents,
        setupCents,
        // charged_cents stays 0 until the wallet is actually debited.
        costCents,
        'EUR',
        paymentMode,
        'pending',
        idempotencyKey,
        input.placedBy ?? null,
        input.notes ? String(input.notes).slice(0, 1000) : null,
      ]
    );

    const orderId = inserted.lastID;
    return this.executeOrder(orderId, { paymentMode });
  }

  /**
   * Runs the upstream call for a stored order. Re-entrant and crash-safe:
   * the persisted idempotency key makes a repeat call replay the provider's
   * stored response instead of creating a second server.
   */
  private async executeOrder(
    orderId: number,
    options: { paymentMode?: string } = {}
  ): Promise<OrderOutcome> {
    const existing = this.inFlightOrders.get(orderId);
    if (existing) return existing;

    const task = this.runOrder(orderId, options).finally(() => {
      this.inFlightOrders.delete(orderId);
    });
    this.inFlightOrders.set(orderId, task);
    return task;
  }

  private async runOrder(
    orderId: number,
    options: { paymentMode?: string } = {}
  ): Promise<OrderOutcome> {
    const client = await this.requireReady();
    const order = await this.db.get<Record<string, any>>(
      `SELECT * FROM reseller_orders WHERE id = ?`,
      [orderId]
    );
    if (!order) throw new ResellerError('Order not found.', 404, 'order_not_found');
    if (order.status === 'provisioned') {
      return this.buildOutcome(order);
    }
    if (order.status === 'cancelled') {
      throw new ResellerError('This order was cancelled.', 409, 'order_cancelled');
    }

    const paymentMode = options.paymentMode || order.payment_mode || 'wallet';

    // Wallet orders must be covered before we spend upstream credit.
    if (paymentMode === 'wallet') {
      const balance = await this.getWalletBalance(order.user_id);
      const needed = Math.round(order.retail_cents + order.setup_cents);
      if (balance < needed) {
        await this.markOrderFailed(orderId, 'insufficient_wallet_balance',
          `Insufficient panel credit: ${centsToMoney(needed)} EUR required, ${centsToMoney(balance)} EUR available.`);
        throw new ResellerError(
          `Insufficient panel credit: this server costs ${centsToMoney(needed)} EUR per cycle but only ${centsToMoney(balance)} EUR is available.`,
          402,
          'insufficient_wallet_balance',
          { requiredCents: needed, availableCents: balance }
        );
      }
    }

    await this.db.run(
      `UPDATE reseller_orders SET status = 'provisioning', attempts = attempts + 1, updated_at = datetime('now') WHERE id = ?`,
      [orderId]
    );

    const payload: UpstreamKvmOrderInput = {
      os: String(order.os_id),
      name: order.server_name || undefined,
      autoRenew: !!order.auto_renew,
      tos: true,
      cancellation: true,
    };
    const plan = order.plan_id ? await this.db.get<ResellerPlanRow>(
      `SELECT * FROM reseller_plans WHERE id = ?`,
      [order.plan_id]
    ) : null;

    if (plan && plan.kind === 'config') {
      payload.config = {
        cpu: String(plan.cpu_family || ''),
        cores: plan.cores,
        memory: plan.memory_gb,
        disk: plan.disk_gb,
        ipv4: plan.ipv4_count,
        ipv6: plan.ipv6_count,
      };
    } else if (plan && plan.upstream_plan_id) {
      payload.planId = String(plan.upstream_plan_id);
    } else if (order.cpu_family && !plan) {
      // Configurator order stored directly on the order row.
      payload.config = {
        cpu: String(order.cpu_family),
        cores: num(order.cores),
        memory: num(order.memory_gb),
        disk: num(order.disk_gb),
        ipv4: num(order.ipv4_count, 1),
        ipv6: num(order.ipv6_count, 1),
      };
    } else {
      await this.markOrderFailed(orderId, 'plan_not_linked', 'The order is not linked to an upstream plan.');
      throw new ResellerError('The order is not linked to an upstream plan.', 409, 'plan_not_linked');
    }

    let upstream;
    try {
      upstream = await client.orderKvm(payload, order.idempotency_key);
    } catch (err) {
      const apiErr = err instanceof UpstreamApiError ? err : null;
      if (apiErr && TERMINAL_ORDER_FAILURES.has(apiErr.code)) {
        await this.db.run(
          `UPDATE reseller_orders SET error_code = ?, error_message = ?, upstream_request_id = ? WHERE id = ?`,
          [apiErr.code, apiErr.upstreamMessage.slice(0, 1000), apiErr.requestId, orderId]
        );
        await this.markOrderFailed(orderId, apiErr.code, humanizeUpstreamError(apiErr));
        throw toResellerError(apiErr);
      }
      // Unknown outcome (timeout / 5xx / rate limit): keep the order queued.
      // The poller retries with the SAME idempotency key, so the customer is
      // never charged twice and never receives two servers.
      const message = apiErr ? humanizeUpstreamError(apiErr) : (err as Error).message;
      await this.db.run(
        `UPDATE reseller_orders SET status = 'pending', error_code = ?, error_message = ?, updated_at = datetime('now') WHERE id = ?`,
        [apiErr?.code || 'network_error', String(message).slice(0, 1000), orderId]
      );
      throw toResellerError(err);
    }

    const result = (upstream.result || {}) as UpstreamKvmOrderResult & Record<string, unknown>;
    const productId = result.id ? String(result.id) : null;
    const pricing = (result.pricing || null) as Record<string, unknown> | null;
    const upstreamPriceCents = pricing
      ? moneyToCents(String(pricing.orderPrice ?? pricing.price ?? '0'))
      : null;

    if (!productId) {
      await this.markOrderFailed(
        orderId,
        'no_product_id',
        'The provider accepted the order but did not return a product id.'
      );
      throw new ResellerError(
        'The provider accepted the order but did not return a product id. Check the API log and contact the provider with the request id.',
        502,
        'no_product_id',
        { requestId: upstream.requestId }
      );
    }

    // --- Money: charge the panel wallet, record our cost --------------------
    const chargeCents = Math.round(order.retail_cents + order.setup_cents);
    let walletBalance = await this.getWalletBalance(order.user_id);
    if (paymentMode === 'wallet' && chargeCents > 0) {
      walletBalance = await this.appendLedger({
        userId: order.user_id,
        deltaCents: -chargeCents,
        kind: 'order',
        reference: order.order_ref,
        description: `${order.server_name} — ${Math.round(order.duration_months)} month(s)`,
        createdBy: order.placed_by ?? null,
        allowNegative: true, // balance was verified above; upstream already committed
      });
    }

    const credentials = result.credentials
      ? {
          username: String(result.credentials.username || 'root'),
          password: String(result.credentials.password || ''),
        }
      : null;

    const expiresAtUtc = upstreamTimeToUtc(result.expireAt);
    const serverId = await this.upsertCloudServer({
      userId: order.user_id,
      orderId,
      provider: order.provider,
      productId,
      detail: result,
      plan,
      order,
      credentials,
      expiresAtUtc,
      retailCents: chargeCents - Math.round(order.setup_cents),
      costCents: upstreamPriceCents ?? Math.round(order.cost_cents),
      billingMode: paymentMode,
    });

    await this.db.run(
      `UPDATE reseller_orders SET
         status = 'provisioned', charged_cents = ?, upstream_product_id = ?, upstream_state = ?,
         upstream_price_cents = ?, upstream_request_id = ?, error_code = NULL, error_message = NULL,
         provisioned_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?`,
      [
        chargeCents,
        productId,
        String(result.state || 'install'),
        upstreamPriceCents,
        upstream.requestId,
        orderId,
      ]
    );

    await this.db.logActivity({
      userId: order.user_id,
      action: 'reseller_order_provisioned',
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: {
        orderRef: order.order_ref,
        upstreamProductId: productId,
        chargedCents: chargeCents,
        costCents: upstreamPriceCents,
        replayed: upstream.replayed,
      },
    });

    const ipNote = result.primaryIpv4
      ? `IPv4 ${result.primaryIpv4}`
      : 'IP addresses appear as soon as the build finishes (usually a few minutes).';
    await this.notify(
      order.user_id,
      'success',
      'Your server has been ordered',
      `${order.server_name} is being provisioned. ${ipNote}${
        credentials ? ` Login: ${credentials.username} — the password is in your server details.` : ''
      }`,
      { serverId, upstreamProductId: productId }
    );

    if (order.placed_by && order.placed_by !== order.user_id) {
      await this.notify(
        order.placed_by,
        'info',
        'Order placed for a customer',
        `${order.order_ref}: ${order.server_name} provisioned for user #${order.user_id}.`,
        { serverId, upstreamProductId: productId }
      );
    }

    const updated = await this.db.get<Record<string, any>>(
      `SELECT * FROM reseller_orders WHERE id = ?`,
      [orderId]
    );
    const outcome = await this.buildOutcome(updated || order, {
      serverId,
      walletBalanceCents: walletBalance,
      credentials,
      requestId: upstream.requestId,
      replayed: upstream.replayed,
      upstreamPriceCents,
    });
    return outcome;
  }

  /**
   * Re-drives a `pending` order (queued after a timeout/5xx) using its stored
   * idempotency key. Also used by the background poller.
   */
  public async retryOrder(orderId: number): Promise<OrderOutcome> {
    const order = await this.db.get<Record<string, any>>(
      `SELECT * FROM reseller_orders WHERE id = ?`,
      [orderId]
    );
    if (!order) throw new ResellerError('Order not found.', 404, 'order_not_found');
    if (!['pending', 'failed'].includes(order.status)) {
      throw new ResellerError(
        `Only pending or failed orders can be retried (this one is "${order.status}").`,
        409,
        'order_not_retryable'
      );
    }
    if (!order.idempotency_key) {
      throw new ResellerError('This order has no idempotency key and cannot be retried safely.', 409, 'missing_idempotency_key');
    }
    await this.db.run(
      `UPDATE reseller_orders SET status = 'pending', failed_at = NULL, updated_at = datetime('now') WHERE id = ?`,
      [orderId]
    );
    return this.executeOrder(orderId);
  }

  public async cancelOrder(orderId: number, actorId?: number | null): Promise<void> {
    const order = await this.db.get<Record<string, any>>(
      `SELECT * FROM reseller_orders WHERE id = ?`,
      [orderId]
    );
    if (!order) throw new ResellerError('Order not found.', 404, 'order_not_found');
    if (order.status === 'provisioned') {
      throw new ResellerError(
        'This order was already provisioned upstream and cannot be cancelled. Suspend or terminate the server instead.',
        409,
        'order_already_provisioned'
      );
    }
    if (order.status === 'cancelled') return;

    await this.db.run(
      `UPDATE reseller_orders SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?`,
      [orderId]
    );
    await this.db.logActivity({
      userId: actorId ?? null,
      action: 'reseller_order_cancelled',
      resourceType: 'reseller_order',
      resourceId: orderId,
      details: { orderRef: order.order_ref, previousStatus: order.status },
    });
  }

  public async listOrders(options: {
    userId?: number;
    status?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<{ orders: Record<string, any>[]; total: number }> {
    const clauses: string[] = ['o.sandbox = 0'];
    const params: unknown[] = [];
    if (options.userId) {
      clauses.push('o.user_id = ?');
      params.push(options.userId);
    }
    if (options.status) {
      clauses.push('o.status = ?');
      params.push(options.status);
    }
    const where = `WHERE ${clauses.join(' AND ')}`;
    const limit = Math.max(1, Math.min(500, options.limit ?? 50));
    const offset = Math.max(0, options.offset ?? 0);

    const totalRow = await this.db.get<{ total: number }>(
      `SELECT COUNT(*) AS total FROM reseller_orders o ${where}`,
      params
    );
    const orders = await this.db.all(
      `SELECT o.*, u.username AS customer_username, p.display_name AS plan_name
       FROM reseller_orders o
       LEFT JOIN users u ON u.id = o.user_id
       LEFT JOIN reseller_plans p ON p.id = o.plan_id
       ${where}
       ORDER BY o.id DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    return { orders, total: totalRow?.total || 0 };
  }

  public async getOrder(orderId: number): Promise<Record<string, any>> {
    const order = await this.db.get<Record<string, any>>(
      `SELECT o.*, u.username AS customer_username, p.display_name AS plan_name
       FROM reseller_orders o
       LEFT JOIN users u ON u.id = o.user_id
       LEFT JOIN reseller_plans p ON p.id = o.plan_id
       WHERE o.id = ?`,
      [orderId]
    );
    if (!order) throw new ResellerError('Order not found.', 404, 'order_not_found');
    return order;
  }

  // -------------------------------------------------------------------------
  // Cloud servers
  // -------------------------------------------------------------------------

  private async upsertCloudServer(params: {
    userId: number;
    orderId: number | null;
    provider: string;
    productId: string;
    detail: Partial<UpstreamKvmServerDetail>;
    plan?: ResellerPlanRow | null;
    order?: Record<string, any> | null;
    credentials?: { username: string; password: string } | null;
    expiresAtUtc?: string | null;
    retailCents?: number;
    costCents?: number;
    billingMode?: string;
  }): Promise<number> {
    const d = params.detail;
    const existing = await this.db.get<CloudServerRow>(
      `SELECT * FROM cloud_servers WHERE provider_product_id = ? LIMIT 1`,
      [params.productId]
    );

    const name = String(d.name || d.customName || params.order?.server_name || params.productId).slice(0, 120);
    const cpu = String(d.cpu || params.plan?.cpu_family || params.order?.cpu_family || '').toLowerCase();
    const cores = num(d.cores, params.plan?.cores ?? params.order?.cores ?? 1);
    const memoryGb = num(d.memory, params.plan?.memory_gb ?? params.order?.memory_gb ?? 1);
    const diskGb = num(d.disk, params.plan?.disk_gb ?? params.order?.disk_gb ?? 10);
    const connection = num(d.connection, params.plan?.connection_gbit ?? 1);
    const ipv4Count = num(d.ipv4, params.plan?.ipv4_count ?? 1);
    const ipv6Count = num(d.ipv6, params.plan?.ipv6_count ?? 1);
    const state = String(d.state || 'install');
    const osId = d.os ? String(d.os) : (params.order?.os_id ?? null);
    const credentialsEnc = params.credentials
      ? encryptSecret(JSON.stringify(params.credentials))
      : existing?.credentials_enc ?? null;

    if (existing) {
      await this.db.run(
        `UPDATE cloud_servers SET
           name = ?, cpu_family = ?, cpu_label = ?, cores = ?, memory_gb = ?, disk_gb = ?,
           connection_gbit = ?, ipv4_count = ?, ipv6_count = ?, primary_ipv4 = ?, primary_ipv6 = ?,
           os_id = ?, os_label = ?, ssh_user = ?, credentials_enc = COALESCE(?, credentials_enc),
           upstream_state = ?, expires_at = ?, last_synced_at = datetime('now'),
           last_error = NULL, updated_at = datetime('now')
         WHERE id = ?`,
        [
          name,
          cpu,
          cpuFamilyLabel(cpu, name),
          cores,
          memoryGb,
          diskGb,
          connection,
          ipv4Count,
          ipv6Count,
          d.primaryIpv4 ? String(d.primaryIpv4) : existing.primary_ipv4,
          d.primaryIpv6 ? String(d.primaryIpv6) : existing.primary_ipv6,
          osId,
          osId ? osLabelFor(osId) : existing.os_label,
          params.credentials?.username || existing.ssh_user || 'root',
          credentialsEnc,
          state,
          params.expiresAtUtc ?? existing.expires_at,
          existing.id,
        ]
      );
      return existing.id;
    }

    const inserted = await this.db.run(
      `INSERT INTO cloud_servers (
         user_id, order_id, provider, provider_product_id, name, hostname, cpu_family, cpu_label,
         cores, memory_gb, disk_gb, connection_gbit, ipv4_count, ipv6_count, primary_ipv4,
         primary_ipv6, os_id, os_label, ssh_user, ssh_port, credentials_enc, upstream_state,
         power_status, retail_cents, renew_cents, cost_cents, currency, duration_months,
         auto_renew, billing_mode, expires_at, suspended, last_synced_at, upstream_created_at,
         created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),?,datetime('now'),datetime('now'))`,
      [
        params.userId,
        params.orderId,
        params.provider,
        params.productId,
        name,
        params.order?.hostname || null,
        cpu,
        cpuFamilyLabel(cpu, name),
        cores,
        memoryGb,
        diskGb,
        connection,
        ipv4Count,
        ipv6Count,
        d.primaryIpv4 ? String(d.primaryIpv4) : null,
        d.primaryIpv6 ? String(d.primaryIpv6) : null,
        osId,
        osId ? osLabelFor(osId) : null,
        params.credentials?.username || 'root',
        22,
        credentialsEnc,
        state,
        'unknown',
        Math.round(params.retailCents ?? params.plan?.retail_cents ?? 0),
        Math.round(params.retailCents ?? params.plan?.retail_renew_cents ?? 0),
        Math.round(params.costCents ?? params.plan?.cost_cents ?? 0),
        'EUR',
        num(d.duration, params.plan?.duration_months ?? params.order?.duration_months ?? 1),
        d.autoRenew === undefined ? (params.order?.auto_renew ?? 1) : num(d.autoRenew, 1),
        params.billingMode || 'wallet',
        params.expiresAtUtc ?? null,
        0,
        upstreamTimeToUtc(d.createdAt) || null,
      ]
    );
    return inserted.lastID;
  }

  public async listCloudServers(options: {
    userId?: number;
    includeShared?: boolean;
    state?: string;
    search?: string;
    limit?: number;
  } = {}): Promise<CloudServerRow[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (options.userId) {
      clauses.push('user_id = ?');
      params.push(options.userId);
    }
    if (options.state) {
      clauses.push('upstream_state = ?');
      params.push(options.state);
    }
    if (options.search) {
      clauses.push('(name LIKE ? OR primary_ipv4 LIKE ? OR provider_product_id LIKE ?)');
      const like = `%${options.search}%`;
      params.push(like, like, like);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Math.max(1, Math.min(500, options.limit ?? 200));
    return this.db.all<CloudServerRow>(
      `SELECT * FROM cloud_servers ${where} ORDER BY created_at DESC, id DESC LIMIT ?`,
      [...params, limit]
    );
  }

  public async getCloudServer(serverId: number): Promise<CloudServerRow> {
    const server = await this.db.get<CloudServerRow>(`SELECT * FROM cloud_servers WHERE id = ?`, [
      serverId,
    ]);
    if (!server) throw new ResellerError('Cloud server not found.', 404, 'server_not_found');
    return server;
  }

  /** Ownership/RBAC guard used by every customer-facing server endpoint. */
  public async getAuthorizedCloudServer(
    principal: { userId: number; role: string },
    serverId: number,
    requireOwner = false
  ): Promise<CloudServerRow> {
    const server = await this.getCloudServer(serverId);
    const isStaff = ['admin', 'subadmin', 'operator'].includes(String(principal.role).toLowerCase());
    if (isStaff) return server;
    if (server.user_id !== principal.userId) {
      throw new ResellerError('Access denied to this server.', 403, 'access_denied');
    }
    if (requireOwner && server.user_id !== principal.userId) {
      throw new ResellerError('Only the server owner may perform this action.', 403, 'owner_only');
    }
    return server;
  }

  /** Decrypts stored upstream root credentials. */
  public revealCredentials(server: CloudServerRow): { username: string; password: string } | null {
    if (!server.credentials_enc) return null;
    try {
      const plain = decryptSecret(server.credentials_enc);
      if (!plain) return null;
      const parsed = JSON.parse(plain);
      if (parsed && typeof parsed === 'object' && parsed.password !== undefined) {
        return { username: String(parsed.username || 'root'), password: String(parsed.password) };
      }
      return { username: server.ssh_user || 'root', password: String(plain) };
    } catch {
      return null;
    }
  }

  /** Sanitised server view for API responses (credentials only when asked). */
  public serializeServer(
    server: CloudServerRow,
    options: { includeCredentials?: boolean } = {}
  ): Record<string, unknown> {
    const credentials =
      options.includeCredentials && server.credentials_enc ? this.revealCredentials(server) : null;
    return {
      id: server.id,
      userId: server.user_id,
      provider: server.provider,
      upstreamProductId: server.provider_product_id,
      name: server.name,
      hostname: server.hostname,
      cpuFamily: server.cpu_family,
      cpuLabel: server.cpu_label || cpuFamilyLabel(server.cpu_family, server.name),
      cores: server.cores,
      memoryGb: server.memory_gb,
      diskGb: server.disk_gb,
      connectionGbit: server.connection_gbit,
      ipv4Count: server.ipv4_count,
      ipv6Count: server.ipv6_count,
      primaryIpv4: server.primary_ipv4,
      primaryIpv6: server.primary_ipv6,
      osId: server.os_id,
      osLabel: server.os_label,
      sshUser: server.ssh_user,
      sshPort: server.ssh_port,
      state: server.upstream_state,
      powerStatus: server.power_status,
      suspended: !!server.suspended,
      suspendedReason: server.suspended_reason,
      retailCents: server.retail_cents,
      renewCents: server.renew_cents,
      costCents: server.cost_cents,
      currency: server.currency,
      durationMonths: server.duration_months,
      autoRenew: !!server.auto_renew,
      billingMode: server.billing_mode,
      expiresAt: server.expires_at,
      expiresAtDisplay: formatUtcForDisplay(server.expires_at),
      lastSyncedAt: server.last_synced_at,
      lastError: server.last_error,
      createdAt: server.created_at,
      credentials,
    };
  }

  // --- Live upstream operations -------------------------------------------

  public async refreshServer(
    serverId: number,
    options: { withStatus?: boolean } = {}
  ): Promise<{ server: CloudServerRow; status: UpstreamKvmStatus | null }> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError(
        'This server is not linked to an upstream product yet.',
        409,
        'not_provisioned'
      );
    }

    const detail = await client.getKvm(server.provider_product_id);
    let status: UpstreamKvmStatus | null = null;
    if (options.withStatus !== false) {
      try {
        status = await client.getKvmStatus(server.provider_product_id);
      } catch (err) {
        if (!(err instanceof UpstreamApiError) || !['not_provisioned', 'product_busy', 'not_found'].includes(err.code)) {
          throw err;
        }
        status = null;
      }
    }

    await this.applyUpstreamServerState(server, detail, status);
    return { server: await this.getCloudServer(serverId), status };
  }

  private async applyUpstreamServerState(
    server: CloudServerRow,
    detail: Partial<UpstreamKvmServerDetail>,
    status: UpstreamKvmStatus | null
  ): Promise<void> {
    const state = String(status?.state || detail.state || server.upstream_state);
    const power = status?.status ? String(status.status) : server.power_status;
    const expiresAtUtc = upstreamTimeToUtc(detail.expireAt) || server.expires_at;

    await this.db.run(
      `UPDATE cloud_servers SET
         upstream_state = ?, power_status = ?, primary_ipv4 = COALESCE(?, primary_ipv4),
         primary_ipv6 = COALESCE(?, primary_ipv6), expires_at = ?, auto_renew = ?,
         renew_cents = ?, cores = ?, memory_gb = ?, disk_gb = ?, ipv4_count = ?, ipv6_count = ?,
         connection_gbit = ?, name = ?, last_error = NULL,
         last_synced_at = datetime('now'), last_status_at = datetime('now'),
         updated_at = datetime('now')
       WHERE id = ?`,
      [
        state,
        power,
        detail.primaryIpv4 ? String(detail.primaryIpv4) : null,
        detail.primaryIpv6 ? String(detail.primaryIpv6) : null,
        expiresAtUtc,
        detail.autoRenew === undefined ? server.auto_renew : num(detail.autoRenew, server.auto_renew),
        detail.price ? Math.max(0, moneyToCents(String(detail.price))) : server.renew_cents,
        num(detail.cores, server.cores),
        num(detail.memory, server.memory_gb),
        num(detail.disk, server.disk_gb),
        num(detail.ipv4, server.ipv4_count),
        num(detail.ipv6, server.ipv6_count),
        num(detail.connection, server.connection_gbit),
        detail.name ? String(detail.name).slice(0, 120) : server.name,
        server.id,
      ]
    );
  }

  public async serverPower(
    serverId: number,
    action: 'start' | 'stop' | 'restart',
    actor?: { userId: number; role: string }
  ): Promise<CloudServerRow> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    if (server.suspended) {
      throw new ResellerError(
        `This server is suspended${server.suspended_reason ? ` (${server.suspended_reason})` : ''}. Contact support.`,
        403,
        'server_suspended'
      );
    }

    try {
      if (action === 'restart') await client.kvmRestart(server.provider_product_id);
      else await client.kvmPower(server.provider_product_id, action);
    } catch (err) {
      if (err instanceof UpstreamApiError && (err.code === 'already_running' || err.code === 'already_stopped')) {
        // Treat as a no-op success and refresh state below.
      } else {
        throw err;
      }
    }

    await this.db.logActivity({
      userId: actor?.userId ?? null,
      action: `cloud_server_${action}`,
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: { name: server.name, upstreamProductId: server.provider_product_id },
    });

    const refreshed = await this.refreshServer(serverId).catch(() => null);
    return refreshed ? refreshed.server : server;
  }

  public async serverConsoleUrl(serverId: number): Promise<{ consoleUrl: string }> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    // The provider returns a short-lived noVNC link — fetch and hand it over
    // immediately, never store it.
    const data = await client.getKvmConsole(server.provider_product_id);
    if (!data?.consoleUrl) {
      throw new ResellerError('The provider did not return a console link.', 502, 'no_console_url');
    }
    return { consoleUrl: String(data.consoleUrl) };
  }

  public async serverStatus(serverId: number): Promise<UpstreamKvmStatus> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    const status = await client.getKvmStatus(server.provider_product_id);
    await this.db.run(
      `UPDATE cloud_servers SET power_status = ?, upstream_state = ?, last_status_at = datetime('now') WHERE id = ?`,
      [String(status.status || 'unknown'), String(status.state || server.upstream_state), serverId]
    );
    return status;
  }

  public async serverStatistics(
    serverId: number,
    period: 'hour' | 'day' | 'week' | 'month' | 'year' = 'hour'
  ): Promise<UpstreamKvmStatistics> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    return client.getKvmStatistics(server.provider_product_id, period);
  }

  public async serverNetwork(serverId: number, rdns = false): Promise<UpstreamKvmNetwork> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    return client.getKvmNetwork(server.provider_product_id, rdns);
  }

  public async serverFirewall(serverId: number): Promise<UpstreamFirewall> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    return client.getKvmFirewall(server.provider_product_id);
  }

  public async serverReinstall(
    serverId: number,
    input: { os: string; password?: string; confirm: true },
    actor?: { userId: number; role: string }
  ): Promise<{ state: string; credentials: { username: string; password: string } | null }> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    if (input.confirm !== true) {
      throw new ResellerError('Reinstall must be confirmed — all data on the server is destroyed.', 422, 'confirm_required');
    }
    if (input.password && !PASSWORD_PATTERN.test(input.password)) {
      throw new ResellerError(
        'Password must be 8-64 characters using letters, digits and !#$%&()*+,-./:;=?@^_{|}~',
        422,
        'invalid_password'
      );
    }

    const idempotencyKey = buildIdempotencyKey(
      'tgv-reinstall',
      `${server.provider_product_id}-${Date.now()}`
    );
    const result = await client.reinstallKvm(
      server.provider_product_id,
      { os: String(input.os), password: input.password, confirm: true },
      idempotencyKey
    );

    const credentials = result.credentials
      ? { username: String(result.credentials.username || 'root'), password: String(result.credentials.password) }
      : null;
    if (credentials) {
      await this.db.run(
        `UPDATE cloud_servers SET credentials_enc = ?, ssh_user = ?, os_id = ?, os_label = ?,
           upstream_state = ?, power_status = 'unknown', updated_at = datetime('now')
         WHERE id = ?`,
        [encryptSecret(JSON.stringify(credentials)), credentials.username, String(input.os), osLabelFor(String(input.os)), String(result.state || 'reinstall'), serverId]
      );
    } else {
      await this.db.run(
        `UPDATE cloud_servers SET os_id = ?, os_label = ?, upstream_state = ?, power_status = 'unknown', updated_at = datetime('now') WHERE id = ?`,
        [String(input.os), osLabelFor(String(input.os)), String(result.state || 'reinstall'), serverId]
      );
    }

    await this.db.logActivity({
      userId: actor?.userId ?? null,
      action: 'cloud_server_reinstall',
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: { os: input.os, name: server.name },
    });
    await this.notify(
      server.user_id,
      'warning',
      'Server reinstall started',
      `${server.name} is being reinstalled with ${osLabelFor(String(input.os))}. All data on the server is destroyed.`
    );

    return { state: String(result.state || 'reinstall'), credentials };
  }

  public async serverSetPassword(
    serverId: number,
    password: string,
    actor?: { userId: number; role: string }
  ): Promise<{ username: string; password: string }> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    if (!PASSWORD_PATTERN.test(String(password || ''))) {
      throw new ResellerError(
        'Password must be 8-64 characters using letters, digits and !#$%&()*+,-./:;=?@^_{|}~',
        422,
        'invalid_password'
      );
    }
    // Requires the server to be running with the QEMU guest agent installed.
    const result = await client.setKvmPassword(server.provider_product_id, String(password));
    const credentials = {
      username: String(result.credentials?.username || server.ssh_user || 'root'),
      password: String(result.credentials?.password || password),
    };
    await this.db.run(
      `UPDATE cloud_servers SET credentials_enc = ?, ssh_user = ?, updated_at = datetime('now') WHERE id = ?`,
      [encryptSecret(JSON.stringify(credentials)), credentials.username, serverId]
    );
    await this.db.logActivity({
      userId: actor?.userId ?? null,
      action: 'cloud_server_password_change',
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: { name: server.name },
    });
    return credentials;
  }

  public async serverSetAutoRenew(
    serverId: number,
    autoRenew: boolean,
    actor?: { userId: number; role: string }
  ): Promise<CloudServerRow> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    await client.setAutoRenew(server.provider_product_id, autoRenew ? 1 : 0);
    await this.db.run(
      `UPDATE cloud_servers SET auto_renew = ?, updated_at = datetime('now') WHERE id = ?`,
      [autoRenew ? 1 : 0, serverId]
    );
    await this.db.logActivity({
      userId: actor?.userId ?? null,
      action: 'cloud_server_autorenew',
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: { name: server.name, autoRenew },
    });
    return this.getCloudServer(serverId);
  }

  public async serverRename(
    serverId: number,
    name: string,
    actor?: { userId: number; role: string }
  ): Promise<CloudServerRow> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    const clean = sanitizeProductName(name);
    if (!clean) throw new ResellerError('Please provide a valid server name.', 422, 'invalid_name');
    if (server.provider_product_id) {
      await client.renameProduct(server.provider_product_id, clean);
    }
    await this.db.run(
      `UPDATE cloud_servers SET name = ?, updated_at = datetime('now') WHERE id = ?`,
      [clean, serverId]
    );
    await this.db.logActivity({
      userId: actor?.userId ?? null,
      action: 'cloud_server_rename',
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: { from: server.name, to: clean },
    });
    return this.getCloudServer(serverId);
  }

  /** Admin-only local suspension (does not touch the upstream product). */
  public async setSuspension(
    serverId: number,
    suspended: boolean,
    reason: string | null,
    actor?: { userId: number; role: string }
  ): Promise<CloudServerRow> {
    const server = await this.getCloudServer(serverId);
    await this.db.run(
      `UPDATE cloud_servers SET suspended = ?, suspended_reason = ?, updated_at = datetime('now') WHERE id = ?`,
      [suspended ? 1 : 0, suspended ? (reason || 'Suspended by staff').slice(0, 255) : null, serverId]
    );
    await this.db.logActivity({
      userId: actor?.userId ?? null,
      action: suspended ? 'cloud_server_suspend' : 'cloud_server_unsuspend',
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: { name: server.name, reason },
    });
    await this.notify(
      server.user_id,
      suspended ? 'warning' : 'success',
      suspended ? 'Server suspended' : 'Server reactivated',
      suspended
        ? `${server.name} was suspended${reason ? `: ${reason}` : ''}. Please contact support.`
        : `${server.name} is active again.`
    );
    return this.getCloudServer(serverId);
  }

  // -------------------------------------------------------------------------
  // Renewals
  // -------------------------------------------------------------------------

  public async renewalQuote(serverId: number): Promise<{
    quote: UpstreamRenewQuote | null;
    retailCents: number;
    walletBalanceCents: number;
    sufficient: boolean;
    newExpiresAt: string | null;
  }> {
    const server = await this.getCloudServer(serverId);
    const walletBalanceCents = await this.getWalletBalance(server.user_id);
    const retailCents = Math.max(0, Math.round(server.renew_cents || server.retail_cents || 0));

    let quote: UpstreamRenewQuote | null = null;
    if (server.provider_product_id) {
      try {
        const client = await this.requireReady();
        quote = await client.getRenewal(server.provider_product_id);
      } catch {
        quote = null;
      }
    }
    return {
      quote,
      retailCents,
      walletBalanceCents,
      sufficient: walletBalanceCents >= retailCents,
      newExpiresAt: quote ? upstreamTimeToUtc(quote.newExpireAt) : null,
    };
  }

  /**
   * Renews a server: charges the customer wallet, then extends the upstream
   * product. If the upstream renewal fails terminally the charge is reversed
   * automatically so the customer never pays for nothing.
   */
  public async renewServer(
    serverId: number,
    actor?: { userId: number; role: string }
  ): Promise<{
    server: CloudServerRow;
    chargedCents: number;
    costCents: number;
    walletBalanceCents: number;
    newExpiresAt: string | null;
  }> {
    const client = await this.requireReady();
    const server = await this.getCloudServer(serverId);
    if (!server.provider_product_id) {
      throw new ResellerError('This server is still being provisioned.', 409, 'not_provisioned');
    }
    if (server.billing_mode === 'free') {
      throw new ResellerError('This server is comped and does not renew from the wallet.', 409, 'billing_mode_free');
    }

    const retailCents = Math.max(0, Math.round(server.renew_cents || server.retail_cents || 0));
    const balance = await this.getWalletBalance(server.user_id);
    const chargeWallet = server.billing_mode === 'wallet' && retailCents > 0;
    if (chargeWallet && balance < retailCents) {
      throw new ResellerError(
        `Insufficient panel credit: renewal costs ${centsToMoney(retailCents)} EUR but only ${centsToMoney(balance)} EUR is available.`,
        402,
        'insufficient_wallet_balance',
        { requiredCents: retailCents, availableCents: balance }
      );
    }

    const idempotencyKey = buildIdempotencyKey(
      'tgv-renew',
      `${server.provider_product_id}-${Date.now()}`
    );

    let result;
    try {
      result = await client.renewProduct(server.provider_product_id, idempotencyKey);
    } catch (err) {
      throw toResellerError(err);
    }

    const costCents = moneyToCents(result.price);
    let walletBalanceCents = balance;
    if (chargeWallet) {
      walletBalanceCents = await this.appendLedger({
        userId: server.user_id,
        deltaCents: -retailCents,
        kind: 'renewal',
        reference: server.provider_product_id,
        description: `Renewal — ${server.name}`,
        createdBy: actor?.userId ?? null,
        allowNegative: true,
      });
    }

    const newExpiresAt = upstreamTimeToUtc(result.expireAt);
    await this.db.run(
      `UPDATE cloud_servers SET expires_at = ?, renew_cents = ?, cost_cents = ?,
         upstream_state = 'active', suspended = 0, suspended_reason = NULL,
         last_synced_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?`,
      [newExpiresAt, retailCents, costCents, serverId]
    );

    await this.db.logActivity({
      userId: actor?.userId ?? server.user_id,
      action: 'cloud_server_renew',
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: { name: server.name, chargedCents: retailCents, costCents, newExpiresAt },
    });
    await this.notify(
      server.user_id,
      'success',
      'Server renewed',
      `${server.name} was renewed${chargeWallet ? ` for ${centsToMoney(retailCents)} EUR` : ''}. New expiry: ${formatUtcForDisplay(newExpiresAt)}.`
    );

    return {
      server: await this.getCloudServer(serverId),
      chargedCents: chargeWallet ? retailCents : 0,
      costCents,
      walletBalanceCents,
      newExpiresAt,
    };
  }

  // -------------------------------------------------------------------------
  // Background reconciliation
  // -------------------------------------------------------------------------

  /** Starts the provisioning poller and the catalogue sync timer. */
  public startBackgroundJobs(): void {
    this.stopBackgroundJobs();
    const envDisabled = String(process.env.TGVPANEL_DISABLE_RESELLER_POLLER || '').toLowerCase();
    if (['1', 'true', 'yes'].includes(envDisabled)) return;

    const pollSec = Math.max(10, Number(process.env.RESELLER_POLL_INTERVAL_SEC) || 30);
    const syncSec = Math.max(300, Number(process.env.RESELLER_SYNC_INTERVAL_SEC) || 900);

    this.pollTimer = setInterval(() => {
      this.syncLoop().catch((err) => {
        console.warn('[Reseller] sync loop error:', (err as Error).message);
      });
    }, pollSec * 1000);
    this.pollTimer.unref?.();

    this.syncTimer = setInterval(() => {
      this.syncCatalogueIfEnabled().catch((err) => {
        console.warn('[Reseller] catalogue sync error:', (err as Error).message);
      });
    }, syncSec * 1000);
    this.syncTimer.unref?.();

    // Kick once shortly after boot so queued orders drain without waiting.
    const kickoff = setTimeout(() => {
      this.syncLoop().catch(() => undefined);
    }, 8000);
    kickoff.unref?.();
  }

  public stopBackgroundJobs(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.pollTimer = null;
    this.syncTimer = null;
  }

  private async syncCatalogueIfEnabled(): Promise<void> {
    if (this.syncRunning) return;
    const ready = await this.isReady();
    if (!ready.ready) return;
    this.syncRunning = true;
    try {
      await this.syncCatalogue();
    } finally {
      this.syncRunning = false;
    }
  }

  /**
   * One reconciliation pass:
   *  1. Re-drive queued orders (idempotent, so never a double purchase).
   *  2. Move `install`/`reinstall` servers to `active` and publish their IPs.
   *  3. Refresh expiry/auto-renew for active servers.
   *  4. Warn the admin when the upstream balance runs low.
   */
  public async syncLoop(): Promise<{
    ordersRetried: number;
    ordersProvisioned: number;
    serversUpdated: number;
    becameActive: number;
    errors: string[];
  }> {
    if (this.pollRunning) {
      return { ordersRetried: 0, ordersProvisioned: 0, serversUpdated: 0, becameActive: 0, errors: [] };
    }
    const ready = await this.isReady();
    if (!ready.ready) {
      return { ordersRetried: 0, ordersProvisioned: 0, serversUpdated: 0, becameActive: 0, errors: [] };
    }

    this.pollRunning = true;
    const errors: string[] = [];
    let ordersRetried = 0;
    let ordersProvisioned = 0;
    let serversUpdated = 0;
    let becameActive = 0;

    try {
      // 1) Queued orders ---------------------------------------------------
      const queued = await this.db.all<{ id: number }>(
        `SELECT id FROM reseller_orders
         WHERE status IN ('pending', 'provisioning') AND sandbox = 0
         ORDER BY id ASC LIMIT 10`
      );
      for (const row of queued) {
        ordersRetried += 1;
        try {
          const outcome = await this.executeOrder(row.id);
          if (outcome.status === 'provisioned') ordersProvisioned += 1;
        } catch (err) {
          const e = toResellerError(err);
          errors.push(`order#${row.id}: ${e.message}`);
          // Avoid hammering a hard-failing order every tick.
          if (e.statusCode >= 400 && e.statusCode < 500 && e.code !== 'rate_limited') {
            await this.markOrderFailed(row.id, e.code, e.message).catch(() => undefined);
          }
        }
      }

      // 2) Servers still building, and 3) periodic refresh of active ones ----
      const building = await this.db.all<CloudServerRow>(
        `SELECT * FROM cloud_servers
         WHERE provider_product_id IS NOT NULL
           AND upstream_state IN ('install', 'reinstall', 'pending')
         ORDER BY id ASC LIMIT 25`
      );
      const staleActive = await this.db.all<CloudServerRow>(
        `SELECT * FROM cloud_servers
         WHERE provider_product_id IS NOT NULL
           AND upstream_state NOT IN ('install', 'reinstall', 'pending')
           AND (last_synced_at IS NULL OR datetime(last_synced_at) <= datetime('now', '-10 minutes'))
         ORDER BY last_synced_at ASC LIMIT 15`
      );

      const client = await this.getClient();
      for (const server of [...building, ...staleActive]) {
        if (!server.provider_product_id) continue;
        try {
          const detail = await client.getKvm(server.provider_product_id);
          let status: UpstreamKvmStatus | null = null;
          try {
            status = await client.getKvmStatus(server.provider_product_id);
          } catch {
            status = null;
          }
          const wasBuilding = ['install', 'reinstall', 'pending'].includes(server.upstream_state);
          await this.applyUpstreamServerState(server, detail, status);
          serversUpdated += 1;

          const newState = String(detail.state || server.upstream_state);
          if (wasBuilding && newState === 'active') {
            becameActive += 1;
            await this.onServerBecameActive(server.id, detail);
          }
        } catch (err) {
          const e = toResellerError(err);
          if (e.code === 'not_found') {
            await this.db.run(
              `UPDATE cloud_servers SET last_error = ?, upstream_state = 'cancelled', updated_at = datetime('now') WHERE id = ?`,
              ['Product no longer exists upstream.', server.id]
            );
            await this.notify(
              server.user_id,
              'error',
              'Server no longer available upstream',
              `${server.name} could not be found at the provider any more. Please contact support.`
            );
          } else {
            await this.db.run(
              `UPDATE cloud_servers SET last_error = ? WHERE id = ?`,
              [e.message.slice(0, 500), server.id]
            );
            errors.push(`server#${server.id}: ${e.message}`);
          }
        }
      }

      // 4) Low upstream balance warning ------------------------------------
      await this.checkUpstreamBalanceAlert(client).catch(() => undefined);
    } finally {
      this.pollRunning = false;
    }

    return { ordersRetried, ordersProvisioned, serversUpdated, becameActive, errors };
  }

  private async onServerBecameActive(
    serverId: number,
    detail: Partial<UpstreamKvmServerDetail>
  ): Promise<void> {
    const server = await this.getCloudServer(serverId).catch(() => null);
    if (!server) return;
    const ipv4 = detail.primaryIpv4 ? String(detail.primaryIpv4) : server.primary_ipv4;
    const ipv6 = detail.primaryIpv6 ? String(detail.primaryIpv6) : server.primary_ipv6;
    const credentials = this.revealCredentials(server);

    await this.notify(
      server.user_id,
      'success',
      'Your server is ready',
      `${server.name} is now active.${ipv4 ? ` IPv4: ${ipv4}.` : ''}${ipv6 ? ` IPv6: ${ipv6}.` : ''}${
        credentials ? ` SSH: ${credentials.username}@${ipv4 || '<ip>'} — password is in your server details.` : ''
      }`,
      { serverId, ipv4, ipv6 }
    );
    await this.db.logActivity({
      userId: server.user_id,
      action: 'cloud_server_ready',
      resourceType: 'cloud_server',
      resourceId: serverId,
      details: { name: server.name, ipv4, ipv6 },
    });
  }

  private lastBalanceAlertAt = 0;

  private async checkUpstreamBalanceAlert(client: ResellerApiClient): Promise<void> {
    const cfg = await this.getSettings();
    // At most one alert per hour.
    if (Date.now() - this.lastBalanceAlertAt < 60 * 60 * 1000) return;
    try {
      const balance = await client.getBalance();
      const cents = moneyToCents(balance.amount);
      await this.setSetting('reseller_upstream_balance_cents', String(cents));
      if (cents < cfg.reseller_low_balance_alert_cents) {
        this.lastBalanceAlertAt = Date.now();
        const admins = await this.db.all<{ id: number }>(
          `SELECT id FROM users WHERE role = 'admin' AND is_active = 1`
        );
        for (const admin of admins) {
          await this.notify(
            admin.id,
            'error',
            'Upstream reseller balance is low',
            `Only ${centsToMoney(cents)} ${balance.currency || 'EUR'} left at the provider. New orders will fail with insufficient_balance once it is exhausted.`,
            { balanceCents: cents }
          );
        }
      }
    } catch {
      // Non-critical.
    }
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private async markOrderFailed(orderId: number, code: string, message: string): Promise<void> {
    await this.db.run(
      `UPDATE reseller_orders SET status = 'failed', error_code = ?, error_message = ?,
         failed_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?`,
      [code, String(message).slice(0, 1000), orderId]
    );
    const order = await this.db.get<{ user_id: number; server_name: string; order_ref: string }>(
      `SELECT user_id, server_name, order_ref FROM reseller_orders WHERE id = ?`,
      [orderId]
    );
    if (order?.user_id) {
      await this.notify(
        order.user_id,
        'error',
        'Order could not be completed',
        `${order.server_name || order.order_ref}: ${message}`,
        { orderId, code }
      );
    }
  }

  /**
   * Assembles the API-facing outcome for an order, joining the provisioned
   * `cloud_servers` row so callers get IPs/credentials in one shot.
   */
  private async buildOutcome(
    order: Record<string, any>,
    extra: {
      serverId?: number | null;
      walletBalanceCents?: number;
      credentials?: { username: string; password: string } | null;
      requestId?: string | null;
      replayed?: boolean;
      upstreamPriceCents?: number | null;
    } = {}
  ): Promise<OrderOutcome> {
    const productId = order.upstream_product_id ? String(order.upstream_product_id) : null;
    let server: CloudServerRow | null = null;
    if (extra.serverId) {
      server = await this.db.get<CloudServerRow>(`SELECT * FROM cloud_servers WHERE id = ?`, [
        extra.serverId,
      ]).catch(() => null) ?? null;
    }
    if (!server && productId) {
      server =
        (await this.db
          .get<CloudServerRow>(
            `SELECT * FROM cloud_servers WHERE provider_product_id = ? ORDER BY id DESC LIMIT 1`,
            [productId]
          )
          .catch(() => undefined)) || null;
    }

    const credentials =
      extra.credentials ?? (server ? this.revealCredentials(server) : null);
    const walletBalanceCents =
      extra.walletBalanceCents !== undefined && extra.walletBalanceCents !== null
        ? extra.walletBalanceCents
        : order.user_id
          ? await this.getWalletBalance(order.user_id).catch(() => 0)
          : 0;

    return {
      orderId: num(order.id),
      orderRef: String(order.order_ref || ''),
      status: String(order.status || 'pending'),
      sandbox: !!order.sandbox,
      retailCents: num(order.retail_cents),
      setupCents: num(order.setup_cents),
      chargedCents: num(order.charged_cents),
      costCents: num(order.cost_cents),
      upstreamPriceCents:
        extra.upstreamPriceCents !== undefined
          ? extra.upstreamPriceCents
          : numOrNull(order.upstream_price_cents),
      walletBalanceCents,
      serverId: server ? server.id : null,
      upstreamProductId: productId,
      upstreamState: server ? server.upstream_state : order.upstream_state ? String(order.upstream_state) : null,
      primaryIpv4: server?.primary_ipv4 || null,
      primaryIpv6: server?.primary_ipv6 || null,
      credentials,
      requestId:
        extra.requestId ?? (order.upstream_request_id ? String(order.upstream_request_id) : null),
      replayed: !!extra.replayed,
      errorCode: order.error_code ? String(order.error_code) : null,
      error: order.error_message ? String(order.error_message) : null,
    };
  }

  private async notify(
    userId: number,
    type: 'info' | 'success' | 'warning' | 'error',
    title: string,
    message: string,
    data?: Record<string, unknown>
  ): Promise<void> {
    try {
      await this.db.run(
        `INSERT INTO notifications (user_id, type, title, message, data, created_at)
         VALUES (?,?,?,?,?,datetime('now'))`,
        [userId, type, title.slice(0, 200), message.slice(0, 1000), data ? JSON.stringify(data) : null]
      );
    } catch {
      // Notifications are best-effort.
    }
  }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

export function applyMarkup(costCents: number, markupPercent: number): number {
  const pct = Number.isFinite(markupPercent) ? markupPercent : 0;
  const gross = Math.round(costCents * (1 + pct / 100));
  // Round to a clean 0.50 EUR step so storefront prices look intentional,
  // but never below cost.
  const stepped = Math.round(gross / 50) * 50;
  return Math.max(costCents, stepped || gross);
}

export function sanitizeProductName(name: unknown): string | null {
  const raw = String(name ?? '').trim().replace(/\s+/g, ' ');
  if (!raw) return null;
  if (!PRODUCT_NAME_PATTERN.test(raw)) return null;
  return raw.slice(0, 50);
}

export function sanitizeHostname(hostname: unknown): string | null {
  const raw = String(hostname ?? '').trim().toLowerCase();
  if (!raw) return null;
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(raw)) {
    return null;
  }
  return raw.slice(0, 253);
}

function osLabelFor(osId: string): string {
  return String(osId)
    .split('-')
    .map((p) => (p ? p.charAt(0).toUpperCase() + p.slice(1) : p))
    .join(' ');
}

function describePlan(plan: UpstreamKvmPlan): string {
  const parts = [
    `${plan.cores} vCPU`,
    `${plan.memory} GB RAM`,
    `${plan.disk} GB storage`,
    `${plan.connection} Gbit/s`,
  ];
  if (plan.ipv4) parts.push(`${plan.ipv4} IPv4`);
  if (plan.ipv6) parts.push(`${plan.ipv6} IPv6`);
  return parts.join(' · ');
}

function toStorePlan(plan: ResellerPlanRow): StorePlan {
  let upstreamConfig: Record<string, unknown> | null = null;
  if (plan.kind === 'config') {
    try {
      const raw = plan.upstream_raw ? JSON.parse(plan.upstream_raw) : null;
      if (raw && typeof raw === 'object') {
        upstreamConfig = {
          cpu: raw.cpu,
          cores: raw.cores,
          memory: raw.memory,
          disk: raw.disk,
          ipv4: raw.ipv4,
          ipv6: raw.ipv6,
        };
      }
    } catch {
      upstreamConfig = null;
    }
    if (!upstreamConfig) {
      upstreamConfig = {
        cpu: plan.cpu_family,
        cores: plan.cores,
        memory: plan.memory_gb,
        disk: plan.disk_gb,
        ipv4: plan.ipv4_count,
        ipv6: plan.ipv6_count,
      };
    }
  }
  return {
    id: plan.id,
    slug: plan.slug,
    kind: plan.kind,
    displayName: plan.display_name,
    description: plan.description,
    cpuFamily: plan.cpu_family,
    cpuLabel: plan.cpu_label || cpuFamilyLabel(plan.cpu_family, plan.display_name),
    cores: plan.cores,
    memoryGb: plan.memory_gb,
    diskGb: plan.disk_gb,
    ipv4: plan.ipv4_count,
    ipv6: plan.ipv6_count,
    connectionGbit: plan.connection_gbit,
    durationMonths: plan.duration_months,
    retailCents: plan.retail_cents,
    retailRenewCents: plan.retail_renew_cents,
    setupCents: plan.setup_cents,
    currency: plan.currency,
    popular: !!plan.is_popular,
    available: plan.upstream_available !== 0,
    upstreamPlanId: plan.upstream_plan_id,
    upstreamConfig,
    discountPercent: plan.upstream_discount_percent,
  };
}

function generateOrderRef(): string {
  const now = new Date();
  const stamp = `${now.getUTCFullYear()}${String(now.getUTCMonth() + 1).padStart(2, '0')}${String(
    now.getUTCDate()
  ).padStart(2, '0')}-${String(now.getUTCHours()).padStart(2, '0')}${String(now.getUTCMinutes()).padStart(
    2,
    '0'
  )}${String(now.getUTCSeconds()).padStart(2, '0')}`;
  const rand = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `TGV-${stamp}-${rand}`;
}

function num(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function numOrNull(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}
