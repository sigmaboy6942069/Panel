/**
 * Low-level HTTP client for the upstream reseller provider (Bukkit-Hosting API v2).
 *
 * Responsibilities, deliberately kept separate from business logic:
 *  - Bearer auth with the reseller API key (never logged, never echoed back).
 *  - Envelope handling: unwraps `{ response, state, data }`, throws typed errors.
 *  - `Idempotency-Key` support for every mutating order/renew/reinstall call.
 *  - Rate-limit awareness: surfaces `X-RateLimit-*`, honours `Retry-After` on 429.
 *  - Bounded retries with jittered backoff for network errors, 429 and 5xx.
 *  - Request logging with credential redaction.
 *
 * Uses Node's built-in http/https so the module has no runtime dependency
 * beyond the standard library.
 */
import http from 'http';
import https from 'https';
import { URL } from 'url';
import {
  UpstreamAccount,
  UpstreamBalance,
  UpstreamEnvelope,
  UpstreamErrorData,
  UpstreamFirewall,
  UpstreamFirewallRuleInput,
  UpstreamKvmConfigurator,
  UpstreamKvmConfiguratorPrice,
  UpstreamKvmNetwork,
  UpstreamKvmOrderInput,
  UpstreamKvmOrderPreview,
  UpstreamKvmOrderResult,
  UpstreamKvmOs,
  UpstreamKvmPlan,
  UpstreamKvmServer,
  UpstreamKvmServerDetail,
  UpstreamKvmStatistics,
  UpstreamKvmStatus,
  UpstreamPagination,
  UpstreamProduct,
  UpstreamRateLimitInfo,
  UpstreamRenewQuote,
  UpstreamRenewResult,
  UpstreamResellerInfo,
  UpstreamTransaction,
} from './types';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type UpstreamErrorKind =
  | 'api'
  | 'network'
  | 'timeout'
  | 'config'
  | 'protocol'
  | 'ratelimit';

/**
 * Thrown for every failed upstream interaction. `code` is the provider's
 * stable machine code (`insufficient_balance`, `out_of_stock`, ...) when the
 * provider supplied one, otherwise a local kind such as `network_error`.
 */
export class UpstreamApiError extends Error {
  public readonly kind: UpstreamErrorKind;
  public readonly statusCode: number;
  public readonly code: string;
  public readonly data: UpstreamErrorData;
  public readonly requestId: string | null;
  public readonly endpoint: string;
  public readonly method: string;
  public readonly rateLimit: UpstreamRateLimitInfo;
  /** Human-readable provider message; safe to show to an administrator. */
  public readonly upstreamMessage: string;
  /** True when re-sending the identical request could succeed. */
  public readonly retryable: boolean;
  /** Seconds to wait before retrying (from `Retry-After`), when provided. */
  public readonly retryAfterSec: number | null;

  constructor(params: {
    kind: UpstreamErrorKind;
    message: string;
    statusCode?: number;
    code?: string;
    data?: UpstreamErrorData;
    requestId?: string | null;
    endpoint?: string;
    method?: string;
    rateLimit?: UpstreamRateLimitInfo;
    upstreamMessage?: string;
    retryable?: boolean;
    retryAfterSec?: number | null;
  }) {
    super(params.message);
    this.name = 'UpstreamApiError';
    this.kind = params.kind;
    this.statusCode = params.statusCode ?? 0;
    this.code = params.code || 'unknown_error';
    this.data = params.data || { code: params.code || 'unknown_error' };
    this.requestId = params.requestId ?? null;
    this.endpoint = params.endpoint || '';
    this.method = params.method || 'GET';
    this.rateLimit = params.rateLimit || emptyRateLimit();
    this.upstreamMessage = params.upstreamMessage || params.message;
    this.retryable = params.retryable ?? false;
    this.retryAfterSec = params.retryAfterSec ?? null;
  }

  /** Flat field errors for 422 `validation_failed` responses. */
  public fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {};
    const raw = this.data?.errors;
    if (!raw || typeof raw !== 'object') return out;
    for (const [field, value] of Object.entries(raw)) {
      out[field] = Array.isArray(value) ? value.join('; ') : String(value);
    }
    return out;
  }

  toJSON() {
    return {
      error: this.message,
      code: this.code,
      kind: this.kind,
      statusCode: this.statusCode,
      requestId: this.requestId,
      retryable: this.retryable,
      retryAfterSec: this.retryAfterSec,
      fields: this.fieldErrors(),
      balance:
        this.code === 'insufficient_balance'
          ? { required: this.data.required ?? null, available: this.data.available ?? null }
          : undefined,
    };
  }
}

export function emptyRateLimit(): UpstreamRateLimitInfo {
  return { limit: null, remaining: null, reset: null, retryAfter: null };
}

/** Error codes for which an identical retry is pointless. */
const NON_RETRYABLE_CODES = new Set([
  'unauthorized',
  'invalid_json',
  'validation_failed',
  'idempotency_mismatch',
  'invalid_idempotency_key',
  'insufficient_balance',
  'owner_only',
  'reseller_only',
  'account_inactive',
  'profile_locked',
  'not_found',
  'endpoint_not_found',
  'method_not_allowed',
  'invalid_price',
  'voucher_invalid',
  'premium_domain',
  'not_offered',
  'domain_unavailable',
  'payload_too_large',
  'out_of_stock',
  'not_available',
]);

// ---------------------------------------------------------------------------
// Money helpers — integer cents end to end, never floats
// ---------------------------------------------------------------------------

/** Parses the provider's "12.50" money string into integer cents. */
export function moneyToCents(value: string | number | null | undefined): number {
  if (value === null || value === undefined || value === '') return 0;
  const str = String(value).trim().replace(/\s+/g, '');
  const negative = str.startsWith('-');
  const unsigned = negative ? str.slice(1) : str;
  const m = unsigned.match(/^(\d*)(?:\.(\d{1,2}))?\d*$/);
  if (!m) {
    const asNum = Number(unsigned);
    if (!Number.isFinite(asNum)) return 0;
    return (negative ? -1 : 1) * Math.round(asNum * 100);
  }
  const whole = m[1] ? parseInt(m[1], 10) : 0;
  const fracRaw = (m[2] || '').padEnd(2, '0').slice(0, 2);
  const cents = whole * 100 + parseInt(fracRaw, 10);
  return (negative ? -1 : 1) * cents;
}

/** Formats integer cents back into the provider's "12.50" representation. */
export function centsToMoney(cents: number): string {
  const n = Math.round(Number(cents) || 0);
  const negative = n < 0;
  const abs = Math.abs(n);
  const whole = Math.floor(abs / 100);
  const frac = String(abs % 100).padStart(2, '0');
  return `${negative ? '-' : ''}${whole}.${frac}`;
}

/** `X.XX €` style display helper used by the UI layer. */
export function formatMoney(cents: number, currency = 'EUR'): string {
  const symbol = currency === 'EUR' ? '€' : currency;
  return `${centsToMoney(cents)} ${symbol}`;
}

/**
 * Generates an `Idempotency-Key` (1-64 chars of `[A-Za-z0-9_-:.]`).
 * Persist it BEFORE the upstream call so a retry replays the same key.
 */
export function buildIdempotencyKey(prefix: string, unique: string): string {
  const safe = `${prefix}:${unique}`.replace(/[^A-Za-z0-9_\-:.]/g, '');
  return safe.slice(0, 64);
}

// ---------------------------------------------------------------------------
// Redaction — keeps credentials out of the API log and out of error messages
// ---------------------------------------------------------------------------

const REDACT_KEYS = new Set([
  'password',
  'credentials',
  'authcode',
  'authtoken',
  'token',
  'secret',
  'apikey',
  'api_key',
  'authorization',
  'consoleurl',
  'paymenturl',
  'login',
  'loginlink',
]);

/** Deep-copies a payload replacing sensitive values with `***`. */
export function redactSensitive(input: unknown, depth = 0): unknown {
  if (depth > 8 || input === null || input === undefined) return input;
  if (Array.isArray(input)) return input.slice(0, 50).map((v) => redactSensitive(v, depth + 1));
  if (typeof input === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      const norm = key.toLowerCase().replace(/[^a-z]/g, '');
      if (REDACT_KEYS.has(norm) || norm.endsWith('password') || norm.endsWith('token')) {
        out[key] = value === null || value === undefined ? value : '***';
        continue;
      }
      out[key] = redactSensitive(value, depth + 1);
    }
    return out;
  }
  if (typeof input === 'string' && input.length > 4000) {
    return `${input.slice(0, 4000)}…[truncated]`;
  }
  return input;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export interface ResellerClientConfig {
  baseUrl: string;
  apiKey: string;
  timeoutMs?: number;
  maxRetries?: number;
  userAgent?: string;
  /** Invoked for every completed attempt (success or failure). */
  onLog?: (entry: ResellerApiLogEntry) => void | Promise<void>;
}

export interface ResellerApiLogEntry {
  method: string;
  endpoint: string;
  statusCode: number | null;
  state: 'success' | 'error' | 'network';
  errorCode: string | null;
  durationMs: number;
  requestId: string | null;
  idempotencyKey: string | null;
  requestBody: unknown;
  responseBody: unknown;
  attempt: number;
}

interface RawResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

export class ResellerApiClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly userAgent: string;
  private readonly onLog?: (entry: ResellerApiLogEntry) => void | Promise<void>;
  /** Last observed rate-limit headers, useful for admin dashboards. */
  public lastRateLimit: UpstreamRateLimitInfo = emptyRateLimit();

  constructor(config: ResellerClientConfig) {
    const rawBase = String(config.baseUrl || '').trim().replace(/\/+$/, '');
    if (!rawBase) {
      throw new UpstreamApiError({
        kind: 'config',
        code: 'missing_base_url',
        message: 'Upstream API base URL is not configured.',
      });
    }
    let parsed: URL;
    try {
      parsed = new URL(rawBase);
    } catch {
      throw new UpstreamApiError({
        kind: 'config',
        code: 'invalid_base_url',
        message: `Upstream API base URL is invalid: ${rawBase}`,
      });
    }
    if (!/^https?:$/.test(parsed.protocol)) {
      throw new UpstreamApiError({
        kind: 'config',
        code: 'invalid_base_url',
        message: 'Upstream API base URL must be http or https.',
      });
    }
    this.baseUrl = parsed.toString().replace(/\/+$/, '');
    this.apiKey = String(config.apiKey || '').trim();
    this.timeoutMs = Math.max(1000, Math.min(120_000, config.timeoutMs ?? 20_000));
    this.maxRetries = Math.max(0, Math.min(6, config.maxRetries ?? 2));
    this.userAgent = config.userAgent || 'TGVPANEL/3.0 (+reseller-integration)';
    this.onLog = config.onLog;
  }

  public isConfigured(): boolean {
    return this.apiKey.length > 0;
  }

  /** Redacted key hint (`bkkt_…abcd`) safe to render in the admin UI. */
  public keyHint(): string {
    if (!this.apiKey) return '';
    const tail = this.apiKey.slice(-4);
    const head = this.apiKey.slice(0, Math.min(6, this.apiKey.length));
    return `${head}…${tail}`;
  }

  private assertConfigured(): void {
    if (!this.apiKey) {
      throw new UpstreamApiError({
        kind: 'config',
        code: 'missing_api_key',
        message:
          'Upstream reseller API key is not configured. Add it in Admin → Reseller → Provider, or set RESELLER_API_KEY in .env.',
        retryable: false,
      });
    }
  }

  // -------------------------------------------------------------------------
  // Transport
  // -------------------------------------------------------------------------

  private buildUrl(path: string, query?: Record<string, unknown>): string {
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    const url = new URL(`${this.baseUrl}${cleanPath}`);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value === undefined || value === null || value === '') continue;
        url.searchParams.set(key, String(value));
      }
    }
    return url.toString();
  }

  private rawRequest(
    method: string,
    urlStr: string,
    body: unknown,
    idempotencyKey?: string | null
  ): Promise<RawResponse> {
    return new Promise((resolve, reject) => {
      const url = new URL(urlStr);
      const isHttps = url.protocol === 'https:';
      const payload =
        body === undefined || body === null ? null : Buffer.from(JSON.stringify(body), 'utf8');

      const headers: Record<string, string | number> = {
        Accept: 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
        'User-Agent': this.userAgent,
      };
      if (payload) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = payload.length;
      }
      if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;

      const transport = isHttps ? https : http;
      const req = transport.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: `${url.pathname}${url.search}`,
          method,
          headers,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            // Hard cap: the provider rejects bodies > 1 MB, responses are small.
            if (size < 8 * 1024 * 1024) chunks.push(chunk);
          });
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode || 0,
              headers: res.headers,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          });
          res.on('error', reject);
        }
      );

      req.setTimeout(this.timeoutMs, () => {
        req.destroy(
          new UpstreamApiError({
            kind: 'timeout',
            code: 'upstream_timeout',
            message: `Upstream request timed out after ${this.timeoutMs}ms (${method} ${url.pathname}).`,
            method,
            endpoint: url.pathname,
            retryable: true,
          })
        );
      });
      req.on('error', (err: Error) => {
        if (err instanceof UpstreamApiError) return reject(err);
        reject(
          new UpstreamApiError({
            kind: 'network',
            code: 'network_error',
            message: `Could not reach the upstream provider: ${err.message}`,
            method,
            endpoint: url.pathname,
            retryable: true,
          })
        );
      });

      if (payload) req.write(payload);
      req.end();
    });
  }

  private parseRateLimit(headers: http.IncomingHttpHeaders): UpstreamRateLimitInfo {
    const num = (v: unknown): number | null => {
      const n = parseInt(String(v ?? ''), 10);
      return Number.isFinite(n) ? n : null;
    };
    return {
      limit: num(headers['x-ratelimit-limit']),
      remaining: num(headers['x-ratelimit-remaining']),
      reset: num(headers['x-ratelimit-reset']),
      retryAfter: num(headers['retry-after']),
    };
  }

  /**
   * Performs a request with retries and converts the response into either the
   * unwrapped `data` payload or a typed `UpstreamApiError`.
   */
  public async request<T = unknown>(opts: {
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    path: string;
    query?: Record<string, unknown>;
    body?: unknown;
    idempotencyKey?: string | null;
    /** HTTP statuses treated as success (orders return 200 for sandbox, 201 for real). */
    okStatuses?: number[];
    retries?: number;
  }): Promise<{ data: T; statusCode: number; requestId: string | null; rateLimit: UpstreamRateLimitInfo; replayed: boolean }> {
    this.assertConfigured();

    const url = this.buildUrl(opts.path, opts.query);
    const endpointPath = new URL(url).pathname;
    const okStatuses = opts.okStatuses || [200, 201, 202];
    const maxAttempts = 1 + (opts.retries ?? this.maxRetries);

    let lastError: UpstreamApiError | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const started = Date.now();
      let raw: RawResponse | null = null;
      let transportError: UpstreamApiError | null = null;

      try {
        raw = await this.rawRequest(opts.method, url, opts.body, opts.idempotencyKey);
      } catch (err) {
        transportError =
          err instanceof UpstreamApiError
            ? err
            : new UpstreamApiError({
                kind: 'network',
                code: 'network_error',
                message: (err as Error).message,
                method: opts.method,
                endpoint: endpointPath,
                retryable: true,
              });
      }

      const durationMs = Date.now() - started;

      if (transportError) {
        await this.emitLog({
          method: opts.method,
          endpoint: endpointPath,
          statusCode: null,
          state: 'network',
          errorCode: transportError.code,
          durationMs,
          requestId: null,
          idempotencyKey: opts.idempotencyKey || null,
          requestBody: opts.body ?? null,
          responseBody: null,
          attempt,
        });
        lastError = transportError;
        if (attempt < maxAttempts && transportError.retryable) {
          await sleep(backoffMs(attempt, transportError.retryAfterSec));
          continue;
        }
        throw transportError;
      }

      const rateLimit = this.parseRateLimit(raw!.headers);
      this.lastRateLimit = rateLimit;
      const requestId = headerStr(raw!.headers['x-request-id']);
      const replayed = String(raw!.headers['idempotent-replayed'] || '').toLowerCase() === 'true';

      let parsed: unknown = null;
      let parseError = false;
      const text = (raw!.body || '').trim();
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parseError = true;
        }
      }

      const envelope = (!parseError && parsed && typeof parsed === 'object'
        ? (parsed as UpstreamEnvelope<unknown>)
        : null);
      const data = (envelope?.data ?? null) as Record<string, unknown> | null;
      const errorCode = data && typeof data.code === 'string' ? data.code : null;
      const message =
        envelope?.response && typeof envelope.response === 'string'
          ? envelope.response
          : parseError
            ? `Upstream returned a non-JSON response (HTTP ${raw!.statusCode}).`
            : `Upstream request failed (HTTP ${raw!.statusCode}).`;

      const isOk = okStatuses.includes(raw!.statusCode) && envelope?.state !== 'error';

      await this.emitLog({
        method: opts.method,
        endpoint: endpointPath,
        statusCode: raw!.statusCode,
        state: isOk ? 'success' : 'error',
        errorCode,
        durationMs,
        requestId,
        idempotencyKey: opts.idempotencyKey || null,
        requestBody: opts.body ?? null,
        responseBody: parsed ?? (text ? text.slice(0, 4000) : null),
        attempt,
      });

      if (isOk) {
        return {
          data: (envelope ? envelope.data : parsed) as T,
          statusCode: raw!.statusCode,
          requestId,
          rateLimit,
          replayed,
        };
      }

      const retryable =
        RETRYABLE_STATUS.has(raw!.statusCode) && !(errorCode && NON_RETRYABLE_CODES.has(errorCode));

      const apiError = new UpstreamApiError({
        kind: raw!.statusCode === 429 ? 'ratelimit' : 'api',
        message:
          raw!.statusCode === 429
            ? `Upstream rate limit reached${rateLimit.retryAfter ? ` (retry in ${rateLimit.retryAfter}s)` : ''}.`
            : message,
        statusCode: raw!.statusCode,
        code: errorCode || httpStatusCode(raw!.statusCode),
        data: (data as UpstreamErrorData) || { code: errorCode || 'unknown_error' },
        requestId,
        endpoint: endpointPath,
        method: opts.method,
        rateLimit,
        upstreamMessage: message,
        retryable,
        retryAfterSec: rateLimit.retryAfter,
      });

      lastError = apiError;
      if (attempt < maxAttempts && retryable) {
        await sleep(backoffMs(attempt, rateLimit.retryAfter));
        continue;
      }
      throw apiError;
    }

    throw lastError || new UpstreamApiError({
      kind: 'network',
      code: 'unknown_error',
      message: 'Upstream request failed after all retries.',
      method: opts.method,
      endpoint: endpointPath,
      retryable: true,
    });
  }

  private async emitLog(entry: ResellerApiLogEntry): Promise<void> {
    if (!this.onLog) return;
    try {
      await this.onLog({
        ...entry,
        requestBody: entry.requestBody === null ? null : safeStringify(redactSensitive(entry.requestBody)),
        responseBody: entry.responseBody === null ? null : safeStringify(redactSensitive(entry.responseBody)),
      });
    } catch {
      // Logging must never break a request.
    }
  }

  // -------------------------------------------------------------------------
  // Account & reseller endpoints
  // -------------------------------------------------------------------------

  public getAccount(): Promise<UpstreamAccount> {
    return this.request<UpstreamAccount>({ method: 'GET', path: '/account' }).then((r) => r.data);
  }

  public getBalance(): Promise<UpstreamBalance> {
    return this.request<UpstreamBalance>({ method: 'GET', path: '/account/balance' }).then(
      (r) => r.data
    );
  }

  public listTransactions(params: { page?: number; perPage?: number; productId?: string } = {}): Promise<{
    transactions: UpstreamTransaction[];
    pagination: UpstreamPagination;
  }> {
    return this.request<{ transactions: UpstreamTransaction[]; pagination: UpstreamPagination }>({
      method: 'GET',
      path: '/account/transactions',
      query: params,
    }).then((r) => r.data);
  }

  public getResellerInfo(): Promise<UpstreamResellerInfo> {
    return this.request<UpstreamResellerInfo>({ method: 'GET', path: '/reseller' }).then(
      (r) => r.data
    );
  }

  // -------------------------------------------------------------------------
  // Products (shared)
  // -------------------------------------------------------------------------

  public listProducts(params: {
    page?: number;
    perPage?: number;
    type?: string;
    state?: string;
    access?: string;
    search?: string;
  } = {}): Promise<{ products: UpstreamProduct[]; pagination: UpstreamPagination }> {
    return this.request<{ products: UpstreamProduct[]; pagination: UpstreamPagination }>({
      method: 'GET',
      path: '/product',
      query: params,
    }).then((r) => r.data);
  }

  public getProduct(productId: string): Promise<UpstreamProduct> {
    return this.request<UpstreamProduct>({
      method: 'GET',
      path: `/product/${encodeURIComponent(productId)}`,
    }).then((r) => r.data);
  }

  public renameProduct(productId: string, name: string | null): Promise<UpstreamProduct> {
    return this.request<UpstreamProduct>({
      method: 'PUT',
      path: `/product/${encodeURIComponent(productId)}/name`,
      body: { name },
    }).then((r) => r.data);
  }

  public setAutoRenew(productId: string, autoRenew: boolean | 0 | 1): Promise<UpstreamProduct> {
    return this.request<UpstreamProduct>({
      method: 'PUT',
      path: `/product/${encodeURIComponent(productId)}/autorenew`,
      body: { autoRenew: autoRenew === true || autoRenew === 1 ? 1 : 0 },
    }).then((r) => r.data);
  }

  public getRenewal(productId: string): Promise<UpstreamRenewQuote> {
    return this.request<UpstreamRenewQuote>({
      method: 'GET',
      path: `/product/${encodeURIComponent(productId)}/renew`,
    }).then((r) => r.data);
  }

  public renewProduct(
    productId: string,
    idempotencyKey?: string | null
  ): Promise<UpstreamRenewResult> {
    return this.request<UpstreamRenewResult>({
      method: 'POST',
      path: `/product/${encodeURIComponent(productId)}/renew`,
      idempotencyKey,
    }).then((r) => r.data);
  }

  // -------------------------------------------------------------------------
  // KVM catalogue
  // -------------------------------------------------------------------------

  public listKvmPlans(cpu?: string): Promise<UpstreamKvmPlan[]> {
    return this.request<UpstreamKvmPlan[]>({
      method: 'GET',
      path: '/kvm/plans',
      query: cpu ? { cpu } : undefined,
    }).then((r) => (Array.isArray(r.data) ? r.data : []));
  }

  public getKvmPlan(planId: string): Promise<UpstreamKvmPlan> {
    return this.request<UpstreamKvmPlan>({
      method: 'GET',
      path: `/kvm/plans/${encodeURIComponent(planId)}`,
    }).then((r) => r.data);
  }

  public getKvmConfigurator(cpu?: string): Promise<UpstreamKvmConfigurator[]> {
    return this.request<UpstreamKvmConfigurator[]>({
      method: 'GET',
      path: '/kvm/configurator',
      query: cpu ? { cpu } : undefined,
    }).then((r) => (Array.isArray(r.data) ? r.data : []));
  }

  public getKvmConfiguratorPrice(params: {
    cpu: string;
    cores: number;
    memory: number;
    disk: number;
    ipv4?: number;
    ipv6?: number;
    voucher?: string;
  }): Promise<UpstreamKvmConfiguratorPrice> {
    return this.request<UpstreamKvmConfiguratorPrice>({
      method: 'GET',
      path: '/kvm/configurator/price',
      query: params,
    }).then((r) => r.data);
  }

  public listKvmOs(): Promise<UpstreamKvmOs[]> {
    return this.request<UpstreamKvmOs[]>({ method: 'GET', path: '/kvm/os' }).then((r) =>
      Array.isArray(r.data) ? r.data : []
    );
  }

  // -------------------------------------------------------------------------
  // KVM ordering & management
  // -------------------------------------------------------------------------

  /**
   * Places (or with `sandbox: true`, prices) a KVM order.
   * Always pass a persisted `idempotencyKey` for real orders.
   */
  public async orderKvm(
    input: UpstreamKvmOrderInput,
    idempotencyKey?: string | null
  ): Promise<{
    sandbox: boolean;
    statusCode: number;
    requestId: string | null;
    replayed: boolean;
    preview?: UpstreamKvmOrderPreview;
    result?: UpstreamKvmOrderResult;
  }> {
    const res = await this.request<UpstreamKvmOrderPreview | UpstreamKvmOrderResult>({
      method: 'POST',
      path: '/kvm/order',
      body: input,
      idempotencyKey,
      okStatuses: [200, 201],
      // Never blind-retry an order: idempotency already protects replays and a
      // retry storm on the `order` rate-limit bucket (20/min) is worse than a
      // queued retry driven by the provisioning poller.
      retries: 0,
    });
    const sandbox = input.sandbox === true || res.statusCode === 200;
    return {
      sandbox,
      statusCode: res.statusCode,
      requestId: res.requestId,
      replayed: res.replayed,
      preview: sandbox ? (res.data as UpstreamKvmOrderPreview) : undefined,
      result: sandbox ? undefined : (res.data as UpstreamKvmOrderResult),
    };
  }

  public listKvm(params: {
    page?: number;
    perPage?: number;
    state?: string;
    search?: string;
    access?: string;
  } = {}): Promise<{ servers: UpstreamKvmServer[]; pagination: UpstreamPagination }> {
    return this.request<{ servers: UpstreamKvmServer[]; pagination: UpstreamPagination }>({
      method: 'GET',
      path: '/kvm',
      query: params,
    }).then((r) => r.data);
  }

  public getKvm(productId: string): Promise<UpstreamKvmServerDetail> {
    return this.request<UpstreamKvmServerDetail>({
      method: 'GET',
      path: `/kvm/${encodeURIComponent(productId)}`,
    }).then((r) => r.data);
  }

  public getKvmStatus(productId: string): Promise<UpstreamKvmStatus> {
    return this.request<UpstreamKvmStatus>({
      method: 'GET',
      path: `/kvm/${encodeURIComponent(productId)}/status`,
    }).then((r) => r.data);
  }

  public kvmPower(productId: string, action: 'start' | 'stop'): Promise<{ id: string; action: string }> {
    return this.request<{ id: string; action: string }>({
      method: 'POST',
      path: `/kvm/${encodeURIComponent(productId)}/power`,
      body: { action },
    }).then((r) => r.data);
  }

  /** Restart is not a native upstream action: stop, then start. */
  public async kvmRestart(productId: string): Promise<{ id: string; action: 'restart' }> {
    try {
      await this.kvmPower(productId, 'stop');
    } catch (err) {
      // `already_stopped` is fine — we still want the start below.
      if (!(err instanceof UpstreamApiError) || err.code !== 'already_stopped') throw err;
    }
    await sleep(2500);
    try {
      await this.kvmPower(productId, 'start');
    } catch (err) {
      if (!(err instanceof UpstreamApiError) || err.code !== 'already_running') throw err;
    }
    return { id: productId, action: 'restart' };
  }

  public reinstallKvm(
    productId: string,
    input: { os: string; password?: string; confirm: true },
    idempotencyKey?: string | null
  ): Promise<{ id: string; state: string; os: string; credentials?: { username: string; password: string } }> {
    return this.request<{
      id: string;
      state: string;
      os: string;
      credentials?: { username: string; password: string };
    }>({
      method: 'POST',
      path: `/kvm/${encodeURIComponent(productId)}/reinstall`,
      body: input,
      idempotencyKey,
      retries: 0,
    }).then((r) => r.data);
  }

  public setKvmPassword(
    productId: string,
    password: string
  ): Promise<{ id: string; credentials: { username: string; password: string } }> {
    return this.request<{ id: string; credentials: { username: string; password: string } }>({
      method: 'PUT',
      path: `/kvm/${encodeURIComponent(productId)}/password`,
      body: { password },
    }).then((r) => r.data);
  }

  public getKvmConsole(productId: string): Promise<{ id: string; consoleUrl: string }> {
    return this.request<{ id: string; consoleUrl: string }>({
      method: 'GET',
      path: `/kvm/${encodeURIComponent(productId)}/console`,
    }).then((r) => r.data);
  }

  public getKvmNetwork(productId: string, rdns = false): Promise<UpstreamKvmNetwork> {
    return this.request<UpstreamKvmNetwork>({
      method: 'GET',
      path: `/kvm/${encodeURIComponent(productId)}/network`,
      query: { rdns: rdns ? 1 : 0 },
    }).then((r) => r.data);
  }

  public getKvmStatistics(
    productId: string,
    period: 'hour' | 'day' | 'week' | 'month' | 'year' = 'hour'
  ): Promise<UpstreamKvmStatistics> {
    return this.request<UpstreamKvmStatistics>({
      method: 'GET',
      path: `/kvm/${encodeURIComponent(productId)}/statistics`,
      query: { period },
    }).then((r) => r.data);
  }

  public getKvmFirewall(productId: string): Promise<UpstreamFirewall> {
    return this.request<UpstreamFirewall>({
      method: 'GET',
      path: `/kvm/${encodeURIComponent(productId)}/firewall`,
    }).then((r) => r.data);
  }

  public addKvmFirewallRule(
    productId: string,
    rule: UpstreamFirewallRuleInput
  ): Promise<UpstreamFirewall> {
    return this.request<UpstreamFirewall>({
      method: 'POST',
      path: `/kvm/${encodeURIComponent(productId)}/firewall/rules`,
      body: rule,
    }).then((r) => r.data);
  }
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function headerStr(value: unknown): string | null {
  if (typeof value === 'string' && value.length) return value;
  if (Array.isArray(value) && value.length) return String(value[0]);
  return null;
}

function httpStatusCode(status: number): string {
  const map: Record<number, string> = {
    400: 'bad_request',
    401: 'unauthorized',
    402: 'insufficient_balance',
    403: 'forbidden',
    404: 'not_found',
    405: 'method_not_allowed',
    409: 'conflict',
    413: 'payload_too_large',
    422: 'validation_failed',
    429: 'rate_limited',
    500: 'internal_error',
    501: 'not_supported',
    502: 'provider_error',
    503: 'unavailable',
  };
  return map[status] || `http_${status}`;
}

function safeStringify(value: unknown): string {
  try {
    const str = JSON.stringify(value);
    return str && str.length > 8000 ? `${str.slice(0, 8000)}…[truncated]` : str;
  } catch {
    return '[unserializable]';
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

/** Exponential backoff with jitter; prefers the provider's `Retry-After`. */
export function backoffMs(attempt: number, retryAfterSec?: number | null): number {
  if (retryAfterSec && retryAfterSec > 0) {
    return Math.min(60_000, retryAfterSec * 1000 + 150);
  }
  const base = Math.min(8000, 400 * Math.pow(2, Math.max(0, attempt - 1)));
  return base + Math.floor(Math.random() * 250);
}
