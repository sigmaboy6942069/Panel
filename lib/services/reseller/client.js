"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ResellerApiClient = exports.UpstreamApiError = void 0;
exports.emptyRateLimit = emptyRateLimit;
exports.moneyToCents = moneyToCents;
exports.centsToMoney = centsToMoney;
exports.formatMoney = formatMoney;
exports.buildIdempotencyKey = buildIdempotencyKey;
exports.redactSensitive = redactSensitive;
exports.sleep = sleep;
exports.backoffMs = backoffMs;
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
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const url_1 = require("url");
/**
 * Thrown for every failed upstream interaction. `code` is the provider's
 * stable machine code (`insufficient_balance`, `out_of_stock`, ...) when the
 * provider supplied one, otherwise a local kind such as `network_error`.
 */
class UpstreamApiError extends Error {
    kind;
    statusCode;
    code;
    data;
    requestId;
    endpoint;
    method;
    rateLimit;
    /** Human-readable provider message; safe to show to an administrator. */
    upstreamMessage;
    /** True when re-sending the identical request could succeed. */
    retryable;
    /** Seconds to wait before retrying (from `Retry-After`), when provided. */
    retryAfterSec;
    constructor(params) {
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
    fieldErrors() {
        const out = {};
        const raw = this.data?.errors;
        if (!raw || typeof raw !== 'object')
            return out;
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
            balance: this.code === 'insufficient_balance'
                ? { required: this.data.required ?? null, available: this.data.available ?? null }
                : undefined,
        };
    }
}
exports.UpstreamApiError = UpstreamApiError;
function emptyRateLimit() {
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
function moneyToCents(value) {
    if (value === null || value === undefined || value === '')
        return 0;
    const str = String(value).trim().replace(/\s+/g, '');
    const negative = str.startsWith('-');
    const unsigned = negative ? str.slice(1) : str;
    const m = unsigned.match(/^(\d*)(?:\.(\d{1,2}))?\d*$/);
    if (!m) {
        const asNum = Number(unsigned);
        if (!Number.isFinite(asNum))
            return 0;
        return (negative ? -1 : 1) * Math.round(asNum * 100);
    }
    const whole = m[1] ? parseInt(m[1], 10) : 0;
    const fracRaw = (m[2] || '').padEnd(2, '0').slice(0, 2);
    const cents = whole * 100 + parseInt(fracRaw, 10);
    return (negative ? -1 : 1) * cents;
}
/** Formats integer cents back into the provider's "12.50" representation. */
function centsToMoney(cents) {
    const n = Math.round(Number(cents) || 0);
    const negative = n < 0;
    const abs = Math.abs(n);
    const whole = Math.floor(abs / 100);
    const frac = String(abs % 100).padStart(2, '0');
    return `${negative ? '-' : ''}${whole}.${frac}`;
}
/** `X.XX €` style display helper used by the UI layer. */
function formatMoney(cents, currency = 'EUR') {
    const symbol = currency === 'EUR' ? '€' : currency;
    return `${centsToMoney(cents)} ${symbol}`;
}
/**
 * Generates an `Idempotency-Key` (1-64 chars of `[A-Za-z0-9_-:.]`).
 * Persist it BEFORE the upstream call so a retry replays the same key.
 */
function buildIdempotencyKey(prefix, unique) {
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
function redactSensitive(input, depth = 0) {
    if (depth > 8 || input === null || input === undefined)
        return input;
    if (Array.isArray(input))
        return input.slice(0, 50).map((v) => redactSensitive(v, depth + 1));
    if (typeof input === 'object') {
        const out = {};
        for (const [key, value] of Object.entries(input)) {
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
const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);
class ResellerApiClient {
    baseUrl;
    apiKey;
    timeoutMs;
    maxRetries;
    userAgent;
    onLog;
    /** Last observed rate-limit headers, useful for admin dashboards. */
    lastRateLimit = emptyRateLimit();
    constructor(config) {
        const rawBase = String(config.baseUrl || '').trim().replace(/\/+$/, '');
        if (!rawBase) {
            throw new UpstreamApiError({
                kind: 'config',
                code: 'missing_base_url',
                message: 'Upstream API base URL is not configured.',
            });
        }
        let parsed;
        try {
            parsed = new url_1.URL(rawBase);
        }
        catch {
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
    isConfigured() {
        return this.apiKey.length > 0;
    }
    /** Redacted key hint (first and last characters only) safe to render in the admin UI. */
    keyHint() {
        if (!this.apiKey)
            return '';
        const tail = this.apiKey.slice(-4);
        const head = this.apiKey.slice(0, Math.min(6, this.apiKey.length));
        return `${head}…${tail}`;
    }
    assertConfigured() {
        if (!this.apiKey) {
            throw new UpstreamApiError({
                kind: 'config',
                code: 'missing_api_key',
                message: 'Upstream reseller API key is not configured. Add it in Admin → Reseller → Provider, or set RESELLER_API_KEY in .env.',
                retryable: false,
            });
        }
    }
    // -------------------------------------------------------------------------
    // Transport
    // -------------------------------------------------------------------------
    buildUrl(path, query) {
        const cleanPath = path.startsWith('/') ? path : `/${path}`;
        const url = new url_1.URL(`${this.baseUrl}${cleanPath}`);
        if (query) {
            for (const [key, value] of Object.entries(query)) {
                if (value === undefined || value === null || value === '')
                    continue;
                url.searchParams.set(key, String(value));
            }
        }
        return url.toString();
    }
    rawRequest(method, urlStr, body, idempotencyKey) {
        return new Promise((resolve, reject) => {
            const url = new url_1.URL(urlStr);
            const isHttps = url.protocol === 'https:';
            const payload = body === undefined || body === null ? null : Buffer.from(JSON.stringify(body), 'utf8');
            const headers = {
                Accept: 'application/json',
                Authorization: `Bearer ${this.apiKey}`,
                'User-Agent': this.userAgent,
            };
            if (payload) {
                headers['Content-Type'] = 'application/json';
                headers['Content-Length'] = payload.length;
            }
            if (idempotencyKey)
                headers['Idempotency-Key'] = idempotencyKey;
            const transport = isHttps ? https_1.default : http_1.default;
            const req = transport.request({
                protocol: url.protocol,
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: `${url.pathname}${url.search}`,
                method,
                headers,
            }, (res) => {
                const chunks = [];
                let size = 0;
                res.on('data', (chunk) => {
                    size += chunk.length;
                    // Hard cap: the provider rejects bodies > 1 MB, responses are small.
                    if (size < 8 * 1024 * 1024)
                        chunks.push(chunk);
                });
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode || 0,
                        headers: res.headers,
                        body: Buffer.concat(chunks).toString('utf8'),
                    });
                });
                res.on('error', reject);
            });
            req.setTimeout(this.timeoutMs, () => {
                req.destroy(new UpstreamApiError({
                    kind: 'timeout',
                    code: 'upstream_timeout',
                    message: `Upstream request timed out after ${this.timeoutMs}ms (${method} ${url.pathname}).`,
                    method,
                    endpoint: url.pathname,
                    retryable: true,
                }));
            });
            req.on('error', (err) => {
                if (err instanceof UpstreamApiError)
                    return reject(err);
                reject(new UpstreamApiError({
                    kind: 'network',
                    code: 'network_error',
                    message: `Could not reach the upstream provider: ${err.message}`,
                    method,
                    endpoint: url.pathname,
                    retryable: true,
                }));
            });
            if (payload)
                req.write(payload);
            req.end();
        });
    }
    parseRateLimit(headers) {
        const num = (v) => {
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
    async request(opts) {
        this.assertConfigured();
        const url = this.buildUrl(opts.path, opts.query);
        const endpointPath = new url_1.URL(url).pathname;
        const okStatuses = opts.okStatuses || [200, 201, 202];
        const maxAttempts = 1 + (opts.retries ?? this.maxRetries);
        let lastError = null;
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            const started = Date.now();
            let raw = null;
            let transportError = null;
            try {
                raw = await this.rawRequest(opts.method, url, opts.body, opts.idempotencyKey);
            }
            catch (err) {
                transportError =
                    err instanceof UpstreamApiError
                        ? err
                        : new UpstreamApiError({
                            kind: 'network',
                            code: 'network_error',
                            message: err.message,
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
            const rateLimit = this.parseRateLimit(raw.headers);
            this.lastRateLimit = rateLimit;
            const requestId = headerStr(raw.headers['x-request-id']);
            const replayed = String(raw.headers['idempotent-replayed'] || '').toLowerCase() === 'true';
            let parsed = null;
            let parseError = false;
            const text = (raw.body || '').trim();
            if (text) {
                try {
                    parsed = JSON.parse(text);
                }
                catch {
                    parseError = true;
                }
            }
            const envelope = (!parseError && parsed && typeof parsed === 'object'
                ? parsed
                : null);
            const data = (envelope?.data ?? null);
            const errorCode = data && typeof data.code === 'string' ? data.code : null;
            const message = envelope?.response && typeof envelope.response === 'string'
                ? envelope.response
                : parseError
                    ? `Upstream returned a non-JSON response (HTTP ${raw.statusCode}).`
                    : `Upstream request failed (HTTP ${raw.statusCode}).`;
            const isOk = okStatuses.includes(raw.statusCode) && envelope?.state !== 'error';
            await this.emitLog({
                method: opts.method,
                endpoint: endpointPath,
                statusCode: raw.statusCode,
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
                    data: (envelope ? envelope.data : parsed),
                    statusCode: raw.statusCode,
                    requestId,
                    rateLimit,
                    replayed,
                };
            }
            const retryable = RETRYABLE_STATUS.has(raw.statusCode) && !(errorCode && NON_RETRYABLE_CODES.has(errorCode));
            const apiError = new UpstreamApiError({
                kind: raw.statusCode === 429 ? 'ratelimit' : 'api',
                message: raw.statusCode === 429
                    ? `Upstream rate limit reached${rateLimit.retryAfter ? ` (retry in ${rateLimit.retryAfter}s)` : ''}.`
                    : message,
                statusCode: raw.statusCode,
                code: errorCode || httpStatusCode(raw.statusCode),
                data: data || { code: errorCode || 'unknown_error' },
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
    async emitLog(entry) {
        if (!this.onLog)
            return;
        try {
            await this.onLog({
                ...entry,
                requestBody: entry.requestBody === null ? null : safeStringify(redactSensitive(entry.requestBody)),
                responseBody: entry.responseBody === null ? null : safeStringify(redactSensitive(entry.responseBody)),
            });
        }
        catch {
            // Logging must never break a request.
        }
    }
    // -------------------------------------------------------------------------
    // Account & reseller endpoints
    // -------------------------------------------------------------------------
    getAccount() {
        return this.request({ method: 'GET', path: '/account' }).then((r) => r.data);
    }
    getBalance() {
        return this.request({ method: 'GET', path: '/account/balance' }).then((r) => r.data);
    }
    listTransactions(params = {}) {
        return this.request({
            method: 'GET',
            path: '/account/transactions',
            query: params,
        }).then((r) => r.data);
    }
    getResellerInfo() {
        return this.request({ method: 'GET', path: '/reseller' }).then((r) => r.data);
    }
    // -------------------------------------------------------------------------
    // Products (shared)
    // -------------------------------------------------------------------------
    listProducts(params = {}) {
        return this.request({
            method: 'GET',
            path: '/product',
            query: params,
        }).then((r) => r.data);
    }
    getProduct(productId) {
        return this.request({
            method: 'GET',
            path: `/product/${encodeURIComponent(productId)}`,
        }).then((r) => r.data);
    }
    renameProduct(productId, name) {
        return this.request({
            method: 'PUT',
            path: `/product/${encodeURIComponent(productId)}/name`,
            body: { name },
        }).then((r) => r.data);
    }
    setAutoRenew(productId, autoRenew) {
        return this.request({
            method: 'PUT',
            path: `/product/${encodeURIComponent(productId)}/autorenew`,
            body: { autoRenew: autoRenew === true || autoRenew === 1 ? 1 : 0 },
        }).then((r) => r.data);
    }
    getRenewal(productId) {
        return this.request({
            method: 'GET',
            path: `/product/${encodeURIComponent(productId)}/renew`,
        }).then((r) => r.data);
    }
    renewProduct(productId, idempotencyKey) {
        return this.request({
            method: 'POST',
            path: `/product/${encodeURIComponent(productId)}/renew`,
            idempotencyKey,
        }).then((r) => r.data);
    }
    // -------------------------------------------------------------------------
    // KVM catalogue
    // -------------------------------------------------------------------------
    listKvmPlans(cpu) {
        return this.request({
            method: 'GET',
            path: '/kvm/plans',
            query: cpu ? { cpu } : undefined,
        }).then((r) => (Array.isArray(r.data) ? r.data : []));
    }
    getKvmPlan(planId) {
        return this.request({
            method: 'GET',
            path: `/kvm/plans/${encodeURIComponent(planId)}`,
        }).then((r) => r.data);
    }
    getKvmConfigurator(cpu) {
        return this.request({
            method: 'GET',
            path: '/kvm/configurator',
            query: cpu ? { cpu } : undefined,
        }).then((r) => (Array.isArray(r.data) ? r.data : []));
    }
    getKvmConfiguratorPrice(params) {
        return this.request({
            method: 'GET',
            path: '/kvm/configurator/price',
            query: params,
        }).then((r) => r.data);
    }
    listKvmOs() {
        return this.request({ method: 'GET', path: '/kvm/os' }).then((r) => Array.isArray(r.data) ? r.data : []);
    }
    // -------------------------------------------------------------------------
    // KVM ordering & management
    // -------------------------------------------------------------------------
    /**
     * Places (or with `sandbox: true`, prices) a KVM order.
     * Always pass a persisted `idempotencyKey` for real orders.
     */
    async orderKvm(input, idempotencyKey) {
        const res = await this.request({
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
            preview: sandbox ? res.data : undefined,
            result: sandbox ? undefined : res.data,
        };
    }
    listKvm(params = {}) {
        return this.request({
            method: 'GET',
            path: '/kvm',
            query: params,
        }).then((r) => r.data);
    }
    getKvm(productId) {
        return this.request({
            method: 'GET',
            path: `/kvm/${encodeURIComponent(productId)}`,
        }).then((r) => r.data);
    }
    getKvmStatus(productId) {
        return this.request({
            method: 'GET',
            path: `/kvm/${encodeURIComponent(productId)}/status`,
        }).then((r) => r.data);
    }
    kvmPower(productId, action) {
        return this.request({
            method: 'POST',
            path: `/kvm/${encodeURIComponent(productId)}/power`,
            body: { action },
        }).then((r) => r.data);
    }
    /** Restart is not a native upstream action: stop, then start. */
    async kvmRestart(productId) {
        try {
            await this.kvmPower(productId, 'stop');
        }
        catch (err) {
            // `already_stopped` is fine — we still want the start below.
            if (!(err instanceof UpstreamApiError) || err.code !== 'already_stopped')
                throw err;
        }
        await sleep(2500);
        try {
            await this.kvmPower(productId, 'start');
        }
        catch (err) {
            if (!(err instanceof UpstreamApiError) || err.code !== 'already_running')
                throw err;
        }
        return { id: productId, action: 'restart' };
    }
    reinstallKvm(productId, input, idempotencyKey) {
        return this.request({
            method: 'POST',
            path: `/kvm/${encodeURIComponent(productId)}/reinstall`,
            body: input,
            idempotencyKey,
            retries: 0,
        }).then((r) => r.data);
    }
    setKvmPassword(productId, password) {
        return this.request({
            method: 'PUT',
            path: `/kvm/${encodeURIComponent(productId)}/password`,
            body: { password },
        }).then((r) => r.data);
    }
    getKvmConsole(productId) {
        return this.request({
            method: 'GET',
            path: `/kvm/${encodeURIComponent(productId)}/console`,
        }).then((r) => r.data);
    }
    getKvmNetwork(productId, rdns = false) {
        return this.request({
            method: 'GET',
            path: `/kvm/${encodeURIComponent(productId)}/network`,
            query: { rdns: rdns ? 1 : 0 },
        }).then((r) => r.data);
    }
    getKvmStatistics(productId, period = 'hour') {
        return this.request({
            method: 'GET',
            path: `/kvm/${encodeURIComponent(productId)}/statistics`,
            query: { period },
        }).then((r) => r.data);
    }
    getKvmFirewall(productId) {
        return this.request({
            method: 'GET',
            path: `/kvm/${encodeURIComponent(productId)}/firewall`,
        }).then((r) => r.data);
    }
    addKvmFirewallRule(productId, rule) {
        return this.request({
            method: 'POST',
            path: `/kvm/${encodeURIComponent(productId)}/firewall/rules`,
            body: rule,
        }).then((r) => r.data);
    }
}
exports.ResellerApiClient = ResellerApiClient;
// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
function headerStr(value) {
    if (typeof value === 'string' && value.length)
        return value;
    if (Array.isArray(value) && value.length)
        return String(value[0]);
    return null;
}
function httpStatusCode(status) {
    const map = {
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
function safeStringify(value) {
    try {
        const str = JSON.stringify(value);
        return str && str.length > 8000 ? `${str.slice(0, 8000)}…[truncated]` : str;
    }
    catch {
        return '[unserializable]';
    }
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}
/** Exponential backoff with jitter; prefers the provider's `Retry-After`. */
function backoffMs(attempt, retryAfterSec) {
    if (retryAfterSec && retryAfterSec > 0) {
        return Math.min(60_000, retryAfterSec * 1000 + 150);
    }
    const base = Math.min(8000, 400 * Math.pow(2, Math.max(0, attempt - 1)));
    return base + Math.floor(Math.random() * 250);
}
