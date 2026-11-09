import { UpstreamAccount, UpstreamBalance, UpstreamErrorData, UpstreamFirewall, UpstreamFirewallRuleInput, UpstreamKvmConfigurator, UpstreamKvmConfiguratorPrice, UpstreamKvmNetwork, UpstreamKvmOrderInput, UpstreamKvmOrderPreview, UpstreamKvmOrderResult, UpstreamKvmOs, UpstreamKvmPlan, UpstreamKvmServer, UpstreamKvmServerDetail, UpstreamKvmStatistics, UpstreamKvmStatus, UpstreamPagination, UpstreamProduct, UpstreamRateLimitInfo, UpstreamRenewQuote, UpstreamRenewResult, UpstreamResellerInfo, UpstreamTransaction } from './types';
export type UpstreamErrorKind = 'api' | 'network' | 'timeout' | 'config' | 'protocol' | 'ratelimit';
/**
 * Thrown for every failed upstream interaction. `code` is the provider's
 * stable machine code (`insufficient_balance`, `out_of_stock`, ...) when the
 * provider supplied one, otherwise a local kind such as `network_error`.
 */
export declare class UpstreamApiError extends Error {
    readonly kind: UpstreamErrorKind;
    readonly statusCode: number;
    readonly code: string;
    readonly data: UpstreamErrorData;
    readonly requestId: string | null;
    readonly endpoint: string;
    readonly method: string;
    readonly rateLimit: UpstreamRateLimitInfo;
    /** Human-readable provider message; safe to show to an administrator. */
    readonly upstreamMessage: string;
    /** True when re-sending the identical request could succeed. */
    readonly retryable: boolean;
    /** Seconds to wait before retrying (from `Retry-After`), when provided. */
    readonly retryAfterSec: number | null;
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
    });
    /** Flat field errors for 422 `validation_failed` responses. */
    fieldErrors(): Record<string, string>;
    toJSON(): {
        error: string;
        code: string;
        kind: UpstreamErrorKind;
        statusCode: number;
        requestId: string | null;
        retryable: boolean;
        retryAfterSec: number | null;
        fields: Record<string, string>;
        balance: {
            required: string | null;
            available: string | null;
        } | undefined;
    };
}
export declare function emptyRateLimit(): UpstreamRateLimitInfo;
/** Parses the provider's "12.50" money string into integer cents. */
export declare function moneyToCents(value: string | number | null | undefined): number;
/** Formats integer cents back into the provider's "12.50" representation. */
export declare function centsToMoney(cents: number): string;
/** `X.XX €` style display helper used by the UI layer. */
export declare function formatMoney(cents: number, currency?: string): string;
/**
 * Generates an `Idempotency-Key` (1-64 chars of `[A-Za-z0-9_-:.]`).
 * Persist it BEFORE the upstream call so a retry replays the same key.
 */
export declare function buildIdempotencyKey(prefix: string, unique: string): string;
/** Deep-copies a payload replacing sensitive values with `***`. */
export declare function redactSensitive(input: unknown, depth?: number): unknown;
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
export declare class ResellerApiClient {
    private readonly baseUrl;
    private readonly apiKey;
    private readonly timeoutMs;
    private readonly maxRetries;
    private readonly userAgent;
    private readonly onLog?;
    /** Last observed rate-limit headers, useful for admin dashboards. */
    lastRateLimit: UpstreamRateLimitInfo;
    constructor(config: ResellerClientConfig);
    isConfigured(): boolean;
    /** Redacted key hint (first and last characters only) safe to render in the admin UI. */
    keyHint(): string;
    private assertConfigured;
    private buildUrl;
    private rawRequest;
    private parseRateLimit;
    /**
     * Performs a request with retries and converts the response into either the
     * unwrapped `data` payload or a typed `UpstreamApiError`.
     */
    request<T = unknown>(opts: {
        method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
        path: string;
        query?: Record<string, unknown>;
        body?: unknown;
        idempotencyKey?: string | null;
        /** HTTP statuses treated as success (orders return 200 for sandbox, 201 for real). */
        okStatuses?: number[];
        retries?: number;
    }): Promise<{
        data: T;
        statusCode: number;
        requestId: string | null;
        rateLimit: UpstreamRateLimitInfo;
        replayed: boolean;
    }>;
    private emitLog;
    getAccount(): Promise<UpstreamAccount>;
    getBalance(): Promise<UpstreamBalance>;
    listTransactions(params?: {
        page?: number;
        perPage?: number;
        productId?: string;
    }): Promise<{
        transactions: UpstreamTransaction[];
        pagination: UpstreamPagination;
    }>;
    getResellerInfo(): Promise<UpstreamResellerInfo>;
    listProducts(params?: {
        page?: number;
        perPage?: number;
        type?: string;
        state?: string;
        access?: string;
        search?: string;
    }): Promise<{
        products: UpstreamProduct[];
        pagination: UpstreamPagination;
    }>;
    getProduct(productId: string): Promise<UpstreamProduct>;
    renameProduct(productId: string, name: string | null): Promise<UpstreamProduct>;
    setAutoRenew(productId: string, autoRenew: boolean | 0 | 1): Promise<UpstreamProduct>;
    getRenewal(productId: string): Promise<UpstreamRenewQuote>;
    renewProduct(productId: string, idempotencyKey?: string | null): Promise<UpstreamRenewResult>;
    listKvmPlans(cpu?: string): Promise<UpstreamKvmPlan[]>;
    getKvmPlan(planId: string): Promise<UpstreamKvmPlan>;
    getKvmConfigurator(cpu?: string): Promise<UpstreamKvmConfigurator[]>;
    getKvmConfiguratorPrice(params: {
        cpu: string;
        cores: number;
        memory: number;
        disk: number;
        ipv4?: number;
        ipv6?: number;
        voucher?: string;
    }): Promise<UpstreamKvmConfiguratorPrice>;
    listKvmOs(): Promise<UpstreamKvmOs[]>;
    /**
     * Places (or with `sandbox: true`, prices) a KVM order.
     * Always pass a persisted `idempotencyKey` for real orders.
     */
    orderKvm(input: UpstreamKvmOrderInput, idempotencyKey?: string | null): Promise<{
        sandbox: boolean;
        statusCode: number;
        requestId: string | null;
        replayed: boolean;
        preview?: UpstreamKvmOrderPreview;
        result?: UpstreamKvmOrderResult;
    }>;
    listKvm(params?: {
        page?: number;
        perPage?: number;
        state?: string;
        search?: string;
        access?: string;
    }): Promise<{
        servers: UpstreamKvmServer[];
        pagination: UpstreamPagination;
    }>;
    getKvm(productId: string): Promise<UpstreamKvmServerDetail>;
    getKvmStatus(productId: string): Promise<UpstreamKvmStatus>;
    kvmPower(productId: string, action: 'start' | 'stop'): Promise<{
        id: string;
        action: string;
    }>;
    /** Restart is not a native upstream action: stop, then start. */
    kvmRestart(productId: string): Promise<{
        id: string;
        action: 'restart';
    }>;
    reinstallKvm(productId: string, input: {
        os: string;
        password?: string;
        confirm: true;
    }, idempotencyKey?: string | null): Promise<{
        id: string;
        state: string;
        os: string;
        credentials?: {
            username: string;
            password: string;
        };
    }>;
    setKvmPassword(productId: string, password: string): Promise<{
        id: string;
        credentials: {
            username: string;
            password: string;
        };
    }>;
    getKvmConsole(productId: string): Promise<{
        id: string;
        consoleUrl: string;
    }>;
    getKvmNetwork(productId: string, rdns?: boolean): Promise<UpstreamKvmNetwork>;
    getKvmStatistics(productId: string, period?: 'hour' | 'day' | 'week' | 'month' | 'year'): Promise<UpstreamKvmStatistics>;
    getKvmFirewall(productId: string): Promise<UpstreamFirewall>;
    addKvmFirewallRule(productId: string, rule: UpstreamFirewallRuleInput): Promise<UpstreamFirewall>;
}
export declare function sleep(ms: number): Promise<void>;
/** Exponential backoff with jitter; prefers the provider's `Retry-After`. */
export declare function backoffMs(attempt: number, retryAfterSec?: number | null): number;
