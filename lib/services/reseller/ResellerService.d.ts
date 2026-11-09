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
import { ResellerApiClient, UpstreamApiError } from './client';
import { CloudServerRow, ResellerOsRow, ResellerPlanRow, UpstreamAccount, UpstreamFirewall, UpstreamKvmConfigurator, UpstreamKvmConfiguratorPrice, UpstreamKvmNetwork, UpstreamKvmStatistics, UpstreamKvmStatus, UpstreamRateLimitInfo, UpstreamRenewQuote, UpstreamResellerInfo, WalletEntryRow } from './types';
export declare class ResellerError extends Error {
    readonly statusCode: number;
    readonly code: string;
    readonly details: Record<string, unknown>;
    constructor(message: string, statusCode?: number, code?: string, details?: Record<string, unknown>);
    toJSON(): {
        error: string;
        code: string;
    };
}
/** Converts any thrown value into something a route can render safely. */
export declare function toResellerError(err: unknown): ResellerError;
/** Maps stable provider error codes onto operator-friendly English copy. */
export declare function humanizeUpstreamError(err: UpstreamApiError): string;
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
/**
 * Converts a provider timestamp (`YYYY-MM-DD HH:mm:ss`, Europe/Berlin) into
 * `YYYY-MM-DD HH:MM:SS` UTC so it can be compared with SQLite's
 * `CURRENT_TIMESTAMP` / `datetime('now')` values.
 */
export declare function upstreamTimeToUtc(value: string | null | undefined): string | null;
/** UTC→Europe/Berlin offset (handles CET/CEST via the IANA database). */
export declare function berlinOffsetMs(utcMs: number): number;
/** Formats a stored UTC datetime for display in the panel (still UTC-labelled). */
export declare function formatUtcForDisplay(utcValue: string | null | undefined): string;
/**
 * Friendly label for a provider CPU family. The upstream `cpu` key is a short
 * family slug (`epyc`, `ryzen`, `xeon`, ...); the concrete model (EPYC 7543,
 * Ryzen 9 5950X, Ryzen 9 9950X, Xeon E5-2697 v4) is carried in the plan name
 * and surfaced through `cpu_label`.
 */
export declare function cpuFamilyLabel(family: string | null | undefined, planName?: string | null): string;
/** Builds a stable, human slug for a configurator-backed plan. */
export declare function configPlanSlug(cpu: string, cores: number, memoryGb: number, diskGb: number): string;
/** Package plan slug keeps the upstream name recognisable. */
export declare function packagePlanSlug(name: string, upstreamId: string): string;
export interface PlaceOrderInput {
    userId: number;
    /** Local `reseller_plans.id`. Required for package plans. */
    planId?: number | null;
    /** Custom configuration (only when the configurator is enabled by the admin). */
    config?: {
        cpu: string;
        cores: number;
        memory: number;
        disk: number;
        ipv4?: number;
        ipv6?: number;
    } | null;
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
    credentials: {
        username: string;
        password: string;
    } | null;
    requestId: string | null;
    replayed: boolean;
    errorCode: string | null;
    error: string | null;
    pricing?: Record<string, unknown> | null;
    balancePreview?: {
        availableCents: number;
        afterOrderCents: number;
    } | null;
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
        cpuFamilies: Array<{
            cpu: string;
            label: string;
            plans: number;
        }>;
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
export declare class ResellerService {
    /** Shared panel database — exposed for audit logging from route handlers. */
    readonly db: UnifiedDatabase;
    private client;
    private clientFingerprint;
    private readonly inFlightOrders;
    private pollTimer;
    private syncTimer;
    private pollRunning;
    private syncRunning;
    constructor(db: UnifiedDatabase);
    getSettings(): Promise<ResellerSettings>;
    setSetting(key: string, value: string | number | boolean | null): Promise<void>;
    /**
     * Stores the upstream API key encrypted at rest (AES-256-GCM via the panel
     * secret vault) and keeps only a short hint for display.
     */
    setApiKey(rawKey: string): Promise<{
        hint: string;
    }>;
    /** Resolves the plaintext API key: encrypted setting first, then `.env`. */
    resolveApiKey(settings?: ResellerSettings): Promise<string>;
    /**
     * Returns a configured client, rebuilding it only when base URL / key /
     * timeout changed. Callers that need to know whether a key exists should
     * check `isConfigured()`.
     */
    getClient(): Promise<ResellerApiClient>;
    isReady(): Promise<{
        ready: boolean;
        enabled: boolean;
        reason: string | null;
    }>;
    /** Guards every upstream-touching operation. */
    private requireReady;
    private writeApiLog;
    listApiLogs(limit?: number): Promise<Record<string, unknown>[]>;
    getStatus(options?: {
        probeUpstream?: boolean;
    }): Promise<ResellerStatus>;
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
    syncCatalogue(options?: {
        actorId?: number | null;
    }): Promise<{
        plansUpserted: number;
        plansNew: number;
        plansDisabled: number;
        osUpserted: number;
        cpuFamilies: string[];
        upstreamBalanceCents: number | null;
    }>;
    /** Fetches live configurator limits/prices (not persisted; priced on demand). */
    getConfigurator(cpu?: string): Promise<UpstreamKvmConfigurator[]>;
    getConfiguratorPrice(params: {
        cpu: string;
        cores: number;
        memory: number;
        disk: number;
        ipv4?: number;
        ipv6?: number;
        voucher?: string;
        markupPercent?: number | null;
    }): Promise<{
        upstream: UpstreamKvmConfiguratorPrice;
        costCents: number;
        retailCents: number;
        retailRenewCents: number;
    }>;
    listOsImages(options?: {
        enabledOnly?: boolean;
    }): Promise<ResellerOsRow[]>;
    listPlans(options?: {
        enabledOnly?: boolean;
        visibleOnly?: boolean;
        cpu?: string;
    }): Promise<ResellerPlanRow[]>;
    /** Customer-facing catalogue grouped by CPU family. */
    getStoreCatalogue(): Promise<{
        enabled: boolean;
        groups: Array<{
            cpu: string;
            label: string;
            plans: StorePlan[];
        }>;
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
    }>;
    getPlan(planId: number): Promise<ResellerPlanRow>;
    updatePlan(planId: number, patch: {
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
    }): Promise<ResellerPlanRow>;
    /**
     * Creates a sellable "custom configuration" plan from configurator limits.
     * Prices are taken from the live provider quote so the margin is exact.
     */
    createConfigPlan(input: {
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
    }): Promise<ResellerPlanRow>;
    getWalletBalance(userId: number): Promise<number>;
    getWalletLedger(userId: number, limit?: number): Promise<WalletEntryRow[]>;
    /**
     * Appends a ledger entry atomically and returns the new balance.
     * `BEGIN IMMEDIATE` serialises concurrent wallet writes so an overdraft
     * cannot slip through between the balance read and the insert.
     */
    private appendLedger;
    /** Admin grants (positive) or withdraws (negative) panel credit. */
    adjustWallet(params: {
        userId: number;
        amountCents: number;
        kind?: 'credit' | 'debit' | 'refund' | 'adjustment';
        description?: string;
        actorId?: number | null;
    }): Promise<{
        balanceCents: number;
        entryId: number;
    }>;
    /** Validates + prices an order without buying anything (`sandbox: true`). */
    previewOrder(input: PlaceOrderInput): Promise<OrderOutcome>;
    /**
     * Places an order and provisions the server onto the customer's panel
     * account. Safe to call repeatedly for the same `orderId` via
     * `retryOrder()` — the persisted idempotency key prevents double purchase.
     */
    placeOrder(input: PlaceOrderInput): Promise<OrderOutcome>;
    /**
     * Runs the upstream call for a stored order. Re-entrant and crash-safe:
     * the persisted idempotency key makes a repeat call replay the provider's
     * stored response instead of creating a second server.
     */
    private executeOrder;
    private runOrder;
    /**
     * Re-drives a `pending` order (queued after a timeout/5xx) using its stored
     * idempotency key. Also used by the background poller.
     */
    retryOrder(orderId: number): Promise<OrderOutcome>;
    cancelOrder(orderId: number, actorId?: number | null): Promise<void>;
    listOrders(options?: {
        userId?: number;
        status?: string;
        limit?: number;
        offset?: number;
    }): Promise<{
        orders: Record<string, any>[];
        total: number;
    }>;
    getOrder(orderId: number): Promise<Record<string, any>>;
    private upsertCloudServer;
    listCloudServers(options?: {
        userId?: number;
        includeShared?: boolean;
        state?: string;
        search?: string;
        limit?: number;
    }): Promise<CloudServerRow[]>;
    getCloudServer(serverId: number): Promise<CloudServerRow>;
    /** Ownership/RBAC guard used by every customer-facing server endpoint. */
    getAuthorizedCloudServer(principal: {
        userId: number;
        role: string;
    }, serverId: number, requireOwner?: boolean): Promise<CloudServerRow>;
    /** Decrypts stored upstream root credentials. */
    revealCredentials(server: CloudServerRow): {
        username: string;
        password: string;
    } | null;
    /** Sanitised server view for API responses (credentials only when asked). */
    serializeServer(server: CloudServerRow, options?: {
        includeCredentials?: boolean;
    }): Record<string, unknown>;
    refreshServer(serverId: number, options?: {
        withStatus?: boolean;
    }): Promise<{
        server: CloudServerRow;
        status: UpstreamKvmStatus | null;
    }>;
    private applyUpstreamServerState;
    serverPower(serverId: number, action: 'start' | 'stop' | 'restart', actor?: {
        userId: number;
        role: string;
    }): Promise<CloudServerRow>;
    serverConsoleUrl(serverId: number): Promise<{
        consoleUrl: string;
    }>;
    serverStatus(serverId: number): Promise<UpstreamKvmStatus>;
    serverStatistics(serverId: number, period?: 'hour' | 'day' | 'week' | 'month' | 'year'): Promise<UpstreamKvmStatistics>;
    serverNetwork(serverId: number, rdns?: boolean): Promise<UpstreamKvmNetwork>;
    serverFirewall(serverId: number): Promise<UpstreamFirewall>;
    serverReinstall(serverId: number, input: {
        os: string;
        password?: string;
        confirm: true;
    }, actor?: {
        userId: number;
        role: string;
    }): Promise<{
        state: string;
        credentials: {
            username: string;
            password: string;
        } | null;
    }>;
    serverSetPassword(serverId: number, password: string, actor?: {
        userId: number;
        role: string;
    }): Promise<{
        username: string;
        password: string;
    }>;
    serverSetAutoRenew(serverId: number, autoRenew: boolean, actor?: {
        userId: number;
        role: string;
    }): Promise<CloudServerRow>;
    serverRename(serverId: number, name: string, actor?: {
        userId: number;
        role: string;
    }): Promise<CloudServerRow>;
    /** Admin-only local suspension (does not touch the upstream product). */
    setSuspension(serverId: number, suspended: boolean, reason: string | null, actor?: {
        userId: number;
        role: string;
    }): Promise<CloudServerRow>;
    renewalQuote(serverId: number): Promise<{
        quote: UpstreamRenewQuote | null;
        retailCents: number;
        walletBalanceCents: number;
        sufficient: boolean;
        newExpiresAt: string | null;
    }>;
    /**
     * Renews a server: charges the customer wallet, then extends the upstream
     * product. If the upstream renewal fails terminally the charge is reversed
     * automatically so the customer never pays for nothing.
     */
    renewServer(serverId: number, actor?: {
        userId: number;
        role: string;
    }): Promise<{
        server: CloudServerRow;
        chargedCents: number;
        costCents: number;
        walletBalanceCents: number;
        newExpiresAt: string | null;
    }>;
    /** Starts the provisioning poller and the catalogue sync timer. */
    startBackgroundJobs(): void;
    stopBackgroundJobs(): void;
    private syncCatalogueIfEnabled;
    /**
     * One reconciliation pass:
     *  1. Re-drive queued orders (idempotent, so never a double purchase).
     *  2. Move `install`/`reinstall` servers to `active` and publish their IPs.
     *  3. Refresh expiry/auto-renew for active servers.
     *  4. Warn the admin when the upstream balance runs low.
     */
    syncLoop(): Promise<{
        ordersRetried: number;
        ordersProvisioned: number;
        serversUpdated: number;
        becameActive: number;
        errors: string[];
    }>;
    private onServerBecameActive;
    private lastBalanceAlertAt;
    private checkUpstreamBalanceAlert;
    private markOrderFailed;
    /**
     * Assembles the API-facing outcome for an order, joining the provisioned
     * `cloud_servers` row so callers get IPs/credentials in one shot.
     */
    private buildOutcome;
    private notify;
}
export declare function applyMarkup(costCents: number, markupPercent: number): number;
export declare function sanitizeProductName(name: unknown): string | null;
export declare function sanitizeHostname(hostname: unknown): string | null;
