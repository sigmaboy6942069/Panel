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
import { CloudServerRow, ResellerOsRow, ResellerPlanRow, ResellerProviderRow, UpstreamAccount, UpstreamFirewall, UpstreamKvmConfigurator, UpstreamKvmConfiguratorPrice, UpstreamKvmNetwork, UpstreamKvmStatistics, UpstreamKvmStatus, UpstreamRateLimitInfo, UpstreamRenewQuote, UpstreamResellerInfo, WalletEntryRow } from './types';
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
/** Normalises a provider display name into a stable slug. */
export declare function slugifyProvider(value: unknown): string;
/** Validates a provider API base URL and returns it without a trailing slash. */
export declare function validateBaseUrl(value: unknown): string;
/** Package plan slug keeps the upstream name recognisable. */
export declare function packagePlanSlug(name: string, upstreamId: string): string;
export interface PlaceOrderInput {
    userId: number;
    /** Local `reseller_plans.id`. Required for package plans. */
    planId?: number | null;
    /**
     * Which upstream provider to buy from. Package plans carry their own
     * provider; this is only needed for custom configurations and as a
     * fallback when nothing else names a provider.
     */
    providerId?: number | null;
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
    /** Upstream provider that fulfils this order. */
    providerId: number | null;
    providerName: string | null;
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
    providerId: number | null;
    providerName: string | null;
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
    /** Provider the figures below belong to (null when none is configured). */
    providerId: number | null;
    providerName: string | null;
    /** All providers with a lightweight health/rollup summary. */
    providers: ProviderSummary[];
    /** `providers` aggregated, i.e. what the whole panel resells. */
    totals: {
        providers: number;
        enabled: number;
        configured: number;
        plansEnabled: number;
        serversTotal: number;
        monthlyMarginCents: number;
        pendingOrders: number;
    };
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
/** Per-provider rollup rendered in the admin provider table. */
export interface ProviderSummary {
    id: number;
    slug: string;
    name: string;
    provider: string;
    baseUrl: string;
    keyHint: string;
    keyConfigured: boolean;
    isDefault: boolean;
    enabled: boolean;
    storeEnabled: boolean;
    markupPercent: number | null;
    requestTimeoutMs: number;
    lastSyncAt: string | null;
    lastProbeAt: string | null;
    lastBalanceCents: number | null;
    lastError: string | null;
    lastErrorAt: string | null;
    notes: string | null;
    plansTotal: number;
    plansEnabled: number;
    osImages: number;
    serversTotal: number;
    serversActive: number;
    ordersPending: number;
    monthlyRetailCents: number;
    monthlyCostCents: number;
    lowBalanceAlert: boolean;
}
export declare class ResellerService {
    /** Shared panel database — exposed for audit logging from route handlers. */
    readonly db: UnifiedDatabase;
    /** One HTTP client per provider id, rebuilt when its config changes. */
    private readonly clients;
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
     * Stores one provider's API key encrypted at rest and keeps a short hint.
     * An empty key clears it.
     */
    setProviderApiKey(providerId: number, rawKey: string): Promise<{
        hint: string;
    }>;
    /** Creates an additional upstream provider. */
    createProvider(input: {
        name: string;
        slug?: string | null;
        provider?: string;
        baseUrl: string;
        apiKey?: string | null;
        enabled?: boolean;
        storeEnabled?: boolean;
        markupPercent?: number | null;
        requestTimeoutMs?: number;
        notes?: string | null;
        makeDefault?: boolean;
        actorId?: number | null;
    }): Promise<ResellerProviderRow>;
    /**
     * Updates a provider's connection settings. The API key is only touched
     * when `apiKey` is provided (a non-empty string sets it, `''` clears it).
     */
    updateProvider(providerId: number, patch: {
        name?: string;
        baseUrl?: string;
        provider?: string;
        enabled?: boolean;
        storeEnabled?: boolean;
        markupPercent?: number | null;
        requestTimeoutMs?: number;
        notes?: string | null;
        isDefault?: boolean;
        apiKey?: string | null;
        actorId?: number | null;
    }): Promise<ResellerProviderRow>;
    /**
     * Deletes a provider. Refuses while it still has servers or open orders,
     * so a removal can never orphan a customer's VPS.
     */
    deleteProvider(providerId: number, actorId?: number | null): Promise<void>;
    /** Sets the fallback provider used when callers do not specify one. */
    setDefaultProvider(providerId: number): Promise<ResellerProviderRow>;
    /** Probes one provider without persisting anything but the probe result. */
    probeProvider(providerId: number): Promise<ResellerStatus>;
    /** Aggregated health/rollup for every provider. */
    /**
     * Public, camelCase view of a provider row. Never includes the encrypted
     * key blob — only a masked hint plus a boolean. Every provider endpoint
     * (list, create, update, default) returns this shape so API clients and
     * the admin console never have to switch between snake_case and camelCase.
     */
    serializeProvider(provider: ResellerProviderRow): ProviderSummary;
    getProviderSummaries(options?: {
        probeUpstream?: boolean;
    }): Promise<ProviderSummary[]>;
    /** Every configured upstream provider, default first. */
    listProviders(options?: {
        enabledOnly?: boolean;
    }): Promise<ResellerProviderRow[]>;
    getProvider(providerId: number): Promise<ResellerProviderRow>;
    /**
     * Resolves a provider by id, falling back to the panel default. `null`
     * means "let the panel decide", which keeps single-provider installs and
     * older API clients working unchanged.
     */
    resolveProvider(providerId?: number | null): Promise<ResellerProviderRow>;
    /** The provider used when a caller does not name one. */
    getDefaultProvider(): Promise<ResellerProviderRow>;
    /** Decrypts a provider's API key, falling back to `RESELLER_API_KEY` for the default one. */
    resolveProviderApiKey(provider: Pick<ResellerProviderRow, 'api_key_enc' | 'is_default'>): string;
    /** Whether an upstream call may be made for this provider right now. */
    isProviderReady(providerId?: number | null): Promise<{
        ready: boolean;
        enabled: boolean;
        reason: string | null;
        provider: ResellerProviderRow | null;
    }>;
    /**
     * Returns a configured client for one provider, rebuilding it only when
     * its base URL / key / timeout changed.
     */
    getClient(providerId?: number | null): Promise<ResellerApiClient>;
    /** Backwards-compatible readiness probe for the default provider. */
    isReady(): Promise<{
        ready: boolean;
        enabled: boolean;
        reason: string | null;
    }>;
    /** Guards every upstream-touching operation. */
    private requireReady;
    /** Resolves the provider behind a stored order/server row. */
    private providerIdForRow;
    private writeApiLog;
    listApiLogs(limit?: number, providerId?: number | null): Promise<Record<string, unknown>[]>;
    /**
     * Health + aggregates. Scoped to one provider by default (the default
     * provider) and always accompanied by a summary of every provider, so the
     * admin console can show the whole reselling business at a glance.
     */
    getStatus(options?: {
        probeUpstream?: boolean;
        providerId?: number | null;
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
        providerId?: number | null;
    }): Promise<{
        providerId: number;
        providerName: string;
        plansUpserted: number;
        plansNew: number;
        plansDisabled: number;
        osUpserted: number;
        cpuFamilies: string[];
        upstreamBalanceCents: number | null;
    }>;
    /** Fetches live configurator limits/prices (not persisted; priced on demand). */
    getConfigurator(cpu?: string, providerId?: number | null): Promise<UpstreamKvmConfigurator[]>;
    getConfiguratorPrice(params: {
        cpu: string;
        cores: number;
        memory: number;
        disk: number;
        ipv4?: number;
        ipv6?: number;
        voucher?: string;
        markupPercent?: number | null;
        providerId?: number | null;
    }): Promise<{
        upstream: UpstreamKvmConfiguratorPrice;
        costCents: number;
        retailCents: number;
        retailRenewCents: number;
    }>;
    listOsImages(options?: {
        enabledOnly?: boolean;
        providerId?: number | null;
        storeProvidersOnly?: boolean;
    }): Promise<ResellerOsRow[]>;
    listPlans(options?: {
        enabledOnly?: boolean;
        visibleOnly?: boolean;
        cpu?: string;
        providerId?: number | null;
        storeProvidersOnly?: boolean;
    }): Promise<ResellerPlanRow[]>;
    /** Customer-facing catalogue grouped by CPU family. */
    getStoreCatalogue(): Promise<{
        enabled: boolean;
        providers: Array<{
            id: number;
            name: string;
            isDefault: boolean;
            storeEnabled: boolean;
        }>;
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
        providerId?: number | null;
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
        providerId?: number | null;
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
        providerId?: number | null;
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
    /** Re-syncs every provider that is enabled, configured and selling. */
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
    /** Last low-balance notification, keyed by provider id. */
    private readonly lastBalanceAlertAt;
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
