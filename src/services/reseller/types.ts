/**
 * Typed contracts for the upstream reseller provider API.
 *
 * Modelled against the Bukkit-Hosting API v2 OpenAPI specification
 * (https://bukkit-hosting.eu/docs → /assets/openapi.yaml).
 *
 * Provider conventions that every type below respects:
 *  - Every response is an envelope: `{ response, state, data }`.
 *  - `state` is `success` or `error`; errors carry a stable `data.code`.
 *  - Money is a *string* with exactly two decimals, always EUR ("12.50").
 *  - Timestamps are `YYYY-MM-DD HH:mm:ss` in Europe/Berlin.
 *  - `autoRenew` is `1` / `0` on read, but accepts booleans on write.
 *  - RAM/disk are GB, connection is Gbit/s, duration is months.
 *  - Field names are camelCase, identifiers are UUIDs.
 */

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

export type UpstreamState = 'success' | 'error';

export interface UpstreamEnvelope<T> {
  response: string;
  state: UpstreamState;
  data: T;
}

export interface UpstreamErrorData {
  code: string;
  /** Field-level messages for HTTP 422 `validation_failed` (dotted paths). */
  errors?: Record<string, string[]> | Record<string, string>;
  /** Present on 402 `insufficient_balance`. */
  required?: string;
  available?: string;
  /** Present on 422 `registry_rejected`. */
  registryCode?: string;
  [key: string]: unknown;
}

export interface UpstreamPagination {
  page: number;
  perPage: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

/** Rate-limit headers returned on every response. */
export interface UpstreamRateLimitInfo {
  limit: number | null;
  remaining: number | null;
  /** Unix seconds. */
  reset: number | null;
  /** Seconds from `Retry-After`, only present on 429. */
  retryAfter: number | null;
}

// ---------------------------------------------------------------------------
// Account / reseller
// ---------------------------------------------------------------------------

export interface UpstreamBalance {
  amount: string;
  currency: string;
}

export interface UpstreamProfile {
  company?: string;
  firstname?: string;
  lastname?: string;
  street?: string;
  number?: string;
  postcode?: string;
  city?: string;
  state?: string;
  country?: string;
  phone?: string;
}

export interface UpstreamAccount {
  userId: string;
  username: string;
  email: string;
  role: string;
  state: string;
  verified: boolean;
  profile?: UpstreamProfile;
  balance?: UpstreamBalance;
  transferReference?: string;
  api?: {
    keyName?: string;
    rateLimits?: Record<string, { limit: number; window: number }>;
  };
  updatedAt?: string;
  createdAt?: string;
}

export interface UpstreamTransaction {
  id: string;
  productId: string | null;
  amount: string;
  description: string;
  createdAt: string;
}

export interface UpstreamResellerInfo {
  role: string;
  reseller: boolean;
  kvm?: { tier: string; customPrices?: boolean };
  domain?: { tier: string; domains: number; next?: { tier: string; domains: number } };
  productValue?: {
    monthly: string;
    level: string;
    next?: { level: string; value: string; missing: string };
  };
}

// ---------------------------------------------------------------------------
// Products (shared across kvm / domain / webspace)
// ---------------------------------------------------------------------------

export type UpstreamProductType =
  | 'kvm'
  | 'webspace'
  | 'domain'
  | 'dedicated'
  | 'gameserver'
  | 'teamspeak'
  | 'ipv4'
  | 'ipv6'
  | 'other';

/**
 * Lifecycle of an upstream product. `install` / `reinstall` are transient
 * build states; IPs are only published once the server reaches `active`.
 */
export type UpstreamProductState =
  | 'install'
  | 'reinstall'
  | 'active'
  | 'suspended'
  | 'expired'
  | 'cancelled'
  | 'pending'
  | string;

export interface UpstreamProduct {
  id: string;
  type: UpstreamProductType;
  name: string;
  customName: string | null;
  state: UpstreamProductState;
  price: string;
  duration: number;
  autoRenew: 0 | 1;
  access: 'owner' | 'shared';
  expireAt: string | null;
  createdAt: string | null;
}

export interface UpstreamRenewQuote {
  productId: string;
  type: string;
  price: string;
  duration: number;
  expireAt: string | null;
  newExpireAt: string | null;
  balance: string;
  sufficient: boolean;
}

export interface UpstreamRenewResult {
  productId: string;
  price: string;
  expireAt: string | null;
  balance: string;
}

// ---------------------------------------------------------------------------
// KVM
// ---------------------------------------------------------------------------

/**
 * CPU family key as used by the provider (`epyc`, `ryzen`, `xeon`, ...).
 * Kept as `string` because the catalogue is fetched at runtime — the
 * reseller's host fleet (EPYC 7543, Ryzen 5900X/5950X/9900X/9950X,
 * Xeon E5-2697 v4) is reflected in these values and in plan names.
 */
export type UpstreamCpuFamily = string;

export interface UpstreamKvmPlan {
  id: string;
  name: string;
  cpu: UpstreamCpuFamily;
  cores: number;
  memory: number;
  disk: number;
  ipv4: number;
  ipv6: number;
  connection: number;
  duration: number;
  price: string;
  discountPercent: number;
  discountEndsAt: string | null;
  /** Price actually charged for order *and* renewal. */
  finalPrice: string;
  available: boolean;
  popular: boolean;
  /** Account-specific offer — other accounts get 404 for this plan. */
  exclusive: boolean;
}

export interface UpstreamConfiguratorLimit {
  min: number;
  max: number;
  step: number;
}

export interface UpstreamKvmConfigurator {
  cpu: UpstreamCpuFamily;
  available: boolean;
  duration: number;
  connection: number;
  limits: {
    cores: UpstreamConfiguratorLimit;
    memory: UpstreamConfiguratorLimit;
    disk: UpstreamConfiguratorLimit;
    ipv4: UpstreamConfiguratorLimit;
    ipv6: UpstreamConfiguratorLimit;
  };
  unitPrices: {
    cores: string;
    memory: string;
    disk: string;
    ipv4: string;
    ipv6: string;
  };
  discountPercent: number;
  discountEndsAt: string | null;
}

export interface UpstreamPricing {
  price: string;
  discountPercent: number;
  discountEndsAt: string | null;
  renewPrice: string;
  voucherCode: string | null;
  voucherDiscount: string;
  orderPrice: string;
  duration: number;
  currency: string;
}

export interface UpstreamKvmConfiguratorPrice {
  cpu: UpstreamCpuFamily;
  cores: number;
  memory: number;
  disk: number;
  ipv4: number;
  ipv6: number;
  connection: number;
  available: boolean;
  pricing: UpstreamPricing;
}

export interface UpstreamKvmOs {
  id: string;
  name: string;
  windows: boolean;
  /** Windows images require at least this many GB of disk. */
  minDisk: number | null;
}

export interface UpstreamCredentials {
  username: string;
  password: string;
}

export interface UpstreamKvmServer {
  id: string;
  name: string;
  customName: string | null;
  state: UpstreamProductState;
  cpu: UpstreamCpuFamily;
  cores: number;
  memory: number;
  disk: number;
  connection: number;
  ipv4: number;
  ipv6: number;
  primaryIpv4: string | null;
  primaryIpv6: string | null;
  price: string;
  duration: number;
  autoRenew: 0 | 1;
  access: 'owner' | 'shared';
  expireAt: string | null;
  createdAt: string | null;
}

export interface UpstreamKvmServerDetail extends UpstreamKvmServer {
  credentials?: UpstreamCredentials | null;
  os?: string;
  planId?: string | null;
}

export interface UpstreamKvmStatus {
  id: string;
  state: UpstreamProductState;
  /** `running` / `stopped` / `unknown` (unknown = hypervisor unreachable). */
  status: string;
  uptime: number | null;
  cpu: number | null;
  memory?: { used: number; total: number } | null;
  /** Only reported when the QEMU guest agent is installed. */
  disk?: { used: number; total: number } | null;
}

export interface UpstreamKvmOrderPreview {
  sandbox: true;
  cpu: UpstreamCpuFamily;
  planId?: string | null;
  name: string;
  cores: number;
  memory: number;
  disk: number;
  ipv4: number;
  ipv6: number;
  connection: number;
  os: string;
  autoRenew: 0 | 1;
  pricing: UpstreamPricing;
  balance: { available: string; afterOrder: string };
}

export interface UpstreamKvmOrderResult extends UpstreamKvmServerDetail {
  credentials?: UpstreamCredentials | null;
  os?: string;
  planId?: string | null;
  pricing?: UpstreamPricing;
  warnings?: string[];
}

/** Custom-configuration order payload (mutually exclusive with `planId`). */
export interface UpstreamKvmConfigInput {
  cpu: UpstreamCpuFamily;
  cores: number;
  memory: number;
  disk: number;
  ipv4?: number;
  ipv6?: number;
}

export interface UpstreamKvmOrderInput {
  /** Package order — mutually exclusive with `config`. */
  planId?: string;
  /** Configurator order — mutually exclusive with `planId`. */
  config?: UpstreamKvmConfigInput;
  /** Image id from `GET /kvm/os`. */
  os: string;
  /** Custom product name, <= 50 chars. */
  name?: string;
  /** 8-64 chars from `[A-Za-z0-9!#$%&()*+,\-./:;=?@^_{|}~]`; auto-generated when omitted. */
  password?: string;
  autoRenew?: boolean | 0 | 1;
  voucher?: string;
  /** Must be true for a real order. */
  tos?: boolean;
  /** Waiver of the right of withdrawal (immediate execution). Must be true. */
  cancellation?: boolean;
  /** Validate + price only, order nothing. */
  sandbox?: boolean;
}

export interface UpstreamKvmNetworkAddress {
  ip: string;
  prefix: number;
  gateway: string;
  main: boolean;
  rdns?: string | null;
}

export interface UpstreamKvmNetwork {
  id: string;
  ipv4: UpstreamKvmNetworkAddress[];
  ipv6: UpstreamKvmNetworkAddress[];
}

export interface UpstreamKvmStatisticsPoint {
  time: string;
  cpu: number;
  memory: number;
  memoryUsed: number;
  netIn: number;
  netOut: number;
}

export interface UpstreamKvmStatistics {
  id: string;
  period: 'hour' | 'day' | 'week' | 'month' | 'year';
  units: Record<string, string>;
  summary: {
    cpu?: { current: number; average: number; max: number };
    memory?: { current: number; average: number; max: number };
    traffic?: { in: number; out: number };
  };
  points: UpstreamKvmStatisticsPoint[];
}

export interface UpstreamFirewallRule {
  pos: number;
  type: 'in' | 'out';
  action: 'ACCEPT' | 'DROP' | 'REJECT' | string;
  enabled: boolean;
  protocol: string;
  source: string;
  sourcePort: string;
  destination: string;
  destinationPort: string;
  comment: string;
  /** Support-managed rule — not editable through the API. */
  locked: boolean;
}

export interface UpstreamFirewall {
  id: string;
  clusterEnabled: boolean;
  policyIn: string;
  policyOut: string;
  digest: string;
  rules: UpstreamFirewallRule[];
  protocols: Array<{ value: string; label: string }>;
}

export interface UpstreamFirewallRuleInput {
  type: 'in' | 'out';
  action: 'ACCEPT' | 'DROP' | 'REJECT';
  enabled?: boolean;
  protocol?: string;
  source?: string;
  sourcePort?: string;
  destination?: string;
  destinationPort?: string;
  comment?: string;
  /** Optimistic-concurrency digest from the last read. */
  digest?: string;
}

// ---------------------------------------------------------------------------
// Local (panel-side) domain types
// ---------------------------------------------------------------------------

export type ResellerOrderStatus =
  | 'pending'
  | 'provisioning'
  | 'provisioned'
  | 'failed'
  | 'cancelled';

export type ResellerPaymentMode = 'wallet' | 'free' | 'manual';

/**
 * A configured upstream reseller account. Panels may have several: each row
 * owns its own API key, base URL, catalogue, orders and servers.
 */
export interface ResellerProviderRow {
  id: number;
  slug: string;
  name: string;
  provider: string;
  base_url: string;
  api_key_enc: string | null;
  api_key_hint: string | null;
  is_default: number;
  is_enabled: number;
  store_enabled: number;
  markup_percent: number | null;
  request_timeout_ms: number;
  last_sync_at: string | null;
  last_probe_at: string | null;
  last_balance_cents: number | null;
  last_error: string | null;
  last_error_at: string | null;
  sort_order: number;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface ResellerPlanRow {
  id: number;
  provider_id: number | null;
  provider: string;
  upstream_plan_id: string | null;
  kind: 'package' | 'config';
  slug: string | null;
  display_name: string;
  description: string | null;
  cpu_family: string | null;
  cpu_label: string | null;
  cores: number;
  memory_gb: number;
  disk_gb: number;
  ipv4_count: number;
  ipv6_count: number;
  connection_gbit: number;
  duration_months: number;
  cost_cents: number;
  cost_renew_cents: number;
  retail_cents: number;
  retail_renew_cents: number;
  setup_cents: number;
  currency: string;
  is_enabled: number;
  is_visible: number;
  is_popular: number;
  sort_order: number;
  stock_state: string;
  upstream_available: number | null;
  upstream_exclusive: number;
  upstream_discount_percent: number;
  upstream_discount_ends_at: string | null;
  upstream_raw: string | null;
  last_synced_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ResellerOsRow {
  id: number;
  provider_id: number | null;
  provider: string;
  upstream_os_id: string;
  display_name: string;
  family: string;
  is_windows: number;
  min_disk_gb: number | null;
  is_enabled: number;
  icon: string | null;
  sort_order: number;
  last_synced_at: string | null;
}

export interface CloudServerRow {
  id: number;
  user_id: number;
  order_id: number | null;
  provider_id: number | null;
  provider: string;
  provider_product_id: string | null;
  name: string;
  hostname: string | null;
  cpu_family: string | null;
  cpu_label: string | null;
  cores: number;
  memory_gb: number;
  disk_gb: number;
  connection_gbit: number;
  ipv4_count: number;
  ipv6_count: number;
  primary_ipv4: string | null;
  primary_ipv6: string | null;
  os_id: string | null;
  os_label: string | null;
  ssh_user: string | null;
  ssh_port: number;
  credentials_enc: string | null;
  upstream_state: string;
  power_status: string;
  retail_cents: number;
  renew_cents: number;
  cost_cents: number;
  currency: string;
  duration_months: number;
  auto_renew: number;
  billing_mode: string;
  expires_at: string | null;
  suspended: number;
  suspended_reason: string | null;
  last_synced_at: string | null;
  last_status_at: string | null;
  last_error: string | null;
  upstream_created_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface WalletEntryRow {
  id: number;
  user_id: number;
  delta_cents: number;
  balance_after_cents: number;
  kind: string;
  reference: string | null;
  description: string | null;
  created_by: number | null;
  created_at: string;
}
