# TGVPANEL — Upstream Reseller & Instant Cloud Provisioning

This guide explains how TGVPANEL resells KVM cloud servers from an **upstream
provider** (by default [Bukkit-Hosting](https://bukkit-hosting.eu), Düsseldorf,
Germany) and provisions them **instantly onto the buying customer's own panel
account** the moment an order is placed.

Everything is optional and config-driven: the panel builds, boots and runs with
**no upstream API key**. Until a key is added and the integration is enabled,
the storefront simply shows "no plans" and every upstream call degrades to a
clear, retryable error instead of crashing.

---

## Table of Contents

1. [How It Works](#1-how-it-works)
2. [What Gets Installed (migration v12)](#2-what-gets-installed-migration-v12)
3. [Quick Start — Add Your API Key](#3-quick-start--add-your-api-key)
4. [Environment Variables](#4-environment-variables)
5. [Selling Model & Money Handling](#5-selling-model--money-handling)
6. [The Order Pipeline (idempotency & crash-safety)](#6-the-order-pipeline-idempotency--crash-safety)
7. [Customer Experience](#7-customer-experience)
8. [Admin Console](#8-admin-console)
9. [REST API Reference](#9-rest-api-reference)
10. [Upstream Error Codes & How They Map](#10-upstream-error-codes--how-they-map)
11. [Background Jobs](#11-background-jobs)
12. [Security Notes](#12-security-notes)
13. [Testing Without a Live Key](#13-testing-without-a-live-key)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. How It Works

```
                 ┌──────────────────────────────────────────────┐
   Customer      │                TGVPANEL (you)                 │        Upstream provider
  ───────────►   │                                               │   ─────────────────────────►
   /store        │  storefront → preview (sandbox) → order       │    POST /kvm/order
                 │        │                                      │    (Idempotency-Key)
                 │        ▼                                      │
                 │  reseller_orders (status=pending) ────────────┼──► upstream buys the server
                 │        │                                      │
                 │        ▼                                      │
                 │  cloud_servers  ◄── IPs / credentials / state ┼──  GET /kvm, /kvm/{id},
                 │        │            (poller reconciles)       │      /status, /network …
                 │        ▼                                      │
   /cloud/:id  ◄─┤  server attached to the CUSTOMER's account    │
                 └──────────────────────────────────────────────┘
```

* The customer browses **your** retail catalogue at `/store`, picks a plan +
  operating system, and checks out against their **panel credit** (a wallet).
* The order is written to `reseller_orders` **first** (status `pending`, with a
  stable idempotency key), then the upstream API is called.
* On success the server is attached to the buyer's account in `cloud_servers`
  and shows up under **My Cloud Servers** (`/cloud`) with its IPs, root
  credentials, power controls, console, network, firewall and usage stats.
* If the upstream call times out or the provider is unreachable, the order
  **stays `pending`** and a background poller re-drives it with the *same*
  idempotency key — so a retry can never buy a second server.

The module is deliberately **standalone**: it does not touch the unified
`instances` (kvm/lxc) engine, which is keyed by integer IDs and local
virtualization. Upstream servers are UUID-identified and prepaid/expiry-billed,
so they live in their own tables, endpoints and pages.

---

## 2. What Gets Installed (migration v12)

Migration `v012_reseller_upstream_provisioning` runs automatically on the next
panel start (a pre-migration backup is taken first, as with every migration). It
creates six tables and seeds 18 `reseller_*` settings:

| Table | Purpose |
| --- | --- |
| `reseller_plans` | Your sellable catalogue: upstream cost vs. your retail price, per CPU family. Money is stored as **integer cents**. |
| `reseller_os_images` | Operating systems offered for order + reinstall (synced from `GET /kvm/os`). |
| `reseller_orders` | Every order with its idempotency key, status, upstream product ID and error state. |
| `cloud_servers` | Provisioned servers attached to a `users.id`, with IPs, encrypted credentials, expiry and suspension state. |
| `reseller_wallet_ledger` | Append-only customer credit ledger (grants, orders, renewals, refunds). Balance = `SUM(delta_cents)`. |
| `reseller_api_logs` | Raw upstream traffic for support/debugging, credential-redacted and trimmed to 2000 rows. |

Key settings (all editable in the admin console):

| Setting | Default | Meaning |
| --- | --- | --- |
| `reseller_enabled` | `0` | Master switch. Nothing upstream happens until this is `1`. |
| `reseller_api_base_url` | `https://bukkit-hosting.eu/api/v2` | Provider API v2 root. |
| `reseller_api_key_enc` | *(empty)* | AES-256-GCM encrypted API key (set via UI or `.env`). |
| `reseller_store_enabled` | `1` | Lets customers self-order from `/store`. |
| `reseller_default_markup_percent` | `20` | Markup applied to newly synced plans. |
| `reseller_auto_renew_default` | `1` | Pre-ticks auto-renewal at checkout. |
| `reseller_allow_configurator` | `0` | Lets staff build custom-config plans. |
| `reseller_sync_interval_sec` | `900` | Catalogue re-sync cadence. |
| `reseller_poll_interval_sec` | `30` | Order/server reconciliation cadence. |
| `reseller_low_balance_alert_cents` | `2000` | Warn admins below this upstream balance. |

---

## 3. Quick Start — Add Your API Key

You can add the key at any time — the panel runs fine without it.

**Option A — Admin console (recommended).** The key is encrypted at rest and
only ever shown again as a hint like `bkkt_d…abcd`.

1. Sign in as an **admin** and open **Admin → Reseller & Cloud** (`/admin/reseller`).
2. On the **Provider** tab, paste your reseller API key (`bkkt_…`) and click
   **Save connection**.
3. Click **Test connection** — you should see the upstream account, its balance
   and your reseller tier.
4. Tick **Integration enabled** (and **Storefront open**) and save.
5. Go to the **Catalogue & pricing** tab and click **Sync from provider**.
   New plans arrive **disabled** — set your retail prices, then enable the ones
   you want to sell.

**Option B — `.env` (headless).** Set `RESELLER_API_KEY=bkkt_…` and restart. A
key stored through the admin UI takes precedence over the env variable.

> The API key is a secret. Never commit it. `.env` and the secret vault file
> `.tgvpanel-secret` are already git-ignored.

---

## 4. Environment Variables

All optional; the admin console values win where both exist.

```dotenv
# Reseller API key (bkkt_…). DB value (set via UI) takes precedence.
RESELLER_API_KEY=
# Provider API v2 root (no trailing slash).
RESELLER_API_BASE_URL=https://bukkit-hosting.eu/api/v2
# How often queued orders are retried and server states/IPs refreshed.
RESELLER_POLL_INTERVAL_SEC=30
# How often the plan/OS catalogue is re-synced from the provider.
RESELLER_SYNC_INTERVAL_SEC=900
# Set to true to keep the reseller background jobs from starting (tests/CI).
TGVPANEL_DISABLE_RESELLER_POLLER=false
```

`TGVPANEL_DISABLE_BACKGROUND_POLLER=true` (used by the test suite) also disables
the reseller poller.

---

## 5. Selling Model & Money Handling

* **All money is integer cents (EUR).** Upstream string amounts like `"12.50"`
  are parsed to `1250`; nothing floats.
* There is **no payment gateway** in the panel. Customers spend from a
  **panel credit wallet**. Grant credit when a customer pays you (bank transfer,
  PayPal, Stripe, cash…) from **Admin → Reseller & Cloud → Customer credit**.
* A customer's balance is `SUM(reseller_wallet_ledger.delta_cents)`. Every
  movement is an auditable ledger row (kind = `credit` / `debit` / `refund` /
  `adjustment`, with an optional reference and the acting admin).
* Your **margin** per plan = `retail_cents − cost_cents`. The admin catalogue
  table shows cost, retail, renewal, one-off setup and the resulting margin.
* The **upstream balance** (what you have prepaid with the provider) is
  admin-only and surfaced on the status strip; a low-balance alert fires below
  `reseller_low_balance_alert_cents`.

Order billing modes (admin-placed orders):

| Mode | Behaviour |
| --- | --- |
| `wallet` | Deduct retail + setup from the customer's credit (default). Refused up-front if the balance is too low. |
| `manual` | Record the order but bill it outside the panel. |
| `free` | Comp the server (no charge). |

---

## 6. The Order Pipeline (idempotency & crash-safety)

Placing an order is the one operation that spends real money, so it is built to
be safe under retries, restarts and network loss:

1. **Validate** the plan, OS and (for `wallet`) that the balance covers
   `retail + setup`. Insufficient credit is refused **before** any upstream call.
2. **Insert** a `reseller_orders` row with `status='pending'` and
   `idempotency_key = tgv:<orderRef>` — persisted *before* the network call.
3. **Call** `POST /kvm/order` with `retries: 0` and the `Idempotency-Key`
   header. An in-flight `Map<orderId, Promise>` serialises concurrent attempts
   for the same order.
4. **Interpret** the result:
   * `201` + `state:"install"` → mark `provisioned`, attach a `cloud_servers`
     row to the buyer, store IPs (null until active) and encrypted credentials,
     debit the wallet.
   * A **terminal** upstream failure (e.g. `out_of_stock`, `insufficient_balance`
     on the *upstream* side, `validation_failed`) → mark `failed` with the code
     and a human-readable message.
   * A **transient** failure (timeout, `5xx`, `429`, network) → leave the order
     `pending`. The poller re-drives it later with the **same** idempotency key;
     the provider replays its stored response instead of selling twice.

The provider caches idempotency keys for 24h. Replaying returns the original
response with `Idempotent-Replayed: true`; sending the same key with a different
body returns `422 idempotency_mismatch`; a still-running key returns
`409 idempotency_in_progress`. All three are handled.

A **sandbox preview** (`POST /store/preview`) sends `"sandbox": true` upstream:
it validates balance and stock and returns live pricing **without ordering
anything** and without needing TOS acceptance. The storefront uses it for the
"Check price" button.

---

## 7. Customer Experience

| Page | Route | What the customer does |
| --- | --- | --- |
| **Server Store** | `/store` | Browse plans grouped by CPU family, pick an OS, name/hostname, optional password & voucher, accept TOS + the immediate-provisioning waiver, preview the price, then order. The result modal shows IPs and root credentials as soon as they exist. |
| **My Cloud Servers** | `/cloud` | Card list of every upstream server on the account with live power state, spec, IP and quick power/console actions. Auto-refreshes. |
| **Server detail** | `/cloud/:id` | Live CPU/RAM/disk meters, uptime, network, firewall, usage history, power (start/stop/restart), noVNC console, SSH line, password reveal & change, auto-renew toggle, renew-now, and owner-only reinstall. |

The stored root password is embedded in the detail page **only for the owner**.
The JSON API never returns credentials unless the caller explicitly requests
`?credentials=1` (owner or staff).

Available CPU families (labels come from the synced plan names, so the exact
models show through): **AMD EPYC 7543, AMD Ryzen 9 5900X / 5950X / 9900X /
9950X, Intel Xeon E5-2697 v4**.

---

## 8. Admin Console

`/admin/reseller` (roles: `admin`, `subadmin`, `operator`; the key-mutation
endpoint is `admin`-only) has six tabs:

* **Provider** — API key, base URL, timeout, low-balance alert, poll/sync
  intervals; selling switches (enabled, storefront, auto-renew default,
  configurator, default markup, checkout terms); live upstream account card
  (balance, reseller tier, rate limits) after a probe.
* **Catalogue & pricing** — every plan with inline retail/renewal/setup editing,
  enable/visible toggles, stock state, margin, an "Apply markup" quick action,
  and a **custom configuration plan** builder (quotes the provider configurator
  live at your markup). OS image table below.
* **Orders** — the queue with filters, per-order failure reason, **retry**
  (re-drives with the same idempotency key) and **cancel**, plus
  **Order for a customer** (choose billing mode).
* **Fleet** — every provisioned server, owner, spec, IP, state, retail vs cost
  vs margin, expiry, and suspend/unsuspend/renew actions.
* **Customer credit** — balances per user, with a **Manage credit** drawer that
  shows the ledger and applies signed adjustments.
* **Upstream API log** — the redacted request/response log for support.

Top-right buttons: **Probe provider**, **Sync catalogue**, **Run reconciliation**.

---

## 9. REST API Reference

All routes are mounted under `/api/v1/reseller` and require an authenticated
principal (session, `Authorization: Bearer`, or `X-API-Key`). Mutations need the
`X-CSRF-Token` header (or `_csrf`) unless authenticated by Bearer/API key.
Staff = role in `admin | subadmin | operator`.

**Customer**
```
GET  /store/catalogue                 enabled plans grouped by CPU family + OS images
POST /store/preview                   sandbox pricing (no order placed)
POST /store/order                     place a real order (201) — needs tos + cancellation
GET  /wallet                          balance + recent ledger
```

**Customer + staff (servers)**
```
GET  /servers                         own servers (staff: ?all=1 or ?userId=)
GET  /servers/:id                     server detail (?credentials=1 to reveal secrets)
POST /servers/:id/power               { action: start | stop | restart }
GET  /servers/:id/status              live power/uptime/cpu/mem/disk
POST /servers/:id/refresh             re-pull from provider (?credentials=1 to reveal)
GET  /servers/:id/console             short-lived noVNC console URL
GET  /servers/:id/statistics          ?period=hour|day|week|month|year
GET  /servers/:id/network             ?rdns=1
GET  /servers/:id/firewall            rules + policy
POST /servers/:id/reinstall           { os, confirm:true }  (owner only, wipes data)
POST /servers/:id/password            { password }          (owner only)
PUT  /servers/:id/autorenew           { autoRenew:bool }     (owner only)
PUT  /servers/:id/name                { name }               (owner only)
GET  /servers/:id/renewal             renewal quote
POST /servers/:id/renew               renew now (owner only)
```

**Orders**
```
GET  /orders                          own orders (staff: ?all=1)
GET  /orders/:id                      owner-or-staff
```

**Staff / admin**
```
GET  /admin/status                    ?probe=0|1  full health + aggregates
GET  /admin/config                    current config (key hint only)
PUT  /admin/config                    admin-only: update config / set-clear API key
POST /admin/test-connection           verify the stored key against GET /account
POST /admin/sync                      sync plans + OS images from provider
GET  /admin/plans                     all plans
PUT  /admin/plans/:id                 edit prices / flags / text
POST /admin/plans/config              create a custom configuration plan
GET  /admin/configurator              ?cpu=  provider configurator limits
GET  /admin/configurator/price        live quote for a custom config
GET  /admin/os-images                 all OS images
GET  /admin/orders                    ?status=&limit=
POST /admin/orders                    place an order for a customer
POST /admin/orders/:id/retry          re-drive a pending/failed order
POST /admin/orders/:id/cancel         cancel a queued order
GET  /admin/servers                   whole fleet
POST /admin/servers/:id/suspend       { suspend:true, reason }
POST /admin/servers/:id/unsuspend
POST /admin/servers/:id/renew
GET  /admin/wallet/:userId            balance + ledger for a user
POST /admin/wallet/:userId/adjust     { amountCents (non-zero), kind, description }
POST /admin/sync-loop                 run one reconciliation pass now
GET  /admin/logs                      ?limit=  redacted upstream API log
```

Errors use a consistent envelope:
`{ "error": "<message>", "code": "<machine_code>", "retryable": bool, "requestId": …, "fields": {…} }`.

---

## 10. Upstream Error Codes & How They Map

The client normalises the provider's `data.code` into friendly messages and
decides whether an order failure is terminal or retryable.

| HTTP | Upstream code | Panel behaviour |
| --- | --- | --- |
| 400 | `invalid_json`, `invalid_idempotency_key` | 400, surfaced verbatim |
| 401 | `unauthorized` | key invalid/revoked — admin alert |
| 402 | `insufficient_balance` | shows `required` vs `available`; **terminal** for the order |
| 403 | `account_inactive`, `owner_only`, `profile_locked`, `reseller_only`, `charge_disabled` | 403 with reason |
| 404 | `not_found` | 404 |
| 409 | `product_busy`, `not_ready`, `already_running`, `already_stopped`, `idempotency_in_progress`, `firewall_conflict` | 409; power `already_*` tolerated during restart |
| 413 | `payload_too_large` | 413 |
| 422 | `validation_failed` (with `data.errors`), `idempotency_mismatch`, `voucher_invalid`, `registry_rejected` | 422; field errors surfaced; **terminal** |
| 429 | `rate_limited` | retryable; honours `Retry-After` |
| 500 | `internal_error` | retryable |
| 502 | `provider_error` | retryable |
| 503 | `out_of_stock` (**terminal**), `unavailable` (retryable) | plan marked out of stock / order retried |

Network/timeout failures become `network_error` (retryable) and leave orders
`pending`.

---

## 11. Background Jobs

`reseller.startBackgroundJobs()` is called during runtime bootstrap (guarded by
`TGVPANEL_DISABLE_BACKGROUND_POLLER` / `TGVPANEL_DISABLE_RESELLER_POLLER`). Two
loops run:

* **Reconciliation** (every `reseller_poll_interval_sec`): re-drive `pending`
  orders with their idempotency keys, refresh server state/power/IPs, detect
  servers that became `active`, and expire/suspend as the provider reports.
* **Catalogue sync** (every `reseller_sync_interval_sec`): refresh plans,
  prices, stock and OS images. Existing hand-set retail prices are **not**
  overwritten; only cost/stock/metadata refresh. Newly discovered plans arrive
  disabled.

Both loops are no-ops when the integration is disabled or unconfigured. You can
trigger either manually from the admin console at any time.

---

## 12. Security Notes

* The **API key** and stored **root credentials** are encrypted with AES-256-GCM
  via the panel's crypto vault (`.tgvpanel-secret`). The key is only ever
  re-shown as a hint.
* **Credentials are never returned by default** from the JSON API; the owner (or
  staff) must pass `?credentials=1`. The server-rendered detail page embeds the
  password for the **owner only**.
* The **noVNC console URL** is short-lived and never stored.
* The **upstream API log** redacts passwords, tokens and console links, and is
  trimmed to the most recent 2000 rows.
* RBAC: customers are scoped to their own servers/orders/wallet; staff routes
  require `admin | subadmin | operator`; setting/clearing the API key requires
  `admin`.

---

## 13. Testing Without a Live Key

The whole feature is verifiable with no provider access:

```bash
npm run build            # tsc → lib/
npx tsc --noEmit         # type gate (must be exit 0)
```

Boot the panel and exercise it:

```bash
TGVPANEL_DISABLE_BACKGROUND_POLLER=true TGVPANEL_DISABLE_RESELLER_POLLER=true node app.js
```

* Without a key: `/store` shows "no plans"; `/store/preview` and `/store/order`
  return `503 reseller_not_configured`; admin probe reports `network_error`.
* Add a **fake** key in the admin console: it is stored encrypted; upstream
  calls fail cleanly with `network_error` and orders stay `pending` (retryable),
  never double-buying.
* Seed plans/OS rows directly and the storefront, cloud list, server detail and
  admin console all render and behave, exercising RBAC, wallet math, order
  queueing, retry/cancel and credential gating end-to-end.

---

## 14. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Storefront shows "no plans" | Integration disabled, no key, or no plans enabled+visible. Sync the catalogue and enable plans. |
| `reseller_not_configured` | No API key. Add it on the Provider tab or via `RESELLER_API_KEY`. |
| `network_error` on every call | Panel can't reach `reseller_api_base_url`. Check outbound HTTPS/DNS/firewall. Orders stay queued and retry automatically. |
| `insufficient_balance` (402) | Your **upstream** prepaid balance is too low. Top it up with the provider. |
| Order stuck `pending` | Transient upstream failure. Click **Run reconciliation** or **retry**; the idempotency key prevents duplicates. |
| `idempotency_mismatch` (422) | Same key reused with a different body — should not happen; each order gets a unique key. |
| Server shows no IP yet | It's still `install`. IPs appear once the provider reports `active` (poller picks this up). |
| Disk stats show "guest agent n/a" | The QEMU guest agent isn't installed inside the VM. Disk metrics need it; CPU/RAM still work. |
| `product_busy` on reinstall/power | The server is mid-operation upstream. Wait and retry. |
| Password change fails | The server must be **running** with the guest agent installed. |

---

*Provider API contract reference: `https://bukkit-hosting.eu/docs`
(OpenAPI 3.0.3, base `https://bukkit-hosting.eu/api/v2`, `Authorization: Bearer bkkt_…`).*
