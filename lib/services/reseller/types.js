"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
