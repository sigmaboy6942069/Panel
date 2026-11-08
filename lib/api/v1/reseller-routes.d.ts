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
import { Router } from 'express';
import { ResellerService } from '../../services/reseller/ResellerService';
export declare function createResellerApiRouter(svc: ResellerService): Router;
