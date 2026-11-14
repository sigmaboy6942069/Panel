/**
 * Two-phase node enrolment.
 *
 * Previously a join token was enough on its own: whoever held the token got a
 * working node's credentials. Tokens travel through shell history, terminal
 * scrollback, pasted commands and chat messages, so "holds the token" is a weak
 * claim.
 *
 * Now the flow is:
 *
 *   1. node   POST /api/v1/nodes/join/:token   -> creates a PENDING request
 *   2. admin  opens /admin/nodes, logs in, passes 2FA, presses Approve
 *   3. node   polls GET /api/v1/nodes/join/status/:pendingId -> receives creds
 *
 * Credentials are minted at approval time and handed out exactly once. A request
 * that nobody approves simply expires and is worthless.
 */
import type { UnifiedDatabase } from '../../db/database';
export interface JoinRequestInput {
    rawToken: string;
    endpointUrl?: string;
    ipAddress?: string;
    hostname?: string;
    agentPort?: number;
    tlsCertPem?: string | null;
    verifySsl?: boolean;
    callerIp?: string;
}
export interface PendingJoinRequest {
    pendingId: string;
    status: 'pending';
    nodeId: number;
    nodeName: string;
    expiresAt: string;
    /** Seconds the node should wait between polls. */
    pollIntervalSeconds: number;
    /** Where an admin goes to approve. */
    approvalUrl: string;
}
export interface IssuedJoinCredentials {
    pendingId: string;
    status: 'approved';
    nodeId: number;
    nodeName: string;
    apiKey: string;
    hmacSecret: string;
    controllerUrl: string | null;
    url: string;
}
export declare const PENDING_TTL_MINUTES = 30;
/** How long an approved-but-uncollected credential set survives. */
export declare const COLLECT_TTL_MINUTES = 15;
export declare class NodeJoinApprovalService {
    private db;
    constructor(db: UnifiedDatabase);
    private approvalRequired;
    setApprovalRequired(required: boolean): Promise<void>;
    /** Status of the policy plus how many requests are waiting, for the admin UI. */
    summary(): Promise<{
        requiresApproval: boolean;
        pendingCount: number;
    }>;
    /**
     * Phase 1. Validates the token, records the request, and returns a handle the
     * node can poll. Does NOT issue credentials and does NOT consume the token —
     * consumption happens on approval, so a denied request leaves the token usable
     * for a retry.
     */
    beginJoin(params: JoinRequestInput): Promise<PendingJoinRequest>;
    /**
     * Phase 3. The node collects its credentials. Atomic: the row is flipped to
     * 'collected' inside the same transaction that reads the secrets, so a second
     * poller cannot also receive them.
     */
    collectJoin(pendingId: string): Promise<{
        state: 'pending';
        expiresAt: string;
        pollIntervalSeconds: number;
        approvalUrl: string;
    } | {
        state: 'denied';
        reason: string;
    } | {
        state: 'expired';
    } | {
        state: 'unknown';
    } | {
        state: 'collected';
        credentials: IssuedJoinCredentials;
    }>;
    /** Requests an admin can act on. Secrets are never included. */
    listPending(): Promise<any[]>;
    /**
     * Phase 2. Called only after the admin has authenticated AND satisfied 2FA.
     * Mints the credentials and marks the request approved.
     */
    /**
     * Record an approval decision. Best effort: a missing or locked activity table
     * must never block the decision itself, but a silent failure would make the
     * log untrustworthy, so failures are surfaced on stderr.
     */
    private audit;
    approve(pendingId: string, adminUserId: number): Promise<{
        nodeId: number;
        nodeName: string;
    }>;
    deny(pendingId: string, adminUserId: number, reason: string): Promise<void>;
    /**
     * Whether the caller may see this specific request. An admin who is fully
     * authenticated can open the approve link; anyone else is bounced to login so
     * the link itself never grants anything.
     */
    describe(pendingId: string): Promise<any | null>;
    /** Housekeeping: expire anything past its window. Cheap, runs on read paths. */
    reapExpired(): Promise<void>;
}
