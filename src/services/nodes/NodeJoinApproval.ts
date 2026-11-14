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

import crypto from 'crypto';
import { encryptSecret, decryptSecret, hashApiKey } from '../../security/crypto-vault';
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

export const PENDING_TTL_MINUTES = 30;
/** How long an approved-but-uncollected credential set survives. */
export const COLLECT_TTL_MINUTES = 15;

export class NodeJoinApprovalService {
  constructor(private db: UnifiedDatabase) {}

  private async approvalRequired(): Promise<boolean> {
    const row = await this.db.get<{ setting_value: string }>(
      `SELECT setting_value FROM settings WHERE setting_key = 'node_join_requires_approval'`
    );
    // Default to requiring approval if the setting is somehow missing: fail safe.
    return String(row?.setting_value ?? '1') === '1';
  }

  public async setApprovalRequired(required: boolean): Promise<void> {
    await this.db.run(
      `INSERT INTO settings (setting_key, setting_value) VALUES ('node_join_requires_approval', ?)
       ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value`,
      [required ? '1' : '0']
    );
  }

  /** Status of the policy plus how many requests are waiting, for the admin UI. */
  public async summary(): Promise<{ requiresApproval: boolean; pendingCount: number }> {
    const pending = await this.db.get<{ n: number }>(
      `SELECT COUNT(*) AS n FROM node_join_requests
       WHERE status = 'pending' AND expires_at > datetime('now')`
    );
    return {
      requiresApproval: await this.approvalRequired(),
      pendingCount: Number(pending?.n || 0),
    };
  }

  /**
   * Phase 1. Validates the token, records the request, and returns a handle the
   * node can poll. Does NOT issue credentials and does NOT consume the token —
   * consumption happens on approval, so a denied request leaves the token usable
   * for a retry.
   */
  public async beginJoin(params: JoinRequestInput): Promise<PendingJoinRequest> {
    const cleanToken = String(params.rawToken || '').trim();
    if (!cleanToken.startsWith('tgv_join_')) {
      throw new Error('Invalid node join token format.');
    }

    const row = await this.db.get<{
      id: number;
      node_id: number;
      controller_url: string | null;
      expires_at: string;
      used_at: string | null;
    }>(`SELECT * FROM node_join_tokens WHERE token_hash = ?`, [hashApiKey(cleanToken)]);

    if (!row) throw new Error('Join token is invalid or unknown.');
    if (row.used_at) {
      throw new Error('This join token has already been redeemed. Generate a new one in the Panel.');
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      throw new Error('Join token has expired. Generate a fresh one in the Panel.');
    }

    const node = await this.db.get<{ id: number; name: string; is_local: number }>(
      `SELECT id, name, is_local FROM nodes WHERE id = ?`,
      [row.node_id]
    );
    if (!node || node.is_local) throw new Error('Target remote node no longer exists.');

    // If approval is switched off the caller should use the direct path instead.
    if (!(await this.approvalRequired())) {
      throw new Error('This panel does not require join approval. Use the direct join endpoint.');
    }

    // One live request per node: a retry should not leave a queue of stale rows
    // that an admin might approve by accident.
    await this.db.run(
      `UPDATE node_join_requests SET status = 'superseded'
       WHERE node_id = ? AND status = 'pending'`,
      [node.id]
    );

    const pendingId = `tgv_req_${crypto.randomBytes(24).toString('hex')}`;
    const expiresAt = new Date(Date.now() + PENDING_TTL_MINUTES * 60_000).toISOString();

    await this.db.run(
      `INSERT INTO node_join_requests
         (pending_id, token_id, node_id, endpoint_url, ip_address, hostname,
          agent_port, tls_cert_pem, verify_ssl, caller_ip, status, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
      [
        pendingId,
        row.id,
        node.id,
        params.endpointUrl || null,
        params.ipAddress || null,
        params.hostname || null,
        params.agentPort || null,
        params.tlsCertPem || null,
        params.verifySsl === undefined ? null : params.verifySsl ? 1 : 0,
        (params.callerIp || '').replace(/^::ffff:/, '') || null,
        expiresAt,
      ]
    );

    // Deliberately not the token: if this handle leaks, it only lets someone
    // watch a request they cannot approve or complete.
    return {
      pendingId,
      status: 'pending',
      nodeId: node.id,
      nodeName: node.name,
      expiresAt,
      pollIntervalSeconds: 3,
      approvalUrl: `/admin/nodes?approve=${encodeURIComponent(pendingId)}`,
    };
  }

  /**
   * Phase 3. The node collects its credentials. Atomic: the row is flipped to
   * 'collected' inside the same transaction that reads the secrets, so a second
   * poller cannot also receive them.
   */
  public async collectJoin(pendingId: string): Promise<
    | { state: 'pending'; expiresAt: string; pollIntervalSeconds: number; approvalUrl: string }
    | { state: 'denied'; reason: string }
    | { state: 'expired' }
    | { state: 'unknown' }
    | { state: 'collected'; credentials: IssuedJoinCredentials }
  > {
    const auth = String(pendingId || '').trim();
    if (!auth.startsWith('tgv_req_')) return { state: 'unknown' };

    const row = await this.db.get<any>(
      `SELECT * FROM node_join_requests WHERE pending_id = ?`,
      [auth]
    );
    if (!row) return { state: 'unknown' };

    if (row.status === 'denied') {
      return { state: 'denied', reason: row.deny_reason || 'The request was denied by an administrator.' };
    }
    if (row.status === 'collected') {
      return { state: 'expired' };
    }
    if (row.status === 'superseded') {
      return { state: 'expired' };
    }

    if (row.status === 'pending') {
      const expired = new Date(row.expires_at).getTime() <= Date.now();
      if (expired) {
        await this.db.run(
          `UPDATE node_join_requests SET status = 'expired'
           WHERE id = ? AND status = 'pending'`,
          [row.id]
        );
        return { state: 'expired' };
      }
      return {
        state: 'pending',
        expiresAt: row.expires_at,
        pollIntervalSeconds: 3,
        approvalUrl: `/admin/nodes?approve=${encodeURIComponent(row.pending_id)}`,
      };
    }

    if (row.status !== 'approved') return { state: 'unknown' };

    // Approved: hand the credentials over exactly once.
    const approvedAt = row.approved_at ? new Date(row.approved_at).getTime() : 0;
    if (approvedAt && Date.now() - approvedAt > COLLECT_TTL_MINUTES * 60_000) {
      await this.db.run(
        `UPDATE node_join_requests SET status = 'expired' WHERE id = ? AND status = 'approved'`,
        [row.id]
      );
      return { state: 'expired' };
    }

    const apiKey = row.issued_api_key_enc ? decryptSecret(row.issued_api_key_enc) : '';
    const hmacSecret = row.issued_hmac_enc ? decryptSecret(row.issued_hmac_enc) : '';
    if (!apiKey || !hmacSecret) return { state: 'expired' };

    // Claim it atomically before returning anything.
    const claim = await this.db.run(
      `UPDATE node_join_requests SET status = 'collected'
       WHERE id = ? AND status = 'approved'`,
      [row.id]
    );
    if (Number((claim as any)?.changes || 0) !== 1) return { state: 'expired' };

    // Burn the token now, not at request time.
    await this.db.run(
      `UPDATE node_join_tokens SET used_at = datetime('now'), used_from_ip = ?
       WHERE id = ? AND used_at IS NULL`,
      [row.caller_ip || null, row.token_id]
    );

    const node = await this.db.get<{ name: string; url: string }>(
      `SELECT name, url FROM nodes WHERE id = ?`,
      [row.node_id]
    );

    return {
      state: 'collected',
      credentials: {
        pendingId: auth,
        status: 'approved',
        nodeId: row.node_id,
        nodeName: node?.name || `node-${row.node_id}`,
        apiKey,
        hmacSecret,
        controllerUrl: null,
        url: node?.url || row.endpoint_url || '',
      },
    };
  }

  /** Requests an admin can act on. Secrets are never included. */
  public async listPending(): Promise<any[]> {
    const rows = await this.db.all<any>(
      `SELECT r.id, r.pending_id, r.node_id, r.hostname, r.ip_address, r.endpoint_url,
              r.agent_port, r.caller_ip, r.requested_at, r.expires_at,
              n.name AS node_name,
              CASE WHEN r.tls_cert_pem IS NOT NULL THEN 1 ELSE 0 END AS has_cert
       FROM node_join_requests r
       LEFT JOIN nodes n ON n.id = r.node_id
       WHERE r.status = 'pending' AND r.expires_at > datetime('now')
       ORDER BY r.requested_at DESC`
    );
    return rows;
  }

  /**
   * Phase 2. Called only after the admin has authenticated AND satisfied 2FA.
   * Mints the credentials and marks the request approved.
   */
  /**
   * Record an approval decision. Best effort: a missing or locked activity table
   * must never block the decision itself, but a silent failure would make the
   * log untrustworthy, so failures are surfaced on stderr.
   */
  private async audit(
    adminUserId: number,
    action: string,
    resourceId: string,
    details: Record<string, unknown>,
    ipAddress?: string
  ): Promise<void> {
    try {
      await this.db.run(
        `INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details, ip_address)
         VALUES (?, ?, 'node_join_request', ?, ?, ?)`,
        [
          adminUserId,
          action,
          resourceId,
          JSON.stringify(details),
          ipAddress || null,
        ]
      );
    } catch (e: any) {
      console.error('[node-join] failed to write audit entry:', e?.message || e);
    }
  }

  public async approve(
    pendingId: string,
    adminUserId: number
  ): Promise<{ nodeId: number; nodeName: string }> {
    const row = await this.db.get<any>(
      `SELECT * FROM node_join_requests WHERE pending_id = ?`,
      [String(pendingId || '').trim()]
    );
    if (!row) throw new Error('Join request not found.');
    if (row.status === 'approved' || row.status === 'collected') {
      throw new Error('This request has already been approved.');
    }
    if (row.status !== 'pending') {
      throw new Error(`This request is ${row.status} and cannot be approved.`);
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      throw new Error('This request has expired. Ask the node operator to run the command again.');
    }

    const node = await this.db.get<{ id: number; name: string; url: string }>(
      `SELECT id, name, url FROM nodes WHERE id = ?`,
      [row.node_id]
    );
    if (!node) throw new Error('The node this request targets no longer exists.');

    // Reuse the node's existing credentials when it already has them, so
    // re-approving a rebuilt machine does not invalidate a working agent.
    const creds = await this.db.get<{ api_key_enc: string; hmac_secret_enc: string }>(
      `SELECT api_key_enc, hmac_secret_enc FROM node_credentials WHERE node_id = ?`,
      [node.id]
    );

    let apiKey = creds?.api_key_enc ? decryptSecret(creds.api_key_enc) : '';
    let hmacSecret = creds?.hmac_secret_enc ? decryptSecret(creds.hmac_secret_enc) : '';

    if (!apiKey || !hmacSecret) {
      apiKey = `tgv_node_${crypto.randomBytes(24).toString('hex')}`;
      hmacSecret = crypto.randomBytes(32).toString('hex');
      const keyHash = hashApiKey(apiKey);
      await this.db.run(
        `INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc, rotated_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(node_id) DO UPDATE SET
           api_key_prefix = excluded.api_key_prefix,
           api_key_hash = excluded.api_key_hash,
           api_key_enc = excluded.api_key_enc,
           hmac_secret_enc = excluded.hmac_secret_enc,
           rotated_at = datetime('now')`,
        [node.id, apiKey.slice(0, 14), keyHash, encryptSecret(apiKey), encryptSecret(hmacSecret)]
      );
    }

    await this.db.transaction(async () => {
      await this.db.run(
        `UPDATE node_join_requests
         SET status = 'approved', approved_by = ?, approved_at = datetime('now'),
             issued_api_key_enc = ?, issued_hmac_enc = ?
         WHERE id = ? AND status = 'pending'`,
        [adminUserId, encryptSecret(apiKey), encryptSecret(hmacSecret), row.id]
      );

      // Stamp the node with what the request reported, so it is correct even
      // before the node collects.
      await this.db.run(
        `UPDATE nodes SET
           hostname = COALESCE(?, hostname),
           ip_address = COALESCE(?, ip_address),
           circuit_state = 'closed',
           consecutive_failures = 0,
           last_error = NULL,
           last_error_at = NULL,
           updated_at = datetime('now')
         WHERE id = ?`,
        [row.hostname || null, row.ip_address || null, node.id]
      );

      if (row.tls_cert_pem) {
        await this.db.run(
          `UPDATE node_credentials SET tls_ca_pem = ? WHERE node_id = ?`,
          [row.tls_cert_pem, node.id]
        );
      }
    });

    await this.audit(adminUserId, 'node.join.approved', row.pending_id, {
      node_id: node.id,
      node_name: node.name,
      hostname: row.hostname,
      ip_address: row.ip_address,
      agent_port: row.agent_port,
      caller_ip: row.caller_ip,
      tls_pinned: Boolean(row.tls_cert_pem),
    });

    return { nodeId: node.id, nodeName: node.name };
  }

  public async deny(pendingId: string, adminUserId: number, reason: string): Promise<void> {
    const result = await this.db.run(
      `UPDATE node_join_requests
       SET status = 'denied', denied_by = ?, denied_at = datetime('now'), deny_reason = ?
       WHERE pending_id = ? AND status = 'pending'`,
      [adminUserId, String(reason || 'Denied by administrator'), String(pendingId || '').trim()]
    );
    if (Number((result as any)?.changes || 0) !== 1) {
      throw new Error('That request is no longer pending.');
    }

    const row = await this.db.get<any>(
      `SELECT node_id, hostname, ip_address, caller_ip FROM node_join_requests WHERE pending_id = ?`,
      [String(pendingId || '').trim()]
    );
    await this.audit(adminUserId, 'node.join.denied', String(pendingId || '').trim(), {
      node_id: row?.node_id,
      hostname: row?.hostname,
      ip_address: row?.ip_address,
      caller_ip: row?.caller_ip,
      reason: String(reason || 'Denied by administrator'),
    });
  }

  /**
   * Whether the caller may see this specific request. An admin who is fully
   * authenticated can open the approve link; anyone else is bounced to login so
   * the link itself never grants anything.
   */
  public async describe(pendingId: string): Promise<any | null> {
    return this.db.get<any>(
      `SELECT r.*, n.name AS node_name
       FROM node_join_requests r
       LEFT JOIN nodes n ON n.id = r.node_id
       WHERE r.pending_id = ?`,
      [String(pendingId || '').trim()]
    );
  }

  /** Housekeeping: expire anything past its window. Cheap, runs on read paths. */
  public async reapExpired(): Promise<void> {
    await this.db.run(
      `UPDATE node_join_requests SET status = 'expired'
       WHERE status = 'pending' AND expires_at <= datetime('now')`
    );
    await this.db.run(
      `UPDATE node_join_requests SET status = 'expired'
       WHERE status = 'approved'
         AND approved_at <= datetime('now', '-${COLLECT_TTL_MINUTES} minutes')`
    );
  }
}
