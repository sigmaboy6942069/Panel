/**
 * Tests for two-phase node enrolment.
 *
 * The security property under test: holding a join token is NOT enough to get
 * credentials. Credentials exist only after an admin, authenticated with a
 * second factor, approves. These tests try to break that from every direction.
 */
const assert = require('assert');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const { NodeJoinApprovalService } = require(path.join(ROOT, 'lib/services/nodes/NodeJoinApproval.js'));
const vault = require(path.join(ROOT, 'lib/security/crypto-vault.js'));

let pass = 0, fail = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  PASS ${name}`);
    pass++;
  } catch (e) {
    console.log(`  FAIL ${name}: ${e.message}`);
    fail++;
  }
}

function wrap(raw) {
  return {
    async run(sql, params = []) {
      const r = raw.prepare(sql).run(...params);
      return { changes: Number(r.changes), lastID: r.lastInsertRowid };
    },
    async get(sql, params = []) {
      return raw.prepare(sql).get(...params);
    },
    async all(sql, params = []) {
      return raw.prepare(sql).all(...params);
    },
    async transaction(fn) {
      raw.exec('BEGIN');
      try { await fn(); raw.exec('COMMIT'); }
      catch (e) { raw.exec('ROLLBACK'); throw e; }
    },
  };
}

function freshDb() {
  const raw = new DatabaseSync(':memory:');
  raw.exec(`
    CREATE TABLE settings (setting_key TEXT PRIMARY KEY, setting_value TEXT);
    CREATE TABLE nodes (
      id INTEGER PRIMARY KEY, name TEXT, is_local INTEGER DEFAULT 0,
      hostname TEXT, ip_address TEXT, url TEXT, verify_ssl INTEGER DEFAULT 0,
      circuit_state TEXT, consecutive_failures INTEGER DEFAULT 0,
      last_error TEXT, last_error_at TEXT, updated_at TEXT
    );
    CREATE TABLE node_join_tokens (
      id INTEGER PRIMARY KEY, node_id INTEGER, token_prefix TEXT,
      token_hash TEXT UNIQUE, controller_url TEXT, expires_at TEXT,
      used_at TEXT, used_from_ip TEXT, created_by INTEGER, created_at TEXT
    );
    CREATE TABLE node_credentials (
      node_id INTEGER PRIMARY KEY, api_key_prefix TEXT, api_key_hash TEXT,
      api_key_enc TEXT, hmac_secret_enc TEXT, tls_ca_pem TEXT, rotated_at TEXT
    );
    CREATE TABLE activity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL,
      resource_type TEXT, resource_id TEXT, details TEXT, ip_address TEXT,
      user_agent TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE node_join_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pending_id TEXT UNIQUE NOT NULL, token_id INTEGER NOT NULL,
      node_id INTEGER NOT NULL, endpoint_url TEXT, ip_address TEXT, hostname TEXT,
      agent_port INTEGER, tls_cert_pem TEXT, verify_ssl INTEGER, caller_ip TEXT,
      status TEXT NOT NULL DEFAULT 'pending', requested_at TEXT,
      expires_at TEXT NOT NULL, approved_by INTEGER, approved_at TEXT,
      denied_by INTEGER, denied_at TEXT, deny_reason TEXT,
      issued_api_key_enc TEXT, issued_hmac_enc TEXT
    );
  `);
  raw.exec(`
    INSERT INTO settings VALUES ('node_join_requires_approval', '1');
    INSERT INTO nodes (id, name, is_local, url) VALUES (2, 'edge-01', 0, 'https://203.0.113.50:8443');
  `);
  return { raw, db: wrap(raw) };
}

/** Insert a join token row and return the raw token. */
function issueToken(raw, nodeId = 2, opts = {}) {
  const rawToken = 'tgv_join_' + require('crypto').randomBytes(24).toString('hex');
  const expires = opts.expiresAt || new Date(Date.now() + 30 * 60_000).toISOString();
  raw.prepare(
    `INSERT INTO node_join_tokens (node_id, token_prefix, token_hash, controller_url, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run(nodeId, rawToken.slice(0, 14), vault.hashApiKey(rawToken), 'https://panel.example.com', expires);
  return rawToken;
}

(async () => {
  console.log('node-join-approval');

  // ---------- phase 1 ----------
  await check('a valid token creates a pending request, not credentials', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const rawToken = issueToken(raw);
    const pending = await svc.beginJoin({ rawToken, hostname: 'edge-01', callerIp: '198.51.100.9' });

    assert.strictEqual(pending.status, 'pending');
    assert.ok(pending.pendingId.startsWith('tgv_req_'), 'unexpected handle format');
    assert.strictEqual(pending.nodeId, 2);
    // The response must not contain secrets.
    assert.ok(!JSON.stringify(pending).includes('apiKey'), 'credentials leaked in phase 1');
    assert.ok(!JSON.stringify(pending).includes('hmacSecret'), 'hmac leaked in phase 1');
  });

  await check('phase 1 does NOT consume the token', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const rawToken = issueToken(raw);
    await svc.beginJoin({ rawToken, hostname: 'edge-01' });
    const row = raw.prepare('SELECT used_at FROM node_join_tokens').get();
    assert.strictEqual(row.used_at, null, 'token was burned before approval');
  });

  await check('an invalid token is rejected', async () => {
    const { db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    await assert.rejects(() => svc.beginJoin({ rawToken: 'tgv_join_deadbeef' }), /invalid or unknown/i);
  });

  await check('a malformed token is rejected before any lookup', async () => {
    const { db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    await assert.rejects(() => svc.beginJoin({ rawToken: 'not-a-token' }), /invalid node join token format/i);
  });

  await check('an expired token is rejected', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const rawToken = issueToken(raw, 2, { expiresAt: new Date(Date.now() - 60_000).toISOString() });
    await assert.rejects(() => svc.beginJoin({ rawToken }), /expired/i);
  });

  await check('an already-used token is rejected', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const rawToken = issueToken(raw);
    raw.prepare(`UPDATE node_join_tokens SET used_at = datetime('now')`).run();
    await assert.rejects(() => svc.beginJoin({ rawToken }), /already been redeemed/i);
  });

  await check('the local node cannot be joined', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    raw.prepare(`INSERT INTO nodes (id, name, is_local) VALUES (1, 'localhost', 1)`).run();
    const rawToken = issueToken(raw, 1);
    await assert.rejects(() => svc.beginJoin({ rawToken }), /no longer exists/i);
  });

  await check('a second request supersedes the first for the same node', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const first = await svc.beginJoin({ rawToken: issueToken(raw) });
    const second = await svc.beginJoin({ rawToken: issueToken(raw) });

    const firstRow = raw.prepare('SELECT status FROM node_join_requests WHERE pending_id = ?').get(first.pendingId);
    assert.strictEqual(firstRow.status, 'superseded', 'stale request still actionable');

    const poll = await svc.collectJoin(first.pendingId);
    assert.strictEqual(poll.state, 'expired', 'a superseded request still polls as live');
    assert.ok(second.pendingId);
  });

  // ---------- phase 3 before approval ----------
  await check('polling before approval returns pending and no secrets', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw) });
    const out = await svc.collectJoin(pending.pendingId);
    assert.strictEqual(out.state, 'pending');
    assert.ok(!JSON.stringify(out).includes('apiKey'));
  });

  await check('an unknown handle returns unknown, not an error with detail', async () => {
    const { db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const out = await svc.collectJoin('tgv_req_doesnotexist');
    assert.strictEqual(out.state, 'unknown');
  });

  await check('a malformed handle never touches the database', async () => {
    const { db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    assert.strictEqual((await svc.collectJoin('garbage')).state, 'unknown');
    assert.strictEqual((await svc.collectJoin('')).state, 'unknown');
  });

  // ---------- approval ----------
  await check('approval mints credentials and marks the request approved', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw), hostname: 'edge-01' });
    const out = await svc.approve(pending.pendingId, 1);

    assert.strictEqual(out.nodeId, 2);
    const row = raw.prepare('SELECT status, approved_by, issued_api_key_enc FROM node_join_requests WHERE pending_id = ?').get(pending.pendingId);
    assert.strictEqual(row.status, 'approved');
    assert.strictEqual(row.approved_by, 1);
    assert.ok(row.issued_api_key_enc, 'no credentials were minted');
    // Stored encrypted, never plaintext.
    assert.ok(!row.issued_api_key_enc.startsWith('tgv_node_'), 'api key stored in plaintext');
  });

  await check('credentials are issued exactly once', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw) });
    await svc.approve(pending.pendingId, 1);

    const first = await svc.collectJoin(pending.pendingId);
    assert.strictEqual(first.state, 'collected');
    assert.ok(first.credentials.apiKey.startsWith('tgv_node_'));
    assert.ok(first.credentials.hmacSecret.length >= 32);

    const second = await svc.collectJoin(pending.pendingId);
    assert.strictEqual(second.state, 'expired', 'credentials were issued twice!');
  });

  await check('collecting burns the underlying join token', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const rawToken = issueToken(raw);
    const pending = await svc.beginJoin({ rawToken });
    await svc.approve(pending.pendingId, 1);
    await svc.collectJoin(pending.pendingId);

    const row = raw.prepare('SELECT used_at FROM node_join_tokens').get();
    assert.ok(row.used_at, 'token still usable after credentials were handed out');
    // And it cannot start a new request.
    await assert.rejects(() => svc.beginJoin({ rawToken }), /already been redeemed/i);
  });

  await check('approving twice is refused', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw) });
    await svc.approve(pending.pendingId, 1);
    await assert.rejects(() => svc.approve(pending.pendingId, 1), /already been approved/i);
  });

  await check('an expired request cannot be approved', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw) });
    raw.prepare(`UPDATE node_join_requests SET expires_at = datetime('now','-1 minute')`).run();
    await assert.rejects(() => svc.approve(pending.pendingId, 1), /expired/i);
  });

  // ---------- denial ----------
  await check('a denied request reports the reason and issues nothing', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw) });
    await svc.deny(pending.pendingId, 1, 'unrecognised machine');

    const out = await svc.collectJoin(pending.pendingId);
    assert.strictEqual(out.state, 'denied');
    assert.match(out.reason, /unrecognised machine/);

    const row = raw.prepare('SELECT issued_api_key_enc FROM node_join_requests WHERE pending_id = ?').get(pending.pendingId);
    assert.strictEqual(row.issued_api_key_enc, null, 'credentials were minted for a denied request');
  });

  await check('a denied token stays usable for a retry', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const rawToken = issueToken(raw);
    const pending = await svc.beginJoin({ rawToken });
    await svc.deny(pending.pendingId, 1, 'try again');

    // Denial should not burn the token, so a corrected retry works.
    const retry = await svc.beginJoin({ rawToken });
    assert.ok(retry.pendingId);
    assert.notStrictEqual(retry.pendingId, pending.pendingId);
  });

  await check('denying an already-decided request is refused', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw) });
    await svc.approve(pending.pendingId, 1);
    await assert.rejects(() => svc.deny(pending.pendingId, 1, 'too late'), /no longer pending/i);
  });

  // ---------- policy ----------
  await check('the policy defaults to requiring approval', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    assert.strictEqual((await svc.summary()).requiresApproval, true);
  });

  await check('the policy can be turned off, and then beginJoin refuses', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    await svc.setApprovalRequired(false);
    assert.strictEqual((await svc.summary()).requiresApproval, false);
    await assert.rejects(
      () => svc.beginJoin({ rawToken: issueToken(raw) }),
      /does not require join approval/i
    );
    // And back on again.
    await svc.setApprovalRequired(true);
    assert.strictEqual((await svc.summary()).requiresApproval, true);
  });

  await check('a missing policy row fails safe (approval required)', async () => {
    const { raw, db } = freshDb();
    raw.prepare(`DELETE FROM settings WHERE setting_key = 'node_join_requires_approval'`).run();
    const svc = new NodeJoinApprovalService(db);
    assert.strictEqual((await svc.summary()).requiresApproval, true, 'a missing policy disabled approval');
  });

  // ---------- listing ----------
  await check('pending list shows no secrets', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    await svc.beginJoin({ rawToken: issueToken(raw), hostname: 'edge-01', callerIp: '198.51.100.9' });
    const list = await svc.listPending();
    assert.strictEqual(list.length, 1);
    const blob = JSON.stringify(list);
    assert.ok(!blob.includes('apiKey'), 'list leaked a credential');
    assert.ok(!blob.includes('hmacSecret'), 'list leaked an hmac');
    assert.strictEqual(list[0].node_name, 'edge-01');
  });

  await check('approved requests disappear from the pending list', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const p = await svc.beginJoin({ rawToken: issueToken(raw) });
    await svc.approve(p.pendingId, 1);
    assert.strictEqual((await svc.listPending()).length, 0);
  });

  await check('reaping expires stale pending requests', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const p = await svc.beginJoin({ rawToken: issueToken(raw) });
    raw.prepare(`UPDATE node_join_requests SET expires_at = datetime('now','-1 minute')`).run();
    await svc.reapExpired();
    const row = raw.prepare('SELECT status FROM node_join_requests WHERE pending_id = ?').get(p.pendingId);
    assert.strictEqual(row.status, 'expired');
  });

  await check('reusing an existing node keeps its credentials stable', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    raw.prepare(
      `INSERT INTO node_credentials (node_id, api_key_enc, hmac_secret_enc) VALUES (2, ?, ?)`
    ).run(vault.encryptSecret('tgv_node_existing_key'), vault.encryptSecret('existing_hmac_value_here'));

    const pending = await svc.beginJoin({ rawToken: issueToken(raw) });
    await svc.approve(pending.pendingId, 1);
    const out = await svc.collectJoin(pending.pendingId);

    assert.strictEqual(out.state, 'collected');
    assert.strictEqual(out.credentials.apiKey, 'tgv_node_existing_key', 'a re-approval rotated a working key');
  });

  // ---------- audit ----------
  await check('approval writes an audit entry naming the admin and caller', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw), hostname: 'edge-01', callerIp: '198.51.100.9' });
    await svc.approve(pending.pendingId, 7);

    const log = raw.prepare(`SELECT * FROM activity_logs WHERE action = 'node.join.approved'`).get();
    assert.ok(log, 'no audit entry was written for an approval');
    assert.strictEqual(log.user_id, 7, 'audit entry does not name the approving admin');
    const details = JSON.parse(log.details);
    assert.strictEqual(details.node_name, 'edge-01');
    assert.strictEqual(details.caller_ip, '198.51.100.9');
  });

  await check('denial writes an audit entry with the reason', async () => {
    const { raw, db } = freshDb();
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw), hostname: 'edge-01' });
    await svc.deny(pending.pendingId, 7, 'unrecognised machine');

    const log = raw.prepare(`SELECT * FROM activity_logs WHERE action = 'node.join.denied'`).get();
    assert.ok(log, 'no audit entry for a denial');
    assert.match(JSON.parse(log.details).reason, /unrecognised/);
  });

  await check('a broken audit table does not block an approval', async () => {
    const { raw, db } = freshDb();
    raw.exec('DROP TABLE activity_logs');
    const svc = new NodeJoinApprovalService(db);
    const pending = await svc.beginJoin({ rawToken: issueToken(raw) });
    const out = await svc.approve(pending.pendingId, 1);
    assert.strictEqual(out.nodeId, 2, 'audit failure blocked a legitimate approval');
  });

  console.log(`\n  ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
