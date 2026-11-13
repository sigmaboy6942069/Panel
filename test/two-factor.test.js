// Tests for the 2FA service: recovery codes and replay protection.
// Runs against a real in-memory SQLite database.
const assert = require('assert');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const tf = require(path.join(__dirname, '..', 'lib', 'security', 'two-factor.js'));
const vault = require(path.join(__dirname, '..', 'lib', 'security', 'crypto-vault.js'));

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

// Minimal promise-based wrapper matching the shape the service expects.
function wrap(sqliteDb) {
  return {
    async run(sql, params = []) {
      const r = sqliteDb.prepare(sql).run(...params);
      return { changes: Number(r.changes), lastInsertRowid: r.lastInsertRowid };
    },
    async get(sql, params = []) {
      return sqliteDb.prepare(sql).get(...params);
    },
    async all(sql, params = []) {
      return sqliteDb.prepare(sql).all(...params);
    },
  };
}

function freshDb() {
  const raw = new DatabaseSync(':memory:');
  raw.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      two_factor_enabled INTEGER DEFAULT 0,
      two_factor_secret_enc TEXT,
      two_factor_last_step INTEGER
    );
    CREATE TABLE two_factor_recovery_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      code_hash TEXT NOT NULL,
      used_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
  raw.prepare('INSERT INTO users (username) VALUES (?)').run('alice');
  return { raw, db: wrap(raw) };
}

(async () => {
  console.log('two-factor');

  await check('generates 10 recovery codes in xxxx-xxxx form', async () => {
    const { db } = freshDb();
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    assert.strictEqual(codes.length, 10);
    assert.strictEqual(new Set(codes).size, 10, 'duplicate codes generated');
    for (const c of codes) {
      assert.ok(/^[a-z0-9]{4}-[a-z0-9]{4}$/.test(c), `bad code shape: ${c}`);
    }
  });

  await check('recovery codes are stored hashed, never in plaintext', async () => {
    const { raw, db } = freshDb();
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    const rows = raw.prepare('SELECT code_hash FROM two_factor_recovery_codes').all();
    const stored = rows.map((r) => r.code_hash).join(' ');
    for (const c of codes) {
      assert.ok(!stored.includes(c), `plaintext code ${c} found in database`);
      assert.ok(!stored.includes(c.replace('-', '')), 'normalised plaintext found in database');
    }
    assert.ok(rows.every((r) => /^[0-9a-f]{64}$/.test(r.code_hash)), 'hashes are not sha256 hex');
  });

  await check('a recovery code works exactly once', async () => {
    const { db } = freshDb();
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    assert.strictEqual(await tf.consumeRecoveryCode(db, 1, codes[0]), true, 'first use rejected');
    assert.strictEqual(await tf.consumeRecoveryCode(db, 1, codes[0]), false, 'reuse was allowed!');
    assert.strictEqual(await tf.consumeRecoveryCode(db, 1, codes[1]), true, 'other codes broke too');
  });

  await check('recovery code accepts sloppy formatting (spaces, case)', async () => {
    const { db } = freshDb();
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    const messy = ` ${codes[0].toUpperCase()} `;
    assert.strictEqual(await tf.consumeRecoveryCode(db, 1, messy), true);
  });

  await check('a recovery code does not work for another user', async () => {
    const { raw, db } = freshDb();
    raw.prepare('INSERT INTO users (username) VALUES (?)').run('bob');
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    assert.strictEqual(await tf.consumeRecoveryCode(db, 2, codes[0]), false);
  });

  await check('regenerating destroys the previous set', async () => {
    const { db } = freshDb();
    const first = await tf.regenerateRecoveryCodes(db, 1);
    await tf.regenerateRecoveryCodes(db, 1);
    assert.strictEqual(await tf.consumeRecoveryCode(db, 1, first[0]), false, 'old code still valid');
    assert.strictEqual(await tf.countUnusedRecoveryCodes(db, 1), 10);
  });

  await check('counts only unused codes', async () => {
    const { db } = freshDb();
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    await tf.consumeRecoveryCode(db, 1, codes[0]);
    await tf.consumeRecoveryCode(db, 1, codes[1]);
    assert.strictEqual(await tf.countUnusedRecoveryCodes(db, 1), 8);
  });

  await check('empty / garbage recovery codes are rejected', async () => {
    const { db } = freshDb();
    await tf.regenerateRecoveryCodes(db, 1);
    for (const bad of ['', '   ', 'not-a-code', null, undefined, '----']) {
      assert.strictEqual(await tf.consumeRecoveryCode(db, 1, bad), false, `accepted: ${bad}`);
    }
  });

  await check('valid TOTP code is accepted', async () => {
    const { db } = freshDb();
    const secret = vault.generateTotpSecret();
    const code = vault.computeTotpCode(secret);
    const r = await tf.verifyTotpForLogin(db, 1, secret, code);
    assert.strictEqual(r.ok, true, JSON.stringify(r));
  });

  await check('REPLAY: same TOTP code is rejected the second time', async () => {
    const { db } = freshDb();
    const secret = vault.generateTotpSecret();
    const code = vault.computeTotpCode(secret);
    const first = await tf.verifyTotpForLogin(db, 1, secret, code);
    assert.strictEqual(first.ok, true, 'first use failed');
    const replay = await tf.verifyTotpForLogin(db, 1, secret, code);
    assert.strictEqual(replay.ok, false, 'the same code was accepted twice!');
    assert.match(replay.reason, /already been used/i);
  });

  await check('REPLAY: rejection holds across the ±1 clock-skew window', async () => {
    const { db } = freshDb();
    const secret = vault.generateTotpSecret();
    // Accept the *previous* step's code, then try to reuse it.
    const prev = vault.computeTotpCode(secret, -1);
    assert.strictEqual((await tf.verifyTotpForLogin(db, 1, secret, prev)).ok, true);
    // Now the current-step code is still fresh and must work...
    const now = vault.computeTotpCode(secret, 0);
    assert.strictEqual((await tf.verifyTotpForLogin(db, 1, secret, now)).ok, true);
    // ...but the older one must not.
    assert.strictEqual((await tf.verifyTotpForLogin(db, 1, secret, prev)).ok, false);
  });

  await check('wrong TOTP code is rejected', async () => {
    const { db } = freshDb();
    const secret = vault.generateTotpSecret();
    const r = await tf.verifyTotpForLogin(db, 1, secret, '000000');
    assert.strictEqual(r.ok, false);
  });

  await check('malformed TOTP codes are rejected without throwing', async () => {
    const { db } = freshDb();
    const secret = vault.generateTotpSecret();
    for (const bad of ['', '12345', 'abcdef', null, undefined]) {
      const r = await tf.verifyTotpForLogin(db, 1, secret, bad);
      assert.strictEqual(r.ok, false, `accepted: ${bad}`);
    }
  });

  await check('a recovery code can complete login when TOTP is unavailable', async () => {
    const { db } = freshDb();
    const secret = vault.generateTotpSecret();
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    const r = await tf.verifyTotpForLogin(db, 1, secret, codes[3]);
    assert.strictEqual(r.ok, true, 'recovery code did not work at login');
  });

  await check('an already-used recovery code cannot complete login', async () => {
    const { db } = freshDb();
    const secret = vault.generateTotpSecret();
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    await tf.consumeRecoveryCode(db, 1, codes[0]);
    const r = await tf.verifyTotpForLogin(db, 1, secret, codes[0]);
    assert.strictEqual(r.ok, false);
  });

  await check('recovery codes are not interchangeable with TOTP codes', async () => {
    const { db } = freshDb();
    const secret = vault.generateTotpSecret();
    await tf.regenerateRecoveryCodes(db, 1);
    // A 6-digit guess must go down the TOTP path and fail, never the lookup path.
    const r = await tf.verifyTotpForLogin(db, 1, secret, '123456');
    assert.strictEqual(r.ok, false);
  });

  await check('describeTwoFactorState reports enabled + remaining codes', async () => {
    const { raw, db } = freshDb();
    raw.prepare('UPDATE users SET two_factor_enabled = 1, two_factor_secret_enc = ? WHERE id = 1')
      .run('ENC');
    const codes = await tf.regenerateRecoveryCodes(db, 1);
    let s = await tf.describeTwoFactorState(db, 1);
    assert.strictEqual(s.enabled, true);
    assert.strictEqual(s.recoveryCodesRemaining, 10);
    assert.strictEqual(s.hint, null);

    for (let i = 0; i < 8; i++) await tf.consumeRecoveryCode(db, 1, codes[i]);
    s = await tf.describeTwoFactorState(db, 1);
    assert.strictEqual(s.recoveryCodesRemaining, 2);
    assert.match(s.hint, /Only 2 recovery codes left/);

    await tf.consumeRecoveryCode(db, 1, codes[8]);
    await tf.consumeRecoveryCode(db, 1, codes[9]);
    s = await tf.describeTwoFactorState(db, 1);
    assert.match(s.hint, /no recovery codes left/i);
  });

  await check('describeTwoFactorState reports disabled users cleanly', async () => {
    const { db } = freshDb();
    const s = await tf.describeTwoFactorState(db, 1);
    assert.strictEqual(s.enabled, false);
    assert.strictEqual(s.recoveryCodesRemaining, 0);
  });

  await check('admin reset clears secret, flag and every recovery code', async () => {
    const { raw, db } = freshDb();
    raw.prepare('UPDATE users SET two_factor_enabled = 1, two_factor_secret_enc = ?, two_factor_last_step = 42 WHERE id = 1')
      .run('ENC');
    const codes = await tf.regenerateRecoveryCodes(db, 1);

    await tf.resetTwoFactorForUser(db, 1);

    const row = raw.prepare('SELECT * FROM users WHERE id = 1').get();
    assert.strictEqual(row.two_factor_enabled, 0);
    assert.strictEqual(row.two_factor_secret_enc, null);
    assert.strictEqual(row.two_factor_last_step, null);
    assert.strictEqual(raw.prepare('SELECT COUNT(*) n FROM two_factor_recovery_codes').get().n, 0);
    assert.strictEqual(await tf.consumeRecoveryCode(db, 1, codes[0]), false, 'old code survived reset');
  });

  await check('matchTotpStep returns a step number for a good code', async () => {
    const secret = vault.generateTotpSecret();
    const code = vault.computeTotpCode(secret);
    const step = tf.matchTotpStep(secret, code);
    assert.strictEqual(typeof step, 'number');
    assert.strictEqual(step, tf.currentTotpStep());
  });

  await check('matchTotpStep returns null for a bad code', async () => {
    const secret = vault.generateTotpSecret();
    assert.strictEqual(tf.matchTotpStep(secret, '000000'), null);
  });

  console.log(`\n  ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
