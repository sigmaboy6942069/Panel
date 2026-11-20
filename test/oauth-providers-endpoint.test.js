/**
 * Regression: the login page must be told about a provider configured through
 * its own Settings form.
 *
 * The Discord button is revealed from /api/oauth/providers. Enabling Discord in
 * the dedicated "Discord Authentication" section writes the legacy
 * `discord_settings` table, which that endpoint used to ignore -- so the config
 * was valid, /auth/discord worked, and the button never appeared. This boots the
 * real app (no listener) and checks the endpoint against real rows.
 */
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

const ROOT = path.join(__dirname, '..');

// Isolate the database before app.js is required: it reads these at boot.
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'oauth-providers-'));
process.env.TGVPANEL_DATA_DIR = DATA_DIR;
process.env.TGVPANEL_NO_LISTEN = '1';
process.env.TGVPANEL_DISABLE_RESELLER_POLLER = 'true';
process.env.PORT = '0';

// The panel's DB layer talks to sqlite3 with callbacks; the sandbox has no
// native bindings, so route it to node:sqlite instead of skipping the test.
require(path.join(ROOT, 'test', 'helpers', 'sqlite3-shim.js'));

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

/**
 * Boot the real app on an ephemeral port and talk to it over HTTP. Going
 * through the real router is the point: the bug was in a route, not a helper.
 */
function listen(app) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

function httpGet(port, urlPath) {
  const http = require('http');
  return new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port, path: urlPath, headers: { accept: 'application/json' } }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, body, location: res.headers.location || '' }));
    }).on('error', (e) => resolve({ status: 0, body: 'ERR ' + e.message, location: '' }));
  });
}

(async () => {
  console.log('oauth-providers-endpoint');

  // Boot the panel. It is started with TGVPANEL_NO_LISTEN=1 by the app itself,
  // but the Express app is still a full router, so listen on our own port.
  const app = require(path.join(ROOT, 'app.js'));
  const server = await listen(app);
  const port = server.address().port;

  // Migrations run asynchronously after require; wait for the tables to exist.
  const { DatabaseSync } = require('node:sqlite');
  const dbPath = path.join(DATA_DIR, 'tgvpanel.db');
  let raw = null;
  for (let i = 0; i < 60; i++) {
    try {
      raw = new DatabaseSync(dbPath);
      raw.prepare('SELECT 1 FROM discord_settings LIMIT 1').get();
      raw.prepare('SELECT 1 FROM oauth_provider_settings LIMIT 1').get();
      break;
    } catch {
      try { raw && raw.close(); } catch {}
      raw = null;
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  if (!raw) {
    console.log('  SKIP database never became ready');
    process.exit(0);
  }

  // Small promise wrappers so the tests read clearly.
  const db = {
    run: (sql, params = []) => raw.prepare(sql).run(...params),
    all: (sql, params = []) => raw.prepare(sql).all(...params),
  };

  const clearProviders = async () => {
    await db.run('DELETE FROM oauth_provider_settings');
    await db.run('DELETE FROM discord_settings');
  };

  // ---------- the bug ----------
  await check('Discord enabled only in discord_settings is advertised', async () => {
    await clearProviders();
    await db.run(
      `INSERT INTO discord_settings (enabled, client_id, client_secret, redirect_uri)
       VALUES (1, '111222333', 'dsecret', 'https://panel.example.com/auth/discord/callback')`
    );

    const res = await httpGet(port, '/api/oauth/providers');
    const body = JSON.parse(res.body);
    assert.ok(
      body.providers.includes('discord'),
      'login page was told no providers, so the Discord button stays hidden — this is the reported bug'
    );
  });

  await check('and /auth/discord agrees, so the button is not a dead end', async () => {
    const res = await httpGet(port, '/auth/discord');
    assert.strictEqual(res.status, 302, `expected a redirect to Discord, got ${res.status}`);
    assert.match(String(res.location || ''), /discord\.com/);
  });

  // ---------- disabled means hidden ----------
  await check('a disabled discord_settings row is not advertised', async () => {
    await clearProviders();
    await db.run(
      `INSERT INTO discord_settings (enabled, client_id, client_secret, redirect_uri)
       VALUES (0, '111222333', 'dsecret', '')`
    );
    const res = await httpGet(port, '/api/oauth/providers');
    assert.ok(!JSON.parse(res.body).providers.includes('discord'), 'a disabled provider was advertised');
  });

  await check('a row with no client secret is not advertised', async () => {
    await clearProviders();
    await db.run(`INSERT INTO discord_settings (enabled, client_id, client_secret) VALUES (1, 'abc', '')`);
    const res = await httpGet(port, '/api/oauth/providers');
    assert.ok(!JSON.parse(res.body).providers.includes('discord'), 'a credential-less provider was advertised');
  });

  // ---------- the generic table still works ----------
  await check('a provider in oauth_provider_settings is still advertised', async () => {
    await clearProviders();
    const vault = require(path.join(ROOT, 'lib', 'security', 'crypto-vault.js'));
    await db.run(
      `INSERT INTO oauth_provider_settings (provider, enabled, client_id, client_secret_enc)
       VALUES ('google', 1, 'g-id', ?)`,
      [vault.encryptSecret('g-secret')]
    );
    const res = await httpGet(port, '/api/oauth/providers');
    assert.ok(JSON.parse(res.body).providers.includes('google'), 'Google stopped working');
  });

  await check('Discord is not double-reported when both tables agree', async () => {
    await clearProviders();
    const vault = require(path.join(ROOT, 'lib', 'security', 'crypto-vault.js'));
    await db.run(
      `INSERT INTO oauth_provider_settings (provider, enabled, client_id, client_secret_enc)
       VALUES ('discord', 1, 'd-id', ?)`,
      [vault.encryptSecret('d-secret')]
    );
    await db.run(`INSERT INTO discord_settings (enabled, client_id, client_secret) VALUES (1, 'x', 'y')`);
    const res = await httpGet(port, '/api/oauth/providers');
    const list = JSON.parse(res.body).providers;
    assert.strictEqual(list.filter((p) => p === 'discord').length, 1, 'discord listed twice');
  });

  // ---------- no credential ever leaks ----------
  await check('the endpoint never returns a client id or secret', async () => {
    await clearProviders();
    await db.run(
      `INSERT INTO discord_settings (enabled, client_id, client_secret)
       VALUES (1, 'SUPER-SECRET-ID', 'SUPER-SECRET-VALUE')`
    );
    const res = await httpGet(port, '/api/oauth/providers');
    assert.ok(!res.body.includes('SUPER-SECRET'), 'the public endpoint leaked a credential');
  });

  await clearProviders();

  console.log(`\n  ${pass} passed, ${fail} failed`);
  try { server.close(); } catch {}
  try { fs.rmSync(DATA_DIR, { recursive: true, force: true }); } catch {}
  process.exit(fail ? 1 : 0);
})();
