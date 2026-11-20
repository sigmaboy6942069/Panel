/**
 * Regression: Discord login used to be implemented twice.
 *
 * There was a legacy stack (its own `discord_settings` table, its own
 * /api/discord-auth-url endpoint, its own callback) and a generic OAuth stack
 * (/auth/:provider reading `oauth_provider_settings`). The login button called
 * the legacy one while the settings page the user was told to use wrote the
 * generic one, so configuring Discord produced a button that failed with
 * "Discord authentication setup incomplete".
 *
 * These tests pin the single path that replaced both.
 */
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'discord-'));

process.env.TGVPANEL_DATA_DIR = DATA_DIR;
process.env.TGVPANEL_NO_LISTEN = '1';
process.env.TGVPANEL_DISABLE_RESELLER_POLLER = 'true';
process.env.TGVPANEL_PUBLIC_URL = 'https://panel.example.com';
process.env.PORT = '0';

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
  console.log('discord-login-unified');

  const app = require(path.join(ROOT, 'app.js'));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = server.address().port;

  const { DatabaseSync } = require('node:sqlite');
  const dbPath = path.join(DATA_DIR, 'tgvpanel.db');
  let raw = null;
  for (let i = 0; i < 60; i++) {
    try {
      raw = new DatabaseSync(dbPath);
      raw.prepare('SELECT 1 FROM oauth_provider_settings LIMIT 1').get();
      raw.prepare('SELECT 1 FROM discord_settings LIMIT 1').get();
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

  const vault = require(path.join(ROOT, 'lib', 'security', 'crypto-vault.js'));
  const clear = () => {
    raw.prepare('DELETE FROM oauth_provider_settings').run();
    raw.prepare('DELETE FROM discord_settings').run();
  };
  const seedGeneric = () => {
    raw.prepare(
      `INSERT INTO oauth_provider_settings (provider, enabled, client_id, client_secret_enc, redirect_uri)
       VALUES ('discord', 1, 'generic-id', ?, 'https://panel.example.com/auth/discord/callback')`
    ).run(vault.encryptSecret('generic-secret'));
  };
  const seedLegacy = () => {
    raw.prepare(
      `INSERT INTO discord_settings (enabled, client_id, client_secret, redirect_uri)
       VALUES (1, 'legacy-id', 'legacy-secret', 'https://panel.example.com/auth/discord/callback')`
    ).run();
  };

  // ---------- the deleted legacy endpoints stay deleted ----------
  await check('/api/discord-auth-url is gone (it caused the failure)', async () => {
    const res = await httpGet(port, '/api/discord-auth-url');
    assert.strictEqual(res.status, 404, 'the legacy endpoint still exists and can still fail at runtime');
  });

  await check('/api/discord-enabled is gone', async () => {
    const res = await httpGet(port, '/api/discord-enabled');
    assert.strictEqual(res.status, 404);
  });

  await check('/api/admin/discord-settings is gone (duplicate settings form)', async () => {
    const res = await httpGet(port, '/api/admin/discord-settings');
    assert.ok(res.status === 404 || res.status === 401 || res.status === 302,
      `legacy settings endpoint still served (${res.status})`);
  });

  await check('the login page no longer calls any removed endpoint', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'views', 'users', 'login.ejs'), 'utf8');
    for (const dead of ['/api/discord-auth-url', '/api/discord-enabled', 'loginWithDiscord', 'loadDiscordSettings']) {
      assert.ok(!src.includes(dead), `login page still references ${dead}`);
    }
  });

  // ---------- one button, one route ----------
  await check('the Discord button navigates to /auth/discord like Google does', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'views', 'users', 'login.ejs'), 'utf8');
    const btn = src.split('\n').find((l) => l.includes('id="discordLoginBtn"')) || '';
    assert.ok(btn.includes("/auth/discord"), 'the button does not use the shared provider route');
    assert.ok(!btn.includes('loginWithDiscord'), 'the button still calls the deleted AJAX handler');
  });

  // ---------- configured the supported way, it works end to end ----------
  await check('Discord configured in the generic card is advertised', async () => {
    clear(); seedGeneric();
    const res = await httpGet(port, '/api/oauth/providers');
    assert.ok(JSON.parse(res.body).providers.includes('discord'));
  });

  await check('and /auth/discord redirects to Discord (not an error page)', async () => {
    clear(); seedGeneric();
    const res = await httpGet(port, '/auth/discord');
    assert.strictEqual(res.status, 302, `got ${res.status} — this is the "setup incomplete" path`);
    assert.match(res.location, /discord\.com\/api\/oauth2\/authorize/);
    assert.match(res.location, /client_id=generic-id/);
    assert.match(res.location, /code_challenge_method=S256/, 'PKCE missing');
    assert.match(res.location, /state=[\w-]{10,}/, 'state missing');
  });

  await check('the authorize URL carries the configured redirect_uri', async () => {
    clear(); seedGeneric();
    const res = await httpGet(port, '/auth/discord');
    assert.match(res.location, /redirect_uri=https%3A%2F%2Fpanel\.example\.com%2Fauth%2Fdiscord%2Fcallback/);
  });

  // ---------- legacy rows are adopted, not lost ----------
  await check('a legacy-only Discord config still works', async () => {
    clear(); seedLegacy();
    const res = await httpGet(port, '/auth/discord');
    assert.strictEqual(res.status, 302);
    assert.match(res.location, /client_id=legacy-id/);
  });

  await check('a legacy-only config is still advertised on the login page', async () => {
    clear(); seedLegacy();
    const res = await httpGet(port, '/api/oauth/providers');
    assert.ok(JSON.parse(res.body).providers.includes('discord'));
  });

  // ---------- nothing enabled means nothing shown/failing ----------
  await check('with nothing configured, Discord is not advertised', async () => {
    clear();
    const res = await httpGet(port, '/api/oauth/providers');
    assert.ok(!JSON.parse(res.body).providers.includes('discord'));
  });

  await check('with nothing configured, /auth/discord explains itself', async () => {
    clear();
    const res = await httpGet(port, '/auth/discord');
    assert.strictEqual(res.status, 404);
    assert.match(res.body, /not enabled/i, 'no explanation for the operator');
  });

  await check('a legacy row with an empty secret cannot enable login', async () => {
    clear();
    raw.prepare(
      `INSERT INTO discord_settings (enabled, client_id, client_secret) VALUES (1, 'x', '')`
    ).run();
    const res = await httpGet(port, '/auth/discord');
    assert.strictEqual(res.status, 404, 'a credential-less config could start a login');
  });

  // ---------- the duplicate settings UI is gone ----------
  await check('the settings page has exactly one Discord form', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'views', 'admin', 'settings.ejs'), 'utf8');
    assert.ok(!src.includes('id="discord_enabled"'), 'the legacy Discord toggle is still rendered');
    assert.ok(!src.includes('discordCredsSection'), 'the legacy credentials section is still rendered');
    assert.ok(src.includes('oauthProviderList'), 'the generic provider list is missing');
  });

  await check('the settings page has no dead call to a removed saver', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'views', 'admin', 'settings.ejs'), 'utf8');
    assert.ok(!src.includes('saveDiscordSettings'), 'a call to a deleted function would throw on save');
  });

  clear();
  console.log(`\n  ${pass} passed, ${fail} failed`);
  try { server.close(); } catch {}
  try { fs.rmSync(DATA_DIR, { recursive: true, force: true }); } catch {}
  process.exit(fail ? 1 : 0);
})();
