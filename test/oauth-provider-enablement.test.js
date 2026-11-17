/**
 * Regression: a provider enabled through its own Settings form must actually be
 * usable from the login page.
 *
 * The Discord section in Admin → Settings writes the legacy `discord_settings`
 * table, while /auth/:provider reads `oauth_provider_settings`. Configuring
 * Discord the way the UI offers used to show a "Login with Discord" button that
 * led to "Signing in with discord is not enabled on this panel". These tests pin
 * the fallback that makes both sources agree.
 */
const assert = require('assert');
const path = require('path');
const express = require('express');

const ROOT = path.join(__dirname, '..');
const { createOAuthRouter } = require(path.join(ROOT, 'lib', 'api', 'oauth-routes.js'));

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
 * Minimal in-memory ctx: only the queries the router actually runs.
 */
function makeCtx({ providerRows = [], legacyDiscord = null } = {}) {
  const db = {
    async get(sql, params) {
      const q = sql.replace(/\s+/g, ' ').trim();
      if (q.includes('FROM oauth_provider_settings')) {
        return providerRows.find((r) => r.provider === params[0]) || undefined;
      }
      if (q.includes('FROM discord_settings')) {
        return legacyDiscord || undefined;
      }
      return undefined;
    },
    async run() { return { changes: 0 }; },
    async all() { return []; },
  };
  return { db };
}

/** Drive a GET and capture the outcome without touching the network. */
function request(ctx, urlPath, session = {}) {
  return new Promise((resolve) => {
    const app = express();
    // The router renders users/oauth-error on failure. Stub the engine so the
    // test stays about routing, not templating.
    app.set('views', path.join(ROOT, 'views'));
    app.engine('ejs', (_file, opts, cb) => cb(null, `rendered: ${opts.message || ''}`));
    app.set('view engine', 'ejs');
    app.use(express.json());
    app.use((req, _res, next) => { req.session = session; next(); });
    app.use(createOAuthRouter({
      ctx,
      resolveRedirectUri: (provider) => `https://panel.example.com/auth/${provider}/callback`,
    }));
    const server = app.listen(0, () => {
      const port = server.address().port;
      const http = require('http');
      http.get({ host: '127.0.0.1', port, path: urlPath }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          server.close();
          resolve({ status: res.statusCode, location: res.headers.location || '', body });
        });
      }).on('error', (e) => { server.close(); resolve({ status: 0, error: e.message, body: '', location: '' }); });
    });
  });
}

(async () => {
  console.log('oauth-provider-enablement');

  // ---------- the bug ----------
  await check('Discord enabled only in the legacy table still starts the flow', async () => {
    const ctx = makeCtx({
      providerRows: [],
      legacyDiscord: {
        enabled: 1,
        client_id: '111222333',
        client_secret: 'legacy-secret',
        redirect_uri: 'https://panel.example.com/auth/discord/callback',
      },
    });
    const res = await request(ctx, '/auth/discord');

    assert.notStrictEqual(res.status, 404, 'still "not enabled on this panel"');
    assert.strictEqual(res.status, 302, `expected a redirect, got ${res.status}`);
    assert.match(res.location, /^https:\/\/discord\.com\/api\/oauth2\/authorize/);
    assert.match(res.location, /client_id=111222333/);
    assert.match(res.location, /code_challenge_method=S256/, 'PKCE was dropped');
    assert.match(res.location, /state=[\w-]{20,}/, 'state was not generated');
  });

  await check('the legacy redirect_uri is honoured when present', async () => {
    const ctx = makeCtx({
      legacyDiscord: {
        enabled: 1,
        client_id: 'abc',
        client_secret: 's',
        redirect_uri: 'https://custom.example/auth/discord/callback',
      },
    });
    const res = await request(ctx, '/auth/discord');
    assert.strictEqual(res.status, 302);
    assert.match(res.location, /redirect_uri=https%3A%2F%2Fcustom\.example%2Fauth%2Fdiscord%2Fcallback/);
  });

  await check('a legacy row with no secret is not treated as enabled', async () => {
    const ctx = makeCtx({
      legacyDiscord: { enabled: 1, client_id: 'abc', client_secret: '', redirect_uri: '' },
    });
    const res = await request(ctx, '/auth/discord');
    assert.strictEqual(res.status, 404, 'enrolled a provider with no secret');
  });

  await check('a legacy row that is disabled is ignored', async () => {
    const ctx = makeCtx({
      legacyDiscord: { enabled: 0, client_id: 'abc', client_secret: 's', redirect_uri: '' },
    });
    const res = await request(ctx, '/auth/discord');
    assert.strictEqual(res.status, 404, 'a disabled provider could still sign in');
  });

  // ---------- the new table still wins ----------
  await check('the generic table takes precedence over the legacy one', async () => {
    const ctx = makeCtx({
      providerRows: [{
        provider: 'discord', enabled: 1, client_id: 'generic-id',
        client_secret_enc: require(path.join(ROOT, 'lib', 'security', 'crypto-vault.js'))
          .encryptSecret('generic-secret'),
        redirect_uri: null, allow_signup: 0, auto_link_verified_email: 1,
      }],
      legacyDiscord: { enabled: 1, client_id: 'legacy-id', client_secret: 'x', redirect_uri: '' },
    });
    const res = await request(ctx, '/auth/discord');
    assert.strictEqual(res.status, 302);
    assert.match(res.location, /client_id=generic-id/, 'legacy config overrode the generic one');
  });

  // ---------- the fallback must not leak to other providers ----------
  await check('Google does not fall back to the Discord table', async () => {
    const ctx = makeCtx({
      providerRows: [],
      legacyDiscord: { enabled: 1, client_id: 'abc', client_secret: 's', redirect_uri: '' },
    });
    const res = await request(ctx, '/auth/google');
    assert.strictEqual(res.status, 404, 'Google was enabled by a Discord row');
  });

  await check('an undisabled Google still 404s cleanly', async () => {
    const ctx = makeCtx({ providerRows: [] });
    const res = await request(ctx, '/auth/google');
    assert.strictEqual(res.status, 404);
    assert.match(res.body, /not enabled/i, 'no explanation shown to the user');
  });

  await check('an unknown provider is rejected before any lookup', async () => {
    const ctx = makeCtx({ providerRows: [] });
    const res = await request(ctx, '/auth/myspace');
    assert.strictEqual(res.status, 404);
    assert.match(res.body, /unknown sign-in provider/i);
  });

  // ---------- callback safety ----------
  await check('a callback with no pending session does not crash', async () => {
    const ctx = makeCtx({
      legacyDiscord: { enabled: 1, client_id: 'abc', client_secret: 's', redirect_uri: '' },
    });
    const res = await request(ctx, '/auth/discord/callback?code=x&state=y');
    assert.strictEqual(res.status, 302);
    assert.match(res.location, /\/login\?error=/, 'a bare callback should bounce to /login with a reason');
  });

  await check('a callback with a mismatched state is refused', async () => {
    const ctx = makeCtx({
      legacyDiscord: { enabled: 1, client_id: 'abc', client_secret: 's', redirect_uri: '' },
    });
    const res = await request(ctx, '/auth/discord/callback?code=x&state=wrong', {
      oauthPending: { provider: 'discord', state: 'right', codeVerifier: 'v', createdAt: Date.now() },
    });
    assert.strictEqual(res.status, 302);
    assert.match(decodeURIComponent(res.location), /security check failed/i);
  });

  await check('a stale pending session is refused', async () => {
    const ctx = makeCtx({
      legacyDiscord: { enabled: 1, client_id: 'abc', client_secret: 's', redirect_uri: '' },
    });
    const res = await request(ctx, '/auth/discord/callback?code=x&state=right', {
      oauthPending: {
        provider: 'discord', state: 'right', codeVerifier: 'v',
        createdAt: Date.now() - 60 * 60 * 1000, // an hour old, TTL is 10 min
      },
    });
    assert.strictEqual(res.status, 302);
    assert.match(decodeURIComponent(res.location), /took too long/i);
  });

  await check('a callback for a different provider than the pending one is refused', async () => {
    const ctx = makeCtx({
      providerRows: [{
        provider: 'google', enabled: 1, client_id: 'g',
        client_secret_enc: require(path.join(ROOT, 'lib', 'security', 'crypto-vault.js'))
          .encryptSecret('gs'),
        redirect_uri: null, allow_signup: 0, auto_link_verified_email: 1,
      }],
    });
    const res = await request(ctx, '/auth/google/callback?code=x&state=right', {
      oauthPending: { provider: 'discord', state: 'right', codeVerifier: 'v', createdAt: Date.now() },
    });
    assert.strictEqual(res.status, 302);
    assert.match(decodeURIComponent(res.location), /session expired/i);
  });

  console.log(`\n  ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
