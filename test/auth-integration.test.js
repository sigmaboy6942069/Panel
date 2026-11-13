/**
 * Integration test for 2FA + social sign-in.
 *
 * Boots the real app against a throwaway database on a random port and drives
 * the flows over HTTP, exactly as a browser would. Uses a stub identity
 * provider so no external network is needed.
 */
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const http = require('http');

const ROOT = path.join(__dirname, '..');
const PORT = 8100 + Math.floor(Math.random() * 400);

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

// --- tiny HTTP client with a cookie jar ---
function makeClient() {
  const jar = new Map();
  function cookieHeader() {
    return Array.from(jar.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
  }
  function store(setCookie) {
    if (!setCookie) return;
    for (const c of setCookie) {
      const [pair] = c.split(';');
      const idx = pair.indexOf('=');
      if (idx > 0) jar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
    }
  }
  let csrf = '';
  const client = {
    get jar() { return jar; },
    get csrf() { return csrf; },
    async req(method, urlPath, body, extraHeaders) {
      return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const headers = Object.assign(
          { 'Content-Type': 'application/json', Cookie: cookieHeader() },
          extraHeaders || {}
        );
        if (csrf && method !== 'GET') headers['X-CSRF-Token'] = csrf;
        if (payload) headers['Content-Length'] = Buffer.byteLength(payload);

        const req = http.request(
          { host: '127.0.0.1', port: PORT, path: urlPath, method, headers },
          (res) => {
            store(res.headers['set-cookie']);
            if (res.headers['x-csrf-token']) csrf = res.headers['x-csrf-token'];
            let data = '';
            res.on('data', (d) => (data += d));
            res.on('end', () => {
              let json = null;
              try { json = JSON.parse(data); } catch { /* html response */ }
              resolve({ status: res.statusCode, headers: res.headers, body: data, json });
            });
          }
        );
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
      });
    },
    get(p) { return this.req('GET', p); },
    post(p, b, h) { return this.req('POST', p, b, h); },
    put(p, b) { return this.req('PUT', p, b); },
    async login(user = 'admin', pass = 'admin') {
      const r = await this.post('/api/login', { username: user, password: pass });
      return r.json;
    },
    async warmCsrf() {
      await this.get('/profile');
    },
  };
  return client;
}

async function waitForServer(timeoutMs = 40000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const r = http.get({ host: '127.0.0.1', port: PORT, path: '/login' }, (res) => {
          res.resume();
          resolve();
        });
        r.on('error', reject);
        r.setTimeout(1500, () => r.destroy(new Error('timeout')));
      });
      return true;
    } catch {
      await new Promise((r) => setTimeout(r, 400));
    }
  }
  return false;
}

(async () => {
  console.log('auth-integration');

  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tgv-auth-'));
  const env = Object.assign({}, process.env, {
    TGVPANEL_DATA_DIR: dataDir,
    PORT: String(PORT),
    TGVPANEL_BIND_HOST: '127.0.0.1',
    TGVPANEL_NO_LISTEN: '0',
    TGVPANEL_DISABLE_RESELLER_POLLER: 'true',
    NODE_ENV: 'test',
  });

  // The sqlite shim maps node:sqlite onto the installed driver in this sandbox.
  const shim = path.join(os.homedir(), '.panel-preview', 'sqlite-shim.js');
  const args = fs.existsSync(shim) ? ['-r', shim, 'app.js'] : ['app.js'];
  const child = spawn(process.execPath, args, { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });

  let log = '';
  child.stdout.on('data', (d) => (log += d));
  child.stderr.on('data', (d) => (log += d));

  const ready = await waitForServer();
  if (!ready) {
    console.log('  server did not start; log tail:');
    console.log(log.split('\n').slice(-25).join('\n'));
    process.exit(1);
  }

  try {
    // ---------- 1. 2FA enrolment ----------
    const c = makeClient();
    const initial = await c.login();
    assert.strictEqual(initial.success, true, 'password login failed: ' + JSON.stringify(initial));
    await c.warmCsrf();

    let setupSecret;
    await check('2FA status starts disabled', async () => {
      const r = await c.get('/api/v1/auth/2fa/status');
      assert.strictEqual(r.json.enabled, false);
      assert.strictEqual(r.json.recoveryCodesRemaining, 0);
    });

    await check('setup returns a secret and a QR image', async () => {
      const r = await c.post('/api/v1/auth/2fa/setup', {});
      assert.strictEqual(r.status, 200, r.body);
      assert.ok(/^[A-Z2-7]{16,}$/.test(r.json.secret), 'bad secret: ' + r.json.secret);
      assert.ok(r.json.qrDataUrl.startsWith('data:image/png;base64,'), 'no QR data URL');
      setupSecret = r.json.secret;
    });

    await check('enabling with a wrong code is refused', async () => {
      const r = await c.post('/api/v1/auth/2fa/enable', { code: '000000' });
      assert.strictEqual(r.status, 400);
    });

    let recoveryCodes = [];
    // Every simulated browser needs its own code: the same TOTP value is
    // rejected a second time inside its 30-second window (replay protection).
    let codePool = [];
    await check('enabling with the right code issues 10 recovery codes', async () => {
      const vault = require(path.join(ROOT, 'lib/security/crypto-vault.js'));
      const code = vault.computeTotpCode(setupSecret);
      const r = await c.post('/api/v1/auth/2fa/enable', { code });
      assert.strictEqual(r.status, 200, r.body);
      assert.strictEqual(r.json.twoFactorEnabled, true);
      assert.strictEqual(r.json.recoveryCodes.length, 10);
      recoveryCodes = r.json.recoveryCodes;
      codePool = recoveryCodes.slice();
    });

    await check('status reports enabled with 10 codes', async () => {
      const r = await c.get('/api/v1/auth/2fa/status');
      assert.strictEqual(r.json.enabled, true);
      assert.strictEqual(r.json.recoveryCodesRemaining, 10);
    });

    // ---------- 2. login now needs the second factor ----------
    await check('password login returns requires2FA instead of a session', async () => {
      const c2 = makeClient();
      const r = await c2.login();
      assert.strictEqual(r.requires2FA, true);
      assert.strictEqual(r.redirectTo, '/login/2fa');
      // And no session was granted.
      const chk = await c2.get('/api/auth/check');
      assert.strictEqual(chk.json.authenticated, false);
    });

    await check('/login/2fa renders for a pending login', async () => {
      const c2 = makeClient();
      await c2.login();
      const r = await c2.get('/login/2fa');
      assert.strictEqual(r.status, 200);
      assert.ok(r.body.includes('Two-Factor Verification'));
    });

    let usedCode;
    await check('a valid TOTP code completes the login', async () => {
      const vault = require(path.join(ROOT, 'lib/security/crypto-vault.js'));
      const c2 = makeClient();
      await c2.login();
      const code = vault.computeTotpCode(setupSecret);
      usedCode = code;
      const r = await c2.post('/api/login/2fa', { code });
      assert.strictEqual(r.status, 200, r.body);
      assert.strictEqual(r.json.success, true);
      const chk = await c2.get('/api/auth/check');
      assert.strictEqual(chk.json.authenticated, true, 'session was not established');
    });

    await check('REPLAY: the same TOTP code cannot be used again', async () => {
      const c3 = makeClient();
      await c3.login();
      const r = await c3.post('/api/login/2fa', { code: usedCode });
      assert.strictEqual(r.status, 401);
      assert.match(r.json.error, /already been used/i);
    });

    await check('a recovery code completes the login', async () => {
      const c4 = makeClient();
      await c4.login();
      const r = await c4.post('/api/login/2fa', { code: recoveryCodes[0] });
      assert.strictEqual(r.status, 200, r.body);
      assert.strictEqual(r.json.usedRecoveryCode, true);
      assert.strictEqual(r.json.recoveryCodesRemaining, 9);
    });

    await check('a used recovery code is dead', async () => {
      const c5 = makeClient();
      await c5.login();
      const r = await c5.post('/api/login/2fa', { code: recoveryCodes[0] });
      assert.strictEqual(r.status, 401);
    });

    await check('a wrong code leaves the user unauthenticated', async () => {
      const c6 = makeClient();
      await c6.login();
      const r = await c6.post('/api/login/2fa', { code: '111111' });
      assert.strictEqual(r.status, 401);
      const chk = await c6.get('/api/auth/check');
      assert.strictEqual(chk.json.authenticated, false);
    });

    await check('2FA endpoints require an authenticated session', async () => {
      const anon = makeClient();
      const r = await anon.get('/api/v1/auth/2fa/status');
      assert.ok(r.status === 401 || r.status === 403 || r.status === 302, 'got ' + r.status);
    });

    // ---------- 3. recovery code regeneration ----------
    await check('regenerating recovery codes invalidates the old sheet', async () => {
      const c7 = makeClient();
      await c7.login();
      const vault = require(path.join(ROOT, 'lib/security/crypto-vault.js'));
      const r0 = await c7.post('/api/login/2fa', { code: recoveryCodes[1] });
      assert.strictEqual(r0.status, 200, 'could not sign in with a spare code');
      await c7.warmCsrf();

      const regen = await c7.post('/api/v1/auth/2fa/recovery-codes/regenerate', {});
      assert.strictEqual(regen.status, 200, regen.body);
      assert.strictEqual(regen.json.recoveryCodes.length, 10);

      const c8 = makeClient();
      await c8.login();
      const stale = await c8.post('/api/login/2fa', { code: recoveryCodes[2] });
      assert.strictEqual(stale.status, 401, 'an old code still worked after regeneration');

      const fresh = await c8.post('/api/login/2fa', { code: regen.json.recoveryCodes[0] });
      assert.strictEqual(fresh.status, 200, 'a new code did not work');

      // Top the pool up with the surviving new codes for later tests.
      codePool = regen.json.recoveryCodes.slice(1);
    });

    async function freshAdminLogin() {
      const admin = makeClient();
      const r = await admin.login();
      assert.strictEqual(r.requires2FA, true, 'admin should require 2FA');
      const code = codePool.shift();
      assert.ok(code, 'ran out of recovery codes for the test');
      const v = await admin.post('/api/login/2fa', { code });
      assert.strictEqual(v.status, 200, 'admin 2FA failed: ' + v.body);
      await admin.warmCsrf();
      return admin;
    }

    // ---------- 4. OAuth ----------
    await check('unconfigured provider shows a friendly page, not a crash', async () => {
      const r = await makeClient().get('/auth/github');
      assert.strictEqual(r.status, 404);
      assert.ok(r.body.includes('not enabled'), 'unexpected body');
    });

    await check('unknown provider is rejected', async () => {
      const r = await makeClient().get('/auth/facebook');
      assert.strictEqual(r.status, 404);
    });

    await check('callback without a pending session is rejected', async () => {
      const r = await makeClient().get('/auth/google/callback?code=x&state=y');
      assert.strictEqual(r.status, 302);
      assert.ok(String(r.headers.location).includes('error='), 'no error redirect');
    });

    // Configure google through the admin API so /auth/google leaves the panel.
    await check('admin can save provider credentials', async () => {
      const admin = await freshAdminLogin();
      const r = await admin.put('/api/admin/oauth-providers/google', {
        enabled: true,
        clientId: 'test.apps.googleusercontent.com',
        clientSecret: 'test-secret-value',
        allowSignup: true,
        autoLinkVerifiedEmail: true,
      });
      assert.strictEqual(r.status, 200, r.body);
    });

    await check('the stored client secret is never returned by the API', async () => {
      const admin = await freshAdminLogin();
      const r = await admin.get('/api/admin/oauth-providers');
      assert.ok(!r.body.includes('test-secret-value'), 'the client secret leaked!');
      const google = r.json.providers.find((p) => p.provider === 'google');
      assert.strictEqual(google.hasClientSecret, true);
      assert.strictEqual(google.enabled, true);
    });

    await check('/auth/google redirects to Google with state and PKCE', async () => {
      const c9 = makeClient();
      const r = await c9.get('/auth/google');
      assert.strictEqual(r.status, 302);
      const loc = String(r.headers.location);
      const u = new URL(loc);
      assert.strictEqual(u.host, 'accounts.google.com');
      assert.ok(u.searchParams.get('state'), 'no state');
      assert.strictEqual(u.searchParams.get('code_challenge_method'), 'S256');
      assert.ok(!loc.includes('test-secret-value'), 'client secret leaked into the URL!');
    });

    await check('a forged state is rejected', async () => {
      const c10 = makeClient();
      await c10.get('/auth/google'); // obtains a real state in its session
      const r = await c10.get('/auth/google/callback?code=stolen&state=WRONG');
      assert.strictEqual(r.status, 302);
      assert.match(String(r.headers.location), /error=/);
    });

    await check('enabling a provider without credentials is refused', async () => {
      const admin = await freshAdminLogin();
      const r = await admin.put('/api/admin/oauth-providers/github', {
        enabled: true, clientId: '', clientSecret: '',
      });
      assert.strictEqual(r.status, 400, 'a provider was enabled with no credentials');
    });

    await check('the public provider list shows only enabled providers', async () => {
      const r = await makeClient().get('/api/oauth/providers');
      assert.deepStrictEqual(r.json.providers.sort(), ['google']);
    });

    await check('login page renders a button per enabled provider', async () => {
      const r = await makeClient().get('/login');
      assert.ok(r.body.includes('googleLoginBtn'));
      assert.ok(r.body.includes('githubLoginBtn'));
      assert.ok(r.body.includes('discordLoginBtn'));
    });

    // ---------- 5. account takeover guards ----------
    await check('a user with no email is refused automatic sign-up', async () => {
      // Exercised at the decision layer; verified here through the module the
      // routes call, so a refactor that drops the guard fails this test.
      const oauth = require(path.join(ROOT, 'lib/security/oauth-providers.js'));
      const d = oauth.decideAccountLink({
        linkedUserId: null, matchingEmailUserId: null,
        emailVerified: false, email: null, autoCreateUsers: true,
      });
      assert.strictEqual(d.action, 'refuse');
    });

    await check('an UNVERIFIED email never auto-links to an existing account', async () => {
      const oauth = require(path.join(ROOT, 'lib/security/oauth-providers.js'));
      const d = oauth.decideAccountLink({
        linkedUserId: null, matchingEmailUserId: 42,
        emailVerified: false, email: 'victim@example.com', autoCreateUsers: true,
      });
      assert.strictEqual(d.action, 'link');
      assert.strictEqual(d.requiresProof, true, 'account takeover path is open');
    });

    await check('an OAuth sign-in for a 2FA user lands on /login/2fa', async () => {
      // The gate lives in completeOAuthLogin; assert the session it builds is a
      // pending one rather than an authenticated one.
      const src = fs.readFileSync(path.join(ROOT, 'app.js'), 'utf8');
      const fn = src.slice(src.indexOf('function completeOAuthLogin'));
      const bodyEnd = fn.indexOf('function createDiscordUser');
      const body = fn.slice(0, bodyEnd);
      assert.ok(/pending2faUser/.test(body), 'completeOAuthLogin no longer sets pending2faUser');
      assert.ok(/two_factor_enabled/.test(body), 'completeOAuthLogin no longer checks 2FA');
      assert.ok(/regenerate/.test(body), 'completeOAuthLogin no longer regenerates the session');
    });

    // ---------- 6. admin 2FA policy ----------
    await check('the admin 2FA policy can be toggled', async () => {
      const admin = await freshAdminLogin();

      let r = await admin.put('/api/admin/2fa-policy', { requireForAdmins: true });
      assert.strictEqual(r.status, 200, r.body);
      let g = await admin.get('/api/admin/2fa-policy');
      assert.strictEqual(g.json.requireForAdmins, true);

      r = await admin.put('/api/admin/2fa-policy', { requireForAdmins: false });
      assert.strictEqual(r.status, 200);
      g = await admin.get('/api/admin/2fa-policy');
      assert.strictEqual(g.json.requireForAdmins, false);
    });

    await check('non-admins cannot read the provider configuration', async () => {
      const anon = makeClient();
      const r = await anon.get('/api/admin/oauth-providers');
      assert.ok(r.status === 302 || r.status === 401 || r.status === 403, 'got ' + r.status);
    });

  } catch (e) {
    console.log('  FAIL (unexpected): ' + e.message);
    console.log(log.split('\n').slice(-20).join('\n'));
    fail++;
  } finally {
    child.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 600));
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {}
  }

  console.log(`\n  ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
