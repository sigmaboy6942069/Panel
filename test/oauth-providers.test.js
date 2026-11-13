// Tests for the OAuth provider registry. No network: fetch is injected.
const path = require('path');
const assert = require('assert');
const TSC = path.join(__dirname, '..', 'lib', 'security', 'oauth-providers.js');
const oauth = require(TSC);

let pass = 0, fail = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  PASS ${name}`);
    pass++;
  } catch (e) {
    console.log(`  FAIL ${name}: ${e.message}`);
    fail++;
  }
}
async function checkAsync(name, fn) {
  try {
    await fn();
    console.log(`  PASS ${name}`);
    pass++;
  } catch (e) {
    console.log(`  FAIL ${name}: ${e.message}`);
    fail++;
  }
}

function fakeFetch(handler) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    return handler(url, opts);
  };
  fn.calls = calls;
  return fn;
}
function jsonRes(obj, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => obj,
    text: async () => JSON.stringify(obj),
  };
}

(async () => {
  console.log('oauth-providers');

  // --- PKCE & state ---
  check('PKCE challenge is S256 of the verifier', () => {
    const { verifier, challenge } = oauth.createPkcePair();
    const expected = require('crypto').createHash('sha256').update(verifier).digest('base64url');
    assert.strictEqual(challenge, expected);
    assert.ok(verifier.length >= 43 && verifier.length <= 128, 'verifier length out of RFC range');
  });

  check('PKCE pairs are unique per call', () => {
    assert.notStrictEqual(oauth.createPkcePair().verifier, oauth.createPkcePair().verifier);
  });

  check('state comparison rejects wrong, empty and missing values', () => {
    const s = oauth.createOAuthState();
    assert.strictEqual(oauth.oauthStateMatches(s, s), true);
    assert.strictEqual(oauth.oauthStateMatches(s, s + 'x'), false);
    assert.strictEqual(oauth.oauthStateMatches(s, undefined), false);
    assert.strictEqual(oauth.oauthStateMatches(undefined, s), false);
    assert.strictEqual(oauth.oauthStateMatches('', ''), false);
    assert.strictEqual(oauth.oauthStateMatches(s, 12345), false);
  });

  check('state is high-entropy and url-safe', () => {
    const s = oauth.createOAuthState();
    assert.ok(s.length >= 40 && /^[A-Za-z0-9_-]+$/.test(s), `bad state: ${s}`);
  });

  // --- authorize URL ---
  check('authorize URL carries state, scope and PKCE for Google', () => {
    const url = new URL(oauth.buildAuthorizeUrl({
      provider: 'google',
      config: { clientId: 'cid', clientSecret: 'sec', redirectUri: 'https://p.example/cb' },
      state: 'st8',
      codeChallenge: 'chal',
    }));
    assert.strictEqual(url.searchParams.get('state'), 'st8');
    assert.strictEqual(url.searchParams.get('code_challenge'), 'chal');
    assert.strictEqual(url.searchParams.get('code_challenge_method'), 'S256');
    assert.strictEqual(url.searchParams.get('redirect_uri'), 'https://p.example/cb');
    assert.ok(url.searchParams.get('scope').includes('email'));
  });

  check('authorize URL omits PKCE for GitHub (unsupported)', () => {
    const url = new URL(oauth.buildAuthorizeUrl({
      provider: 'github',
      config: { clientId: 'cid', clientSecret: 'sec', redirectUri: 'https://p.example/cb' },
      state: 'st8',
      codeChallenge: 'chal',
    }));
    assert.strictEqual(url.searchParams.get('code_challenge'), null);
  });

  check('client secret never appears in the authorize URL', () => {
    for (const p of ['google', 'discord', 'github']) {
      const u = oauth.buildAuthorizeUrl({
        provider: p,
        config: { clientId: 'cid', clientSecret: 'TOPSECRET', redirectUri: 'https://p/cb' },
        state: 's',
      });
      assert.ok(!u.includes('TOPSECRET'), `${p} leaked the client secret`);
    }
  });

  // --- token exchange ---
  await checkAsync('token exchange sends verifier and returns the access token', async () => {
    const f = fakeFetch(() => jsonRes({ access_token: 'at123', token_type: 'Bearer' }));
    const out = await oauth.exchangeCodeForToken({
      provider: 'google',
      config: { clientId: 'cid', clientSecret: 'sec', redirectUri: 'https://p/cb' },
      code: 'code1',
      codeVerifier: 'ver1',
      fetchImpl: f,
    });
    assert.strictEqual(out.accessToken, 'at123');
    const body = new URLSearchParams(f.calls[0].opts.body);
    assert.strictEqual(body.get('code_verifier'), 'ver1');
    assert.strictEqual(body.get('grant_type'), 'authorization_code');
  });

  await checkAsync('GitHub form-encoded token response is parsed', async () => {
    const f = fakeFetch(() => ({
      ok: true, status: 200,
      json: async () => { throw new Error('not json'); },
      text: async () => 'access_token=gho_x&token_type=bearer&scope=read:user',
    }));
    const out = await oauth.exchangeCodeForToken({
      provider: 'github',
      config: { clientId: 'c', clientSecret: 's', redirectUri: 'https://p/cb' },
      code: 'c1',
      fetchImpl: f,
    });
    assert.strictEqual(out.accessToken, 'gho_x');
  });

  await checkAsync('token exchange failure throws with status', async () => {
    const f = fakeFetch(() => ({ ok: false, status: 400, text: async () => 'bad_verification_code' }));
    await assert.rejects(
      () => oauth.exchangeCodeForToken({
        provider: 'google',
        config: { clientId: 'c', clientSecret: 's', redirectUri: 'https://p/cb' },
        code: 'x', fetchImpl: f,
      }),
      /400/
    );
  });

  await checkAsync('token response with error field is rejected', async () => {
    const f = fakeFetch(() => jsonRes({ error: 'invalid_grant', error_description: 'expired' }));
    await assert.rejects(
      () => oauth.exchangeCodeForToken({
        provider: 'discord',
        config: { clientId: 'c', clientSecret: 's', redirectUri: 'https://p/cb' },
        code: 'x', fetchImpl: f,
      }),
      /invalid_grant|expired/
    );
  });

  await checkAsync('missing access_token is rejected', async () => {
    const f = fakeFetch(() => jsonRes({ token_type: 'Bearer' }));
    await assert.rejects(
      () => oauth.exchangeCodeForToken({
        provider: 'google',
        config: { clientId: 'c', clientSecret: 's', redirectUri: 'https://p/cb' },
        code: 'x', fetchImpl: f,
      }),
      /no access_token/
    );
  });

  // --- profile normalisation ---
  await checkAsync('Google profile: subject is sub, not email', async () => {
    const f = fakeFetch(() => jsonRes({
      sub: '1234567890', email: 'a@b.com', email_verified: true, name: 'Alice', picture: 'https://x/a.png',
    }));
    const p = await oauth.fetchNormalizedProfile({ provider: 'google', accessToken: 't', fetchImpl: f });
    assert.strictEqual(p.subject, '1234567890');
    assert.strictEqual(p.email, 'a@b.com');
    assert.strictEqual(p.emailVerified, true);
    assert.strictEqual(p.avatarUrl, 'https://x/a.png');
  });

  await checkAsync('Google unverified email is not trusted', async () => {
    const f = fakeFetch(() => jsonRes({ sub: '1', email: 'a@b.com', email_verified: false }));
    const p = await oauth.fetchNormalizedProfile({ provider: 'google', accessToken: 't', fetchImpl: f });
    assert.strictEqual(p.emailVerified, false);
  });

  await checkAsync('Discord profile builds a CDN avatar URL', async () => {
    const f = fakeFetch(() => jsonRes({
      id: '99', username: 'bob', global_name: 'Bobby', email: 'b@c.com', verified: true, avatar: 'abc',
    }));
    const p = await oauth.fetchNormalizedProfile({ provider: 'discord', accessToken: 't', fetchImpl: f });
    assert.strictEqual(p.subject, '99');
    assert.strictEqual(p.username, 'Bobby');
    assert.ok(p.avatarUrl.includes('/avatars/99/abc.png'));
    assert.strictEqual(p.emailVerified, true);
  });

  await checkAsync('Discord unverified account marks email untrusted', async () => {
    const f = fakeFetch(() => jsonRes({ id: '99', username: 'bob', email: 'b@c.com', verified: false }));
    const p = await oauth.fetchNormalizedProfile({ provider: 'discord', accessToken: 't', fetchImpl: f });
    assert.strictEqual(p.emailVerified, false);
  });

  await checkAsync('GitHub falls back to /user/emails for a verified address', async () => {
    const f = fakeFetch((url) => {
      if (url.endsWith('/user')) return jsonRes({ id: 7, login: 'carol', email: null });
      return jsonRes([
        { email: 'other@x.com', primary: false, verified: true },
        { email: 'carol@x.com', primary: true, verified: true },
      ]);
    });
    const p = await oauth.fetchNormalizedProfile({ provider: 'github', accessToken: 't', fetchImpl: f });
    assert.strictEqual(p.email, 'carol@x.com');
    assert.strictEqual(p.emailVerified, true);
    assert.strictEqual(p.subject, '7');
  });

  await checkAsync('GitHub public email is only trusted if /emails confirms it', async () => {
    const f = fakeFetch((url) => {
      if (url.endsWith('/user')) return jsonRes({ id: 7, login: 'carol', email: 'public@x.com' });
      return jsonRes([{ email: 'public@x.com', primary: true, verified: false }]);
    });
    const p = await oauth.fetchNormalizedProfile({ provider: 'github', accessToken: 't', fetchImpl: f });
    assert.strictEqual(p.emailVerified, false);
  });

  await checkAsync('profile fetch failure throws', async () => {
    const f = fakeFetch(() => ({ ok: false, status: 401, json: async () => ({}) }));
    await assert.rejects(
      () => oauth.fetchNormalizedProfile({ provider: 'google', accessToken: 'bad', fetchImpl: f }),
      /401/
    );
  });

  // --- account linking decisions (the security-critical part) ---
  check('existing link always signs in', () => {
    const d = oauth.decideAccountLink({
      linkedUserId: 5, matchingEmailUserId: 9, emailVerified: false, email: 'x@y.z', autoCreateUsers: false,
    });
    assert.deepStrictEqual(d, { action: 'login', userId: 5 });
  });

  check('verified email auto-links to the matching account', () => {
    const d = oauth.decideAccountLink({
      linkedUserId: null, matchingEmailUserId: 9, emailVerified: true, email: 'x@y.z', autoCreateUsers: true,
    });
    assert.deepStrictEqual(d, { action: 'link', userId: 9, requiresProof: false });
  });

  check('UNVERIFIED email must not auto-link (account takeover)', () => {
    const d = oauth.decideAccountLink({
      linkedUserId: null, matchingEmailUserId: 9, emailVerified: false, email: 'x@y.z', autoCreateUsers: true,
    });
    assert.strictEqual(d.action, 'link');
    assert.strictEqual(d.requiresProof, true, 'unverified email was trusted!');
  });

  check('unknown email creates a user when sign-up is allowed', () => {
    const d = oauth.decideAccountLink({
      linkedUserId: null, matchingEmailUserId: null, emailVerified: true, email: 'new@y.z', autoCreateUsers: true,
    });
    assert.strictEqual(d.action, 'create');
  });

  check('unknown email is refused when sign-up is disabled', () => {
    const d = oauth.decideAccountLink({
      linkedUserId: null, matchingEmailUserId: null, emailVerified: true, email: 'new@y.z', autoCreateUsers: false,
    });
    assert.strictEqual(d.action, 'refuse');
  });

  check('no email means no account creation', () => {
    const d = oauth.decideAccountLink({
      linkedUserId: null, matchingEmailUserId: null, emailVerified: false, email: null, autoCreateUsers: true,
    });
    assert.strictEqual(d.action, 'refuse');
  });

  check('provider ids are validated against the registry', () => {
    assert.strictEqual(oauth.isOAuthProviderId('google'), true);
    assert.strictEqual(oauth.isOAuthProviderId('discord'), true);
    assert.strictEqual(oauth.isOAuthProviderId('github'), true);
    assert.strictEqual(oauth.isOAuthProviderId('facebook'), false);
    assert.strictEqual(oauth.isOAuthProviderId('__proto__'), false);
    assert.strictEqual(oauth.isOAuthProviderId(null), false);
  });

  console.log(`\n  ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
