/**
 * Tests for the requireSecondFactor middleware.
 *
 * This is the gate in front of node approval, so the assertions are mostly
 * about what it must REFUSE: API keys, unverified sessions, stale sessions,
 * and sessions belonging to a different user than the one that proved 2FA.
 */
const assert = require('assert');
const path = require('path');
const { requireSecondFactor } = require(path.join(
  __dirname, '..', 'lib', 'security', 'middleware.js'
));

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

/** Runs the middleware and reports what it decided. */
function run(req) {
  const result = { passed: false, status: null, body: null, redirected: null };
  const res = {
    status(code) { result.status = code; return this; },
    json(body) { result.body = body; return this; },
    send(body) { result.body = body; return this; },
    redirect(to) { result.redirected = to; return this; },
  };
  const next = () => { result.passed = true; };
  requireSecondFactor(req, res, next);
  return result;
}

function baseReq(overrides = {}) {
  return Object.assign(
    {
      originalUrl: '/api/v1/nodes/join-requests/x/approve',
      path: '/api/v1/nodes/join-requests/x/approve',
      method: 'POST',
      headers: { accept: 'application/json' },
      principal: { userId: 1, role: 'admin', viaApiKey: false },
      session: {
        userId: 1,
        twoFactorVerifiedAt: Date.now(),
        twoFactorVerifiedFor: 1,
        twoFactorEnrolled: true,
      },
    },
    overrides
  );
}

console.log('second-factor-gate');

check('a freshly 2FA-verified session passes', () => {
  const r = run(baseReq());
  assert.strictEqual(r.passed, true, 'valid session was blocked');
});

check('an unauthenticated request is rejected', () => {
  const r = run(baseReq({ principal: undefined }));
  assert.strictEqual(r.passed, false);
  assert.strictEqual(r.status, 401);
});

check('API key principals are always rejected', () => {
  const r = run(baseReq({ principal: { userId: 1, role: 'admin', viaApiKey: true } }));
  assert.strictEqual(r.passed, false, 'an API key could approve a node join!');
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.code, 'second_factor_required');
  assert.match(r.body.error, /API key/i);
});

check('an API key is rejected even when the session looks verified', () => {
  // Belt and braces: an API-key principal must not inherit a cookie's trust.
  const r = run(baseReq({ principal: { userId: 1, role: 'admin', viaApiKey: true } }));
  assert.strictEqual(r.passed, false);
});

check('a session with no 2FA stamp is rejected', () => {
  const r = run(baseReq({ session: { userId: 1 } }));
  assert.strictEqual(r.passed, false);
  assert.strictEqual(r.body.code, 'enrol_2fa_first');
});

check('a session where 2FA was never satisfied is rejected', () => {
  const r = run(baseReq({
    session: { userId: 1, twoFactorEnrolled: true },
  }));
  assert.strictEqual(r.passed, false, 'a session with no verifiedAt was accepted');
  assert.strictEqual(r.body.code, 'second_factor_required');
});

check('a session verified for a different user is rejected', () => {
  const r = run(baseReq({
    session: { userId: 1, twoFactorVerifiedAt: Date.now(), twoFactorVerifiedFor: 99, twoFactorEnrolled: true },
  }));
  assert.strictEqual(r.passed, false, 'session fixation: verified user mismatch accepted');
  assert.strictEqual(r.body.code, 'second_factor_required');
});

check('a stale verification (older than the re-auth window) is rejected', () => {
  const r = run(baseReq({
    session: {
      userId: 1,
      twoFactorVerifiedAt: Date.now() - 3 * 60 * 60 * 1000, // 3 hours ago
      twoFactorVerifiedFor: 1,
      twoFactorEnrolled: true,
    },
  }));
  assert.strictEqual(r.passed, false, 'a 3-hour-old verification approved a node');
  assert.strictEqual(r.body.code, 'second_factor_stale');
});

check('a verification just inside the window passes', () => {
  const r = run(baseReq({
    session: {
      userId: 1,
      twoFactorVerifiedAt: Date.now() - 30 * 60 * 1000, // 30 min ago, window is 60
      twoFactorVerifiedFor: 1,
      twoFactorEnrolled: true,
    },
  }));
  assert.strictEqual(r.passed, true, 'a 30-minute-old verification was wrongly rejected');
});

check('the re-auth window is configurable', () => {
  const prev = process.env.TGVPANEL_2FA_REAUTH_MINUTES;
  process.env.TGVPANEL_2FA_REAUTH_MINUTES = '5';
  try {
    const r = run(baseReq({
      session: {
        userId: 1,
        twoFactorVerifiedAt: Date.now() - 10 * 60 * 1000, // 10 min, window now 5
        twoFactorVerifiedFor: 1,
        twoFactorEnrolled: true,
      },
    }));
    assert.strictEqual(r.passed, false, 'a custom shorter window was ignored');
  } finally {
    if (prev === undefined) delete process.env.TGVPANEL_2FA_REAUTH_MINUTES;
    else process.env.TGVPANEL_2FA_REAUTH_MINUTES = prev;
  }
});

check('a missing session object does not throw', () => {
  const r = run(baseReq({ session: undefined }));
  assert.strictEqual(r.passed, false);
  assert.strictEqual(r.status, 403);
});

check('browser requests are redirected, not JSON-errorred', () => {
  const r = run(baseReq({
    headers: {},
    originalUrl: '/admin/nodes',
    path: '/admin/nodes',
    session: { userId: 1 },
  }));
  assert.strictEqual(r.passed, false);
  assert.ok(r.redirected && r.redirected.startsWith('/login/2fa'), 'no redirect for a browser request');
});

check('the denial message tells the user how to fix it', () => {
  const r = run(baseReq({ session: { userId: 1 } }));
  assert.match(r.body.error, /Profile|2FA/i, 'message does not explain what to do');
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
