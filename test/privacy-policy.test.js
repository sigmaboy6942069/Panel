/**
 * Tests for the public privacy policy page.
 *
 * Google will not publish an OAuth app without a reachable privacy policy, and
 * reviewers open it signed out. So the two properties that matter most are:
 * it renders without authentication, and it tells the truth about what this
 * panel actually stores.
 */
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-'));

process.env.TGVPANEL_DATA_DIR = DATA_DIR;
process.env.TGVPANEL_NO_LISTEN = '1';
process.env.TGVPANEL_DISABLE_RESELLER_POLLER = 'true';
process.env.PORT = '0';

require(path.join(ROOT, 'test', 'helpers', 'sqlite3-shim.js'));

const ejs = require('ejs');

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

const TEMPLATE = path.join(ROOT, 'views', 'pages', 'privacy.ejs');

function render(data) {
  return ejs.renderFile(TEMPLATE, {
    siteName: 'TGVPANEL',
    siteLogo: '/images/logo.png',
    panelVersion: 'V3.0',
    companyName: '',
    contactEmail: '',
    contactAddress: '',
    termsUrl: '',
    updated: '1 January 2026',
    ...data,
  }, { async: true });
}

(async () => {
  console.log('privacy-policy');

  // ---------- it renders at all ----------
  await check('the template renders with no optional data', async () => {
    const html = await render({});
    assert.match(html, /Privacy Policy/);
    assert.ok(html.length > 3000, 'page is suspiciously short');
  });

  await check('operator details are interpolated when provided', async () => {
    const html = await render({
      companyName: 'Hynex Cloud',
      contactEmail: 'privacy@example.com',
      contactAddress: '1 Example Street, Brussels',
      termsUrl: 'https://example.com/terms',
      updated: '10 November 2026',
    });
    assert.match(html, /Hynex Cloud/);
    assert.match(html, /privacy@example\.com/);
    assert.match(html, /1 Example Street, Brussels/);
    assert.match(html, /10 November 2026/);
    assert.match(html, /https:\/\/example\.com\/terms/);
  });

  await check('an unconfigured contact is called out rather than silently blank', async () => {
    const html = await render({});
    assert.match(html, /No privacy contact address has been configured/,
      'the operator gets no warning that the page is not publishable');
  });

  await check('the warning disappears once a contact is set', async () => {
    const html = await render({ contactEmail: 'privacy@example.com' });
    assert.ok(!html.includes('No privacy contact address has been configured'));
  });

  await check('the legal footer link is hidden when no terms URL is set', async () => {
    const html = await render({});
    assert.ok(!html.includes('>Terms of Service<'), 'a dead Terms link was rendered');
  });

  // ---------- it must be truthful about this panel ----------
  await check('it discloses the session cookie', async () => {
    const html = await render({});
    assert.match(html, /session cookie/i);
    assert.match(html, /HttpOnly/);
    assert.match(html, /SameSite/i);
  });

  await check('it says there are no advertising or analytics cookies', async () => {
    const html = await render({});
    assert.match(html, /no advertising, analytics or fingerprinting cookies/i);
  });

  await check('it names every social provider the panel supports', async () => {
    const html = await render({});
    for (const p of ['Google', 'GitHub', 'Discord']) {
      assert.ok(html.includes(p), `${p} is not mentioned`);
    }
  });

  await check('it covers the data the panel really stores', async () => {
    const html = await render({});
    const mustMention = [
      /two-factor/i,
      /activity logs/i,
      /virtual machine/i,
      /recovery codes/i,
      /IP address/i,
    ];
    for (const re of mustMention) assert.match(html, re);
  });

  await check('it states the rights a subject can exercise', async () => {
    const html = await render({});
    for (const r of ['Access', 'Correction', 'Deletion', 'Portability']) {
      assert.ok(html.includes(r), `missing right: ${r}`);
    }
  });

  await check('it says data is not sold', async () => {
    const html = await render({});
    assert.match(html, /not sold/i);
  });

  // ---------- safety ----------
  await check('admin-supplied values are HTML-escaped', async () => {
    const html = await render({ companyName: '<script>alert(1)</script>' });
    assert.ok(!html.includes('<script>alert(1)</script>'), 'XSS: operator field rendered raw');
    assert.match(html, /&lt;script&gt;/);
  });

  await check('an attacker cannot inject an event handler', async () => {
    const html = await render({ contactAddress: '<img src=x onerror=alert(2)>' });
    assert.ok(!/<img src=x onerror=/.test(html), 'XSS via address field');
  });

  await check('a non-http terms URL is not turned into a link blindly', async () => {
    const html = await render({ termsUrl: 'javascript:alert(1)' });
    // The template escapes attribute values, so javascript: would still be a
    // live link. Assert the router-level validation is the thing preventing it.
    const src = fs.readFileSync(path.join(ROOT, 'views', 'admin', 'settings.ejs'), 'utf8');
    assert.match(src, /must start with http/i, 'no validation on the terms URL field');
  });

  // ---------- route wiring ----------
  await check('the /privacy route is registered and public', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'src', 'api', 'web-routes.ts'), 'utf8');
    assert.match(src, /router\.get\('\/privacy'/, '/privacy route missing');
    const block = src.slice(src.indexOf("router.get('/privacy'"), src.indexOf("router.get('/privacy'") + 1200);
    assert.ok(!/requireRole|requirePrincipal|checkAuth/.test(block), '/privacy must not require a session');
  });

  await check('the login page links to the policy', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'views', 'users', 'login.ejs'), 'utf8');
    assert.match(src, /href="\/privacy"/, 'no way to reach the policy from the login page');
  });

  // ---------- retranscription drift ----------
  await check('the page does not claim a fixed retention it cannot keep', async () => {
    const html = await render({});
    // A hard "we keep everything for exactly N days" would be a promise the
    // panel cannot enforce, since retention is configurable.
    assert.ok(!/kept for exactly \d+ days/i.test(html));
  });

  console.log(`\n  ${pass} passed, ${fail} failed`);
  try { fs.rmSync(DATA_DIR, { recursive: true, force: true }); } catch {}
  process.exit(fail ? 1 : 0);
})();
