/**
 * Tests for the public Terms of Service page.
 *
 * The point of these terms is that they describe what this panel actually does.
 * Hosting ToS templates routinely promise domains, phone support and a money-back
 * guarantee the operator cannot honour, which is worse than having no terms. So
 * several of these tests assert that things the panel does NOT do are absent.
 */
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const ejs = require('ejs');

const ROOT = path.join(__dirname, '..');
const TEMPLATE = path.join(ROOT, 'views', 'pages', 'terms.ejs');

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

function render(data) {
  return ejs.renderFile(TEMPLATE, {
    siteName: 'TGVPANEL',
    siteLogo: '/images/logo.png',
    panelVersion: 'V3.0',
    companyName: '',
    contactEmail: '',
    contactAddress: '',
    abuseEmail: '',
    updated: '1 January 2026',
    governingLaw: 'the country in which the operator is established',
    disputeStatement: 'the operator is not obliged to participate',
    ...data,
  }, { async: true });
}

(async () => {
  console.log('terms-of-service');

  // ---------- renders ----------
  await check('renders with no operator details', async () => {
    const html = await render({});
    assert.match(html, /Terms of Service/);
    assert.ok(html.length > 6000, 'suspiciously short');
  });

  await check('operator details are interpolated', async () => {
    const html = await render({
      companyName: 'Hynex Cloud',
      contactEmail: 'legal@example.com',
      contactAddress: '1 Example Street, Brussels',
      abuseEmail: 'abuse@example.com',
      governingLaw: 'Belgium',
    });
    for (const t of ['Hynex Cloud', 'legal@example.com', '1 Example Street, Brussels', 'abuse@example.com', 'Belgium']) {
      assert.ok(html.includes(t), `missing: ${t}`);
    }
  });

  await check('warns the operator when business details are unset', async () => {
    const html = await render({});
    assert.match(html, /has not configured their business details/,
      'nothing tells the operator the page is not publishable');
  });

  await check('the warning clears once a company name is set', async () => {
    const html = await render({ companyName: 'Hynex Cloud' });
    assert.ok(!html.includes('has not configured their business details'));
  });

  await check('an unset abuse address falls back to the contact address', async () => {
    const html = await render({ contactEmail: 'legal@example.com' });
    assert.ok(html.includes('legal@example.com'));
    assert.ok(!/abuse reports:/i.test(html.replace(/abuse reports:.*<a[^>]*>[^<]*<\/a>/i, '')),
      'rendered an empty abuse entry');
  });

  // ---------- truthful about THIS panel ----------
  await check('it covers the services the panel actually provides', async () => {
    const html = await render({});
    for (const s of ['Virtual machines', 'Containers', 'Storage', 'Networking', 'Monitoring', 'Reselling']) {
      assert.ok(html.includes(s), `terms do not mention ${s}`);
    }
  });

  await check('it does NOT promise domains the panel cannot sell', async () => {
    const html = await render({});
    assert.ok(!/domain registration/i.test(html), 'terms promise a domain service this panel has no code for');
    assert.ok(!/domain transfers?/i.test(html), 'terms promise domain transfers');
  });

  await check('it does NOT promise shared hosting', async () => {
    const html = await render({});
    assert.ok(!/shared hosting/i.test(html), 'terms promise shared hosting, which is not a panel feature');
  });

  await check('it does NOT promise a money-back guarantee', async () => {
    const html = await render({});
    assert.ok(!/money[- ]back/i.test(html), 'terms promise a refund policy the panel cannot enforce');
    assert.ok(!/\d+[- ]day refund/i.test(html));
  });

  // ---------- the clauses that matter ----------
  await check('acceptable use bans the categories that get operators terminated', async () => {
    const html = await render({});
    const banned = [
      /CSAM|sexualises minors/i,
      /malware|ransomware/i,
      /denial-of-service|DoS/i,
      /spam/i,
      /cryptocurrency mining|crypto.?mining/i,
      /sanctions/i,
    ];
    for (const re of banned) assert.match(html, re);
  });

  await check('it says mining is banned outright, not merely restricted', async () => {
    const html = await render({});
    const idx = html.search(/cryptocurrency mining/i);
    assert.ok(idx > -1);
    assert.match(html.slice(idx - 200, idx + 300), /never|banned|not permitted|prohibited|forbidden/i);
  });

  await check('liability is limited without excluding mandatory liability', async () => {
    const html = await render({});
    assert.match(html, /death or personal injury/i);
    assert.match(html, /gross negligence/i);
    assert.match(html, /not liable|excluded/i);
  });

  await check('it keeps consumer rights alive despite the governing-law clause', async () => {
    const html = await render({});
    assert.match(html, /does not remove the protection of mandatory rules/i,
      'the governing-law clause could strip consumer protections');
  });

  await check('it explains the withdrawal right and when it ends', async () => {
    const html = await render({});
    assert.match(html, /right of withdrawal/i);
    assert.match(html, /ends early|provisioned within minutes/i);
  });

  await check('it warns that deleting a service destroys data', async () => {
    const html = await render({});
    assert.match(html, /cannot be undone|destroys its data/i);
  });

  await check('it tells the customer to take their own backups', async () => {
    const html = await render({});
    assert.match(html, /back ?up/i);
    assert.match(html, /not a guarantee|not\s+guarantee/i);
  });

  await check('resellers are made responsible for their own customers', async () => {
    const html = await render({});
    assert.match(html, /resell/i);
    assert.match(html, /remaining responsible|remains?\s+responsible|remain responsible/i);
  });

  await check('it links to the privacy policy', async () => {
    const html = await render({});
    assert.match(html, /href="\/privacy"/);
  });

  // ---------- safety ----------
  await check('operator fields are HTML-escaped', async () => {
    const html = await render({ governingLaw: '<script>alert(1)</script>' });
    assert.ok(!html.includes('<script>alert(1)</script>'), 'XSS: governing law rendered raw');
    assert.match(html, /&lt;script&gt;/);
  });

  await check('an event handler cannot be injected through the dispute field', async () => {
    const html = await render({ disputeStatement: '<img src=x onerror=alert(2)>' });
    assert.ok(!/<img src=x onerror=/.test(html), 'XSS via dispute statement');
  });

  // ---------- wiring ----------
  await check('the /terms route is registered and public', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'src', 'api', 'web-routes.ts'), 'utf8');
    assert.match(src, /router\.get\('\/terms'/, '/terms route missing');
    const block = src.slice(src.indexOf("router.get('/terms'"), src.indexOf("router.get('/terms'") + 1400);
    assert.ok(!/requireRole|requirePrincipal|checkAuth/.test(block), '/terms must not require a session');
  });

  await check('the login page links to the terms', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'views', 'users', 'login.ejs'), 'utf8');
    assert.match(src, /href="\/terms"/, 'no way to reach the terms from the login page');
  });

  await check('the privacy page links to the terms', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'views', 'pages', 'privacy.ejs'), 'utf8');
    assert.match(src, /termsUrl \|\| '\/terms'/, 'privacy footer does not fall back to /terms');
  });

  console.log(`\n  ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
