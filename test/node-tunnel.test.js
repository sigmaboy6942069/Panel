/**
 * Proves the outbound SSH tunnel: a node agent bound to 127.0.0.1 (i.e. no
 * public port) is reachable from the panel through an SSH forward, the tunnel
 * is reused, and teardown closes the local listener.
 *
 * Requires sshd + ssh-keygen on the box; skips cleanly when unavailable.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const { execFileSync, spawn } = require('child_process');

const repo = path.resolve(__dirname, '..');
const { nodeTunnels } = require(path.join(repo, 'lib/services/nodes/NodeTunnel'));

let pass = 0, fail = 0;
const check = (n, ok, d) => { ok ? (pass++, console.log('  PASS ', n, d || '')) : (fail++, console.log('  FAIL ', n, d || '')); };

(async () => {
  const which = (b) => { try { execFileSync('which', [b], { stdio: 'ignore' }); return true; } catch { return false; } };
  if (!which('sshd') && !fs.existsSync('/usr/sbin/sshd')) {
    console.log('SKIP: sshd not installed');
    process.exit(0);
  }

  const dir = fs.mkdtempSync('/tmp/tunnel-');
  const run = (c, a) => execFileSync(c, a, { cwd: dir, stdio: 'ignore' });
  run('ssh-keygen', ['-t', 'ed25519', '-f', 'host_key', '-N', '', '-q']);
  run('ssh-keygen', ['-t', 'ed25519', '-f', 'client_key', '-N', '', '-q']);
  fs.copyFileSync(path.join(dir, 'client_key.pub'), path.join(dir, 'authorized_keys'));
  fs.chmodSync(path.join(dir, 'authorized_keys'), 0o600);

  const port = 2300 + Math.floor(Math.random() * 500);
  fs.writeFileSync(path.join(dir, 'sshd_config'), [
    `Port ${port}`, 'ListenAddress 127.0.0.1',
    `HostKey ${dir}/host_key`, `AuthorizedKeysFile ${dir}/authorized_keys`,
    'PasswordAuthentication no', 'PubkeyAuthentication yes',
    'PermitRootLogin prohibit-password', 'UsePAM no', 'AllowTcpForwarding yes',
    'StrictModes no', `PidFile ${dir}/sshd.pid`,
  ].join('\n'));

  try { fs.mkdirSync('/run/sshd', { recursive: true }); } catch {}
  const sshd = spawn('/usr/sbin/sshd', ['-D', '-f', path.join(dir, 'sshd_config')], { stdio: 'ignore' });
  const agentPort = 5400 + Math.floor(Math.random() * 400);
  const agent = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true, path: req.url, signed: !!req.headers['x-hkvm-node-key'] }));
  }).listen(agentPort, '127.0.0.1');

  await new Promise((r) => setTimeout(r, 1200));

  const cfg = {
    host: '127.0.0.1', port, username: process.env.USER || 'root',
    privateKeyPath: path.join(dir, 'client_key'),
    targetHost: '127.0.0.1', targetPort: agentPort,
  };

  const url = await nodeTunnels.getTunnelUrl(1, cfg);
  check('tunnel opened on loopback', /^http:\/\/127\.0\.0\.1:\d+$/.test(url), url);

  const body = await new Promise((resolve, reject) => {
    const t = new URL(url);
    const req = http.request({ host: t.hostname, port: t.port, path: '/api/v1/system',
      headers: { 'X-HKVM-Node-Key': 'tgv_node_test' } }, (res) => {
      let d = ''; res.on('data', (c) => d += c); res.on('end', () => resolve(JSON.parse(d)));
    });
    req.on('error', reject); req.end();
  });
  check('request reached the agent through SSH', body.ok === true, JSON.stringify(body));
  check('HMAC header preserved end to end', body.signed === true);

  const url2 = await nodeTunnels.getTunnelUrl(1, cfg);
  check('tunnel is reused, not rebuilt', url === url2, url2);

  await nodeTunnels.close(1);
  const closed = await new Promise((r) => {
    const t = new URL(url);
    const req = http.get({ host: t.hostname, port: t.port, path: '/', timeout: 1500 }, () => r(false));
    req.on('error', () => r(true));
    req.on('timeout', () => { req.destroy(); r(true); });
  });
  check('teardown closes the listener', closed);

  agent.close();
  try { sshd.kill('SIGKILL'); } catch {}
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n===== ${pass}/${pass + fail} checks passed =====`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('CRASH:', e.message); process.exit(1); });
