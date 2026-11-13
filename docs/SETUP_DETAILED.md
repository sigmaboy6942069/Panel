# TGVPANEL — Detailed Setup

The same nine steps as [SETUP_QUICK.md](SETUP_QUICK.md), in the same order, with
the reasoning and the options behind each one. Skim the parts you don't need.

If you just want it working: use the quick guide. Come here when something
doesn't behave as described, or when you want a different transport.

---

## Contents

1. [Install the panel](#1-install-the-panel)
2. [HTTPS and firewall](#2-https-and-firewall)
3. [Add a compute node](#3-add-a-compute-node)
4. [Secure the node link](#4-secure-the-node-link)
5. [Sell from your own nodes](#5-sell-from-your-own-nodes)
6. [Upstream reseller APIs](#6-upstream-reseller-apis)
7. [Security model](#7-security-model)
8. [Updating](#8-updating)
9. [Checks and diagnostics](#9-checks-and-diagnostics)

---

## 1. Install the panel

### What the box becomes

Three roles exist, and one machine can only sensibly be one of them:

| Role | Runs | Should customers live here? |
| --- | --- | --- |
| **Controller** | panel, database, reseller logic | No |
| **Compute node** | `tgvpanel-node-agent`, LXC/QEMU | Yes |
| **Both** (single-server) | everything | Only for testing |

The installer supports all three. For a real deployment, keep the controller
separate — a customer VM that saturates the panel's disk or network takes your
whole business offline, including the billing.

### What gets installed

`menu.sh` is one script that handles every install mode: Node.js runtime, LXC and
build tools, npm dependencies, a versioned SQLite database, and a systemd unit.
It also generates `.tgvpanel-secret` (0600) on first run, which is the AES key
store for credentials and session secrets.

```bash
curl -fsSL https://raw.githubusercontent.com/sigmaboy6942069/Panel/main/menu.sh -o menu.sh
sudo bash menu.sh
```

### Verifying the install

```bash
sudo systemctl status tgvpanel --no-pager | head -4
sudo journalctl -u tgvpanel -n 20 --no-pager | grep -iE "own-node|Server:"
```

`[own-node] KVM provisioning hook registered` means the reseller engine picked up
the virtualization layer. If that line is missing, own-node selling cannot create
VMs — the rest of the panel still works, but stop and fix it before selling.

The database version should already be at its highest value:

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
console.log(new DatabaseSync('data/tgvpanel.db').prepare('SELECT MAX(version) v FROM schema_migrations').get());
"
```

Migrations run automatically on boot and take a backup first, so a fresh install
lands at the current version with no manual step.

### First login

`admin` / `admin`. Change it before anything else — the default is the same on
every install.

---

## 2. HTTPS and firewall

### Why a proxy rather than TLS in the panel

Keeping certificates in one place (nginx) means renewal, cipher choice and
redirects are a solved problem, and the panel stays a plain HTTP process bound to
loopback where nothing can reach it directly. It also means the panel can be
restarted or crash without dropping TLS.

### DNS first

```bash
dig +short panel.example.com     # must return your VPS IP
```

Certbot validates over HTTP, so the record must resolve **before** you run it.

### The proxy block

The two WebSocket headers matter more than they look:

```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_read_timeout 3600s;
```

Without them the panel loads fine but consoles and shells disconnect the moment
they open. That symptom looks like a bug in the panel; it's the proxy.

### Binding to loopback

```bash
echo 'TGVPANEL_BIND_HOST=127.0.0.1' | sudo tee -a /opt/tgvpanel/.env
```

Default is `0.0.0.0` so a bare install is reachable by IP. Setting loopback means
the only way in is nginx. This also makes the session cookie `Secure`, since the
panel now sees HTTPS via `X-Forwarded-Proto` and `trust proxy`.

### Firewall

| Port | Reason |
| --- | --- |
| 22 | SSH — key-only, disable password auth |
| 80 | ACME challenges and HTTP→HTTPS redirect |
| 443 | The panel |

Everything else closed. Verify the panel port is genuinely invisible:

```bash
curl -m 5 http://YOUR_SERVER_IP:8080/
```

Connection refused is correct.

---

## 3. Add a compute node

### What the agent is

A small HTTPS service that accepts signed instructions: create a container, start
a VM, report stats, open a console. It holds **no database, no customer records,
no billing logic**. Compromise of a node exposes the instances on that node, not
your customer list.

### Installing

```bash
curl -fsSL https://raw.githubusercontent.com/sigmaboy6942069/Panel/main/menu.sh -o menu.sh
sudo bash menu.sh      # choose "remote node agent"
```

Installs Node.js, `lxc`, `lxc-templates`, `uidmap`, `bridge-utils`, `dnsmasq-base`,
`iproute2`, `iptables`/`nftables`, plus QEMU where available. `lxcfs` is
recommended on Ubuntu/Debian so `free -h` and `nproc` inside a container report
the container's own limits rather than the host's:

```bash
sudo apt-get install -y lxcfs
```

### Registering

In **Admin → Nodes → Register Remote Node**, the **Agent URL** is the address the
*panel* will dial. That is the single most common misconfiguration:

- Tunnel mode → `http://127.0.0.1:5055` (step 4 substitutes the real endpoint)
- TLS mode → `https://NODE_PUBLIC_IP:8443`
- WireGuard → `http://10.90.0.2:5055`

The join token is single-use and time-limited. **Pair** on the node row reissues
one without re-registering.

### Pairing

```bash
sudo bash menu.sh --join "https://panel.example.com" "tgv_join_YOUR_TOKEN"
```

Writes the node's ID, API key and HMAC secret into the node's `.env`, sets the
controller URL for outbound heartbeats, and starts the agent.

### How "online" is decided

The agent pushes a signed heartbeat **outbound** to the controller every 45s.
That's independent of inbound connectivity — a node can be fully firewalled and
still report healthy. An `OFFLINE` node therefore usually means a credential or
clock problem, not a network one.

Clock drift beyond ±300s invalidates the HMAC and shows as `HMAC signature
verification failed`. Fix with:

```bash
sudo timedatectl set-ntp true
```

---

## 4. Secure the node link

Four transports. Pick one; the tunnel is the default recommendation for a
homeserver or any box you'd rather not expose.

### Comparison

| | Inbound port | Cert | Auth | Fits |
| --- | --- | --- | --- | --- |
| Self-signed TLS | 8443 | self-signed | HMAC | quick, public IP |
| Let's Encrypt | 8443 | CA | HMAC | node has a domain |
| Mutual TLS | 8443 | mutual | cert + HMAC | strict |
| **SSH tunnel** | **none** | no | SSH key + HMAC | **homeservers** |
| WireGuard | UDP 51820 | no | tunnel + HMAC | private network |

All five keep HMAC signing. None of them are "unauthenticated".

### The SSH tunnel

The controller opens SSH **outbound** and forwards a loopback port to the agent's
loopback address. Two consequences:

1. The node publishes nothing but SSH.
2. No certificate to issue, pin, or renew.

Configured with five variables on the controller:

```ini
TGVPANEL_NODE_TUNNEL_ENABLED=true
TGVPANEL_NODE_SSH_USER=root
TGVPANEL_NODE_SSH_KEY=/opt/tgvpanel/.ssh/node_tunnel
TGVPANEL_NODE_SSH_PORT=22
TGVPANEL_NODE_AGENT_LOOPBACK_PORT=5055
```

Behaviour worth knowing:

- One tunnel per node, opened lazily on first request and **reused**.
- If SSH drops, the tunnel is discarded and rebuilt on the next request.
- Keepalives every 15s detect dead peers.
- The local port is OS-assigned on `127.0.0.1` — nothing predictable to attack.
- The private key lives on disk and is read at runtime; it is never written to
  the database.

Passphrase-protected keys work via `TGVPANEL_NODE_SSH_PASSPHRASE`.

### Self-signed TLS

If you'd rather keep the direct connection:

```ini
TGVPANEL_AGENT_HOST=0.0.0.0
TGVPANEL_AGENT_PORT=8443
TGVPANEL_AGENT_TLS_CERT=/etc/tgvpanel/ssl/agent.crt
TGVPANEL_AGENT_TLS_KEY=/etc/tgvpanel/ssl/agent.key
```

Register `https://NODE_IP:8443`, then use **Test Reachability** to pin the
certificate. Pinning means a swapped certificate is rejected.

### Mutual TLS

Both ends present certificates — the strictest option:

```ini
TGVPANEL_AGENT_TLS_CA=/etc/tgvpanel/ssl/ca.crt
TGVPANEL_NODE_MTLS=true
```

### WireGuard

Same result as the tunnel but at the network layer. Agent binds the tunnel
address only (`TGVPANEL_AGENT_HOST=10.90.0.2`), so the only reachable port is
WireGuard's UDP 51820, from the peer.

Panel `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.90.0.1/24
ListenPort = 51820
PrivateKey = PANEL_PRIVATE_KEY

[Peer]
PublicKey = NODE_PUBLIC_KEY
AllowedIPs = 10.90.0.2/32
```

Node `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.90.0.2/24
PrivateKey = NODE_PRIVATE_KEY

[Peer]
PublicKey = PANEL_PUBLIC_KEY
Endpoint = PANEL_IP:51820
AllowedIPs = 10.90.0.1/32
PersistentKeepalive = 25
```

```bash
sudo systemctl enable --now wg-quick@wg0
```

### Hardening either way

`TGVPANEL_ALLOWED_CONTROLLER_IPS` on the node restricts which source addresses are
accepted at all:

```ini
TGVPANEL_ALLOWED_CONTROLLER_IPS=198.51.100.5
```

---

## 5. Sell from your own nodes

### The reseller model

A **provider** is a source of servers. Two kinds exist and they share one
storefront:

- **Upstream API** — you pay someone else, they pay you. Cost per server = their price.
- **Own nodes** — you pay for hardware. Cost per server = 0.

Plans from both sit in the same catalogue. Customers see one price list.

### Why the local node is cordoned, not deleted

Every install registers itself as a local node, which is what makes
single-server setups work. `deleteNode()` explicitly refuses to remove it:

```ts
if (node.is_local) throw new Error('Cannot delete the built-in localhost controller node.');
```

Container creation and credential recovery both fall back to it, so removal
breaks things subtly rather than loudly. `maintenance_mode = 1` is the supported
way to stop it accepting instances while keeping it functional.

### How capacity becomes plans

Sync walks every node that is online and not in maintenance, checks what engines
it supports, and offers the standard shape ladder for whatever fits. Committed
usage is subtracted first, so a node already hosting two servers doesn't advertise
its full RAM.

Plan IDs are deterministic (`node<id>-<engine>-<cores>c-<ram>g-<disk>g`), which is
why re-syncing updates rows instead of duplicating them, and why your prices and
enable-flags survive.

New plans arrive **disabled**. This is deliberate — syncing should never
accidentally put an unprofitable server on sale.

### Stock

`stock` records how many of each shape still fit. When it reaches zero the plan
shows **sold out** in the store and checkout refuses with `out_of_stock`, rather
than failing halfway through provisioning.

### What happens on an order

1. Wallet is debited and the order row is the lock.
2. The engine resolves the plan's node and engine.
3. **LXC** → `LXCAdapter.createLxcInstance({ provisionOnHost: true })` creates the
   container, assigns an IP, returns the root password.
4. **KVM** → the panel's own VM pipeline (qcow2 + cloud-init seed + boot), wired
   in at boot as a hook.
5. The instance is linked back via `cloud_servers.engine`, `node_id`,
   `instance_ref_id`, `instance_uid`.

From then on, power and status route through the virtualization layer, not an
API. A local server never falls back to HTTP calls.

### Failure handling

Failures are classified:

- **Terminal** (missing LXC tooling, unknown template, node in maintenance) →
  order marked `failed`, reason stored, wallet untouched.
- **Transient** (agent unreachable) → order stays `pending` for retry.

Terminal failures never retry. Without that distinction a node missing
`lxc-create` would loop forever, debiting and refunding.

### Testing before you sell

Buy the cheapest plan yourself. Check `reseller_orders.status = provisioned` **and**
that `cloud_servers.instance_ref_id` points at something real, then exercise
start / stop / restart from the customer side.

A provisioned order with a null `instance_ref_id` means the instance was created
but not linked — worth catching before a customer does.

---

## 6. Upstream reseller APIs

Unchanged from a classic reseller panel: base URL, API key, sync, price, sell.
Multiple providers can coexist, each with its own key, catalogue and orders.

Orders are pinned to the provider they were placed with, so a queued retry always
returns to the same upstream. Idempotency keys prevent double-billing if a
response is lost mid-request.

`GET /account` balances are cached so the dashboard can warn about low credit
without a live call on every page load.

---

## 7. Security model

| Layer | Mechanism |
| --- | --- |
| Transport to browser | TLS at nginx, HSTS |
| Session | `Secure`, `HttpOnly`, `SameSite=Lax` cookie |
| CSRF | token or verified origin on all mutations |
| Login | 10 failures / IP / 15 min, cleared on success |
| Headers | CSP, `X-Frame-Options: DENY`, COOP, Permissions-Policy |
| At rest | AES-256-GCM via `.tgvpanel-secret` |
| Node transport | HMAC-SHA256, ±300s replay window |
| Node identity | per-node API key + HMAC secret |
| Tunnel | SSH key, outbound only |

### The `.tgvpanel-secret` file

Holds the session secret, CSRF secret and credential encryption key. Lose it and
every stored credential becomes unreadable — node API keys, customer passwords,
upstream API keys. Treat it like a private key:

```bash
sudo cp /opt/tgvpanel/.tgvpanel-secret /root/backup/tgvpanel-secret-$(date +%F)
sudo chmod 600 /root/backup/tgvpanel-secret-*
```

One exception: if it's missing, the panel regenerates a new one, but existing
encrypted values can no longer be decrypted. Node credentials get re-issued
automatically; customer passwords and upstream keys do not.

### Known limits

- The panel trusts `X-Forwarded-For` when `trust proxy` is on. Keep nginx as the
  only thing that can reach port 8080, or the rate limiter becomes spoofable.
- CSP allows `'unsafe-inline'` because the templates use inline handlers. Removing
  that would need a nonce refactor across every view.
- Node compromise exposes that node's instances. It does not expose billing,
  customers, or other nodes' credentials.

---

## 8. Updating

```bash
cd /opt/tgvpanel
sudo ./scripts/sync-from-github.sh main --dry-run
sudo ./scripts/sync-from-github.sh main
```

The script stops the service, takes a WAL-safe backup with `VACUUM INTO`, verifies
it, then fast-forwards code and migrates. If the backup fails it aborts before
touching anything.

### Why the usual git commands are dangerous here

`data/tgvpanel.db` is **tracked**. So:

| Command | What it does to your data |
| --- | --- |
| `git reset --hard` | reverts the DB to the empty starter copy |
| `git clean -fdx` | deletes `data/` and your secrets |
| `git checkout -- data/` | same as reset, for the database only |
| `git stash` | stashes the live DB, replaces it with the repo copy |

That last one is easy to run by accident while "just tidying up". If you already
did, the data is still in the stash — recover with:

```bash
git checkout 'stash@{0}' -- data/tgvpanel.db
```

### Manual migration

```bash
cd /opt/tgvpanel
sudo npm run migrate
```

Safe to run repeatedly; already-applied migrations are skipped.

### Never edit a migration that has shipped

`runMigrations` stamps a checksum of `version:name`. Changing an applied migration
means the code and database disagree. Add a new version instead.

---

## 9. Checks and diagnostics

### Health at a glance

```bash
sudo systemctl status tgvpanel --no-pager | head -4
sudo journalctl -u tgvpanel -n 50 --no-pager | grep -iE "error|own-node"
```

### Database state

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync('data/tgvpanel.db');
const q=(s)=>d.prepare(s).all();
console.log('schema   ', q('SELECT MAX(version) v FROM schema_migrations'));
console.log('nodes    ', q('SELECT id,name,status,maintenance_mode FROM nodes'));
console.log('orders   ', q('SELECT id,status,error_code FROM reseller_orders ORDER BY id DESC LIMIT 5'));
console.log('servers  ', q('SELECT id,name,engine,node_id,instance_ref_id FROM cloud_servers'));
"
```

### What the numbers should look like

| Check | Healthy |
| --- | --- |
| schema version | 14 |
| node status | `online`, `maintenance_mode = 0` for sellable nodes |
| local node | `maintenance_mode = 1` |
| order status | `provisioned` (or `pending` briefly) |
| `instance_ref_id` | non-null on provisioned servers |

### Common failures

**`HMAC signature verification failed`** — clock drift. Enable NTP on the node.

**`Invalid node API key`** — credentials rotated or `.tgvpanel-secret` changed.
Re-pair the node.

**`DEPTH_ZERO_SELF_SIGNED_CERT`** — panel refusing a self-signed agent cert. Pin
it via Test Reachability, or switch to the tunnel.

**`Circuit breaker OPEN`** — the panel backed off after repeated failures. Fix the
cause, then reset:

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync('data/tgvpanel.db');
d.prepare(\"UPDATE nodes SET circuit_state='closed', consecutive_failures=0\").run();
"
```

**Console disconnects instantly** — missing WebSocket headers in nginx, or
WebSockets disabled at Cloudflare.

**Login returns 429** — rate limit tripped. Wait 15 minutes or restart the panel.

**`GLIBC_2.38 not found` on sqlite3** — the prebuilt binary is too new. Rebuild:

```bash
sudo npm_config_nodedir=/usr/local node node_modules/node-gyp/bin/node-gyp.js rebuild --build-from-source
```

Or copy a working `node_modules` from another install of the same version.

### Recovery

Restore a database backup:

```bash
cd /opt/tgvpanel
sudo systemctl stop tgvpanel
ls -lt data/backups/pre_migration_*.db | head -3
sudo cp data/backups/pre_migration_v6_XXXX.db data/tgvpanel.db
sudo rm -f data/tgvpanel.db-wal data/tgvpanel.db-shm
sudo systemctl start tgvpanel
```

Manual backup at any time:

```bash
cd /opt/tgvpanel
sudo sqlite3 data/tgvpanel.db "VACUUM INTO 'data/backups/manual_$(date +%F_%H%M).db'"
```
