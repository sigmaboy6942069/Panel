# TGVPANEL — Detailed Reference

Explanations, options and troubleshooting. For the command sequence, use
**[SETUP_QUICK.md](SETUP_QUICK.md)**.

---

## Contents

1. [Architecture](#1-architecture)
2. [Ports and firewall](#2-ports-and-firewall)
3. [Node transports](#3-node-transports)
4. [WireGuard](#4-wireguard)
5. [Node agent environment](#5-node-agent-environment)
6. [Migrations](#6-migrations)
7. [Troubleshooting](#7-troubleshooting)
8. [Recovery](#8-recovery)

---

## 1. Architecture

```
Browser ──HTTPS──> nginx ──HTTP loopback──> Panel (Node.js) ──> SQLite
                                                  │
                                    ┌─────────────┴─────────────┐
                                    │                           │
                              upstream reseller           compute nodes
                              (someone else's API)     (your KVM/LXC hosts)
```

Two independent things can supply servers:

- **Upstream reseller API** — you buy from another host and resell. Requires a
  base URL + API key.
- **Own nodes** — you run the hardware. Requires a node with the agent
  installed. Orders create real instances on that node.

Both appear in one storefront. A customer cannot tell which is which.

The **panel never needs to run on a compute node**, and a compute node never
runs the panel — it runs `tgvpanel-node-agent` only.

---

## 2. Ports and firewall

| Port | Where | Purpose | Expose publicly? |
| --- | --- | --- | --- |
| 22 | panel, node | SSH admin | Yes, ideally key-only |
| 80 | panel | ACME + redirect | Yes |
| 443 | panel | HTTPS panel | Yes |
| 8080 | panel | Panel itself | **No** — bind to loopback |
| 8443 | node | Agent (TLS mode) | Only to the panel IP |
| 5055 | node | Agent (tunnel mode) | **No** — loopback only |
| 2222 | panel | Customer VM SSH | Only if selling VMs |
| 80/443 | node | Customer VMs | Per your offering |

Minimum safe set: **22, 80, 443 on the panel**; **22 on nodes**.

```bash
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw enable
```

Lock the agent to the panel only, if using TLS mode:

```bash
sudo ufw allow from PANEL_IP to any port 8443 proto tcp
```

---

## 3. Node transports

Four ways for the panel to reach a node agent.

### A. Self-signed TLS *(public IP node)*

Fastest. Panel pins the certificate.

On the node:

```ini
TGVPANEL_AGENT_HOST=0.0.0.0
TGVPANEL_AGENT_PORT=8443
TGVPANEL_AGENT_TLS_CERT=/etc/tgvpanel/ssl/agent.crt
TGVPANEL_AGENT_TLS_KEY=/etc/tgvpanel/ssl/agent.key
```

Register with Agent URL `https://NODE_IP:8443` and pin the cert via
**Test Reachability**.

### B. Let's Encrypt *(node has a domain)*

Node cert issued by a real CA; no pinning needed.

```ini
TGVPANEL_AGENT_TLS_CERT=/etc/letsencrypt/live/node.example.com/fullchain.pem
TGVPANEL_AGENT_TLS_KEY=/etc/letsencrypt/live/node.example.com/privkey.pem
```

### C. Mutual TLS *(strictest of the TLS options)*

Both sides present certificates.

```ini
TGVPANEL_AGENT_TLS_CERT=/etc/tgvpanel/ssl/agent.crt
TGVPANEL_AGENT_TLS_KEY=/etc/tgvpanel/ssl/agent.key
TGVPANEL_AGENT_TLS_CA=/etc/tgvpanel/ssl/ca.crt
TGVPANEL_NODE_MTLS=true
```

### D. SSH tunnel *(no inbound port)*

The panel opens an SSH connection **outbound** and forwards a loopback port to
the agent. The node accepts nothing but SSH.

Controller:

```ini
TGVPANEL_NODE_TUNNEL_ENABLED=true
TGVPANEL_NODE_SSH_USER=root
TGVPANEL_NODE_SSH_KEY=/opt/tgvpanel/.ssh/node_tunnel
TGVPANEL_NODE_SSH_PORT=22
TGVPANEL_NODE_AGENT_LOOPBACK_PORT=5055
```

Node:

```ini
TGVPANEL_AGENT_HOST=127.0.0.1
TGVPANEL_AGENT_PORT=5055
```

Register with Agent URL `http://127.0.0.1:5055`. The panel substitutes its
tunnel endpoint automatically.

Behaviour:

- One tunnel per node, opened on first request and reused.
- Rebuilt automatically if SSH drops.
- Optional passphrase via `TGVPANEL_NODE_SSH_PASSPHRASE`.

Requests remain HMAC-signed either way, so the tunnel adds a layer rather than
replacing authentication.

### Comparison

| | Inbound port | Cert needed | Key auth | Best for |
| --- | --- | --- | --- | --- |
| A. Self-signed TLS | 8443 | self-signed | HMAC | public IP, quick |
| B. Let's Encrypt | 8443 | CA | HMAC | node has a domain |
| C. mTLS | 8443 | mutual | cert + HMAC | strictest |
| D. SSH tunnel | **none** | no | SSH key | **homeservers, max security** |

---

## 4. WireGuard

Zero public ports, same as the SSH tunnel but at the network layer.

```bash
sudo apt install -y wireguard
```

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

Node agent binds to the tunnel address only:

```ini
TGVPANEL_AGENT_HOST=10.90.0.2
TGVPANEL_AGENT_PORT=5055
```

Register with Agent URL `http://10.90.0.2:5055`. Only UDP 51820 is reachable,
and only by the peer.

---

## 5. Node agent environment

`/opt/tgvpanel/.env` on a compute node.

| Variable | Default | Notes |
| --- | --- | --- |
| `TGVPANEL_NODE_ID` | — | From registration |
| `TGVPANEL_AGENT_HOST` | `0.0.0.0` | Use `127.0.0.1` for tunnel mode |
| `TGVPANEL_AGENT_PORT` | `8443` | `5055` for tunnel mode |
| `TGVPANEL_NODE_API_KEY` | — | From registration |
| `TGVPANEL_NODE_HMAC_SECRET` | — | From registration |
| `TGVPANEL_CONTROLLER_URL` | — | Panel URL, enables outbound heartbeat |
| `TGVPANEL_CONTROLLER_VERIFY_SSL` | `false` | `true` with a valid CA cert |
| `TGVPANEL_AGENT_TLS_CERT` | — | Enables HTTPS |
| `TGVPANEL_AGENT_TLS_KEY` | — | |
| `TGVPANEL_AGENT_TLS_CA` | — | For mTLS |
| `TGVPANEL_NODE_MTLS` | `false` | Require client certs |
| `TGVPANEL_ALLOWED_CONTROLLER_IPS` | — | Comma-separated allowlist |
| `TGVPANEL_DATA_DIR` | `/opt/tgvpanel/data` | |
| `TGVPANEL_LXC_DIR` | `/var/lib/lxc` | |
| `TGVPANEL_BACKUP_DIR` | `/opt/tgvpanel/backups` | |

The agent pushes a signed heartbeat **outbound** to the controller every 45s
when `TGVPANEL_CONTROLLER_URL` is set. This is independent of inbound access and
is what keeps the node marked ONLINE.

---

## 6. Migrations

Versioned, append-only, applied automatically on boot and by `npm run migrate`.

| Version | Adds |
| --- | --- |
| v12 | `reseller_*` tables, `cloud_servers` |
| v13 | `reseller_providers` (multi-provider) |
| v14 | `engine`/`node_id`/`instance_ref_id`/`instance_uid` on `cloud_servers`; `engine`/`node_id`/`lxc_template`/`bridge`/`stock` on `reseller_plans`; `base_url` nullable |

Check the version:

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync('data/tgvpanel.db');
console.log(d.prepare('SELECT MAX(version) v FROM schema_migrations').get());
"
```

A backup is written to `data/backups/` before any pending migration applies.

**Never edit an already-applied migration.** Add a new one.

---

## 7. Troubleshooting

### `HMAC signature verification failed` (401)

Clock drift. The replay guard allows ±300s.

```bash
sudo timedatectl set-ntp true
timedatectl status
```

### `Invalid node API key` (401)

Credentials don't match. Re-register or rotate in **Admin → Nodes**.

### `DEPTH_ZERO_SELF_SIGNED_CERT`

Panel rejecting a self-signed agent cert. Pin it via **Test Reachability**, or
use a CA-signed cert, or use the SSH tunnel.

### `Controller IP not allowlisted` (403)

Add the panel IP to `TGVPANEL_ALLOWED_CONTROLLER_IPS` on the node.

### `Circuit breaker OPEN for node #N`

Too many consecutive failures; the panel is backing off. Fix the underlying
cause, then:

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync('data/tgvpanel.db');
d.prepare('UPDATE nodes SET circuit_state=\'closed\', consecutive_failures=0').run();
"
```

### Console disconnects immediately behind nginx/Cloudflare

WebSocket headers are missing from the proxy block. Ensure:

```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_read_timeout 3600s;
```

Cloudflare needs WebSockets enabled for the zone.

### Login returns 429

Rate limit tripped: 10 failures per IP per 15 minutes. Wait it out, or restart
the panel to clear counters.

### `GLIBC_2.38 not found` when loading sqlite3

The prebuilt binary is too new for the host. Build from source:

```bash
cd /opt/tgvpanel
sudo npm_config_nodedir=/usr/local node node_modules/node-gyp/bin/node-gyp.js rebuild --build-from-source
node -e "require('sqlite3'); console.log('sqlite3 OK')"
```

Keep an existing working `node_modules` if you have one — copying it is faster:

```bash
cp -a /old/install/node_modules /opt/tgvpanel/
```

### Node stuck OFFLINE

```bash
sudo systemctl status tgvpanel-node-agent --no-pager
sudo journalctl -u tgvpanel-node-agent -n 40 --no-pager
ss -lntp | grep -E '5055|8443'
```

Check the agent is listening on the address you registered, and that the
heartbeat reaches the panel.

---

## 8. Recovery

### Restore the database

```bash
cd /opt/tgvpanel
sudo systemctl stop tgvpanel
ls -lt data/backups/pre_migration_*.db | head -3
sudo cp data/backups/pre_migration_v6_XXXX.db data/tgvpanel.db
sudo rm -f data/tgvpanel.db-wal data/tgvpanel.db-shm
sudo systemctl start tgvpanel
```

### Manual backup

```bash
cd /opt/tgvpanel
sudo sqlite3 data/tgvpanel.db "VACUUM INTO 'data/backups/manual_$(date +%F_%H%M).db'"
```

No `sqlite3` CLI:

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync('data/tgvpanel.db');
d.prepare(\"VACUUM INTO 'data/backups/manual_bk.db'\").run();
console.log('backup written');
"
```

### Never do these

```bash
git reset --hard      # reverts data/tgvpanel.db to the empty starter DB
git clean -fdx        # deletes data/ and secrets
git checkout -- data/ # same as reset for the database
```

`data/tgvpanel.db` is tracked, which is why these destroy live data. Use
`scripts/sync-from-github.sh` instead.
