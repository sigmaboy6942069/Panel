# TGVPANEL — Quick Start

Compact setup guide. For the reasoning, edge cases and troubleshooting behind
each step, see **[SETUP_DETAILED.md](SETUP_DETAILED.md)**.

---

## 1. Install the panel (controller)

On a fresh Ubuntu/Debian VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/sigmaboy6942069/Panel/main/menu.sh -o menu.sh
sudo bash menu.sh
```

Choose **install controller**. This installs Node.js, LXC, dependencies, and the
`tgvpanel` systemd service.

Verify:

```bash
sudo systemctl status tgvpanel --no-pager | head -4
sudo journalctl -u tgvpanel -n 20 --no-pager | grep -iE "own-node|Server:"
```

Open `http://YOUR_SERVER_IP:8080` and log in as `admin`.

---

## 2. Put the panel behind HTTPS

The panel should not face the internet directly.

```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
```

Point a DNS A record (e.g. `panel.example.com`) at your VPS IP, then:

```bash
sudo tee /etc/nginx/sites-available/tgvpanel > /dev/null <<'EOF'
server {
    listen 80;
    server_name panel.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
sudo ln -sf /etc/nginx/sites-available/tgvpanel /etc/nginx/sites-enabled/tgvpanel
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d panel.example.com --redirect
```

The `Upgrade`/`Connection` lines are required — consoles and shells use
WebSockets.

Then stop the panel listening publicly:

```bash
echo 'TGVPANEL_BIND_HOST=127.0.0.1' | sudo tee -a /opt/tgvpanel/.env
sudo systemctl restart tgvpanel
```

Firewall — allow only SSH, HTTP, HTTPS:

```bash
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw enable && sudo ufw status verbose
```

**Do not open 8080.** Verify from outside that it's closed:

```bash
curl -m 5 http://YOUR_SERVER_IP:8080/    # should fail
```

---

## 3. Add a compute node

A node runs **only the agent**, never the panel. For the tunnel setup below the
node exposes **no inbound port** — only SSH.

### 3a. On the node — install the agent

```bash
curl -fsSL https://raw.githubusercontent.com/sigmaboy6942069/Panel/main/menu.sh -o menu.sh
sudo bash menu.sh
```

Choose **remote node agent / auto-join**.

### 3b. On the panel — register the node

**Admin → Nodes → Register Remote Node**. Fill in:

| Field | Value |
| --- | --- |
| Node name | `home-node-1` |
| IPv4 | node's public IP |
| Agent URL | `http://127.0.0.1:5055` *(tunnel mode)* |
| Datacenter | free text label |

Copy the join token shown after registering.

### 3c. On the node — pair it

```bash
sudo bash menu.sh --join "https://panel.example.com" "tgv_join_YOUR_TOKEN"
```

The node appears **ONLINE** in **Admin → Nodes** within a minute.

---

## 4. Secure the node link (SSH tunnel)

With this enabled the node needs **no inbound port at all** — the panel dials
*out*. Skipping this step means opening `8443` to the internet.

### On the node

```bash
# Agent listens on loopback only
grep -q TGVPANEL_AGENT_HOST /opt/tgvpanel/.env \
  && sudo sed -i 's|^TGVPANEL_AGENT_HOST=.*|TGVPANEL_AGENT_HOST=127.0.0.1|' /opt/tgvpanel/.env \
  || echo 'TGVPANEL_AGENT_HOST=127.0.0.1' | sudo tee -a /opt/tgvpanel/.env
echo 'TGVPANEL_AGENT_PORT=5055' | sudo tee -a /opt/tgvpanel/.env
sudo systemctl restart tgvpanel-node-agent
```

### On the panel

```bash
sudo mkdir -p /opt/tgvpanel/.ssh
sudo ssh-keygen -t ed25519 -f /opt/tgvpanel/.ssh/node_tunnel -N ""
sudo ssh-copy-id -i /opt/tgvpanel/.ssh/node_tunnel.pub root@NODE_IP
sudo chmod 600 /opt/tgvpanel/.ssh/node_tunnel
```

Add to `/opt/tgvpanel/.env`:

```ini
TGVPANEL_NODE_TUNNEL_ENABLED=true
TGVPANEL_NODE_SSH_USER=root
TGVPANEL_NODE_SSH_KEY=/opt/tgvpanel/.ssh/node_tunnel
TGVPANEL_NODE_SSH_PORT=22
TGVPANEL_NODE_AGENT_LOOPBACK_PORT=5055
```

```bash
sudo systemctl restart tgvpanel
```

Confirm the node still reports ONLINE. Firewall on the node needs only SSH:

```bash
sudo ufw allow 22/tcp && sudo ufw enable && sudo ufw status
```

> Alternative with the same result: WireGuard. See
> [SETUP_DETAILED.md](SETUP_DETAILED.md#wireguard).

---

## 5. Sell servers from your own nodes

### 5a. Cordon the panel's own node

The panel VPS is registered as a local node. It should not host customer
servers:

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync('data/tgvpanel.db');
d.prepare('UPDATE nodes SET maintenance_mode = 1 WHERE is_local = 1').run();
console.log(d.prepare('SELECT id,name,is_local,maintenance_mode FROM nodes').all());
"
sudo systemctl restart tgvpanel
```

### 5b. Create an own-node provider

**Admin → Reseller → Providers → Add provider**

1. **Where do these servers come from** → *My own nodes (I run KVM/LXC myself)*
2. Name it, save. No API key needed.
3. Click **sync** — your node's capacity becomes plans, **disabled**.
4. Set prices, enable the plans you want to sell.

**Discover capacity** (provider Settings tab) shows what's sellable right now.

Shapes offered per node/engine:

```
1c/2G/20G    2c/4G/40G
1c/4G/40G    4c/8G/80G
2c/2G/20G    8c/16G/160G
```

When a node fills up, plans show **sold out** instead of failing at checkout.

### 5c. Test one order

Buy the cheapest plan yourself before opening the store. Check:

- The panel creates a real instance on your node
- It gets an IP and boots
- Start / stop / restart work from the customer dashboard

If provisioning fails, the order is marked `failed` and **the wallet is not
charged**.

---

## 6. Sell from an upstream reseller API

**Admin → Reseller → Providers → Add provider**, leave the type as
*Upstream reseller API*, then enter the base URL and API key.

Sync the catalogue, set retail prices, enable plans. The storefront shows one
catalogue with both resold and own-node plans side by side.

---

## 7. Security defaults

Already on, no action needed:

| Protection | Detail |
| --- | --- |
| Login lockout | 10 failures per IP per 15 min |
| CSRF | enforced on all state-changing requests |
| Security headers | CSP, `X-Frame-Options: DENY`, COOP, Permissions-Policy |
| HSTS | sent over HTTPS |
| Session cookie | `Secure` over HTTPS, `HttpOnly`, `SameSite=Lax` |
| Credentials | AES-256-GCM at rest in `.tgvpanel-secret` |
| Node requests | HMAC-SHA256 signed, ±300s replay guard |

Tunable in `/opt/tgvpanel/.env`:

```ini
TGVPANEL_LOGIN_MAX_FAILURES=10
TGVPANEL_LOGIN_WINDOW_MS=900000
TGVPANEL_BIND_HOST=127.0.0.1
```

---

## 8. Updating

```bash
cd /opt/tgvpanel
sudo ./scripts/sync-from-github.sh main
```

Stops the service, backs up the database, fast-forwards code, migrates, restarts.
Preview first with `--dry-run`.

Never use `git reset --hard` or `git clean -fdx` — `data/tgvpanel.db` is tracked
and will be reverted to the empty starter database.

---

## 9. Quick checks

```bash
# Panel healthy?
sudo systemctl status tgvpanel --no-pager | head -4

# Migration version (want 14)
cd /opt/tgvpanel && node -e "const{DatabaseSync}=require('node:sqlite');console.log(new DatabaseSync('data/tgvpanel.db').prepare('SELECT MAX(version) v FROM schema_migrations').get())"

# Own-node hook registered?
sudo journalctl -u tgvpanel -n 50 --no-pager | grep -i own-node

# Nodes online
cd /opt/tgvpanel && node -e "const{DatabaseSync}=require('node:sqlite');console.log(new DatabaseSync('data/tgvpanel.db').prepare('SELECT id,name,status,maintenance_mode FROM nodes').all())"

# Installer command points at YOUR repo
curl -s -c /tmp/c.txt -X POST http://127.0.0.1:8080/api/login -H "Content-Type: application/json" -d '{"username":"admin","password":"admin"}' -o /dev/null
curl -s -b /tmp/c.txt http://127.0.0.1:8080/admin/nodes | grep -o 'nodeQuickInstallCmd">[^<]*'
```

---

## Something wrong?

See **[SETUP_DETAILED.md](SETUP_DETAILED.md)** for:

- Firewall and port reference
- Node agent environment variables
- Troubleshooting (clock skew, cert errors, circuit breaker, WebSocket drops)
- WireGuard alternative
- Restoring a database backup
