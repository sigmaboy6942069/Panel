# TGVPANEL — Quick Start

Nine steps, in order. Each has the commands plus a short note on *why*.

Deeper explanations (all transports, env vars, troubleshooting, recovery) live in
**[SETUP_DETAILED.md](SETUP_DETAILED.md)** — but you don't need it to get running.

**What you end up with:** a panel on your VPS, reachable only over HTTPS, plus
compute nodes that host customer servers. The panel and the nodes are separate
machines — the panel never runs on a customer's host.

---

## 1. Install the panel

Run this on a fresh Ubuntu/Debian VPS. This box becomes your **controller** — it
runs the web panel and the database, *not* customer servers.

```bash
curl -fsSL https://raw.githubusercontent.com/sigmaboy6942069/Panel/main/menu.sh -o menu.sh
sudo bash menu.sh
```

Choose **install controller** when prompted. It installs Node.js, LXC,
dependencies, and registers the `tgvpanel` systemd service.

Check it came up:

```bash
sudo systemctl status tgvpanel --no-pager | head -4
sudo journalctl -u tgvpanel -n 20 --no-pager | grep -iE "own-node|Server:"
```

Two lines matter: `Active: active (running)` and
`[own-node] KVM provisioning hook registered`.

Open `http://YOUR_SERVER_IP:8080`, log in as `admin`, and **change the password
immediately** — the default is `admin`/`admin`.

> **Why not just stop here?** Port 8080 is plain HTTP. Your password and session
> cookie cross the internet in the clear. Step 2 fixes that.

---

## 2. Put the panel behind HTTPS

A TLS proxy sits in front of the panel. The proxy holds the certificate; the
panel only listens on loopback.

```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
```

**Before continuing**, point an A record at your VPS — e.g. `panel.example.com`.
Let's Encrypt will not issue a certificate for a bare IP.

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

The two `Upgrade`/`Connection` lines are not optional — the browser console and
shell sessions are WebSockets and silently break without them.

From here the panel answers on `https://panel.example.com` through nginx.

Firewall — three ports, that's all the panel needs:

```bash
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw enable && sudo ufw status verbose
```

Confirm the domain works:

```bash
curl -m 5 -I https://panel.example.com/
```

### Optional: close port 8080 to the outside

Right now nginx reaches the panel on `127.0.0.1:8080`, but the panel also
listens on every other interface, so `http://YOUR_SERVER_IP:8080` answers too.
That's plain HTTP — your password crosses the network in the clear.

**Leave it open if you plan to put a Cloudflare Tunnel or another reverse proxy
in front** — those reach the panel over `0.0.0.0` and will break on loopback.
Close it only when nginx on this same machine is your only front door:

```bash
echo 'TGVPANEL_BIND_HOST=127.0.0.1' | sudo tee -a /opt/tgvpanel/.env
sudo systemctl restart tgvpanel
curl -m 5 http://YOUR_SERVER_IP:8080/     # should now fail to connect
```

To undo it later — for example when you switch to a tunnel — delete the line:

```bash
sudo sed -i '/^TGVPANEL_BIND_HOST=/d' /opt/tgvpanel/.env
sudo systemctl restart tgvpanel
```

---

## 3. Add a compute node

A **node** is a machine that runs customer servers. It runs
`tgvpanel-node-agent` only — never the panel. A homeserver or a rented dedicated
box both work; it needs root and a public IP (or SSH access).

### 3a. On the node — install the agent

```bash
curl -fsSL https://raw.githubusercontent.com/sigmaboy6942069/Panel/main/menu.sh -o menu.sh
sudo bash menu.sh
```

Choose **remote node agent / auto-join**. This installs Node.js, LXC, KVM tooling
if available, and the agent service. It does **not** create a panel or a database.

### 3b. On the panel — register the node

**Admin → Nodes → Register Remote Node**:

| Field | Value |
| --- | --- |
| Node name | `home-node-1` |
| IPv4 | the node's public IP |
| Agent URL | `http://127.0.0.1:5055` *(tunnel mode)* |
| Datacenter | free text, e.g. `Home, BE` |
| Allowed engines | tick KVM and/or LXC |

Click **Register Node** and copy the `tgv_join_...` token it shows. It's
single-use and expires — if you lose it, the **Pair** button reissues one.

### 3c. On the node — pair it

```bash
sudo bash menu.sh --join "https://panel.example.com" "tgv_join_YOUR_TOKEN"
```

This redeems the token and stamps the node's identity into its `.env`.

Within a minute the node should show **ONLINE** in **Admin → Nodes**. If it
doesn't, jump to [troubleshooting](SETUP_DETAILED.md#how-online-is-decided) — don't
continue, nothing downstream will work.

---

## 4. Secure the node link

**This is the step that keeps ports closed.** Normally a node listens on public
`8443` for the panel to call in. With the SSH tunnel the direction flips: the
panel connects **out** over SSH and forwards a local port to the agent, so the
node accepts nothing but SSH.

If the panel can already reach the node over a private network (WireGuard, LAN),
skip this — see [WireGuard](SETUP_DETAILED.md#4-secure-the-node-link) instead.

### On the node — listen on loopback only

```bash
sudo sed -i 's|^TGVPANEL_AGENT_HOST=.*|TGVPANEL_AGENT_HOST=127.0.0.1|' /opt/tgvpanel/.env
grep -q '^TGVPANEL_AGENT_PORT=' /opt/tgvpanel/.env \
  || echo 'TGVPANEL_AGENT_PORT=5055' | sudo tee -a /opt/tgvpanel/.env
sudo sed -i 's|^TGVPANEL_AGENT_PORT=.*|TGVPANEL_AGENT_PORT=5055|' /opt/tgvpanel/.env
sudo systemctl restart tgvpanel-node-agent
```

Check it's no longer public — you want `127.0.0.1:5055`, not `0.0.0.0`:

```bash
ss -lntp | grep 5055
```

### On the panel — generate a key and authorize it

```bash
sudo mkdir -p /opt/tgvpanel/.ssh
sudo ssh-keygen -t ed25519 -f /opt/tgvpanel/.ssh/node_tunnel -N ""
sudo ssh-copy-id -i /opt/tgvpanel/.ssh/node_tunnel.pub root@NODE_IP
sudo chmod 600 /opt/tgvpanel/.ssh/node_tunnel
```

Test the key works before wiring it in:

```bash
sudo ssh -i /opt/tgvpanel/.ssh/node_tunnel -o BatchMode=yes root@NODE_IP true && echo "key OK"
```

### On the panel — enable the tunnel

```bash
sudo tee -a /opt/tgvpanel/.env > /dev/null <<'EOF'
TGVPANEL_NODE_TUNNEL_ENABLED=true
TGVPANEL_NODE_SSH_USER=root
TGVPANEL_NODE_SSH_KEY=/opt/tgvpanel/.ssh/node_tunnel
TGVPANEL_NODE_SSH_PORT=22
TGVPANEL_NODE_AGENT_LOOPBACK_PORT=5055
EOF
sudo systemctl restart tgvpanel
```

Confirm the node still reads **ONLINE**. Then close the agent port on the node's
firewall if you ever opened it:

```bash
sudo ufw allow 22/tcp && sudo ufw enable && sudo ufw status
```

**Result:** the node exposes SSH and nothing else. Requests stay HMAC-signed, so
this adds a layer rather than replacing authentication.

---

## 5. Sell servers from your own nodes

### 5a. Cordon the panel's own node

The panel registers itself as a "local node" so single-server installs work. You
don't want customers on your panel VPS, so put it in maintenance — it keeps
working for administration but accepts no new instances.

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync('data/tgvpanel.db');
d.prepare('UPDATE nodes SET maintenance_mode = 1 WHERE is_local = 1').run();
console.log(d.prepare('SELECT id,name,is_local,maintenance_mode FROM nodes').all());
"
sudo systemctl restart tgvpanel
```

The local node **cannot be deleted** — the code refuses, because LXC creation and
credential setup fall back to it. Maintenance mode is the supported way to take
it out of service.

### 5b. Create an own-node provider

**Admin → Reseller → Providers → Add provider**

1. **Where do these servers come from** → *My own nodes (I run KVM/LXC myself)*
2. Give it a name, save. No API key or URL — there's no upstream.
3. Click **sync**. Your node's free capacity becomes plans, **disabled**.
4. Set your retail prices, then enable the plans you want to sell.

Sync offers these shapes, skipping anything that won't fit on the node:

```
1 vCPU / 2 GB / 20 GB      2 vCPU / 4 GB / 40 GB
1 vCPU / 4 GB / 40 GB      4 vCPU / 8 GB / 80 GB
2 vCPU / 2 GB / 20 GB      8 vCPU / 16 GB / 160 GB
```

Plans are named `node<id>-<engine>-<cores>c-<ram>g-<disk>g`, so re-syncing
updates the same rows instead of duplicating them, and your prices survive.

The provider's Settings tab has **Discover capacity** — shows what's sellable
right now, before you sync.

### 5c. Test one order

Buy the cheapest plan yourself before opening the store. Then verify:

```bash
cd /opt/tgvpanel && node -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync('data/tgvpanel.db');
console.log(d.prepare('SELECT id,status,error_code FROM reseller_orders ORDER BY id DESC LIMIT 3').all());
console.log(d.prepare('SELECT id,name,engine,node_id,instance_ref_id FROM cloud_servers').all());
"
```

A good order is `status: provisioned` with a `cloud_servers` row that has a real
`instance_ref_id`. Then log in as the customer and test start / stop / restart.

If provisioning fails, the order is marked `failed`, the reason is recorded, and
**the wallet is not charged** — so a broken node can't quietly eat money.

---

## 6. Sell from an upstream reseller API

Optional — only if you also resell someone else's servers.

**Admin → Reseller → Providers → Add provider**, leave the type as
*Upstream reseller API*, and enter the base URL and API key. Sync, price,
enable. Both kinds of provider appear in one storefront; customers can't tell
which is which.

---

## 7. Security defaults

Already on, nothing to configure:

| Protection | Behaviour |
| --- | --- |
| Login lockout | 10 failures per IP, then 15 min block |
| CSRF | enforced on every state-changing request |
| Headers | CSP, `X-Frame-Options: DENY`, COOP, Permissions-Policy |
| HSTS | sent over HTTPS |
| Session cookie | `Secure` over HTTPS, `HttpOnly`, `SameSite=Lax` |
| Secrets | AES-256-GCM at rest in `.tgvpanel-secret` |
| Node requests | HMAC-SHA256 + ±300s replay guard |

Adjustable in `/opt/tgvpanel/.env`:

```ini
TGVPANEL_LOGIN_MAX_FAILURES=10
TGVPANEL_LOGIN_WINDOW_MS=900000
```

`TGVPANEL_BIND_HOST` is **not set by default** and the panel listens on
`0.0.0.0`. Only add it if you are closing 8080 behind a local proxy — see step 2.
Setting it to `127.0.0.1` while a tunnel or remote proxy is in front will make
the panel unreachable.

Keep `.tgvpanel-secret` — it decrypts stored credentials and session secrets. If
you lose it, node keys and stored passwords become unreadable. Back it up, never
commit it.

### Optional: 2FA and social login

Both are off by default. If you want them:

- **2FA** — sign in, open **Profile → Two-Factor Authentication → Set up**,
  scan the code, save the 10 recovery codes. Do this for your admin account
  at minimum.
- **Google / Discord / GitHub login** — **Admin → Settings → Sign-in**.
  Each provider needs a client ID and secret from its own developer console,
  plus the redirect URI the panel shows you.

Full walkthrough, including how accounts get linked and what to do when someone
is locked out: **[AUTH_AND_SIGNIN.md](AUTH_AND_SIGNIN.md)**.

---

## 8. Updating

```bash
cd /opt/tgvpanel
sudo ./scripts/sync-from-github.sh main --dry-run   # preview
sudo ./scripts/sync-from-github.sh main             # apply
```

Stops the service, backs up the database (verified before it proceeds),
fast-forwards code, runs migrations, restarts.

**Never** run `git reset --hard`, `git clean -fdx`, or `git checkout -- data/` —
`data/tgvpanel.db` is tracked by git, so those revert your live database to the
empty starter copy. The sync script exists precisely to avoid this.

---

## 9. Quick checks

```bash
# Panel running?
sudo systemctl status tgvpanel --no-pager | head -4

# Schema version — want 14
cd /opt/tgvpanel && node -e "const{DatabaseSync}=require('node:sqlite');console.log(new DatabaseSync('data/tgvpanel.db').prepare('SELECT MAX(version) v FROM schema_migrations').get())"

# Own-node hook registered?
sudo journalctl -u tgvpanel -n 50 --no-pager | grep -i own-node

# Node states (maintenance_mode 1 = cordoned)
cd /opt/tgvpanel && node -e "const{DatabaseSync}=require('node:sqlite');console.log(new DatabaseSync('data/tgvpanel.db').prepare('SELECT id,name,status,maintenance_mode FROM nodes').all())"

# Installer command points at your repo
curl -s -c /tmp/c.txt -X POST http://127.0.0.1:8080/api/login \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"admin"}' -o /dev/null
curl -s -b /tmp/c.txt http://127.0.0.1:8080/admin/nodes | grep -o 'nodeQuickInstallCmd">[^<]*'
```

That last one should print a URL containing `sigmaboy6942069/Panel`.

---

## When something breaks

**[SETUP_DETAILED.md](SETUP_DETAILED.md)** has the answers:

- [Choosing a node transport](SETUP_DETAILED.md#4-secure-the-node-link) — TLS,
  self-signed, mTLS, SSH tunnel, WireGuard compared
- [Why a node shows offline](SETUP_DETAILED.md#how-online-is-decided)
- [Common failures](SETUP_DETAILED.md#common-failures) — clock skew, cert errors,
  circuit breaker, WebSocket drops, 429s, GLIBC build failures
- [Recovery](SETUP_DETAILED.md#recovery) — restoring a database backup
- [Security model and known limits](SETUP_DETAILED.md#7-security-model)
