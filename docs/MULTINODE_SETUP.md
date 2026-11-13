# TGVPANEL — Node & Multi-Node Setup

This guide has been split into two documents:

- **[SETUP_QUICK.md](SETUP_QUICK.md)** — the command sequence. Start here.
- **[SETUP_DETAILED.md](SETUP_DETAILED.md)** — architecture, all node transports
  (including the outbound SSH tunnel and WireGuard), environment variables,
  migrations, troubleshooting and recovery.

## Short version

A **compute node** runs only `tgvpanel-node-agent`. It never runs the panel.

The panel can reach a node four ways. The two that expose **no inbound port**:

| Method | Config |
| --- | --- |
| Outbound SSH tunnel | `TGVPANEL_NODE_TUNNEL_ENABLED=true` on the panel; agent on `127.0.0.1:5055` |
| WireGuard | Agent bound to the tunnel IP, e.g. `10.90.0.2:5055` |

Register the node in **Admin → Nodes**, then run the join command on the node:

```bash
curl -fsSL https://raw.githubusercontent.com/sigmaboy6942069/Panel/main/menu.sh -o menu.sh
sudo bash menu.sh --join "https://panel.example.com" "tgv_join_YOUR_TOKEN"
```

Full walkthrough: [SETUP_QUICK.md §3](SETUP_QUICK.md#3-add-a-compute-node).
