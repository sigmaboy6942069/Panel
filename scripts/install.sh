#!/usr/bin/env bash
# ==============================================================================
# TGVPANEL — Unified Virtualization Control Panel Installer (QEMU/KVM + LXC)
# Supports: Ubuntu 22.04/24.04, Debian 12/13, AlmaLinux/Rocky 9
# Modes:
#   1) Unified Panel + KVM + LXC (Single-Server / Master + Local Compute)
#   2) Unified Panel + KVM Only
#   3) Unified Panel + LXC Only
#   4) Standalone Remote Node Agent Only
# ==============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${TGVPANEL_INSTALL_MODE:-${HKVM_INSTALL_MODE:-auto}}"
PANEL_PORT="${PORT:-8080}"
AGENT_PORT="${AGENT_PORT:-8443}"
NONINTERACTIVE="${TGVPANEL_NONINTERACTIVE:-${HKVM_NONINTERACTIVE:-0}}"

log()  { printf "\033[1;34m[TGVPANEL-INSTALL]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[  OK  ]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[ WARN ]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[ERROR ]\033[0m %s\n" "$*" >&2; }

detect_capabilities() {
  log "Scanning host hardware & kernel virtualization capabilities..."
  HAS_KVM=0
  HAS_QEMU=0
  HAS_LXC=0
  HAS_CGROUPV2=0

  [[ -e /dev/kvm ]] && HAS_KVM=1
  command -v qemu-system-x86_64 >/dev/null 2>&1 && HAS_QEMU=1
  command -v lxc-create >/dev/null 2>&1 && HAS_LXC=1
  [[ -f /sys/fs/cgroup/cgroup.controllers ]] && HAS_CGROUPV2=1

  echo "------------------------------------------------------------"
  echo "  Host Kernel      : $(uname -sr)"
  echo "  Architecture     : $(uname -m)"
  echo "  /dev/kvm         : $([[ $HAS_KVM -eq 1 ]] && echo 'AVAILABLE' || echo 'NOT DETECTED (nested virt / container)')"
  echo "  QEMU/KVM Tools   : $([[ $HAS_QEMU -eq 1 ]] && echo 'INSTALLED' || echo 'MISSING')"
  echo "  Native LXC Tools : $([[ $HAS_LXC -eq 1 ]] && echo 'INSTALLED' || echo 'MISSING')"
  echo "  Cgroups v2       : $([[ $HAS_CGROUPV2 -eq 1 ]] && echo 'ACTIVE' || echo 'LEGACY/PARTIAL')"
  echo "------------------------------------------------------------"
}

install_os_packages() {
  local role="$1"
  if [[ "${SKIP_OS_PACKAGES:-0}" == "1" ]]; then
    warn "Skipping OS package installation (SKIP_OS_PACKAGES=1)."
    return 0
  fi

  if [[ $EUID -ne 0 ]]; then
    warn "Not running as root; skipping apt/dnf system package installation."
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y curl ca-certificates gnupg build-essential python3 make g++ sqlite3 tar iproute2 iptables nftables openssl

    if [[ "$role" == "unified" || "$role" == "kvm" ]]; then
      apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils genisoimage bridge-utils || warn "Some KVM packages could not be installed."
    fi
    if [[ "$role" == "unified" || "$role" == "lxc" || "$role" == "agent" ]]; then
      apt-get install -y lxc lxc-templates uidmap bridge-utils dnsmasq-base || warn "Some LXC packages could not be installed."
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates gcc gcc-c++ make python3 sqlite tar iproute iptables nftables openssl
    if [[ "$role" == "unified" || "$role" == "kvm" ]]; then
      dnf install -y qemu-kvm qemu-img genisoimage || warn "Some KVM packages could not be installed."
    fi
    if [[ "$role" == "unified" || "$role" == "lxc" || "$role" == "agent" ]]; then
      dnf install -y lxc lxc-templates || warn "Some LXC packages could not be installed."
    fi
  fi
}

ensure_node_and_deps() {
  if ! command -v node >/dev/null 2>&1; then
    err "Node.js 20+ is required. Install Node.js 20 LTS or 22 LTS and re-run."
    exit 1
  fi
  ok "Detected Node.js $(node -v) & npm $(npm -v)"

  cd "$APP_DIR"
  if [[ -d /usr/local/include/node ]]; then
    export npm_config_nodedir="/usr/local"
  fi

  if [[ ! -d node_modules ]]; then
    log "Installing Node.js dependencies..."
    npm install
  fi

  # Bundle xterm frontend assets locally
  mkdir -p public/vendor/xterm
  [[ -f node_modules/@xterm/xterm/lib/xterm.js ]] && cp -f node_modules/@xterm/xterm/lib/xterm.js public/vendor/xterm/xterm.js
  [[ -f node_modules/@xterm/xterm/css/xterm.css ]] && cp -f node_modules/@xterm/xterm/css/xterm.css public/vendor/xterm/xterm.css
  [[ -f node_modules/@xterm/addon-fit/lib/addon-fit.js ]] && cp -f node_modules/@xterm/addon-fit/lib/addon-fit.js public/vendor/xterm/addon-fit.js

  log "Compiling TGVPANEL TypeScript services..."
  npm run build
  ok "TypeScript build succeeded."
}

init_secrets_and_db() {
  cd "$APP_DIR"
  mkdir -p data data/backups data/instance-backups "$HOME/vms/iso" "$HOME/vms/cloudvm"

  if [[ ! -f .env && -f .env.example ]]; then
    cp .env.example .env
    chmod 600 .env
    ok "Created .env from .env.example (0600)."
  fi

  if [[ -f .hkvm-secret && ! -f .tgvpanel-secret ]]; then
    mv .hkvm-secret .tgvpanel-secret
  fi

  log "Initializing .tgvpanel-secret vault & running versioned SQLite migrations..."
  npm run migrate
  chmod 600 .tgvpanel-secret 2>/dev/null || true
  ok "Database migrations verified."
}

write_systemd_units() {
  local role="$1"
  if [[ $EUID -ne 0 ]] || ! command -v systemctl >/dev/null 2>&1; then
    log "Systemd unit templates saved under $APP_DIR/scripts/systemd/ (non-root or container host)."
    mkdir -p "$APP_DIR/scripts/systemd"
    UNIT_DIR="$APP_DIR/scripts/systemd"
  else
    UNIT_DIR="/etc/systemd/system"
  fi

  if [[ "$role" != "agent" ]]; then
    cat > "$UNIT_DIR/tgvpanel.service" <<EOF
[Unit]
Description=TGVPANEL Unified Virtualization Control Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=-$APP_DIR/.env
Environment=NODE_ENV=production
Environment=PORT=$PANEL_PORT
ExecStart=$(command -v node) $APP_DIR/app.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    ok "Generated $UNIT_DIR/tgvpanel.service"
  fi

  if [[ "$role" == "agent" ]]; then
    cat > "$UNIT_DIR/tgvpanel-node-agent.service" <<EOF
[Unit]
Description=TGVPANEL Remote Node Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=-$APP_DIR/.env
Environment=NODE_ENV=production
Environment=TGVPANEL_AGENT_PORT=$AGENT_PORT
ExecStart=$(command -v node) $APP_DIR/lib/node-agent/agent.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    ok "Generated $UNIT_DIR/tgvpanel-node-agent.service"
  fi

  if [[ "$UNIT_DIR" == "/etc/systemd/system" ]]; then
    systemctl daemon-reload
    if [[ "$role" != "agent" ]]; then
      systemctl enable --now tgvpanel.service
    else
      systemctl enable tgvpanel-node-agent.service
      if [[ -f "$APP_DIR/.env" ]] && grep -qE '^TGVPANEL_NODE_API_KEY=.+' "$APP_DIR/.env"; then
        systemctl restart tgvpanel-node-agent.service
        ok "Started tgvpanel-node-agent.service on port $AGENT_PORT"
      else
        warn "tgvpanel-node-agent.service enabled. Paste TGVPANEL_NODE_API_KEY & TGVPANEL_NODE_HMAC_SECRET into $APP_DIR/.env, then run:"
        warn "  sudo systemctl restart tgvpanel-node-agent.service"
      fi
    fi
  fi
}

main() {
  detect_capabilities

  if [[ "$MODE" == "auto" && "$NONINTERACTIVE" != "1" && -t 0 ]]; then
    echo "Select TGVPANEL Installation Mode:"
    echo "  1) Unified Panel + KVM + LXC (Recommended)"
    echo "  2) Unified Panel + KVM Only"
    echo "  3) Unified Panel + LXC Only"
    echo "  4) Standalone Remote Node Agent"
    read -rp "Choice [1-4, default 1]: " choice
    case "${choice:-1}" in
      2) MODE="kvm" ;;
      3) MODE="lxc" ;;
      4) MODE="agent" ;;
      *) MODE="unified" ;;
    esac
  elif [[ "$MODE" == "auto" ]]; then
    MODE="unified"
  fi

  log "Selected installation mode: $MODE"
  install_os_packages "$MODE"
  ensure_node_and_deps
  if [[ "$MODE" != "agent" ]]; then
    init_secrets_and_db
  fi
  write_systemd_units "$MODE"
  detect_capabilities
  ok "TGVPANEL installation complete! Start manually with: npm start"
}

main "$@"
