#!/usr/bin/env bash
# ==============================================================================
# TGVPANEL — Interactive Management Menu (Panel + Remote Node + Migration + Update)
# Repository : https://github.com/ShadowGamerIND37/TGVPANEL
#
# Usage:
#   Interactive Menu : sudo bash menu.sh
#   One-Liner        : curl -fsSL https://raw.githubusercontent.com/ShadowGamerIND37/TGVPANEL/main/menu.sh -o menu.sh && sudo bash menu.sh
#   CLI Shortcuts    : sudo bash menu.sh [--status | --update | --migrate-db | --help]
# ==============================================================================
set -euo pipefail

REPO_URL="${TGVPANEL_REPO_URL:-https://github.com/ShadowGamerIND37/TGVPANEL.git}"
REPO_BRANCH="${TGVPANEL_REPO_BRANCH:-main}"

# Resolve install directory: if running inside an existing TGVPANEL repo, default to it; else /opt/tgvpanel
SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
DETECTED_DIR=""
if [[ -n "$SCRIPT_SOURCE" && -f "$SCRIPT_SOURCE" ]]; then
  CANDIDATE_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
  if [[ -f "$CANDIDATE_DIR/package.json" && -f "$CANDIDATE_DIR/app.js" ]]; then
    DETECTED_DIR="$CANDIDATE_DIR"
  fi
fi
DEFAULT_INSTALL_DIR="${TGVPANEL_DIR:-${DETECTED_DIR:-/opt/tgvpanel}}"
APP_DIR="$DEFAULT_INSTALL_DIR"

# Colors, Gradient Palette & ASCII Art UI Helpers
if [[ -n "${NO_COLOR:-}" || "${TERM:-}" == "dumb" ]]; then
  C_RESET=""
  C_BOLD=""
  C_BLUE=""
  C_CYAN=""
  C_GREEN=""
  C_YELLOW=""
  C_RED=""
  C_DIM=""
  C_GRAD1=""
  C_GRAD2=""
  C_GRAD3=""
  C_GRAD4=""
  C_GRAD5=""
elif [[ "${TERM:-}" =~ (256color|xterm|screen|tmux|rxvt|kitty|alacritty|linux) ]] || { command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 16)" -ge 256 ]]; }; then
  C_RESET="\033[0m"
  C_BOLD="\033[1m"
  C_BLUE="\033[1;34m"
  C_CYAN="\033[1;36m"
  C_GREEN="\033[1;32m"
  C_YELLOW="\033[1;33m"
  C_RED="\033[1;31m"
  C_DIM="\033[2m"
  C_GRAD1="\033[1;38;5;51m"
  C_GRAD2="\033[1;38;5;45m"
  C_GRAD3="\033[1;38;5;39m"
  C_GRAD4="\033[1;38;5;33m"
  C_GRAD5="\033[1;38;5;69m"
else
  C_RESET="\033[0m"
  C_BOLD="\033[1m"
  C_BLUE="\033[1;34m"
  C_CYAN="\033[1;36m"
  C_GREEN="\033[1;32m"
  C_YELLOW="\033[1;33m"
  C_RED="\033[1;31m"
  C_DIM="\033[2m"
  C_GRAD1="\033[1;36m"
  C_GRAD2="\033[1;36m"
  C_GRAD3="\033[1;34m"
  C_GRAD4="\033[1;34m"
  C_GRAD5="\033[1;35m"
fi

# Raw 65-column pure 7-bit ASCII logo lines (safe across all SSH/TTY locales)
TGVPANEL_ASCII_1=' _______  _____ __    __ _____      /\     _   _  ______  _      '
TGVPANEL_ASCII_2='|__   __|/ ____|\ \  / /|  __ \    /  \   | \ | ||  ____|| |     '
TGVPANEL_ASCII_3='   | |  | |  __  \ \/ / | |__) |  / /\ \  |  \| || |__   | |     '
TGVPANEL_ASCII_4='   | |  | | |_ |  \  /  |  ___/  / ____ \ | |\  ||  __|  | |____ '
TGVPANEL_ASCII_5='   |_|   \_____|   \/   |_|     /_/    \_\|_| \_||______||______|'

print_ascii_logo() {
  printf "  %b%s%b\n" "$C_GRAD1" "$TGVPANEL_ASCII_1" "$C_RESET"
  printf "  %b%s%b\n" "$C_GRAD2" "$TGVPANEL_ASCII_2" "$C_RESET"
  printf "  %b%s%b\n" "$C_GRAD3" "$TGVPANEL_ASCII_3" "$C_RESET"
  printf "  %b%s%b\n" "$C_GRAD4" "$TGVPANEL_ASCII_4" "$C_RESET"
  printf "  %b%s%b\n" "$C_GRAD5" "$TGVPANEL_ASCII_5" "$C_RESET"
  printf "  %bUnified QEMU/KVM Virtual Machines  •  LXC Containers  •  v3.0%b\n" "$C_DIM" "$C_RESET"
}

print_section_banner() {
  local title="$1"
  echo ""
  printf "%b+----------------------------------------------------------------------+%b\n" "$C_CYAN" "$C_RESET"
  printf "%b|%b  %b%-68s%b%b|%b\n" "$C_CYAN" "$C_RESET" "$C_BOLD" "$title" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b+----------------------------------------------------------------------+%b\n" "$C_CYAN" "$C_RESET"
  echo ""
}

info()  { printf "${C_BLUE}[TGVPANEL]${C_RESET} %s\n" "$*"; }
ok()    { printf "${C_GREEN}[  OK  ]${C_RESET} %s\n" "$*"; }
warn()  { printf "${C_YELLOW}[ WARN ]${C_RESET} %s\n" "$*"; }
err()   { printf "${C_RED}[ERROR ]${C_RESET} %s\n" "$*" >&2; }

pause_menu() {
  echo ""
  read -r -p "Press [Enter] to return to the menu..." _ || true
}

prompt_default() {
  local prompt_text="$1"
  local default_val="$2"
  local reply=""
  if [[ -n "$default_val" ]]; then
    printf "${C_CYAN}?${C_RESET} %s [${C_BOLD}%s${C_RESET}]: " "$prompt_text" "$default_val" >&2
    read -r reply || true
    printf "%s" "${reply:-$default_val}"
  else
    printf "${C_CYAN}?${C_RESET} %s: " "$prompt_text" >&2
    read -r reply || true
    printf "%s" "$reply"
  fi
}

prompt_secret() {
  local prompt_text="$1"
  local default_val="${2:-}"
  local reply=""
  if [[ -n "$default_val" ]]; then
    printf "${C_CYAN}?${C_RESET} %s [press Enter to keep existing]: " "$prompt_text" >&2
    read -r -s reply || true
    echo "" >&2
    printf "%s" "${reply:-$default_val}"
  else
    printf "${C_CYAN}?${C_RESET} %s: " "$prompt_text" >&2
    read -r -s reply || true
    echo "" >&2
    printf "%s" "$reply"
  fi
}

prompt_yes_no() {
  local prompt_text="$1"
  local default_ans="${2:-Y}"
  local hint="Y/n"
  [[ "$default_ans" =~ ^[Nn]$ ]] && hint="y/N"
  local reply=""
  printf "${C_CYAN}?${C_RESET} %s [%s]: " "$prompt_text" "$hint" >&2
  read -r reply || true
  reply="${reply:-$default_ans}"
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# ------------------------------------------------------------------------------
# Privilege & System Helpers
# ------------------------------------------------------------------------------
run_priv() {
  if [[ $EUID -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    err "Root privileges are required for: $*"
    return 1
  fi
}

is_systemd_active() {
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

detect_primary_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
  fi
  if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  printf "%s" "${ip:-127.0.0.1}"
}

is_ip_literal() {
  local val="${1:-}"
  [[ "$val" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$val" == *:* ]]
}

build_openssl_san_ext() {
  local primary_ip="${1:-}"
  local host_fqdn="${2:-}"
  local adv_url="${3:-}"
  local san="IP:127.0.0.1"
  if [[ -n "$primary_ip" && "$primary_ip" != "127.0.0.1" ]]; then
    if is_ip_literal "$primary_ip"; then
      san="${san},IP:${primary_ip}"
    else
      san="${san},DNS:${primary_ip}"
    fi
  fi
  if [[ -n "$host_fqdn" ]]; then
    if is_ip_literal "$host_fqdn"; then
      [[ "$san" != *"IP:${host_fqdn}"* ]] && san="${san},IP:${host_fqdn}"
    else
      [[ "$san" != *"DNS:${host_fqdn}"* ]] && san="${san},DNS:${host_fqdn}"
    fi
  fi
  if [[ -n "$adv_url" ]]; then
    local adv_host="${adv_url#*://}"
    adv_host="${adv_host%%/*}"
    adv_host="${adv_host#[}"
    if [[ "$adv_host" == *"]"* ]]; then
      adv_host="${adv_host%%]*}"
    else
      adv_host="${adv_host%%:*}"
    fi
    if [[ -n "$adv_host" ]]; then
      if is_ip_literal "$adv_host"; then
        [[ "$san" != *"IP:${adv_host}"* ]] && san="${san},IP:${adv_host}"
      else
        [[ "$san" != *"DNS:${adv_host}"* ]] && san="${san},DNS:${adv_host}"
      fi
    fi
  fi
  printf "%s" "$san"
}

read_env_val() {
  local key="$1"
  local env_file="$2"
  if [[ -f "$env_file" ]]; then
    awk -F= -v k="$key" '$1 == k {sub(/^[^=]*=/, ""); gsub(/^["'\'']|["'\'']$/, ""); print; exit}' "$env_file"
  fi
}

upsert_env_val() {
  local key="$1"
  local val="$2"
  local env_file="$3"
  mkdir -p "$(dirname "$env_file")"
  touch "$env_file"
  chmod 600 "$env_file" 2>/dev/null || true

  local tmp_file="${env_file}.tmp.$$"
  awk -v k="$key" -v v="$val" '
    BEGIN { updated = 0 }
    index($0, k "=") == 1 {
      print k "=" v
      updated = 1
      next
    }
    { print }
    END {
      if (!updated) print k "=" v
    }
  ' "$env_file" > "$tmp_file"
  mv "$tmp_file" "$env_file"
  chmod 600 "$env_file" 2>/dev/null || true
}

get_service_state() {
  local svc_name="$1"
  local pid_file="$2"
  if is_systemd_active; then
    if systemctl is-active --quiet "${svc_name}.service" 2>/dev/null; then
      printf "running"
      return 0
    fi
  fi
  if [[ -f "$pid_file" ]]; then
    local pid=""
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      printf "running"
      return 0
    fi
  fi
  printf "stopped"
}

sync_system_clock() {
  if command -v timedatectl >/dev/null 2>&1 && is_systemd_active; then
    run_priv timedatectl set-ntp true 2>/dev/null || true
  fi
}

install_global_shortcut() {
  local target_dir="$1"
  if [[ -f "$target_dir/menu.sh" ]]; then
    chmod +x "$target_dir/menu.sh" 2>/dev/null || true
    if [[ $EUID -eq 0 ]] || command -v sudo >/dev/null 2>&1; then
      run_priv ln -sf "$target_dir/menu.sh" /usr/local/bin/tgvpanel 2>/dev/null || true
    fi
  fi
}

# ------------------------------------------------------------------------------
# OS Package, Node.js 20+ & GitHub Repository Bootstrap
# ------------------------------------------------------------------------------
ensure_os_dependencies() {
  local role="$1" # unified | kvm | lxc | agent
  info "Installing system packages for mode: $role..."

  if command -v apt-get >/dev/null 2>&1; then
    run_priv env DEBIAN_FRONTEND=noninteractive apt-get update -y
    run_priv env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      git curl ca-certificates gnupg build-essential python3 make g++ \
      sqlite3 tar iproute2 iptables nftables openssl procps

    if [[ "$role" == "unified" || "$role" == "kvm" ]]; then
      run_priv env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        qemu-system-x86 qemu-utils cloud-image-utils genisoimage bridge-utils || \
        warn "Some optional KVM packages could not be installed on this host."
    fi
    if [[ "$role" == "unified" || "$role" == "lxc" || "$role" == "agent" ]]; then
      run_priv env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        lxc lxc-templates lxcfs uidmap bridge-utils dnsmasq-base || \
        run_priv env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        lxc lxc-templates uidmap bridge-utils dnsmasq-base || \
        warn "Some optional LXC packages could not be installed on this host."
    fi
  elif command -v dnf >/dev/null 2>&1; then
    run_priv dnf install -y \
      git curl ca-certificates gcc gcc-c++ make python3 \
      sqlite tar iproute iptables nftables openssl procps-ng
    if [[ "$role" == "unified" || "$role" == "kvm" ]]; then
      run_priv dnf install -y qemu-kvm qemu-img genisoimage || \
        warn "Some optional KVM packages could not be installed on this host."
    fi
    if [[ "$role" == "unified" || "$role" == "lxc" || "$role" == "agent" ]]; then
      run_priv dnf install -y lxc lxc-templates lxcfs || \
        run_priv dnf install -y lxc lxc-templates || \
        warn "Some optional LXC packages could not be installed on this host."
    fi
  else
    warn "Unsupported package manager (expected apt-get or dnf). Assuming OS packages are pre-installed."
  fi
}

ensure_nodejs_20_plus() {
  local need_install=0
  if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    need_install=1
  else
    local major=""
    major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
    if [[ "$major" -lt 20 ]]; then
      warn "Detected Node.js $(node -v); upgrading to Node.js 20 LTS..."
      need_install=1
    fi
  fi

  if [[ "$need_install" -eq 1 ]]; then
    info "Installing Node.js 20 LTS..."
    if command -v apt-get >/dev/null 2>&1; then
      curl -fsSL https://deb.nodesource.com/setup_20.x | run_priv bash -
      run_priv env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
    elif command -v dnf >/dev/null 2>&1; then
      curl -fsSL https://rpm.nodesource.com/setup_20.x | run_priv bash -
      run_priv dnf install -y nodejs
    else
      err "Automatic Node.js 20 installation requires apt-get or dnf. Install Node.js 20+ manually and re-run."
      return 1
    fi
  fi

  ok "Node.js $(node -v) & npm $(npm -v) ready."
}

ensure_repo_cloned_and_built() {
  local target_dir="$1"
  local branch="${2:-$REPO_BRANCH}"

  if [[ -f "$target_dir/package.json" && -f "$target_dir/app.js" ]]; then
    info "Found existing TGVPANEL installation at $target_dir"
    if [[ -d "$target_dir/.git" ]]; then
      info "Fetching latest updates from GitHub ($branch)..."
      (cd "$target_dir" && git fetch origin "$branch" 2>/dev/null && git pull --ff-only origin "$branch" 2>/dev/null) || \
        info "Keeping current working tree in $target_dir"
    fi
  else
    if [[ -e "$target_dir" ]] && [[ -n "$(ls -A "$target_dir" 2>/dev/null || true)" ]]; then
      local backup_existing="${target_dir}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
      warn "Directory $target_dir is non-empty; moving existing contents to $backup_existing"
      run_priv mv "$target_dir" "$backup_existing"
    fi
    info "Cloning TGVPANEL from $REPO_URL (branch: $branch) into $target_dir..."
    run_priv mkdir -p "$(dirname "$target_dir")"
    run_priv git clone --branch "$branch" "$REPO_URL" "$target_dir"
    if [[ $EUID -ne 0 ]]; then
      run_priv chown -R "$(id -u):$(id -g)" "$target_dir"
    fi
  fi

  APP_DIR="$target_dir"
  cd "$APP_DIR"

  if [[ -d /usr/local/include/node ]]; then
    export npm_config_nodedir="/usr/local"
  fi

  info "Installing Node.js dependencies (this may take 1-2 minutes)..."
  npm install

  mkdir -p public/vendor/xterm
  [[ -f node_modules/@xterm/xterm/lib/xterm.js ]] && cp -f node_modules/@xterm/xterm/lib/xterm.js public/vendor/xterm/xterm.js
  [[ -f node_modules/@xterm/xterm/css/xterm.css ]] && cp -f node_modules/@xterm/xterm/css/xterm.css public/vendor/xterm/xterm.css
  [[ -f node_modules/@xterm/addon-fit/lib/addon-fit.js ]] && cp -f node_modules/@xterm/addon-fit/lib/addon-fit.js public/vendor/xterm/addon-fit.js

  info "Compiling TypeScript services (src/ -> lib/)..."
  npm run build
  ok "TGVPANEL build completed cleanly."
  install_global_shortcut "$APP_DIR"
}

# ------------------------------------------------------------------------------
# 24/7 Service Supervision (systemd primary + non-systemd keepalive fallback)
# ------------------------------------------------------------------------------
start_panel_24_7() {
  local target_dir="$1"
  local port="$2"
  local node_bin
  node_bin="$(command -v node)"
  mkdir -p "$target_dir/data/logs"

  if is_systemd_active; then
    info "Configuring 24/7 systemd service: tgvpanel.service..."
    run_priv tee /etc/systemd/system/tgvpanel.service >/dev/null <<EOF
[Unit]
Description=TGVPANEL Unified Virtualization Control Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$target_dir
EnvironmentFile=-$target_dir/.env
Environment=NODE_ENV=production
Environment=PORT=$port
ExecStart=$node_bin $target_dir/app.js
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    run_priv systemctl daemon-reload
    run_priv systemctl enable tgvpanel.service
    run_priv systemctl restart tgvpanel.service
    ok "tgvpanel.service enabled on boot and running 24/7 via systemd."
  else
    warn "systemd is not active as PID 1 (container/WSL host). Starting 24/7 background keepalive supervisor..."
    local pid_file="$target_dir/data/tgvpanel-panel.pid"
    local log_file="$target_dir/data/logs/panel.log"
    if [[ -f "$pid_file" ]]; then
      local old_pid
      old_pid="$(cat "$pid_file" 2>/dev/null || true)"
      [[ -n "$old_pid" ]] && kill "$old_pid" 2>/dev/null || true
      sleep 1
    fi
    nohup bash -c "
      cd '$target_dir'
      while true; do
        NODE_ENV=production PORT='$port' '$node_bin' '$target_dir/app.js' >> '$log_file' 2>&1 || true
        sleep 3
      done
    " >/dev/null 2>&1 &
    echo "$!" > "$pid_file"
    ok "Panel keepalive supervisor running 24/7 in background (PID $(cat "$pid_file"), log: $log_file)."
  fi
}

start_agent_24_7() {
  local target_dir="$1"
  local port="$2"
  local node_bin
  node_bin="$(command -v node)"
  mkdir -p "$target_dir/data/logs"

  if is_systemd_active; then
    info "Configuring 24/7 systemd service: tgvpanel-node-agent.service..."
    run_priv tee /etc/systemd/system/tgvpanel-node-agent.service >/dev/null <<EOF
[Unit]
Description=TGVPANEL Standalone Remote Node Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$target_dir
EnvironmentFile=-$target_dir/.env
Environment=NODE_ENV=production
Environment=TGVPANEL_AGENT_PORT=$port
ExecStart=$node_bin $target_dir/lib/node-agent/agent.js
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    run_priv systemctl daemon-reload
    run_priv systemctl enable tgvpanel-node-agent.service
    run_priv systemctl restart tgvpanel-node-agent.service
    ok "tgvpanel-node-agent.service enabled on boot and running 24/7 via systemd."
  else
    warn "systemd is not active as PID 1 (container/WSL host). Starting 24/7 background keepalive supervisor..."
    local pid_file="$target_dir/data/tgvpanel-agent.pid"
    local log_file="$target_dir/data/logs/node-agent.log"
    if [[ -f "$pid_file" ]]; then
      local old_pid
      old_pid="$(cat "$pid_file" 2>/dev/null || true)"
      [[ -n "$old_pid" ]] && kill "$old_pid" 2>/dev/null || true
      sleep 1
    fi
    nohup bash -c "
      cd '$target_dir'
      while true; do
        NODE_ENV=production TGVPANEL_AGENT_PORT='$port' '$node_bin' '$target_dir/lib/node-agent/agent.js' >> '$log_file' 2>&1 || true
        sleep 3
      done
    " >/dev/null 2>&1 &
    echo "$!" > "$pid_file"
    ok "Node Agent keepalive supervisor running 24/7 in background (PID $(cat "$pid_file"), log: $log_file)."
  fi
}

stop_managed_service() {
  local svc_name="$1"
  local pid_file="$2"
  local match_pattern="$3"
  if is_systemd_active; then
    run_priv systemctl stop "${svc_name}.service" 2>/dev/null || true
  fi
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$pid_file"
  fi
  pkill -f "$match_pattern" 2>/dev/null || true
}

configure_firewall_port() {
  local port="$1"
  local source_ip="${2:-}"
  local label="${3:-TGVPANEL}"

  if command -v ufw >/dev/null 2>&1 && run_priv ufw status 2>/dev/null | grep -q "Status: active"; then
    if [[ -n "$source_ip" ]]; then
      for sip in $(echo "$source_ip" | tr ',' ' '); do
        run_priv ufw allow from "$sip" to any port "$port" proto tcp comment "$label" || true
      done
      ok "UFW rule added: allow TCP $port from $source_ip"
    else
      run_priv ufw allow "${port}/tcp" comment "$label" || true
      ok "UFW rule added: allow TCP $port"
    fi
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    if [[ -n "$source_ip" ]]; then
      for sip in $(echo "$source_ip" | tr ',' ' '); do
        run_priv firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"${sip}\" port port=\"${port}\" protocol=\"tcp\" accept" || true
      done
      run_priv firewall-cmd --reload || true
      ok "Firewalld rich rule added: allow TCP $port from $source_ip"
    else
      run_priv firewall-cmd --permanent --add-port="${port}/tcp" || true
      run_priv firewall-cmd --reload || true
      ok "Firewalld rule added: allow TCP $port"
    fi
  fi
}

# ==============================================================================
# OPTION 1: Auto Install & Setup Panel
# ==============================================================================
option_install_panel() {
  print_section_banner "[1] Auto Install & Setup TGVPANEL (24/7 Controller + Compute)"

  local target_dir
  target_dir="$(prompt_default "Installation directory" "$APP_DIR")"
  local branch
  branch="$(prompt_default "GitHub branch" "$REPO_BRANCH")"

  echo ""
  echo "Select Hypervisor Stack to Install on this Panel Server:"
  echo "  1) Unified Panel + QEMU/KVM + LXC  (Recommended)"
  echo "  2) Unified Panel + QEMU/KVM Only"
  echo "  3) Unified Panel + LXC Only"
  local mode_choice
  mode_choice="$(prompt_default "Choice (1-3)" "1")"
  local role="unified"
  case "$mode_choice" in
    2) role="kvm" ;;
    3) role="lxc" ;;
    *) role="unified" ;;
  esac

  local existing_port
  existing_port="$(read_env_val "PORT" "$target_dir/.env")"
  local panel_port
  panel_port="$(prompt_default "Panel HTTP port" "${existing_port:-8080}")"

  local enable_shell="false"
  if prompt_yes_no "Enable audited interactive Admin Host Shell (/admin/node-console)?" "N"; then
    enable_shell="true"
  fi

  local set_custom_admin="0"
  local admin_user="admin"
  local admin_pass=""
  if prompt_yes_no "Set a custom password for the 'admin' panel account now?" "Y"; then
    admin_user="$(prompt_default "Admin username" "admin")"
    while [[ -z "$admin_pass" || "${#admin_pass}" -lt 6 ]]; do
      admin_pass="$(prompt_secret "Enter admin password (min 6 characters)")"
      if [[ "${#admin_pass}" -lt 6 ]]; then
        warn "Password must be at least 6 characters."
      fi
    done
    set_custom_admin="1"
  fi

  local open_fw="0"
  if prompt_yes_no "Automatically allow TCP port $panel_port in UFW/Firewalld (if active)?" "Y"; then
    open_fw="1"
  fi

  echo ""
  sync_system_clock
  ensure_os_dependencies "$role"
  ensure_nodejs_20_plus
  ensure_repo_cloned_and_built "$target_dir" "$branch"

  cd "$APP_DIR"
  mkdir -p data data/backups data/instance-backups "$HOME/vms/iso" "$HOME/vms/cloudvm" "$HOME/vms/templates"
  if [[ ! -f .env && -f .env.example ]]; then
    cp .env.example .env
  fi
  upsert_env_val "PORT" "$panel_port" "$APP_DIR/.env"
  upsert_env_val "HOST" "0.0.0.0" "$APP_DIR/.env"
  upsert_env_val "NODE_ENV" "production" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_ENABLE_NODE_SHELL" "$enable_shell" "$APP_DIR/.env"

  if [[ -f .hkvm-secret && ! -f .tgvpanel-secret ]]; then
    mv .hkvm-secret .tgvpanel-secret
  fi

  info "Initializing .tgvpanel-secret vault & applying database migrations..."
  npm run migrate
  chmod 600 .tgvpanel-secret .env 2>/dev/null || true

  if [[ "$set_custom_admin" == "1" ]]; then
    info "Configuring administrator account '$admin_user'..."
    TGVP_ADMIN_USER="$admin_user" TGVP_ADMIN_PASS="$admin_pass" node -e '
      const sqlite3 = require("sqlite3");
      const bcrypt = require("bcryptjs");
      const { resolveAndMigrateDatabasePath } = require("./lib/db/database");
      const dbPath = resolveAndMigrateDatabasePath("./data");
      const db = new sqlite3.Database(dbPath);
      const hash = bcrypt.hashSync(process.env.TGVP_ADMIN_PASS, 10);
      const user = process.env.TGVP_ADMIN_USER;
      db.get("SELECT id FROM users WHERE username = ?", [user], (err, row) => {
        if (err) { console.error(err); process.exit(1); }
        if (row) {
          db.run("UPDATE users SET password = ?, role = '\''admin'\'', is_active = 1 WHERE id = ?", [hash, row.id], (e2) => {
            if (e2) { console.error(e2); process.exit(1); }
            db.close();
          });
        } else {
          db.run(
            "INSERT INTO users (username, password, email, role, is_active) VALUES (?, ?, ?, '\''admin'\'', 1)",
            [user, hash, user + "@shadowgamerind.local"],
            (e2) => {
              if (e2) { console.error(e2); process.exit(1); }
              db.close();
            }
          );
        }
      });
    '
    ok "Admin user '$admin_user' configured."
  fi

  if [[ "$open_fw" == "1" ]]; then
    configure_firewall_port "$panel_port" "" "TGVPANEL Web Panel"
  fi

  start_panel_24_7 "$APP_DIR" "$panel_port"

  info "Verifying TGVPANEL HTTP readiness on port $panel_port..."
  local ready=0
  for _ in $(seq 1 20); do
    if curl -fsS "http://127.0.0.1:${panel_port}/login" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done

  local host_ip
  host_ip="$(detect_primary_ip)"
  echo ""
  echo -e "${C_GREEN}╔══════════════════════════════════════════════════════════════════════╗${C_RESET}"
  echo -e "${C_GREEN}║            TGVPANEL INSTALLED & RUNNING 24/7 SUCCESSFULLY            ║${C_RESET}"
  echo -e "${C_GREEN}╚══════════════════════════════════════════════════════════════════════╝${C_RESET}"
  echo -e "  Panel URL       : ${C_BOLD}http://${host_ip}:${panel_port}${C_RESET}"
  echo -e "  Install Dir     : ${C_BOLD}${APP_DIR}${C_RESET}"
  echo -e "  Database        : ${C_BOLD}${APP_DIR}/data/tgvpanel.db${C_RESET}"
  echo -e "  HTTP Health     : $([[ "$ready" -eq 1 ]] && echo -e "${C_GREEN}ONLINE (200 OK)${C_RESET}" || echo -e "${C_YELLOW}STARTING (check logs)${C_RESET}")"
  echo -e "  Reopen Menu     : ${C_BOLD}sudo tgvpanel${C_RESET}  (or: sudo bash $APP_DIR/menu.sh)"
}

# ==============================================================================
# OPTION 2: Auto Configure Node (Remote Compute Node -> Online 24/7)
# ==============================================================================
option_configure_node() {
  print_section_banner "[2] Auto Configure Remote Compute Node (24/7 Node Agent)"

  local target_dir
  target_dir="$(prompt_default "Node Agent installation directory" "$APP_DIR")"
  local branch
  branch="$(prompt_default "GitHub branch" "$REPO_BRANCH")"

  local detected_ip
  detected_ip="$(detect_primary_ip)"
  local node_ip
  node_ip="$(prompt_default "This Node's IPv4 / Mesh IP (or LAN IP if behind Cloudflare Tunnel)" "$detected_ip")"

  local default_hostname
  default_hostname="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "node-02")"
  local node_hostname
  node_hostname="$(prompt_default "This Node's Hostname / Cloudflare Tunnel FQDN" "$default_hostname")"

  local existing_agent_port
  existing_agent_port="$(read_env_val "TGVPANEL_AGENT_PORT" "$target_dir/.env")"
  local agent_port
  agent_port="$(prompt_default "Node Agent listening port" "${existing_agent_port:-8443}")"

  echo ""
  echo "Select TLS / Transport Security Mode for this Node Agent:"
  echo "  1) Auto-Generate Self-Signed HTTPS Certificate (Recommended for Public IP)"
  echo "  2) Use Existing TLS Certificate Files (Let's Encrypt / Custom PEM)"
  echo "  3) Plain HTTP (Only for Private WireGuard / Trusted Internal LAN)"
  local tls_choice
  tls_choice="$(prompt_default "Choice (1-3)" "1")"

  local tls_cert=""
  local tls_key=""
  local tls_ca=""
  local require_mtls="false"
  local scheme="https"
  local verify_ssl_json="false"

  case "$tls_choice" in
    2)
      scheme="https"
      verify_ssl_json="true"
      tls_cert="$(prompt_default "Path to TLS certificate PEM (fullchain.pem)" "/etc/letsencrypt/live/${node_hostname}/fullchain.pem")"
      tls_key="$(prompt_default "Path to TLS private key PEM (privkey.pem)" "/etc/letsencrypt/live/${node_hostname}/privkey.pem")"
      if prompt_yes_no "Enable Mutual TLS (mTLS client certificate verification)?" "N"; then
        require_mtls="true"
        tls_ca="$(prompt_default "Path to mTLS CA certificate PEM" "/etc/tgvpanel/ssl/ca.crt")"
      fi
      ;;
    3)
      scheme="http"
      verify_ssl_json="false"
      ;;
    *)
      scheme="https"
      verify_ssl_json="false"
      tls_cert="/etc/tgvpanel/ssl/agent.crt"
      tls_key="/etc/tgvpanel/ssl/agent.key"
      ;;
  esac

  local advertised_url="${scheme}://${node_ip}:${agent_port}"
  if [[ "$tls_choice" == "2" && "$node_hostname" == *.* ]]; then
    advertised_url="${scheme}://${node_hostname}:${agent_port}"
  fi
  advertised_url="$(prompt_default "Public Agent Endpoint URL (or Cloudflare Tunnel URL e.g. https://node1.example.com)" "${TGVPANEL_ADVERTISE_URL:-$advertised_url}")"
  advertised_url="${advertised_url%/}"

  echo ""
  echo "How would you like to connect this Node to your Main TGVPANEL Controller?"
  echo "  1) Instant Pair via 1-Time Join Token (Recommended — from Admin -> Nodes -> Pair / Join)"
  echo "  2) Paste Bootstrap Credentials from Panel UI  (Admin -> Nodes -> Register Node)"
  echo "  3) Auto-Register via Controller URL + Admin API Token (Bearer PAT)"
  local cred_mode
  cred_mode="$(prompt_default "Choice (1-3)" "1")"

  local node_id=""
  local node_api_key=""
  local node_hmac_secret=""
  local controller_url=""
  local join_token=""
  local admin_pat=""
  local node_display_name=""
  local node_location=""

  if [[ "$cred_mode" == "1" ]]; then
    controller_url="$(prompt_default "Controller Panel URL (e.g. https://panel.example.com or http://1.2.3.4:8080)" "")"
    controller_url="${controller_url%/}"
    if [[ -z "$controller_url" ]]; then
      err "Controller URL is required for Join Token pairing."
      return 1
    fi
    join_token="$(prompt_secret "Single-Use Node Join Token (starts with tgv_join_...)")"
    if [[ -z "$join_token" ]]; then
      err "Join Token cannot be empty."
      return 1
    fi
  elif [[ "$cred_mode" == "3" ]]; then
    controller_url="$(prompt_default "Controller Panel URL (e.g. https://panel.example.com or http://1.2.3.4:8080)" "")"
    controller_url="${controller_url%/}"
    if [[ -z "$controller_url" ]]; then
      err "Controller URL is required for Auto-Register mode."
      return 1
    fi
    admin_pat="$(prompt_secret "Admin Personal Access Token (from Admin -> API Keys, with nodes:write)")"
    if [[ -z "$admin_pat" ]]; then
      err "Admin API token is required for Auto-Register mode."
      return 1
    fi
    node_display_name="$(prompt_default "Node Display Name in Panel" "$(hostname -s 2>/dev/null || echo "remote-node")")"
    node_location="$(prompt_default "Node Datacenter / Location" "Remote Datacenter")"
  else
    local prev_id prev_key prev_hmac prev_ctrl
    prev_id="$(read_env_val "TGVPANEL_NODE_ID" "$target_dir/.env")"
    prev_key="$(read_env_val "TGVPANEL_NODE_API_KEY" "$target_dir/.env")"
    prev_hmac="$(read_env_val "TGVPANEL_NODE_HMAC_SECRET" "$target_dir/.env")"
    prev_ctrl="$(read_env_val "TGVPANEL_CONTROLLER_URL" "$target_dir/.env")"

    echo ""
    echo -e "${C_DIM}Tip: In your Panel open Admin -> Nodes, register '${advertised_url}', and paste below:${C_RESET}"
    node_id="$(prompt_default "TGVPANEL_NODE_ID" "${prev_id:-2}")"
    while [[ -z "$node_api_key" ]]; do
      node_api_key="$(prompt_secret "TGVPANEL_NODE_API_KEY" "$prev_key")"
      [[ -z "$node_api_key" ]] && warn "TGVPANEL_NODE_API_KEY cannot be empty."
    done
    while [[ -z "$node_hmac_secret" ]]; do
      node_hmac_secret="$(prompt_secret "TGVPANEL_NODE_HMAC_SECRET" "$prev_hmac")"
      [[ -z "$node_hmac_secret" ]] && warn "TGVPANEL_NODE_HMAC_SECRET cannot be empty."
    done
    controller_url="$(prompt_default "Optional Controller URL for active push-heartbeats (blank to skip)" "$prev_ctrl")"
    controller_url="${controller_url%/}"
  fi

  local existing_allowed_ips
  existing_allowed_ips="$(read_env_val "TGVPANEL_ALLOWED_CONTROLLER_IPS" "$target_dir/.env")"
  local allowed_ips
  allowed_ips="$(prompt_default "Controller IP allowlist (comma-separated, or blank for any authenticated IP)" "$existing_allowed_ips")"

  local lxc_dir
  lxc_dir="$(prompt_default "LXC container directory" "/var/lib/lxc")"

  local enable_shell="false"
  if prompt_yes_no "Enable audited interactive Admin Host Shell on this node?" "N"; then
    enable_shell="true"
  fi

  local open_fw="0"
  if prompt_yes_no "Configure UFW/Firewalld for Node Agent TCP port $agent_port?" "Y"; then
    open_fw="1"
  fi

  echo ""
  info "Synchronizing NTP clock (required for ±300s HMAC replay protection)..."
  sync_system_clock

  ensure_os_dependencies "agent"
  ensure_nodejs_20_plus
  ensure_repo_cloned_and_built "$target_dir" "$branch"

  # Generate self-signed TLS certificate BEFORE pairing/registering so we can pin exact X.509 PEM!
  if [[ "$tls_choice" == "1" ]]; then
    info "Generating 4096-bit self-signed TLS certificate at /etc/tgvpanel/ssl/..."
    run_priv mkdir -p /etc/tgvpanel/ssl
    local san_ext
    san_ext="$(build_openssl_san_ext "$node_ip" "$node_hostname" "$advertised_url")"
    run_priv openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
      -keyout "$tls_key" \
      -out "$tls_cert" \
      -subj "/CN=${node_hostname}" \
      -addext "subjectAltName=${san_ext}" >/dev/null 2>&1
    run_priv chmod 644 "$tls_cert"
    if [[ $EUID -ne 0 ]]; then
      run_priv chown "$(id -u):$(id -g)" "$tls_key" "$tls_cert"
    fi
    chmod 600 "$tls_key" 2>/dev/null || run_priv chmod 600 "$tls_key"
    ok "Generated TLS certificate: $tls_cert"
  fi

  local cert_pem_content=""
  if [[ -n "$tls_cert" && -f "$tls_cert" ]]; then
    cert_pem_content="$(cat "$tls_cert" 2>/dev/null || true)"
  fi

  if [[ "$cred_mode" == "1" ]]; then
    info "Redeeming single-use Join Token with Controller (${controller_url})..."
    local join_json
    join_json="$(TGVP_CTRL="$controller_url" \
      TGVP_TOK="$join_token" \
      TGVP_HOST="$node_hostname" \
      TGVP_IP="$node_ip" \
      TGVP_PORT="$agent_port" \
      TGVP_URL="$advertised_url" \
      TGVP_CERT="$cert_pem_content" \
      TGVP_VSSL="$verify_ssl_json" \
      node -e '
        const http = require("http");
        const https = require("https");
        const base = process.env.TGVP_CTRL.replace(/\/+$/, "") + "/";
        const u = new URL("api/v1/nodes/join/" + encodeURIComponent(process.env.TGVP_TOK), base);
        const body = JSON.stringify({
          endpointUrl: process.env.TGVP_URL,
          ipAddress: process.env.TGVP_IP,
          hostname: process.env.TGVP_HOST,
          agentPort: Number(process.env.TGVP_PORT || 8443),
          tlsCertPem: process.env.TGVP_CERT || null,
          verifySsl: Boolean(process.env.TGVP_CERT) || process.env.TGVP_VSSL === "true"
        });
        const mod = u.protocol === "https:" ? https : http;
        const req = mod.request(u, {
          method: "POST",
          rejectUnauthorized: false,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body)
          }
        }, (res) => {
          let data = "";
          res.on("data", (c) => data += c);
          res.on("end", () => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              console.error("HTTP " + res.statusCode + ": " + data);
              process.exit(1);
            }
            console.log(data);
          });
        });
        req.on("error", (e) => { console.error(e.message); process.exit(1); });
        req.write(body);
        req.end();
      ')"

    node_id="$(printf "%s" "$join_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.nodeId));')"
    node_api_key="$(printf "%s" "$join_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.apiKey));')"
    node_hmac_secret="$(printf "%s" "$join_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.hmacSecret));')"
    ok "Paired with Controller as Node #${node_id} (TLS certificate pinned automatically)!"
  elif [[ "$cred_mode" == "3" ]]; then
    info "Auto-registering node '${node_display_name}' (${advertised_url}) with Controller..."
    local reg_json
    reg_json="$(TGVP_CTRL="$controller_url" \
      TGVP_PAT="$admin_pat" \
      TGVP_NAME="$node_display_name" \
      TGVP_HOST="$node_hostname" \
      TGVP_IP="$node_ip" \
      TGVP_URL="$advertised_url" \
      TGVP_LOC="$node_location" \
      TGVP_CERT="$cert_pem_content" \
      TGVP_VSSL="$verify_ssl_json" \
      node -e '
        const http = require("http");
        const https = require("https");
        const base = process.env.TGVP_CTRL.replace(/\/+$/, "") + "/";
        const u = new URL("api/v1/nodes", base);
        const body = JSON.stringify({
          name: process.env.TGVP_NAME,
          hostname: process.env.TGVP_HOST,
          ipAddress: process.env.TGVP_IP,
          url: process.env.TGVP_URL,
          location: process.env.TGVP_LOC,
          tlsCaPem: process.env.TGVP_CERT || null,
          verifySsl: Boolean(process.env.TGVP_CERT) || process.env.TGVP_VSSL === "true"
        });
        const mod = u.protocol === "https:" ? https : http;
        const req = mod.request(u, {
          method: "POST",
          rejectUnauthorized: false,
          headers: {
            "Authorization": "Bearer " + process.env.TGVP_PAT,
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body)
          }
        }, (res) => {
          let data = "";
          res.on("data", (c) => data += c);
          res.on("end", () => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              console.error("HTTP " + res.statusCode + ": " + data);
              process.exit(1);
            }
            console.log(data);
          });
        });
        req.on("error", (e) => { console.error(e.message); process.exit(1); });
        req.write(body);
        req.end();
      ')"

    node_id="$(printf "%s" "$reg_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.node.id));')"
    node_api_key="$(printf "%s" "$reg_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.bootstrapCredentials.apiKey));')"
    node_hmac_secret="$(printf "%s" "$reg_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.bootstrapCredentials.hmacSecret));')"
    ok "Registered as Node #${node_id} on Controller!"
  fi

  cd "$APP_DIR"
  mkdir -p "$APP_DIR/data" "$APP_DIR/backups"
  run_priv mkdir -p "$lxc_dir"

  # Remove any stale rotated credentials cache so newly configured credentials take effect
  rm -f "$APP_DIR/data/node-agent-credentials.json"

  if [[ ! -f "$APP_DIR/.env" && -f "$APP_DIR/.env.example" ]]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
  fi

  upsert_env_val "NODE_ENV" "production" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_NODE_ID" "$node_id" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_HOST" "0.0.0.0" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_PORT" "$agent_port" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_NODE_API_KEY" "$node_api_key" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_NODE_HMAC_SECRET" "$node_hmac_secret" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_CONTROLLER_URL" "$controller_url" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_ALLOWED_CONTROLLER_IPS" "$allowed_ips" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_TLS_CERT" "$tls_cert" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_TLS_KEY" "$tls_key" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_TLS_CA" "$tls_ca" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_NODE_MTLS" "$require_mtls" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_DATA_DIR" "$APP_DIR/data" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_LXC_DIR" "$lxc_dir" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_BACKUP_DIR" "$APP_DIR/backups" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_ENABLE_NODE_SHELL" "$enable_shell" "$APP_DIR/.env"
  chmod 600 "$APP_DIR/.env"
  ok "Saved secure Node Agent configuration to $APP_DIR/.env (0600)."

  # Pre-warm LXC cgroup v2 delegation & lxcfs on this compute host
  node -e '
    const { LxcContainerManager } = require("./lib/node-agent/container-manager");
    const cm = new LxcContainerManager(process.env.TGVPANEL_LXC_DIR || "/var/lib/lxc");
    cm.ensureHostIsolationReady().then(() => process.exit(0)).catch(() => process.exit(0));
  ' 2>/dev/null || true

  if [[ "$open_fw" == "1" ]]; then
    configure_firewall_port "$agent_port" "$allowed_ips" "TGVPANEL Node Agent"
  fi

  start_agent_24_7 "$APP_DIR" "$agent_port"

  info "Verifying local Node Agent listener on ${scheme}://127.0.0.1:${agent_port}..."
  local agent_ready=0
  local http_code=""
  for _ in $(seq 1 20); do
    http_code="$(curl -ks -o /dev/null -w "%{http_code}" "${scheme}://127.0.0.1:${agent_port}/api/v1/health" 2>/dev/null || true)"
    if [[ "$http_code" == "401" || "$http_code" == "403" || "$http_code" == "200" ]]; then
      agent_ready=1
      break
    fi
    sleep 1
  done

  # If auto-registered via PAT, trigger immediate Controller health check so node turns ONLINE right away!
  local remote_synced=0
  if [[ "$cred_mode" == "1" && "$agent_ready" -eq 1 ]]; then
    remote_synced=1
  elif [[ "$cred_mode" == "3" && "$agent_ready" -eq 1 ]]; then
    info "Triggering Controller health & capability sync for Node #${node_id}..."
    if TGVP_CTRL="$controller_url" TGVP_PAT="$admin_pat" TGVP_NID="$node_id" node -e '
      const http = require("http");
      const https = require("https");
      const base = process.env.TGVP_CTRL.replace(/\/+$/, "") + "/";
      const u = new URL("api/v1/nodes/" + process.env.TGVP_NID + "/check", base);
      const mod = u.protocol === "https:" ? https : http;
      const req = mod.request(u, {
        method: "POST",
        rejectUnauthorized: false,
        headers: { "Authorization": "Bearer " + process.env.TGVP_PAT }
      }, (res) => {
        res.resume();
        res.on("end", () => process.exit(res.statusCode >= 200 && res.statusCode < 300 ? 0 : 1));
      });
      req.on("error", () => process.exit(1));
      req.end();
    '; then
      remote_synced=1
      ok "Controller verified Node #${node_id} is ONLINE!"
    else
      warn "Agent is running locally, but Controller could not reach ${advertised_url} yet. Check firewall/NAT and click 'Probe' in Admin -> Nodes."
    fi
  fi

  echo ""
  echo -e "${C_GREEN}╔══════════════════════════════════════════════════════════════════════╗${C_RESET}"
  echo -e "${C_GREEN}║          TGVPANEL NODE AGENT CONFIGURED & ONLINE 24/7                ║${C_RESET}"
  echo -e "${C_GREEN}╚══════════════════════════════════════════════════════════════════════╝${C_RESET}"
  echo -e "  Node ID         : ${C_BOLD}#${node_id}${C_RESET}"
  echo -e "  Agent Endpoint  : ${C_BOLD}${advertised_url}${C_RESET}"
  echo -e "  Listener Status : $([[ "$agent_ready" -eq 1 ]] && echo -e "${C_GREEN}LISTENING & PROTECTED (HMAC Active)${C_RESET}" || echo -e "${C_RED}FAILED TO BIND (check logs via Option 5)${C_RESET}")"
  if [[ "$cred_mode" == "2" ]]; then
    echo -e "  Next Step       : Open ${C_BOLD}Admin -> Nodes${C_RESET} on your Panel and click ${C_BOLD}Probe${C_RESET}!"
    if [[ "$tls_choice" == "1" ]]; then
      echo -e "  Self-Signed TLS : Click ${C_BOLD}Trust Node TLS Cert${C_RESET} in Admin -> Nodes to pin this node's certificate."
    fi
  elif [[ "$remote_synced" -eq 1 ]]; then
    echo -e "  Panel Sync      : ${C_GREEN}PAIRED & ACTIVE HEARTBEAT ENABLED${C_RESET}"
  fi
}

# Non-interactive 1-Command Auto-Join (`sudo bash menu.sh --join <CONTROLLER_URL> <JOIN_TOKEN> [PORT]`)
headless_join_node() {
  local controller_url="${1:-}"
  local join_token="${2:-}"
  local agent_port="${3:-${AGENT_PORT:-8443}}"
  controller_url="${controller_url%/}"

  if [[ -z "$controller_url" || -z "$join_token" ]]; then
    err "Usage: sudo bash menu.sh --join <CONTROLLER_URL> <JOIN_TOKEN> [AGENT_PORT]"
    exit 1
  fi

  print_section_banner "TGVPANEL 1-Command Remote Node Auto-Join"
  info "Controller URL : $controller_url"
  info "Agent TLS Port : $agent_port"

  sync_system_clock
  ensure_os_dependencies "agent"
  ensure_nodejs_20_plus
  ensure_repo_cloned_and_built "$APP_DIR" "$REPO_BRANCH"

  local node_ip node_hostname tls_cert tls_key san_ext advertised_url
  node_ip="${TGVPANEL_ADVERTISE_IP:-$(detect_primary_ip)}"
  node_hostname="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "remote-node")"
  tls_cert="${TGVPANEL_AGENT_TLS_CERT:-/etc/tgvpanel/ssl/agent.crt}"
  tls_key="${TGVPANEL_AGENT_TLS_KEY:-/etc/tgvpanel/ssl/agent.key}"
  advertised_url="${4:-${TGVPANEL_ADVERTISE_URL:-https://${node_ip}:${agent_port}}}"
  advertised_url="${advertised_url%/}"
  info "Advertised URL : $advertised_url"

  info "Generating 4096-bit SAN TLS certificate ($tls_cert)..."
  run_priv mkdir -p "$(dirname "$tls_cert")"
  san_ext="$(build_openssl_san_ext "$node_ip" "$node_hostname" "$advertised_url")"
  run_priv openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
    -keyout "$tls_key" \
    -out "$tls_cert" \
    -subj "/CN=${node_hostname}" \
    -addext "subjectAltName=${san_ext}" >/dev/null 2>&1
  run_priv chmod 644 "$tls_cert"
  if [[ $EUID -ne 0 ]]; then
    run_priv chown "$(id -u):$(id -g)" "$tls_key" "$tls_cert"
  fi
  chmod 600 "$tls_key" 2>/dev/null || run_priv chmod 600 "$tls_key"

  local cert_pem
  cert_pem="$(cat "$tls_cert")"

  info "Pairing with Controller & pinning TLS certificate..."
  local join_json
  join_json="$(TGVP_CTRL="$controller_url" \
    TGVP_TOK="$join_token" \
    TGVP_HOST="$node_hostname" \
    TGVP_IP="$node_ip" \
    TGVP_PORT="$agent_port" \
    TGVP_URL="$advertised_url" \
    TGVP_CERT="$cert_pem" \
    node -e '
      const http = require("http");
      const https = require("https");
      const base = process.env.TGVP_CTRL.replace(/\/+$/, "") + "/";
      const u = new URL("api/v1/nodes/join/" + encodeURIComponent(process.env.TGVP_TOK), base);
      const body = JSON.stringify({
        endpointUrl: process.env.TGVP_URL,
        ipAddress: process.env.TGVP_IP,
        hostname: process.env.TGVP_HOST,
        agentPort: Number(process.env.TGVP_PORT || 8443),
        tlsCertPem: process.env.TGVP_CERT,
        verifySsl: true
      });
      const mod = u.protocol === "https:" ? https : http;
      const req = mod.request(u, {
        method: "POST",
        rejectUnauthorized: false,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body)
        }
      }, (res) => {
        let data = "";
        res.on("data", (c) => data += c);
        res.on("end", () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            console.error("HTTP " + res.statusCode + ": " + data);
            process.exit(1);
          }
          console.log(data);
        });
      });
      req.on("error", (e) => { console.error(e.message); process.exit(1); });
      req.write(body);
      req.end();
    ')"

  local node_id node_api_key node_hmac_secret lxc_dir
  node_id="$(printf "%s" "$join_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.nodeId));')"
  node_api_key="$(printf "%s" "$join_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.apiKey));')"
  node_hmac_secret="$(printf "%s" "$join_json" | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); process.stdout.write(String(j.hmacSecret));')"
  lxc_dir="${TGVPANEL_LXC_DIR:-/var/lib/lxc}"

  cd "$APP_DIR"
  mkdir -p "$APP_DIR/data" "$APP_DIR/backups"
  run_priv mkdir -p "$lxc_dir"
  rm -f "$APP_DIR/data/node-agent-credentials.json"
  [[ ! -f "$APP_DIR/.env" && -f "$APP_DIR/.env.example" ]] && cp "$APP_DIR/.env.example" "$APP_DIR/.env"

  upsert_env_val "NODE_ENV" "production" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_NODE_ID" "$node_id" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_HOST" "0.0.0.0" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_PORT" "$agent_port" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_NODE_API_KEY" "$node_api_key" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_NODE_HMAC_SECRET" "$node_hmac_secret" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_CONTROLLER_URL" "$controller_url" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_TLS_CERT" "$tls_cert" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_AGENT_TLS_KEY" "$tls_key" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_DATA_DIR" "$APP_DIR/data" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_LXC_DIR" "$lxc_dir" "$APP_DIR/.env"
  upsert_env_val "TGVPANEL_BACKUP_DIR" "$APP_DIR/backups" "$APP_DIR/.env"
  chmod 600 "$APP_DIR/.env"

  configure_firewall_port "$agent_port" "" "TGVPANEL Node Agent" || true
  start_agent_24_7 "$APP_DIR" "$agent_port"

  for _ in $(seq 1 20); do
    if curl -ks "https://127.0.0.1:${agent_port}/api/v1/ping" 2>/dev/null | grep -q "tgvpanel-node-agent"; then
      break
    fi
    sleep 1
  done

  ok "Node #${node_id} paired, TLS-pinned, and running 24/7 at ${advertised_url}!"
}

# ==============================================================================
# OPTION 3: Migration Center
# ==============================================================================
migration_run_schema() {
  if [[ ! -f "$APP_DIR/package.json" ]]; then
    err "TGVPANEL is not installed at $APP_DIR yet. Run Option 1 first."
    return 1
  fi
  cd "$APP_DIR"
  if [[ ! -f "$APP_DIR/lib/db/cli-migrate.js" ]]; then
    npm run build
  fi
  info "Backing up database & applying latest TGVPANEL schema migrations..."
  npm run migrate
  ok "Database schema migrations completed."
}

migration_import_legacy_db() {
  if [[ ! -f "$APP_DIR/package.json" ]]; then
    err "TGVPANEL is not installed at $APP_DIR yet. Run Option 1 first."
    return 1
  fi
  cd "$APP_DIR"
  echo ""
  local legacy_path
  legacy_path="$(prompt_default "Path to legacy SQLite database (.db) to import" "")"
  if [[ -z "$legacy_path" || ! -f "$legacy_path" ]]; then
    err "File not found: ${legacy_path:-<empty>}"
    return 1
  fi
  info "Creating automatic pre-import backup & importing legacy database..."
  npm run import:hvm -- "$legacy_path"
  ok "Legacy database imported into $APP_DIR/data/tgvpanel.db!"
  if [[ "$(get_service_state "tgvpanel" "$APP_DIR/data/tgvpanel-panel.pid")" == "running" ]]; then
    if prompt_yes_no "Restart TGVPANEL now to reload imported instances?" "Y"; then
      local p
      p="$(read_env_val "PORT" "$APP_DIR/.env")"
      start_panel_24_7 "$APP_DIR" "${p:-8080}"
    fi
  fi
}

migration_cross_node_lxc() {
  if [[ ! -f "$APP_DIR/data/tgvpanel.db" ]]; then
    err "Controller database ($APP_DIR/data/tgvpanel.db) not found. Run this on the Main Panel server."
    return 1
  fi
  cd "$APP_DIR"
  echo ""
  info "Loading registered Nodes & LXC Containers from TGVPANEL database..."
  node -e '
    const sqlite3 = require("sqlite3");
    const db = new sqlite3.Database("./data/tgvpanel.db");
    db.all("SELECT id, name, url, status, is_local, maintenance_mode FROM nodes ORDER BY id ASC", [], (e1, nodes) => {
      if (e1) { console.error(e1.message); process.exit(1); }
      console.log("\nRegistered Compute Nodes:");
      for (const n of nodes) {
        console.log(`  Node #${n.id} : ${n.name} (${n.is_local ? "localhost" : n.url}) [status=${n.status}${n.maintenance_mode ? ", maintenance" : ""}]`);
      }
      db.all("SELECT id, container_name, hostname, node_id, status, disk_gb, ip_address FROM lxc_instances ORDER BY id ASC", [], (e2, cts) => {
        if (e2) { console.error(e2.message); process.exit(1); }
        console.log("\nLXC Containers:");
        if (!cts.length) {
          console.log("  (No LXC containers found)");
        } else {
          for (const c of cts) {
            console.log(`  LXC #${c.id} : ${c.container_name} (on Node #${c.node_id}, status=${c.status}, disk=${c.disk_gb}GB, ip=${c.ip_address || "DHCP"})`);
          }
        }
        db.close();
      });
    });
  '

  echo ""
  local lxc_id
  lxc_id="$(prompt_default "Enter LXC ID to migrate (or leave blank to cancel)" "")"
  [[ -z "$lxc_id" ]] && return 0

  local target_node_id
  target_node_id="$(prompt_default "Enter Target Node ID" "")"
  [[ -z "$target_node_id" ]] && return 0

  local target_bridge
  target_bridge="$(prompt_default "Target Linux bridge on destination node" "lxcbr0")"
  local target_ip
  target_ip="$(prompt_default "Target IPv4 CIDR (optional, leave blank to auto/keep)" "")"
  local target_gw
  target_gw="$(prompt_default "Target IPv4 Gateway (optional, leave blank to auto/keep)" "")"

  info "Starting 7-Stage SHA-256 Verified Offline Migration (LXC #${lxc_id} -> Node #${target_node_id})..."
  TGVP_MIG_LXC="$lxc_id" \
  TGVP_MIG_NODE="$target_node_id" \
  TGVP_MIG_BR="$target_bridge" \
  TGVP_MIG_IP="$target_ip" \
  TGVP_MIG_GW="$target_gw" \
  node -e '
    (async () => {
      const sqlite3 = require("sqlite3");
      const { UnifiedDatabase, resolveAndMigrateDatabasePath } = require("./lib/db/database");
      const { NodeManager } = require("./lib/services/nodes/NodeClient");
      const { StorageManager } = require("./lib/services/storage/StorageManager");
      const { LXCAdapter } = require("./lib/services/virtualization/LXCAdapter");
      const { MigrationManager } = require("./lib/services/migration/MigrationManager");

      const dbPath = resolveAndMigrateDatabasePath("./data");
      const raw = new sqlite3.Database(dbPath);
      const db = new UnifiedDatabase(raw, dbPath);
      try {
        const nm = new NodeManager(db);
        const sm = new StorageManager(db, nm);
        const lxc = new LXCAdapter(db, nm);
        const mm = new MigrationManager(db, nm, sm, lxc);
        const job = await mm.startOfflineLxcMigration({
          lxcId: Number(process.env.TGVP_MIG_LXC),
          targetNodeId: Number(process.env.TGVP_MIG_NODE),
          targetBridge: process.env.TGVP_MIG_BR || "lxcbr0",
          targetIpv4: process.env.TGVP_MIG_IP || undefined,
          targetGateway: process.env.TGVP_MIG_GW || undefined,
          initiatedByUserId: 1
        });
        console.log(JSON.stringify(job, null, 2));
        if (job.status !== "completed") process.exit(1);
      } finally {
        await db.close();
      }
    })().catch((err) => {
      console.error("[Migration Failed]:", err.message);
      process.exit(1);
    });
  '
  ok "Cross-node LXC migration completed and verified!"
}

migration_panel_bundle() {
  if [[ ! -f "$APP_DIR/package.json" ]]; then
    err "TGVPANEL is not installed at $APP_DIR yet."
    return 1
  fi
  cd "$APP_DIR"
  echo ""
  echo "Panel Server-to-Server Migration Bundle:"
  echo "  1) Export Panel Bundle (tgvpanel.db + .tgvpanel-secret + .env -> .tar.gz)"
  echo "  2) Import Panel Bundle (restore .tar.gz onto this server)"
  local sub
  sub="$(prompt_default "Choice (1-2)" "1")"

  if [[ "$sub" == "1" ]]; then
    local stamp
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    local out_dir="$APP_DIR/data/backups"
    mkdir -p "$out_dir"
    local stage_dir
    stage_dir="$(mktemp -d)"
    local bundle_file="$out_dir/tgvpanel_panel_migration_${stamp}.tar.gz"

    if [[ -f "$APP_DIR/data/tgvpanel.db" ]]; then
      info "Creating consistent SQLite snapshot..."
      STAGE_DB="$stage_dir/tgvpanel.db" node -e '
        const sqlite3 = require("sqlite3");
        const db = new sqlite3.Database("./data/tgvpanel.db");
        db.run("VACUUM INTO " + JSON.stringify(process.env.STAGE_DB), (err) => {
          if (err) { console.error(err); process.exit(1); }
          db.close();
        });
      '
    fi
    [[ -f "$APP_DIR/.tgvpanel-secret" ]] && cp -f "$APP_DIR/.tgvpanel-secret" "$stage_dir/.tgvpanel-secret"
    [[ -f "$APP_DIR/.env" ]] && cp -f "$APP_DIR/.env" "$stage_dir/.env"

    tar -czf "$bundle_file" -C "$stage_dir" .
    chmod 600 "$bundle_file"
    rm -rf "$stage_dir"
    local sha=""
    if command -v sha256sum >/dev/null 2>&1; then
      sha="$(sha256sum "$bundle_file" | awk '{print $1}')"
      echo "$sha  $(basename "$bundle_file")" > "${bundle_file}.sha256"
    fi
    ok "Exported Panel Migration Bundle: $bundle_file"
    [[ -n "$sha" ]] && info "SHA-256: $sha"
  elif [[ "$sub" == "2" ]]; then
    local bundle_in
    bundle_in="$(prompt_default "Path to exported tgvpanel_panel_migration_*.tar.gz" "")"
    if [[ -z "$bundle_in" || ! -f "$bundle_in" ]]; then
      err "Archive not found: ${bundle_in:-<empty>}"
      return 1
    fi
    if ! prompt_yes_no "Restore panel DB & secret vault from $bundle_in? (Current DB will be backed up first)" "N"; then
      return 0
    fi
    local stage_in
    stage_in="$(mktemp -d)"
    tar -xzf "$bundle_in" -C "$stage_in"
    mkdir -p "$APP_DIR/data/backups"
    if [[ -f "$APP_DIR/data/tgvpanel.db" ]]; then
      cp -f "$APP_DIR/data/tgvpanel.db" "$APP_DIR/data/backups/tgvpanel_before_bundle_restore_$(date -u +%Y%m%dT%H%M%SZ).db"
    fi
    stop_managed_service "tgvpanel" "$APP_DIR/data/tgvpanel-panel.pid" "$APP_DIR/app.js"
    rm -f "$APP_DIR/data/tgvpanel.db-wal" "$APP_DIR/data/tgvpanel.db-shm"
    [[ -f "$stage_in/tgvpanel.db" ]] && cp -f "$stage_in/tgvpanel.db" "$APP_DIR/data/tgvpanel.db"
    if [[ -f "$stage_in/.tgvpanel-secret" ]]; then
      cp -f "$stage_in/.tgvpanel-secret" "$APP_DIR/.tgvpanel-secret"
      chmod 600 "$APP_DIR/.tgvpanel-secret"
    fi
    if [[ -f "$stage_in/.env" ]]; then
      cp -f "$stage_in/.env" "$APP_DIR/.env"
      chmod 600 "$APP_DIR/.env"
    fi
    rm -rf "$stage_in"
    npm run migrate
    local p
    p="$(read_env_val "PORT" "$APP_DIR/.env")"
    start_panel_24_7 "$APP_DIR" "${p:-8080}"
    ok "Panel Migration Bundle restored and TGVPANEL restarted 24/7!"
  fi
}

option_migration_menu() {
  print_section_banner "[3] TGVPANEL Migration Center"
  local target_dir
  target_dir="$(prompt_default "TGVPANEL directory" "$APP_DIR")"
  APP_DIR="$target_dir"

  echo ""
  echo "Select Migration Type:"
  echo "  1) Run Database Schema Migrations        (Backup DB + apply latest migrations)"
  echo "  2) Import Legacy Database                (Migrate HVM / older .db into TGVPANEL)"
  echo "  3) Migrate LXC VPS Between Nodes         (7-Stage SHA-256 Verified Cross-Node Transfer)"
  echo "  4) Export / Import Full Panel Bundle     (Move Controller Panel to a New Server)"
  echo "  0) Back to Main Menu"
  local m_choice
  m_choice="$(prompt_default "Choice (0-4)" "1")"
  case "$m_choice" in
    1) migration_run_schema ;;
    2) migration_import_legacy_db ;;
    3) migration_cross_node_lxc ;;
    4) migration_panel_bundle ;;
    0) return 0 ;;
    *) warn "Invalid selection." ;;
  esac
}

# ==============================================================================
# OPTION 4: Auto Update (Zero-Data-Loss Backup -> Git Pull -> Build -> Restart)
# ==============================================================================
option_auto_update() {
  print_section_banner "[4] Zero-Data-Loss Auto Update"
  local target_dir="${1:-}"
  if [[ -z "$target_dir" ]]; then
    target_dir="$(prompt_default "TGVPANEL directory to update" "$APP_DIR")"
  fi
  if [[ ! -f "$target_dir/package.json" ]]; then
    err "No TGVPANEL installation found at $target_dir. Use Option 1 or Option 2 first."
    return 1
  fi
  APP_DIR="$target_dir"
  cd "$APP_DIR"

  local panel_was_running=0
  local agent_was_running=0
  [[ "$(get_service_state "tgvpanel" "$APP_DIR/data/tgvpanel-panel.pid")" == "running" ]] && panel_was_running=1
  [[ "$(get_service_state "tgvpanel-node-agent" "$APP_DIR/data/tgvpanel-agent.pid")" == "running" ]] && agent_was_running=1

  bash "$APP_DIR/scripts/update.sh"

  # Refresh xterm vendor bundle as well
  mkdir -p public/vendor/xterm
  [[ -f node_modules/@xterm/xterm/lib/xterm.js ]] && cp -f node_modules/@xterm/xterm/lib/xterm.js public/vendor/xterm/xterm.js
  [[ -f node_modules/@xterm/xterm/css/xterm.css ]] && cp -f node_modules/@xterm/xterm/css/xterm.css public/vendor/xterm/xterm.css
  [[ -f node_modules/@xterm/addon-fit/lib/addon-fit.js ]] && cp -f node_modules/@xterm/addon-fit/lib/addon-fit.js public/vendor/xterm/addon-fit.js

  install_global_shortcut "$APP_DIR"

  # Also restart non-systemd keepalive supervisors if active
  if ! is_systemd_active; then
    if [[ "$panel_was_running" -eq 1 ]]; then
      local p
      p="$(read_env_val "PORT" "$APP_DIR/.env")"
      start_panel_24_7 "$APP_DIR" "${p:-8080}"
    fi
    if [[ "$agent_was_running" -eq 1 ]]; then
      local ap
      ap="$(read_env_val "TGVPANEL_AGENT_PORT" "$APP_DIR/.env")"
      start_agent_24_7 "$APP_DIR" "${ap:-8443}"
    fi
  fi

  ok "Auto Update completed cleanly!"
}

# ==============================================================================
# OPTION 5: Service Status, Control & Live Logs
# ==============================================================================
print_status_summary() {
  local show_logo="${1:-0}"
  local panel_state agent_state panel_port agent_port
  panel_state="$(get_service_state "tgvpanel" "$APP_DIR/data/tgvpanel-panel.pid")"
  agent_state="$(get_service_state "tgvpanel-node-agent" "$APP_DIR/data/tgvpanel-agent.pid")"
  panel_port="$(read_env_val "PORT" "$APP_DIR/.env")"
  agent_port="$(read_env_val "TGVPANEL_AGENT_PORT" "$APP_DIR/.env")"

  if [[ "$show_logo" == "1" ]]; then
    echo ""
    print_ascii_logo
  fi

  echo ""
  echo -e "${C_BOLD}--- TGVPANEL Runtime Status ---${C_RESET}"
  echo -e "  Install Dir : ${C_BOLD}${APP_DIR}${C_RESET} ($([[ -f "$APP_DIR/package.json" ]] && echo "installed" || echo "not installed yet"))"
  echo -e "  Host IP     : $(detect_primary_ip)"
  echo -e "  Node.js     : $(command -v node >/dev/null 2>&1 && node -v || echo "not installed")"
  echo -e "  KVM /dev/kvm: $([[ -e /dev/kvm ]] && echo "available" || echo "not detected")"
  echo -e "  Native LXC  : $(command -v lxc-create >/dev/null 2>&1 && echo "installed ($(lxc-create --version 2>/dev/null || echo ok))" || echo "not installed")"
  echo -e "  Cgroups v2  : $([[ -f /sys/fs/cgroup/cgroup.controllers ]] && echo "active" || echo "legacy/partial")"
  echo -e "  Panel (24/7): $([[ "$panel_state" == "running" ]] && echo -e "${C_GREEN}RUNNING${C_RESET} (port ${panel_port:-8080})" || echo -e "${C_YELLOW}STOPPED${C_RESET}")"
  echo -e "  Node Agent  : $([[ "$agent_state" == "running" ]] && echo -e "${C_GREEN}RUNNING${C_RESET} (port ${agent_port:-8443})" || echo -e "${C_YELLOW}STOPPED${C_RESET}")"
}

option_service_control() {
  print_section_banner "[5] Service Status, Control & Live Logs"
  print_status_summary 0
  echo ""
  echo "Service Actions:"
  echo "  1) Restart Panel (24/7)"
  echo "  2) Stop Panel"
  echo "  3) Restart Node Agent (24/7)"
  echo "  4) Stop Node Agent"
  echo "  5) View Panel Logs (last 40 lines)"
  echo "  6) View Node Agent Logs (last 40 lines)"
  echo "  0) Back"
  local s_choice
  s_choice="$(prompt_default "Choice (0-6)" "0")"
  case "$s_choice" in
    1)
      local p
      p="$(read_env_val "PORT" "$APP_DIR/.env")"
      start_panel_24_7 "$APP_DIR" "${p:-8080}"
      ;;
    2)
      stop_managed_service "tgvpanel" "$APP_DIR/data/tgvpanel-panel.pid" "$APP_DIR/app.js"
      ok "Panel stopped."
      ;;
    3)
      local ap
      ap="$(read_env_val "TGVPANEL_AGENT_PORT" "$APP_DIR/.env")"
      start_agent_24_7 "$APP_DIR" "${ap:-8443}"
      ;;
    4)
      stop_managed_service "tgvpanel-node-agent" "$APP_DIR/data/tgvpanel-agent.pid" "$APP_DIR/lib/node-agent/agent.js"
      ok "Node Agent stopped."
      ;;
    5)
      if is_systemd_active; then
        run_priv journalctl -u tgvpanel.service -n 40 --no-pager || true
      elif [[ -f "$APP_DIR/data/logs/panel.log" ]]; then
        tail -n 40 "$APP_DIR/data/logs/panel.log"
      else
        warn "No panel logs found yet."
      fi
      ;;
    6)
      if is_systemd_active; then
        run_priv journalctl -u tgvpanel-node-agent.service -n 40 --no-pager || true
      elif [[ -f "$APP_DIR/data/logs/node-agent.log" ]]; then
        tail -n 40 "$APP_DIR/data/logs/node-agent.log"
      else
        warn "No node agent logs found yet."
      fi
      ;;
    *) ;;
  esac
}

# ==============================================================================
# Interactive Main Menu Loop & CLI Entrypoint
# ==============================================================================
render_banner() {
  local p_state a_state p_port a_port p_badge a_badge host_ip kvm_badge lxc_badge
  p_state="$(get_service_state "tgvpanel" "$APP_DIR/data/tgvpanel-panel.pid")"
  a_state="$(get_service_state "tgvpanel-node-agent" "$APP_DIR/data/tgvpanel-agent.pid")"
  p_port="$(read_env_val "PORT" "$APP_DIR/.env")"
  a_port="$(read_env_val "TGVPANEL_AGENT_PORT" "$APP_DIR/.env")"
  host_ip="$(detect_primary_ip)"

  if [[ "$p_state" == "running" ]]; then
    p_badge="${C_GREEN}● ONLINE (:${p_port:-8080})${C_RESET}"
  else
    p_badge="${C_DIM}○ STOPPED${C_RESET}"
  fi

  if [[ "$a_state" == "running" ]]; then
    a_badge="${C_GREEN}● ONLINE (:${a_port:-8443})${C_RESET}"
  else
    a_badge="${C_DIM}○ STOPPED${C_RESET}"
  fi

  if [[ -e /dev/kvm ]]; then
    kvm_badge="${C_GREEN}KVM:READY${C_RESET}"
  else
    kvm_badge="${C_DIM}KVM:N/A${C_RESET}"
  fi

  if command -v lxc-create >/dev/null 2>&1; then
    lxc_badge="${C_GREEN}LXC:READY${C_RESET}"
  else
    lxc_badge="${C_DIM}LXC:N/A${C_RESET}"
  fi

  clear 2>/dev/null || true
  printf "%b╔══════════════════════════════════════════════════════════════════════╗%b\n" "$C_CYAN" "$C_RESET"
  printf "%b║%b   %b%s%b  %b║%b\n" "$C_CYAN" "$C_RESET" "$C_GRAD1" "$TGVPANEL_ASCII_1" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b║%b   %b%s%b  %b║%b\n" "$C_CYAN" "$C_RESET" "$C_GRAD2" "$TGVPANEL_ASCII_2" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b║%b   %b%s%b  %b║%b\n" "$C_CYAN" "$C_RESET" "$C_GRAD3" "$TGVPANEL_ASCII_3" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b║%b   %b%s%b  %b║%b\n" "$C_CYAN" "$C_RESET" "$C_GRAD4" "$TGVPANEL_ASCII_4" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b║%b   %b%s%b  %b║%b\n" "$C_CYAN" "$C_RESET" "$C_GRAD5" "$TGVPANEL_ASCII_5" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b║%b                                                                      %b║%b\n" "$C_CYAN" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b║%b        %bUNIFIED VIRTUALIZATION MANAGEMENT MENU  •  VERSION 3.0%b        %b║%b\n" "$C_CYAN" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b║%b          %bQEMU/KVM Virtual Machines  •  LXC Containers  •  24/7%b       %b║%b\n" "$C_CYAN" "$C_RESET" "$C_DIM" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf "%b╠══════════════════════════════════════════════════════════════════════╣%b\n" "$C_CYAN" "$C_RESET"
  echo -e "  Panel : ${p_badge}      Node Agent : ${a_badge}"
  echo -e "  Host  : ${C_BOLD}${host_ip}${C_RESET}   (${kvm_badge} • ${lxc_badge})   Path: ${C_BOLD}${APP_DIR}${C_RESET}"
  printf "%b╠══════════════════════════════════════════════════════════════════════╣%b\n" "$C_CYAN" "$C_RESET"
  echo -e "  ${C_CYAN}[1]${C_RESET} ${C_BOLD}Auto Install & Setup Panel${C_RESET}   ${C_DIM}(GitHub -> Deps -> Run Panel 24/7)${C_RESET}"
  echo -e "  ${C_CYAN}[2]${C_RESET} ${C_BOLD}Auto Configure Node${C_RESET}          ${C_DIM}(Interactive Setup -> Online 24/7)${C_RESET}"
  echo -e "  ${C_CYAN}[3]${C_RESET} ${C_BOLD}Migration${C_RESET}                    ${C_DIM}(Schema / Legacy DB / Node VPS / Bundle)${C_RESET}"
  echo -e "  ${C_CYAN}[4]${C_RESET} ${C_BOLD}Auto Update${C_RESET}                  ${C_DIM}(Safe DB Backup -> Git Pull -> Rebuild)${C_RESET}"
  echo -e "  ${C_CYAN}[5]${C_RESET} ${C_BOLD}Service Status & Live Logs${C_RESET}   ${C_DIM}(Start / Stop / Restart / Logs)${C_RESET}"
  echo -e "  ${C_CYAN}[0]${C_RESET} ${C_BOLD}Exit${C_RESET}"
  printf "%b╚══════════════════════════════════════════════════════════════════════╝%b\n" "$C_CYAN" "$C_RESET"
}

print_help() {
  echo ""
  print_ascii_logo
  cat <<EOF

Usage:
  sudo bash menu.sh                                  Launch interactive menu
  sudo bash menu.sh --join <PANEL_URL> <JOIN_TOKEN>  Auto-install, pair & start remote Node Agent 24/7
  sudo bash menu.sh --status                         Print Panel & Node Agent status summary
  sudo bash menu.sh --migrate-db                     Backup DB & run schema migrations non-interactively
  sudo bash menu.sh --update                         Run safe zero-data-loss Auto Update non-interactively
  sudo bash menu.sh --help                           Show this help message
EOF
}

main() {
  case "${1:-}" in
    --help|-h)
      print_help
      exit 0
      ;;
    --join)
      headless_join_node "${2:-}" "${3:-}" "${4:-}"
      exit 0
      ;;
    --status)
      print_status_summary 1
      exit 0
      ;;
    --migrate-db)
      migration_run_schema
      exit 0
      ;;
    --update)
      option_auto_update "$APP_DIR"
      exit 0
      ;;
  esac

  # If piped via `curl ... | sudo bash`, attach to controlling terminal when available
  if [[ ! -t 0 && "${TGVPANEL_MENU_STDIN:-0}" != "1" ]] && (: < /dev/tty) 2>/dev/null; then
    exec < /dev/tty
  fi

  while true; do
    render_banner
    local choice=""
    read -r -p "$(printf "\n${C_CYAN}Select an option [0-5]:${C_RESET} ")" choice || break
    case "${choice}" in
      1)
        option_install_panel || warn "Panel setup encountered an error."
        pause_menu
        ;;
      2)
        option_configure_node || warn "Node configuration encountered an error."
        pause_menu
        ;;
      3)
        option_migration_menu || warn "Migration task encountered an error."
        pause_menu
        ;;
      4)
        option_auto_update "" || warn "Update encountered an error."
        pause_menu
        ;;
      5)
        option_service_control || true
        pause_menu
        ;;
      0|q|Q|exit)
        echo "Goodbye!"
        exit 0
        ;;
      *)
        warn "Invalid choice '${choice}'. Please enter 1, 2, 3, 4, 5, or 0."
        sleep 1
        ;;
    esac
  done
}

main "$@"
