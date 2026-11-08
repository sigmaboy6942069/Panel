#!/usr/bin/env bash
# TGVPANEL Fetch - lightweight VPS/system information dashboard
# Compatible with Bash 4+ and common Ubuntu/Debian VPS environments.
# Uses /proc and standard utilities; curl/ip/systemd-detect-virt are optional.

set -u

# ---------- Colors ----------
if [[ -t 1 && "${NO_COLOR:-}" == "" ]]; then
    RESET=$'\033[0m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    CYAN=$'\033[38;5;45m'
    BLUE=$'\033[38;5;39m'
    GREEN=$'\033[38;5;82m'
    YELLOW=$'\033[38;5;220m'
    RED=$'\033[38;5;196m'
    WHITE=$'\033[97m'
    GRAY=$'\033[90m'
else
    RESET='' BOLD='' DIM='' CYAN='' BLUE='' GREEN='' YELLOW='' RED='' WHITE='' GRAY=''
fi

# ---------- Helpers ----------
have() { command -v "$1" >/dev/null 2>&1; }

clean() {
    # Keep terminal output on one line and strip control characters.
    printf '%s' "${1:-Unknown}" | tr '\n\r' '  ' | cut -c1-100
}

human_bytes() {
    local n=${1:-0}
    if have numfmt; then
        numfmt --to=iec-i --suffix=B "$n" 2>/dev/null || printf '%s B' "$n"
    else
        awk -v n="$n" 'BEGIN {
            split("B KiB MiB GiB TiB",u," ");
            i=1; while(n>=1024 && i<5){n/=1024;i++}
            printf "%.1f %s",n,u[i]
        }'
    fi
}

bar() {
    local percent=${1:-0} width=${2:-20} filled empty color
    (( percent < 0 )) && percent=0
    (( percent > 100 )) && percent=100
    filled=$(( percent * width / 100 ))
    empty=$(( width - filled ))
    color=$GREEN
    (( percent >= 70 )) && color=$YELLOW
    (( percent >= 90 )) && color=$RED
    printf '%s' "$color"
    printf '%*s' "$filled" '' | tr ' ' '█'
    printf '%s' "$GRAY"
    printf '%*s' "$empty" '' | tr ' ' '░'
    printf '%s' "$RESET"
}

line() {
    printf '%s%s%s\n' "$GRAY" "  ──────────────────────────────────────────────────────────────" "$RESET"
}

label() {
    printf '  %s%-13s%s ' "$CYAN" "$1" "$RESET"
}

# ---------- System data ----------
HOSTNAME_VALUE=$(hostname 2>/dev/null || printf 'Unknown')
OS_VALUE="Unknown"
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_VALUE="${PRETTY_NAME:-${NAME:-Unknown}}"
fi
KERNEL_VALUE=$(uname -r 2>/dev/null || printf 'Unknown')
ARCH_VALUE=$(uname -m 2>/dev/null || printf 'Unknown')
UPTIME_VALUE=$(uptime -p 2>/dev/null | sed 's/^up //' || true)
[[ -n "$UPTIME_VALUE" ]] || UPTIME_VALUE=$(awk '{d=int($1/86400);h=int(($1%86400)/3600);m=int(($1%3600)/60); if(d)printf "%dd ",d; if(h)printf "%dh ",h; printf "%dm",m}' /proc/uptime 2>/dev/null)

CPU_MODEL=$(awk -F: '/model name/ {sub(/^[ \t]+/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)
[[ -n "$CPU_MODEL" ]] || CPU_MODEL=$(awk -F: '/Hardware/ {sub(/^[ \t]+/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)
[[ -n "$CPU_MODEL" ]] || CPU_MODEL="Unknown CPU"
CPU_CORES=$(getconf _NPROCESSORS_ONLN 2>/dev/null || awk '/^processor/ {n++} END{print n+0}' /proc/cpuinfo)
[[ "$CPU_CORES" =~ ^[0-9]+$ ]] || CPU_CORES=0

# CPU usage from /proc/stat. A short sample gives a current approximate value.
cpu_usage() {
    local user nice system idle iowait irq softirq steal total1 idle1 total2 idle2
    read -r _ user nice system idle iowait irq softirq steal _ < /proc/stat
    total1=$((user+nice+system+idle+iowait+irq+softirq+steal))
    idle1=$((idle+iowait))
    sleep 0.35
    read -r _ user nice system idle iowait irq softirq steal _ < /proc/stat
    total2=$((user+nice+system+idle+iowait+irq+softirq+steal))
    idle2=$((idle+iowait))
    if (( total2 > total1 )); then
        awk -v t1="$total1" -v t2="$total2" -v i1="$idle1" -v i2="$idle2" \
            'BEGIN {printf "%d", (1-(i2-i1)/(t2-t1))*100}'
    else
        printf '0'
    fi
}
CPU_USAGE=$(cpu_usage 2>/dev/null || printf '0')
[[ "$CPU_USAGE" =~ ^[0-9]+$ ]] || CPU_USAGE=0

MEM_TOTAL=$(awk '/MemTotal:/ {print $2*1024}' /proc/meminfo 2>/dev/null)
MEM_AVAIL=$(awk '/MemAvailable:/ {print $2*1024}' /proc/meminfo 2>/dev/null)
[[ "$MEM_TOTAL" =~ ^[0-9]+$ ]] || MEM_TOTAL=0
[[ "$MEM_AVAIL" =~ ^[0-9]+$ ]] || MEM_AVAIL=0
MEM_USED=$(( MEM_TOTAL > MEM_AVAIL ? MEM_TOTAL-MEM_AVAIL : 0 ))
MEM_PERCENT=0
(( MEM_TOTAL > 0 )) && MEM_PERCENT=$(( MEM_USED*100/MEM_TOTAL ))

SWAP_TOTAL=$(awk '/SwapTotal:/ {print $2*1024}' /proc/meminfo 2>/dev/null)
SWAP_FREE=$(awk '/SwapFree:/ {print $2*1024}' /proc/meminfo 2>/dev/null)
[[ "$SWAP_TOTAL" =~ ^[0-9]+$ ]] || SWAP_TOTAL=0
[[ "$SWAP_FREE" =~ ^[0-9]+$ ]] || SWAP_FREE=0
SWAP_USED=$(( SWAP_TOTAL > SWAP_FREE ? SWAP_TOTAL-SWAP_FREE : 0 ))
SWAP_PERCENT=0
(( SWAP_TOTAL > 0 )) && SWAP_PERCENT=$(( SWAP_USED*100/SWAP_TOTAL ))

DISK_LINE=$(df -P -B1 / 2>/dev/null | awk 'NR==2 {print $2, $3, $4, $5}')
read -r DISK_TOTAL DISK_USED DISK_FREE DISK_PERCENT_RAW <<< "$DISK_LINE"
DISK_TOTAL=${DISK_TOTAL:-0}; DISK_USED=${DISK_USED:-0}; DISK_FREE=${DISK_FREE:-0}
DISK_PERCENT=${DISK_PERCENT_RAW%%%}
[[ "$DISK_PERCENT" =~ ^[0-9]+$ ]] || DISK_PERCENT=0

PRIVATE_IP="Unavailable"
if have hostname; then
    PRIVATE_IP=$(hostname -I 2>/dev/null | awk '{$1=$1; print; exit}')
fi
[[ -n "$PRIVATE_IP" ]] || PRIVATE_IP="Unavailable"

PUBLIC_IP="Not checked"
if have curl; then
    PUBLIC_IP=$(curl -4 -fsS --connect-timeout 2 --max-time 3 https://api.ipify.org 2>/dev/null || true)
    [[ -n "$PUBLIC_IP" ]] || PUBLIC_IP="Unavailable"
fi

VIRT="Physical / Unknown"
if have systemd-detect-virt; then
    VIRT=$(systemd-detect-virt 2>/dev/null || true)
    [[ -n "$VIRT" ]] || VIRT="none (physical or undetected)"
fi

DOCKER_STATUS="Not installed"
if have docker; then
    if docker info >/dev/null 2>&1; then DOCKER_STATUS="Running"; else DOCKER_STATUS="Installed / stopped"; fi
fi

LXC_STATUS="Not installed"
if have lxc-info || have lxc-ls || have lxc; then LXC_STATUS="Installed"; fi
if [[ "$VIRT" == *lxc* ]]; then LXC_STATUS="Running inside LXC"; fi

SYSTEMD_STATUS="Unavailable"
have systemctl && SYSTEMD_STATUS="Available"

# Network interface: prefer the default route's interface when `ip` exists.
NET_IFACE="Unknown"
if have ip; then
    NET_IFACE=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
    [[ -n "$NET_IFACE" ]] || NET_IFACE=$(ip -o link 2>/dev/null | awk -F': ' '$2!="lo" {gsub(/@.*/,"",$2); print $2; exit}')
fi

# ---------- Display ----------
clear 2>/dev/null || true
printf '\n'
printf '%s' "$CYAN"
cat <<'LOGO'
       _______  _______  _______
      |__   __||  ____||  _____|
         | |   | |__   | |__
         | |   |  __|  |  __|
         | |   | |     | |
         |_|   |_|     |_|
LOGO
printf '%s' "$RESET"
printf '  %sTGVPANEL FETCH%s %s• VPS SYSTEM OVERVIEW%s\n' "$BOLD$WHITE" "$RESET" "$GRAY" "$RESET"
printf '  %s%s%s  %s\n' "$DIM" "Live system snapshot" "$RESET" "$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date)"
line

printf '\n  %sSYSTEM%s\n' "$BOLD$BLUE" "$RESET"
label "Hostname"; printf '%s\n' "$(clean "$HOSTNAME_VALUE")"
label "Operating OS"; printf '%s\n' "$(clean "$OS_VALUE")"
label "Kernel"; printf '%s\n' "$(clean "$KERNEL_VALUE")  ($ARCH_VALUE)"
label "Uptime"; printf '%s\n' "$(clean "${UPTIME_VALUE:-Unknown}")"
label "Virtualization"; printf '%s\n' "$(clean "$VIRT")"

printf '\n  %sPROCESSOR & MEMORY%s\n' "$BOLD$BLUE" "$RESET"
label "CPU"; printf '%s\n' "$(clean "$CPU_MODEL")"
label "CPU cores"; printf '%s\n' "$CPU_CORES vCPU / logical cores"
label "CPU usage"; printf '%s %3s%%  ' "$(bar "$CPU_USAGE" 20)" "$CPU_USAGE"; printf '\n'
label "RAM"; printf '%s / %s  (%s%%)\n' "$(human_bytes "$MEM_USED")" "$(human_bytes "$MEM_TOTAL")" "$MEM_PERCENT"
label "RAM usage"; printf '%s %3s%%\n' "$(bar "$MEM_PERCENT" 20)" "$MEM_PERCENT"
if (( SWAP_TOTAL > 0 )); then
    label "Swap"; printf '%s / %s  (%s%%)\n' "$(human_bytes "$SWAP_USED")" "$(human_bytes "$SWAP_TOTAL")" "$SWAP_PERCENT"
fi

printf '\n  %sSTORAGE%s\n' "$BOLD$BLUE" "$RESET"
label "Root disk"; printf '%s / %s  (%s%%)\n' "$(human_bytes "$DISK_USED")" "$(human_bytes "$DISK_TOTAL")" "$DISK_PERCENT"
label "Disk usage"; printf '%s %3s%%\n' "$(bar "$DISK_PERCENT" 20)" "$DISK_PERCENT"
label "Free space"; printf '%s\n' "$(human_bytes "$DISK_FREE")"

printf '\n  %sNETWORK%s\n' "$BOLD$BLUE" "$RESET"
label "Interface"; printf '%s\n' "$(clean "$NET_IFACE")"
label "Private IP"; printf '%s\n' "$(clean "$PRIVATE_IP")"
label "Public IPv4"; printf '%s\n' "$(clean "$PUBLIC_IP")"

printf '\n  %sCONTAINER & SERVICES%s\n' "$BOLD$BLUE" "$RESET"
label "Docker"; printf '%s\n' "$(clean "$DOCKER_STATUS")"
label "LXC"; printf '%s\n' "$(clean "$LXC_STATUS")"
label "Systemd"; printf '%s\n' "$(clean "$SYSTEMD_STATUS")"

line
printf '  %sTGVPANEL FETCH%s %s• Built for VPS administrators%s\n\n' "$BOLD$CYAN" "$RESET" "$DIM" "$RESET"
