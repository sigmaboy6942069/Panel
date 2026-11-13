#!/usr/bin/env bash
# TGVPANEL diagnostic: why is my domain not opening?
#
# Read-only. Changes nothing, installs nothing. Prints what is actually true
# about the running panel, the proxy in front of it, and DNS.
#
#   sudo bash diagnose-panel.sh
#
# Optional: pass your domain to test DNS and the public URL end to end.
#   sudo bash diagnose-panel.sh panel.example.com

set -u

DOMAIN="${1:-}"
DIR="$(systemctl show -p WorkingDirectory --value tgvpanel 2>/dev/null)"
[[ -z "$DIR" || "$DIR" == "-" ]] && DIR=/opt/tgvpanel

pass() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
info() { printf '  ---- %s\n' "$1"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

echo "TGVPANEL diagnostics  ($(date -Is))"
echo "install dir: $DIR"

VERDICTS=()

head_ "1. Service"
if systemctl is-active --quiet tgvpanel; then
  pass "tgvpanel is active"
else
  fail "tgvpanel is NOT running (state: $(systemctl is-active tgvpanel 2>/dev/null || echo unknown))"
  VERDICTS+=("service-down")
fi

RESTARTS="$(systemctl show -p NRestarts --value tgvpanel 2>/dev/null || echo 0)"
info "restart count: $RESTARTS"
if [[ "${RESTARTS:-0}" -gt 5 ]]; then
  warn "the service has restarted $RESTARTS times — it is crash-looping, check journalctl"
  VERDICTS+=("crash-loop")
fi

head_ "2. What it is bound to"
PORT_ENV="$(systemctl show -p Environment --value tgvpanel 2>/dev/null | tr ' ' '\n' | grep '^PORT=' | cut -d= -f2)"
BIND_ENV="$(systemctl show -p Environment --value tgvpanel 2>/dev/null | tr ' ' '\n' | grep '^TGVPANEL_BIND_HOST=' | cut -d= -f2)"
PORT_FILE="$(grep -E '^PORT=' "$DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2)"
BIND_FILE="$(grep -E '^TGVPANEL_BIND_HOST=' "$DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2)"

PORT="${PORT_ENV:-${PORT_FILE:-8080}}"
info "port: ${PORT:-8080}  (from $([[ -n "$PORT_ENV" ]] && echo 'systemd Environment' || echo '.env or default'))"
if [[ -n "$BIND_ENV" ]]; then
  warn "TGVPANEL_BIND_HOST=$BIND_ENV is forced by the systemd unit (not .env)"
  VERDICTS+=("bind-forced-by-unit")
elif [[ -n "$BIND_FILE" ]]; then
  warn "TGVPANEL_BIND_HOST=$BIND_FILE set in $DIR/.env"
  VERDICTS+=("bind-in-env-file")
else
  # Also check the live process: an override can come from the unit, .env, or
  # whatever started it. The listening socket is the only real authority, but
  # naming the source saves a round trip.
  PROC_BIND="$(tr '\0' '\n' < /proc/"$(pgrep -f 'app\.js' | head -1)"/environ 2>/dev/null | grep '^TGVPANEL_BIND_HOST=' | cut -d= -f2)"
  if [[ -n "$PROC_BIND" ]]; then
    warn "running process has TGVPANEL_BIND_HOST=$PROC_BIND (set outside systemd/.env)"
    VERDICTS+=("bind-set-in-process-env")
  else
    pass "no BIND_HOST override — panel should listen on 0.0.0.0"
  fi
fi

LISTEN="$(ss -lntp 2>/dev/null | grep -E "[:.]${PORT:-8080}\b" | head -3)"
if [[ -z "$LISTEN" ]]; then
  fail "nothing is listening on port ${PORT:-8080}"
  VERDICTS+=("not-listening")
else
  echo "$LISTEN" | sed 's/^/       /'
  if echo "$LISTEN" | grep -q '0.0.0.0:'"${PORT:-8080}"; then
    pass "listening on all interfaces (0.0.0.0)"
  elif echo "$LISTEN" | grep -q '127.0.0.1:'"${PORT:-8080}"; then
    warn "listening on loopback only — a tunnel or remote proxy cannot reach it"
    VERDICTS+=("loopback-only")
  elif echo "$LISTEN" | grep -q '\[::\]:'"${PORT:-8080}"; then
    pass "listening on IPv6 all interfaces ([::])"
  fi
fi

head_ "3. Does the panel itself answer locally?"
CODE_LOCAL="$(curl -s -o /dev/null -m 4 -w '%{http_code}' "http://127.0.0.1:${PORT:-8080}/login" 2>/dev/null)"
CODE_LOCAL="${CODE_LOCAL:0:3}"; CODE_LOCAL="${CODE_LOCAL:-000}"
if [[ "$CODE_LOCAL" =~ ^(200|302)$ ]]; then
  pass "127.0.0.1:${PORT:-8080} answers ($CODE_LOCAL)"
else
  fail "127.0.0.1:${PORT:-8080} does not answer (got '$CODE_LOCAL')"
  VERDICTS+=("panel-not-answering-locally")
fi

head_ "4. Firewall"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  info "ufw is active:"
  ufw status 2>/dev/null | sed -n '4,20p' | sed 's/^/       /'
else
  info "ufw not active (or not installed)"
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state 2>/dev/null | grep -q running; then
  info "firewalld is running"
fi
if command -v iptables >/dev/null; then
  DROPS="$(iptables -S 2>/dev/null | grep -cE 'DROP|REJECT' || echo 0)"
  info "iptables rules with DROP/REJECT: $DROPS"
fi

head_ "5. Reverse proxy"
NGINX_UP=0
if systemctl is-active --quiet nginx 2>/dev/null; then
  pass "nginx is active"
  NGINX_UP=1
else
  info "nginx is not active"
fi

if [[ $NGINX_UP -eq 1 ]]; then
  SITE="$(grep -rl "tgvpanel\|proxy_pass" /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null | head -3)"
  if [[ -z "$SITE" ]]; then
    fail "nginx has no site configured for the panel"
    VERDICTS+=("nginx-no-site")
  else
    for f in $SITE; do
      info "site: $f"
      grep -E "server_name|proxy_pass|listen" "$f" 2>/dev/null | sed 's/^/       /'
      PP="$(grep -oE 'proxy_pass +https?://[^;]+' "$f" 2>/dev/null | head -1 | sed -E 's#proxy_pass +##')"
      if [[ -n "$PP" ]]; then
        if [[ "$PP" =~ 127\.0\.0\.1:${PORT:-8080} || "$PP" =~ localhost:${PORT:-8080} || "$PP" =~ 0\.0\.0\.0:${PORT:-8080} ]]; then
          pass "proxies to $PP which matches the panel port"
        else
          warn "proxies to $PP but the panel listens on ${PORT:-8080} — port mismatch"
          VERDICTS+=("nginx-port-mismatch")
        fi
      fi
    done
  fi
  if nginx -t 2>&1 | grep -q successful; then
    pass "nginx config tests clean"
  else
    fail "nginx config has errors:"
    nginx -t 2>&1 | sed 's/^/       /'
  fi
fi

CLOUDFLARED=0
if systemctl is-active --quiet cloudflared 2>/dev/null; then
  pass "cloudflared is active"
  CLOUDFLARED=1
  CF_CONF="/etc/cloudflared/config.yml"
  if [[ -f "$CF_CONF" ]]; then
    info "cloudflared config:"
    grep -E "hostname|service" "$CF_CONF" | sed 's/^/       /'
    SVC="$(grep -oE 'service: *https?://[^ ]+' "$CF_CONF" | head -1 | sed -E 's#service: *##')"
    if [[ -n "$SVC" ]]; then
      SVC_CODE="$(curl -s -o /dev/null -m 4 -w '%{http_code}' "$SVC/login" 2>/dev/null)"
      SVC_CODE="${SVC_CODE:0:3}"; SVC_CODE="${SVC_CODE:-000}"
      if [[ "$SVC_CODE" =~ ^(200|302)$ ]]; then
        pass "tunnel target $SVC answers ($SVC_CODE)"
      else
        fail "tunnel target $SVC does not answer (got '$SVC_CODE')"
        VERDICTS+=("tunnel-target-unreachable")
      fi
    fi
  fi
else
  info "cloudflared is not active"
fi

head_ "6. Public reachability"
if [[ -n "$DOMAIN" ]]; then
  RESOLVED="$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1)"
  if [[ -z "$RESOLVED" ]]; then
    fail "$DOMAIN does not resolve"
    VERDICTS+=("dns-no-record")
  else
    pass "$DOMAIN resolves to $RESOLVED"
    if [[ "$RESOLVED" =~ ^104\.(1[6-9]|2[0-9]|3[01])\. ]]; then
      info "that is a Cloudflare address — origin IP is hidden (proxied)"
    fi
  fi
  for SCHEME in https http; do
    PC="$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$SCHEME://$DOMAIN/login" 2>/dev/null)"
    PC="${PC:0:3}"; PC="${PC:-000}"
    if [[ "$PC" =~ ^(200|301|302)$ ]]; then
      pass "$SCHEME://$DOMAIN answers ($PC)"
      break
    else
      fail "$SCHEME://$DOMAIN gave '$PC'"
      VERDICTS+=("public-$SCHEME-fail")
    fi
  done
else
  info "pass your domain as an argument to test DNS and the public URL:"
  info "  sudo bash $0 panel.example.com"
fi

head_ "7. Recent errors"
journalctl -u tgvpanel -n 200 --no-pager 2>/dev/null \
  | grep -iE "error|EADDRINUSE|EACCES|cannot find module" | tail -5 | sed 's/^/       /' || true
if [[ -z "$(journalctl -u tgvpanel -n 200 --no-pager 2>/dev/null | grep -iE 'error|EADDRINUSE|EACCES' | tail -1)" ]]; then
  pass "no errors in the last 200 log lines"
fi

head_ "SUMMARY"
if [[ ${#VERDICTS[@]} -eq 0 ]]; then
  printf '  \033[32mEverything checks out.\033[0m If the domain still fails, the problem is\n'
  echo  "  upstream of this machine: DNS, your registrar, or Cloudflare itself."
else
  printf '  \033[1mFindings:\033[0m\n'
  for v in "${VERDICTS[@]}"; do
    echo "    - $v"
  done
  echo
  echo "  Fix the first one, then re-run this script."
fi
echo
