#!/usr/bin/env bash
# =============================================================================
# Rikune — Hybrid Diagnostic Script
# Run on the Linux host to diagnose connectivity and runtime issues.
# =============================================================================
set -euo pipefail

C_RESET="\033[0m"
C_CYAN="\033[36m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"

header()  { printf "\n${C_CYAN}==================================================${C_RESET}\n  ${C_CYAN}%s${C_RESET}\n${C_CYAN}==================================================${C_RESET}\n\n" "$1"; }
step()    { printf "\n${C_CYAN}[CHECK] %s${C_RESET}\n" "$1"; }
ok()      { printf "  ${C_GREEN}[PASS]${C_RESET} %s\n" "$1"; }
warn()    { printf "  ${C_YELLOW}[WARN]${C_RESET} %s\n" "$1"; }
err()     { printf "  ${C_RED}[FAIL]${C_RESET} %s\n" "$1"; }
info()    { printf "    %s\n" "$1"; }

WINDOWS_HOST=""
WINDOWS_USER="${WINDOWS_USER:-Administrator}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.hybrid.yml"
ENV_FILE="$PROJECT_ROOT/.env"

usage() {
  cat <<EOF
Usage: $0 -w <windows-host> [options]

Options:
  -w HOST    Windows host IP or hostname (required)
  -u USER    Windows SSH user (default: $WINDOWS_USER)
  -k KEY     SSH private key path (default: $SSH_KEY)
  -h         Show this help
EOF
  exit 1
}

while getopts ":w:u:k:h" opt; do
  case $opt in
    w) WINDOWS_HOST="$OPTARG" ;;
    u) WINDOWS_USER="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    h|*) usage ;;
  esac
done

[ -n "$WINDOWS_HOST" ] || { echo "Error: Windows host is required (-w)"; usage; }

header "Rikune — Hybrid Diagnostics"
info "Windows Host: $WINDOWS_HOST"

# ─────────────────────────────────────────────────────────────────────────────
# Linux side checks
# ─────────────────────────────────────────────────────────────────────────────
step "Linux Analyzer Container"

if [ -f "$COMPOSE_FILE" ]; then
  ok "docker-compose.hybrid.yml found"
else
  err "docker-compose.hybrid.yml not found. Run deploy-hybrid.sh first."
fi

if docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "rikune-analyzer"; then
  ok "Analyzer container is running"
  ANALYZER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' rikune-analyzer 2>/dev/null || true)
  info "Analyzer container IP: $ANALYZER_IP"
else
  err "Analyzer container is not running"
  info "Try: docker compose -f $COMPOSE_FILE up -d"
fi

if curl -sf http://localhost:18080/api/v1/health >/dev/null 2>&1; then
  ok "Analyzer API (localhost:18080) responds"
else
  err "Analyzer API (localhost:18080) does not respond"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Network path to Windows
# ─────────────────────────────────────────────────────────────────────────────
step "Network Path to Windows Host"

if ping -c 1 -W 2 "$WINDOWS_HOST" >/dev/null 2>&1; then
  ok "ICMP ping to $WINDOWS_HOST succeeds"
else
  warn "ICMP ping to $WINDOWS_HOST timed out (firewall may block ICMP)"
fi

for port in 22 18082; do
  if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$WINDOWS_HOST/$port" 2>/dev/null; then
    ok "TCP port $port on $WINDOWS_HOST is open"
  else
    err "TCP port $port on $WINDOWS_HOST is unreachable"
    if [ "$port" = "18082" ]; then
      info "Ensure Windows Defender Firewall allows inbound TCP $port"
      info "Run on Windows (Admin): netsh advfirewall firewall add rule name=RikuneHostAgent dir=in action=allow protocol=tcp localport=18082"
    fi
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
# Windows side checks (via SSH)
# ─────────────────────────────────────────────────────────────────────────────
step "Windows Host Agent Status"

SSH_BASE="ssh -o BatchMode=yes -o ConnectTimeout=5 -i $SSH_KEY ${WINDOWS_USER}@${WINDOWS_HOST}"

if $SSH_BASE "echo ok" >/dev/null 2>&1; then
  ok "SSH connectivity works"
else
  err "SSH to ${WINDOWS_USER}@${WINDOWS_HOST} failed"
  info "Ensure OpenSSH Server is running and the SSH key is authorized."
  exit 1
fi

HOST_AGENT_PID=$($SSH_BASE "powershell -Command '(Get-Process node -ErrorAction SilentlyContinue | Where-Object { \$_.CommandLine -like \"*windows-host-agent*\" }).Id'" 2>/dev/null || true)
if [ -n "$HOST_AGENT_PID" ] && [ "$HOST_AGENT_PID" != "" ]; then
  ok "Host Agent node process is running (PID: $HOST_AGENT_PID)"
else
  err "Host Agent node process not found"
  info "Try restarting it on Windows: powershell -File C:/rikune/install-runtime-windows.ps1 -Headless -Service"
fi

PORTPROXY=$($SSH_BASE "netsh interface portproxy show v4tov4" 2>/dev/null || true)
if echo "$PORTPROXY" | grep -q "1808"; then
  ok "netsh portproxy rules exist"
  info "$(echo "$PORTPROXY" | grep "1808" | sed 's/^/    /')"
else
  warn "No netsh portproxy rules found for 1808x ports"
  info "This is normal if no Sandbox is currently active."
fi

# ─────────────────────────────────────────────────────────────────────────────
# Host Agent API check from Linux
# ─────────────────────────────────────────────────────────────────────────────
step "Host Agent API Validation"

API_KEY=""
if [ -f "$ENV_FILE" ]; then
  API_KEY=$(grep '^RUNTIME_API_KEY=' "$ENV_FILE" | cut -d'=' -f2- || true)
fi

HOST_AGENT_URL="http://${WINDOWS_HOST}:18082"
if [ -n "$API_KEY" ]; then
  HEALTH=$(curl -sf -H "Authorization: Bearer $API_KEY" "${HOST_AGENT_URL}/sandbox/health" 2>/dev/null || true)
else
  HEALTH=$(curl -sf "${HOST_AGENT_URL}/sandbox/health" 2>/dev/null || true)
fi

if echo "$HEALTH" | grep -q '"ok":true'; then
  ok "Host Agent /sandbox/health responds"
  ACTIVE=$(echo "$HEALTH" | grep -o '"sandboxId"' | wc -l)
  info "Active sandboxes: $ACTIVE"
else
  err "Host Agent /sandbox/health did not return ok"
  info "Raw response: $HEALTH"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Windows Sandbox feature check
# ─────────────────────────────────────────────────────────────────────────────
step "Windows Sandbox Feature"

SANDBOX_FEATURE=$($SSH_BASE "powershell -Command '(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClient).State'" 2>/dev/null || true)
if [ "$SANDBOX_FEATURE" = "Enabled" ]; then
  ok "Windows Sandbox feature is Enabled"
else
  err "Windows Sandbox feature state: ${SANDBOX_FEATURE:-unknown}"
  info "Enable with (Admin): Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClient"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
header "Diagnostics Complete"
info "If any checks failed, review the messages above."
info "For Windows-side manual verification, RDP or SSH to $WINDOWS_HOST and run:"
info "  Get-Process | Where-Object { \$_.ProcessName -like '*WindowsSandbox*' -or \$_.ProcessName -like '*node*' }"
