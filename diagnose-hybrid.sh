#!/usr/bin/env bash
# Diagnose Rikune hybrid deployments.

set -euo pipefail

C_RESET="\033[0m"
C_CYAN="\033[36m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"

header() { printf "\n${C_CYAN}==================================================${C_RESET}\n  ${C_CYAN}%s${C_RESET}\n${C_CYAN}==================================================${C_RESET}\n\n" "$1"; }
step() { printf "\n${C_CYAN}[CHECK] %s${C_RESET}\n" "$1"; }
ok() { printf "  ${C_GREEN}[PASS]${C_RESET} %s\n" "$1"; }
warn() { printf "  ${C_YELLOW}[WARN]${C_RESET} %s\n" "$1"; }
err() { printf "  ${C_RED}[FAIL]${C_RESET} %s\n" "$1"; }
info() { printf "    %s\n" "$1"; }

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
WINDOWS_HOST=""
WINDOWS_USER="${WINDOWS_USER:-Administrator}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
ENV_FILE="$PROJECT_ROOT/.docker-runtime.env"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.hybrid.yml"

usage() {
  cat <<EOF
Usage: $0 -w <windows-host> [options]

Options:
  -w HOST    Windows host IP or hostname
  -u USER    Windows SSH user (default: $WINDOWS_USER)
  -k KEY     SSH private key path (default: $SSH_KEY)
  -h         Show this help
EOF
  exit 1
}

while getopts ":w:u:k:h" opt; do
  case "$opt" in
    w) WINDOWS_HOST="$OPTARG" ;;
    u) WINDOWS_USER="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    h|*) usage ;;
  esac
done

env_value() {
  local key="$1" file="$2"
  [ -f "$file" ] || return 0
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0,$2)); exit }' "$file"
}

if [ ! -f "$ENV_FILE" ] && [ -f "$PROJECT_ROOT/.env" ]; then
  ENV_FILE="$PROJECT_ROOT/.env"
fi

HOST_AGENT_ENDPOINT="$(env_value RUNTIME_HOST_AGENT_ENDPOINT "$ENV_FILE")"
HOST_AGENT_API_KEY="$(env_value RUNTIME_HOST_AGENT_API_KEY "$ENV_FILE")"
if [ -z "$HOST_AGENT_API_KEY" ]; then
  HOST_AGENT_API_KEY="$(env_value HOST_AGENT_API_KEY "$ENV_FILE")"
fi

if [ -z "$WINDOWS_HOST" ] && [ -n "$HOST_AGENT_ENDPOINT" ]; then
  WINDOWS_HOST="$(printf "%s" "$HOST_AGENT_ENDPOINT" | sed -E 's#^[a-zA-Z]+://([^:/]+).*#\1#')"
fi

if [ -z "$WINDOWS_HOST" ]; then
  err "Windows host was not provided and could not be inferred from $ENV_FILE"
  usage
fi

if [ -z "$HOST_AGENT_ENDPOINT" ]; then
  HOST_AGENT_ENDPOINT="http://${WINDOWS_HOST}:18082"
fi

HOST_AGENT_PORT="$(printf "%s" "$HOST_AGENT_ENDPOINT" | sed -nE 's#^[a-zA-Z]+://[^:/]+:([0-9]+).*#\1#p')"
if [ -z "$HOST_AGENT_PORT" ]; then
  HOST_AGENT_PORT="18082"
fi

header "Rikune Hybrid Diagnostics"
info "Project root: $PROJECT_ROOT"
info "Compose file: $COMPOSE_FILE"
info "Env file: $ENV_FILE"
info "Windows host: $WINDOWS_HOST"
info "Host Agent endpoint: $HOST_AGENT_ENDPOINT"

step "Linux analyzer container"

if [ -f "$COMPOSE_FILE" ]; then
  ok "docker-compose.hybrid.yml exists"
else
  err "docker-compose.hybrid.yml not found. Run: node scripts/generate-docker.mjs --profile=hybrid"
fi

if docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps analyzer 2>/dev/null | grep -q "rikune-analyzer"; then
  ok "Analyzer service is known to Docker Compose"
else
  err "Analyzer service is not running or Compose cannot find it"
  info "Try: docker compose --env-file $ENV_FILE -f $COMPOSE_FILE up -d analyzer"
fi

if docker ps --format '{{.Names}}' | grep -qx "rikune-analyzer"; then
  ok "Container rikune-analyzer is running"
  ANALYZER_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' rikune-analyzer 2>/dev/null || true)"
  [ -n "$ANALYZER_IP" ] && info "Analyzer container IP: $ANALYZER_IP"
else
  err "Container rikune-analyzer is not running"
fi

if curl -sf http://localhost:18080/api/v1/health >/dev/null 2>&1; then
  ok "Analyzer API responds on localhost:18080"
else
  err "Analyzer API does not respond on localhost:18080"
  info "Check: docker logs rikune-analyzer"
fi

step "Network path to Windows"

if ping -c 1 -W 2 "$WINDOWS_HOST" >/dev/null 2>&1; then
  ok "ICMP ping to $WINDOWS_HOST succeeds"
else
  warn "ICMP ping to $WINDOWS_HOST timed out; firewall may block ping"
fi

for port in 22 "$HOST_AGENT_PORT"; do
  if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$WINDOWS_HOST/$port" 2>/dev/null; then
    ok "TCP port $port on $WINDOWS_HOST is reachable"
  else
    err "TCP port $port on $WINDOWS_HOST is unreachable"
    if [ "$port" = "$HOST_AGENT_PORT" ]; then
      info "Open Windows Firewall inbound TCP $HOST_AGENT_PORT for the Host Agent"
    fi
  fi
done

step "Host Agent API"

if [ -n "$HOST_AGENT_API_KEY" ]; then
  HEALTH="$(curl -sf -H "Authorization: Bearer $HOST_AGENT_API_KEY" "$HOST_AGENT_ENDPOINT/sandbox/health" 2>/dev/null || true)"
else
  warn "RUNTIME_HOST_AGENT_API_KEY is missing; trying unauthenticated health request"
  HEALTH="$(curl -sf "$HOST_AGENT_ENDPOINT/sandbox/health" 2>/dev/null || true)"
fi

if printf "%s" "$HEALTH" | grep -q '"ok":true'; then
  ok "Host Agent /sandbox/health returned ok"
else
  err "Host Agent /sandbox/health did not return ok"
  info "Raw response: ${HEALTH:-<empty>}"
fi

step "Windows host state over SSH"

SSH_BASE=(ssh -o BatchMode=yes -o ConnectTimeout=5 -i "$SSH_KEY" "${WINDOWS_USER}@${WINDOWS_HOST}")

if "${SSH_BASE[@]}" "echo ok" >/dev/null 2>&1; then
  ok "SSH connectivity works"
else
  err "SSH to ${WINDOWS_USER}@${WINDOWS_HOST} failed"
  info "OpenSSH Server must be running and the SSH key must be authorized."
  header "Diagnostics Complete"
  exit 0
fi

HOST_AGENT_PID="$("${SSH_BASE[@]}" "powershell -NoProfile -Command \"(Get-CimInstance Win32_Process -Filter \\\"name='node.exe'\\\" | Where-Object { \\\$_.CommandLine -like '*windows-host-agent*' } | Select-Object -ExpandProperty ProcessId) -join ','\"" 2>/dev/null || true)"
if [ -n "$HOST_AGENT_PID" ]; then
  ok "Host Agent node process is running (PID: $HOST_AGENT_PID)"
else
  err "Host Agent node process was not found"
  info "Try on Windows: powershell -File C:/rikune/install-runtime-windows.ps1 -Headless -Service"
fi

SANDBOX_FEATURE="$("${SSH_BASE[@]}" "powershell -NoProfile -Command \"(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClient).State\"" 2>/dev/null || true)"
if [ "$SANDBOX_FEATURE" = "Enabled" ]; then
  ok "Windows Sandbox feature is enabled"
else
  err "Windows Sandbox feature state: ${SANDBOX_FEATURE:-unknown}"
  info "Enable on Windows Pro/Enterprise: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClient -All"
fi

PORTPROXY="$("${SSH_BASE[@]}" "netsh interface portproxy show v4tov4" 2>/dev/null || true)"
if printf "%s" "$PORTPROXY" | grep -q "1808"; then
  ok "netsh portproxy has 1808x rules"
  printf "%s\n" "$PORTPROXY" | grep "1808" | sed 's/^/    /' || true
else
  warn "No netsh portproxy rules for 1808x ports"
  info "This is normal when no Windows Sandbox runtime is active."
fi

header "Diagnostics Complete"
info "Failed checks above point to the exact side of the split deployment that needs attention."
