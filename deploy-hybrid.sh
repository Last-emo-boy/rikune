#!/usr/bin/env bash
# =============================================================================
# Rikune — Hybrid Deployment Script (Linux Analyzer + Windows Sandbox Runtime)
# Run this on the Linux host to orchestrate both sides.
# =============================================================================
set -euo pipefail

C_RESET="\033[0m"
C_CYAN="\033[36m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"

header()  { printf "\n${C_CYAN}==================================================${C_RESET}\n  ${C_CYAN}%s${C_RESET}\n${C_CYAN}==================================================${C_RESET}\n\n" "$1"; }
step()    { printf "\n${C_CYAN}[STEP] %s${C_RESET}\n${C_CYAN}-----------------------------------------${C_RESET}\n" "$1"; }
ok()      { printf "${C_GREEN}[OK]${C_RESET} %s\n" "$1"; }
warn()    { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$1"; }
err()     { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$1"; }
info()    { printf "  %s\n" "$1"; }

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
WINDOWS_HOST=""
WINDOWS_USER="${WINDOWS_USER:-Administrator}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
SKIP_WINDOWS_SETUP=false
DATA_ROOT="${RIKUNE_DATA_ROOT:-$HOME/.rikune}"

usage() {
  cat <<EOF
Usage: $0 -w <windows-host> [options]

Options:
  -w HOST    Windows host IP or hostname (required)
  -u USER    Windows SSH user (default: $WINDOWS_USER)
  -k KEY     SSH private key path (default: $SSH_KEY)
  -d DIR     Linux data root (default: $DATA_ROOT)
  -s         Skip Windows setup (only configure Linux side)
  -h         Show this help

Example:
  $0 -w 192.168.1.100 -u admin
EOF
  exit 1
}

while getopts ":w:u:k:d:sh" opt; do
  case $opt in
    w) WINDOWS_HOST="$OPTARG" ;;
    u) WINDOWS_USER="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    d) DATA_ROOT="$OPTARG" ;;
    s) SKIP_WINDOWS_SETUP=true ;;
    h|*) usage ;;
  esac
done

[ -n "$WINDOWS_HOST" ] || { err "Windows host is required (-w)"; usage; }

header "Rikune — Hybrid Deployment"
info "Windows Host: $WINDOWS_HOST"
info "Windows User: $WINDOWS_USER"
info "Linux Data Root: $DATA_ROOT"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Pre-checks on Linux side
# ─────────────────────────────────────────────────────────────────────────────
step "Checking Linux Analyzer Prerequisites"

command -v docker >/dev/null 2>&1 || { err "Docker not found"; exit 1; }
ok "Docker: $(docker --version | awk '{print $3}' | tr -d ',')"

command -v node >/dev/null 2>&1 || { err "Node.js not found (22+ required)"; exit 1; }
ok "Node.js: $(node --version)"

command -v ssh >/dev/null 2>&1 || { err "ssh client not found"; exit 1; }
ok "SSH client available"

# ─────────────────────────────────────────────────────────────────────────────
# 2. Deploy Windows Runtime side
# ─────────────────────────────────────────────────────────────────────────────
step "Deploying Windows Runtime"

if [ "$SKIP_WINDOWS_SETUP" = true ]; then
  warn "Skipping Windows setup (-s). Assuming Host Agent is already running."
else
  info "Testing SSH connectivity to $WINDOWS_HOST..."
  if ! ssh -o BatchMode=yes -o ConnectTimeout=5 -i "$SSH_KEY" "${WINDOWS_USER}@${WINDOWS_HOST}" "echo ok" >/dev/null 2>&1; then
    err "Cannot SSH to ${WINDOWS_USER}@${WINDOWS_HOST} with key $SSH_KEY"
    info "Ensure the Windows host has OpenSSH Server installed and your public key is in authorized_keys."
    exit 1
  fi
  ok "SSH connectivity verified"

  info "Uploading / syncing project to Windows host..."
  # Use rsync if available, otherwise fall back to tar+ssh
  if command -v rsync >/dev/null 2>&1; then
    rsync -az --exclude 'node_modules' --exclude '.git' --exclude 'dist' \
      -e "ssh -i $SSH_KEY" "$PROJECT_ROOT/" "${WINDOWS_USER}@${WINDOWS_HOST}:/C:/rikune/" 2>&1 || true
    ok "Project synced via rsync"
  else
    warn "rsync not found; falling back to tar over ssh (slower)"
    tar czf - --exclude='node_modules' --exclude='.git' --exclude='dist' -C "$PROJECT_ROOT" . | \
      ssh -i "$SSH_KEY" "${WINDOWS_USER}@${WINDOWS_HOST}" "mkdir -p C:/rikune && tar xzf - -C C:/rikune" 2>&1
    ok "Project transferred via tar+ssh"
  fi

  info "Running install-runtime-windows.ps1 on Windows host..."
  ssh -i "$SSH_KEY" "${WINDOWS_USER}@${WINDOWS_HOST}" \
    "powershell -ExecutionPolicy Bypass -File C:/rikune/install-runtime-windows.ps1 -ProjectRoot C:/rikune -Headless -Service -WorkspaceRoot C:/rikune-runtime" 2>&1
  ok "Windows Runtime setup completed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. Discover Windows endpoint & API key
# ─────────────────────────────────────────────────────────────────────────────
step "Discovering Windows Host Agent Endpoint"

# Try to read the generated env file from Windows
REMOTE_ENV=$(ssh -i "$SSH_KEY" "${WINDOWS_USER}@${WINDOWS_HOST}" "powershell -Command Get-Content C:/rikune/.env.runtime-windows" 2>/dev/null || true)
if [ -z "$REMOTE_ENV" ]; then
  err "Could not retrieve .env.runtime-windows from Windows host"
  exit 1
fi

API_KEY=$(echo "$REMOTE_ENV" | grep '^HOST_AGENT_API_KEY=' | cut -d'=' -f2-)
HOST_AGENT_PORT=$(echo "$REMOTE_ENV" | grep '^HOST_AGENT_PORT=' | cut -d'=' -f2-)
[ -n "$API_KEY" ] || { err "API_KEY not found in remote .env"; exit 1; }
[ -n "$HOST_AGENT_PORT" ] || HOST_AGENT_PORT=18082

ENDPOINT="http://${WINDOWS_HOST}:${HOST_AGENT_PORT}"
ok "Host Agent endpoint: $ENDPOINT"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Write Linux Analyzer configuration
# ─────────────────────────────────────────────────────────────────────────────
step "Configuring Linux Analyzer"

mkdir -p "$DATA_ROOT"/{workspaces,data,cache,logs,storage,ghidra-projects,ghidra-logs}

ENV_FILE="$PROJECT_ROOT/.env"
cat > "$ENV_FILE" <<EOF
# Rikune Analyzer Environment — generated by deploy-hybrid.sh
NODE_ENV=production
NODE_ROLE=analyzer
RUNTIME_MODE=remote-sandbox
RUNTIME_HOST_AGENT_ENDPOINT=$ENDPOINT
RUNTIME_API_KEY=$API_KEY

WORKSPACE_ROOT=$DATA_ROOT/workspaces
DB_PATH=$DATA_ROOT/data/database.db
CACHE_ROOT=$DATA_ROOT/cache
AUDIT_LOG_PATH=$DATA_ROOT/logs/audit.log
LOG_LEVEL=info

API_ENABLED=true
API_PORT=18080
API_STORAGE_ROOT=$DATA_ROOT/storage
EOF
ok "Analyzer .env written: $ENV_FILE"

# Render docker-compose.hybrid.yml
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.hybrid.yml"
cat > "$COMPOSE_FILE" <<EOF
name: rikune-hybrid
services:
  analyzer:
    image: rikune:latest
    build:
      context: .
      dockerfile: Dockerfile
    container_name: rikune-analyzer
    env_file:
      - .env
    volumes:
      - ./samples:/samples:ro
      - "$DATA_ROOT/workspaces:/app/workspaces:rw"
      - "$DATA_ROOT/data:/app/data:rw"
      - "$DATA_ROOT/cache:/app/cache:rw"
      - "$DATA_ROOT/logs:/app/logs:rw"
      - "$DATA_ROOT/storage:/app/storage:rw"
      - "$DATA_ROOT/ghidra-projects:/ghidra-projects:rw"
      - "$DATA_ROOT/ghidra-logs:/ghidra-logs:rw"
    ports:
      - "18080:18080"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "node", "-e", "const http=require('http');const r=http.get('http://localhost:18080/api/v1/health',res=>{process.exit(res.statusCode===200?0:1)});r.on('error',()=>process.exit(1));r.setTimeout(5000,()=>process.exit(1))"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
EOF
ok "Docker Compose file written: $COMPOSE_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Build & start Analyzer
# ─────────────────────────────────────────────────────────────────────────────
step "Building & Starting Linux Analyzer"

cd "$PROJECT_ROOT"
info "Building Docker image..."
docker build -t rikune:latest . 2>&1
ok "Docker image built"

info "Starting Analyzer container..."
docker compose -f "$COMPOSE_FILE" up -d 2>&1
ok "Analyzer container started"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Connectivity test
# ─────────────────────────────────────────────────────────────────────────────
step "Running Connectivity Tests"

info "Testing Analyzer API health..."
sleep 3
ANALYZER_HEALTH=$(docker compose -f "$COMPOSE_FILE" exec -T analyzer node -e "const http=require('http'); const r=http.get('http://localhost:18080/api/v1/health',res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{console.log(d);process.exit(0)})}); r.on('error',e=>{console.error(e);process.exit(1)})" 2>/dev/null || true)
if echo "$ANALYZER_HEALTH" | grep -q '"ok":true'; then
  ok "Analyzer API is healthy"
else
  warn "Analyzer API health check returned unexpected result"
  info "$ANALYZER_HEALTH"
fi

info "Testing Host Agent reachability from Linux..."
if curl -sf -H "Authorization: Bearer $API_KEY" "${ENDPOINT}/sandbox/health" >/dev/null 2>&1; then
  ok "Host Agent is reachable"
else
  warn "Host Agent did not respond. Check Windows firewall rules for port $HOST_AGENT_PORT"
fi

info "Testing Host Agent -> Sandbox start (dry-run)..."
SANDBOX_RESULT=$(curl -sf -X POST -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d '{"timeoutMs":30000}' "${ENDPOINT}/sandbox/start" 2>/dev/null || true)
if echo "$SANDBOX_RESULT" | grep -q '"ok":true'; then
  SANDBOX_ID=$(echo "$SANDBOX_RESULT" | grep -o '"sandboxId":"[^"]*"' | cut -d'"' -f4)
  ok "Sandbox started successfully (sandboxId: $SANDBOX_ID)"
  info "Stopping test sandbox..."
  curl -sf -X POST -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\"sandboxId\":\"$SANDBOX_ID\"}" "${ENDPOINT}/sandbox/stop" >/dev/null 2>&1 || true
  ok "Test sandbox stopped"
else
  warn "Sandbox start test failed or timed out"
  info "Response: $SANDBOX_RESULT"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
header "Deployment Complete"

echo "  Windows Runtime:  $ENDPOINT"
echo "  Linux Analyzer:   http://localhost:18080"
echo "  Data Root:        $DATA_ROOT"
echo "  Env File:         $ENV_FILE"
echo ""
echo "  Next steps:"
echo "    1. Configure your MCP client to point to the Analyzer container"
echo "    2. Submit a sample for analysis — the Windows Sandbox will start automatically"
echo "    3. If anything goes wrong, run: ./diagnose-hybrid.sh -w $WINDOWS_HOST"
echo ""
