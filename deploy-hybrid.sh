#!/usr/bin/env bash
# Rikune hybrid deployment: Linux Docker analyzer + Windows Host Agent runtime.

set -euo pipefail

C_RESET="\033[0m"
C_CYAN="\033[36m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"

header() { printf "\n${C_CYAN}==================================================${C_RESET}\n  ${C_CYAN}%s${C_RESET}\n${C_CYAN}==================================================${C_RESET}\n\n" "$1"; }
step() { printf "\n${C_CYAN}[STEP] %s${C_RESET}\n${C_CYAN}-----------------------------------------${C_RESET}\n" "$1"; }
ok() { printf "${C_GREEN}[OK]${C_RESET} %s\n" "$1"; }
warn() { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$1"; }
err() { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$1"; }
info() { printf "  %s\n" "$1"; }

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
WINDOWS_HOST=""
WINDOWS_USER="${WINDOWS_USER:-Administrator}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
DATA_ROOT="${RIKUNE_DATA_ROOT:-$HOME/.rikune}"
HOST_AGENT_PORT="${HOST_AGENT_PORT:-18082}"
HOST_AGENT_ENDPOINT="${RUNTIME_HOST_AGENT_ENDPOINT:-}"
HOST_AGENT_API_KEY="${RUNTIME_HOST_AGENT_API_KEY:-}"
RUNTIME_API_KEY="${RUNTIME_API_KEY:-}"
SKIP_WINDOWS_SETUP=false

usage() {
  cat <<EOF
Usage: $0 -w <windows-host> [options]

Options:
  -w HOST      Windows host IP or hostname
  -u USER      Windows SSH user (default: $WINDOWS_USER)
  -k KEY       SSH private key path (default: $SSH_KEY)
  -d DIR       Linux data root (default: $DATA_ROOT)
  -p PORT      Windows Host Agent port (default: $HOST_AGENT_PORT)
  -e URL       Windows Host Agent endpoint (default: http://HOST:PORT)
  -a KEY       Host Agent API key; passed to Windows installer when setup is not skipped
  -r KEY       Runtime Node API key; defaults to the Host Agent key
  -s           Skip Windows setup and only configure/start the Linux analyzer
  -h           Show this help

Examples:
  $0 -w 192.168.1.100 -u admin
  $0 -w 192.168.1.100 -s -a existing-host-agent-key
EOF
  exit 1
}

while getopts ":w:u:k:d:p:e:a:r:sh" opt; do
  case "$opt" in
    w) WINDOWS_HOST="$OPTARG" ;;
    u) WINDOWS_USER="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    d) DATA_ROOT="$OPTARG" ;;
    p) HOST_AGENT_PORT="$OPTARG" ;;
    e) HOST_AGENT_ENDPOINT="$OPTARG" ;;
    a) HOST_AGENT_API_KEY="$OPTARG" ;;
    r) RUNTIME_API_KEY="$OPTARG" ;;
    s) SKIP_WINDOWS_SETUP=true ;;
    h|*) usage ;;
  esac
done

if [ -z "$WINDOWS_HOST" ] && [ -z "$HOST_AGENT_ENDPOINT" ]; then
  err "Provide -w <windows-host> or -e <host-agent-endpoint>"
  usage
fi

if [ -z "$HOST_AGENT_ENDPOINT" ]; then
  HOST_AGENT_ENDPOINT="http://${WINDOWS_HOST}:${HOST_AGENT_PORT}"
fi

if [ -n "$HOST_AGENT_API_KEY" ] && printf "%s" "$HOST_AGENT_API_KEY" | grep -q "'"; then
  err "Host Agent API key must not contain a single quote for SSH bootstrap"
  exit 1
fi

header "Rikune Hybrid Deployment"
info "Project root: $PROJECT_ROOT"
info "Linux data root: $DATA_ROOT"
info "Windows host: ${WINDOWS_HOST:-from endpoint}"
info "Host Agent endpoint: $HOST_AGENT_ENDPOINT"

step "Checking Linux prerequisites"
command -v docker >/dev/null 2>&1 || { err "Docker not found"; exit 1; }
docker info >/dev/null 2>&1 || { err "Docker daemon is not running"; exit 1; }
ok "Docker: $(docker --version | awk '{print $3}' | tr -d ',')"

docker compose version >/dev/null 2>&1 || { err "Docker Compose plugin not found"; exit 1; }
ok "Docker Compose plugin available"

command -v node >/dev/null 2>&1 || { err "Node.js 22+ not found"; exit 1; }
command -v npm >/dev/null 2>&1 || { err "npm not found"; exit 1; }
ok "Node.js: $(node --version)"
ok "npm: $(npm --version)"

if [ -n "$WINDOWS_HOST" ]; then
  command -v ssh >/dev/null 2>&1 || { err "ssh client not found"; exit 1; }
  ok "SSH client available"
fi

ssh_win() {
  ssh -o BatchMode=yes -o ConnectTimeout=10 -i "$SSH_KEY" "${WINDOWS_USER}@${WINDOWS_HOST}" "$@"
}

step "Preparing Windows runtime"

if [ "$SKIP_WINDOWS_SETUP" = true ]; then
  warn "Skipping Windows setup. The Host Agent must already be running."
else
  [ -n "$WINDOWS_HOST" ] || { err "-w <windows-host> is required unless -s is used"; exit 1; }

  info "Testing SSH connectivity to ${WINDOWS_USER}@${WINDOWS_HOST}..."
  ssh_win "echo ok" >/dev/null
  ok "SSH connectivity verified"

  info "Creating C:/rikune on Windows..."
  ssh_win "powershell -NoProfile -Command \"New-Item -ItemType Directory -Path C:/rikune -Force | Out-Null\"" >/dev/null

  info "Syncing project to Windows host..."
  if command -v rsync >/dev/null 2>&1; then
    rsync -az \
      --exclude node_modules \
      --exclude .git \
      --exclude dist \
      --exclude .docker-runtime.env \
      -e "ssh -i $SSH_KEY" \
      "$PROJECT_ROOT/" "${WINDOWS_USER}@${WINDOWS_HOST}:/C:/rikune/"
    ok "Project synced with rsync"
  else
    warn "rsync not found; using tar over ssh"
    tar czf - \
      --exclude=node_modules \
      --exclude=.git \
      --exclude=dist \
      --exclude=.docker-runtime.env \
      -C "$PROJECT_ROOT" . | ssh -i "$SSH_KEY" "${WINDOWS_USER}@${WINDOWS_HOST}" \
        "powershell -NoProfile -Command \"tar -xzf - -C C:/rikune\""
    ok "Project synced with tar"
  fi

  remote_install="powershell -ExecutionPolicy Bypass -File C:/rikune/install-runtime-windows.ps1 -ProjectRoot C:/rikune -Headless -Service -WorkspaceRoot C:/rikune-runtime"
  if [ -n "$HOST_AGENT_API_KEY" ]; then
    remote_install="$remote_install -ApiKey '$HOST_AGENT_API_KEY'"
  fi

  info "Installing Windows Runtime Host Agent..."
  ssh_win "$remote_install"
  ok "Windows Runtime Host Agent installed"
fi

step "Resolving Host Agent credentials"

if [ -n "$WINDOWS_HOST" ]; then
  remote_env="$(ssh_win "powershell -NoProfile -Command \"Get-Content -Path C:/rikune/.env.runtime-windows -ErrorAction SilentlyContinue\"" 2>/dev/null || true)"
else
  remote_env=""
fi

if [ -z "$HOST_AGENT_API_KEY" ] && [ -n "$remote_env" ]; then
  HOST_AGENT_API_KEY="$(printf "%s\n" "$remote_env" | awk -F= '/^HOST_AGENT_API_KEY=/{print substr($0, index($0,$2))}' | tail -n 1)"
fi

if [ -n "$remote_env" ]; then
  remote_port="$(printf "%s\n" "$remote_env" | awk -F= '/^HOST_AGENT_PORT=/{print $2}' | tail -n 1)"
  if [ -n "$remote_port" ]; then
    HOST_AGENT_PORT="$remote_port"
    if [ -z "${RUNTIME_HOST_AGENT_ENDPOINT:-}" ]; then
      HOST_AGENT_ENDPOINT="http://${WINDOWS_HOST}:${HOST_AGENT_PORT}"
    fi
  fi
fi

if [ -z "$HOST_AGENT_API_KEY" ]; then
  err "Host Agent API key is missing. Pass -a KEY or run Windows setup so .env.runtime-windows can be read."
  exit 1
fi

if [ -z "$RUNTIME_API_KEY" ]; then
  RUNTIME_API_KEY="$HOST_AGENT_API_KEY"
fi

ok "Host Agent endpoint: $HOST_AGENT_ENDPOINT"
ok "Host Agent API key resolved"

step "Preparing Linux analyzer profile"

mkdir -p "$DATA_ROOT"/{samples,workspaces,data,cache,logs,storage,ghidra-projects,ghidra-logs,qiling-rootfs,config}
ok "Data directories ready"

cd "$PROJECT_ROOT"
info "Installing npm dependencies..."
npm install
ok "npm dependencies installed"

info "Building project..."
npm run build
ok "Project built"

info "Generating hybrid Docker files..."
node scripts/generate-docker.mjs --profile=hybrid
ok "Generated docker-compose.hybrid.yml and docker/Dockerfile.analyzer"

ENV_FILE="$PROJECT_ROOT/.docker-runtime.env"
cat > "$ENV_FILE" <<EOF
# Rikune hybrid Docker runtime environment - generated by deploy-hybrid.sh
RIKUNE_DATA_ROOT=$DATA_ROOT
RIKUNE_BUILD_HTTP_PROXY=${RIKUNE_BUILD_HTTP_PROXY:-}
RIKUNE_BUILD_HTTPS_PROXY=${RIKUNE_BUILD_HTTPS_PROXY:-}
RIKUNE_BUILD_NO_PROXY=${RIKUNE_BUILD_NO_PROXY:-localhost,127.0.0.1,deb.debian.org,security.debian.org,mirrors.aliyun.com,archive.ubuntu.com,security.ubuntu.com,aliyuncs.com}
RUNTIME_HOST_AGENT_ENDPOINT=$HOST_AGENT_ENDPOINT
RUNTIME_HOST_AGENT_API_KEY=$HOST_AGENT_API_KEY
RUNTIME_API_KEY=$RUNTIME_API_KEY
EOF
ok "Compose env file written: $ENV_FILE"

step "Building and starting Linux analyzer"
docker compose --env-file .docker-runtime.env -f docker-compose.hybrid.yml up -d --build analyzer
ok "Analyzer container started"

step "Connectivity tests"

if curl -sf http://localhost:18080/api/v1/health >/dev/null 2>&1; then
  ok "Analyzer API responds on localhost:18080"
else
  warn "Analyzer API health check failed. Check: docker logs rikune-analyzer"
fi

if curl -sf -H "Authorization: Bearer $HOST_AGENT_API_KEY" "$HOST_AGENT_ENDPOINT/sandbox/health" >/dev/null 2>&1; then
  ok "Windows Host Agent responds"
else
  warn "Windows Host Agent did not respond. Check firewall, endpoint, and API key."
fi

header "Hybrid Deployment Complete"
echo "  Analyzer API:       http://localhost:18080"
echo "  Dashboard:          http://localhost:18080/dashboard"
echo "  Windows Host Agent: $HOST_AGENT_ENDPOINT"
echo "  Data root:          $DATA_ROOT"
echo ""
echo "  Logs:"
echo "    docker compose --env-file .docker-runtime.env -f docker-compose.hybrid.yml logs -f analyzer"
echo ""
echo "  Diagnostics:"
echo "    ./diagnose-hybrid.sh -w ${WINDOWS_HOST:-<windows-host>} -u $WINDOWS_USER"
