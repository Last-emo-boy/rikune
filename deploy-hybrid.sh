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
HOST_AGENT_API_KEY="${RUNTIME_HOST_AGENT_API_KEY:-${RIKUNE_HOST_AGENT_API_KEY:-${HOST_AGENT_API_KEY:-}}}"
RUNTIME_API_KEY="${RUNTIME_API_KEY:-${RIKUNE_RUNTIME_NODE_API_KEY:-${HOST_AGENT_RUNTIME_API_KEY:-}}}"
ANALYZER_API_KEY="${RIKUNE_API_KEY:-${RIKUNE_ANALYZER_API_KEY:-}}"
export -n HOST_AGENT_API_KEY RUNTIME_API_KEY ANALYZER_API_KEY 2>/dev/null || true
unset RUNTIME_HOST_AGENT_API_KEY RIKUNE_HOST_AGENT_API_KEY HOST_AGENT_RUNTIME_API_KEY
unset RIKUNE_RUNTIME_NODE_API_KEY RIKUNE_RUNTIME_API_KEY
unset RIKUNE_API_KEY RIKUNE_ANALYZER_API_KEY
HOST_AGENT_ENDPOINT_EXPLICIT=false
[ -n "$HOST_AGENT_ENDPOINT" ] && HOST_AGENT_ENDPOINT_EXPLICIT=true
SKIP_WINDOWS_SETUP=false
ALLOW_INSECURE_RUNTIME_HTTP=false
ENV_FILE="$PROJECT_ROOT/.docker-runtime.env"
PRIVATE_ENV_WRITER="$PROJECT_ROOT/scripts/write-docker-runtime-env.mjs"
PRIVATE_ENV_SNAPSHOT=""
PRIVATE_ENV_TRANSACTION_ACTIVE=false
PRIVATE_ENV_TRANSACTION_COMMITTED=false

usage() {
  cat <<EOF
Usage: $0 -w <windows-host> [options]

Options:
  -w HOST      Windows host IP or hostname
  -u USER      Windows SSH user (default: $WINDOWS_USER)
  -k KEY       SSH private key path (default: $SSH_KEY)
  -d DIR       Linux data root (default: $DATA_ROOT)
  -p PORT      Windows Host Agent port (default: $HOST_AGENT_PORT)
  -e URL       Windows Host Agent endpoint (default: http://HOST:PORT, requires -i)
  -i           Allow remote plaintext HTTP only on an isolated trusted network
  -s           Skip Windows setup and only configure/start the Linux analyzer
  -h           Show this help

Credentials:
  Provide distinct RUNTIME_HOST_AGENT_API_KEY and RUNTIME_API_KEY through a
  protected process environment or secret manager. Secrets are not accepted
  as command-line arguments.

Examples:
  $0 -w runtime.example.internal -u admin -e https://runtime.example.internal
  $0 -w 192.168.1.100 -u admin -i
EOF
  exit 1
}

while getopts ":w:u:k:d:p:e:ish" opt; do
  case "$opt" in
    w) WINDOWS_HOST="$OPTARG" ;;
    u) WINDOWS_USER="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    d) DATA_ROOT="$OPTARG" ;;
    p) HOST_AGENT_PORT="$OPTARG" ;;
    e) HOST_AGENT_ENDPOINT="$OPTARG"; HOST_AGENT_ENDPOINT_EXPLICIT=true ;;
    i) ALLOW_INSECURE_RUNTIME_HTTP=true ;;
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

if [ -n "$WINDOWS_HOST" ] && ! [[ "$WINDOWS_HOST" =~ ^[A-Za-z0-9.-]+$ ]]; then
  err "Windows host must be a DNS name or IPv4 address containing only letters, digits, dots, and hyphens"
  exit 1
fi

assert_secure_runtime_endpoint() {
  local endpoint="$1"
  local authority="${endpoint#*://}"
  authority="${authority%%/*}"
  authority="${authority%%\?*}"
  authority="${authority%%\#*}"
  if [ -z "$authority" ] || [[ "$authority" == *"@"* ]] || [[ "$endpoint" =~ [[:space:]] ]]; then
    err "Host Agent endpoint must contain a valid authority and no URL credentials"
    exit 1
  fi
  if [[ "$endpoint" =~ ^https:// ]]; then
    return 0
  fi
  if [[ "$endpoint" =~ ^http://(localhost|127\.0\.0\.1|host\.docker\.internal|\[::1\])(:[0-9]+)?(/|$) ]]; then
    return 0
  fi
  if [[ "$endpoint" =~ ^http:// ]] && [ "$ALLOW_INSECURE_RUNTIME_HTTP" = true ]; then
    warn "Remote runtime HTTP was explicitly enabled. Restrict it to an isolated trusted network or VPN."
    return 0
  fi
  if [[ "$endpoint" =~ ^http:// ]]; then
    err "Remote Host Agent endpoints must use HTTPS. Use -i only for an isolated trusted network."
  else
    err "Host Agent endpoint must use http:// or https://"
  fi
  exit 1
}

assert_runtime_api_key() {
  local name="$1"
  local value="$2"
  if ! printf '%s' "$value" | LC_ALL=C grep -Eq '^[!-~]{32,}$'; then
    err "$name must contain at least 32 printable non-space ASCII characters"
    exit 1
  fi
}

assert_secret_environment_cleared() {
  local name declaration
  for name in \
    RIKUNE_API_KEY RIKUNE_ANALYZER_API_KEY RUNTIME_HOST_AGENT_API_KEY \
    HOST_AGENT_API_KEY HOST_AGENT_RUNTIME_API_KEY RUNTIME_API_KEY \
    RIKUNE_HOST_AGENT_API_KEY RIKUNE_RUNTIME_API_KEY RIKUNE_RUNTIME_NODE_API_KEY; do
    declaration="$(declare -p "$name" 2>/dev/null || true)"
    if [[ "$declaration" == "declare -x"* ]]; then
      err "Secret environment alias must be cleared before dependency or build commands: $name"
      exit 1
    fi
  done
}

rollback_private_env_transaction() {
  local original_status="${1:-1}"
  trap - EXIT INT TERM
  if [ "$PRIVATE_ENV_TRANSACTION_ACTIVE" = true ] && [ "$PRIVATE_ENV_TRANSACTION_COMMITTED" != true ]; then
    set +e
    printf '%s' "$PRIVATE_ENV_SNAPSHOT" |
      RIKUNE_RESTORE_PRIVATE_ENV_PATH="$ENV_FILE" node "$PRIVATE_ENV_WRITER"
    local restore_status=$?
    set -e
    if [ "$restore_status" -ne 0 ]; then
      err "Failed to restore the protected Compose env after hybrid deployment failure."
      [ "$original_status" -ne 0 ] || original_status=1
    fi
  fi
  PRIVATE_ENV_SNAPSHOT=""
  exit "$original_status"
}

interrupt_private_env_transaction() {
  case "$1" in
    INT) exit 130 ;;
    TERM) exit 143 ;;
  esac
}

begin_private_env_transaction() {
  PRIVATE_ENV_SNAPSHOT="$(RIKUNE_STAGE_DOCKER_ENV_PATH="$ENV_FILE" node "$PRIVATE_ENV_WRITER")"
  export -n PRIVATE_ENV_SNAPSHOT 2>/dev/null || true
  PRIVATE_ENV_TRANSACTION_ACTIVE=true
  trap 'rollback_private_env_transaction "$?"' EXIT
  trap 'interrupt_private_env_transaction INT' INT
  trap 'interrupt_private_env_transaction TERM' TERM
  printf '%s' "$PRIVATE_ENV_SNAPSHOT" |
    RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH="$ENV_FILE" node "$PRIVATE_ENV_WRITER"
  info "Any prior protected Compose env was removed before dependency lifecycle commands; credentials will be rotated after build."
}

commit_private_env_transaction() {
  PRIVATE_ENV_TRANSACTION_COMMITTED=true
  PRIVATE_ENV_SNAPSHOT=""
  trap - EXIT INT TERM
}

provision_analyzer_api_key() {
  if [ -z "$ANALYZER_API_KEY" ]; then
    ANALYZER_API_KEY="$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")"
  fi
  assert_runtime_api_key "Analyzer API key" "$ANALYZER_API_KEY"
}

assert_secure_runtime_endpoint "$HOST_AGENT_ENDPOINT"
if [ "$SKIP_WINDOWS_SETUP" = false ] && [ "$ALLOW_INSECURE_RUNTIME_HTTP" != true ]; then
  err "Remote Windows Sandbox runtime ports use plaintext HTTP on the trusted network. Re-run with -i only behind a VPN/isolated network, or use -s with a separately secured runtime."
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

command -v node >/dev/null 2>&1 || { err "Node.js 22.9+ not found"; exit 1; }
command -v npm >/dev/null 2>&1 || { err "npm not found"; exit 1; }
NODE_VERSION="$(node --version)"
NODE_VERSION_CORE="${NODE_VERSION#v}"
NODE_MAJOR="${NODE_VERSION_CORE%%.*}"
NODE_MINOR="${NODE_VERSION_CORE#*.}"
NODE_MINOR="${NODE_MINOR%%.*}"
if [ "$NODE_MAJOR" -lt 22 ] || { [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -lt 9 ]; }; then
  err "Node.js $NODE_VERSION is too old; 22.9+ is required"
  exit 1
fi
ok "Node.js: $NODE_VERSION"
ok "npm: $(npm --version)"

[ -f "$PRIVATE_ENV_WRITER" ] || { err "Secure private environment writer not found: $PRIVATE_ENV_WRITER"; exit 1; }
begin_private_env_transaction
assert_secret_environment_cleared

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

  info "Checking PowerShell 7 on the Windows host..."
  ssh_win "pwsh -NoProfile -NonInteractive -Command \"if (\$PSVersionTable.PSVersion.Major -lt 7) { exit 1 }\"" >/dev/null
  ok "PowerShell 7 available"

  info "Creating C:/rikune on Windows..."
  ssh_win "powershell -NoProfile -Command \"New-Item -ItemType Directory -Path C:/rikune -Force | Out-Null\"" >/dev/null

  info "Syncing project to Windows host..."
  command -v rsync >/dev/null 2>&1 || {
    err "rsync is required for exact remote synchronization; refusing a stale-file-prone tar overlay"
    exit 1
  }
  rsync -az --delete \
    --exclude node_modules \
    --exclude .git \
    --exclude dist \
    --exclude .docker-runtime.env \
    --exclude .env.runtime-windows \
    -e "ssh -i $SSH_KEY" \
    "$PROJECT_ROOT/" "${WINDOWS_USER}@${WINDOWS_HOST}:/C:/rikune/"
  ok "Project synced exactly with rsync"

  remote_install="pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:/rikune/install-runtime-windows.ps1 -ProjectRoot C:/rikune -Headless -Service -WorkspaceRoot C:/rikune-runtime -BindHost 0.0.0.0 -RuntimeBindHost 0.0.0.0 -RuntimeAdvertisedHost ${WINDOWS_HOST} -AllowInsecureRuntimeHttp"

  info "Installing Windows Runtime Host Agent..."
  ssh_win "$remote_install"
  ok "Windows Runtime Host Agent installed"
fi

step "Resolving Host Agent credentials"

if [ -n "$WINDOWS_HOST" ]; then
  remote_env="$(ssh_win "pwsh -NoProfile -NonInteractive -Command \"Get-Content -Path C:/rikune/.env.runtime-windows -ErrorAction SilentlyContinue\"" 2>/dev/null || true)"
else
  remote_env=""
fi

if [ -n "$remote_env" ]; then
  remote_host_key="$(printf "%s\n" "$remote_env" | awk -F= '/^HOST_AGENT_API_KEY=/{print substr($0, index($0,$2))}' | tail -n 1)"
  remote_runtime_key="$(printf "%s\n" "$remote_env" | awk -F= '/^HOST_AGENT_RUNTIME_API_KEY=/{print substr($0, index($0,$2))}' | tail -n 1)"
  [ -n "$remote_host_key" ] && HOST_AGENT_API_KEY="$remote_host_key"
  [ -n "$remote_runtime_key" ] && RUNTIME_API_KEY="$remote_runtime_key"
  remote_host_key=""
  remote_runtime_key=""
fi

if [ -n "$remote_env" ]; then
  remote_port="$(printf "%s\n" "$remote_env" | awk -F= '/^HOST_AGENT_PORT=/{print $2}' | tail -n 1)"
  if [ -n "$remote_port" ]; then
    HOST_AGENT_PORT="$remote_port"
    if [ "$HOST_AGENT_ENDPOINT_EXPLICIT" = false ]; then
      HOST_AGENT_ENDPOINT="http://${WINDOWS_HOST}:${HOST_AGENT_PORT}"
    fi
  fi
fi

if [ -z "$HOST_AGENT_API_KEY" ]; then
  if [ -t 0 ]; then
    read -r -s -p "Windows Host Agent API key: " HOST_AGENT_API_KEY
    printf '\n'
  fi
  if [ -z "$HOST_AGENT_API_KEY" ]; then
    err "Host Agent API key is missing. Provide RUNTIME_HOST_AGENT_API_KEY through a protected environment or run Windows setup."
    exit 1
  fi
fi

if [ -z "$RUNTIME_API_KEY" ]; then
  if [ -t 0 ]; then
    read -r -s -p "Distinct Runtime Node API key: " RUNTIME_API_KEY
    printf '\n'
  fi
  if [ -z "$RUNTIME_API_KEY" ]; then
    err "Runtime Node API key is missing. Provide a distinct RUNTIME_API_KEY or run Windows setup."
    exit 1
  fi
fi
remote_env=""

assert_runtime_api_key "Host Agent API key" "$HOST_AGENT_API_KEY"
assert_runtime_api_key "Runtime Node API key" "$RUNTIME_API_KEY"
if [ "$HOST_AGENT_API_KEY" = "$RUNTIME_API_KEY" ]; then
  err "Host Agent and Runtime Node API keys must be distinct"
  exit 1
fi

assert_secure_runtime_endpoint "$HOST_AGENT_ENDPOINT"

ok "Host Agent endpoint: $HOST_AGENT_ENDPOINT"
ok "Host Agent API key resolved"

step "Preparing Linux analyzer profile"

mkdir -p "$DATA_ROOT"/{samples,workspaces,data,cache,logs,storage,ghidra-projects,ghidra-logs,qiling-rootfs,config}
ok "Data directories ready"

cd "$PROJECT_ROOT"
info "Installing npm dependencies..."
npm ci --include=dev
ok "npm dependencies installed"

info "Building project..."
npm run build
ok "Project built"

info "Generating hybrid Docker files..."
node scripts/generate-docker.mjs --profile=hybrid
ok "Generated docker-compose.hybrid.yml and docker/Dockerfile.hybrid"

assert_secret_environment_cleared
provision_analyzer_api_key
printf '%s' "$PRIVATE_ENV_SNAPSHOT" |
RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN=1 \
RIKUNE_DOCKER_ENV_PATH="$ENV_FILE" \
RIKUNE_DOCKER_ENV_DATA_ROOT="$DATA_ROOT" \
RIKUNE_DOCKER_ENV_PROFILE="hybrid" \
RIKUNE_BUILD_HTTP_PROXY="${RIKUNE_BUILD_HTTP_PROXY:-}" \
RIKUNE_BUILD_HTTPS_PROXY="${RIKUNE_BUILD_HTTPS_PROXY:-}" \
RIKUNE_BUILD_NO_PROXY="${RIKUNE_BUILD_NO_PROXY:-localhost,127.0.0.1,deb.debian.org,security.debian.org,mirrors.aliyun.com,archive.ubuntu.com,security.ubuntu.com,aliyuncs.com}" \
RIKUNE_API_KEY="$ANALYZER_API_KEY" \
RUNTIME_HOST_AGENT_ENDPOINT="$HOST_AGENT_ENDPOINT" \
RUNTIME_HOST_AGENT_API_KEY="$HOST_AGENT_API_KEY" \
RUNTIME_API_KEY="$RUNTIME_API_KEY" \
RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP="$ALLOW_INSECURE_RUNTIME_HTTP" \
  node scripts/write-docker-runtime-env.mjs
# The verified replacement is authoritative before any container can start.
# Later Compose/health failures must not restore an old, mismatched credential.
commit_private_env_transaction
chmod 600 "$ENV_FILE"
ok "Compose env file written: $ENV_FILE"

step "Building and starting Linux analyzer"
docker compose --env-file .docker-runtime.env -f docker-compose.hybrid.yml up -d --build analyzer
ok "Analyzer container started"

step "Connectivity tests"

if curl -sf http://localhost:18080/api/v1/health >/dev/null 2>&1; then
  ok "Analyzer API responds on localhost:18080"
else
  err "Analyzer API health check failed. Check: docker logs rikune-analyzer"
  exit 1
fi

if printf 'Authorization: Bearer %s\n' "$HOST_AGENT_API_KEY" | curl -sf --header @- "$HOST_AGENT_ENDPOINT/sandbox/health" >/dev/null 2>&1; then
  ok "Windows Host Agent responds"
else
  err "Windows Host Agent did not respond. Check firewall, endpoint, and API key."
  exit 1
fi

info "Verifying the full sandbox lifecycle from the analyzer container..."
if docker exec rikune-analyzer node /app/scripts/verify-hybrid-runtime.mjs; then
  ok "Hybrid Host Agent and Runtime Node lifecycle verified"
else
  err "Hybrid runtime lifecycle verification failed; sandbox cleanup is required before retrying."
  exit 1
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
