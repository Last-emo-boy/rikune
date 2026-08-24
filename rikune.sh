#!/usr/bin/env bash
# Rikune top-level deployment and operations script for Linux/macOS.

set -euo pipefail

C_RESET="\033[0m"
C_CYAN="\033[36m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"

header() { printf "\n${C_CYAN}==================================================${C_RESET}\n  ${C_CYAN}%s${C_RESET}\n${C_CYAN}==================================================${C_RESET}\n" "$1"; }
step() { printf "\n${C_CYAN}[STEP] %s${C_RESET}\n${C_CYAN}-----------------------------------------${C_RESET}\n" "$1"; }
ok() { printf "${C_GREEN}[OK]${C_RESET} %s\n" "$1"; }
warn() { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$1"; }
err() { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$1"; }
info() { printf "  %s\n" "$1"; }

ACTION="menu"
if [ "$#" -gt 0 ] && [[ "$1" != --* ]]; then
  ACTION="$1"
  shift
fi

PROFILE="${RIKUNE_PROFILE:-static}"
DATA_ROOT="${RIKUNE_DATA_ROOT:-$HOME/.rikune}"
WINDOWS_HOST="${WINDOWS_HOST:-}"
WINDOWS_USER="${WINDOWS_USER:-Administrator}"
SSH_KEY="${SSH_KEY:-}"
HOST_AGENT_PORT="${HOST_AGENT_PORT:-18082}"
HOST_AGENT_ENDPOINT="${RUNTIME_HOST_AGENT_ENDPOINT:-}"
HOST_AGENT_API_KEY="${RUNTIME_HOST_AGENT_API_KEY:-${RIKUNE_HOST_AGENT_API_KEY:-${HOST_AGENT_API_KEY:-}}}"
RUNTIME_API_KEY="${RUNTIME_API_KEY:-${RIKUNE_RUNTIME_NODE_API_KEY:-${HOST_AGENT_RUNTIME_API_KEY:-}}}"
ANALYZER_API_KEY="${RIKUNE_API_KEY:-${RIKUNE_ANALYZER_API_KEY:-}}"
BUILD_HTTP_PROXY="${RIKUNE_BUILD_HTTP_PROXY:-}"
BUILD_HTTPS_PROXY="${RIKUNE_BUILD_HTTPS_PROXY:-}"
BUILD_NO_PROXY="${RIKUNE_BUILD_NO_PROXY:-localhost,127.0.0.1,deb.debian.org,security.debian.org,mirrors.aliyun.com,archive.ubuntu.com,security.ubuntu.com,aliyuncs.com}"
export -n HOST_AGENT_API_KEY RUNTIME_API_KEY ANALYZER_API_KEY \
  BUILD_HTTP_PROXY BUILD_HTTPS_PROXY BUILD_NO_PROXY 2>/dev/null || true
unset RUNTIME_HOST_AGENT_ENDPOINT RUNTIME_HOST_AGENT_API_KEY \
  RIKUNE_HOST_AGENT_API_KEY HOST_AGENT_RUNTIME_API_KEY
unset RIKUNE_RUNTIME_NODE_API_KEY RIKUNE_RUNTIME_API_KEY
unset RIKUNE_API_KEY RIKUNE_ANALYZER_API_KEY
unset RIKUNE_VERIFY_PRIVATE_ENV_PATH RIKUNE_STAGE_DOCKER_ENV_PATH \
  RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH RIKUNE_RESTORE_PRIVATE_ENV_PATH \
  RIKUNE_REMOVE_PRIVATE_ENV_PATH RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN \
  RIKUNE_DOCKER_ENV_PATH RIKUNE_DOCKER_ENV_DATA_ROOT RIKUNE_DOCKER_ENV_PROFILE \
  RIKUNE_BUILD_HTTP_PROXY RIKUNE_BUILD_HTTPS_PROXY RIKUNE_BUILD_NO_PROXY \
  RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP RIKUNE_STAGE_LOCAL_ENV_PATH \
  RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN RIKUNE_LOCAL_EXISTING_ENV_BASE64 \
  RIKUNE_LOCAL_ENV_PATH RIKUNE_LOCAL_ENV_FORCE_KEYS RIKUNE_PRIVATE_ENV_PATH \
  RIKUNE_PRIVATE_ENV_ACL_MODE STAGED_LOCAL_ENV_BASE64
SCRIPT_DIRECTORY="${BASH_SOURCE[0]%/*}"
[ "$SCRIPT_DIRECTORY" != "${BASH_SOURCE[0]}" ] || SCRIPT_DIRECTORY="."
PROJECT_ROOT="$(cd "$SCRIPT_DIRECTORY" && pwd)"
SKIP_BUILD=false
SKIP_START=false
SKIP_WINDOWS_SETUP=false
RESET_DATA=false
FOLLOW=false
TAIL=100
ALLOW_INSECURE_RUNTIME_HTTP=false
PRIVATE_ENV_WRITER="$PROJECT_ROOT/scripts/write-docker-runtime-env.mjs"
PRIVATE_ENV_TARGET="$PROJECT_ROOT/.docker-runtime.env"
PRIVATE_ENV_SNAPSHOT=""
PRIVATE_ENV_TRANSACTION_ACTIVE=false
PRIVATE_ENV_TRANSACTION_COMMITTED=false

usage() {
  cat <<EOF
Usage:
  ./rikune.sh
  ./rikune.sh install --profile static
  ./rikune.sh install --profile full
  ./rikune.sh install --profile hybrid --windows-host <host> --windows-user <user>
  ./rikune.sh install --profile hybrid --host-agent-endpoint https://<trusted-runtime-endpoint>
  ./rikune.sh start|stop|restart|status|logs|health|doctor|generate [--profile static|hybrid|full]

Options:
  -p, --profile NAME              static, hybrid, or full (default: static)
  -d, --data-root DIR             Persistent data root (default: \$HOME/.rikune)
  -w, --windows-host HOST         Remote Windows host for hybrid SSH bootstrap
  -u, --windows-user USER         Remote Windows SSH user (default: Administrator)
  -k, --ssh-key PATH              SSH private key path for remote Windows bootstrap
  -e, --host-agent-endpoint URL   Existing Windows Host Agent endpoint
      --host-agent-port PORT      Windows Host Agent port (default: 18082)
      --allow-insecure-runtime-http
                                      Allow remote plaintext HTTP only on an isolated trusted network
      --skip-build                Skip Docker image build
      --skip-start                Skip Compose start
      --skip-windows-setup        For remote hybrid, do not install Windows runtime
      --reset-data                Delete and recreate the data root before install
  -f, --follow                    Follow logs
      --tail N                    Log tail count (default: 100)
  -h, --help                      Show this help

Credentials:
  Provide distinct RUNTIME_HOST_AGENT_API_KEY and RUNTIME_API_KEY through a
  protected process environment or an interactive hidden prompt. Secrets are
  not accepted as command-line arguments.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|--profile) PROFILE="$2"; shift 2 ;;
    -d|--data-root) DATA_ROOT="$2"; shift 2 ;;
    -w|--windows-host) WINDOWS_HOST="$2"; shift 2 ;;
    -u|--windows-user) WINDOWS_USER="$2"; shift 2 ;;
    -k|--ssh-key) SSH_KEY="$2"; shift 2 ;;
    -e|--host-agent-endpoint) HOST_AGENT_ENDPOINT="$2"; shift 2 ;;
    --host-agent-port) HOST_AGENT_PORT="$2"; shift 2 ;;
    --allow-insecure-runtime-http) ALLOW_INSECURE_RUNTIME_HTTP=true; shift ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --skip-start) SKIP_START=true; shift ;;
    --skip-windows-setup) SKIP_WINDOWS_SETUP=true; shift ;;
    --reset-data) RESET_DATA=true; shift ;;
    -f|--follow) FOLLOW=true; shift ;;
    --tail) TAIL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown option: $1"; usage; exit 1 ;;
  esac
done

validate_profile() {
  case "$1" in
    static|hybrid|full) ;;
    *) err "Unknown profile: $1"; exit 1 ;;
  esac
}

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
    err "Remote Host Agent endpoints must use HTTPS. Use --allow-insecure-runtime-http only for an isolated trusted network."
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

compose_file() {
  case "$1" in
    static) printf "docker-compose.analyzer.yml" ;;
    hybrid) printf "docker-compose.hybrid.yml" ;;
    full) printf "docker-compose.yml" ;;
  esac
}

service_name() {
  case "$1" in
    static|hybrid) printf "analyzer" ;;
    full) printf "mcp-server" ;;
  esac
}

generator_profile() {
  case "$1" in
    static) printf "static" ;;
    hybrid) printf "hybrid" ;;
    full) printf "full" ;;
  esac
}

profile_description() {
  case "$1" in
    static) printf "Static-only Docker analyzer" ;;
    hybrid) printf "Docker analyzer + Windows Host Agent / Windows Sandbox" ;;
    full) printf "Full all-in-one Linux Docker image" ;;
  esac
}

require_cmd() {
  local cmd="$1"
  local hint="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "$cmd not found"
    [ -n "$hint" ] && info "$hint"
    exit 1
  fi
}

has_compose() {
  docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1
}

run_compose() {
  local profile="$1"
  shift
  local file
  file="$PROJECT_ROOT/$(compose_file "$profile")"
  local args=()

  [ -f "$file" ] || { err "Compose file not found: $file"; exit 1; }
  if [ -e "$PROJECT_ROOT/.docker-runtime.env" ] || [ -L "$PROJECT_ROOT/.docker-runtime.env" ]; then
    verify_private_env_file "$PROJECT_ROOT/.docker-runtime.env"
    args+=(--env-file "$PROJECT_ROOT/.docker-runtime.env")
  else
    warn ".docker-runtime.env not found. Compose defaults will be used."
  fi
  args+=(-f "$file")

  if docker compose version >/dev/null 2>&1; then
    (cd "$PROJECT_ROOT" && docker compose "${args[@]}" "$@")
  elif command -v docker-compose >/dev/null 2>&1; then
    (cd "$PROJECT_ROOT" && docker-compose "${args[@]}" "$@")
  else
    err "Docker Compose not found"
    exit 1
  fi
}

verify_private_env_file() {
  local target="$1"
  RIKUNE_VERIFY_PRIVATE_ENV_PATH="$target" \
    node "$PROJECT_ROOT/scripts/write-docker-runtime-env.mjs"
}

rollback_private_env_transaction() {
  local original_status="${1:-1}"
  trap - EXIT INT TERM
  if [ "$PRIVATE_ENV_TRANSACTION_ACTIVE" = true ] && [ "$PRIVATE_ENV_TRANSACTION_COMMITTED" != true ]; then
    set +e
    printf '%s' "$PRIVATE_ENV_SNAPSHOT" |
      RIKUNE_RESTORE_PRIVATE_ENV_PATH="$PRIVATE_ENV_TARGET" node "$PRIVATE_ENV_WRITER"
    local restore_status=$?
    set -e
    if [ "$restore_status" -ne 0 ]; then
      err "Failed to restore the protected Compose env after installer failure."
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
  PRIVATE_ENV_SNAPSHOT="$(RIKUNE_STAGE_DOCKER_ENV_PATH="$PRIVATE_ENV_TARGET" node "$PRIVATE_ENV_WRITER")"
  export -n PRIVATE_ENV_SNAPSHOT 2>/dev/null || true
  PRIVATE_ENV_TRANSACTION_ACTIVE=true
  trap 'rollback_private_env_transaction "$?"' EXIT
  trap 'interrupt_private_env_transaction INT' INT
  trap 'interrupt_private_env_transaction TERM' TERM
  printf '%s' "$PRIVATE_ENV_SNAPSHOT" |
    RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH="$PRIVATE_ENV_TARGET" node "$PRIVATE_ENV_WRITER"
  info "Any prior protected Compose env was removed before dependency lifecycle commands; credentials will be rotated after build."
}

commit_private_env_transaction() {
  PRIVATE_ENV_TRANSACTION_COMMITTED=true
  PRIVATE_ENV_SNAPSHOT=""
  trap - EXIT INT TERM
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

provision_analyzer_api_key() {
  if [ -z "$ANALYZER_API_KEY" ]; then
    ANALYZER_API_KEY="$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")"
  fi
  assert_runtime_api_key "Analyzer API key" "$ANALYZER_API_KEY"
}

env_value() {
  local key="$1"
  local file="${2:-$PROJECT_ROOT/.docker-runtime.env}"
  [ -f "$file" ] || return 0
  awk -v k="$key" 'index($0, k "=") == 1 { print substr($0, length(k) + 2) }' "$file" | tail -n 1 | tr -d '\r'
}

prompt_default() {
  local prompt="$1"
  local default="$2"
  local value
  read -r -p "$prompt [$default]: " value
  if [ -z "$value" ]; then
    printf "%s" "$default"
  else
    printf "%s" "$value"
  fi
}

check_prereqs() {
  step "Checking prerequisites"
  require_cmd docker "Install Docker Engine or Docker Desktop."
  docker info >/dev/null 2>&1 || { err "Docker daemon is not running"; exit 1; }
  ok "Docker daemon is running"

  has_compose || { err "Docker Compose not found"; exit 1; }
  ok "Docker Compose available"

  require_cmd node "Install Node.js 22.9+."
  require_cmd npm "Install npm with Node.js."
  local node_version
  node_version="$(node --version)"
  local node_version_core="${node_version#v}"
  local node_major="$node_version_core"
  node_major="${node_major%%.*}"
  local node_minor="${node_version_core#*.}"
  node_minor="${node_minor%%.*}"
  if [ "$node_major" -lt 22 ] || { [ "$node_major" -eq 22 ] && [ "$node_minor" -lt 9 ]; }; then
    err "Node.js $node_version is too old; 22.9+ is required"
    exit 1
  fi
  ok "Node.js: $node_version"
  ok "npm: $(npm --version)"
}

write_env_file() {
  local profile="$1"
  local env_file="$PROJECT_ROOT/.docker-runtime.env"
  reset_data_root
  mkdir -p \
    "$DATA_ROOT/samples" \
    "$DATA_ROOT/workspaces" \
    "$DATA_ROOT/data" \
    "$DATA_ROOT/cache" \
    "$DATA_ROOT/logs" \
    "$DATA_ROOT/storage" \
    "$DATA_ROOT/ghidra-projects" \
    "$DATA_ROOT/ghidra-logs" \
    "$DATA_ROOT/qiling-rootfs" \
    "$DATA_ROOT/config"
  prepare_linux_data_root_permissions

  printf '%s' "$PRIVATE_ENV_SNAPSHOT" |
  RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN=1 \
  RIKUNE_DOCKER_ENV_PATH="$env_file" \
  RIKUNE_DOCKER_ENV_DATA_ROOT="$DATA_ROOT" \
  RIKUNE_DOCKER_ENV_PROFILE="$profile" \
  RIKUNE_BUILD_HTTP_PROXY="$BUILD_HTTP_PROXY" \
  RIKUNE_BUILD_HTTPS_PROXY="$BUILD_HTTPS_PROXY" \
  RIKUNE_BUILD_NO_PROXY="$BUILD_NO_PROXY" \
  RIKUNE_API_KEY="$ANALYZER_API_KEY" \
  RUNTIME_HOST_AGENT_ENDPOINT="$HOST_AGENT_ENDPOINT" \
  RUNTIME_HOST_AGENT_API_KEY="$HOST_AGENT_API_KEY" \
  RUNTIME_API_KEY="$RUNTIME_API_KEY" \
  RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP="$ALLOW_INSECURE_RUNTIME_HTTP" \
    node "$PROJECT_ROOT/scripts/write-docker-runtime-env.mjs"

  # The writer atomically installed and verified the new private file. From this
  # point onward it is authoritative; later Compose failures must not restore an
  # old key while a container may already be using the new one.
  commit_private_env_transaction
  chmod 600 "$env_file"

  ok "Wrote .docker-runtime.env"
}

prepare_linux_data_root_permissions() {
  local os_name
  os_name="$(uname -s 2>/dev/null || printf "unknown")"
  case "$os_name" in
    Linux*) ;;
    *) return 0 ;;
  esac

  if [ "$(id -u)" -ne 0 ]; then
    warn "Linux Docker bind mounts may need appuser ownership. If the analyzer cannot open SQLite, run: sudo chown -R 1000:1000 '$DATA_ROOT'"
    return 0
  fi

  chown -R 1000:1000 \
    "$DATA_ROOT/workspaces" \
    "$DATA_ROOT/data" \
    "$DATA_ROOT/cache" \
    "$DATA_ROOT/logs" \
    "$DATA_ROOT/storage" \
    "$DATA_ROOT/ghidra-projects" \
    "$DATA_ROOT/ghidra-logs" \
    "$DATA_ROOT/qiling-rootfs" \
    "$DATA_ROOT/config"
  ok "Prepared Linux Docker bind mount ownership for appuser"
}

reset_data_root() {
  [ "$RESET_DATA" = true ] || return 0
  [ -e "$DATA_ROOT" ] || return 0

  case "$DATA_ROOT" in
    ""|"/"|"."|".."|"$HOME") err "Refusing to delete unsafe data root: $DATA_ROOT"; exit 1 ;;
  esac
  if [ "${#DATA_ROOT}" -lt 6 ]; then
    err "Refusing to delete short data root: $DATA_ROOT"
    exit 1
  fi

  warn "Deleting data root because --reset-data was specified: $DATA_ROOT"
  rm -rf -- "$DATA_ROOT"
}

generate_profile() {
  local profile="$1"
  step "Generating Docker profile"
  (cd "$PROJECT_ROOT" && node scripts/generate-docker.mjs "--profile=$(generator_profile "$profile")")
  ok "Generated $(compose_file "$profile")"
}

build_project() {
  step "Building project"
  (cd "$PROJECT_ROOT" && npm ci --include=dev && npm run build)
  ok "Project build completed"
}

verify_hybrid_runtime() {
  step "Verifying Hybrid runtime lifecycle from the analyzer container"
  docker exec rikune-analyzer node /app/scripts/verify-hybrid-runtime.mjs
  ok "Hybrid Host Agent and Runtime Node lifecycle verified"
}

install_remote_hybrid() {
  reset_data_root
  [ -x "$PROJECT_ROOT/deploy-hybrid.sh" ] || chmod +x "$PROJECT_ROOT/deploy-hybrid.sh" 2>/dev/null || true
  [ -f "$PROJECT_ROOT/deploy-hybrid.sh" ] || { err "deploy-hybrid.sh not found"; exit 1; }

  local args=(-w "$WINDOWS_HOST" -u "$WINDOWS_USER" -d "$DATA_ROOT" -p "$HOST_AGENT_PORT")
  [ -n "$SSH_KEY" ] && args+=(-k "$SSH_KEY")
  [ -n "$HOST_AGENT_ENDPOINT" ] && args+=(-e "$HOST_AGENT_ENDPOINT")
  [ "$SKIP_WINDOWS_SETUP" = true ] && args+=(-s)
  [ "$ALLOW_INSECURE_RUNTIME_HTTP" = true ] && args+=(-i)

  step "Delegating hybrid install to deploy-hybrid.sh"
  RUNTIME_HOST_AGENT_API_KEY="$HOST_AGENT_API_KEY" \
  RUNTIME_API_KEY="$RUNTIME_API_KEY" \
  RIKUNE_API_KEY="$ANALYZER_API_KEY" \
    "$PROJECT_ROOT/deploy-hybrid.sh" "${args[@]}"
}

install_stack() {
  local profile="$1"
  validate_profile "$profile"

  header "Rikune Install: $profile"
  info "$(profile_description "$profile")"
  info "Project root: $PROJECT_ROOT"
  info "Data root: $DATA_ROOT"

  if [ "$profile" = "hybrid" ] && [ -n "$WINDOWS_HOST" ]; then
    install_remote_hybrid
    return
  fi

  if [ "$profile" = "hybrid" ]; then
    if [ -z "$HOST_AGENT_ENDPOINT" ] && [ -t 0 ]; then
      HOST_AGENT_ENDPOINT="$(prompt_default "Windows Host Agent endpoint" "http://<windows-host>:18082")"
    fi
    if [ -z "$HOST_AGENT_API_KEY" ] && [ -t 0 ]; then
      read -r -s -p "Windows Host Agent API key: " HOST_AGENT_API_KEY
      printf '\n'
    fi
    if [ -z "$RUNTIME_API_KEY" ] && [ -t 0 ]; then
      read -r -s -p "Distinct Runtime Node API key: " RUNTIME_API_KEY
      printf '\n'
    fi
    if [ -z "$HOST_AGENT_ENDPOINT" ] || [ -z "$HOST_AGENT_API_KEY" ] || [ -z "$RUNTIME_API_KEY" ]; then
      err "Hybrid install needs --windows-host for SSH bootstrap, or an existing endpoint plus distinct RUNTIME_HOST_AGENT_API_KEY and RUNTIME_API_KEY values from a protected environment."
      exit 1
    fi
    assert_runtime_api_key "Host Agent API key" "$HOST_AGENT_API_KEY"
    assert_runtime_api_key "Runtime Node API key" "$RUNTIME_API_KEY"
    if [ "$HOST_AGENT_API_KEY" = "$RUNTIME_API_KEY" ]; then
      err "Host Agent and Runtime Node API keys must be distinct"
      exit 1
    fi
    assert_secure_runtime_endpoint "$HOST_AGENT_ENDPOINT"
  fi

  check_prereqs
  [ -f "$PRIVATE_ENV_WRITER" ] || { err "Secure private environment writer not found: $PRIVATE_ENV_WRITER"; exit 1; }
  begin_private_env_transaction
  assert_secret_environment_cleared
  build_project
  generate_profile "$profile"
  provision_analyzer_api_key
  write_env_file "$profile"

  local service
  service="$(service_name "$profile")"

  if [ "$SKIP_BUILD" = true ]; then
    warn "Skipping Docker image build"
  else
    step "Building Docker image"
    run_compose "$profile" build "$service"
    ok "Docker image build completed"
  fi

  if [ "$SKIP_START" = true ]; then
    warn "Skipping Compose start"
  else
    step "Starting service"
    run_compose "$profile" up -d "$service"
    ok "Service started: $service"
    show_health "$profile"
    [ "$profile" = "hybrid" ] && verify_hybrid_runtime
  fi
}

start_stack() {
  local profile="$1"
  local service
  validate_profile "$profile"
  service="$(service_name "$profile")"
  header "Start Rikune: $profile"
  run_compose "$profile" up -d "$service"
  ok "Service started: $service"
}

stop_stack() {
  local profile="$1"
  validate_profile "$profile"
  header "Stop Rikune: $profile"
  run_compose "$profile" down
  ok "Compose stack stopped"
}

restart_stack() {
  local profile="$1"
  stop_stack "$profile"
  start_stack "$profile"
}

show_logs() {
  local profile="$1"
  local service
  validate_profile "$profile"
  service="$(service_name "$profile")"

  local args=(logs --tail "$TAIL")
  [ "$FOLLOW" = true ] && args+=(-f)
  args+=("$service")
  run_compose "$profile" "${args[@]}"
}

curl_json() {
  local url="$1"
  shift || true
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "$@" "$url"
  elif command -v node >/dev/null 2>&1; then
    node -e "const http=require('http');const url=process.argv[1];http.get(url,res=>{process.exit(res.statusCode===200?0:1)}).on('error',()=>process.exit(1));" "$url"
  else
    return 1
  fi
}

check_analyzer_health() {
  local url="http://127.0.0.1:18080/api/v1/health"
  if curl_json "$url" >/dev/null 2>&1; then
    ok "Analyzer API healthy: $url"
  else
    warn "Analyzer API health check failed: $url"
  fi
}

check_runtime_health() {
  if [ -e "$PROJECT_ROOT/.docker-runtime.env" ] || [ -L "$PROJECT_ROOT/.docker-runtime.env" ]; then
    verify_private_env_file "$PROJECT_ROOT/.docker-runtime.env"
  fi
  local endpoint="${HOST_AGENT_ENDPOINT:-$(env_value RUNTIME_HOST_AGENT_ENDPOINT)}"
  local key="${HOST_AGENT_API_KEY:-$(env_value RUNTIME_HOST_AGENT_API_KEY)}"

  if [ -z "$endpoint" ] || [ -z "$key" ]; then
    warn "Host Agent endpoint/key not found"
    return 0
  fi

  local url="${endpoint%/}/sandbox/health"
  if command -v curl >/dev/null 2>&1 && printf 'Authorization: Bearer %s\n' "$key" | curl -fsS --header @- "$url" >/dev/null 2>&1; then
    ok "Windows Host Agent healthy: $url"
  else
    warn "Windows Host Agent health check failed: $url"
  fi
}

show_health() {
  local profile="$1"
  validate_profile "$profile"
  header "Rikune Health: $profile"
  check_analyzer_health
  [ "$profile" = "hybrid" ] && check_runtime_health
  return 0
}

show_status() {
  local profile="$1"
  validate_profile "$profile"
  header "Rikune Status: $profile"
  run_compose "$profile" ps || true
  show_health "$profile"
}

show_doctor() {
  local profile="$1"
  validate_profile "$profile"
  header "Rikune Doctor"

  command -v uname >/dev/null 2>&1 && ok "OS: $(uname -s) $(uname -m)"

  if command -v docker >/dev/null 2>&1; then
    ok "Docker CLI: $(docker --version)"
    if docker info >/dev/null 2>&1; then ok "Docker daemon is running"; else warn "Docker daemon is not reachable"; fi
  else
    err "Docker CLI not found"
  fi

  if has_compose; then ok "Docker Compose available"; else err "Docker Compose not found"; fi

  if command -v node >/dev/null 2>&1; then ok "Node.js: $(node --version)"; else err "Node.js not found"; fi
  if command -v npm >/dev/null 2>&1; then ok "npm: $(npm --version)"; else err "npm not found"; fi

  for file in install-docker.ps1 install-runtime-windows.ps1 scripts/generate-docker.mjs; do
    if [ -f "$PROJECT_ROOT/$file" ]; then ok "Found $file"; else err "Missing $file"; fi
  done

  if [ "$profile" = "hybrid" ]; then
    if [ -n "$WINDOWS_HOST" ]; then
      if command -v ssh >/dev/null 2>&1; then ok "SSH client available"; else err "SSH client not found"; fi
      info "Windows host: $WINDOWS_HOST"
    fi
    check_runtime_health
  fi

  local file
  file="$PROJECT_ROOT/$(compose_file "$profile")"
  if [ -f "$file" ] && has_compose; then
    if run_compose "$profile" config --quiet >/dev/null 2>&1; then
      ok "Compose config is valid for profile '$profile'"
    else
      warn "Compose config check failed for profile '$profile'"
    fi
  else
    warn "Compose config check skipped"
  fi
}

runtime_stop() {
  if [ -z "$WINDOWS_HOST" ]; then
    err "runtime-stop requires --windows-host and SSH access"
    exit 1
  fi

  require_cmd ssh "Install an SSH client."
  local ssh_args=(-o BatchMode=yes -o ConnectTimeout=10)
  [ -n "$SSH_KEY" ] && ssh_args+=(-i "$SSH_KEY")

  header "Stop remote Windows Host Agent"
  ssh "${ssh_args[@]}" "${WINDOWS_USER}@${WINDOWS_HOST}" \
    "pwsh -NoProfile -NonInteractive -Command \"\$pm2='C:/rikune/node_modules/.bin/pm2.cmd'; if (Test-Path -LiteralPath \$pm2) { & \$pm2 stop rikune-host-agent; & \$pm2 delete rikune-host-agent }; Get-CimInstance Win32_Process -Filter 'Name = ''node.exe''' | Where-Object { \$_.CommandLine -match 'windows-host-agent' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force }\""
  ok "Remote Host Agent stop attempted"
}

show_menu() {
  header "Rikune Control"
  printf "  [1] Install static Docker analyzer\n"
  printf "  [2] Install hybrid with remote Windows host over SSH\n"
  printf "  [3] Install hybrid with existing Host Agent endpoint/key\n"
  printf "  [4] Install full Docker image\n"
  printf "  [5] Start current profile\n"
  printf "  [6] Status and health\n"
  printf "  [7] Logs\n"
  printf "  [8] Stop current profile\n"
  printf "  [9] Doctor\n"
  printf "  [0] Exit\n"
  read -r -p "Select: " choice

  case "$choice" in
    1)
      PROFILE="static"
      DATA_ROOT="$(prompt_default "Data root" "$DATA_ROOT")"
      install_stack "$PROFILE"
      ;;
    2)
      PROFILE="hybrid"
      DATA_ROOT="$(prompt_default "Data root" "$DATA_ROOT")"
      read -r -p "Windows host: " WINDOWS_HOST
      WINDOWS_USER="$(prompt_default "Windows SSH user" "$WINDOWS_USER")"
      SSH_KEY="$(prompt_default "SSH private key path (empty for ssh default)" "$SSH_KEY")"
      HOST_AGENT_ENDPOINT="$(prompt_default "Windows Host Agent endpoint" "https://$WINDOWS_HOST")"
      if [[ "$HOST_AGENT_ENDPOINT" =~ ^http:// ]] && ! [[ "$HOST_AGENT_ENDPOINT" =~ ^http://(localhost|127\.0\.0\.1|host\.docker\.internal|\[::1\])(:[0-9]+)?(/|$) ]]; then
        read -r -p "Allow plaintext runtime HTTP only on an isolated trusted network? [y/N]: " allow_http
        case "$allow_http" in
          y|Y|yes|YES) ALLOW_INSECURE_RUNTIME_HTTP=true ;;
          *) err "Remote Hybrid installation cancelled because HTTPS was not configured."; return ;;
        esac
      fi
      install_stack "$PROFILE"
      ;;
    3)
      PROFILE="hybrid"
      DATA_ROOT="$(prompt_default "Data root" "$DATA_ROOT")"
      HOST_AGENT_ENDPOINT="$(prompt_default "Windows Host Agent endpoint" "https://<trusted-runtime-endpoint>")"
      read -r -s -p "Windows Host Agent API key: " HOST_AGENT_API_KEY
      printf '\n'
      read -r -s -p "Distinct Runtime Node API key: " RUNTIME_API_KEY
      printf '\n'
      install_stack "$PROFILE"
      ;;
    4)
      PROFILE="full"
      DATA_ROOT="$(prompt_default "Data root" "$DATA_ROOT")"
      install_stack "$PROFILE"
      ;;
    5)
      PROFILE="$(prompt_default "Profile" "$PROFILE")"
      start_stack "$PROFILE"
      ;;
    6)
      PROFILE="$(prompt_default "Profile" "$PROFILE")"
      show_status "$PROFILE"
      ;;
    7)
      PROFILE="$(prompt_default "Profile" "$PROFILE")"
      FOLLOW=true
      show_logs "$PROFILE"
      ;;
    8)
      PROFILE="$(prompt_default "Profile" "$PROFILE")"
      stop_stack "$PROFILE"
      ;;
    9)
      PROFILE="$(prompt_default "Profile" "$PROFILE")"
      show_doctor "$PROFILE"
      ;;
    0) exit 0 ;;
    *) warn "Unknown selection" ;;
  esac
}

validate_profile "$PROFILE"

case "$ACTION" in
  menu) show_menu ;;
  install) install_stack "$PROFILE" ;;
  start) start_stack "$PROFILE" ;;
  stop) stop_stack "$PROFILE" ;;
  restart) restart_stack "$PROFILE" ;;
  status) show_status "$PROFILE" ;;
  logs) show_logs "$PROFILE" ;;
  health) show_health "$PROFILE" ;;
  doctor) show_doctor "$PROFILE" ;;
  generate) generate_profile "$PROFILE" ;;
  runtime-status) check_runtime_health ;;
  runtime-stop) runtime_stop ;;
  *) err "Unknown action: $ACTION"; usage; exit 1 ;;
esac
