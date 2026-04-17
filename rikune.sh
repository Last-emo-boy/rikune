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

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
HOST_AGENT_API_KEY="${RUNTIME_HOST_AGENT_API_KEY:-}"
RUNTIME_API_KEY="${RUNTIME_API_KEY:-}"
SKIP_BUILD=false
SKIP_START=false
SKIP_WINDOWS_SETUP=false
RESET_DATA=false
FOLLOW=false
TAIL=100

usage() {
  cat <<EOF
Usage:
  ./rikune.sh
  ./rikune.sh install --profile static
  ./rikune.sh install --profile full
  ./rikune.sh install --profile hybrid --windows-host <host> --windows-user <user>
  ./rikune.sh install --profile hybrid --host-agent-endpoint http://<windows-host>:18082 --host-agent-api-key <key>
  ./rikune.sh start|stop|restart|status|logs|health|doctor|generate [--profile static|hybrid|full]

Options:
  -p, --profile NAME              static, hybrid, or full (default: static)
  -d, --data-root DIR             Persistent data root (default: \$HOME/.rikune)
  -w, --windows-host HOST         Remote Windows host for hybrid SSH bootstrap
  -u, --windows-user USER         Remote Windows SSH user (default: Administrator)
  -k, --ssh-key PATH              SSH private key path for remote Windows bootstrap
  -e, --host-agent-endpoint URL   Existing Windows Host Agent endpoint
  -a, --host-agent-api-key KEY    Existing Windows Host Agent API key
  -r, --runtime-api-key KEY       Runtime Node API key, defaults to Host Agent key
      --host-agent-port PORT      Windows Host Agent port (default: 18082)
      --skip-build                Skip Docker image build
      --skip-start                Skip Compose start
      --skip-windows-setup        For remote hybrid, do not install Windows runtime
      --reset-data                Delete and recreate the data root before install
  -f, --follow                    Follow logs
      --tail N                    Log tail count (default: 100)
  -h, --help                      Show this help
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
    -a|--host-agent-api-key) HOST_AGENT_API_KEY="$2"; shift 2 ;;
    -r|--runtime-api-key) RUNTIME_API_KEY="$2"; shift 2 ;;
    --host-agent-port) HOST_AGENT_PORT="$2"; shift 2 ;;
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
  local file="$PROJECT_ROOT/$(compose_file "$profile")"
  local args=()

  [ -f "$file" ] || { err "Compose file not found: $file"; exit 1; }
  if [ -f "$PROJECT_ROOT/.docker-runtime.env" ]; then
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

  require_cmd node "Install Node.js 22+."
  require_cmd npm "Install npm with Node.js."
  local node_version
  node_version="$(node --version)"
  local node_major="${node_version#v}"
  node_major="${node_major%%.*}"
  if [ "$node_major" -lt 22 ]; then
    err "Node.js $node_version is too old; 22+ is required"
    exit 1
  fi
  ok "Node.js: $node_version"
  ok "npm: $(npm --version)"
}

write_env_file() {
  local profile="$1"
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

  cat > "$PROJECT_ROOT/.docker-runtime.env" <<EOF
# Rikune Docker runtime environment - generated by rikune.sh
RIKUNE_DATA_ROOT=$DATA_ROOT
RIKUNE_BUILD_HTTP_PROXY=${RIKUNE_BUILD_HTTP_PROXY:-}
RIKUNE_BUILD_HTTPS_PROXY=${RIKUNE_BUILD_HTTPS_PROXY:-}
RIKUNE_BUILD_NO_PROXY=localhost,127.0.0.1,deb.debian.org,security.debian.org,mirrors.aliyun.com,archive.ubuntu.com,security.ubuntu.com,aliyuncs.com
EOF

  if [ "$profile" = "hybrid" ]; then
    {
      printf "RUNTIME_HOST_AGENT_ENDPOINT=%s\n" "$HOST_AGENT_ENDPOINT"
      printf "RUNTIME_HOST_AGENT_API_KEY=%s\n" "$HOST_AGENT_API_KEY"
      printf "RUNTIME_API_KEY=%s\n" "${RUNTIME_API_KEY:-$HOST_AGENT_API_KEY}"
    } >> "$PROJECT_ROOT/.docker-runtime.env"
  fi

  ok "Wrote .docker-runtime.env"
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
  (cd "$PROJECT_ROOT" && npm install && npm run build)
  ok "Project build completed"
}

install_remote_hybrid() {
  reset_data_root
  [ -x "$PROJECT_ROOT/deploy-hybrid.sh" ] || chmod +x "$PROJECT_ROOT/deploy-hybrid.sh" 2>/dev/null || true
  [ -f "$PROJECT_ROOT/deploy-hybrid.sh" ] || { err "deploy-hybrid.sh not found"; exit 1; }

  local args=(-w "$WINDOWS_HOST" -u "$WINDOWS_USER" -d "$DATA_ROOT" -p "$HOST_AGENT_PORT")
  [ -n "$SSH_KEY" ] && args+=(-k "$SSH_KEY")
  [ -n "$HOST_AGENT_ENDPOINT" ] && args+=(-e "$HOST_AGENT_ENDPOINT")
  [ -n "$HOST_AGENT_API_KEY" ] && args+=(-a "$HOST_AGENT_API_KEY")
  [ -n "$RUNTIME_API_KEY" ] && args+=(-r "$RUNTIME_API_KEY")
  [ "$SKIP_WINDOWS_SETUP" = true ] && args+=(-s)

  step "Delegating hybrid install to deploy-hybrid.sh"
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
      read -r -p "Windows Host Agent API key: " HOST_AGENT_API_KEY
    fi
    if [ -z "$RUNTIME_API_KEY" ]; then
      RUNTIME_API_KEY="$HOST_AGENT_API_KEY"
    fi
    if [ -z "$HOST_AGENT_ENDPOINT" ] || [ -z "$HOST_AGENT_API_KEY" ]; then
      err "Hybrid install needs --windows-host for SSH bootstrap, or --host-agent-endpoint and --host-agent-api-key for an existing Host Agent."
      exit 1
    fi
  fi

  check_prereqs
  write_env_file "$profile"
  build_project
  generate_profile "$profile"

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
  local endpoint="${HOST_AGENT_ENDPOINT:-$(env_value RUNTIME_HOST_AGENT_ENDPOINT)}"
  local key="${HOST_AGENT_API_KEY:-$(env_value RUNTIME_HOST_AGENT_API_KEY)}"

  if [ -z "$endpoint" ] || [ -z "$key" ]; then
    warn "Host Agent endpoint/key not found"
    return 0
  fi

  local url="${endpoint%/}/sandbox/health"
  if command -v curl >/dev/null 2>&1 && curl -fsS -H "Authorization: Bearer $key" "$url" >/dev/null 2>&1; then
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

  local file="$PROJECT_ROOT/$(compose_file "$profile")"
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
    "powershell -NoProfile -Command \"if (Get-Command pm2 -ErrorAction SilentlyContinue) { pm2 stop rikune-host-agent; pm2 delete rikune-host-agent }; Get-CimInstance Win32_Process -Filter 'Name = ''node.exe''' | Where-Object { \$_.CommandLine -match 'windows-host-agent' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force }\""
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
      install_stack "$PROFILE"
      ;;
    3)
      PROFILE="hybrid"
      DATA_ROOT="$(prompt_default "Data root" "$DATA_ROOT")"
      HOST_AGENT_ENDPOINT="$(prompt_default "Windows Host Agent endpoint" "http://<windows-host>:18082")"
      read -r -p "Windows Host Agent API key: " HOST_AGENT_API_KEY
      RUNTIME_API_KEY="${RUNTIME_API_KEY:-$HOST_AGENT_API_KEY}"
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
