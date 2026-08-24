#!/usr/bin/env bash
# =============================================================================
# Rikune — Local (Non-Docker) Install Script for Linux x86_64
# Requires: Node.js 22.9+, CPython 3.12 x86_64, bash
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

is_wsl_kernel() {
  [ -n "${WSL_DISTRO_NAME:-}" ] || [ -n "${WSL_INTEROP:-}" ] ||
    { [ -r /proc/sys/kernel/osrelease ] && grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease; } ||
    { [ -r /proc/version ] && grep -qiE 'microsoft|wsl' /proc/version; }
}

is_verified_wsl2_kernel() {
  { [ -r /proc/sys/kernel/osrelease ] && grep -qiE 'microsoft-standard|wsl2' /proc/sys/kernel/osrelease; } ||
    { [ -r /proc/version ] && grep -qiE 'microsoft-standard|wsl2' /proc/version; }
}

decode_mountinfo_path() {
  local value="$1"
  value="${value//\\040/ }"
  value="${value//\\011/$'\t'}"
  value="${value//\\012/$'\n'}"
  value="${value//\\134/\\}"
  printf '%s' "$value"
}

assert_supported_wsl_data_root() {
  local configured_root="$1"
  is_wsl_kernel || return 0
  is_verified_wsl2_kernel || {
    err "Rikune Analyzer requires WSL2; WSL1 and unverified WSL kernels are unsupported."
    exit 1
  }

  command -v realpath >/dev/null 2>&1 || {
    err "Cannot verify the WSL2 data root because realpath is unavailable."
    exit 1
  }
  [ -r /proc/self/mountinfo ] || {
    err "Cannot verify the WSL2 data root because /proc/self/mountinfo is unavailable."
    exit 1
  }

  local normalized_root probe_root canonical_probe parent
  normalized_root="$(realpath -m -- "$configured_root")" || {
    err "Cannot canonicalize the WSL2 data root: $configured_root"
    exit 1
  }
  if [ -e "$normalized_root" ] && [ ! -d "$normalized_root" ]; then
    err "Data root must be a directory: $normalized_root"
    exit 1
  fi

  probe_root="$normalized_root"
  while [ ! -e "$probe_root" ]; do
    parent="$(dirname -- "$probe_root")"
    [ "$parent" != "$probe_root" ] || {
      err "Cannot resolve an existing ancestor for the WSL2 data root: $normalized_root"
      exit 1
    }
    probe_root="$parent"
  done
  canonical_probe="$(realpath -e -- "$probe_root")" || {
    err "Cannot canonicalize the WSL2 data root ancestor: $probe_root"
    exit 1
  }

  local probe_fd mount_id
  if ! exec {probe_fd}< "$canonical_probe"; then
    err "Cannot open the WSL2 data root ancestor for mount verification: $canonical_probe"
    exit 1
  fi
  mount_id="$(awk '$1 == "mnt_id:" { print $2; exit }' "/proc/self/fdinfo/$probe_fd")"
  exec {probe_fd}<&-
  [[ "$mount_id" =~ ^[0-9]+$ ]] || {
    err "Cannot resolve the effective WSL2 mount ID for data root: $normalized_root"
    exit 1
  }

  local line before_separator after_separator raw_mount_point mount_point
  local filesystem_type
  local selected_mount_point="" selected_filesystem_type=""
  local -a before_fields after_fields
  while IFS= read -r line; do
    before_separator="${line%% - *}"
    after_separator="${line#* - }"
    [ "$before_separator" != "$line" ] || continue
    read -r -a before_fields <<< "$before_separator"
    read -r -a after_fields <<< "$after_separator"
    [ "${#before_fields[@]}" -ge 5 ] || continue
    [ "${#after_fields[@]}" -ge 3 ] || continue
    [ "${before_fields[0]}" = "$mount_id" ] || continue

    raw_mount_point="${before_fields[4]}"
    mount_point="$(decode_mountinfo_path "$raw_mount_point")"
    filesystem_type="${after_fields[0]}"
    if [ "$mount_point" = "/" ] || [ "$canonical_probe" = "$mount_point" ] ||
      [[ "$canonical_probe" == "$mount_point/"* ]]; then
      selected_mount_point="$mount_point"
      selected_filesystem_type="$filesystem_type"
      break
    fi
  done < /proc/self/mountinfo

  [ -n "$selected_mount_point" ] || {
    err "Cannot identify the WSL2 mount for data root: $normalized_root"
    exit 1
  }

  case "${selected_filesystem_type,,}" in
    drvfs|9p|plan9|virtio-plan9|virtiofs)
      err "Rikune Analyzer data roots must use the WSL2 Linux filesystem; Windows-mounted DrvFS transport $selected_mount_point ($selected_filesystem_type) is unsupported."
      err "Choose a path such as /home/<user>/.rikune, not /mnt/<drive>/..."
      exit 1
      ;;
  esac
}

DATA_ROOT="${RIKUNE_DATA_ROOT:-$HOME/.rikune}"
RUNTIME_MODE="${RUNTIME_MODE:-disabled}"
ANALYZER_API_KEY="${RIKUNE_API_KEY:-${RIKUNE_ANALYZER_API_KEY:-}}"
export -n ANALYZER_API_KEY 2>/dev/null || true
unset RIKUNE_API_KEY RIKUNE_ANALYZER_API_KEY RIKUNE_STAGE_LOCAL_ENV_PATH \
  RIKUNE_LOCAL_EXISTING_ENV_BASE64 RIKUNE_LOCAL_ENV_PATH RIKUNE_LOCAL_ENV_FORCE_KEYS \
  RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN RIKUNE_VERIFY_PRIVATE_ENV_PATH \
  RIKUNE_STAGE_DOCKER_ENV_PATH RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH \
  RIKUNE_RESTORE_PRIVATE_ENV_PATH RIKUNE_REMOVE_PRIVATE_ENV_PATH \
  RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN RIKUNE_DOCKER_ENV_PATH \
  RIKUNE_DOCKER_ENV_DATA_ROOT RIKUNE_DOCKER_ENV_PROFILE RIKUNE_BUILD_HTTP_PROXY \
  RIKUNE_BUILD_HTTPS_PROXY RIKUNE_BUILD_NO_PROXY RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP \
  RIKUNE_PRIVATE_ENV_PATH RIKUNE_PRIVATE_ENV_ACL_MODE STAGED_LOCAL_ENV_BASE64 \
  RUNTIME_HOST_AGENT_ENDPOINT RUNTIME_HOST_AGENT_API_KEY HOST_AGENT_API_KEY \
  HOST_AGENT_RUNTIME_API_KEY RUNTIME_API_KEY RIKUNE_HOST_AGENT_API_KEY \
  RIKUNE_RUNTIME_API_KEY RIKUNE_RUNTIME_NODE_API_KEY
SCRIPT_DIRECTORY="${BASH_SOURCE[0]%/*}"
[ "$SCRIPT_DIRECTORY" != "${BASH_SOURCE[0]}" ] || SCRIPT_DIRECTORY="."
PROJECT_ROOT="$(cd "$SCRIPT_DIRECTORY" && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"
LOCAL_ENV_WRITER="$PROJECT_ROOT/scripts/write-local-runtime-env.mjs"
PRIVATE_ENV_WRITER="$PROJECT_ROOT/scripts/write-docker-runtime-env.mjs"
PRIVATE_ENV_SNAPSHOT=""
PRIVATE_ENV_TRANSACTION_ACTIVE=false
PRIVATE_ENV_TRANSACTION_COMMITTED=false

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
      err "Failed to restore the protected environment file after installer failure."
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
  PRIVATE_ENV_SNAPSHOT="$(RIKUNE_STAGE_LOCAL_ENV_PATH="$ENV_FILE" node "$LOCAL_ENV_WRITER")"
  export -n PRIVATE_ENV_SNAPSHOT 2>/dev/null || true
  PRIVATE_ENV_TRANSACTION_ACTIVE=true
  trap 'rollback_private_env_transaction "$?"' EXIT
  trap 'interrupt_private_env_transaction INT' INT
  trap 'interrupt_private_env_transaction TERM' TERM
  printf '%s' "$PRIVATE_ENV_SNAPSHOT" |
    RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH="$ENV_FILE" node "$PRIVATE_ENV_WRITER"
}

commit_private_env_transaction() {
  PRIVATE_ENV_TRANSACTION_COMMITTED=true
  PRIVATE_ENV_SNAPSHOT=""
  trap - EXIT INT TERM
}
if [ -n "$ANALYZER_API_KEY" ] && ! printf '%s\n' "$ANALYZER_API_KEY" | LC_ALL=C grep -Eq '^[!-~]{32,}$'; then
  err "RIKUNE_API_KEY must contain at least 32 printable non-space ASCII characters"
  exit 1
fi

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -d DIR   Data root (default: $DATA_ROOT)
  -r MODE  Runtime mode: disabled, manual, remote-sandbox (default: $RUNTIME_MODE)
  -h       Show this help
EOF
  exit 1
}

while getopts ":d:r:h" opt; do
  case "$opt" in
    d) DATA_ROOT="$OPTARG" ;;
    r) RUNTIME_MODE="$OPTARG" ;;
    h|*) usage ;;
  esac
done

case "$RUNTIME_MODE" in
  disabled|manual|remote-sandbox) ;;
  auto-sandbox)
    err "RUNTIME_MODE=auto-sandbox has no supported v1.4.0 topology. Use remote-sandbox with a Windows Host Agent."
    exit 1
    ;;
  *)
    err "Invalid runtime mode: $RUNTIME_MODE"
    usage
    ;;
esac

header "Rikune — Local Install (No Docker)"

echo "This script will:"
echo "  1. Check Node.js & Python"
echo "  2. Install npm dependencies & build"
echo "  3. Set up Python virtual environment"
echo "  4. Create data directories"
echo "  5. Check optional analysis tools"
echo "  6. Write NODE_ROLE=analyzer and RUNTIME_MODE=$RUNTIME_MODE"
echo ""
printf "Continue? (Y/n) "
read -r ans
[ "$ans" = "n" ] || [ "$ans" = "N" ] && { warn "Cancelled"; exit 0; }

# ─────────────────────────────────────────────────────────────────────────────
# 1. Required Tools
# ─────────────────────────────────────────────────────────────────────────────
step "Checking Required Tools"

[ "$(uname -s)" = "Linux" ] || {
  err "This installer requires Linux; no hashed macOS Python production lock is available."
  exit 1
}
case "$(uname -m)" in
  x86_64|amd64) ;;
  *)
    err "This installer requires Linux x86_64; the repository Python locks target x86_64."
    exit 1
    ;;
esac

printf "\nData root directory [%s]: " "$DATA_ROOT"
read -r custom_root
[ -n "$custom_root" ] && DATA_ROOT="$custom_root"
command -v realpath >/dev/null 2>&1 || {
  err "realpath is required to resolve the data root before installation."
  exit 1
}
DATA_ROOT="$(realpath -m -- "$DATA_ROOT")" || {
  err "Cannot canonicalize the data root: $DATA_ROOT"
  exit 1
}
assert_supported_wsl_data_root "$DATA_ROOT"
ok "Data root: $DATA_ROOT"

command -v node >/dev/null 2>&1 || { err "Node.js not found. Install 22.9+: https://nodejs.org/"; exit 1; }
NODE_VER=$(node --version)
NODE_VERSION_CORE=${NODE_VER#v}
NODE_MAJOR=${NODE_VERSION_CORE%%.*}
NODE_MINOR=${NODE_VERSION_CORE#*.}; NODE_MINOR=${NODE_MINOR%%.*}
if [ "$NODE_MAJOR" -lt 22 ] || { [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -lt 9 ]; }; then
  err "Node.js $NODE_VER too old (need 22.9+)"
  exit 1
fi
ok "Node.js: $NODE_VER"

command -v npm >/dev/null 2>&1 || { err "npm not found"; exit 1; }
ok "npm: $(npm --version)"

[ -f "$LOCAL_ENV_WRITER" ] || { err "Secure local environment writer not found: $LOCAL_ENV_WRITER"; exit 1; }
[ -f "$PRIVATE_ENV_WRITER" ] || { err "Secure private environment writer not found: $PRIVATE_ENV_WRITER"; exit 1; }
begin_private_env_transaction

PYTHON_CMD=""
for cmd in python3.12 python3 python; do
  if command -v "$cmd" >/dev/null 2>&1; then
    if "$cmd" -c "import struct, sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8 else 1)" 2>/dev/null; then
      PYTHON_CMD="$cmd"
      break
    fi
  fi
done
[ -n "$PYTHON_CMD" ] || { err "CPython 3.12 x86_64 not found. Install: https://www.python.org/downloads/"; exit 1; }
PY_VER=$("$PYTHON_CMD" --version)
ok "Python: $PY_VER (command: $PYTHON_CMD)"

# ─────────────────────────────────────────────────────────────────────────────
# 2. lockfile npm install & build
# ─────────────────────────────────────────────────────────────────────────────
step "Installing npm Dependencies & Building"

cd "$PROJECT_ROOT"
info "Running npm ci --include=dev..."
npm ci --include=dev --silent 2>&1
ok "npm dependencies installed from package-lock.json"

info "Building TypeScript..."
npm run build --silent 2>&1
ok "Project built (dist/ ready)"

# ─────────────────────────────────────────────────────────────────────────────
# 3. Python virtual environment
# ─────────────────────────────────────────────────────────────────────────────
step "Setting Up Python Virtual Environment"

WORKERS_DIR="$PROJECT_ROOT/workers"
VENV_DIR="$WORKERS_DIR/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
BASE_REQUIREMENTS_LOCK="$PROJECT_ROOT/requirements.lock.txt"
DYNAMIC_REQUIREMENTS_LOCK="$WORKERS_DIR/requirements-dynamic.lock.txt"
ANGR_REQUIREMENTS_LOCK="$PROJECT_ROOT/src/plugins/angr/requirements.lock.txt"
[ -f "$BASE_REQUIREMENTS_LOCK" ] || { err "Linux base Python lock not found: $BASE_REQUIREMENTS_LOCK"; exit 1; }

if [ ! -d "$VENV_DIR" ]; then
  info "Creating virtual environment..."
  "$PYTHON_CMD" -m venv "$VENV_DIR"
  ok "Virtual environment created: $VENV_DIR"
else
  ok "Virtual environment exists: $VENV_DIR"
fi

[ -x "$VENV_PYTHON" ] || { err "Python venv executable not found: $VENV_PYTHON"; exit 1; }
"$VENV_PYTHON" -c "import struct, sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8 else 1)" 2>/dev/null || {
  err "Existing Python venv must use CPython 3.12 x86_64. Remove $VENV_DIR and rerun."
  exit 1
}
"$VENV_PYTHON" -m pip --version >/dev/null 2>&1 || {
  err "pip is unavailable in the CPython 3.12 virtual environment. Recreate $VENV_DIR."
  exit 1
}

info "Installing base Python requirements..."
"$VENV_PYTHON" -m pip install --disable-pip-version-check --require-hashes --requirement "$BASE_REQUIREMENTS_LOCK" -q 2>&1
ok "Base Python requirements installed"

printf "\nInstall dynamic analysis packages? (frida, speakeasy, pandare) (Y/n) "
read -r ans
if [ "$ans" != "n" ] && [ "$ans" != "N" ]; then
  info "Installing dynamic packages..."
  [ -f "$DYNAMIC_REQUIREMENTS_LOCK" ] || { err "Linux dynamic Python lock not found: $DYNAMIC_REQUIREMENTS_LOCK"; exit 1; }
  "$VENV_PYTHON" -m pip install --disable-pip-version-check --require-hashes --requirement "$DYNAMIC_REQUIREMENTS_LOCK" -q 2>&1
  ok "Dynamic analysis packages installed"
fi

warn "Qiling installation is disabled: no hashed Linux production lock is available."

printf "\nInstall angr symbolic execution? (y/N) "
read -r ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  ANGR_VENV="$PROJECT_ROOT/angr-venv"
  ANGR_PYTHON="$ANGR_VENV/bin/python"
  [ -f "$ANGR_REQUIREMENTS_LOCK" ] || { err "Linux angr Python lock not found: $ANGR_REQUIREMENTS_LOCK"; exit 1; }
  [ -d "$ANGR_VENV" ] || "$PYTHON_CMD" -m venv "$ANGR_VENV"
  [ -x "$ANGR_PYTHON" ] || { err "angr venv Python executable not found: $ANGR_PYTHON"; exit 1; }
  "$ANGR_PYTHON" -c "import struct, sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8 else 1)" 2>/dev/null || {
    err "Existing angr venv must use CPython 3.12 x86_64. Remove $ANGR_VENV and rerun."
    exit 1
  }
  "$ANGR_PYTHON" -m pip --version >/dev/null 2>&1 || { err "pip is unavailable in the angr venv."; exit 1; }
  "$ANGR_PYTHON" -m pip install --disable-pip-version-check --require-hashes --requirement "$ANGR_REQUIREMENTS_LOCK" -q 2>&1
  ok "angr installed: $ANGR_VENV"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. Data directories
# ─────────────────────────────────────────────────────────────────────────────
step "Creating Data Directories"

for dir in workspaces data cache ghidra-projects ghidra-logs logs storage samples; do
  mkdir -p "$DATA_ROOT/$dir"
done
ok "Directories created"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Optional tools check
# ─────────────────────────────────────────────────────────────────────────────
step "Checking Optional Analysis Tools"

check_tool() {
  local name="$1" cmd="$2" desc="$4"
  if command -v "$cmd" >/dev/null 2>&1; then
    printf "  [${C_GREEN}OK${C_RESET}]  %s (%s)\n" "$name" "$(command -v "$cmd")"
    return 0
  else
    printf "  [${C_YELLOW}--${C_RESET}]  %s — %s\n" "$name" "$desc"
    return 1
  fi
}

FOUND=0; MISSING=0
check_tool "Ghidra"       "analyzeHeadless" "https://ghidra-sre.org/"            "Decompilation & analysis"        && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "Java 21+"     "java"            "https://adoptium.net/"              "Required by Ghidra"              && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "Rizin"        "rizin"           "https://rizin.re/"                  "Binary disassembly"              && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "capa"         "capa"            "https://github.com/mandiant/capa"   "Capability detection"            && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "UPX"          "upx"             "https://upx.github.io/"             "Unpacking executables"           && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "JADX"         "jadx"            "https://github.com/skylot/jadx"     "APK/DEX decompilation"           && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "Graphviz"     "dot"             "https://graphviz.org/"              "Graph visualization"             && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "Wine"         "wine"            "https://www.winehq.org/"            "Windows PE execution"            && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "RetDec"       "retdec-decompiler" "https://github.com/avast/retdec"  "Retargetable decompiler"         && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "Frida"        "frida"           "https://frida.re/"                  "Dynamic instrumentation"         && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "GDB"          "gdb"             "https://www.sourceware.org/gdb/"    "Debug sessions"                  && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))
check_tool "Volatility3"  "vol"             "https://github.com/volatilityfoundation/volatility3" "Memory forensics" && FOUND=$((FOUND+1)) || MISSING=$((MISSING+1))

echo ""
ok "$FOUND found, $MISSING optional tools not installed"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Generate .env
# ─────────────────────────────────────────────────────────────────────────────
step "Generating Environment Configuration"

RIKUNE_LOCAL_ENV_PATH="$ENV_FILE" \
RIKUNE_LOCAL_ENV_FORCE_KEYS="NODE_ROLE,RUNTIME_MODE,WORKSPACE_ROOT,DB_PATH,CACHE_ROOT,AUDIT_LOG_PATH,LOG_LEVEL,SANDBOX_PYTHON_PATH,API_ENABLED,API_PORT,API_STORAGE_ROOT" \
RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN=1 \
RIKUNE_API_KEY="$ANALYZER_API_KEY" \
  node "$LOCAL_ENV_WRITER" <<EOF
$PRIVATE_ENV_SNAPSHOT
# Rikune Local Environment — generated by install-local.sh
NODE_ROLE=analyzer
RUNTIME_MODE=$RUNTIME_MODE
WORKSPACE_ROOT=$DATA_ROOT/workspaces
DB_PATH=$DATA_ROOT/data/database.db
CACHE_ROOT=$DATA_ROOT/cache
AUDIT_LOG_PATH=$DATA_ROOT/logs/audit.log
LOG_LEVEL=info
SANDBOX_PYTHON_PATH=$VENV_PYTHON
API_ENABLED=true
API_PORT=18080
API_STORAGE_ROOT=$DATA_ROOT/storage
API_KEY=__RIKUNE_CSPRNG_API_KEY__

# Ghidra (uncomment and set if installed)
# GHIDRA_INSTALL_DIR=/opt/ghidra
# GHIDRA_PROJECT_ROOT=$DATA_ROOT/ghidra-projects
# GHIDRA_LOG_ROOT=$DATA_ROOT/ghidra-logs

# Optional tools (uncomment and set paths)
# RIZIN_PATH=/usr/bin/rizin
# CAPA_PATH=/usr/local/bin/capa
# CAPA_RULES_PATH=/opt/capa-rules
# UPX_PATH=/usr/local/bin/upx
# JADX_PATH=/opt/jadx/bin/jadx
# RETDEC_PATH=/opt/retdec/bin/retdec-decompiler
# GRAPHVIZ_DOT_PATH=/usr/bin/dot
# ANGR_PYTHON=$PROJECT_ROOT/angr-venv/bin/python
# QILING_PYTHON=$PROJECT_ROOT/qiling-venv/bin/python
EOF
commit_private_env_transaction
ANALYZER_API_KEY=""

ok "Protected environment file: $ENV_FILE (mode 0600)"
info "Edit .env to set paths to your locally installed tools"

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
header "Installation Complete"

echo "  Data Root:    $DATA_ROOT"
echo "  Project Root: $PROJECT_ROOT"
echo "  Python venv:  $VENV_DIR"
echo "  Env File:     $ENV_FILE"
echo "  Runtime Mode: $RUNTIME_MODE"
echo ""
echo "  Quick Start:"
echo "    cd $PROJECT_ROOT"
echo "    node --env-file=.env dist/index.js"
echo ""
echo "  Or with npm:"
echo "    npm start"
echo ""
echo "  Development:"
echo "    npm run dev      # watch mode"
echo "    npm test         # run tests"
echo ""
echo "  To add optional tools later:"
echo "    1. Install the tool (apt, brew, or download)"
echo "    2. Set the env var in .env"
echo "    3. Restart Rikune — it auto-detects via plugin systemDeps"
echo ""
