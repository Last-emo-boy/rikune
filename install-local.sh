#!/usr/bin/env bash
# =============================================================================
# Rikune — Local (Non-Docker) Install Script for Linux / macOS
# Requires: Node.js 22+, Python 3.11+, bash
# =============================================================================
set -euo pipefail

C_RESET="\033[0m"
C_CYAN="\033[36m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"
C_BOLD="\033[1m"

header()  { printf "\n${C_CYAN}==================================================${C_RESET}\n  ${C_CYAN}%s${C_RESET}\n${C_CYAN}==================================================${C_RESET}\n\n" "$1"; }
step()    { printf "\n${C_CYAN}[STEP] %s${C_RESET}\n${C_CYAN}-----------------------------------------${C_RESET}\n" "$1"; }
ok()      { printf "${C_GREEN}[OK]${C_RESET} %s\n" "$1"; }
warn()    { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$1"; }
err()     { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$1"; }
info()    { printf "  %s\n" "$1"; }

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
DATA_ROOT="${RIKUNE_DATA_ROOT:-$HOME/.rikune}"

header "Rikune — Local Install (No Docker)"

echo "This script will:"
echo "  1. Check Node.js & Python"
echo "  2. Install npm dependencies & build"
echo "  3. Set up Python virtual environment"
echo "  4. Create data directories"
echo "  5. Check optional analysis tools"
echo ""
printf "Continue? (Y/n) "
read -r ans
[ "$ans" = "n" ] || [ "$ans" = "N" ] && { warn "Cancelled"; exit 0; }

# ─────────────────────────────────────────────────────────────────────────────
# 1. Required Tools
# ─────────────────────────────────────────────────────────────────────────────
step "Checking Required Tools"

command -v node >/dev/null 2>&1 || { err "Node.js not found. Install 22+: https://nodejs.org/"; exit 1; }
NODE_VER=$(node --version)
NODE_MAJOR=${NODE_VER#v}; NODE_MAJOR=${NODE_MAJOR%%.*}
[ "$NODE_MAJOR" -ge 22 ] || { err "Node.js $NODE_VER too old (need 22+)"; exit 1; }
ok "Node.js: $NODE_VER"

command -v npm >/dev/null 2>&1 || { err "npm not found"; exit 1; }
ok "npm: $(npm --version)"

PYTHON_CMD=""
for cmd in python3 python; do
  if command -v "$cmd" >/dev/null 2>&1; then
    if "$cmd" -c "import sys; assert sys.version_info >= (3,11)" 2>/dev/null; then
      PYTHON_CMD="$cmd"
      break
    fi
  fi
done
[ -n "$PYTHON_CMD" ] || { err "Python 3.11+ not found. Install: https://www.python.org/downloads/"; exit 1; }
PY_VER=$($PYTHON_CMD --version)
ok "Python: $PY_VER (command: $PYTHON_CMD)"

# ─────────────────────────────────────────────────────────────────────────────
# 2. npm install & build
# ─────────────────────────────────────────────────────────────────────────────
step "Installing npm Dependencies & Building"

cd "$PROJECT_ROOT"
info "Running npm install..."
npm install --silent 2>&1
ok "npm dependencies installed"

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

if [ ! -d "$VENV_DIR" ]; then
  info "Creating virtual environment..."
  $PYTHON_CMD -m venv "$VENV_DIR"
  ok "Virtual environment created: $VENV_DIR"
else
  ok "Virtual environment exists: $VENV_DIR"
fi

info "Installing base Python requirements..."
"$VENV_PYTHON" -m pip install --upgrade pip -q 2>&1
"$VENV_PYTHON" -m pip install -r "$PROJECT_ROOT/requirements.txt" -q 2>&1
"$VENV_PYTHON" -m pip install -r "$WORKERS_DIR/requirements.txt" -q 2>&1
ok "Base Python requirements installed"

printf "\nInstall dynamic analysis packages? (frida, speakeasy, pandare) (Y/n) "
read -r ans
if [ "$ans" != "n" ] && [ "$ans" != "N" ]; then
  info "Installing dynamic packages..."
  "$VENV_PYTHON" -m pip install -r "$WORKERS_DIR/requirements-dynamic.txt" -q 2>&1 || warn "Some dynamic packages failed"
  ok "Dynamic analysis packages installed"
fi

printf "\nInstall Qiling emulation? (y/N) "
read -r ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  QILING_VENV="$PROJECT_ROOT/qiling-venv"
  [ -d "$QILING_VENV" ] || $PYTHON_CMD -m venv "$QILING_VENV"
  "$QILING_VENV/bin/python" -m pip install --upgrade pip -q 2>&1
  "$QILING_VENV/bin/python" -m pip install -r "$WORKERS_DIR/requirements-qiling.txt" -q 2>&1 || warn "Qiling failed"
  ok "Qiling installed: $QILING_VENV"
fi

printf "\nInstall angr symbolic execution? (y/N) "
read -r ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  ANGR_VENV="$PROJECT_ROOT/angr-venv"
  [ -d "$ANGR_VENV" ] || $PYTHON_CMD -m venv "$ANGR_VENV"
  "$ANGR_VENV/bin/python" -m pip install --upgrade pip -q 2>&1
  "$ANGR_VENV/bin/python" -m pip install angr -q 2>&1 || warn "angr failed"
  ok "angr installed: $ANGR_VENV"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. Data directories
# ─────────────────────────────────────────────────────────────────────────────
step "Creating Data Directories"

printf "\nData root directory [%s]: " "$DATA_ROOT"
read -r custom_root
[ -n "$custom_root" ] && DATA_ROOT="$custom_root"
ok "Data root: $DATA_ROOT"

for dir in workspaces data cache ghidra-projects ghidra-logs logs storage samples; do
  mkdir -p "$DATA_ROOT/$dir"
done
ok "Directories created"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Optional tools check
# ─────────────────────────────────────────────────────────────────────────────
step "Checking Optional Analysis Tools"

check_tool() {
  local name="$1" cmd="$2" url="$3" desc="$4"
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

ENV_FILE="$PROJECT_ROOT/.env"
cat > "$ENV_FILE" <<EOF
# Rikune Local Environment — generated by install-local.sh
WORKSPACE_ROOT=$DATA_ROOT/workspaces
DB_PATH=$DATA_ROOT/data/database.db
CACHE_ROOT=$DATA_ROOT/cache
AUDIT_LOG_PATH=$DATA_ROOT/logs/audit.log
LOG_LEVEL=info
SANDBOX_PYTHON_PATH=$VENV_PYTHON
API_ENABLED=true
API_PORT=18080
API_STORAGE_ROOT=$DATA_ROOT/storage
# API_KEY=your-secret-key-here

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

ok "Environment file: $ENV_FILE"
info "Edit .env to set paths to your locally installed tools"

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
header "Installation Complete"

echo "  Data Root:    $DATA_ROOT"
echo "  Project Root: $PROJECT_ROOT"
echo "  Python venv:  $VENV_DIR"
echo "  Env File:     $ENV_FILE"
echo ""
echo "  Quick Start:"
echo "    cd $PROJECT_ROOT"
echo "    node dist/index.js"
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
