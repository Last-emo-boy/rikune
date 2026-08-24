#!/bin/bash
# =============================================================================
# Docker Entrypoint Script for Rikune
# =============================================================================
# This script handles container initialization:
# 1. Validate required environment variables
# 2. Create necessary directories
# 3. Set permissions
# 4. Start MCP Server
# =============================================================================

set -e

# Disable colors for MCP stdio compatibility
RED=''
GREEN=''
YELLOW=''
NC=''

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

RUNNING_UID="$(id -u 2>/dev/null || echo 0)"

is_root() {
    [ "$RUNNING_UID" = "0" ]
}

# Check if an environment variable is set
check_env() {
    local var_name=$1
    local var_value="${!var_name}"
    
    if [ -z "$var_value" ]; then
        log_error "Environment variable $var_name is not set"
        exit 1
    fi
    
    log_info "$var_name=$var_value"
}

check_optional_command() {
    local label=$1
    local command_name=$2
    local version_args=${3:---version}

    if command -v "$command_name" >/dev/null 2>&1; then
        local version_output
        version_output=$("$command_name" "$version_args" 2>&1 | head -n 1 || true)
        if [ -n "$version_output" ]; then
            log_info "$label available: $version_output"
        else
            log_info "$label available at $(command -v "$command_name")"
        fi
    else
        log_warn "$label is not available on PATH"
    fi
}

plugin_enabled() {
    local plugin_name=$1
    case ",${PLUGINS:-}," in
        *,"$plugin_name",*) return 0 ;;
        *) return 1 ;;
    esac
}

require_ghidra() {
    plugin_enabled "ghidra"
}

validate_static_image_contract() {
    if ! node --input-type=module --eval '
        const { assertStaticImageStartupContract } = await import("file:///app/dist/core/static-profile-lock.js");
        assertStaticImageStartupContract();
    '; then
        log_error "Static image identity or lock validation failed"
        exit 1
    fi
}

# Check that a runtime directory is real and writable by the image user. The
# static image never changes ownership at startup: bind/named volumes must be
# provisioned for uid/gid 1000 by the operator.
ensure_dir() {
    local dir_path=$1

    if [ -L "$dir_path" ]; then
        log_error "Runtime directory must not be a symlink: $dir_path"
        return 1
    fi

    if [ ! -d "$dir_path" ]; then
        log_info "Creating directory: $dir_path"
        if ! mkdir -p "$dir_path"; then
            log_error "Could not create runtime directory: $dir_path"
            return 1
        fi
    fi

    if [ ! -x "$dir_path" ]; then
        log_error "Runtime directory is not writable by uid $RUNNING_UID: $dir_path"
        return 1
    fi

    # `test -w` can report a mode-bit answer that does not reflect a read-only
    # container mount. Prove actual create+unlink capability instead.
    local write_probe="$dir_path/.rikune-write-probe.$$"
    if ! (set -C; : > "$write_probe") 2>/dev/null; then
        log_error "Runtime directory failed its real write probe: $dir_path"
        return 1
    fi
    if ! rm -f -- "$write_probe"; then
        log_error "Runtime directory failed its write-probe cleanup: $dir_path"
        return 1
    fi
}

ensure_optional_dir() {
    local dir_path=$1
    if ! ensure_dir "$dir_path"; then
        log_warn "Could not create optional directory: $dir_path"
        return 0
    fi
}

require_readonly_input_dir() {
    local dir_path=$1

    if [ -L "$dir_path" ] || [ ! -d "$dir_path" ] || [ ! -r "$dir_path" ] || [ ! -x "$dir_path" ]; then
        log_error "Input directory must be a readable, non-symlink directory: $dir_path"
        return 1
    fi
}

# =============================================================================
# Step 1: Validate Environment Variables
# =============================================================================

log_info "=== Validating Environment Variables ==="

# A baked static marker cannot be disabled with `docker run -e`. Validate the
# exact lock, plugin list, stage allowlist, and disabled runtime before doing
# any mutable filesystem initialization or forwarding an alternate command.
validate_static_image_contract

check_env WORKSPACE_ROOT
check_env DB_PATH
check_env CACHE_ROOT

if require_ghidra; then
    check_env GHIDRA_INSTALL_DIR
else
    if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
        log_info "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
    else
        log_info "GHIDRA_INSTALL_DIR is not set; Ghidra plugin is not enabled for this profile"
    fi
fi

if require_ghidra; then
    check_env JAVA_HOME
else
    if [ -n "${JAVA_HOME:-}" ]; then
        log_info "JAVA_HOME=$JAVA_HOME"
    else
        log_info "JAVA_HOME is not set; Ghidra plugin is not enabled for this profile"
    fi
fi

# Optional variables (log if set)
if [ -n "$GHIDRA_PROJECT_ROOT" ]; then
    log_info "GHIDRA_PROJECT_ROOT=$GHIDRA_PROJECT_ROOT"
fi

if [ -n "$GHIDRA_LOG_ROOT" ]; then
    log_info "GHIDRA_LOG_ROOT=$GHIDRA_LOG_ROOT"
fi

# =============================================================================
# Step 2: Verify Tool Availability
# =============================================================================

log_info "=== Verifying Tool Availability ==="

# Check Node.js
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    log_info "Node.js available: $NODE_VERSION"
else
    log_error "Node.js is not installed"
    exit 1
fi

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    log_info "Python available: $PYTHON_VERSION"
else
    log_error "Python 3 is not installed"
    exit 1
fi

# Check Java. Required for Ghidra profiles, optional otherwise.
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1)
    log_info "Java available: $JAVA_VERSION"
elif require_ghidra; then
    log_error "Java is not installed"
    exit 1
else
    log_warn "Java is not available on PATH; Ghidra plugin is disabled for this profile"
fi

# Check Ghidra analyzeHeadless. Required only when the ghidra plugin is enabled.
if require_ghidra && [ -f "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]; then
    log_info "Ghidra analyzeHeadless found at: $GHIDRA_INSTALL_DIR/support/analyzeHeadless"
elif require_ghidra; then
    log_error "Ghidra plugin is enabled but analyzeHeadless was not found at: $GHIDRA_INSTALL_DIR/support/analyzeHeadless"
    exit 1
else
    log_info "Ghidra plugin is disabled for this profile; skipping analyzeHeadless check"
fi

check_optional_command "Graphviz dot" "${GRAPHVIZ_DOT_PATH:-dot}" "-V"
check_optional_command "Rizin" "${RIZIN_PATH:-rizin}" "-v"
check_optional_command "UPX" "${UPX_PATH:-upx}" "--version"
if [ "${RUNTIME_MODE:-disabled}" = "remote-sandbox" ]; then
    log_info "Wine delegated to remote runtime"
else
    check_optional_command "Wine" "${WINE_PATH:-wine}" "--version"
fi
check_optional_command "RetDec" "${RETDEC_PATH:-retdec-decompiler}" "--help"

if [ "${RUNTIME_MODE:-disabled}" = "remote-sandbox" ]; then
    log_info "Frida CLI delegated to remote runtime"
elif command -v frida-ps >/dev/null 2>&1; then
    log_info "Frida CLI available: $(frida-ps --help 2>&1 | head -n 1 || true)"
else
    log_warn "Frida CLI is not available on PATH"
fi

if [ -x "${ANGR_PYTHON:-}" ]; then
    log_info "angr runtime available at ${ANGR_PYTHON}"
else
    log_warn "ANGR_PYTHON is not executable: ${ANGR_PYTHON:-unset}"
fi

if [ "${RUNTIME_MODE:-disabled}" = "remote-sandbox" ]; then
    log_info "Qiling runtime delegated to remote runtime"
elif [ -x "${QILING_PYTHON:-}" ]; then
    log_info "Qiling runtime available at ${QILING_PYTHON}"
else
    log_warn "QILING_PYTHON is not executable: ${QILING_PYTHON:-unset}"
fi

if [ "${RUNTIME_MODE:-disabled}" = "remote-sandbox" ]; then
    log_info "PANDA runtime delegated to remote runtime"
elif [ -x "${PANDA_PYTHON:-}" ]; then
    log_info "PANDA runtime available at ${PANDA_PYTHON}"
else
    log_warn "PANDA_PYTHON is not executable: ${PANDA_PYTHON:-unset}"
fi

# =============================================================================
# Step 3: Create Runtime Directories
# =============================================================================

log_info "=== Creating Runtime Directories ==="

# Create directories (will be mounted as volumes or created if not mounted)
ensure_dir "$WORKSPACE_ROOT"
ensure_dir "$(dirname "$DB_PATH")"
ensure_dir "$CACHE_ROOT"
if [ -n "$HOME" ]; then
    ensure_dir "$HOME"
    ensure_dir "$HOME/.rikune"
    ensure_dir "$HOME/.cache"
fi
ensure_dir "/app/logs"
if [ -n "$XDG_CONFIG_HOME" ]; then
    ensure_dir "$XDG_CONFIG_HOME"
fi
if [ -n "$XDG_CACHE_HOME" ]; then
    ensure_dir "$XDG_CACHE_HOME"
fi
ensure_dir "/ghidra-projects"
ensure_dir "/ghidra-logs"
require_readonly_input_dir "/samples"
if [ -n "${QILING_ROOTFS:-}" ]; then
    ensure_optional_dir "$QILING_ROOTFS"
else
    log_warn "QILING_ROOTFS is not set; skipping Qiling rootfs directory creation"
fi
ensure_dir "/tmp"

# Ensure database directory exists
DB_DIR=$(dirname "$DB_PATH")
if [ ! -d "$DB_DIR" ]; then
    log_info "Creating database directory: $DB_DIR"
    mkdir -p "$DB_DIR"
fi

# =============================================================================
# Step 4: Set Permissions
# =============================================================================

log_info "=== Verifying Runtime Identity ==="
if [ -f /app/.rikune-static-profile ] && [ "$RUNNING_UID" = "0" ]; then
    log_error "The static runtime must not start as root"
    exit 1
fi

# =============================================================================
# Step 5: Pre-flight Checks
# =============================================================================

log_info "=== Running Pre-flight Checks ==="

# Check if dist/index.js exists
if [ ! -f "/app/dist/index.js" ]; then
    log_error "MCP Server entry point not found: /app/dist/index.js"
    log_error "Make sure the Docker image was built correctly with 'npm run build'"
    exit 1
fi

# Check if workers/static_worker.py exists and is valid
if [ -f "/app/workers/static_worker.py" ]; then
    log_info "Validating Python worker syntax..."
    if PYTHONPYCACHEPREFIX=/tmp/rikune-pycache python3 -m py_compile /app/workers/static_worker.py 2>/dev/null; then
        log_info "Python worker syntax OK"
    else
        log_warn "Python worker syntax check failed, but continuing..."
    fi
fi

# Check if node_modules exists
if [ ! -d "/app/node_modules" ]; then
    log_error "node_modules not found. Docker image build may have failed."
    exit 1
fi

# =============================================================================
# Step 6: Display Configuration Summary
# =============================================================================

log_info "=== Configuration Summary ==="
log_info "Workspace Root:    $WORKSPACE_ROOT"
log_info "Database Path:     $DB_PATH"
log_info "Cache Root:        $CACHE_ROOT"
log_info "Ghidra Install:    $GHIDRA_INSTALL_DIR"
log_info "Ghidra Projects:   ${GHIDRA_PROJECT_ROOT:-/ghidra-projects}"
log_info "Ghidra Logs:       ${GHIDRA_LOG_ROOT:-/ghidra-logs}"
log_info "Graphviz Dot:      ${GRAPHVIZ_DOT_PATH:-dot}"
log_info "Rizin:             ${RIZIN_PATH:-rizin}"
log_info "UPX:               ${UPX_PATH:-upx}"
log_info "Wine:              ${WINE_PATH:-wine}"
log_info "winedbg:           ${WINEDBG_PATH:-winedbg}"
log_info "YARA-X Python:     ${YARAX_PYTHON:-python3}"
log_info "Qiling Python:     ${QILING_PYTHON:-python3}"
log_info "Qiling RootFS:     ${QILING_ROOTFS:-/opt/qiling-rootfs}"
log_info "angr Python:       ${ANGR_PYTHON:-unset}"
log_info "PANDA Python:      ${PANDA_PYTHON:-python3}"
log_info "RetDec:            ${RETDEC_PATH:-retdec-decompiler}"
log_info "Samples Root:      /samples"
log_info ""
log_info "Security:"
log_info "  - Running as user: $(whoami)"
log_info "  - Network:         ${NETWORK_MODE:-none (default)}"
log_info "  - Root filesystem: ${READ_ONLY_MODE:-read-only (recommended)}"
log_info ""

# =============================================================================
# Step 7: Start requested command
# =============================================================================

if [ "$#" -eq 0 ]; then
    set -- node dist/index.js
fi

log_info "=== Starting Container Command ==="
log_info ""

# Docker's CMD supplies the MCP server command by default. Forward explicit
# arguments so `docker run IMAGE <command>` works for diagnostics and tooling.
# Use exec so the requested process becomes PID 1 and receives signals directly.
exec "$@"
