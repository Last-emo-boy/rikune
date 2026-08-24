#!/usr/bin/env bash
# Reproducible development setup for Linux x86_64.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/workers/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
REQUIREMENTS_LOCK="$PROJECT_ROOT/requirements.lock.txt"

secret_environment_names=(
  RIKUNE_API_KEY
  RIKUNE_ANALYZER_API_KEY
  RUNTIME_HOST_AGENT_API_KEY
  HOST_AGENT_API_KEY
  HOST_AGENT_RUNTIME_API_KEY
  RUNTIME_API_KEY
  RIKUNE_HOST_AGENT_API_KEY
  RIKUNE_RUNTIME_API_KEY
  RIKUNE_RUNTIME_NODE_API_KEY
  ANALYZER_API_KEY
  STAGED_LOCAL_ENV_BASE64
  RIKUNE_LOCAL_EXISTING_ENV_BASE64
)
for name in "${secret_environment_names[@]}"; do
  unset "$name"
done

for private_env in .env .docker-runtime.env .env.runtime-windows; do
  if [ -e "$PROJECT_ROOT/$private_env" ] || [ -L "$PROJECT_ROOT/$private_env" ]; then
    printf 'Refusing dependency setup while private environment file exists: %s\n' "$PROJECT_ROOT/$private_env" >&2
    printf 'Move the protected file outside the repository or use the corresponding secure installer.\n' >&2
    exit 1
  fi
done

[ "$(uname -s)" = "Linux" ] || {
  printf 'This setup requires Linux; no hashed macOS Python lock is available.\n' >&2
  exit 1
}
case "$(uname -m)" in
  x86_64|amd64) ;;
  *)
    printf 'This setup requires Linux x86_64.\n' >&2
    exit 1
    ;;
esac

command -v node >/dev/null 2>&1 || { printf 'Node.js 22+ is required.\n' >&2; exit 1; }
node_major="$(node --version)"
node_major="${node_major#v}"
node_major="${node_major%%.*}"
[ "$node_major" -ge 22 ] || { printf 'Node.js 22+ is required.\n' >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { printf 'npm is required.\n' >&2; exit 1; }

python_command=""
for candidate in python3.12 python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 &&
    "$candidate" -c "import struct, sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8 else 1)" 2>/dev/null; then
    python_command="$candidate"
    break
  fi
done
[ -n "$python_command" ] || { printf 'CPython 3.12 x86_64 is required.\n' >&2; exit 1; }
[ -f "$REQUIREMENTS_LOCK" ] || { printf 'Python hash lock is missing: %s\n' "$REQUIREMENTS_LOCK" >&2; exit 1; }

cd "$PROJECT_ROOT"
printf 'Installing Node.js dependencies from package-lock.json...\n'
npm ci --include=dev

if [ ! -d "$VENV_DIR" ]; then
  "$python_command" -m venv "$VENV_DIR"
fi
[ -x "$VENV_PYTHON" ] || { printf 'Virtual environment Python is missing: %s\n' "$VENV_PYTHON" >&2; exit 1; }
"$VENV_PYTHON" -c "import struct, sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8 else 1)" || {
  printf 'Existing workers/venv must use CPython 3.12 x86_64.\n' >&2
  exit 1
}
"$VENV_PYTHON" -m pip --version >/dev/null
printf 'Installing Python dependencies from the hash lock...\n'
"$VENV_PYTHON" -m pip install --disable-pip-version-check --require-hashes --requirement "$REQUIREMENTS_LOCK"

printf 'Setup complete.\n'
