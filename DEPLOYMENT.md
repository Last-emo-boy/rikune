# Rikune Deployment Guide

Rikune can run as a static Analyzer, a hybrid Analyzer plus Windows runtime, a full Linux toolchain image, or a Windows-native process. Docker files are generated from templates and compiled plugin metadata; do not hand-edit generated compose files unless you intend to regenerate and reapply the change.

## Deployment Profiles

| Profile | Analyzer | Runtime | Dockerfile | Compose file | Container |
| --- | --- | --- | --- | --- | --- |
| `static` | Linux Docker | disabled | `docker/Dockerfile.analyzer` | `docker-compose.analyzer.yml` | `rikune-analyzer` |
| `hybrid` | Linux Docker | Windows Host Agent plus Sandbox or Hyper-V | `docker/Dockerfile.analyzer` | `docker-compose.hybrid.yml` | `rikune-analyzer` |
| `full` | Linux Docker full toolchain | disabled unless configured | `Dockerfile` | `docker-compose.yml` | `rikune` |
| Windows native | Windows Node process | local `auto-sandbox` possible | none | none | none |

Use `static` first unless you need live runtime evidence. Use `hybrid` when the Analyzer should stay in Docker but Windows execution must happen in an isolated Windows environment.

## Top-Level Scripts

Windows:

```powershell
.\rikune.ps1
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
.\rikune.ps1 install -Profile hybrid -InstallRuntime
.\rikune.ps1 status
.\rikune.ps1 logs
.\rikune.ps1 stop
```

Linux/macOS:

```bash
./rikune.sh
./rikune.sh install --profile static --data-root "$HOME/.rikune"
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
./rikune.sh status
./rikune.sh logs
./rikune.sh stop
```

Lower-level scripts remain available for automation:

- `install-docker.ps1`
- `install-runtime-windows.ps1`
- `install-local.ps1`
- `install-local.sh`

## Static Docker Analyzer

Static Docker is the default safe profile. It disables runtime execution and keeps analysis in the Analyzer container.

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

Manual equivalent:

```bash
RIKUNE_REMOVE_PRIVATE_ENV_PATH="$PWD/.docker-runtime.env" node scripts/write-docker-runtime-env.mjs
unset RIKUNE_API_KEY RIKUNE_ANALYZER_API_KEY RUNTIME_HOST_AGENT_API_KEY \
  HOST_AGENT_API_KEY HOST_AGENT_RUNTIME_API_KEY RUNTIME_API_KEY
npm ci --include=dev
npm run build
npm run docker:generate:all
RIKUNE_DOCKER_ENV_PATH="$PWD/.docker-runtime.env" \
RIKUNE_DOCKER_ENV_DATA_ROOT="${RIKUNE_DATA_ROOT:-$HOME/.rikune}" \
RIKUNE_DOCKER_ENV_PROFILE=static \
  node scripts/write-docker-runtime-env.mjs
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
```

Expected runtime configuration:

```env
RUNTIME_MODE=disabled
API_ENABLED=true
RIKUNE_API_KEY=<generated-secret>
RIKUNE_ANALYZER_API_KEY=<same-generated-secret>
PLUGINS=*
```

## Hybrid Docker + Windows Runtime

Hybrid mode keeps the Analyzer in Docker and delegates live execution to a Windows Host Agent. The Host Agent runs on Windows and can start Windows Sandbox on demand or control a named Hyper-V VM.

Important behavior:

- Starting the Analyzer does not launch Windows Sandbox.
- Connecting an MCP client does not run samples.
- `dynamic.runtime.status` and planning tools are passive.
- Live tools such as `runtime.debug.session.start`, `runtime.debug.command`, and `sandbox.execute` explicitly request runtime work.
- Docker/WSL analyzers must use `remote-sandbox`, not `auto-sandbox`.

### Same Windows Host

For a single Windows machine running Docker Desktop, Host Agent, and Windows Sandbox:

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime
```

The Host Agent must run in the logged-on user session for Windows Sandbox compatibility. It should not be installed as a traditional Windows service when the Sandbox backend is required.

### Remote Windows Host

For Linux/macOS Analyzer plus remote Windows runtime host:

```bash
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user> \
  --host-agent-endpoint https://runtime.example.internal
```

The script syncs the repository to Windows, runs the Windows runtime installer, generates compose files, writes a mode-`0600` `.docker-runtime.env`, and starts the Analyzer. The HTTPS endpoint should terminate at a trusted reverse proxy/VPN path to the loopback Host Agent. Direct plaintext HTTP requires `--allow-insecure-runtime-http` and is only supported as an explicit opt-in on an isolated trusted network. Provide strong runtime keys through a protected environment or hidden prompt, never through CLI arguments.

### Hyper-V Runtime

Hybrid can use a pre-provisioned Hyper-V VM. Configure the VM name and checkpoint policy through the installer or environment.

Common settings:

```env
RUNTIME_HOST_AGENT_BACKEND=hyperv-vm
RUNTIME_HOST_AGENT_ENDPOINT=http://host.docker.internal:18082
RUNTIME_HOST_AGENT_API_KEY=<host-agent-key>
RUNTIME_HYPERV_VM_NAME=rikune-runtime
RUNTIME_HYPERV_SNAPSHOT_NAME=clean-runtime
```

Release behavior is controlled by the runtime session request or Host Agent defaults. Supported policies include clean rollback, stop only, and preserve dirty state.

## Full Docker Image

The full profile builds the broad Linux toolchain image. It is heavier than `static` and still does not automatically provide safe Windows live execution.

```powershell
.\install-docker.ps1 -Profile full
```

```bash
docker compose --env-file .docker-runtime.env -f docker-compose.yml up -d --build mcp-server
```

Use this profile when you want the complete static and emulation-oriented Linux toolchain in one container.

## Windows Native + Auto Sandbox

Windows-native Analyzer can use `auto-sandbox`. In this mode the Analyzer launches Windows Sandbox locally and connects to the Runtime Node inside it.

Requirements:

- Windows Sandbox enabled.
- Interactive user session.
- Node.js 22+.
- Runtime bundle built with `npm run build:runtime`.
- Host has enough memory for Windows Sandbox.

Docker and WSL should not use `auto-sandbox` because Windows Sandbox launch and portproxy behavior must be controlled from Windows.

## Environment Variables

Common Analyzer variables:

| Variable | Purpose |
| --- | --- |
| `API_ENABLED` | Enable HTTP API/dashboard |
| `API_PORT` | HTTP API port, default commonly 18080 |
| `API_KEY` | Required Analyzer API key whenever the HTTP API is enabled |
| `PLUGINS` | Plugin filter |
| `RUNTIME_MODE` | `disabled`, `manual`, `remote-sandbox`, or `auto-sandbox` |
| `RUNTIME_ENDPOINT` | Manual Runtime Node endpoint |
| `RUNTIME_API_KEY` | Runtime Node API key |
| `RUNTIME_HOST_AGENT_ENDPOINT` | Windows Host Agent endpoint |
| `RUNTIME_HOST_AGENT_API_KEY` | Host Agent API key |
| `RIKUNE_DATA_ROOT` | Persistent Docker data root |
| `GHIDRA_INSTALL_DIR` | Ghidra install directory |
| `JAVA_HOME` | Java home for Ghidra |

Runtime and Host Agent keys must contain at least 32 printable non-space ASCII characters. Keep them in the installer-protected environment files (`0600` on POSIX; restricted ACL on Windows), rotate them after suspected exposure, and never transmit them over remote plaintext HTTP.

## MCP Client Configuration

For Docker Compose plus stdio:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": ["exec", "-i", "rikune-analyzer", "node", "dist/index.js"]
    }
  }
}
```

For local build:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "node",
      "args": ["D:/Playground/windows-exe-decompiler-mcp-server/dist/index.js"]
    }
  }
}
```

For the published CLI:

```bash
rikune
rikune docker-stdio
rikune agent
```

The Agent Gateway (`rikune agent`) can proxy Analyzer/runtime connections and expose connection-management tools.

## Health And Readiness

HTTP API endpoints:

| Endpoint | Meaning |
| --- | --- |
| `/api/v1/health` | Process and HTTP liveness |
| `/api/v1/ready` | Database, queue, runtime, and enabled-plugin readiness |
| `/api/v1/events` | SSE events |

MCP tools:

- `system.health`
- `system.setup.guide`
- `system.config.validate`
- `dynamic.runtime.status`
- `dynamic.toolkit.status`
- `tool.readiness`
- `plugin.list`

Readiness is profile-aware. Disabled plugins should not make a static deployment unhealthy.

## Dynamic Execution Semantics

Runtime-related tools should report whether a result came from:

- plan-only analysis;
- safe simulation;
- emulation;
- live Windows Sandbox;
- live Hyper-V;
- manual runtime.

Safe simulation is not live runtime evidence. Treat it as guidance or a fallback.

## Common Commands

Run `rikune.sh install`, `rikune.ps1 install`, or the secure env writer shown above before invoking Compose directly. The generated env file is secret material and must not be committed.

```bash
npm run docker:generate:all
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
docker compose --env-file .docker-runtime.env -f docker-compose.hybrid.yml up -d --build analyzer
docker compose --env-file .docker-runtime.env -f docker-compose.yml up -d --build mcp-server
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml logs -f analyzer
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml down
```

## Persistent Data

Docker installers write or consume `.docker-runtime.env` and map persistent data to `RIKUNE_DATA_ROOT`.

Typical host layout:

```text
<data-root>/
  samples/
  artifacts/
  uploads/
  cache/
  logs/
  rikune.db
  audit.jsonl
```

The Analyzer stores immutable originals and derived artifacts separately. Do not mount unknown sample directories over the application source tree.
