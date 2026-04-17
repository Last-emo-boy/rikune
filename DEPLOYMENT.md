# Rikune Deployment Guide

Rikune now has three deployment profiles. The Docker files are generated from
compiled plugin metadata, not maintained by hand.

## Deployment Profiles

| Profile | Analyzer | Runtime | Dockerfile | Compose file | Container |
|---------|----------|---------|------------|--------------|-----------|
| `static` | Linux Docker | None | `docker/Dockerfile.analyzer` | `docker-compose.analyzer.yml` | `rikune-analyzer` |
| `hybrid` | Linux Docker | Windows Host Agent + Windows Sandbox | `docker/Dockerfile.analyzer` | `docker-compose.hybrid.yml` | `rikune-analyzer` |
| `full` | Linux Docker | None by default | `Dockerfile` | `docker-compose.yml` | `rikune` |
| Windows native | Windows process | Local Windows Sandbox | none | none | none |

Use `static` as the safe default. Use `hybrid` only when a Windows Host Agent is
available. Use `full` when you intentionally want the heavier all-in-one Linux
toolchain image.

## Top-Level Control Scripts

Normal users should start with the top-level scripts. They wrap installation,
start/stop, logs, health checks, status, and diagnostics.

```powershell
# Windows menu
.\rikune.ps1

# Windows single-host hybrid: Docker Desktop + Host Agent + Windows Sandbox
.\rikune.ps1 install -Profile hybrid -InstallRuntime -Service

# Status, logs, and stop
.\rikune.ps1 status -Profile hybrid
.\rikune.ps1 logs -Profile hybrid -Follow
.\rikune.ps1 stop -Profile hybrid
```

Windows menu choices:

| Choice | Action |
|--------|--------|
| `1` | Install the `static` Docker analyzer |
| `2` | Install `hybrid` on the same Windows host: Docker Desktop + Host Agent + Windows Sandbox |
| `3` | Install the `full` Docker image |
| `4` | Start the selected profile |
| `5` | Show Compose status and HTTP/runtime health |
| `6` | Show logs |
| `7` | Stop the selected profile |
| `8` | Run local diagnostics |
| `9` | Check Windows Host Agent / runtime health |

```bash
# Linux/macOS menu
./rikune.sh

# Linux analyzer + remote Windows Host Agent over SSH
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>

# Status, logs, and stop
./rikune.sh status --profile hybrid
./rikune.sh logs --profile hybrid --follow
./rikune.sh stop --profile hybrid
```

Lower-level scripts remain available for automation and advanced manual flows.

## Static Docker Analyzer

Static Docker is the default install path. It disables sample execution and only
runs static/offline analysis inside the container.

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

Manual equivalent:

```bash
npm install
npm run build
npm run docker:generate:static
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
```

The generated container uses:

- `NODE_ROLE=analyzer`
- `RUNTIME_MODE=disabled`
- `PLUGINS=<static-capable plugins>`
- persistent data under `RIKUNE_DATA_ROOT` (default `D:/Docker/rikune` on Windows install)

## Hybrid Docker + Windows Sandbox Runtime

Hybrid mode keeps analysis in Docker but delegates real Windows execution to a
Windows Host Agent, which can start Windows Sandbox on demand.

The important distinction is that install/start prepares the runtime plane; it
does not need to keep a Windows Sandbox window open. When an MCP tool requests a
dynamic/sandbox execution lane, the analyzer calls the Host Agent, the Host
Agent creates a fresh Sandbox session, the Runtime Node runs inside it, and the
resulting traces/artifacts are returned to the analyzer.

### Windows Runtime Side

Requirements:

- Windows 10/11 Pro or Enterprise
- Windows Sandbox feature enabled
- Node.js 22+
- Python 3.11+

Install the Host Agent:

```powershell
.\install-runtime-windows.ps1 -Headless -Service -ApiKey <host-agent-key>
```

The installer writes `.env.runtime-windows` with `HOST_AGENT_PORT`,
`HOST_AGENT_API_KEY`, and runtime-node defaults.

Open the Host Agent port if needed:

```powershell
netsh advfirewall firewall add rule name="RikuneHostAgent" dir=in action=allow protocol=tcp localport=18082
```

### Linux / Docker Analyzer Side

On Windows PowerShell with Docker Desktop and a local Windows runtime:

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime -Service
```

When connecting to an existing Host Agent endpoint:

```powershell
.\install-docker.ps1 -Profile hybrid `
  -HostAgentEndpoint http://<windows-host>:18082 `
  -HostAgentApiKey <host-agent-key>
```

On a Linux analyzer host:

```bash
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
```

The Linux script syncs the repo to Windows over SSH, runs the Windows runtime
installer, generates `docker-compose.hybrid.yml`, writes `.docker-runtime.env`,
and starts the analyzer.

Diagnostics:

```bash
./diagnose-hybrid.sh -w <windows-host> -u <windows-user>
```

Hybrid environment contract:

| Variable | Meaning |
|----------|---------|
| `RUNTIME_MODE=remote-sandbox` | Analyzer delegates runtime work to a Host Agent |
| `RUNTIME_HOST_AGENT_ENDPOINT` | Host Agent URL, usually `http://<windows-host>:18082` |
| `RUNTIME_HOST_AGENT_API_KEY` | Analyzer -> Host Agent control-plane key |
| `RUNTIME_API_KEY` | Analyzer -> Runtime Node key, only needed if the Runtime Node enforces separate auth |

## MCP Client Configuration

Docker deployments use a long-running analyzer container for the dashboard/API,
then MCP clients start a separate stdio process inside that same container with
`docker exec -i`. For `static` and `hybrid`, the container name is
`rikune-analyzer`; for `full`, it is `rikune`.

JSON-style clients:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "-e", "API_ENABLED=false",
        "-e", "NODE_ENV=production",
        "-e", "PYTHONUNBUFFERED=1",
        "rikune-analyzer",
        "node",
        "dist/index.js"
      ],
      "env": {
        "NODE_ENV": "production",
        "PYTHONUNBUFFERED": "1"
      },
      "timeout": 300000
    }
  }
}
```

Codex TOML:

```toml
[mcp_servers.rikune]
command = "docker"
startup_timeout_sec = 180
args = [
  "exec",
  "-i",
  "-e", "API_ENABLED=false",
  "-e", "NODE_ENV=production",
  "-e", "PYTHONUNBUFFERED=1",
  "rikune-analyzer",
  "node",
  "dist/index.js"
]

[mcp_servers.rikune.env]
NODE_ENV = "production"
PYTHONUNBUFFERED = "1"
```

`API_ENABLED=false` is intentional. It prevents the MCP stdio child process from
trying to bind the dashboard port that is already owned by the daemon process.
The dashboard remains available at `http://localhost:18080/dashboard`.
`startup_timeout_sec` should be at least 180 for Docker profiles because the
stdio child process loads the plugin graph and registers the full MCP surface on
startup.

## Full Docker Image

The full profile builds the heavier Linux image with the dynamic Linux-side
toolchain. It is useful for experiments and CI where the larger image is
acceptable.

```powershell
.\rikune.ps1 install -Profile full -DataRoot "D:\Docker\rikune"
```

Manual equivalent:

```bash
npm install
npm run build
npm run docker:generate
docker compose --env-file .docker-runtime.env -f docker-compose.yml up -d --build mcp-server
```

## Windows Native + Auto Sandbox

Use this when the analyzer runs directly on Windows and should start local
Windows Sandbox instances by itself.

```powershell
.\install-local.ps1 -RuntimeMode auto-sandbox
npm start
```

`auto-sandbox` is not valid inside Docker or WSL. Docker/WSL analyzers must use
`static` or `hybrid`.

## Common Commands

```bash
# Generate all Docker profiles
npm run docker:generate:all

# Build/start static analyzer
npm run docker:up:static

# Build/start full profile
npm run docker:up:full

# Build/start hybrid profile after .docker-runtime.env has Host Agent settings
npm run docker:up:hybrid

# Logs
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml logs -f analyzer

# Stop static analyzer
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml down
```

## Persistent Data

The Docker installer defaults to `D:\Docker\rikune` on Windows. The expected
layout is:

```text
D:\Docker\rikune\
  samples\
  workspaces\
  data\
  cache\
  logs\
  storage\
  ghidra-projects\
  ghidra-logs\
  qiling-rootfs\
  config\
```

Use `-ResetData` on `install-docker.ps1` only when you intentionally want to
delete and recreate the data root.
