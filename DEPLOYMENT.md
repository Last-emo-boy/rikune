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
