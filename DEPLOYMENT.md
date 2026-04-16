# Rikune Deployment Guide

This document covers three ways to deploy Rikune, from a single Windows machine to a fully distributed Linux-Analyzer + Windows-Runtime setup.

---

## Table of Contents

1. [Deployment Topologies](#deployment-topologies)
2. [Topology A: Windows Single Machine (Auto-Sandbox)](#topology-a-windows-single-machine-auto-sandbox)
3. [Topology B: Linux Docker Analyzer + Manual Windows VM](#topology-b-linux-docker-analyzer--manual-windows-vm)
4. [Topology C: Linux Docker Analyzer + Windows Host Agent (Recommended)](#topology-c-linux-docker-analyzer--windows-host-agent-recommended)
5. [Quick Reference](#quick-reference)

---

## Deployment Topologies

| Topology | Analyzer | Runtime | Complexity | Best For |
|----------|----------|---------|------------|----------|
| **A** | Windows native / WSL | Windows Sandbox on same host | Low | Local development, quick tests |
| **B** | Linux Docker | Manual Windows VM/Sandbox | Medium | Air-gapped labs, custom VM images |
| **C** | Linux Docker | Windows Host Agent auto-starts Sandbox | Low-Medium | **Production & daily use** |

---

## Topology A: Windows Single Machine (Auto-Sandbox)

**Use this when you want everything on one Windows PC.**

### Requirements
- Windows 10/11 **Pro or Enterprise** (Windows Sandbox is not available on Home)
- Windows Sandbox feature enabled
- Node.js 22+, Python 3.11+

### Steps

1. **Enable Windows Sandbox**
   ```powershell
   # Run as Administrator
   Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClient" -All
   # Restart if prompted
   ```

2. **Install Rikune locally**
   ```powershell
   git clone https://github.com/Last-emo-boy/rikune.git
   cd rikune
   .\install-local.ps1
   ```

3. **Enable Auto-Sandbox runtime**
   Edit `.env` in the project root:
   ```env
   NODE_ROLE=analyzer
   RUNTIME_MODE=auto-sandbox
   ```

4. **Start the server**
   ```powershell
   npm start
   ```

When you call a dynamic-analysis tool (e.g. `sandbox.execute`), Rikune will automatically start Windows Sandbox, run the sample, collect artifacts, and return the result.

---

## Topology B: Linux Docker Analyzer + Manual Windows VM

**Use this when you already have a dedicated Windows VM and want full manual control over when the Runtime starts.**

### Requirements
- Linux host with Docker installed
- Windows VM (or physical machine) with Windows Sandbox or equivalent isolation
- Network connectivity between the two machines

### Steps

#### On the Windows VM

1. Clone the repository and build the Runtime Node:
   ```powershell
   git clone https://github.com/Last-emo-boy/rikune.git
   cd rikune
   npm install
   npm run build:runtime
   npm run build:host-agent
   ```

2. Start the Runtime Node **inside** Windows Sandbox (or your isolated VM):
   ```powershell
   $env:ALLOW_UNSAFE_RUNTIME="true"   # only if NOT in Sandbox
   node packages/runtime-node/dist/index.js --host 0.0.0.0 --port 18081 --inbox C:\rikune-inbox --outbox C:\rikune-outbox
   ```

   > **Security warning:** If you run the Runtime Node directly on a Windows physical machine (not inside a VM/Sandbox), set `ALLOW_UNSAFE_RUNTIME=true` only for temporary development. In production, the Runtime must always be inside a virtual machine.

3. Note the VM's IP address:
   ```powershell
   (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { !$_.InterfaceAlias.Contains("Loopback") }).IPAddress
   ```

#### On the Linux host

4. Copy `.env.analyzer.example` to `.env` and configure:
   ```env
   NODE_ROLE=analyzer
   RUNTIME_MODE=manual
   RUNTIME_ENDPOINT=http://<windows-vm-ip>:18081
   RUNTIME_API_KEY=optional-api-key
   ```

5. Build and start the Analyzer container:
   ```bash
   docker build -t rikune:latest .
   docker compose -f docker-compose.hybrid.yml up -d
   ```

---

## Topology C: Linux Docker Analyzer + Windows Host Agent (Recommended)

**This is the recommended setup for daily use.** The Linux Analyzer automatically asks the Windows Host Agent to start/stop Windows Sandbox on demand.

### Architecture Overview

```
┌─────────────────────────────┐
│   Linux Host (Docker)       │
│  ┌───────────────────────┐  │
│  │   Rikune Analyzer     │  │
│  │   (MCP Server)        │  │
│  └──────────┬────────────┘  │
└─────────────┼───────────────┘
              │ HTTP (18082)
              ▼
┌─────────────────────────────┐
│   Windows Host              │
│  ┌───────────────────────┐  │
│  │  Windows Host Agent   │  │
│  │  (Node.js HTTP svc)   │  │
│  └──────────┬────────────┘  │
│             │ launches      │
│             ▼               │
│  ┌───────────────────────┐  │
│  │   Windows Sandbox     │  │
│  │   (Container)         │  │
│  │  ┌─────────────────┐  │  │
│  │  │  Runtime Node   │  │  │
│  │  │  (port 18081)   │  │  │
│  │  └─────────────────┘  │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

### Requirements
- **Linux host:** Docker, Node.js 22+, bash, ssh client
- **Windows host:** Windows 10/11 Pro or Enterprise, Windows Sandbox enabled, Node.js 22+, Python 3.11+, OpenSSH Server

### One-Line Deploy (Linux side)

If the Windows host is already running and reachable via SSH:

```bash
./deploy-hybrid.sh -w <windows-ip> -u <windows-user>
```

Example:
```bash
./deploy-hybrid.sh -w 192.168.1.100 -u admin
```

This script will:
1. Sync the project to the Windows host
2. Run `install-runtime-windows.ps1` to build and start the Host Agent as a service
3. Write the Linux Analyzer `.env` and `docker-compose.hybrid.yml`
4. Build and start the Analyzer Docker container
5. Run a connectivity test (including a test Sandbox start/stop)

### Manual Step-by-Step

#### On the Windows host

1. **Enable Windows Sandbox** (see Topology A step 1)

2. **Install the Windows Runtime**:
   ```powershell
   cd rikune
   .\install-runtime-windows.ps1 -Headless -Service
   ```

   The installer will:
   - Check Windows Sandbox availability
   - Build `runtime-node` and `windows-host-agent`
   - Generate `.env.runtime-windows` with a random API key
   - Start the Host Agent (as a Windows Service via `pm2` or `node-windows`)
   - Verify health

3. **Open firewall port 18082** (if Windows Firewall is active):
   ```powershell
   # Run as Administrator
   netsh advfirewall firewall add rule name="RikuneHostAgent" dir=in action=allow protocol=tcp localport=18082
   ```

4. **Note the Windows IP address** and the API key from `.env.runtime-windows`.

#### On the Linux host

5. **Create the Analyzer environment**:
   ```bash
   cp .env.analyzer.example .env
   # Edit .env:
   # RUNTIME_MODE=remote-sandbox
   # RUNTIME_HOST_AGENT_ENDPOINT=http://<windows-ip>:18082
   # RUNTIME_API_KEY=<api-key-from-step-4>
   ```

6. **Start the Analyzer**:
   ```bash
   docker build -t rikune:latest .
   docker compose -f docker-compose.hybrid.yml up -d
   ```

7. **Verify everything is connected**:
   ```bash
   ./diagnose-hybrid.sh -w <windows-ip>
   ```

---

## Quick Reference

### Environment Variables

| Variable | Topology | Description |
|----------|----------|-------------|
| `NODE_ROLE` | All | `analyzer` to run only static analysis |
| `RUNTIME_MODE` | All | `disabled` \| `auto-sandbox` \| `manual` \| `remote-sandbox` |
| `RUNTIME_ENDPOINT` | B, manual | Direct URL to Runtime Node (`http://vm:18081`) |
| `RUNTIME_HOST_AGENT_ENDPOINT` | C | URL to Windows Host Agent (`http://win:18082`) |
| `RUNTIME_API_KEY` | B, C | Shared secret for Runtime/Host-Agent authentication |
| `HOST_AGENT_PORT` | C | Port the Host Agent listens on (default: 18082) |
| `HOST_AGENT_API_KEY` | C | API key the Host Agent requires |

### Common Commands

```bash
# Linux Analyzer logs
docker compose -f docker-compose.hybrid.yml logs -f analyzer

# Windows Host Agent logs (if using pm2)
ssh admin@windows-host "pm2 logs rikune-host-agent"

# Run diagnostics
./diagnose-hybrid.sh -w <windows-ip>

# Rebuild after code changes
npm run build
docker build -t rikune:latest .
docker compose -f docker-compose.hybrid.yml up -d
```

### Updating After Code Changes

1. **Pull latest code** on both Linux and Windows hosts
2. **Rebuild** on Windows: `npm run build:runtime && npm run build:host-agent`
3. **Rebuild Docker** on Linux: `docker build -t rikune:latest .`
4. **Restart** services as needed (`docker compose restart` or `pm2 restart`)
