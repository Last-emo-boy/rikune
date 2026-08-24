# Install In GitHub Copilot

Use the Linux Docker Analyzer when you want to register Rikune as an MCP server for GitHub Copilot or VS Code. Native Windows and macOS Node Analyzers are not supported in v1.4.0 because sample custody requires Linux filesystem primitives.

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

The installer builds and starts the Linux Analyzer container. Client configuration is an explicit,
manual step so the installer never overwrites an existing MCP configuration or copies runtime
credentials into a client-owned file. Use `-Profile hybrid -InstallRuntime` when a Windows Host
Agent/runtime is required.

## Recommended Flow

1. Install Docker Desktop and Node.js 22.9+.
2. Clone or unpack this repository.
3. Run:

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

4. Run **MCP: Open Workspace Folder Configuration** in VS Code, or create `.vscode/mcp.json`, and
   add the Docker stdio config below.
5. Restart VS Code or reload the MCP client.
6. Ask the client to call `tool.help`, `sample.ingest`, or `workflow.analyze.start`.

For Docker-based use, prefer:

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

or, when live Windows runtime is required:

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime
```

## What The Script Updates

The Docker installer:

- run `npm ci`;
- run `npm run build`;
- verify Docker, Docker Compose, Node.js, and npm;
- generate the selected Compose profile;
- build, start, and health-check the Linux Analyzer container.

It does not edit VS Code, Copilot, Claude, Codex, or generic client configuration files.

## Example MCP Config

Docker stdio:

```json
{
  "servers": {
    "rikune": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "-e",
        "API_ENABLED=false",
        "-e",
        "NODE_ENV=production",
        "-e",
        "PYTHONUNBUFFERED=1",
        "rikune-analyzer",
        "node",
        "dist/index.js"
      ]
    }
  }
}
```

This `.vscode/mcp.json` form uses the credential-free Docker stdio channel. Do not embed the
Analyzer, Host Agent, or Runtime API keys in a workspace file.

## Verify

In Copilot or another MCP client:

1. List tools.
2. Call `tool.help`.
3. Call `system.health`.
4. Import a benign test sample with `sample.ingest`.
5. Start the staged workflow with `workflow.analyze.start`.
6. Poll `workflow.analyze.status`.

## First-Run Setup Guidance

Useful tools:

- `system.health`
- `system.setup.guide`
- `system.config.validate`
- `plugin.list`
- `tool.readiness`
- `tools.discover`

For Ghidra, keep Java 21+ available and set `GHIDRA_INSTALL_DIR` if auto-detection fails.

For Python workers on the Linux Analyzer, use the exact production locks instead of
installing the mutable `requirements.txt` inputs directly:

```bash
python -m pip install --require-hashes -r requirements.lock.txt
python -m pip install --require-hashes -r workers/requirements-dynamic.lock.txt
```

On Windows, keep the Analyzer in Docker/WSL2 and use the native Host Agent only for
runtime delegation. Do not install Analyzer Python workers on the Windows host.

## Scope

This guide covers local Copilot/MCP configuration. For deployment topology, see [DEPLOYMENT.md](DEPLOYMENT.md). For Docker installation, see [INSTALL.md](INSTALL.md).
