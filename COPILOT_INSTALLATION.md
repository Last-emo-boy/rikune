# Install In GitHub Copilot

Use the local installer when you want to register Rikune as an MCP server for GitHub Copilot or VS Code.

```powershell
.\install-local.ps1
```

The installer can build the project, check dependencies, and update supported MCP client configuration files.

## Recommended Flow

1. Install Node.js 22+.
2. Clone or unpack this repository.
3. Run:

```powershell
.\install-local.ps1
```

4. Select the GitHub Copilot / VS Code MCP option when prompted.
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

Depending on selected options, the installer can:

- run `npm install`;
- run `npm run build`;
- verify Node, npm, Python, Java, and Ghidra paths;
- configure local MCP stdio command;
- configure Docker stdio command;
- preserve existing client configuration where possible.

## Example MCP Config

Local build:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "node",
      "args": ["D:/Playground/windows-exe-decompiler-mcp-server/dist/index.js"],
      "env": {
        "API_ENABLED": "true",
        "API_PORT": "18080",
        "PLUGINS": "*"
      }
    }
  }
}
```

Docker stdio:

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

For Python workers:

```powershell
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

## Scope

This guide covers local Copilot/MCP configuration. For deployment topology, see [DEPLOYMENT.md](DEPLOYMENT.md). For Docker installation, see [INSTALL.md](INSTALL.md).
