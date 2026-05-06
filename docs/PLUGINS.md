# Plugin SDK

The MCP server uses a plugin architecture for optional tool modules that can be
enabled, disabled, discovered, hot-loaded/unloaded, and extended — without
modifying core code. Third-party developers can drop `.js`/`.mjs` files into a
`plugins/` directory and have them auto-discovered at startup.

## Overview

Each plugin:

- Has a unique `id` (kebab-case) and human-readable `name`
- Defines tools with `definePlugin` / `defineTool`, or implements `register(server, deps)` for advanced registration
- Can optionally declare a `check()` prerequisite that must pass before loading
- Can declare `configSchema` fields for environment-based configuration
- Can declare `dependencies` on other plugins (topologically sorted)
- Can implement `hooks` for lifecycle interception (before/after/error)
- Can implement `teardown()` for cleanup on unload

Plugins are loaded during server bootstrap via `loadPlugins()`, which is called
from the centralised tool registry.

## Built-in plugins

| Plugin ID | Name | Tools | Prerequisites |
|-----------|------|-------|---------------|
| `android` | Android / APK Analysis | `apk.structure.analyze`, `dex.decompile`, `dex.classes.list`, `apk.packer.detect` | jadx binary accessible |
| `angr` | angr | `angr.analyze` | `ANGR_PYTHON` |
| `api-hash` | API Hash Resolution | `hash.resolve`, `hash.identify`, `hash.resolver.plan` | None |
| `apk-smali` | APK Smali Analysis | `apk.disassemble`, `apk.manifest.parse`, `apk.resources.decode` | `JADX_PATH` |
| `batch` | Batch Analysis | `batch.submit`, `batch.status`, `batch.results` | None |
| `behavior-first` | Behavior-First Analysis | 3 tools | None |
| `binary-diff` | Binary Diff | 2 tools | None |
| `capstone` | Capstone Disassembly | `disasm.quick`, `shellcode.disasm` | None |
| `code-analysis` | Code Analysis | 19 tools (CFG, decompile, xrefs, patterns) | None |
| `crackme` | CrackMe Automation | `crackme.locate_validation`, `symbolic.explore`, `patch.generate`, `keygen.verify` | None (angr optional) |
| `cross-module` | Cross-Module Analysis | `cross_binary.compare`, `call_graph.cross_module`, `dll.dependency_tree` | None |
| `debug-session` | Debug Session | 9 tools | None |
| `deep-unpack` | Deep Unpack | 3 tools | Speakeasy / Qiling / Wine optional |
| `die` | Detect It Easy | `die.scan`, `die.identify` | `DIE_PATH` |
| `dotnet-decompile` | .NET Decompile | `dotnet.decompile`, `dotnet.decompile.type` | None |
| `dotnet-reactor` | .NET Reactor | 4 tools | python3 |
| `dynamic` | Dynamic Analysis Automation | 24 tools: `dynamic.auto_hook`, `dynamic.trace_attribute`, `dynamic.memory_dump`, `dynamic.behavior.capture`, `dynamic.behavior.diff`, `dynamic.dependencies`, `dynamic.trace.import`, `dynamic.memory.import`, `sandbox.execute`, `runtime.debug.session.start`, `runtime.debug.session.status`, `runtime.debug.session.stop`, `runtime.debug.command`, `dynamic.runtime.status`, `dynamic.toolkit.status`, `dynamic.deep_plan`, `debug.cdb.plan`, `debug.procdump.plan`, `debug.telemetry.plan`, `debug.network.plan`, `debug.managed.plan`, `debug.gui.handoff`, `dynamic.persona.plan`, `runtime.hyperv.control` | None |
| `elf-macho` | ELF/Mach-O Analysis | 4 tools | None |
| `firmware` | Firmware Analysis | 3 tools | None |
| `frida` | Frida Instrumentation | `frida.runtime.instrument`, `frida.script.inject`, `frida.trace.capture`, `frida.script.generate` | `frida --version` succeeds |
| `ghidra` | Ghidra Integration | `ghidra.analyze`, `ghidra.health` | `GHIDRA_INSTALL_DIR` set and accessible |
| `go-analysis` | Go Analysis | `go.symbols.recover`, `go.types.list`, `go.binary.analyze` | None |
| `graphviz` | Graphviz | `graphviz.render` | `GRAPHVIZ_DOT_PATH` |
| `host-correlation` | Host Correlation | 1 tool | python3 |
| `kb-collaboration` | Knowledge Base & Collaboration | 8 tools | None |
| `malware` | Malware Analysis | `c2.extract`, `malware.config.extract`, `malware.classify`, `sandbox.report` | None |
| `managed-fake-c2` | Managed Fake C2 | 1 tool | python3 |
| `managed-il-xrefs` | Managed IL XRefs | 2 tools | python3 |
| `managed-sandbox` | Managed Sandbox | 1 tool | python3 |
| `memory-forensics` | Memory Forensics | 6 tools | `VOLATILITY3_PATH` |
| `metadata` | File Metadata | `metadata.extract` | None |
| `observability` | Observability | `observability.metrics` | None |
| `office-analysis` | Office Analysis | `office.vba.extract`, `office.macro.detect`, `office.ole.analyze` | None |
| `panda` | PANDA | `panda.inspect` | `PANDA_PATH` |
| `pcap-analysis` | PCAP Analysis | `pcap.analyze`, `pcap.dns.list`, `pcap.extract.streams` | None |
| `pe-analysis` | PE Analysis | 6 tools | None |
| `pe-signature` | PE Authenticode Signature | `pe.signature.verify`, `pe.certificate.extract` | None |
| `qiling` | Qiling | `qiling.inspect` | `QILING_PYTHON` |
| `reporting` | Reporting | `report.summarize`, `report.generate`, `workflow.summarize` | None |
| `retdec` | RetDec | `retdec.decompile` | `RETDEC_PATH` |
| `rizin` | Rizin | `rizin.analyze` | `RIZIN_PATH` |
| `runtime-deobfuscate` | Runtime Deobfuscation | 4 tools | de4dot optional |
| `sbom` | SBOM | 1 tool | None |
| `similarity` | Sample Similarity | `sample.similarity`, `sample.cluster.fuzzy` | py-tlsh optional |
| `speakeasy` | Speakeasy Emulator | `speakeasy.emulate`, `speakeasy.shellcode`, `speakeasy.api_trace` | speakeasy-emulator |
| `static-triage` | Static Triage | 20 tools: includes `static.resource.graph`, `static.config.carver`, and `static.behavior.classify` for resource/payload graphing, generic config carving, and persistence/injection classification | None |
| `strings` | Strings | 2 tools | FLOSS optional |
| `threat-intel` | Threat Intelligence | `attack.map`, `ioc.export`, `sigma.rule.generate` | None |
| `unpacking` | Unpacking | 3 tools: `unpack.auto`, `unpack.guide`, `unpack.child.handoff` | None |
| `upx` | UPX | `upx.inspect` | `UPX_PATH` |
| `visualization` | Visualization & Reporting | `report.html.generate`, `behavior.timeline`, `data_flow.map`, `analysis.evidence.graph`, `crypto.lifecycle.graph` | None |
| `vm-analysis` | VM Analysis | 10 tools | None |
| `vuln-scanner` | Vulnerability Scanner | 2 tools | None |
| `wine` | Wine | `wine.run` | `WINE_PATH` |
| `yara` | YARA | `yara.scan`, `yara.generate`, `yara.generate.batch` | yara-python optional |
| `yara-x` | YARA-X | `yaraX.scan` | `YARA_X_PATH` |

## Plugin introspection tools

Three MCP tools let LLM clients discover and manage plugins at runtime:

| Tool | Description |
|------|-------------|
| `plugin.list` | List all plugins, their status, tools, and optional config schema |
| `plugin.enable` | Hot-load a known but currently-unloaded plugin |
| `plugin.disable` | Unload a loaded plugin (tools become unavailable) |

## Configuration

### `PLUGINS` environment variable

Controls which plugins are loaded at startup.

| Value | Meaning |
|-------|---------|
| `*` (default) | Load all built-in plugins |
| _(empty)_ | Load all built-in plugins |
| `android,malware` | Load only the listed plugins |
| `-dynamic` | Load all except the listed plugins (prefix with `-`) |

### Plugin config schema

Each plugin can declare `configSchema` — an array of `PluginConfigField` values:

```typescript
interface PluginConfigField {
  envVar: string       // e.g. 'GHIDRA_INSTALL_DIR'
  description: string  // shown in plugin.list output
  required: boolean
  defaultValue?: string
}
```

Use `plugin.list` with `include_config: true` to discover required environment
variables and their current set/unset status.

Use `plugin.list` with `execution_domain: "static"` or `"dynamic"` to inspect one
side of the plugin surface. Static plugins run on analyzer nodes. Dynamic plugins
are delegated to a Runtime Node when live execution or instrumentation is needed.

### Examples

```bash
# Load all plugins (default)
PLUGINS=* node dist/index.js

# Only Android and malware tools
PLUGINS=android,malware node dist/index.js

# Everything except dynamic analysis
PLUGINS=-dynamic node dist/index.js

# Set Ghidra dir to enable ghidra plugin
GHIDRA_INSTALL_DIR=/opt/ghidra node dist/index.js
```

### Docker

In `docker-compose.yml`:

```yaml
services:
  mcp-server:
    environment:
      PLUGINS: "android,malware"
      GHIDRA_INSTALL_DIR: "/opt/ghidra"
```

## Plugin lifecycle

1. `registerAllTools()` calls `loadPlugins(server, deps)`
2. `discoverExternalPlugins()` scans `plugins/` for compiled `.js`/`.mjs` plugins and directory plugins with optional `plugin.json`
3. `PluginManager.loadAll()` resolves enabled plugins via `PLUGINS` env var
4. Plugins are topologically sorted by `dependencies`
5. For each enabled plugin in dependency order:
   - Dependency check: all declared dependencies must be loaded
   - If `check()` is defined, it is called. If it returns `false`, the plugin is skipped.
   - Declarative tools are registered, or `register(server, deps)` is called.
   - Plugin status is recorded as `loaded`, `skipped-check`, `skipped-deps`, or `error`
6. `server.setPluginManager(mgr)` wires in lifecycle hooks for `callTool()`
7. Plugin introspection tools (`plugin.list`, `.enable`, `.disable`) are registered

### Lifecycle hooks

When a tool belonging to a plugin is called, the server fires:

- `onBeforeToolCall(toolName, args)` — before execution
- `onAfterToolCall(toolName, args, elapsedMs)` — after successful return
- `onToolError(toolName, error)` — when an error is thrown

Hook errors are caught and logged but never propagate to the client.

### Hot-load / unload

- `plugin.enable` → `PluginManager.hotLoad(plugin)` — registers tools at runtime
- `plugin.disable` → `PluginManager.unload(id)` — calls `teardown()`, unregisters tools
- No server restart required

## Writing a plugin

Use the scaffold when starting from scratch:

```bash
node scripts/create-plugin.js my-feature --name "My Feature"
cd plugins/my-feature
npm install
npm run build
```

The server discovers the compiled `plugins/my-feature/index.js` on restart.

Recommended TypeScript shape:

```typescript
import { z } from 'zod'
import { definePlugin, defineTool, ok } from '@rikune/plugin-sdk'

export default definePlugin({
  id: 'my-feature',
  name: 'My Feature',
  version: '0.1.0',
  executionDomain: 'static',
  description: 'Does something cool',
  surfaceRules: { tier: 3, category: 'static-analysis' },
  tools: [
    defineTool({
      name: 'my_feature.analyze',
      description: 'Analyze a sample with my feature',
      inputSchema: z.object({ sample_id: z.string() }),
      handler: async (args) => ok({ sample_id: args.sample_id }),
    }),
  ],
})
```

Manifest-backed plugins can keep metadata in `plugin.json` and export handlers from `index.js`:

```json
{
  "id": "my-feature",
  "name": "My Feature",
  "version": "0.1.0",
  "executionDomain": "static",
  "surfaceRules": { "tier": 3, "category": "static-analysis" },
  "tools": [
    {
      "name": "my_feature.analyze",
      "description": "Analyze a sample with my feature",
      "inputSchema": { "type": "object" }
    }
  ]
}
```

```javascript
import { ok } from '@rikune/plugin-sdk'

export const handlers = {
  'my_feature.analyze': async () => ok({ completed: true }),
}
```

External plugins are discovered automatically at startup — no code changes needed.

### Built-in plugin

1. Create `src/plugins/<id>/index.ts`
2. Export a plugin object with `definePlugin()`
3. Rebuild: `npm run build`

### Runtime extra plugin

```typescript
import { loadPlugins } from './plugins.js'
await loadPlugins(server, deps, [myPlugin])
```

## Plugin interface (full SDK)

```typescript
interface Plugin {
  id: string                        // unique kebab-case identifier
  name: string                      // human-readable display name
  description?: string              // short capability description
  version?: string                  // semver string
  executionDomain?: 'static' | 'dynamic' | 'both'
  dependencies?: string[]           // IDs of plugins that must load first
  configSchema?: PluginConfigField[] // declarative config fields
  hooks?: PluginHooks               // lifecycle hooks
  check?: () => boolean | Promise<boolean>  // prerequisite gate
  tools?: DefinedTool[]             // declarative tools
  register?: (server: MCPServer, deps: ToolDeps) => string[] | void  // advanced registration
  teardown?: () => void | Promise<void>     // cleanup on unload
}
```

Runtime-delegated tool definitions use a `runtime` contract, not an execution hint:

```typescript
interface ToolRuntimeContract {
  type: 'python-worker' | 'spawn' | 'inline'
  handler: string
  modes?: Array<'plan_only' | 'safe_simulation' | 'emulation' | 'live_sandbox' | 'live_hyperv' | 'manual_runtime'>
  requiredProfiles?: string[]
  requiredTools?: string[]
  optionalTools?: string[]
  produces?: string[]
  timeoutMs?: number
}
```

```typescript
interface PluginHooks {
  onBeforeToolCall?: (toolName: string, args: Record<string, unknown>) => void | Promise<void>
  onAfterToolCall?: (toolName: string, args: Record<string, unknown>, elapsedMs: number) => void | Promise<void>
  onToolError?: (toolName: string, error: unknown) => void | Promise<void>
}

interface PluginConfigField {
  envVar: string
  description: string
  required: boolean
  defaultValue?: string
}
```

## Troubleshooting

### Plugin not loading

1. Check `PLUGINS` env var — ensure the plugin ID is included (or not excluded).
2. If the plugin defines `check()`, verify its prerequisites (e.g. external tool paths, env vars).
3. Check server logs for `Plugin skipped (prerequisites not met)` or `skipped-deps` messages.
4. Use `plugin.list` to see all plugin statuses and error messages.

### Tool not appearing after adding a plugin

1. Ensure the compiled `index.js` is under `plugins/<id>/` or a `.js`/`.mjs` file is directly under `plugins/`.
2. Ensure `defineTool()` names are unique and handlers are functions.
3. If using `plugin.json`, ensure every tool has a matching exported handler.
4. Rebuild the plugin and restart the server.

### Hot-load not working

1. `plugin.enable` only works for plugins known to the system (built-in or previously discovered).
2. If prerequisites fail, `hotLoad()` returns a `skipped-check` status.
3. Check that `setPluginManager()` was called during bootstrap.
