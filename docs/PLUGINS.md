# Plugin SDK And Built-In Plugins

Rikune uses plugins for most optional and specialist analysis surfaces. Core intake, workflow, artifact, task, and system tools are registered by `src/core/tool-registry.ts`; specialist tools are registered by plugins under `src/plugins/<id>/`.

The public plugin contract lives in `packages/plugin-sdk/src/index.ts`. Compatibility re-exports are available through `src/plugins/sdk.ts`.

## Plugin Responsibilities

A plugin can:

- register one or more MCP tools;
- declare static, dynamic, or both-domain execution;
- declare dependencies on other plugins;
- declare external system dependencies;
- expose configuration schema for `plugin.list`;
- provide lifecycle hooks;
- provide Docker generation metadata;
- define progressive tool surface rules;
- delegate execution to Runtime Node through a runtime contract.

## Built-In Plugins

The repository currently contains 56 built-in plugins.

| ID | Name | Domain | Surface tier |
| --- | --- | --- | --- |
| `android` | Android / APK Analysis | static | 1 |
| `angr` | angr | static | 3 |
| `api-hash` | API Hash Resolution | static | 2 |
| `apk-smali` | APK Smali Analysis | static | 1 |
| `batch` | Batch Analysis | both | 0 |
| `behavior-first` | Behavior-First Analysis | dynamic | 2 |
| `binary-diff` | Binary Diff | static | 2 |
| `capstone` | Capstone Disassembly | static | 2 |
| `code-analysis` | Code Analysis | static | 0 |
| `crackme` | CrackMe Automation | static | 3 |
| `cross-module` | Cross-Module Analysis | static | 2 |
| `debug-session` | Debug Session | dynamic | 3 |
| `deep-unpack` | Deep Unpack | static | 2 |
| `die` | Detect It Easy | static | 0 |
| `dotnet-decompile` | .NET Decompile | static | 2 |
| `dotnet-reactor` | .NET Reactor Deobfuscation | static | 2 |
| `dynamic` | Dynamic Analysis Automation | dynamic | 3 |
| `elf-macho` | ELF / Mach-O | static | 1 |
| `firmware` | Firmware Analysis | static | 1 |
| `frida` | Frida Instrumentation | dynamic | 3 |
| `ghidra` | Ghidra Integration | static | 3 |
| `go-analysis` | Go Analysis | static | 2 |
| `graphviz` | Graphviz | static | 0 |
| `host-correlation` | Host Correlation | static | 2 |
| `kb-collaboration` | Knowledge Base & Collaboration | static | 0 |
| `malware` | Malware Analysis | static | 0 |
| `managed-fake-c2` | Managed Fake C2 | dynamic | 2 |
| `managed-il-xrefs` | Managed IL Cross-References | static | 2 |
| `managed-sandbox` | Managed Sandbox | dynamic | 2 |
| `memory-forensics` | Memory Forensics (Volatility 3) | static | 3 |
| `metadata` | File Metadata | static | 0 |
| `observability` | observability.metrics | both | 0 |
| `office-analysis` | Office Analysis | static | 1 |
| `panda` | PANDA | dynamic | 3 |
| `pcap-analysis` | PCAP Analysis | static | 1 |
| `pe-analysis` | PE Analysis | static | 0 |
| `pe-signature` | PE Authenticode Signature | static | 2 |
| `qiling` | Qiling | dynamic | 3 |
| `reporting` | Reporting | both | 0 |
| `retdec` | RetDec | static | 3 |
| `rizin` | Rizin | static | 3 |
| `runtime-deobfuscate` | Runtime Deobfuscation | dynamic | 2 |
| `sbom` | SBOM | static | 2 |
| `similarity` | Sample Similarity | static | 2 |
| `speakeasy` | Speakeasy Emulator | dynamic | 2 |
| `static-triage` | Static Triage | static | 0 |
| `strings` | Strings Extraction | static | 0 |
| `threat-intel` | Threat Intelligence | static | 0 |
| `unpacking` | Unpacking | static | 2 |
| `upx` | UPX | static | 2 |
| `visualization` | Visualization & Reporting | static | 0 |
| `vm-analysis` | VM Analysis & Symbolic | static | 3 |
| `vuln-scanner` | Vulnerability Scanner | static | 2 |
| `wine` | Wine | dynamic | 3 |
| `yara` | YARA | static | 0 |
| `yara-x` | YARA-X | static | 2 |

Surface tier meanings:

- `0`: visible gateway tools.
- `1`: file-type activated tools.
- `2`: finding/signal activated tools.
- `3`: expert tools, usually surfaced by `tools.discover` or explicit readiness checks.

## Runtime Management Tools

| Tool | Purpose |
| --- | --- |
| `plugin.list` | List known plugins, status, registered tools, dependencies, and optional config schema |
| `plugin.enable` | Hot-load a known plugin when supported |
| `plugin.disable` | Unload a plugin when supported |
| `tools.discover` | Reveal relevant specialist tools for a sample, finding, or goal |
| `tool.readiness` | Explain prerequisites, runtime contract, policy requirements, and backend availability for a tool |

## Loading Configuration

`PLUGINS` controls the startup plugin set.

```bash
PLUGINS=*                 # default: all built-ins
PLUGINS=pe-analysis,yara  # only selected plugin IDs
PLUGINS=-dynamic          # all except listed plugin IDs
```

Docker profile generation also uses plugin metadata. Regenerate Docker files after adding or removing plugin dependencies:

```bash
npm run build
npm run docker:generate:all
```

## Discovery And Lifecycle

Startup discovery:

1. Discover built-ins from `dist/plugins` in built packages or `src/plugins` in development.
2. Discover external compiled plugins under repository-level `plugins/`.
3. Apply `PLUGINS` filtering.
4. Sort by plugin dependency graph.
5. Validate plugin shape and dependencies.
6. Check system dependencies and plugin `check()` hooks when present.
7. Register plugin tools.
8. Record plugin status and tool ownership.
9. Register plugin introspection tools and diagnostics.

Runtime lifecycle hooks:

- `onBeforeToolCall`
- `onAfterToolCall`
- `onToolError`

The executor only fires plugin hooks for tools owned by that plugin.

## Recommended Plugin Shape

```ts
import { z } from 'zod'
import { definePlugin, defineTool, ok } from '@rikune/plugin-sdk'

const echoTool = defineTool({
  name: 'example.echo',
  description: 'Return a message from the example plugin',
  inputSchema: z.object({
    message: z.string(),
  }),
  handler: () => async (args) => ok({ message: args.message }),
})

export default definePlugin({
  id: 'example',
  name: 'Example Plugin',
  description: 'Small external plugin example',
  version: '1.0.0',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'example' },
  register(server) {
    server.registerTool(echoTool.definition, echoTool.handlerFactory({}))
    return ['example.echo']
  },
})
```

External plugins should compile to ESM JavaScript and be placed under `plugins/<id>/index.js` or as a direct `.js`/`.mjs` file under `plugins/`.

The repository also includes:

```bash
node scripts/create-plugin.js my-feature --name "My Feature"
```

## Manifest-Backed Plugins

Plugins can keep metadata in `plugin.json` and export handlers from `index.js`. Manifest validation is part of the SDK.

Minimal shape:

```json
{
  "id": "my-feature",
  "name": "My Feature",
  "version": "1.0.0",
  "description": "External feature plugin",
  "executionDomain": "static",
  "tools": [
    {
      "name": "my_feature.inspect",
      "description": "Inspect a sample"
    }
  ]
}
```

## Runtime Contracts

Dynamic or delegated tools can declare runtime contracts. Contracts describe execution mode, required capabilities, input/output artifacts, timeout, and backend needs. Analyzer-side `RuntimeClient` validates the contract before dispatching to Runtime Node.

Common execution modes:

- `plan_only`
- `safe_simulation`
- `emulation`
- `live_sandbox`
- `live_hyperv`
- `manual_runtime`

Live modes should require explicit policy approval and an isolated runtime backend.

## System Dependencies

Plugin `systemDeps` can describe binaries, Python modules, files, environment variables, Docker install snippets, and validation commands. These surface in:

- Docker generation;
- `plugin.list`;
- readiness checks;
- setup guidance;
- dashboard readiness.

## Troubleshooting

Plugin does not load:

1. Check `PLUGINS`.
2. Run `plugin.list` with config/status details.
3. Check system dependency messages.
4. Confirm the plugin exports a valid default plugin object.
5. Rebuild TypeScript if using built-in plugin changes.

Tool is missing:

1. Confirm the plugin loaded.
2. Check progressive surface behavior with `tools.discover`.
3. Use `tool.readiness`.
4. Check aliases if the client normalizes dotted names.

Runtime-delegated tool fails:

1. Check `dynamic.runtime.status`.
2. Check `/api/v1/ready`.
3. Confirm `RUNTIME_MODE`, Host Agent endpoint, and API keys.
4. Verify the Runtime Node advertises the required capability.
5. Confirm policy approval for live execution.
