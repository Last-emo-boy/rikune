# Plugin SDK For Rikune

`@rikune/plugin-sdk` is the public contract for Rikune plugins. Plugins should import SDK types and helpers from this package instead of importing Analyzer internals.

## Installation

Inside this monorepo the package is available through npm workspaces.

For external plugins:

```bash
npm install @rikune/plugin-sdk zod
```

## Core Concepts

| Concept | Purpose |
| --- | --- |
| `Plugin` | The object exported by a plugin |
| `ToolDefinition` | MCP tool metadata, input schema, optional output schema, optional runtime contract |
| `PluginToolDeps` | Services injected by the Analyzer during registration |
| `PluginServerInterface` | Minimal server facade exposed to plugins |
| `ToolRuntimeContract` | Runtime Node delegation contract |
| `ok`, `fail`, `toolText` | Result helpers |

## Recommended Plugin Shape

```ts
import { z } from 'zod'
import { definePlugin, defineTool, ok } from '@rikune/plugin-sdk'

const inspectTool = defineTool({
  name: 'example.inspect',
  description: 'Inspect a sample with the example plugin',
  inputSchema: z.object({
    sample_id: z.string(),
  }),
  handler: () => async (args, deps) => {
    const workspace = deps.services?.workspace
    return ok({
      sample_id: args.sample_id,
      has_workspace_service: Boolean(workspace?.manager),
    })
  },
})

export default definePlugin({
  id: 'example',
  name: 'Example',
  description: 'Example Rikune plugin',
  version: '1.0.0',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'example' },
  register(server, deps) {
    server.registerTool(inspectTool.definition, (args) => inspectTool.handler(args, deps))
    return ['example.inspect']
  },
})
```

## Plugin Object

Important fields:

```ts
interface Plugin {
  id: string
  name: string
  description?: string
  version?: string
  executionDomain?: 'static' | 'dynamic' | 'both'
  dependencies?: string[]
  configSchema?: PluginConfigField[]
  systemDeps?: PluginSystemDependency[]
  surfaceRules?: PluginSurfaceRules
  register(server: PluginServerInterface, deps: PluginToolDeps, ctx?: PluginContext): string[] | void | Promise<string[] | void>
  check?(deps: PluginToolDeps, ctx?: PluginContext): boolean | Promise<boolean>
  teardown?(deps: PluginToolDeps, ctx?: PluginContext): void | Promise<void>
  hooks?: PluginHooks
}
```

## Dependency Injection

Plugins receive services through `PluginToolDeps`.

Common services:

- `workspaceManager`
- `database`
- `cacheManager`
- `jobQueue`
- `storageManager`
- `policyGuard`
- `runtimeClient`
- `services.workspace`
- `services.platform`
- `services.runtime`
- `services.ghidra`

Prefer service helpers such as `requireWorkspaceManager`, `requireDatabase`, and `getRuntimeServices` where available. Avoid importing from `src/core`, `src/persistence`, or other Analyzer internals directly.

## Manifest-Backed Plugins

External plugins can declare metadata in `plugin.json` and export handlers from `index.js`.

```json
{
  "id": "example",
  "name": "Example",
  "version": "1.0.0",
  "description": "Example external plugin",
  "executionDomain": "static",
  "tools": [
    {
      "name": "example.inspect",
      "description": "Inspect a sample"
    }
  ]
}
```

The SDK includes manifest validation helpers used by the Analyzer loader.

## Runtime Contracts

Tools delegated to Runtime Node can attach a `runtime` contract to their `ToolDefinition`.

Contracts describe:

- supported execution modes;
- required backend capabilities;
- timeout;
- expected artifact inputs and outputs;
- fallback behavior;
- failure categories.

Execution modes include:

- `plan_only`
- `safe_simulation`
- `emulation`
- `live_sandbox`
- `live_hyperv`
- `manual_runtime`

Live execution should remain explicit and policy-gated.

## Results

Use result helpers for consistent MCP output:

```ts
return ok({
  summary: 'analysis complete',
  findings: [],
})
```

Return errors as structured tool results when the failure is expected and user-actionable. Throw only for unexpected implementation failures.

## Surface Rules

`surfaceRules` controls when plugin tools are visible.

| Tier | Meaning |
| --- | --- |
| 0 | Visible gateway tools |
| 1 | File-type activated |
| 2 | Finding/signal activated |
| 3 | Expert/manual discovery |

Use `tools.discover` and `tool.readiness` to help clients find tier 1-3 tools.

## External Plugin Placement

Compiled external plugins can be placed in:

```text
plugins/<id>/index.js
plugins/<id>/plugin.json
```

or as a direct `.js` / `.mjs` module under `plugins/`.

The repository scaffold helper is:

```bash
node scripts/create-plugin.js my-feature --name "My Feature"
```

## Testing Plugins

Recommended checks:

```bash
npm run build
npm run test:unit
npm run typecheck
```

Then validate runtime behavior with:

- `plugin.list`
- `tools.discover`
- `tool.readiness`
- the plugin's own tools
