# Plugin SDK for Rikune

Type-safe SDK for building compiled JavaScript plugins for `rikune`.

## Installation

```bash
npm install @rikune/plugin-sdk zod
```

## Recommended Plugin Shape

```typescript
import { z } from 'zod'
import { definePlugin, defineTool, ok } from '@rikune/plugin-sdk'

export default definePlugin({
  id: 'my-custom-tool',
  name: 'My Custom Analysis Tool',
  version: '0.1.0',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'static-analysis' },
  configSchema: [
    { envVar: 'MY_TOOL_PATH', description: 'Path to custom tool binary', required: false },
  ],
  tools: [
    defineTool({
      name: 'my_custom_tool.analyze',
      description: 'Run custom analysis',
      inputSchema: z.object({ sample_id: z.string() }),
      handler: async (args, deps, ctx) =>
        ok({
          sample_id: args.sample_id,
          plugin: ctx?.pluginId,
          configured_path: ctx?.getConfig('MY_TOOL_PATH') ?? null,
        }),
    }),
  ],
})
```

Build the plugin to JavaScript and place the compiled `index.js` under `plugins/<id>/`.

## Manifest-Backed Plugins

Plugins may keep metadata in `plugin.json` and export handlers from `index.js`:

```json
{
  "id": "my-custom-tool",
  "name": "My Custom Analysis Tool",
  "version": "0.1.0",
  "executionDomain": "static",
  "surfaceRules": { "tier": 3, "category": "static-analysis" },
  "tools": [
    {
      "name": "my_custom_tool.analyze",
      "description": "Run custom analysis",
      "inputSchema": { "type": "object" }
    }
  ]
}
```

```typescript
import { ok } from '@rikune/plugin-sdk'

export const handlers = {
  'my_custom_tool.analyze': async () => ok({ completed: true }),
}
```

## API

- `definePlugin(config)` - defines a plugin and auto-registers declarative tools.
- `defineTool(config)` - defines one MCP tool plus its handler.
- `defineManifestPlugin(manifest, handlers)` - binds `plugin.json` metadata to handlers.
- `ok(data, options)` / `fail(errors, options)` - build standard `WorkerResult` payloads.
- `toolText(payload, options)` - build text MCP `ToolResult` payloads.
- `validatePlugin(plugin)` / `validateTool(tool)` - return field-level validation results.
- `pathExists(path)` / `envIsSet(name)` - small helpers for prerequisite checks.
- `getWorkspaceServices`, `getPlatformServices`, `getRuntimeServices`, `getGhidraServices` - grouped service accessors with fallback to existing dependency fields.
- `requireServices(deps, paths, consumer)` - fail fast when required injected services are missing.

## Runtime Contracts

Dynamic tools that are delegated to a Runtime Node declare a `runtime` contract:

```typescript
defineTool({
  name: 'sample_runtime.capture',
  description: 'Capture runtime behavior',
  inputSchema: z.object({ sample_id: z.string() }),
  runtime: {
    type: 'inline',
    handler: 'executeBehaviorCapture',
    modes: ['live_sandbox', 'live_hyperv', 'manual_runtime'],
    requiredProfiles: ['behavior_capture'],
    produces: ['dynamic_trace_json'],
  },
  handler: async () => ok({ status: 'queued' }),
})
```

The server uses this contract for readiness checks, runtime routing, setup diagnostics, and execution semantics.

## Lifecycle

1. Discovery loads compiled plugins from `plugins/`.
2. Optional `check()` and `systemDeps` validate prerequisites.
3. `definePlugin()` auto-registers declarative tools, or a plugin can provide `register()` for advanced registration.
4. Hooks can observe tool calls.
5. Optional `teardown()` runs when the plugin unloads.
