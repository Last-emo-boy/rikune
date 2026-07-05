# Minimize Tool Surface Iteration

Date: 2026-05-29

Branch: `beta-minimize-tool-surface`

This Maestro task set captures a focused iteration to reduce the MCP tools exposed through
`tools/list` as much as practical while preserving discoverability through gateway tools.
The goal is not to remove capabilities. The goal is to keep specialist and high-cost tools
registered but hidden until `tools.discover`, sample context, readiness review, or explicit
activation exposes them.

Current anchors:

- `src/core/tool-registry.ts` defines `CORE_GATEWAY_TOOLS` as the startup-visible core allowlist.
- `src/core/tool-surface-manager.ts` already supports hidden core tools, plugin tiers, explicit
  activation, file-type activation, finding activation, and `recommended_next_tools` expansion.
- `src/core/tool-executor.ts` blocks direct calls to registered tools hidden by the progressive
  surface and points users back to `tools.discover`.
- `src/tools/tools-discover.ts` searches visible and hidden core/plugin capabilities and returns
  readiness, activation plans, activation commands, and hidden-surface explanations.
- `tool.help`, `tool.readiness`, and `tools.discover` are the key metadata-only gateway surfaces.

Design intent:

1. Make the default `tools/list` surface gateway-only by policy, not by accident.
2. Keep all analysis, runtime, backend, plugin management, workflow, task, artifact, and diagnostic
   tools callable only after explicit surface activation unless they are deliberately allowlisted.
3. Preserve a low-friction path from natural language or sample metadata to the right hidden tools
   through `tools.discover` recommendations and `tool.help`/`tool.readiness` details.
4. Add guard tests so future plugins or core tools cannot silently widen startup visibility.
5. Update docs and catalog text to describe the smaller surface and the intended activation path.

Non-goals:

- Do not delete tools or plugin registrations.
- Do not start backend processes from discovery, help, readiness, plugin list, catalog generation, or
  tests.
- Do not auto-activate runtime, debugger, Frida, sandbox, sidecar, GPU, DBI, or license-gated tools.
- Do not bypass `ToolExecutor` hidden-tool blocking.
- Do not modify unrelated prior `.workflow` task sets or generated artifacts unless the release guard
  explicitly requires regeneration.

Relevant source files:

- `src/core/tool-registry.ts`
- `src/core/tool-surface-manager.ts`
- `src/core/tool-executor.ts`
- `src/core/tool-surface-guidance.ts`
- `src/tools/tools-discover.ts`
- `src/tools/tool-help.ts`
- `src/tools/tool-readiness.ts`
- `tests/unit/core/tool-surface-manager.test.ts`
- `tests/unit/core/tool-executor.test.ts`
- `tests/unit/tools-discover.test.ts`
- `tests/unit/mcp-tool-safety.test.ts`
- `docs/PLUGINS.md`
- `docs/ARCHITECTURE.md`
- `README.md`

Expected outcome:

- The startup tool list is limited to the smallest practical metadata gateway.
- Hidden core tools and plugin tools remain discoverable through `tools.discover`.
- Any tool outside the gateway has a tested activation path and clear hidden-surface explanation.
- Safety/readiness boundaries remain metadata-only and do not launch external backends.
