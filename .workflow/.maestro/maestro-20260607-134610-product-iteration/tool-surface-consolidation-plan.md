# Tool Surface Consolidation Plan

Session: `maestro-20260607-134610-product-iteration`

Date: 2026-06-07 15:05:24 +08:00

Objective: use subagent analysis to map Rikune's current capabilities and converge the MCP tool surface to the smallest practical set, using profile-based search to route to internal tools and workflows.

## Evidence Summary

Four read-only subagents inspected the current repo from separate angles:

- Capability inventory: core tool groups, plugin capability categories, metadata fields, and search-profile candidates.
- Surface mechanics: MCP registration, `tools/list` visibility, hidden-tool call gates, activation paths, and alias handling.
- Search data sources: sample profile, workflow intent, backend readiness, coverage gaps, workflow recipes, and existing ranking.
- Implementation path: staged migration from `tools.discover` to `workflow.search` and from `workflow.analyze.*` to `workflow.run`.

Key repo anchors:

- `src/core/tool-registry.ts`: core gateway tools are currently `sample.request_upload`, `sample.ingest`, and `tools.discover`.
- `src/core/server.ts`: `tools/list` is already filtered through `ToolSurfaceManager`.
- `src/core/tool-executor.ts`: direct calls to hidden tools are blocked by the progressive surface gate.
- `src/tools/tools-discover.ts`: existing passive `status`, `list`, `recommend`, and active `activate` paths already rank and explain hidden capabilities.
- `src/tools/sample-profile-get.ts`: sample profile already aggregates formats, platforms, architectures, evidence signals, workflow recipes, nested route hints, and recommended tools.
- `src/tools/tool-aspect-matrix.ts`: plugin/tool metadata is already indexed by aspects and workflow recipes.
- `src/workflows/analyze-pipeline.ts`: staged workflow execution already exists as `workflow.analyze.start/status/promote`.
- `src/analysis/analysis-run-state.ts`: `analysis_runs.id` can serve as external `plan_id` without a new DB key.

## Current Capability Map

Rikune already has enough metadata to support profile search without exposing every tool schema.

Core capability groups:

- Sample and context: `sample.ingest`, `sample.request_upload`, `sample.profile.get`, `analysis.context.get`.
- Workflow lifecycle: `workflow.analyze.auto`, `workflow.analyze.start`, `workflow.analyze.status`, `workflow.analyze.promote`, `workflow.triage`, `workflow.reconstruct`, semantic review workflows.
- Artifact and evidence: `artifact.list`, `artifact.read`, `artifact.diff`, `artifact.download`, evidence graph/reporting surfaces.
- Task/control plane: `task.status`, `task.cancel`, `task.sweep`.
- System/setup: `system.health`, setup/remediation/config validation.
- Discovery/help/readiness: `tools.discover`, `tool.help`, `tool.readiness`.
- Plugin management: `plugin.list`, `plugin.enable`, `plugin.disable`.

Plugin capability categories:

- Static analysis: PE, ELF, Mach-O, Linux, Apple, firmware, office, WASM, container/archive.
- Reverse engineering: code analysis, Ghidra, Rizin, RetDec, binary diff, JavaScript deobfuscation.
- Dynamic/runtime: sandbox, Frida, Wine, Windows runtime, debug/session planning.
- Platform families: Android, .NET/managed, Go, JVM, WebAssembly, Unity.
- Malware workflows: YARA/YARA-X, config carving, threat intel, similarity, unpacking.
- Specialist surfaces: PCAP/network, memory forensics, symbolic execution, VM analysis, vulnerability research.

Reusable metadata fields:

- Plugin/tool aspects: `formats`, `platforms`, `architectures`, `execution`, `runtimes`, `capabilities`, `evidence`.
- Progressive surface: `surfaceRules.tier`, `activateOn.fileTypes`, `activateOn.findings`, `category`.
- Tool declarations: `artifacts`, `evidence`, `workflowRecipes`, runtime policy, runtime contract, worker backend.
- Analysis context: completed analyses, active jobs, staged runs, coverage gaps, upgrade paths, reuse hints.
- Readiness: missing deps, backend install profile, runtime gates, worker backend readiness, tool surface role.

## Target Surface

The final MCP surface should expose as few tools as possible while preserving safe discoverability and execution:

Minimum target:

1. `workflow.search`
2. `workflow.run`
3. `artifact.read`

Optional gateway tools:

- `sample.request_upload`: keep if `workflow.run` does not own upload/session creation.
- `artifact.list`: keep if `artifact.read` selectors are not sufficient for common clients.
- `task.status`: keep if `workflow.run status` does not expose queue-level details well enough.

Compatibility tools remain registered but hidden:

- `tools.discover`
- `tool.help`
- `tool.readiness`
- `workflow.analyze.start`
- `workflow.analyze.status`
- `workflow.analyze.promote`
- `workflow.analyze.auto`
- direct plugin tools

The goal is not to delete specialist tools. They remain registered, schema-validated, hook-aware, policy-gated, and auditable inside the server. They stop being default context.

## Workflow Search

`workflow.search` should be passive. It must not activate plugins, execute tools, start backends, or perform live readiness actions.

Inputs:

- `query`: natural language user request.
- `sample_id`: optional existing sample context.
- `goal`: `triage | static | reverse | dynamic | report`.
- `depth`: `safe | balanced | deep`.
- `backend_policy`: `auto | conservative | newest | disabled` according to existing schemas.
- `top_k`: default small value such as 5.
- `include_hidden`: default true for search results, because hidden tools are the point of search.

Profile sources:

- `sample.profile.get` fields: file type tags, formats, platforms, architectures, evidence signals, workflow recipes, recommended tools, nested route hints.
- `analysis.context.get` or `buildSampleReuseHints`: active jobs, completed work, staged runs, reusable artifacts, avoid-rerun hints.
- `buildIntentBackendPlan`: intent-to-backend and stage roles.
- `CoverageEnvelope`: coverage gaps and upgrade paths.
- `tools.discover?action=recommend`: current plugin/core tool recall, scoring, hidden reasons, activation plans.

Ranking fields:

- Extension/file type match.
- Format/platform/architecture match.
- Query/intent term match.
- Workflow recipe match.
- Coverage gap closure.
- Existing recommended tools and nested route hints.
- Backend readiness and missing deps.
- Safety/runtime/cost penalties.
- Surface role preference, especially primary workflow wrappers over direct expert tools.

Recommended response shape:

```ts
{
  result_mode: 'workflow_search',
  query: string,
  sample_id?: string,
  goal?: string,
  depth?: string,
  top_k: number,
  search_profile: {
    file_type_tags: string[],
    formats: string[],
    platforms: string[],
    architectures: string[],
    evidence_signals: string[],
    workflow_recipes: string[],
    coverage_gaps: Array<{ domain: string; status: string; reason: string }>,
    upgrade_paths: Array<{
      tool: string
      closes_gaps: string[]
      cost_tier: string
      availability: string
    }>,
    reuse_hints?: Record<string, unknown>
  },
  results: Array<{
    rank: number
    score: number
    kind: 'workflow' | 'tool' | 'plugin'
    tool_name?: string
    plugin_id?: string
    workflow_id?: string
    readiness_state: string
    activation_required: boolean
    activation_command?: Record<string, unknown>
    closes_gaps: string[]
    matched_profile_fields: string[]
    match_reasons: string[]
    score_breakdown: Record<string, number>
    next_actions: string[]
  }>
}
```

## Workflow Run

`workflow.run` should be the only primary execution gateway for workflows. It should not be a generic arbitrary tool invoker.

Inputs:

- `operation`: `start | status | promote | auto`.
- `plan_id`: external name for existing `analysis_runs.id`; returned alongside compatibility `run_id`.
- `sample_id`, or optional ingest inputs if the phase chooses to fold sample ingest into the run gateway.
- `goal`, `depth`, `backend_policy`.
- `through_stage` / `stages`.
- `allow_transformations`, `allow_live_execution`, `force_refresh`.

Allowed internal delegation:

- `start` wraps `createAnalyzeWorkflowStartHandler`.
- `status` wraps `createAnalyzeWorkflowStatusHandler`.
- `promote` wraps `createAnalyzeWorkflowPromoteHandler`.
- `auto` wraps `createAnalyzeAutoWorkflowHandler` or performs search-first routing to start/promote.

Hard non-goals:

- Do not accept arbitrary `tool_name` execution.
- Do not bypass `PolicyGuard`, runtime contract checks, approval token binding, or existing queued job tracking.
- Do not bypass `sample.ingest` size/path/sidecar handling if ingest is folded in.

## Migration Plan

Phase 1: passive `workflow.search`

- Add `src/tools/workflow-search.ts`.
- Register it in `src/core/tool-registry/utility-tools.ts` or workflow tools.
- Change `CORE_GATEWAY_TOOLS` to include `workflow.search` instead of `tools.discover`.
- Keep `sample.request_upload` and `sample.ingest` visible during this phase.
- Add tests proving `workflow.search` searches hidden core/plugin capabilities and does not activate or execute anything.

Phase 2: primary `workflow.run`

- Add `src/tools/workflow-run.ts` or `src/workflows/workflow-run.ts`.
- Register `workflow.run`.
- Use existing `analysis_runs.id` as `plan_id`.
- Return both `plan_id` and `run_id` for compatibility.
- Add unit/integration tests for start/status/promote and dynamic safety.

Phase 3: minimal default gateway

- Finalize gateway to `workflow.search`, `workflow.run`, and optionally `sample.request_upload` / `artifact.read`.
- Keep old tools hidden but registered.
- Update hidden-tool error messages to recommend `workflow.search` / `workflow.run`.
- Fix docs that still say tier 0 tools are immediately visible when implementation defaults otherwise.

Phase 4: compatibility cleanup

- Mark `tools.discover`, `workflow.analyze.*`, `tool.help`, and direct plugin tools as compatibility surfaces in descriptions/help.
- Update README, architecture docs, plugin docs, generated catalog, and sample-ingest next-action hints.
- Keep `SURFACE_PROGRESSIVE=0` as an escape hatch for old clients.

## Test Strategy

Required tests:

- `workflow.search` can find hidden core tools by canonical and transport names.
- `workflow.search` can recommend hidden plugin tools by file type/profile/query.
- `workflow.search` includes reasons, activation state, readiness state, and does not change visible tool counts.
- `workflow.run start` creates a persisted plan/run from `sample_id`.
- `workflow.run status` reports the same state as `workflow.analyze.status`.
- `workflow.run promote` queues expected stages and preserves `job_id`.
- Hidden direct plugin/core calls still fail through `ToolExecutor`.
- `SURFACE_PROGRESSIVE=0` still exposes all registered tools for compatibility.
- Dynamic/live execution remains approval and policy gated under the wrapper.

Existing test anchors:

- `tests/unit/core/tool-surface-manager.test.ts`
- `tests/unit/tools-discover.test.ts`
- `tests/unit/core/tool-executor.test.ts`
- `tests/unit/tool-help.test.ts`
- `tests/integration/workflow.test.ts`
- `tests/unit/mcp-tool-safety.test.ts`

## Decision

Proceed with implementation in the next wave by building `workflow.search` first. This yields immediate context reduction and better routing without changing execution semantics. `workflow.run` should follow only after search output and profile schema are stable enough to make execution routing predictable.
