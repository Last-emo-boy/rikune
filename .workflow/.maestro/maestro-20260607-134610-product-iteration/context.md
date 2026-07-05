# Maestro Product Iteration Session

Session: `maestro-20260607-134610-product-iteration`

Objective: continuously iterate Rikune with subagents and record progress through Maestro session files.

## Initial Subagent Findings

- Core/plugin surface: plugin `register()` return values can drift from actual registered tools; tier 0 surface semantics differ between SDK docs and implementation; `ToolResult.structuredContent` does not drive surface expansion; hot unload does not remove plugin surface entries.
- Workflow/persistence: analysis run compatibility does not include `allow_live_execution` or `allow_transformations`; run status can infer `completed` from materialized stage rows only; `finished_at` can be set when the run is not terminal; restart recovery is split between `JobQueue` and run summary reconciliation.
- Runtime/security: runtime delegation can bypass local handler `PolicyGuard`; Host Agent and Runtime Node can run without API keys; explicit sidecars can read arbitrary Analyzer-local paths; runtime artifact staging can copy arbitrary existing worker-returned paths by basename.
- Tests/CI: build and unit tests are hard gates; lint, integration, coverage, and audits are soft gates; `tests/node/*.integration.mjs` is not covered by the normal Jest/CI path.

## Iteration Queue

1. Enforce runtime delegation policy gates.
2. Fix staged analysis authorization compatibility and run status inference.
3. Reduce plugin surface drift and registration mismatch.
4. Add or adjust targeted tests for each fix.

## Progress Log

- 2026-06-07 13:46:10 +08: Created Maestro session and seeded first product iteration queue from subagent reading reports.
- 2026-06-07 13:55:44 +08: Wave 1 implementation completed. Runtime delegation now enforces local `PolicyGuard` before contract validation, sample upload, or remote execution. Analysis run compatibility now includes `allow_live_execution` and `allow_transformations`, and nonterminal summaries clear stale `finished_at`. Tool execution now feeds `ToolResult.structuredContent` into surface expansion.
- 2026-06-07 13:55:44 +08: Wave 2 verification passed with `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/runtime-client/delegation-server.test.ts tests/unit/core/tool-executor.test.ts tests/unit/analysis-run-state.test.ts tests/unit/nonblocking-analysis-core.test.ts tests/unit/policy-guard.test.ts tests/unit/sandbox-execute.test.ts`, `npm test -- --runInBand --forceExit --runTestsByPath tests/integration/workflow.test.ts`, `npm run typecheck`, `npx tsc --noEmit --pretty false`, and `git diff --check`. `git diff --check` reported only LF-to-CRLF warnings for existing files.
- 2026-06-07 13:58:54 +08: Wave 3 started with four worker subagents: Auth Defaults, Sidecar Containment, Runtime Artifact Containment, and Hot Unload Surface Cleanup. Initial local scan confirmed the target risk areas: Host Agent defaults to `0.0.0.0` and can allow missing API key; Runtime Node missing API key currently warns in production; runtime artifact staging copies worker-returned paths into outbox without source containment; plugin unload unregisters tools but does not clear `ToolSurfaceManager` state.
- 2026-06-07 14:09:07 +08: Wave 3 implementation completed. Runtime Node now defaults to `127.0.0.1` and refuses production or non-loopback startup without `RUNTIME_API_KEY`; Host Agent now defaults to loopback and fails fast without `HOST_AGENT_API_KEY` when production or non-loopback. Auto-sandbox now refuses missing `runtime.apiKey` and passes it into `buildWsbXml`. Explicit sidecars are contained to the sample directory, Runtime Node artifact staging is contained to current task inbox/outbox, and plugin hot unload clears `ToolSurfaceManager` state.
- 2026-06-07 14:09:07 +08: Wave 4 verification passed with touched-path unit tests (`11 suites / 110 tests`), `npm --workspace @rikune/runtime-node test`, `npm --workspace @rikune/windows-host-agent test`, `npm run typecheck`, `npx tsc --noEmit --pretty false`, runtime client/shared regression tests (`4 suites / 26 tests`), and `git diff --check`. `git diff --check` reported only existing LF-to-CRLF warnings.
- 2026-06-07 14:11:26 +08: Wave 5 started with four worker subagents: Sidecar Warning Propagation, Runtime Capability Validation, Approval Token Binding, and Node Integration Verification. These map directly to the next iteration candidates from Wave 4.
- 2026-06-07 14:42:35 +08: Wave 5 implementation completed. Delegated runtime results now surface sidecar warnings, runtime contract support is matched deeply through shared matcher APIs, approval tokens are bound to operation and runtime context, and `tests/node` now has npm scripts plus a CI safe-mode entrypoint.
- 2026-06-07 14:42:35 +08: Wave 6 verification passed with `npm run build:shared`, Wave 5 targeted Jest suite (`8 suites / 119 tests`), `npm run build`, `npm run test:node -- --list`, `npm run test:node` (`passed=11 failed=0 skipped=0`), `npm run typecheck`, `npx tsc --noEmit --pretty false`, and `git diff --check`. The first combined Jest attempt exposed a Windows temp directory cleanup timeout in `sidecar-staging.test.ts`; the cleanup hook now uses `fs.rm` retries and a 30s timeout. `git diff --check` reported only LF-to-CRLF warnings.
- 2026-06-07 15:05:24 +08: Wave 7 planning completed. Four read-only subagents mapped the current capability inventory, progressive surface mechanics, profile-search data sources, and implementation path for converging the default MCP surface toward `workflow.search` and `workflow.run`. The consolidated plan is recorded in `tool-surface-consolidation-plan.md`.
- 2026-06-07 15:15:04 +08: Wave 8 implementation completed. Added passive `workflow.search` as the default profile-search gateway, wired it through utility tool registration, moved the default gateway from `tools.discover` to `workflow.search`, kept `tools.discover` as a hidden compatibility activator, updated hidden-tool guidance to point to `workflow.search`, added a `ToolSurfaceManager` passive guard for `workflow.search`, and added regression tests proving search can find hidden plugin/core capabilities without activating or auto-expanding them.
- 2026-06-07 15:23:25 +08: Wave 9 implementation completed. Added `workflow.run` as a compact execution gateway with whitelisted `start/status/promote` actions over `workflow.analyze.start/status/promote`, mapped external `plan_id` to persisted `analysis_runs.id`/`run_id`, kept raw routed results opt-in, and reduced the default visible gateway to `sample.request_upload`, `workflow.search`, `workflow.run`, and `artifact.read`.
- 2026-06-07 15:27:55 +08: Wave 10 implementation completed. Updated sample upload/ingest outputs, system health recommendations, tool readiness surface guidance, and tool help classification so primary next steps route through `workflow.search` / `workflow.run` instead of hidden `workflow.analyze.*` tools.
- 2026-06-07 15:34:13 +08: Wave 11 implementation completed. Added `workflow.run action=request_upload` to create upload sessions through the existing `sample.request_upload` handler, removed `sample.request_upload` from `CORE_GATEWAY_TOOLS`, updated sample prerequisite hints, and verified the default visible gateway is now `workflow.search`, `workflow.run`, and `artifact.read`.
- 2026-06-07 15:43:18 +08: Wave 12 implementation completed. Enhanced `workflow.search` with passive profile reranking before `top_k`, using extension/sample profile tags, query terms, goal/depth/finding aliases, workflow metadata, recommended tools, and readiness state. Targeted and broader adjacent Jest suites, root TypeScript, and diff checks passed.
- 2026-06-07 16:18:35 +08: Wave 13 implementation completed. Demoted remaining sample upload/ingest, task status, tool help/readiness, sample profile routing, and `workflow.summarize` guidance to compatibility semantics. The primary recommended surface is now consistently `workflow.search`, `workflow.run`, and `artifact.read`. The closure pass verified the 11-suite surface/gateway regression set (`101 tests`), root TypeScript, targeted diff check, and a legacy primary-path scan.
- 2026-06-07 16:37:21 +08: Wave 14 implementation completed. `workflow.search action=activate` now owns controlled activation, hidden `tools.discover` is no longer the recommended activation path, default primary role classification is whitelist-only, and README/generated docs now align on the three-tool gateway. Verification passed for the targeted 14-suite regression set (`119 tests`), generated tool catalog, root TypeScript, targeted diff check, and legacy drift scans.

## Wave 1 Implementation Summary

- Runtime/security: delegated runtime paths now share the same local policy gate as nondelegated handlers.
- Workflow/persistence: run reuse and status derivation now account for authorization-affecting inputs and the full planned stage list.
- Core/plugin surface: ToolResult payloads can reveal newly available hidden tools through `structuredContent`, reducing surface drift.

## Wave 3 Implementation Summary

- Runtime/auth defaults: Host Agent and Runtime Node now treat remote exposure and production mode as authenticated-only, while preserving unauthenticated loopback development.
- Auto-sandbox integration: analyzer-side Windows Sandbox launch now requires `runtime.apiKey` and passes it into the sandbox Runtime Node configuration.
- Runtime upload boundaries: explicit sidecar paths are constrained to the sample directory using lexical and realpath checks.
- Runtime artifact boundaries: worker-returned artifact paths are staged only when they are inside the current task inbox or outbox.
- Plugin lifecycle: hot unload unregisters plugin surface state so hidden/discoverable/activated state cannot survive after tools are removed.

## Wave 5 Implementation Summary

- Runtime warning propagation: sidecar staging warnings are appended to delegated runtime `ToolResult` payloads, including `structuredContent.warnings` and text JSON.
- Runtime capability validation: shared contract matching now validates declared `modes`, `requiredTools`, `isolation`, and `policy` support instead of only `type + handler`.
- Approval safety: approval tokens are bound to dangerous operation type, tool, sample, normalized args hash, and runtime/capability context; `approved=true` remains only as a no-token legacy fallback.
- Verification hardening: `tests/node/*.integration.mjs` now run through `npm run test:node`, with `--list` support and a CI safe-mode step after build.
- Test stability: `sidecar-staging.test.ts` cleanup now retries Windows temp directory removal and allows a longer hook timeout.

## Wave 7 Tool Surface Plan

- Current state: Rikune already has a progressive surface. `tools/list` is filtered by `ToolSurfaceManager`, and hidden tool calls are blocked by `ToolExecutor`.
- Current gateway: `sample.request_upload`, `sample.ingest`, and `tools.discover`.
- Capability metadata is strong enough for profile search: plugin/tool `formats`, `platforms`, `architectures`, `execution`, `runtimes`, `capabilities`, `evidence`, `workflowRecipes`, runtime policy, worker backend, and artifact/evidence declarations.
- Target default gateway: `workflow.search`, `workflow.run`, and optionally `sample.request_upload` / `artifact.read` depending on upload and artifact selector ergonomics.
- `workflow.search` should be passive: no activation, no backend execution, no live readiness side effects.
- `workflow.run` should be a whitelisted workflow wrapper over existing staged handlers, not an arbitrary `tool_name` invoker.
- Existing `analysis_runs.id` can become external `plan_id`; no new DB key is needed.
- Implementation should start with passive `workflow.search`, then add `workflow.run`, then hide compatibility surfaces by default.

## Wave 8 Implementation Summary

- `workflow.search`: passive profile-search gateway over existing discovery metadata. It accepts query, sample/file type hints, goal/depth, category/plugin/tool filters, finding hints, and `top_k`.
- Default surface after Wave 8: core gateway exposed `sample.request_upload`, `sample.ingest`, and `workflow.search`; `tools.discover` remained registered but was no longer the default visible entry.
- Context reduction: `workflow.search` is marked as a sample entry tool, so registry descriptions do not append upload prerequisite noise just because the schema accepts `sample_id`.
- Safety: `workflow.search` does not return top-level `recommended_next_tools` or `file_type`, and `ToolSurfaceManager` explicitly skips `workflow.search` auto-expansion so future plugin `signalMap` fields cannot turn search output into an activation signal.
- Guidance: hidden direct tool calls now instruct callers to use `workflow.search` for routing, readiness, and activation requirements instead of pointing first at hidden `tools.discover`.
- Verification: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/workflow-search.test.ts tests/unit/tools-discover.test.ts tests/unit/core/tool-surface-manager.test.ts tests/unit/core/tool-executor.test.ts tests/unit/mcp-tool-safety.test.ts`, `npx tsc --noEmit --pretty false`, and targeted `git diff --check` passed.

## Wave 9 Implementation Summary

- `workflow.run`: compact execution gateway with fixed `action=start|status|promote`; it does not accept arbitrary `tool_name`.
- Routing: `start` calls `workflow.analyze.start`, `status` calls `workflow.analyze.status`, and `promote` calls `workflow.analyze.promote`.
- Plan ID: public `plan_id` maps directly to persisted `analysis_runs.id` / internal `run_id`; no new DB key was introduced.
- Output: default output is compact workflow state (`plan_id`, `status`, stage, coverage, next actions). Full routed result is opt-in via `include_raw_result=true`.
- Default surface: core gateway now exposes `sample.request_upload`, `workflow.search`, `workflow.run`, and `artifact.read`; `sample.ingest`, `tools.discover`, and `workflow.analyze.*` remain registered but hidden by default.
- Safety: `ToolSurfaceManager` skips auto-expansion for both `workflow.search` and `workflow.run`, so result fields cannot accidentally expose specialist tools.
- Verification: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/workflow-run.test.ts tests/unit/workflow-search.test.ts tests/unit/tools-discover.test.ts tests/unit/core/tool-surface-manager.test.ts tests/unit/core/tool-executor.test.ts tests/unit/core/mcp-registry.test.ts tests/unit/mcp-tool-safety.test.ts`, `npx tsc --noEmit --pretty false`, and targeted `git diff --check` passed.

## Wave 10 Implementation Summary

- Sample intake guidance: `sample.request_upload` and `sample.ingest` now recommend `workflow.run`, `workflow.search`, and `artifact.read` instead of direct `workflow.analyze.*` / `workflow.triage`.
- Health guidance: healthy `system.health` now recommends `workflow.search`, `workflow.run`, and `artifact.read`.
- Surface guidance: `workflow.analyze.auto/start/status/promote`, `workflow.triage`, and `task.status` are classified as compatibility surfaces with `workflow.run` as preferred primary replacement.
- Verification: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/sample-request-upload.test.ts tests/unit/system-health.test.ts tests/unit/tool-readiness.test.ts tests/unit/tool-help.test.ts tests/unit/task-tools.test.ts tests/unit/workflow-run.test.ts tests/unit/workflow-search.test.ts tests/unit/core/tool-surface-manager.test.ts`, `npx tsc --noEmit --pretty false`, and targeted `git diff --check` passed.

## Wave 11 Implementation Summary

- `workflow.run action=request_upload`: creates upload sessions via the existing `sample.request_upload` handler and returns compact upload fields (`upload_url`, `status_url`, `token`, `expires_at`, `ttl_seconds`).
- Default surface: `CORE_GATEWAY_TOOLS` is now exactly `workflow.search`, `workflow.run`, and `artifact.read`.
- Compatibility: `sample.request_upload` remains registered and discoverable/activatable, but is no longer a default visible tool.
- Prerequisite hint: generic sample prerequisites now tell clients to use `workflow.run action=request_upload` and then `workflow.run action=start`.
- Verification: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/workflow-run.test.ts tests/unit/workflow-search.test.ts tests/unit/tools-discover.test.ts tests/unit/core/tool-surface-manager.test.ts tests/unit/core/tool-executor.test.ts tests/unit/core/mcp-registry.test.ts tests/unit/mcp-tool-safety.test.ts tests/unit/sample-request-upload.test.ts tests/unit/sample-ingest.test.ts tests/unit/sample.test.ts tests/unit/system-health.test.ts tests/unit/tool-readiness.test.ts tests/unit/tool-help.test.ts tests/unit/task-tools.test.ts`, `npx tsc --noEmit --pretty false`, and targeted `git diff --check` passed.

## Wave 12 Implementation Summary

- `workflow.search` now reranks `tools.discover` candidates before slicing `top_k`.
- Rerank signals include normalized file/profile tags such as `.exe -> pe/exe/windows`, query/tool/plugin/category terms, goal/depth/finding aliases, workflow recipes, recommended/available tools, and readiness penalties.
- Compact results now include richer `score_breakdown`, `matched_profile_fields`, `recommended_tools`, `available_tools`, and `blocked_tools`, without adding top-level `recommended_next_tools` or `file_type`.
- Regression coverage verifies `.exe + reverse` ranks the PE workflow ahead of a generic Windows profile, `bytecode handler recovery` ranks the JSVMP workflow, and hidden tools remain invisible.
- Verification: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/workflow-search.test.ts tests/unit/tools-discover.test.ts tests/unit/core/tool-surface-manager.test.ts`, the broader adjacent 14-suite workflow/surface/sample/readiness/help suite (`120 tests`), `npx tsc --noEmit --pretty false`, and `git diff --check -- src/tools/workflow-search.ts tests/unit/workflow-search.test.ts` passed.

## Wave 13 Implementation Summary

- Primary surface guidance is now narrowed to `workflow.search`, `workflow.run`, and `artifact.read`.
- `sample.request_upload`, `sample.ingest`, `task.status`, `tool.help`, `tool.readiness`, `sample.profile.get`, and `workflow.summarize` now describe themselves or route next steps as compatibility surfaces instead of primary entrypoints.
- `report.generate` and `graphviz.render` guidance now prefers the minimal gateway path through `workflow.search` / `artifact.read` rather than expanding direct tool exposure.
- The legacy-guidance scan only matched `tool-help.ts` wording for the `workflow.run action=request_upload` primary host-file path, which is the intended gateway route.
- Verification: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/sample-request-upload.test.ts tests/unit/sample-ingest.test.ts tests/unit/task-tools.test.ts tests/unit/tool-help.test.ts tests/unit/tool-readiness.test.ts tests/unit/workflow-summarize.test.ts tests/unit/sample-profile-get.test.ts tests/unit/tools-discover.test.ts tests/unit/workflow-search.test.ts tests/unit/workflow-run.test.ts tests/unit/core/tool-surface-manager.test.ts` passed (`11 suites / 101 tests`), `npx tsc --noEmit --pretty false` passed, and targeted `git diff --check` passed.

## Wave 14 Implementation Summary

- Controlled activation now routes through `workflow.search action=activate`, which internally reuses `tools.discover action=activate` without exposing hidden activation tooling as the normal next step.
- `workflow.search` activation output keeps the activation audit and activated tool list while avoiding top-level broad recommendation fields.
- `workflow.run` normalizes wrapped workflow recommendations back to `workflow.run`, `workflow.search`, and `artifact.read`.
- Primary tool classification is whitelist-only: only `workflow.search`, `workflow.run`, and `artifact.read` are primary by default; unclassified tools default to compatibility.
- `tools.discover`, tool readiness, system health, analyze/triage workflow descriptions, plugin workflow recommendations, README, generated docs, and the catalog generator now describe the three-tool gateway as the default path.
- Verification: the targeted 14-suite gateway/surface regression set passed (`119 tests`), `npm run docs:tool-catalog` regenerated the catalog successfully, `npx tsc --noEmit --pretty false` passed, targeted `git diff --check` passed with only LF-to-CRLF warnings in generated/static docs, and two drift scans returned no legacy primary-path matches.

## Next Iteration Candidates

1. Add real Windows Sandbox and Hyper-V smoke verification for hardened auth defaults.
2. Populate runtime backend inventories with explicit `modes`, `requiredTools`, `isolation`, and `policy` metadata.
3. Migrate remaining legacy `approved=true` callers toward token-only approval.
4. Promote more soft gates such as lint, coverage, and audit into regular verification.
5. Reduce noisy plugin discovery logs in targeted unit and node integration tests.

## Closure Record 2026-06-09

- Branch at closure: `beta-minimize-tool-surface`, ahead of `origin/beta-minimize-tool-surface` by 34 commits.
- Recent scoped commits recorded for this iteration:
  - `f359671 feat: 深化 html report artifact 交接`
  - `051c1e7 feat: 深化样本家族聚类交接`
- Iteration stop condition: user explicitly requested entering closure and no further implementation iteration. Do not continue into `sample.cluster.fuzzy` or other plugin deepening work in this session.
- Completed plugin handoff improvements:
  - `report.html.generate` now registers a stable `html_report` artifact and returns `artifact_read` / `workflow_handoff.read_args` guidance; unit coverage includes `artifact.read` round-trip behavior.
  - `sample.family.cluster` now emits `rikune.sample_family_cluster.v1` with `evidence_summary`, `workflow_handoff`, `route_profile`, and `quality_gates`; recipe next-tool guidance was updated.
- Verification recorded as passed:
  - `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/report-html-generate.test.ts`
  - `npx prettier --check src/plugins/visualization/tools/report-html-generate.ts tests/unit/report-html-generate.test.ts`
  - `npx eslint src/plugins/visualization/tools/report-html-generate.ts tests/unit/report-html-generate.test.ts --quiet --no-error-on-unmatched-pattern`
  - `git diff --check -- src/plugins/visualization/tools/report-html-generate.ts tests/unit/report-html-generate.test.ts`
  - `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/sample-family-cluster.test.ts`
  - `npx prettier --check src/plugins/similarity/tools/sample-family-cluster.ts tests/unit/sample-family-cluster.test.ts`
  - `npx eslint src/plugins/similarity/tools/sample-family-cluster.ts tests/unit/sample-family-cluster.test.ts --quiet --no-error-on-unmatched-pattern`
  - `git diff --check -- src/plugins/similarity/tools/sample-family-cluster.ts tests/unit/sample-family-cluster.test.ts`
