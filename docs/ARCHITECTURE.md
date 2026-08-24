# Architecture

This document describes the current Rikune architecture as implemented in the repository.

## System Shape

```text
MCP client
  |
  | stdio
  v
Analyzer process
  src/index.ts
  src/core/server.ts
  src/core/mcp-registry.ts
  src/core/tool-executor.ts
  src/core/tool-registry.ts
  |
  | optional HTTP API / dashboard
  v
Persistence and artifacts
  SQLite
  sample workspaces
  storage manager
  job queue
  cache
  audit log
  |
  | optional runtime delegation
  v
Windows Host Agent
  packages/windows-host-agent
  |
  v
Runtime Node
  packages/runtime-node
  inside Windows Sandbox or Hyper-V VM
```

The Analyzer owns MCP, storage, plugin orchestration, static analysis, and workflow state. Runtime Node owns isolated execution. The Windows Host Agent owns sandbox or VM lifecycle.

## Entry Point

The main entry is `src/index.ts`.

Startup sequence:

1. Load configuration with `loadConfig()`.
2. Create `WorkspaceManager`, `DatabaseManager`, `PolicyGuard`, `CacheManager`, `StorageManager`, and `JobQueue`.
3. Start `AnalysisTaskRunner`.
4. Configure runtime mode:
   - `disabled`
   - `manual`
   - `remote-sandbox`
   - `auto-sandbox`
5. Create `MCPServer`.
6. Register all core tools, prompts, resources, and plugins through `registerAllTools()`.
7. Start MCP stdio transport.
8. Handle graceful shutdown for runtime clients, sandbox processes, worker pools, and server resources.

Root files such as `src/server.ts`, `src/tool-registry.ts`, and `src/plugins.ts` are compatibility forwarders. New implementation work should target `src/core/*`.

## Core Modules

| Module | Responsibility |
| --- | --- |
| `src/core/server.ts` | MCP SDK server wrapper, stdio transport, optional HTTP file server, handler registration |
| `src/core/mcp-registry.ts` | Internal registry for tools, prompts, resources, aliases, Zod-to-JSON-Schema conversion |
| `src/core/tool-executor.ts` | Tool lookup, argument validation, plugin hooks, result normalization, output-schema validation |
| `src/core/tool-registry.ts` | Registration orchestration for core tools, prompts, resources, plugins, diagnostics |
| `src/core/tool-registry/*.ts` | Domain slices for sample, artifact, workflow, task, system, utility, plugin, diagnostics, scripts |
| `src/core/plugins.ts` | Plugin manager facade and singleton access |
| `src/core/plugin-orchestrator.ts` | Built-in/external plugin discovery, dependency sort, load/unload, status tracking |
| `src/core/plugin-system/discovery.ts` | Plugin discovery from `src/plugins`, `dist/plugins`, and external `plugins/` |
| `src/core/tool-surface-manager.ts` | Progressive exposure of plugin tools |

## MCP Registry And Names

Tool definitions are registered with canonical dotted names, for example `workflow.analyze.start`. The MCP transport also exposes normalized aliases where needed. `MCPRegistry` keeps both canonical and transport-safe names so older clients can still resolve many underscore aliases.

`ToolExecutor` performs these steps for every call:

1. Resolve canonical name or alias.
2. Validate input with the tool's Zod schema.
3. Fire plugin `before` hooks.
4. Run the handler.
5. Normalize return shape.
6. Validate `structuredContent` against an output schema when present.
7. Rewrite tool references for transport-visible names.
8. Enforce response-size guards.
9. Fire plugin `after` or `error` hooks.

## Core Tool Groups

Core tools are registered before plugins, but the default AI-facing visible surface is intentionally small: `workflow.search`, `workflow.run`, and `artifact.read`. The other core tools remain registered as compatibility, specialist, or low-level inspection surfaces.

| Group | Examples |
| --- | --- |
| Gateway | `workflow.search`, `workflow.run`, `artifact.read` |
| Sample intake compatibility | `sample.ingest`, `sample.request_upload`, `sample.profile.get`, `analysis.context.get` |
| Artifacts | `artifact.read`, plus compatibility helpers `artifacts.list`, `artifacts.diff`, `artifact.download` |
| Workflow compatibility | `workflow.analyze.start`, `workflow.analyze.status`, `workflow.analyze.promote`, `workflow.analyze.auto`, `workflow.triage`, `workflow.deep_static`, `workflow.reconstruct` |
| Semantic review | `workflow.semantic_name_review`, `workflow.function_explanation_review`, `workflow.module_reconstruction_review` |
| Tasks | `task.status`, `task.cancel`, `task.sweep` |
| System | `system.health`, `system.setup.guide`, `setup.remediate` |
| Utility compatibility | `tool.help`, `tool.readiness`, `tools.discover` |
| Plugins | `plugin.list`, `plugin.enable`, `plugin.disable` |
| Diagnostics | `system.config.validate` |

## Staged Analysis Pipeline

The primary analysis path is implemented in `src/workflows/analyze-pipeline.ts` and wrapped for clients by `workflow.run`.

Stages:

1. `fast_profile`
2. `enrich_static`
3. `function_map`
4. `reconstruct`
5. `semantic_name_review`
6. `semantic_explain_review`
7. `semantic_module_review`
8. `dynamic_plan`
9. `dynamic_execute`
10. `summarize`

Externally, `workflow.run action=start` creates or reuses an analysis run and executes the initial profile. `workflow.run action=promote` queues or runs deeper stages. `workflow.run action=status` returns compact run state, stage state, evidence, coverage, pending work, and polling guidance. The direct `workflow.analyze.*` handlers remain registered as wrapped compatibility targets.

Long-running stages use `JobQueue` and `AnalysisTaskRunner`. Jobs are persisted in SQLite and restored after restart; interrupted running jobs are made visible for recovery.

The run-state layer preserves the queue `job_id` while a stage transitions from queued to running and completed. This lets `workflow.run action=status`, `task.status`, scheduler telemetry, and restart recovery describe the same underlying worker instead of treating active work as lost context.

Large workflow responses are bounded by `src/core/response-guard.ts`. The guard prunes heavyweight `raw_results` and historical stage payloads while keeping schema-valid structured content. When pruning occurs, the tool returns a top-level warning and callers should use `artifact.read` or a stage-specific tool for full detail.

## Agent Investigation State And Trust Boundaries

Long-lived Agent investigations use four separate layers:

1. Analyzer Artifacts and `AnalysisEvidence` are the only evidence-bearing layer.
2. `analysis.claims.apply` writes append-only `analysis_claim_set` revisions. AI and imported producers are restricted to `inferred` status.
3. `analysis.case.checkpoint` writes immutable full `analysis_case_state` snapshots; `analysis.case.snapshot` resumes one Case.
4. `analysis.context.pack` builds a deterministic, token-bounded view, while `workflow.summarize` persists bounded context-only digests.

Claim sets, Case states, summaries, and reports are centrally classified as context-only. They cannot be cited as Claim evidence or appear in summary source lineage. Claim overlays remain separate from deterministic Evidence Graph nodes.

Case consumers are isolated by `case_id`. A sole Case may be auto-selected, but multiple Cases require an explicit selector. Claim views are restricted to the selected Case's `active_claim_ids`; an existing but untrusted Case state causes Claims to be withheld. Active Claim resolution scans newest-to-oldest with chain, SHA-256, schema, and sample validation, bounded to 512 Claim Set Artifacts and 128 MiB. Missing IDs, integrity failures, or exhausted bounds withhold the complete Case Claim view. Context markers and final-summary reuse both bind to the selected Case and fail closed on cross-Case reuse.

Summary digest reuse is additionally bound to a versioned fingerprint covering synthesis mode, all scope/session selectors, non-context source Artifact metadata, persisted Evidence/Function/Analysis/Run/RunStage state, Claim/Case markers, and integrity-review state. Source Artifact files undergo streaming SHA-256 validation before reuse. Digests without a compatible fingerprint remain parseable but are not reuse candidates.

Claim/Case persistence uses a heartbeat-backed SQLite CAS lease outside the owner-identified filesystem lock. Stale lease takeover compares the observed owner token and heartbeat. Writers synchronously reassert ownership before the final file rename, and the Artifact row insert atomically fences on the current owner token. Stale malformed filesystem locks and stale locks from a prior host namespace are recovered through identity-checked quarantine, while recent or live local locks remain fail-closed. Workspace creation validates the configured canonical root and each shard/sample directory before any lock or Artifact write, rejecting symlink substitution.

Primary Evidence classification uses trusted family/backend/provenance combinations. Arbitrary producer metadata cannot promote a derived result. Sampling may rewrite narrative fields, but Evidence-backed findings, coverage, and source refs are rebuilt from deterministic digests.

## Runtime Worker Pool and Process Visibility

Persistent helper processes are managed by `src/worker/runtime-worker-pool.ts`. The pool keys workers by family, deployment, and compatibility, then reuses warm workers for compatible static requests. Idle workers are automatically evicted after their configured TTL; eviction does not depend on a later tool call.

The scheduler and status surfaces distinguish three related concepts:

| Concept | Surface |
| --- | --- |
| Queue state | `JobQueue`, persisted jobs, `task.status` |
| Stage state | `analysis_run_stages`, `workflow.run action=status` |
| External subprocess pressure | scheduler snapshots, `task.status.external_active_*` |

`task.status` reports bounded external analyzer subprocess telemetry (`external_active_rss_mb`, `external_active_process_count`, `external_active_processes`) so operators can see FLOSS, capa, Ghidra, Rizin, or similar work that is still consuming memory even when the in-memory queue is empty.

PE runtime function metadata is also materialized into the function index: `pe.pdata.extract` imports `.pdata` boundaries into `functions` by default, so `code.functions.list` can serve a useful function map before or without a successful Ghidra extraction.

## Persistence

Persistence is split by responsibility:

| Area | File |
| --- | --- |
| SQLite schema and CRUD | `src/persistence/database.ts` |
| Workspace layout and retention | `src/persistence/workspace-manager.ts` |
| Sample finalization | `src/sample/sample-finalization.ts` |
| Sample workspace integrity | `src/sample/sample-workspace.ts` |
| Uploads and artifacts | `src/storage/storage-manager.ts` |
| Job queue | `src/execution/job-queue.ts` |
| Analysis run state | `src/analysis/analysis-run-state.ts` |

Samples are identified by SHA-256. Workspaces are bucketed by hash prefix and contain immutable originals plus analysis-specific subdirectories.

## Plugin Architecture

Built-in plugins live under `src/plugins/<id>/`. External plugins can be discovered from the repository-level `plugins/` directory after build.

Plugins can:

- register tools;
- declare dependencies on other plugins;
- declare system dependencies;
- expose configuration schema;
- provide lifecycle hooks;
- provide Docker build metadata;
- attach runtime contracts for delegated execution;
- define progressive-surface rules.

Plugin contracts are defined in `packages/plugin-sdk/src/index.ts` and re-exported for compatibility through `src/plugins/sdk.ts`.

See [PLUGINS.md](./PLUGINS.md).

## Progressive Tool Surface

`ToolSurfaceManager` keeps the initial MCP surface small while preserving access to specialist tools.

Tiers:

| Tier | Meaning |
| --- | --- |
| 0 | Gateway-capable plugin tools, not necessarily visible unless included in the explicit gateway |
| 1 | File-type activated tools |
| 2 | Finding/signal activated tools |
| 3 | Expert tools, normally selected through `workflow.search` and exposed only through explicit activation |

Tool results can activate later tools by returning file-type, findings, or recommended-next-tool signals. The server can notify clients that the tool list changed.

## Runtime Delegation

Runtime delegation uses a contract defined in `packages/shared/src/runtime-contract.ts`.

Analyzer-side client:

- `src/runtime-client/runtime-client.ts`
- `src/runtime-client/delegation-server.ts`

Runtime-side server:

- `packages/runtime-node/src/index.ts`
- `packages/runtime-node/src/router.ts`
- `packages/runtime-node/src/executor.ts`

Host lifecycle:

- `packages/windows-host-agent/src/index.ts`

Execution modes include plan-only, safe simulation, emulation, live sandbox, live Hyper-V, and manual runtime. Live execution is gated by policy and should run only in an isolated runtime environment.

## HTTP API And Dashboard

`src/api/file-server.ts` hosts the dashboard and API when enabled.

Important endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/api/v1/health` | Liveness |
| `/api/v1/ready` | Database, queue, runtime, and plugin readiness |
| `/api/v1/events` | SSE events |
| `/api/v1/samples` | Multipart/direct upload |
| `/api/v1/uploads/:token` | Durable upload session |
| `/api/v1/artifacts` | Artifact listing |
| `/api/v1/artifacts/:id` | Artifact read/delete |

When the HTTP API is enabled, the API layer requires a non-empty API key and also applies rate limiting, security headers, and CORS constraints.

## Safe Command Execution

`src/infrastructure/safe-command.ts` centralizes command execution helpers. The project favors structured process APIs such as `execFile` and `spawn` over shell strings, validates command names, and keeps format-specific allowlists where needed.

Policy-sensitive actions are guarded by `src/routing/policy-guard.ts`.

## Worker Processes

Python and Ghidra work are isolated from MCP request handling:

- `src/worker/python-process-pool.ts` manages Python process execution with concurrency, queueing, timeouts, and kill behavior.
- `src/worker/decompiler-worker.ts` integrates Ghidra headless analysis, function extraction, decompilation, CFG, xrefs, diagnostics, and project lock retries.
- `workers/` contains Python analysis workers and rules.

## Docker Generation

Docker files are generated from templates and plugin metadata.

Key files:

- `scripts/generate-docker.mjs`
- `docker/Dockerfile.template`
- `docker-compose.analyzer.yml`
- `docker-compose.hybrid.yml`
- `docker-compose.yml`

Profiles:

| Profile | Analyzer | Runtime |
| --- | --- | --- |
| `static` | Linux Docker analyzer | runtime disabled |
| `hybrid` | Linux Docker analyzer | Windows Host Agent plus Sandbox or Hyper-V |
| `full` | Linux Docker full toolchain | runtime disabled unless configured |
| Windows native | Windows Node process | local `auto-sandbox` possible |

## Prompts And Resources

Prompt definitions are registered in `src/core/tool-registry/prompts.ts`.

Registered prompt families:

- `reverse.semantic_name_review`
- `reverse.function_explanation_review`
- `reverse.module_reconstruction_review`

Script resources are registered from `src/core/tool-registry/script-resource-manifest.ts`. They expose Frida and Ghidra helper scripts through MCP `resources/list` and `resources/read`.

## Testing Surface

Test configuration:

- `jest.config.js`
- `tests/jest.setup.ts`
- unit tests under `tests/unit`
- integration tests under `tests/integration`
- e2e tests under `tests/e2e`

Common commands:

```bash
npm test
npm run test:unit
npm run test:integration
npm run test:e2e
npm run test:agent-case:e2e -- --help
npm run typecheck
```

Golden fixture policy:

- `tests/fixtures/golden-samples.manifest.json` is the default regression corpus contract.
- Default CI fixtures are synthetic or metadata-only and must not require host execution.
- The manifest covers PE fast profile, suspected packed PE, .NET, DLL, ELF, Mach-O, APK, and missing optional backend degradation.
- Integration tests should prefer generated minimal samples and mocked backend readiness so optional tools such as Ghidra, Docker, Windows Sandbox, Hyper-V, YARA-X, and Rizin are not required for the default path.
- Real samples and live runtime validation are opt-in only and must stay outside the repository unless they are benign, reproducible, and documented with generation steps.
