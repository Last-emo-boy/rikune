# Frontier Worker Integration

Date: 2026-05-23

This Maestro task set turns the 2026-05-23 frontier plugin suite from plan-only plugin surfaces into bounded Worker-backed plugin capabilities.

The existing plan-only tools remain useful as triage and handoff surfaces, but the next iteration must add real execution paths under strict policy gates:

- Static workers may process local artifacts only, with size limits, timeouts, pinned backend metadata, structured output, and fixture tests.
- Read-only native IR workers may launch external backends only through the shared worker contract and must not mutate binaries.
- Runtime workers must require explicit analyst opt-in, delegated isolation, and readiness proof before any sample execution or instrumentation.
- Discovery, help, readiness, profile, and plan paths must never start external backends.

Primary implementation anchors:

- `src/plugins/backend-plan.ts`
- `src/plugins/sdk.ts`
- `packages/plugin-sdk/src/index.ts`
- `src/tools/tool-readiness.ts`
- `src/tools/tools-discover.ts`
- `src/tools/plugin-list.ts`
- `src/tools/static-worker-client.ts`
- `src/worker/runtime-worker-pool.ts`
- `src/worker/python-process-pool.ts`
- `tests/unit/backend-plan-plugins.test.ts`
- `tests/unit/plugin-format-matrix.test.ts`
- `tests/unit/tool-readiness.test.ts`
- `tests/unit/static-worker-client.test.ts`

Worker priority:

1. Shared bounded worker contract and readiness surface.
2. Static JavaScript workers: REstringer, JSIMPLIFIER, JSIR/CASCADE.
3. Read-only native IR workers: GTIRB, Remill, Manifold fact extraction.
4. Runtime-gated and specialized workers: QBDI, CuLifter.
5. Release guard: tests, docs, plugin matrix, changelog, and Maestro status.

Non-goals:

- Do not execute samples from plan, profile, readiness, help, plugin list, or discovery tools.
- Do not make heavy external backends mandatory startup dependencies.
- Do not download backend repos, submit samples, mount images, attach debuggers, inject instrumentation, or load GPU drivers in default tests.
- Do not remove the existing plan-only tools; add explicit Worker tools beside them.

## Execution Report

Completed on 2026-05-23.

Implemented:

- Added `backend-worker.v1` SDK and internal metadata via `workerBackend`.
- Added a shared backend Worker client with passive readiness checks and builtin fixture-safe execution.
- Exposed Worker metadata through `plugin.list`, `tools.discover`, `tool.help`, `tool.readiness`, and the tool aspect matrix.
- Added explicit Worker tools beside existing plan-only tools:
  - `restringer.deobfuscation.run`
  - `jsimplifier.pipeline.run`
  - `jsir.cascade.normalize`
  - `gtirb.ir.generate`
  - `remill.lift.run`
  - `manifold.fact.extract`
  - `qbdi.trace.run`
  - `culifter.gpu.artifact.inventory`
- Preserved passive defaults: readiness/discovery/help/list do not start external backends. QBDI remains delegated-runtime and requires explicit approval/isolation.
- Updated README, SDK docs, plugin matrix docs, CHANGELOG, release-guard tests, `tasks.csv`, `results.csv`, and all `TASK-039` through `TASK-050` JSON states.

Verification:

- `npm test -- --runTestsByPath tests/unit/backend-worker-contract.test.ts tests/unit/static-worker-client.test.ts tests/unit/tool-readiness.test.ts`
- `npm test -- --runTestsByPath tests/unit/restringer-worker.test.ts tests/unit/jsimplifier-worker.test.ts tests/unit/jsir-cascade-worker.test.ts`
- `npm test -- --runTestsByPath tests/unit/gtirb-worker.test.ts tests/unit/remill-worker.test.ts tests/unit/manifold-worker.test.ts`
- `npm test -- --runTestsByPath tests/unit/qbdi-worker.test.ts tests/unit/culifter-worker.test.ts`
- `npm test -- --runTestsByPath tests/unit/backend-plan-plugins.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/plugin-list.test.ts tests/unit/tools-discover.test.ts`
- `npm test -- --runTestsByPath tests/unit/backend-worker-contract.test.ts tests/unit/frontier-worker-plugins.test.ts tests/unit/tool-readiness.test.ts tests/unit/plugin-list.test.ts tests/unit/tools-discover.test.ts tests/unit/tool-help.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/backend-plan-plugins.test.ts`
- `npm run typecheck`
- `npm run lint`
