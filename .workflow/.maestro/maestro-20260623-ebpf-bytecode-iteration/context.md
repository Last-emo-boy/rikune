# Maestro eBPF Bytecode Iteration

Session: `maestro-20260623-ebpf-bytecode-iteration`

Branch: `feat/ebpf-bytecode-analyzer`

Objective: add a passive eBPF bytecode static-analysis capability to broaden Rikune's binary-analysis surface without expanding the default MCP gateway beyond `workflow.search`, `workflow.run`, and `artifact.read`.

## Subagent Findings

- Plugin pattern: follow the passive `bytecode` / `wasm` two-file plugin layout with `definePlugin`, `defineTool`, bounded reads, optional artifact persistence, workflow recipes, evidence metadata, and strict runtime policy.
- Analysis schema: expose compact instruction decode, helper calls, map/BTF pseudo-load hints, control-flow facts, verifier-relevant passive prechecks, risk flags, and workflow handoff. Never report `verifier_passed`.
- Verification: prove parser usefulness, passive safety boundaries, built-in discovery, file-type normalization, and `workflow.search` recommendation without auto-activating hidden tools.

## Implementation Scope

- Add `src/plugins/ebpf-bytecode` with `ebpf.bytecode.inventory`.
- Detect `.bpf/.ebpf` raw streams as `eBPF-Bytecode` and ELF `EM_BPF` objects as `eBPF-ELF`.
- Add `SURFACE_FILE_TYPE_TAGS` for `ebpf`, `bpf`, `raw-ebpf`, `ebpf-elf`, and common program-type tags.
- Keep runtime follow-up plan-only through `linux.runtime.plan` / `tool.readiness`.
- Update Docker compose plugin allowlists and plugin-count docs.

## Verification Plan

- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/ebpf-bytecode-inventory.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/packages/plugin-sdk.test.ts tests/unit/workflow-search.test.ts`
- `npx tsc --noEmit --pretty false`
- `git diff --check`

## Verification Results

- Passed: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/ebpf-bytecode-inventory.test.ts tests/unit/packages/plugin-sdk.test.ts tests/unit/workflow-search.test.ts` (3 suites, 38 tests).
- Passed: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/plugin-format-matrix.test.ts -t "detects AppImage|detects object|discovers cross-platform|discovers native reverse"` (4 focused tests).
- Passed: `git diff --check`.
- Checked: `npx tsc --noEmit --pretty false` reports no `src/plugins/ebpf-bytecode` diagnostics. The repository baseline still reports 40 TypeScript diagnostic lines, including unresolved `@rikune/shared` workspace types and pre-existing plugin schema strictness issues.
- Known baseline failure: full `tests/unit/plugin-format-matrix.test.ts` still fails `release guard covers completed capability workflow recipes` because `kb-collaboration` starts with `kb.context.suggest` but the guard expects both `kb.context.suggest` and `analysis.notes`.
