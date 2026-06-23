# Maestro LLVM Bitcode Iteration

Session: `maestro-20260623-llvm-bitcode-iteration`

Branch: `feat/llvm-bitcode-inventory`

Objective: add a passive LLVM bitcode inventory capability so Rikune can inspect IR-level artifacts produced by compilers, Apple bitcode workflows, or lifting backends without requiring LLVM tools or executing samples.

## Initial Scope

- Add `src/plugins/llvm-bitcode` with `llvm.bitcode.inventory`.
- Detect raw LLVM bitcode streams and LLVM bitcode wrapper files.
- Provide passive structure evidence: magic/container type, wrapper offsets/sizes, bitstream block and record summaries, string hints, and workflow handoff.
- Keep default MCP gateway limited to `workflow.search`, `workflow.run`, and `artifact.read`.

## Verification Plan

- Targeted plugin unit tests for raw bitstream and wrapper fixtures.
- Plugin SDK file-type tags and workflow search tests for `llvm-bitcode` routing.
- `git diff --check`.

## Subagent Findings

- Plugin pattern: follow passive `bytecode` / `wasm` inventory layout with `definePlugin`, `defineTool`, bounded reads, artifact persistence, workflow recipes, and strict static safety metadata.
- Schema: output raw/wrapper detection, wrapper bounds, bitstream block/record summaries, string/toolchain hints, risk flags, quality gates, and workflow handoff.
- Verification: prove parser behavior, sample type detection, SDK file-type normalization, `workflow.search` routing, and default gateway containment. One verification subagent did not call `report_agent_job_result`; main agent completed the verification scope directly.

## Verification Results

- Passed: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/llvm-bitcode-inventory.test.ts tests/unit/packages/plugin-sdk.test.ts tests/unit/workflow-search.test.ts` (3 suites, 39 tests).
- Passed: `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/plugin-format-matrix.test.ts -t "detects AppImage|builds LLVM bitcode|discovers cross-platform"` (3 focused tests).
- Passed: `git diff --check`.
- Checked: `npx tsc --noEmit --pretty false` reports no LLVM bitcode iteration diagnostics. The repository baseline still reports 40 TypeScript diagnostic lines.
- Known baseline failure: full `tests/unit/plugin-format-matrix.test.ts` still fails `release guard covers completed capability workflow recipes` because `kb-collaboration` starts with `kb.context.suggest` but the guard expects both `kb.context.suggest` and `analysis.notes`.
