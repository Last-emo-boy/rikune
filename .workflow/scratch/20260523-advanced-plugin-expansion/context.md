# Advanced Plugin Expansion Maestro Task

## Summary

Added a plan-only advanced plugin expansion wave after Plugin Standard v2.

- Plan: `.workflow/scratch/20260523-advanced-plugin-expansion/plan.json`
- Tasks: `.workflow/scratch/20260523-advanced-plugin-expansion/tasks.csv`
- Results: `.workflow/scratch/20260523-advanced-plugin-expansion/results.csv`

## External Signals

- `google/jsir`: current JavaScript analysis tooling, active on 2026-05-20.
- `CASCADE`: 2026 ICSE-SEIP JavaScript deobfuscation paper using JSIR and LLM-assisted recovery.
- `JSIMPLIFIER`: 2026 NDSS JavaScript deobfuscation pipeline and benchmark direction.
- `HumanSecurity/restringer`: JavaScript deobfuscator, still relevant as an optional static backend.
- `revng/revng`: active rev.ng core repository for lift/decompile workflows.
- `JonathanSalwan/Triton`: active symbolic/dynamic binary analysis framework.
- `cea-sec/miasm`: active Python reverse-engineering framework for IR and data-flow work.
- `lief-project/LIEF`: active executable format parsing/instrumentation library for PE/ELF/Mach-O/object review.
- `radareorg/radare2`: active reverse-engineering framework and r2pipe-compatible cross-backend comparison candidate.
- `WebAssembly/wabt`: active WebAssembly Binary Toolkit for wasm2wat, wasm-objdump, wasm-decompile, and wasm2c workflows.

## Implemented Direction

1. `javascript-deobfuscation`
   - Adds `javascript.obfuscation.profile`.
   - Covers JavaScript, source maps, V8 cache, JSIR/CASCADE, REstringer, and JSVMP-style VM dispatch triage.
   - Default boundary: no JavaScript execution, no Node/V8/browser start, no network, no external deobfuscator invocation.

2. `revng`
   - Adds `revng.pipeline.plan`.
   - Covers lift/decompile/cross-backend comparison planning.
   - Default boundary: no rev.ng process, no lifting, no decompile.

3. `triton`
   - Adds `triton.symbolic.plan`.
   - Covers symbolic execution, taint, path constraints, and VM-analysis handoff planning.
   - Default boundary: no Triton, Unicorn, solver, or emulation start.

4. `miasm`
   - Adds `miasm.ir.plan`.
   - Covers IR lifting, data-flow, symbolic and deobfuscation planning.
   - Default boundary: no Python backend start, no IR lift execution.

5. `jsvmp-analysis`
   - Adds `jsvmp.bytecode.plan`.
   - Covers bytecode containers, dispatch loops, handler maps, stack/register semantics, and JSIMPLIFIER-style future worker design.
   - Default boundary: no JavaScript execution, no interpreter-assisted normalization, no Node/V8/browser start.

6. `lief`
   - Adds `lief.binary.plan`.
   - Covers cross-format binary structure, signing, relocation, import/export, and mutation-boundary planning.
   - Default boundary: no LIEF process/import, no binary parsing through backend, no binary mutation.

7. `radare2`
   - Adds `radare2.pipeline.plan`.
   - Covers r2pipe command planning and cross-backend function/xref comparison.
   - Default boundary: no radare2 process, no r2pipe command execution, no debugger attach.

8. `wabt`
   - Adds `wabt.toolchain.plan`.
   - Covers wasm2wat, wasm-objdump, wasm-decompile, wasm2c, and WASI capability review planning.
   - Default boundary: no WABT process, no WASM instantiation, no WASI resource grant.

## Verification Plan

- Focused no-execute tests:
  - `tests/unit/javascript-obfuscation-profile.test.ts`
  - `tests/unit/backend-plan-plugins.test.ts`
- Release guard:
  - `tests/unit/plugin-format-matrix.test.ts`
  - `tests/unit/tool-readiness.test.ts`
  - `tests/unit/tools-discover.test.ts`
  - `tests/unit/tool-help.test.ts`
  - `tests/unit/plugin-list.test.ts`
- Project guards:
  - `npm run typecheck`
  - `npm run lint`
