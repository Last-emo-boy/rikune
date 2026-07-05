# TASK-068 Summary

Status: completed

Promoted high-value plan-only plugins to bounded `backend-worker.v1` workers:

- `radare2.pipeline.run`
- `wabt.toolchain.run`
- `lief.binary.inspect`
- `miasm.ir.lift`
- `triton.symbolic.slice`

Each worker keeps builtin mode fixture-safe, declares external backend readiness metadata, and emits
artifact/evidence/workflow metadata for discovery and readiness surfaces.

Primary files:

- `src/plugins/radare2/index.ts`
- `src/plugins/wabt/index.ts`
- `src/plugins/lief/index.ts`
- `src/plugins/miasm/index.ts`
- `src/plugins/triton/index.ts`
- `tests/unit/frontier-worker-plugins.test.ts`

Verification:

- `npm test -- --runTestsByPath tests/unit/frontier-worker-plugins.test.ts tests/unit/backend-worker-contract.test.ts tests/unit/tool-readiness.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`
- `npm run lint`
