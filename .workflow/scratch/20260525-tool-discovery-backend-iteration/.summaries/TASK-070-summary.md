# TASK-070 Summary

Status: completed

Added `code.cross_decompiler.consensus`, a passive consensus workflow for fixture-safe comparison of
provided decompiler/IR artifact summaries. The tool reports agreement, disagreement, missing
backend gaps, follow-up recommendations, and an evidence graph without starting Ghidra, RetDec,
radare2, Rizin, Angr, revng, Remill, or GTIRB.

Primary files:

- `src/plugins/code-analysis/tools/cross-decompiler-consensus.ts`
- `src/plugins/code-analysis/index.ts`
- `tests/unit/cross-decompiler-consensus.test.ts`
- `tests/unit/plugin-format-matrix.test.ts`

Verification:

- `npm test -- --runTestsByPath tests/unit/cross-decompiler-consensus.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm test -- tests/unit/tools-discover.test.ts --runInBand`
- `npm run typecheck`
