# TASK-065 Summary

Status: completed

Implemented ranked `tools.discover` recommendations. Recommendation entries now include score,
match reasons, readiness state, activation plan, activation command, and hidden-surface
explanations.

Primary files:

- `src/tools/tools-discover.ts`
- `tests/unit/tools-discover.test.ts`

Verification:

- `npm test -- tests/unit/tools-discover.test.ts --runInBand`
- `npx tsc --noEmit -p tsconfig.json`
