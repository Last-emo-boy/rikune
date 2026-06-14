# TASK-067 Summary

Status: completed

Added backend install profile metadata and surfaced backend profile/readiness guidance through
`tools.discover` recommendations without starting backend processes.

Primary files:

- `src/core/backend-install-profile.ts`
- `src/tools/tools-discover.ts`
- `tests/unit/backend-install-contract.test.ts`
- `tests/unit/tools-discover.test.ts`

Verification:

- `npm test -- tests/unit/tools-discover.test.ts --runInBand`
- `npm test -- --runTestsByPath tests/unit/backend-install-contract.test.ts`
- `npx tsc --noEmit -p tsconfig.json`
