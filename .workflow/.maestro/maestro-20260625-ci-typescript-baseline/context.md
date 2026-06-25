# CI TypeScript Baseline Repair

## Summary

This session repaired the shared TypeScript build baseline that was blocking validate jobs for feature PRs based on `beta-minimize-tool-surface`.

PR: https://github.com/Last-emo-boy/rikune/pull/43

## Root Causes

- `@rikune/plugin-sdk` exposed manifest types directly from passthrough Zod schemas, causing fields to become `unknown` under strict package builds.
- `DynamicRuntimePolicy` no longer typed the legacy safety booleans already used by many static plugins: `noNetwork`, `noMutation`, and `noLiveExecution`.
- GTIRB runtime policy lacked an explicit `DynamicRuntimePolicy` annotation, so `allowedBackends` widened to `string[]`.
- Several inventory builders mixed Zod-inferred optional output types with stricter metadata envelope contracts.
- Local package build could be left with stale project-reference declaration output; `plugin-sdk` now forces its project-reference build.

## Verification

- `npm run build` passed.
- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/packages/plugin-sdk.test.ts tests/unit/dotnet-managed-metadata.test.ts tests/unit/native-object-inventory.test.ts tests/unit/windows-debug-symbols-metadata.test.ts tests/unit/gtirb-worker.test.ts tests/unit/workflow-search.test.ts` passed: 6 suites, 46 tests.
- `git diff --check` passed.
- `npm run lint` passed after formatting the repository lint baseline.
