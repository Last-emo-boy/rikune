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
- `npx eslint packages/plugin-sdk/src/index.ts packages/shared/src/runtime-contract.ts src/plugins/dotnet-managed/dotnet-managed-metadata.ts src/plugins/dotnet-managed/tools/dotnet-assembly-inspect.ts src/plugins/gtirb/index.ts src/plugins/native-object/native-object-metadata.ts src/plugins/native-object/tools/native-object-inventory.ts src/plugins/windows-debug-symbols/tools/windows-debug-metadata-inspect.ts src/plugins/windows-debug-symbols/windows-debug-symbols-metadata.ts --quiet --no-error-on-unmatched-pattern` passed.

## Known Baseline Limitation

Full `npm run lint` still fails on unrelated historical Prettier findings outside the files touched by this session.
