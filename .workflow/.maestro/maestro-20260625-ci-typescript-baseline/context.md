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
- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/plugin-format-matrix.test.ts tests/unit/cross-decompiler-consensus.test.ts tests/unit/plugin-contracts.test.ts` passed after repairing the CI failure cluster.
- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/kb-collaboration-metadata.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/cross-decompiler-consensus.test.ts tests/unit/plugin-contracts.test.ts` passed: 4 suites, 41 tests.
- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/attack-map.test.ts` passed: 1 suite, 6 tests.
- `npm test -- --runInBand --forceExit --testPathPatterns="tests/unit/" --silent --json --outputFile=tests/temp/full-unit-results.json` passed.
- `npm run test:node` passed: 11 node integration smoke tests.
- `git diff --check` passed.
- `npm run lint` passed after formatting the repository lint baseline.

## Full Unit CI Baseline Follow-up

- `kb.context.suggest` workflow recipe now includes `analysis.notes` in `startsWith`, matching the release guard and keeping the handoff explicit.
- `managed.fake_c2` keeps the Python worker handler in the runtime contract as a string literal so the runtime contract guard can verify it.
- `code-analysis` cross-decompiler discovery test now expects `runtime_opt_in_required`, matching the plugin runtime policy without exposing the hidden tool surface automatically.
- Slow Windows discovery and ATT&CK mapping tests have explicit timeout budgets that match observed full-suite runtime.
- Node integration smoke tests now expect `code.function.cfg` as a specialist surface and `workflow.summarize` as a compatibility surface, matching `tool-surface-guidance`.
