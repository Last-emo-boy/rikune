# TASK-006 Summary

Status: completed

Extended `src/plugins/runtime-plan.ts` with opt-in `session_templates` for every platform runtime plan. Templates include backend, isolation profile, network policy, mounts, artifacts, readiness checks, setup tools, execution tools, teardown, and safety notes. Runtime plan tools also expose workflow recipes such as `android.runtime.opt-in` and remain plan-only by default.

Verification:
- `npm test -- --runTestsByPath tests/unit/runtime-session-templates.test.ts ...`
- `npm test -- --runTestsByPath tests/unit/tool-readiness.test.ts tests/unit/tool-help.test.ts`
- `npm test -- --runTestsByPath tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`
- `npm run lint`
