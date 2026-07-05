# TASK-008 Summary

Status: completed

Implemented `android.behavior.graph` as a passive static behavior correlation workflow over manifest permissions and intents, DEX class hints, smali snippets, URL/crypto/storage/reflection signals, and native library handoffs. Runtime recommendations remain plan-only through Android runtime and Frida workflow metadata.

Verification:
- `npm test -- --runTestsByPath tests/unit/sbom-provenance-graph.test.ts tests/unit/android-behavior-graph.test.ts tests/unit/apple-security-profile.test.ts tests/unit/firmware-workflow-plan.test.ts tests/unit/wasm-structure-analyze.test.ts`
- `npm test -- --runTestsByPath tests/unit/tool-readiness.test.ts tests/unit/tool-help.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`
- `npm run lint`
