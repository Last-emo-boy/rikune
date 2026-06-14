# TASK-071 Summary

Status: completed

Added the `external-re-bridge` plugin and `external_re.bridge.sync` tool. The bridge normalizes
provided local sidecar artifact manifests from IDA, Binary Ninja, Ghidra, and radare2 profiles into
external RE artifact bundles and cross-decompiler consensus input bundles.

The bridge is read-only, local-endpoint-only, BYO/sidecar-gated, and does not connect to or start
sidecars in default execution paths.

Primary files:

- `src/plugins/external-re-bridge/index.ts`
- `tests/unit/external-re-bridge.test.ts`

Verification:

- `npm test -- --runTestsByPath tests/unit/external-re-bridge.test.ts tests/unit/tool-readiness.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`
- `npm run lint`
