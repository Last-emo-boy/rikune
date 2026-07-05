# TASK-007 Summary

Status: completed

Implemented `sbom.provenance.graph` as a passive supply-chain provenance workflow. It merges package, container, installer, Android, and firmware inventory hints into deterministic components with evidence sources, CycloneDX and SPDX-lite exports, risk summary, and local-only vuln/report handoff recommendations.

Verification:
- `npm test -- --runTestsByPath tests/unit/sbom-provenance-graph.test.ts tests/unit/android-behavior-graph.test.ts tests/unit/apple-security-profile.test.ts tests/unit/firmware-workflow-plan.test.ts tests/unit/wasm-structure-analyze.test.ts`
- `npm test -- --runTestsByPath tests/unit/tool-readiness.test.ts tests/unit/tool-help.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`
- `npm run lint`
