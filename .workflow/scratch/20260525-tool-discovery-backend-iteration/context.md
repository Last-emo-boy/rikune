# Tool Discovery Backend Iteration

Date: 2026-05-25

This Maestro task set captures the next iteration after narrowing the MCP startup surface and adding the `tools.discover` portal. The goal is to make the portal stronger instead of exposing more tools by default: AI agents should start with a small gateway, describe a sample or goal, and receive ranked toolchains with readiness and backend install context.

Final local evidence:

- Branch: `beta`.
- Startup visibility stays intentionally small; hidden registered tools remain blocked by `ToolExecutor` until `tools.discover` exposes them.
- `tools.discover` now ranks recommendations with score, match reasons, readiness state, activation plan, activation command, hidden-surface explanation, backend install profiles, and `activation_audit`.
- Catalog generation reports 33 core tools, 93 built-in plugins, 281 plugin tools, and 0 plugin registration errors.
- Plugin aspect metadata is complete for the current built-in plugin inventory.
- New bounded `backend-worker.v1` tools exist for `radare2.pipeline.run`, `wabt.toolchain.run`, `lief.binary.inspect`, `miasm.ir.lift`, and `triton.symbolic.slice`.
- JavaScript/JSVMP routing now connects `javascript.obfuscation.profile` to REstringer, JSIMPLIFIER, JSIR/CASCADE, and JSVMP static worker surfaces without JS eval/runtime execution.
- `code.cross_decompiler.consensus` compares supplied decompiler/IR artifact summaries and reports agreement, disagreement, backend gaps, follow-up recommendations, and evidence graph output without starting heavy backends.
- `external-re-bridge` represents IDA, Binary Ninja, Ghidra, and radare2 BYO/sidecar artifact sync as local-only read-only contracts feeding cross-decompiler consensus bundles.
- The benchmark guard suite validates representative recommendation quality over CI-safe metadata fixtures.
- MCP/backend safety guards cover hidden direct-call blocking, schema rejection, backend input limits, artifact `allowedRoots`, shell command rejection, diagnostic redaction, and external sidecar endpoint restrictions.
- Docker dry-runs discover 93 plugins and 56 plugins with `systemDeps`.
- Static/default backend dry-run enables installed/default features while skipping BYO, sidecar, GPU, runtime, license-gated, and optional profile routes.
- Static/all backend dry-run enables optional profile-gated backends such as GTIRB, JSIR/CASCADE, JSVMP, and radare2 while still skipping BYO/sidecar/runtime/GPU/license-sensitive routes.

Key source files:

- `src/tools/tools-discover.ts` — current discovery portal and activation handler.
- `src/tools/tool-aspect-matrix.ts` — aspect matrix and sample target matching.
- `src/core/tool-surface-manager.ts` — progressive visibility and activation rules.
- `src/core/tool-executor.ts` — hidden tool direct-call blocking.
- `packages/plugin-sdk/src/index.ts` — `PluginAspects`, `SurfaceRules`, `BackendWorkerContract`, and plugin audit rules.
- `src/plugins/frontier-worker-tools.ts` — shared `backend-worker.v1` tool contract factory.
- `scripts/generate-docker.mjs` — plugin-driven Docker/Compose backend install route generation.
- `tests/unit/tools-discover.test.ts`, `tests/unit/plugin-format-matrix.test.ts`, `tests/unit/backend-install-contract.test.ts`, and `tests/unit/tool-readiness.test.ts` — main guard rails.

External trend anchors observed in the previous investigation:

- Google JSIR / CASCADE-style JavaScript IR direction should feed the JavaScript/JSVMP suite.
- HumanSecurity REstringer remains a practical JavaScript deobfuscation backend.
- radare2, Remill, rev.ng, GTIRB/ddisasm, Miasm, Triton, WABT, and LIEF remain the strongest external reverse-engineering backend families to bridge, but heavy, runtime, GPL/AGPL, GPU, and license-sensitive tooling must stay profile-gated or BYO.
- Recent decompilation research emphasizes multi-agent or constraint-guided decompilation quality, which maps better to cross-backend consensus than to a single new decompiler plugin.
- Recent MCP security research makes schema/path/activation/backend safety a required release guard for a malware/reversing MCP server.

Execution intent:

1. Completed: `tools.discover` ranks and explains recommendations instead of only listing matches.
2. Completed: plugin `aspects` metadata is complete for the current 93 built-in plugin catalog.
3. Completed: backend install/profile readiness is exposed without starting backend processes.
4. Completed: selected plan-only tools were promoted into bounded Worker adapters.
5. Completed: JS/JSVMP and cross-decompiler suites were added from existing and new backend artifacts.
6. Completed: external RE IDE/MCP integrations are represented as BYO/local sidecar contracts.
7. Completed: benchmark, safety, docs, catalog, lint, typecheck, `tsc`, and Docker dry-run guards pass.

Execution report:

| Task | Status | Result |
| --- | --- | --- |
| `TASK-065` | completed | Ranked `tools.discover` recommendation fields and hidden activation guidance. |
| `TASK-066` | completed | Plugin aspects completed for the current 93-plugin inventory. |
| `TASK-067` | completed | Backend install/profile metadata surfaced in discovery recommendations. |
| `TASK-068` | completed | Added bounded workers for radare2, WABT, LIEF, Miasm, and Triton. |
| `TASK-069` | completed | Built the JavaScript/JSVMP static analysis suite pipeline. |
| `TASK-070` | completed | Added passive cross-decompiler consensus workflow. |
| `TASK-071` | completed | Added read-only BYO external RE sidecar bridge contracts. |
| `TASK-072` | completed | Added CI-safe reverse-engineering benchmark guard suite. |
| `TASK-073` | completed | Hardened MCP activation and backend safety boundaries. |
| `TASK-074` | completed | Refreshed docs/catalog/results and ran release guard verification. |

Verification evidence:

- `npm run docs:tool-catalog` — generated `docs/tool-catalog.html` with 33 core tools, 93 plugins, 281 plugin tools, and 0 registration errors.
- `npm test -- tests/unit/tools-discover.test.ts tests/unit/core/tool-surface-manager.test.ts tests/unit/core/tool-executor.test.ts --runInBand` — 21 tests passed.
- `npm test -- --runTestsByPath tests/unit/plugin-format-matrix.test.ts tests/unit/tool-readiness.test.ts tests/unit/backend-install-contract.test.ts tests/unit/docker-generator-backends.test.ts` — 51 tests passed.
- `npm test -- --runTestsByPath tests/unit/frontier-worker-plugins.test.ts tests/unit/javascript-obfuscation-profile.test.ts tests/unit/backend-plan-plugins.test.ts tests/unit/cross-decompiler-consensus.test.ts tests/unit/external-re-bridge.test.ts tests/unit/reverse-benchmark-suite.test.ts tests/unit/tools-discover.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/tool-readiness.test.ts tests/unit/backend-worker-contract.test.ts tests/unit/mcp-tool-safety.test.ts tests/unit/backend-install-contract.test.ts` — 145 tests passed.
- `npm test -- --runTestsByPath tests/unit/plugin-list.test.ts` — 1 test passed.
- `npm run lint` — passed.
- `npm run typecheck` — passed.
- `npx tsc --noEmit -p tsconfig.json` — passed.
- `node scripts/generate-docker.mjs --profile=static --backend-profile=default --dry-run` — passed; no files written.
- `node scripts/generate-docker.mjs --profile=static --backend-profile=all --dry-run` — passed; no files written.

Non-goals:

- Do not widen the initial MCP tool list.
- Do not start backend processes from discovery, help, readiness, plugin list, catalog generation, or Docker dry-run paths.
- Do not silently install GPL/AGPL, commercial, GPU, DBI, runtime, or very heavy backends in default images.
- Do not execute user samples during tests or readiness checks.
- Do not stage or modify unrelated untracked `.workflow` directories from older sessions.
