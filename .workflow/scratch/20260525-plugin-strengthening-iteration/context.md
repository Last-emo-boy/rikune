# Plugin Strengthening Iteration

Date: 2026-05-25

Goal: continue iterating Plugin capability depth. Prefer strengthening existing plugins over adding new plugins.

Current result:

- `TASK-075` completed for the existing `malware` plugin.
- `malware.intel.loop` now normalizes IOC values, deduplicates repeated evidence across `config`, `c2`, `behavior`, `strings`, `classification`, and `findings`, and preserves source provenance.
- The tool now emits `fusion_summary`, `evidence_summary`, `normalized_iocs`, `workflow_handoff`, and `quality_gates` in addition to the existing `ioc_export`, `attack_map`, `rule_generation`, and validation plan fields.
- Default safety remains passive/offline: no malware execution, online threat-intel lookup, backend start, YARA backend invocation, or dynamic runtime start.
- `TASK-076` completed for the existing `unpacking` plugin.
- `unpack.workflow.plan` now emits `packer_assessment`, `evidence_summary`, `runtime_gate_matrix`, `retriage_handoff`, and `quality_gates` while preserving the previous workflow, dump strategy, runtime gate, reanalysis, next-tool, and safety fields.
- UPX evidence routes to `static_decompress_first`; harder packers such as VMProtect keep runtime dumping behind explicit opt-in, isolation, and backend readiness gates.
- Re-triage handoff now keeps child sample execution disabled and routes dumped payload artifacts toward static triage, comparison tools, and `analysis.evidence.graph`.
- `TASK-077` completed for the existing `static-triage` plugin.
- `static.capability.triage` now emits `evidence_summary`, `correlation_bundle`, `workflow_handoff`, and `quality_gates` alongside the original capability, backend, confidence, artifact, and analysis fields.
- The new `static_triage_correlation_bundle` routes behavior, config, crypto, and packer signals toward `static.config.carver`, `static.behavior.classify`, `crypto.identify`, `packer.detect`, `malware.intel.loop`, reports, and `analysis.evidence.graph`.
- Default safety remains passive/static-only: no sample execution, runtime backend start, or network access.
- `TASK-078` completed for the existing `code-analysis` plugin.
- `code.cross_decompiler.consensus` now emits `backend_coverage`, `evidence_summary`, `function_evidence_handoff`, and `quality_gates` alongside the original agreement, disagreement, missing backend, evidence graph, and follow-up fields.
- The new function handoff separates stable functions from disputed functions and routes them toward reconstruction, explanation prep, CFG/disassembly review, evidence graph, and report generation.
- Default safety remains fixture-safe/passive: no decompiler backend process, sample execution, mutation, or network access.
- `TASK-079` completed for the existing `visualization` plugin and shared evidence correlation layer.
- `analysis.evidence.graph` now normalizes `malware_intel_loop`, `static_triage_correlation_bundle`, `cross_decompiler_consensus`, and `function_evidence_handoff` artifacts into plugin evidence nodes and function handoff nodes.
- The evidence graph output now emits `plugin_evidence_summary`, `reporting_handoff`, and `quality_gates` so reports and staged summaries can consume plugin evidence without starting new analysis backends.
- Default safety remains passive/artifact-only: no backend start, sample execution, mutation, or network access.
- `TASK-080` completed the release guard for the plugin-strengthening wave.
- The final guard covered the strengthened malware, unpacking, static-triage, code-analysis, visualization evidence graph, behavior-first compatibility, and plugin metadata tests, then reran typecheck, lint, and tool catalog generation.

Verification so far:

- `npm test -- --runTestsByPath tests/unit/malware-intel-loop.test.ts --runInBand` — 3 tests passed.
- `npm test -- --runTestsByPath tests/unit/plugin-format-matrix.test.ts tests/unit/malware-intel-loop.test.ts --runInBand` — 33 tests passed.
- `npm run typecheck` — passed.
- `npm run lint` — passed.
- `npm run docs:tool-catalog` — generated `docs/tool-catalog.html` with 33 core tools, 93 plugins, 281 plugin tools, and 0 registration errors.
- `npm test -- --runTestsByPath tests/unit/unpack-workflow-plan.test.ts --runInBand` — 3 tests passed.
- `npm test -- --runTestsByPath tests/unit/plugin-format-matrix.test.ts tests/unit/unpack-workflow-plan.test.ts --runInBand` — 33 tests passed.
- `npm test -- --runTestsByPath tests/unit/static-analysis-tools.test.ts --runInBand` — 4 tests passed.
- `npm test -- --runTestsByPath tests/unit/static-analysis-tools.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` — 34 tests passed.
- `npm run typecheck` — passed after `TASK-077`.
- `npm run lint` — passed after `TASK-077`.
- `npm run docs:tool-catalog` — generated `docs/tool-catalog.html` with 33 core tools, 93 plugins, 281 plugin tools, and 0 registration errors after `TASK-077`.
- `npm test -- --runTestsByPath tests/unit/cross-decompiler-consensus.test.ts --runInBand` — 3 tests passed.
- `npm test -- --runTestsByPath tests/unit/cross-decompiler-consensus.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` — 33 tests passed.
- `npm run typecheck` — passed after `TASK-078`.
- `npm run lint` — passed after `TASK-078`.
- `npm run docs:tool-catalog` — generated `docs/tool-catalog.html` with 33 core tools, 93 plugins, 281 plugin tools, and 0 registration errors after `TASK-078`.
- `npm test -- --runTestsByPath tests/unit/evidence-graph.test.ts --runInBand` — 3 tests passed.
- `npm test -- --runTestsByPath tests/unit/plugin-format-matrix.test.ts tests/unit/evidence-graph.test.ts --runInBand` — 33 tests passed.
- `npm test -- --runTestsByPath tests/unit/evidence-graph.test.ts tests/unit/behavior-first-correlation.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` — 35 tests passed.
- `npm run typecheck` — passed after `TASK-079`.
- `npm run lint` — passed after `TASK-079`.
- `npm run docs:tool-catalog` — generated `docs/tool-catalog.html` with 33 core tools, 93 plugins, 281 plugin tools, and 0 registration errors after `TASK-079`.
- `npm test -- --runTestsByPath tests/unit/malware-intel-loop.test.ts tests/unit/unpack-workflow-plan.test.ts tests/unit/static-analysis-tools.test.ts tests/unit/cross-decompiler-consensus.test.ts tests/unit/evidence-graph.test.ts tests/unit/behavior-first-correlation.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` — 7 test suites, 48 tests passed.
- `npm run typecheck` — passed after `TASK-080`.
- `npm run lint` — passed after `TASK-080`.
- `npm run docs:tool-catalog` — generated `docs/tool-catalog.html` with 33 core tools, 93 plugins, 281 plugin tools, and 0 registration errors after `TASK-080`.

Next pending tasks:

- None in this plugin-strengthening wave.
