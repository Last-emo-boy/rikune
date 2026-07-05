# Plugin Strengthening Iteration - 2026-05-26

## TASK-081 completed

Strengthened the existing `api-hash` plugin instead of creating a new plugin.

Key changes:
- `hash.resolver.plan` now emits `evidence_summary`, `workflow_handoff`, and `quality_gates`.
- Tool metadata now declares `api_hash_resolver_plan`, evidence categories, and `api-hash.resolver-recovery`.
- `analysis.evidence.graph` now consumes `api_hash_resolver_plan` as plugin evidence and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/hash-resolver-plan.test.ts tests/unit/evidence-graph.test.ts tests/unit/malware-intel-loop.test.ts tests/unit/unpack-workflow-plan.test.ts tests/unit/static-analysis-tools.test.ts tests/unit/cross-decompiler-consensus.test.ts tests/unit/behavior-first-correlation.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 8 suites, 50 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only LF/CRLF warnings from Git.

## Next candidates

## TASK-082 completed

Strengthened the existing `static-triage` plugin behavior classifier.

Key changes:
- `static.behavior.classify` now emits `evidence_summary`, `workflow_handoff`, and `quality_gates`.
- Tool metadata now declares `static_behavior_classifier`, evidence categories, and `static-triage.behavior-runtime-validation`.
- `analysis.evidence.graph` now consumes `static_behavior_classifier` as plugin behavior evidence and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.
- `scripts/generate-tool-catalog-doc.mjs` now strips trailing spaces before writing generated HTML.

Verification:
- `npm test -- --runTestsByPath tests/unit/static-behavior-classify.test.ts tests/unit/evidence-graph.test.ts tests/unit/hash-resolver-plan.test.ts tests/unit/malware-intel-loop.test.ts tests/unit/unpack-workflow-plan.test.ts tests/unit/static-analysis-tools.test.ts tests/unit/cross-decompiler-consensus.test.ts tests/unit/behavior-first-correlation.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 9 suites, 52 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only LF/CRLF warnings from Git.

## Next candidates

TASK-083 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption.

## TASK-083 completed

Strengthened the existing `static-triage` plugin crypto identifier.

Key changes:
- `crypto.identify` now emits `evidence_summary`, `workflow_handoff`, and `quality_gates`.
- Tool metadata now declares `crypto_identification`, evidence categories, and `static-triage.crypto-runtime-tracing`.
- `analysis.evidence.graph` now consumes `crypto_identification` as plugin crypto capability evidence, constant triage signals, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/crypto-identify.test.ts tests/unit/crypto-lifecycle-graph.test.ts tests/unit/evidence-graph.test.ts tests/unit/static-behavior-classify.test.ts tests/unit/hash-resolver-plan.test.ts tests/unit/malware-intel-loop.test.ts tests/unit/unpack-workflow-plan.test.ts tests/unit/static-analysis-tools.test.ts tests/unit/cross-decompiler-consensus.test.ts tests/unit/behavior-first-correlation.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 11 suites, 55 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only LF/CRLF warnings from Git.

## Next candidates

TASK-084 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption.

## TASK-084 completed

Strengthened the existing `static-triage` plugin config carver.

Key changes:
- `static.config.carver` now emits `evidence_summary`, `workflow_handoff`, and `quality_gates`.
- Tool metadata now declares `static_config_carver`, evidence categories, and `static-triage.config-evidence-correlation`.
- `analysis.evidence.graph` now consumes `static_config_carver` as plugin IOC evidence, config triage signals, and workflow routes in addition to static expectations.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/static-config-carver.test.ts tests/unit/evidence-graph.test.ts tests/unit/static-behavior-classify.test.ts tests/unit/crypto-identify.test.ts tests/unit/malware-intel-loop.test.ts tests/unit/dynamic-behavior-diff.test.ts tests/unit/behavior-first-correlation.test.ts tests/unit/static-resource-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 9 suites, 47 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only LF/CRLF warnings from Git.

## Next candidates

TASK-085 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption.

## TASK-085 completed

Strengthened the existing `static-triage` plugin resource graph.

Key changes:
- `static.resource.graph` now emits `evidence_summary`, `workflow_handoff`, and `quality_gates`.
- Tool metadata now declares `static_resource_graph`, evidence categories, and `static-triage.resource-payload-correlation`.
- `analysis.evidence.graph` now consumes `static_resource_graph` as plugin evidence for embedded payload signals, high-entropy resource signals, resource URL IOCs, and workflow routes in addition to static expectations.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/static-resource-graph.test.ts tests/unit/evidence-graph.test.ts tests/unit/static-config-carver.test.ts tests/unit/unpack-workflow-plan.test.ts tests/unit/crypto-identify.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 6 suites, 41 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## Next candidates

TASK-086 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption.

## TASK-086 completed

Strengthened the existing `static-triage` plugin compiler/packer detector.

Key changes:
- `compiler.packer.detect` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool metadata now declares `compiler_packer_attribution`, evidence categories, and `static-triage.compiler-packer-attribution`.
- `analysis.evidence.graph` now consumes `compiler_packer_attribution` as plugin evidence for toolchain capability, packer/protector/file-type triage signals, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/static-analysis-tools.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/unpack-workflow-plan.test.ts tests/unit/static-resource-graph.test.ts tests/unit/static-config-carver.test.ts --runInBand` passed: 6 suites, 44 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## Next candidates

TASK-087 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption.

## TASK-087 completed

Strengthened the existing `strings` plugin FLOSS decoder.

Key changes:
- `strings.floss.decode` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool metadata now declares `enriched_string_analysis`, encoded-config evidence, and `strings.floss-decoded-evidence`.
- `analysis.evidence.graph` now consumes `enriched_string_analysis` as plugin evidence for decoded-string IOCs, suspicious/encoded string triage signals, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/strings-floss-decode.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 3 suites, 52 tests.
- `npm test -- --runTestsByPath tests/unit/strings-floss-decode.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/analysis-context-link.test.ts tests/unit/static-config-carver.test.ts tests/unit/malware-intel-loop.test.ts --runInBand` passed: 6 suites, 59 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## Next candidates

TASK-088 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption.

## TASK-088 completed

Strengthened the existing `strings` plugin raw string extractor.

Key changes:
- `strings.extract` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool metadata now declares `enriched_string_analysis`, encoded-config/workflow/provenance evidence, and `strings.raw-extraction-evidence`.
- Cache and fresh execution paths now synthesize the same structured handoff, so old cache entries are upgraded in returned MCP output.
- Persisted enriched string artifacts and canonical evidence now carry the structured raw-string handoff payload.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/strings-extract.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/evidence-graph.test.ts --runInBand` passed: 3 suites, 46 tests.
- `npm test -- --runTestsByPath tests/unit/strings-extract.test.ts tests/unit/strings-floss-decode.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/analysis-context-link.test.ts tests/unit/static-config-carver.test.ts tests/unit/malware-intel-loop.test.ts --runInBand` passed: 7 suites, 72 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## TASK-089 completed

Strengthened the existing `yara` plugin rule generator.

Key changes:
- `yara.generate` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool and plugin metadata now declare workflow/provenance evidence, passive no-live-sample safety, and `yara.rule-generation-handoff`.
- Persisted `yara_rule_generation` artifacts now carry the same structured validation/reporting handoff returned by the MCP tool.
- `analysis.evidence.graph` now consumes `yara_rule_generation` as plugin signature evidence, rule-input triage evidence, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/yara-generate.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 3 suites, 46 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## Next candidates

TASK-090 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption.

## TASK-090 completed

Strengthened the existing `yara` plugin batch family rule generator.

Key changes:
- `yara.generate.batch` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool metadata now declares the `yara_family_rule` artifact, workflow/provenance evidence, passive no-live-sample safety, and `yara.family-rule-generation-handoff`.
- Persisted `yara_family_rule` artifacts now carry the same structured family rule handoff returned by the MCP tool.
- `analysis.evidence.graph` now consumes `yara_family_rule` as plugin signature evidence, rule-input triage evidence, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/yara-generate.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## Next candidates

TASK-091 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption. Candidate focus: `threat-intel` artifact/export tools such as `ioc.export` and `sigma.rule.generate`.

## TASK-091 completed

Strengthened the existing `threat-intel` plugin IOC exporter.

Key changes:
- `ioc.export` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool metadata now declares workflow/provenance evidence, passive no-live-sample safety, and `threat-intel.ioc-export-handoff`.
- Persisted JSON IOC exports carry the structured handoff payload; STIX exports carry MCP `x_mcp_*` handoff extensions while CSV remains plain CSV.
- `analysis.evidence.graph` now consumes `ioc_export_json`, `ioc_export_csv`, and `ioc_export_stix2` artifacts as plugin IOC, ATT&CK behavior, summary, and workflow-route evidence.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/ioc-export.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 3 suites, 38 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## Next candidates

TASK-092 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption. Candidate focus: `threat-intel` `sigma.rule.generate`, which already produces `sigma_rules` but still lacks structured handoff, quality gates, workflow recipe metadata, and evidence graph ingestion.

## TASK-092 completed

Strengthened the existing `threat-intel` plugin Sigma rule generator.

Key changes:
- `sigma.rule.generate` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool metadata now declares workflow/provenance evidence, passive no-live-sample safety, and `threat-intel.sigma-rule-generation-handoff`.
- Persisted `sigma_rules` artifacts now carry the same structured validation/reporting handoff returned by the MCP tool.
- `analysis.evidence.graph` now consumes `sigma_rules` as plugin rule evidence, summary triage evidence, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/sigma-rule-generate.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## Next candidates

TASK-093 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption. Candidate focus: `yara-x` `yara_x.scan` or `upx` `upx.inspect`, both of which already produce artifacts and recommended follow-ups but may still lack structured workflow handoff and graph consumption.

## TASK-093 completed

Strengthened the existing `yara-x` plugin scan tool.

Key changes:
- `yara_x.scan` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool and plugin metadata now declare workflow/provenance evidence, passive no-live-sample safety, evidence-correlation capability, and `yara-x.scan-validation-handoff`.
- Persisted `backend_yara_x_scan` artifacts now carry the structured YARA-X scan handoff returned by the MCP tool.
- `analysis.evidence.graph` now consumes `backend_yara_x_scan` as signature capability evidence, scan-summary triage evidence, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/yara-x-scan.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed.
- `npm run typecheck` passed.
- `npm run lint` passed after formatting long TASK-093 lines.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.

## Next candidates

TASK-094 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption. Candidate focus: `upx` `upx.inspect`, which already has backend artifact semantics and should be able to route unpack planning, static triage, evidence graph, and reporting with passive gates.

## TASK-094 completed

Strengthened the existing `upx` plugin inspection tool.

Key changes:
- `upx.inspect` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool and plugin metadata now declare workflow/provenance evidence, passive no-live-sample safety, evidence-correlation capability, and `upx.inspect-validation-handoff`.
- Persisted `backend_upx_list` and `backend_upx_test` artifacts now carry the structured UPX inspection handoff; `decompress` keeps the binary `backend_upx_decompress` artifact while returning a structured handoff.
- `analysis.evidence.graph` now consumes `backend_upx_list` and `backend_upx_test` as packer triage evidence, unpack capability evidence, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/upx-inspect.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 3 suites, 36 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.

## Next candidates

TASK-095 selection is in progress. Priority remains strengthening existing plugins with missing structured handoff, quality gates, metadata, workflow recipes, and evidence graph consumption. Candidate focus: `die` `die.scan`, which already identifies packers/toolchains but may still lack a structured validation handoff and graph-consumable artifact evidence.

## TASK-095 completed

Strengthened the existing `die` plugin scan tool.

Key changes:
- `die.scan` now emits `evidence_summary`, `workflow_handoff`, `quality_gates`, `recommended_next_tools`, and `next_actions`.
- Tool and plugin metadata now declare workflow/provenance evidence, passive no-live-sample safety, evidence-correlation capability, and `die.scan-validation-handoff`.
- Persisted `backend_die_scan` artifacts now carry structured DIE scan handoff data plus the original raw DIE JSON.
- `analysis.evidence.graph` now consumes `backend_die_scan` as packer/protector triage evidence, toolchain capability evidence, crypto capability evidence, scan-summary evidence, and workflow routes.
- Release guard coverage was added in `plugin-format-matrix.test.ts`.
- `docs/PLUGINS.md` and `docs/tool-catalog.html` were updated.

Verification:
- `npm test -- --runTestsByPath tests/unit/die-scan.test.ts tests/unit/evidence-graph.test.ts tests/unit/plugin-format-matrix.test.ts --runInBand` passed: 3 suites, 35 tests.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run docs:tool-catalog` generated 33 core tools, 93 plugins, 281 plugin tools, 0 registration errors.
- Scoped `git diff --check` had no whitespace errors; only the existing `docs/tool-catalog.html` LF/CRLF warning from Git.

## Pause point

Per current instruction, plugin strengthening is paused after TASK-095 for wrap-up instead of selecting TASK-096.
