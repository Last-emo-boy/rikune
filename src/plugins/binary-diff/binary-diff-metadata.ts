import type { ArtifactRef, BackendWorkerContract, ToolDefinition } from '../../types.js'
import type { BinaryDiffResult, FunctionDiffEntry } from './binary-diff-engine.js'

export const BINARY_DIFF_ARTIFACT_TYPE = 'binary_diff'
export const BINARY_DIFF_SCHEMA = 'rikune.binary_diff.result.v1'

export const BINARY_DIFF_FOLLOW_UP_TOOLS = [
  'binary.diff.summary',
  'analysis.evidence.graph',
  'report.generate',
  'artifact.read',
  'workflow.search',
]

export const BINARY_DIFF_ASPECTS = {
  formats: ['pe', 'exe', 'dll', 'elf', 'macho', 'dotnet', 'native-binary', 'firmware'],
  platforms: ['windows', 'linux', 'macos', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc', 'riscv'],
  execution: ['static', 'correlation', 'comparison', 'workflow-handoff'],
  safety: ['passive', 'no_network_by_default', 'no_mutation', 'no_live_sample_by_default'],
  capabilities: [
    'binary-diff',
    'variant-comparison',
    'variant-diff',
    'function-comparison',
    'function-similarity',
    'structural-delta',
    'structural-diff',
    'similarity-profile',
    'diff-provenance',
    'radiff2-readiness',
    'rizin-radiff2',
    'imports-delta',
    'exports-delta',
    'sections-delta',
    'strings-delta',
    'attack-delta',
    'evidence-graph-handoff',
    'report-handoff',
  ],
  evidence: [
    'binary-diff',
    'variant-comparison',
    'function-similarity',
    'structural-delta',
    'imports',
    'exports',
    'sections',
    'strings',
    'attack',
    'similarity',
    'workflow',
    'provenance',
  ],
}

export const BINARY_DIFF_ARTIFACTS: NonNullable<ToolDefinition['artifacts']> = [
  {
    type: BINARY_DIFF_ARTIFACT_TYPE,
    description:
      'Binary diff result with radiff2 function comparison, structural delta, ATT&CK delta, similarity profile, provenance, and workflow handoff metadata',
    mimeTypes: ['application/json'],
  },
]

export const BINARY_DIFF_EVIDENCE: NonNullable<ToolDefinition['evidence']> = [
  { category: 'binary-diff', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'variant-comparison', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'function-similarity', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'structural-delta', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'imports', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'exports', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'sections', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'strings', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'attack', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'similarity', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'workflow', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
  { category: 'provenance', artifactTypes: [BINARY_DIFF_ARTIFACT_TYPE] },
]

export const BINARY_DIFF_WORKFLOW_RECIPES: NonNullable<ToolDefinition['workflowRecipes']> = [
  {
    id: 'binary-diff.variant-comparison',
    title: 'Binary variant comparison and similarity handoff',
    description:
      'Compare two binary variants with binary diff, variant comparison, function comparison, structural delta, radiff2 readiness, provenance, and evidence graph/report handoff.',
    startsWith: ['binary.diff'],
    nextTools: BINARY_DIFF_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample-a', 'sample-b', 'static-structure-evidence'],
    producesArtifacts: [BINARY_DIFF_ARTIFACT_TYPE],
    evidence: [
      'binary-diff',
      'variant-comparison',
      'function-similarity',
      'structural-delta',
      'similarity',
      'workflow',
      'provenance',
    ],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    runtimeBackends: ['radiff2', 'rizin'],
  },
  {
    id: 'binary-diff.function-comparison',
    title: 'Function comparison and radiff2 readiness review',
    description:
      'Use radiff2 function similarity deltas to prioritize changed, added, and removed functions before deeper reverse-engineering.',
    startsWith: ['binary.diff'],
    nextTools: [
      'binary.diff.summary',
      'analysis.evidence.graph',
      'report.generate',
      'tool.readiness',
    ],
    requiredArtifacts: ['sample-a', 'sample-b'],
    producesArtifacts: [BINARY_DIFF_ARTIFACT_TYPE],
    evidence: ['function-similarity', 'binary-diff', 'provenance'],
    safety: ['passive', 'backend_readiness_probe_only'],
    runtimeBackends: ['radiff2', 'rizin'],
  },
  {
    id: 'binary-diff.structural-delta-handoff',
    title: 'Structural delta handoff for imports, exports, sections, strings, and ATT&CK',
    description:
      'Route imports/exports/sections/strings/ATT&CK delta evidence from binary diff into evidence graph, report, and similarity workflows.',
    startsWith: ['binary.diff'],
    nextTools: [
      'analysis.evidence.graph',
      'report.generate',
      'binary.diff.summary',
      'artifact.read',
    ],
    requiredArtifacts: ['pe-imports', 'pe-exports', 'structure', 'strings', 'attack-map'],
    producesArtifacts: [BINARY_DIFF_ARTIFACT_TYPE],
    evidence: ['imports', 'exports', 'sections', 'strings', 'attack', 'structural-delta'],
    safety: ['passive', 'artifact_only'],
  },
]

export const BINARY_DIFF_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'binary.diff is a passive static comparison tool; it does not execute either sample.',
    'Function diff uses a local radiff2/Rizin worker when available; missing radiff2 degrades to warnings while structural deltas can still be produced.',
    'Evidence graph and report follow-ups consume the persisted binary_diff artifact instead of re-running heavyweight backends by default.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}

export const BINARY_DIFF_WORKER_BACKEND: BackendWorkerContract = {
  version: 'backend-worker.v1',
  backendName: 'RizinRadiff2',
  backendKind: 'external',
  adapter: 'binary-diff.radiff2',
  availability: 'optional',
  envVar: 'RADIFF2_PATH',
  supportedModes: ['external'],
  defaultMode: 'external',
  inputArtifactTypes: ['sample-a', 'sample-b'],
  outputArtifactTypes: [BINARY_DIFF_ARTIFACT_TYPE],
  policy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    defaultTimeoutMs: 180_000,
    maxInputBytes: 2 * 1024 * 1024,
    maxOutputBytes: 8 * 1024 * 1024,
    notes: ['Only read-only radiff2 comparison commands are expected for function diff mode.'],
  },
  readiness: {
    doesNotStartBackend: true,
    setupActions: [
      'Set RADIFF2_PATH to a pinned radiff2 binary, or install Rizin so radiff2 is available on PATH.',
      'If using RIZIN_PATH, keep radiff2 beside the configured Rizin binary.',
      'When radiff2 is unavailable, run binary.diff with include_function_diff=false for structural/ATT&CK deltas only.',
    ],
    missingBackendBehavior:
      'Function comparison is skipped with a warning; structural imports/exports/sections/strings and ATT&CK deltas remain available from existing evidence.',
  },
  packaging: {
    installRoute: 'profile-gated',
    installProfile: 'optional',
    dockerFeature: 'rizin',
    envVar: 'RADIFF2_PATH',
    dockerDefault: '/opt/rizin/bin/radiff2',
    notes: ['Rizin packages usually provide radiff2 alongside rizin.'],
  },
}

export interface BinaryDiffMetadataInput {
  include_function_diff?: boolean
  include_structural_diff?: boolean
  include_attack_diff?: boolean
  max_functions?: number
}

function roundMetric(value: number | null): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? Number(value.toFixed(3)) : null
}

function deltaRatio(commonCount: number, addedCount: number, removedCount: number): number | null {
  const total = commonCount + addedCount + removedCount
  if (total <= 0) return null
  return commonCount / total
}

function average(values: number[]): number | null {
  if (values.length === 0) return null
  return values.reduce((sum, value) => sum + value, 0) / values.length
}

function finiteSimilarities(functions: FunctionDiffEntry[]): number[] {
  return functions
    .map((entry) => entry.similarity)
    .filter((value): value is number => typeof value === 'number' && Number.isFinite(value))
}

function classifySimilarity(overall: number | null): string {
  if (overall === null) return 'unknown'
  if (overall >= 0.98) return 'near-identical'
  if (overall >= 0.8) return 'close-variant'
  if (overall >= 0.55) return 'related-variant'
  return 'structural-divergence'
}

function topModifiedFunctions(diff: BinaryDiffResult): Array<{
  name: string
  similarity: number | null
  address_a?: number | string | null
  address_b?: number | string | null
}> {
  return [...(diff.function_diff?.functions_modified ?? [])]
    .sort((a, b) => (a.similarity ?? 1) - (b.similarity ?? 1))
    .slice(0, 10)
    .map((entry) => ({
      name: entry.name,
      similarity: roundMetric(
        typeof entry.similarity === 'number' && Number.isFinite(entry.similarity)
          ? entry.similarity
          : null
      ),
      address_a: entry.address_a,
      address_b: entry.address_b,
    }))
}

export function buildBinaryDiffSimilarityProfile(diff: BinaryDiffResult) {
  const modifiedSimilarities = finiteSimilarities(diff.function_diff?.functions_modified ?? [])
  const functionAverage = roundMetric(average(modifiedSimilarities))
  const functionMinimum =
    modifiedSimilarities.length > 0 ? roundMetric(Math.min(...modifiedSimilarities)) : null
  const importsSimilarity = diff.structural_delta
    ? roundMetric(
        deltaRatio(
          diff.structural_delta.imports.common_count,
          diff.structural_delta.imports.added.length,
          diff.structural_delta.imports.removed.length
        )
      )
    : null
  const exportsSimilarity = diff.structural_delta
    ? roundMetric(
        deltaRatio(
          diff.structural_delta.exports.common_count,
          diff.structural_delta.exports.added.length,
          diff.structural_delta.exports.removed.length
        )
      )
    : null
  const stringsSimilarity = diff.structural_delta
    ? roundMetric(
        deltaRatio(
          diff.structural_delta.strings.common_count,
          diff.structural_delta.strings.added.length,
          diff.structural_delta.strings.removed.length
        )
      )
    : null
  const availableScores = [
    functionAverage,
    importsSimilarity,
    exportsSimilarity,
    stringsSimilarity,
  ].filter((value): value is number => typeof value === 'number')
  const overallSimilarity = roundMetric(average(availableScores))
  const sectionDeltaCount = diff.structural_delta
    ? diff.structural_delta.sections.added.length +
      diff.structural_delta.sections.removed.length +
      diff.structural_delta.sections.size_changed.length
    : 0

  return {
    schema: 'rikune.binary_diff.similarity_profile.v1',
    sample_pair: {
      sample_id_a: diff.sample_id_a,
      sample_id_b: diff.sample_id_b,
    },
    classification: classifySimilarity(overallSimilarity),
    overall_similarity: overallSimilarity,
    function_similarity: {
      available: Boolean(diff.function_diff),
      backend: 'radiff2',
      backend_ok: diff.function_diff?.ok ?? false,
      average_modified_similarity: functionAverage,
      minimum_modified_similarity: functionMinimum,
      modified_count: diff.function_diff?.functions_modified.length ?? 0,
      added_count: diff.function_diff?.functions_added.length ?? 0,
      removed_count: diff.function_diff?.functions_removed.length ?? 0,
      top_modified: topModifiedFunctions(diff),
    },
    structural_similarity: {
      available: Boolean(diff.structural_delta),
      imports_similarity: importsSimilarity,
      exports_similarity: exportsSimilarity,
      strings_similarity: stringsSimilarity,
      section_delta_count: sectionDeltaCount,
      structural_change_count: diff.structural_delta
        ? diff.structural_delta.imports.added.length +
          diff.structural_delta.imports.removed.length +
          diff.structural_delta.exports.added.length +
          diff.structural_delta.exports.removed.length +
          sectionDeltaCount +
          diff.structural_delta.strings.added.length +
          diff.structural_delta.strings.removed.length
        : 0,
    },
    score_basis: [
      'radiff2 modified function similarity when function diff is available',
      'imports/exports/strings common-vs-delta ratios from existing static evidence',
      'section add/remove/size-change counts as structural divergence signals',
    ],
  }
}

export function buildBinaryDiffEvidenceSummary(diff: BinaryDiffResult) {
  const stats = diff.summary_stats
  return {
    schema: 'rikune.binary_diff.evidence_summary.v1',
    sample_pair: {
      sample_id_a: diff.sample_id_a,
      sample_id_b: diff.sample_id_b,
    },
    artifact_type: BINARY_DIFF_ARTIFACT_TYPE,
    evidence_kind: 'binary-diff',
    delta_counts: {
      functions: {
        added: stats.functions_added,
        removed: stats.functions_removed,
        modified: stats.functions_modified,
      },
      imports: {
        added: stats.imports_added,
        removed: stats.imports_removed,
        common: diff.structural_delta?.imports.common_count ?? 0,
      },
      exports: {
        added: diff.structural_delta?.exports.added.length ?? 0,
        removed: diff.structural_delta?.exports.removed.length ?? 0,
        common: diff.structural_delta?.exports.common_count ?? 0,
      },
      sections: {
        added: diff.structural_delta?.sections.added.length ?? 0,
        removed: diff.structural_delta?.sections.removed.length ?? 0,
        size_changed: diff.structural_delta?.sections.size_changed.length ?? 0,
      },
      strings: {
        added: stats.strings_added,
        removed: stats.strings_removed,
        common: diff.structural_delta?.strings.common_count ?? 0,
      },
      attack: {
        added: stats.attack_techniques_added,
        removed: stats.attack_techniques_removed,
        confidence_changed: diff.attack_delta?.confidence_changed.length ?? 0,
      },
    },
    top_function_changes: topModifiedFunctions(diff),
    structural_delta_preview: {
      imports_added: diff.structural_delta?.imports.added.slice(0, 20) ?? [],
      imports_removed: diff.structural_delta?.imports.removed.slice(0, 20) ?? [],
      exports_added: diff.structural_delta?.exports.added.slice(0, 20) ?? [],
      exports_removed: diff.structural_delta?.exports.removed.slice(0, 20) ?? [],
      sections_added: diff.structural_delta?.sections.added.slice(0, 20) ?? [],
      sections_removed: diff.structural_delta?.sections.removed.slice(0, 20) ?? [],
      strings_added: diff.structural_delta?.strings.added.slice(0, 20) ?? [],
      strings_removed: diff.structural_delta?.strings.removed.slice(0, 20) ?? [],
    },
    attack_delta_preview: {
      techniques_added: diff.attack_delta?.techniques_added.slice(0, 20) ?? [],
      techniques_removed: diff.attack_delta?.techniques_removed.slice(0, 20) ?? [],
      confidence_changed: diff.attack_delta?.confidence_changed.slice(0, 20) ?? [],
    },
    similarity_profile: buildBinaryDiffSimilarityProfile(diff),
    recommended_next_tools: BINARY_DIFF_FOLLOW_UP_TOOLS,
  }
}

export function buildBinaryDiffProvenance(
  diff: BinaryDiffResult,
  input: BinaryDiffMetadataInput = {}
) {
  return {
    schema: 'rikune.binary_diff.provenance.v1',
    tool: 'binary.diff',
    artifact_type: BINARY_DIFF_ARTIFACT_TYPE,
    generated_at: new Date().toISOString(),
    sample_pair: {
      sample_id_a: diff.sample_id_a,
      sample_id_b: diff.sample_id_b,
    },
    requested_options: {
      include_function_diff: input.include_function_diff ?? true,
      include_structural_diff: input.include_structural_diff ?? true,
      include_attack_diff: input.include_attack_diff ?? true,
      max_functions: input.max_functions ?? null,
    },
    sources: {
      function_diff: {
        backend: 'radiff2',
        adapter: BINARY_DIFF_WORKER_BACKEND.adapter,
        readiness_tool: 'tool.readiness',
        requested: input.include_function_diff ?? true,
        available: Boolean(diff.function_diff),
        ok: diff.function_diff?.ok ?? false,
        warnings: diff.function_diff?.warnings ?? [],
        error: diff.function_diff?.error ?? null,
      },
      structural_delta: {
        source: 'analysis_evidence',
        requested: input.include_structural_diff ?? true,
        available: Boolean(diff.structural_delta),
        evidence_families: ['imports', 'exports', 'sections', 'strings'],
      },
      attack_delta: {
        source: 'analysis_evidence',
        requested: input.include_attack_diff ?? true,
        available: Boolean(diff.attack_delta),
        evidence_families: ['attack_map', 'attack'],
      },
    },
    warnings: diff.warnings,
    errors: diff.errors,
  }
}

export function buildBinaryDiffWorkflowHandoff(diff: BinaryDiffResult, artifact?: ArtifactRef) {
  const artifactSelector = artifact
    ? { artifact_id: artifact.id, artifact_type: artifact.type, path: artifact.path }
    : { artifact_type: BINARY_DIFF_ARTIFACT_TYPE }
  return {
    schema: 'rikune.binary_diff.workflow_handoff.v1',
    sample_pair: {
      sample_id_a: diff.sample_id_a,
      sample_id_b: diff.sample_id_b,
    },
    artifact_contract: {
      produces: [BINARY_DIFF_ARTIFACT_TYPE],
      primary: artifactSelector,
      consumers: ['binary.diff.summary', 'analysis.evidence.graph', 'report.generate'],
    },
    routing: [
      {
        goal: 'variant-comparison',
        next_tools: ['binary.diff.summary', 'analysis.evidence.graph', 'report.generate'],
        evidence: ['binary-diff', 'similarity', 'provenance'],
      },
      {
        goal: 'function-comparison',
        next_tools: ['binary.diff.summary', 'tool.readiness', 'analysis.evidence.graph'],
        evidence: ['function-similarity'],
        backend: 'radiff2',
      },
      {
        goal: 'structural-delta',
        next_tools: ['analysis.evidence.graph', 'report.generate', 'artifact.read'],
        evidence: ['imports', 'exports', 'sections', 'strings', 'attack'],
      },
    ],
    evidence_graph: {
      tool: 'analysis.evidence.graph',
      node_kinds: [
        'sample',
        'binary_diff',
        'function_similarity',
        'structural_delta',
        'attack_delta',
      ],
      edge_hints: [
        'sample_a compared_to sample_b',
        'binary_diff has_function_similarity function_similarity',
        'binary_diff has_structural_delta structural_delta',
        'binary_diff has_attack_delta attack_delta',
      ],
    },
    report: {
      tool: 'report.generate',
      recommended_sections: [
        'Binary diff provenance',
        'Variant similarity profile',
        'Function comparison deltas',
        'Imports/exports/sections/strings structural deltas',
        'ATT&CK technique delta',
      ],
    },
    similarity: {
      profile_schema: 'rikune.binary_diff.similarity_profile.v1',
      classification: buildBinaryDiffSimilarityProfile(diff).classification,
      next_tools: ['binary.diff.summary', 'analysis.evidence.graph'],
    },
    dynamic_boundary: {
      status: 'static_only',
      no_live_sample_execution: true,
      no_network: true,
      no_mutation: true,
    },
    recommended_next_tools: BINARY_DIFF_FOLLOW_UP_TOOLS,
  }
}

export function buildBinaryDiffQualityGates(diff: BinaryDiffResult) {
  return {
    schema: 'rikune.binary_diff.quality_gates.v1',
    static_only: true,
    function_diff_requested_or_available: Boolean(diff.function_diff),
    function_diff_backend_ok: diff.function_diff?.ok ?? false,
    structural_delta_available: Boolean(diff.structural_delta),
    attack_delta_available: Boolean(diff.attack_delta),
    has_diff_signal:
      diff.summary_stats.functions_added +
        diff.summary_stats.functions_removed +
        diff.summary_stats.functions_modified +
        diff.summary_stats.imports_added +
        diff.summary_stats.imports_removed +
        diff.summary_stats.strings_added +
        diff.summary_stats.strings_removed +
        diff.summary_stats.attack_techniques_added +
        diff.summary_stats.attack_techniques_removed >
      0,
    warnings_count: diff.warnings.length,
    errors_count: diff.errors.length,
  }
}
