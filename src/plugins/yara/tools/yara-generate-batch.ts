/**
 * yara.generate.batch MCP tool — generate family detection rules from multiple samples.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import {
  extractRuleEvidence,
  buildHybridRule,
  scoreRule,
  type RuleMeta,
  type RuleEvidence,
  type Strictness,
} from '../yara-rule-builder.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'yara.generate.batch'
const TOOL_VERSION = '0.1.0'
const YARA_FAMILY_RULE_ARTIFACT_TYPE = 'yara_family_rule'

const GeneratedYaraFamilyRuleSchema = z.object({
  type: z.string(),
  rule_text: z.string(),
  score: z.number(),
  breakdown: z.record(z.any()),
})

export const YaraGenerateBatchInputSchema = z.object({
  sample_ids: z
    .array(z.string())
    .min(2)
    .max(50)
    .describe('Array of sample IDs to find common features'),
  strictness: z
    .enum(['tight', 'balanced', 'loose'])
    .optional()
    .default('balanced')
    .describe('Rule strictness'),
  family_name: z.string().optional().describe('Malware family name for the rule'),
})

export const YaraGenerateBatchOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_ids: z.array(z.string()).optional(),
      primary_sample_id: z.string().optional(),
      strictness: z.enum(['tight', 'balanced', 'loose']).optional(),
      family_name: z.string().nullable().optional(),
      family_rule: GeneratedYaraFamilyRuleSchema.optional(),
      rule_text: z.string().optional(),
      score: z.number().optional(),
      breakdown: z.record(z.any()).optional(),
      common_features: z
        .object({
          strings: z.number(),
          imports: z.number(),
          min_occurrence: z.number(),
        })
        .optional(),
      sample_count: z.number().optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
    })
    .passthrough()
    .optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const yaraGenerateBatchToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Generate YARA family detection rules by finding common unique features across multiple samples.',
  inputSchema: YaraGenerateBatchInputSchema,
  outputSchema: YaraGenerateBatchOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'apk', 'dex', 'jar', 'dotnet', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'family-rule-generation',
      'cluster-common-features',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: YARA_FAMILY_RULE_ARTIFACT_TYPE,
      description:
        'Generated YARA family rule with common feature evidence, workflow handoff, and quality gates',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'signatures',
      artifactTypes: [YARA_FAMILY_RULE_ARTIFACT_TYPE],
    },
    {
      category: 'strings',
      artifactTypes: [YARA_FAMILY_RULE_ARTIFACT_TYPE],
    },
    {
      category: 'imports',
      artifactTypes: [YARA_FAMILY_RULE_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [YARA_FAMILY_RULE_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [YARA_FAMILY_RULE_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'yara.family-rule-generation-handoff',
      title: 'YARA family rule generation to validation and reporting',
      description:
        'Generate a multi-sample family YARA rule from common strings/imports, then route it through corpus validation, family clustering, evidence graphing, and reporting.',
      startsWith: ['yara.generate.batch', 'sample.family.cluster', 'yara.generate'],
      nextTools: [
        'yara.scan',
        'sample.family.cluster',
        'analysis.evidence.graph',
        'report.generate',
        'artifact.read',
      ],
      requiredArtifacts: ['analysis_evidence'],
      producesArtifacts: [YARA_FAMILY_RULE_ARTIFACT_TYPE],
      evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

// ============================================================================
// Common feature extraction
// ============================================================================

function findCommonStrings(evidenceList: RuleEvidence[], minOccurrence: number): string[] {
  const counts = new Map<string, number>()
  for (const ev of evidenceList) {
    const seen = new Set<string>()
    for (const s of ev.unique_strings) {
      if (!seen.has(s)) {
        counts.set(s, (counts.get(s) ?? 0) + 1)
        seen.add(s)
      }
    }
  }
  return [...counts.entries()]
    .filter(([, count]) => count >= minOccurrence)
    .sort((a, b) => b[1] - a[1])
    .map(([s]) => s)
    .slice(0, 50)
}

function findCommonImports(evidenceList: RuleEvidence[], minOccurrence: number): string[] {
  const counts = new Map<string, number>()
  for (const ev of evidenceList) {
    const seen = new Set<string>()
    for (const imp of ev.suspicious_imports) {
      const key = imp.toLowerCase()
      if (!seen.has(key)) {
        counts.set(key, (counts.get(key) ?? 0) + 1)
        seen.add(key)
      }
    }
  }
  return [...counts.entries()]
    .filter(([, count]) => count >= minOccurrence)
    .sort((a, b) => b[1] - a[1])
    .map(([s]) => s)
    .slice(0, 20)
}

type GeneratedYaraFamilyRule = z.infer<typeof GeneratedYaraFamilyRuleSchema>

interface CommonFeatureCounts {
  strings: number
  imports: number
  min_occurrence: number
}

function qualityTier(score: number): 'high' | 'medium' | 'low' {
  if (score >= 75) return 'high'
  if (score >= 50) return 'medium'
  return 'low'
}

function buildRecommendedNextTools(): string[] {
  return [
    'yara.scan',
    'sample.family.cluster',
    'analysis.evidence.graph',
    'report.generate',
    'artifact.read',
  ]
}

function buildNextActions(args: { score: number; commonFeatures: CommonFeatureCounts }): string[] {
  const actions = [
    'Validate the generated family rule against related samples and a benign corpus before relying on it.',
    'Use sample.family.cluster or binary.diff.summary to confirm that common features represent family-level behavior.',
    'Publish the persisted yara_family_rule artifact through analysis.evidence.graph and report.generate.',
  ]

  if (args.commonFeatures.strings + args.commonFeatures.imports < 2) {
    actions.unshift(
      'Gather more family samples or richer string/import evidence before promoting this rule.'
    )
  }
  if (args.score < 50) {
    actions.unshift(
      'Review the rule manually because the generated score is below the promotion floor.'
    )
  }

  return actions
}

function buildEvidenceSummary(args: {
  sampleIds: string[]
  strictness: Strictness
  familyName?: string
  score: number
  evidenceList: RuleEvidence[]
  commonFeatures: CommonFeatureCounts
}) {
  return {
    schema: 'rikune.yara_family_rule.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_count: args.sampleIds.length,
    sample_ids: args.sampleIds,
    family_name: args.familyName || null,
    strictness: args.strictness,
    score: args.score,
    quality_tier: qualityTier(args.score),
    common_feature_counts: args.commonFeatures,
    support_threshold: {
      min_occurrence: args.commonFeatures.min_occurrence,
      sample_count: args.sampleIds.length,
    },
    per_sample_evidence_counts: args.evidenceList.map((evidence, index) => ({
      sample_id: args.sampleIds[index],
      unique_strings: evidence.unique_strings.length,
      all_imports: evidence.all_imports.length,
      suspicious_imports: evidence.suspicious_imports.length,
      byte_patterns: evidence.byte_patterns.length,
    })),
    evidence_sources: ['analysis_evidence', 'sample_metadata'],
  }
}

function buildQualityGates(args: {
  score: number
  sampleCount: number
  commonFeatures: CommonFeatureCounts
}) {
  return {
    schema: 'rikune.yara_generate_batch.quality_gates.v1',
    passive_generation_only: true,
    sample_executed_by_tool: false,
    backend_started: false,
    network_accessed_by_tool: false,
    generated_rule_count: 1,
    family_sample_count: args.sampleCount,
    minimum_family_size_met: args.sampleCount >= 2,
    common_feature_floor_met: args.commonFeatures.strings + args.commonFeatures.imports > 0,
    best_score: args.score,
    quality_tier: qualityTier(args.score),
    minimum_score_met: args.score >= 50,
    family_cluster_review_required: true,
    false_positive_review_required: true,
    corpus_validation_required: true,
    analyst_review_required: true,
  }
}

function buildWorkflowHandoff(args: {
  sampleIds: string[]
  strictness: Strictness
  familyName?: string
  score: number
  commonFeatures: CommonFeatureCounts
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.yara_generate_batch.workflow_handoff.v1',
    handoff_mode: 'yara_family_rule_to_cluster_validation_and_reporting',
    source_tool: TOOL_NAME,
    artifact_type: YARA_FAMILY_RULE_ARTIFACT_TYPE,
    primary_sample_id: args.sampleIds[0],
    sample_ids: args.sampleIds,
    family_name: args.familyName || null,
    strictness: args.strictness,
    generated_rule_count: 1,
    score: args.score,
    common_features: args.commonFeatures,
    recommended_next_tools: args.recommendedNextTools,
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: false,
      network_accessed_by_tool: false,
      live_scan_started: false,
      deployment_mutation_requested: false,
    },
    routing: [
      {
        goal: 'family-rule-validation-and-false-positive-review',
        priority: 'high',
        next_tools: ['yara.scan'],
        required_evidence: [
          YARA_FAMILY_RULE_ARTIFACT_TYPE,
          'related sample corpus',
          'benign corpus',
        ],
      },
      {
        goal: 'family-cluster-corroboration',
        priority: 'normal',
        next_tools: ['sample.family.cluster', 'binary.diff.summary'],
        required_evidence: [YARA_FAMILY_RULE_ARTIFACT_TYPE, 'multi-sample analysis evidence'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [YARA_FAMILY_RULE_ARTIFACT_TYPE],
      },
    ],
  }
}

function buildStructuredResult(args: {
  sampleIds: string[]
  strictness: Strictness
  familyName?: string
  rule: GeneratedYaraFamilyRule
  evidenceList: RuleEvidence[]
  commonFeatures: CommonFeatureCounts
}) {
  const recommendedNextTools = buildRecommendedNextTools()
  const evidenceSummary = buildEvidenceSummary({
    sampleIds: args.sampleIds,
    strictness: args.strictness,
    familyName: args.familyName,
    score: args.rule.score,
    evidenceList: args.evidenceList,
    commonFeatures: args.commonFeatures,
  })
  const qualityGates = buildQualityGates({
    score: args.rule.score,
    sampleCount: args.sampleIds.length,
    commonFeatures: args.commonFeatures,
  })
  const workflowHandoff = buildWorkflowHandoff({
    sampleIds: args.sampleIds,
    strictness: args.strictness,
    familyName: args.familyName,
    score: args.rule.score,
    commonFeatures: args.commonFeatures,
    recommendedNextTools,
  })

  return {
    schema: 'rikune.yara_family_rule.v1',
    tool_version: TOOL_VERSION,
    sample_ids: args.sampleIds,
    primary_sample_id: args.sampleIds[0],
    strictness: args.strictness,
    family_name: args.familyName || null,
    family_rule: args.rule,
    rule_text: args.rule.rule_text,
    score: args.rule.score,
    breakdown: args.rule.breakdown,
    common_features: args.commonFeatures,
    sample_count: args.sampleIds.length,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
    recommended_next_tools: recommendedNextTools,
    next_actions: buildNextActions({
      score: args.rule.score,
      commonFeatures: args.commonFeatures,
    }),
  }
}

// ============================================================================
// Handler
// ============================================================================

export function createYaraGenerateBatchHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = YaraGenerateBatchInputSchema.parse(args)
    const warnings: string[] = []

    // Validate all samples exist
    const missing = input.sample_ids.filter((id) => !database.findSample(id))
    if (missing.length > 0) {
      return { ok: false, errors: [`Samples not found: ${missing.join(', ')}`] }
    }

    // Load evidence for all samples
    const evidenceList: RuleEvidence[] = []
    for (const sampleId of input.sample_ids) {
      const evidence = database.findAnalysisEvidenceBySample(sampleId)
      const combined: Record<string, unknown> = {}
      if (Array.isArray(evidence)) {
        for (const entry of evidence) {
          const data =
            typeof entry.result_json === 'string'
              ? JSON.parse(entry.result_json)
              : entry.result_json
          if (data && typeof data === 'object') Object.assign(combined, data)
        }
      }
      const sample = database.findSample(sampleId)
      if (sample) combined.file_size = sample.size
      evidenceList.push(extractRuleEvidence(combined))
    }

    // Find common features (present in >= 60% of samples)
    const minOccurrence = Math.max(2, Math.floor(input.sample_ids.length * 0.6))
    const commonStrings = findCommonStrings(evidenceList, minOccurrence)
    const commonImports = findCommonImports(evidenceList, minOccurrence)

    if (commonStrings.length === 0 && commonImports.length === 0) {
      return {
        ok: false,
        errors: ['No common features found across the provided samples'],
        warnings,
      }
    }

    const familyEvidence: RuleEvidence = {
      unique_strings: commonStrings,
      suspicious_imports: commonImports,
      all_imports: commonImports,
      byte_patterns: [],
    }

    const meta: RuleMeta = {
      sample_id: input.sample_ids[0],
      description: `Family rule for ${input.family_name ?? 'unknown'} (${input.sample_ids.length} samples)`,
      family: input.family_name,
      date: new Date().toISOString().slice(0, 10),
    }

    const ruleText = buildHybridRule(familyEvidence, input.strictness as Strictness, meta)
    if (!ruleText) {
      return { ok: false, errors: ['Failed to generate family rule'] }
    }

    const { score, breakdown } = scoreRule(ruleText, familyEvidence)
    const familyRule: GeneratedYaraFamilyRule = {
      type: 'family_hybrid',
      rule_text: ruleText,
      score,
      breakdown,
    }
    const commonFeatures = {
      strings: commonStrings.length,
      imports: commonImports.length,
      min_occurrence: minOccurrence,
    }
    const structuredResult = buildStructuredResult({
      sampleIds: input.sample_ids,
      strictness: input.strictness,
      familyName: input.family_name,
      rule: familyRule,
      evidenceList,
      commonFeatures,
    })

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager,
        database,
        input.sample_ids[0],
        YARA_FAMILY_RULE_ARTIFACT_TYPE,
        `yara_family_${input.family_name ?? 'batch'}`,
        structuredResult
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist family rule artifact')
    }

    return {
      ok: true,
      data: structuredResult,
      warnings: warnings.length > 0 ? warnings : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
