/**
 * yara.generate MCP tool — auto-generate YARA detection rules from sample analysis evidence.
 */

import { z } from 'zod'
import fs from 'fs/promises'
import path from 'path'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import {
  extractRuleEvidence,
  buildStringRule,
  buildImportRule,
  buildBytePatternRule,
  buildHybridRule,
  scoreRule,
  type Strictness,
  type RuleMeta,
  type RuleEvidence,
} from '../yara-rule-builder.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'yara.generate'
const TOOL_VERSION = '0.1.0'
const YARA_RULE_GENERATION_ARTIFACT_TYPE = 'yara_rule_generation'

const GeneratedYaraRuleSchema = z.object({
  type: z.string(),
  rule_text: z.string(),
  score: z.number(),
  breakdown: z.record(z.string(), z.any()),
})

export const YaraGenerateInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  strictness: z
    .enum(['tight', 'balanced', 'loose'])
    .optional()
    .default('balanced')
    .describe('Rule strictness: tight (fewer FPs), balanced, loose (fewer FNs)'),
  deploy: z
    .boolean()
    .optional()
    .default(false)
    .describe('Deploy generated rule to workers/yara_rules/ for future scans'),
  rule_types: z
    .array(z.enum(['string', 'import', 'byte_pattern', 'hybrid']))
    .optional()
    .default(['hybrid'])
    .describe('Types of rules to generate'),
})

export const YaraGenerateOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      strictness: z.enum(['tight', 'balanced', 'loose']).optional(),
      deploy_requested: z.boolean().optional(),
      rules: z.array(GeneratedYaraRuleSchema).optional(),
      best_rule: GeneratedYaraRuleSchema.optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
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

export const yaraGenerateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Auto-generate YARA detection rules from sample analysis evidence (strings, imports, byte patterns). Supports tight/balanced/loose strictness levels.',
  inputSchema: YaraGenerateInputSchema,
  outputSchema: YaraGenerateOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'apk', 'dex', 'jar', 'dotnet', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'rule-generation',
      'strings',
      'imports',
      'byte-patterns',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: YARA_RULE_GENERATION_ARTIFACT_TYPE,
      description:
        'Generated YARA rules with evidence summary, workflow handoff, and quality gates',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'signatures',
      artifactTypes: [YARA_RULE_GENERATION_ARTIFACT_TYPE],
    },
    {
      category: 'strings',
      artifactTypes: [YARA_RULE_GENERATION_ARTIFACT_TYPE],
    },
    {
      category: 'imports',
      artifactTypes: [YARA_RULE_GENERATION_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [YARA_RULE_GENERATION_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [YARA_RULE_GENERATION_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'yara.rule-generation-handoff',
      title: 'YARA rule generation to validation and reporting',
      description:
        'Turn extracted strings, imports, and byte patterns into generated YARA rules with validation gates, evidence graph routing, and reporting handoff.',
      startsWith: ['yara.generate', 'strings.extract', 'pe.imports.extract'],
      nextTools: ['yara.scan', 'analysis.evidence.graph', 'report.generate', 'artifact.read'],
      requiredArtifacts: ['analysis_evidence'],
      producesArtifacts: [YARA_RULE_GENERATION_ARTIFACT_TYPE],
      evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

// ============================================================================
// Handler
// ============================================================================

async function loadAnalysisEvidence(
  database: DatabaseManager,
  sampleId: string
): Promise<Record<string, unknown>> {
  const combined: Record<string, unknown> = {}
  const evidence = database.findAnalysisEvidenceBySample(sampleId)

  if (Array.isArray(evidence)) {
    for (const entry of evidence) {
      const data =
        typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
      if (!data || typeof data !== 'object') continue
      Object.assign(combined, data)
    }
  }

  // Also get sample info
  const sample = database.findSample(sampleId)
  if (sample) {
    combined.file_size = sample.size
  }

  return combined
}

type GeneratedYaraRule = z.infer<typeof GeneratedYaraRuleSchema>

function buildEvidenceSummary(args: {
  sampleId: string
  strictness: Strictness
  deployRequested: boolean
  evidence: RuleEvidence
  rules: GeneratedYaraRule[]
}) {
  const bestScore = Math.max(...args.rules.map((rule) => rule.score), 0)

  return {
    schema: 'rikune.yara_rule_generation.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    strictness: args.strictness,
    deploy_requested: args.deployRequested,
    rules_generated: args.rules.length,
    generated_rule_types: args.rules.map((rule) => rule.type),
    best_score: bestScore,
    evidence_counts: {
      unique_strings: args.evidence.unique_strings.length,
      all_imports: args.evidence.all_imports.length,
      suspicious_imports: args.evidence.suspicious_imports.length,
      byte_patterns: args.evidence.byte_patterns.length,
    },
    evidence_sources: ['analysis_evidence', 'sample_metadata'],
  }
}

function qualityTier(score: number): 'high' | 'medium' | 'low' {
  if (score >= 75) return 'high'
  if (score >= 50) return 'medium'
  return 'low'
}

function buildRecommendedNextTools(): string[] {
  return ['yara.scan', 'analysis.evidence.graph', 'report.generate', 'artifact.read']
}

function buildNextActions(args: { bestScore: number; deployRequested: boolean }): string[] {
  const actions = [
    'Review the best rule score and score breakdown for over-broad strings, imports, or byte patterns.',
    'Run yara.scan against related malware samples and a benign corpus before relying on the rule.',
    'Publish the persisted yara_rule_generation artifact through analysis.evidence.graph and report.generate.',
  ]

  if (args.bestScore < 50) {
    actions.unshift(
      'Gather richer string/import evidence before promoting this rule to detection use.'
    )
  }
  if (args.deployRequested) {
    actions.unshift('Confirm deployed rule files were reviewed before production scanning.')
  }

  return actions
}

function buildQualityGates(args: {
  bestScore: number
  deployRequested: boolean
  evidence: RuleEvidence
  rules: GeneratedYaraRule[]
}) {
  return {
    schema: 'rikune.yara_generate.quality_gates.v1',
    passive_generation_only: true,
    sample_executed_by_tool: false,
    backend_started: false,
    network_accessed_by_tool: false,
    generated_rule_count: args.rules.length,
    best_score: args.bestScore,
    quality_tier: qualityTier(args.bestScore),
    minimum_score_met: args.bestScore >= 50,
    false_positive_review_required: true,
    corpus_validation_required: true,
    analyst_review_required: true,
    deploy_requested: args.deployRequested,
    deployment_mutation_requested: args.deployRequested,
    evidence_floor: {
      unique_strings: args.evidence.unique_strings.length,
      suspicious_imports: args.evidence.suspicious_imports.length,
      byte_patterns: args.evidence.byte_patterns.length,
    },
  }
}

function buildWorkflowHandoff(args: {
  sampleId: string
  strictness: Strictness
  deployRequested: boolean
  bestScore: number
  evidence: RuleEvidence
  rules: GeneratedYaraRule[]
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.yara_generate.workflow_handoff.v1',
    handoff_mode: 'yara_rule_generation_to_validation_and_reporting',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    artifact_type: YARA_RULE_GENERATION_ARTIFACT_TYPE,
    strictness: args.strictness,
    deploy_requested: args.deployRequested,
    generated_rule_count: args.rules.length,
    generated_rule_types: args.rules.map((rule) => rule.type),
    best_score: args.bestScore,
    recommended_next_tools: args.recommendedNextTools,
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: false,
      network_accessed_by_tool: false,
      live_scan_started: false,
      deployment_mutation_requested: args.deployRequested,
    },
    routing: [
      {
        goal: 'rule-validation-and-false-positive-review',
        priority: 'high',
        next_tools: ['yara.scan'],
        required_evidence: [
          YARA_RULE_GENERATION_ARTIFACT_TYPE,
          'known benign or related sample corpus',
        ],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [YARA_RULE_GENERATION_ARTIFACT_TYPE],
      },
      {
        goal: 'ioc-and-family-feedback-loop',
        priority:
          args.evidence.suspicious_imports.length > 0 || args.evidence.unique_strings.length > 0
            ? 'normal'
            : 'low',
        next_tools: ['malware.intel.loop', 'ioc.export'],
        required_evidence: ['analyst approved YARA rule', 'rule evidence summary'],
      },
    ],
  }
}

function buildStructuredResult(args: {
  sampleId: string
  strictness: Strictness
  deployRequested: boolean
  evidence: RuleEvidence
  rules: GeneratedYaraRule[]
}) {
  const sortedRules = [...args.rules].sort((a, b) => b.score - a.score)
  const bestRule = sortedRules[0]
  const bestScore = bestRule?.score ?? 0
  const recommendedNextTools = buildRecommendedNextTools()
  const nextActions = buildNextActions({ bestScore, deployRequested: args.deployRequested })
  const evidenceSummary = buildEvidenceSummary({
    sampleId: args.sampleId,
    strictness: args.strictness,
    deployRequested: args.deployRequested,
    evidence: args.evidence,
    rules: args.rules,
  })
  const qualityGates = buildQualityGates({
    bestScore,
    deployRequested: args.deployRequested,
    evidence: args.evidence,
    rules: args.rules,
  })
  const workflowHandoff = buildWorkflowHandoff({
    sampleId: args.sampleId,
    strictness: args.strictness,
    deployRequested: args.deployRequested,
    bestScore,
    evidence: args.evidence,
    rules: args.rules,
    recommendedNextTools,
  })

  return {
    schema: 'rikune.yara_rule_generation.v1',
    tool_version: TOOL_VERSION,
    sample_id: args.sampleId,
    strictness: args.strictness,
    deploy_requested: args.deployRequested,
    rules: args.rules,
    best_rule: bestRule,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
    recommended_next_tools: recommendedNextTools,
    next_actions: nextActions,
  }
}

export function createYaraGenerateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = YaraGenerateInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Load analysis evidence
    const analysisData = await loadAnalysisEvidence(database, input.sample_id)
    const evidence = extractRuleEvidence(analysisData)

    if (
      evidence.unique_strings.length === 0 &&
      evidence.all_imports.length === 0 &&
      evidence.byte_patterns.length === 0
    ) {
      return {
        ok: false,
        errors: [
          'Insufficient analysis evidence to generate YARA rules. Run strings.extract and pe.imports.extract first.',
        ],
      }
    }

    const meta: RuleMeta = {
      sample_id: input.sample_id,
      description: `Auto-generated ${input.strictness} YARA rule`,
      hash: input.sample_id.startsWith('sha256:') ? input.sample_id.slice(7) : undefined,
      date: new Date().toISOString().slice(0, 10),
    }

    // Generate requested rules
    const rules: GeneratedYaraRule[] = []

    for (const ruleType of input.rule_types) {
      let ruleText = ''
      switch (ruleType) {
        case 'string':
          ruleText = buildStringRule(evidence.unique_strings, meta)
          break
        case 'import':
          ruleText = buildImportRule(
            evidence.suspicious_imports.length > 0
              ? evidence.suspicious_imports
              : evidence.all_imports,
            meta
          )
          break
        case 'byte_pattern':
          ruleText = buildBytePatternRule(evidence.byte_patterns, meta)
          break
        case 'hybrid':
          ruleText = buildHybridRule(evidence, input.strictness as Strictness, meta)
          break
      }

      if (ruleText) {
        const { score, breakdown } = scoreRule(ruleText, evidence)
        rules.push({ type: ruleType, rule_text: ruleText, score, breakdown })
      } else {
        warnings.push(`Could not generate ${ruleType} rule — insufficient evidence`)
      }
    }

    if (rules.length === 0) {
      return {
        ok: false,
        errors: ['No rules could be generated from available evidence'],
        warnings,
      }
    }

    // Deploy if requested
    if (input.deploy) {
      const yaraDir = path.resolve('workers', 'yara_rules')
      try {
        await fs.mkdir(yaraDir, { recursive: true })
        for (const rule of rules) {
          const filename = `auto_${input.sample_id.slice(7, 19)}_${rule.type}.yar`
          await fs.writeFile(path.join(yaraDir, filename), rule.rule_text, 'utf8')
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        warnings.push(`Deploy failed: ${msg.slice(0, 200)}`)
      }
    }

    // Persist artifact
    const artifacts: ArtifactRef[] = []
    const structuredResult = buildStructuredResult({
      sampleId: input.sample_id,
      strictness: input.strictness,
      deployRequested: input.deploy,
      evidence,
      rules,
    })
    try {
      const artifactRef = await persistStaticAnalysisJsonArtifact(
        workspaceManager,
        database,
        input.sample_id,
        YARA_RULE_GENERATION_ARTIFACT_TYPE,
        `yara_${input.strictness}`,
        structuredResult
      )
      artifacts.push(artifactRef)
    } catch {
      warnings.push('Failed to persist rule artifact')
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
