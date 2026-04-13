import { z } from 'zod'
import { clamp } from '../utils/shared-helpers.js'

export const ConfidenceSemanticsSchema = z.object({
  score_kind: z.enum([
    'heuristic_reconstruction',
    'runtime_correlation',
    'naming_resolution',
    'report_assessment',
    'capability_assessment',
    'pe_structure_analysis',
    'toolchain_attribution',
  ]),
  score: z.number().min(0).max(1).nullable(),
  band: z.enum(['none', 'low', 'medium', 'high']),
  calibrated: z.boolean(),
  meaning: z.string(),
  compare_within: z.string(),
  caution: z.string(),
  acceptance_rule: z.string().nullable().optional(),
  drivers: z.array(z.string()),
})

export type ConfidenceSemantics = z.infer<typeof ConfidenceSemanticsSchema>

export function confidenceBand(score: number | null | undefined): z.infer<typeof ConfidenceSemanticsSchema>['band'] {
  if (typeof score !== 'number' || Number.isNaN(score)) {
    return 'none'
  }
  if (score >= 0.75) {
    return 'high'
  }
  if (score >= 0.45) {
    return 'medium'
  }
  return 'low'
}

export function buildReconstructionConfidenceSemantics(input: {
  score: number
  breakdown: {
    decompile: number
    cfg: number
    assembly: number
    context: number
  }
  runtimeConfidence?: number | null
}): ConfidenceSemantics {
  const drivers = [
    input.breakdown.decompile > 0 ? `decompile=${input.breakdown.decompile.toFixed(2)}` : '',
    input.breakdown.cfg > 0 ? `cfg=${input.breakdown.cfg.toFixed(2)}` : '',
    input.breakdown.assembly > 0 ? `assembly=${input.breakdown.assembly.toFixed(2)}` : '',
    input.breakdown.context > 0 ? `context=${input.breakdown.context.toFixed(2)}` : '',
    typeof input.runtimeConfidence === 'number' && input.runtimeConfidence > 0
      ? `runtime_correlation=${input.runtimeConfidence.toFixed(2)}`
      : '',
  ].filter((item) => item.length > 0)

  return {
    score_kind: 'heuristic_reconstruction',
    score: clamp(input.score, 0, 1),
    band: confidenceBand(input.score),
    calibrated: false,
    meaning:
      'Heuristic evidence score for reconstruction quality. Higher values mean stronger decompile/CFG/assembly/context support, not probability of semantic correctness.',
    compare_within:
      'Compare across functions produced by the same tool version and evidence scope, not across unrelated tools or datasets.',
    caution:
      'Treat as ranking-oriented guidance. Low-level helper functions can still be correct at lower scores, and large complex functions can still contain wrong details at high scores.',
    drivers,
  }
}

export function buildRuntimeConfidenceSemantics(input: {
  score: number | null | undefined
  matchedApis?: string[]
  matchedStages?: string[]
  matchedMemoryRegions?: string[]
  executed?: boolean
  evidenceSources?: string[]
}): ConfidenceSemantics | null {
  if (typeof input.score !== 'number' || Number.isNaN(input.score)) {
    return null
  }

  const drivers = [
    (input.matchedApis || []).length > 0 ? `matched_apis=${(input.matchedApis || []).length}` : '',
    (input.matchedStages || []).length > 0 ? `matched_stages=${(input.matchedStages || []).length}` : '',
    (input.matchedMemoryRegions || []).length > 0
      ? `matched_regions=${(input.matchedMemoryRegions || []).length}`
      : '',
    input.executed ? 'executed_trace=yes' : 'executed_trace=no',
    (input.evidenceSources || []).length > 0
      ? `sources=${(input.evidenceSources || []).slice(0, 3).join(',')}`
      : '',
  ].filter((item) => item.length > 0)

  return {
    score_kind: 'runtime_correlation',
    score: clamp(input.score, 0, 1),
    band: confidenceBand(input.score),
    calibrated: false,
    meaning:
      'Heuristic overlap score between this function and runtime evidence. Higher values mean more API/stage/region corroboration, not proof that the entire function executed.',
    compare_within:
      'Compare across functions under the same evidence_scope and selected runtime artifacts.',
    caution:
      'String-heavy memory snapshots and shared helper routines can inflate overlap without proving exact control-flow execution.',
    drivers,
  }
}

export function buildNamingConfidenceSemantics(input: {
  resolutionSource: 'rule' | 'llm' | 'hybrid' | 'unresolved'
  renameConfidence?: number | null
  llmConfidence?: number | null
  ruleBasedName?: string | null
  validatedName?: string | null
}): ConfidenceSemantics {
  const baseScore =
    input.resolutionSource === 'llm'
      ? input.llmConfidence ?? null
      : input.renameConfidence ?? input.llmConfidence ?? null

  const drivers = [
    input.ruleBasedName ? `rule_name=${input.ruleBasedName}` : '',
    input.validatedName ? `validated_name=${input.validatedName}` : '',
    typeof input.renameConfidence === 'number' ? `rule_score=${input.renameConfidence.toFixed(2)}` : '',
    typeof input.llmConfidence === 'number' ? `llm_score=${input.llmConfidence.toFixed(2)}` : '',
    `resolution_source=${input.resolutionSource}`,
  ].filter((item) => item.length > 0)

  return {
    score_kind: 'naming_resolution',
    score: typeof baseScore === 'number' ? clamp(baseScore, 0, 1) : null,
    band: confidenceBand(baseScore),
    calibrated: false,
    meaning:
      'Semantic naming confidence for the chosen label. It ranks naming support strength, not certainty that the recovered name matches the original source identifier.',
    compare_within:
      'Compare across names generated by the same naming pipeline version. Rule-based and LLM-suggested scores are still heuristic.',
    caution:
      'A validated name can still be approximate. Original developer naming cannot be reconstructed from this score alone.',
    acceptance_rule:
      'Rule-based names currently take priority. Pure LLM suggestions are promoted to validated_name only when llm_confidence >= 0.62.',
    drivers,
  }
}

export function buildReportConfidenceSemantics(input: {
  score: number
  evidenceScope: 'all' | 'latest' | 'session'
  runtimeLayers?: string[]
  executedTracePresent?: boolean
}): ConfidenceSemantics {
  const drivers = [
    `evidence_scope=${input.evidenceScope}`,
    (input.runtimeLayers || []).length > 0
      ? `runtime_layers=${(input.runtimeLayers || []).join('>')}`
      : 'runtime_layers=static_only',
    input.executedTracePresent ? 'executed_trace=yes' : 'executed_trace=no',
  ]

  return {
    score_kind: 'report_assessment',
    score: clamp(input.score, 0, 1),
    band: confidenceBand(input.score),
    calibrated: false,
    meaning:
      'Assessment confidence for the generated report or triage summary. It indicates evidence strength and corroboration depth, not a calibrated threat probability.',
    compare_within:
      'Compare within the same report mode, tool version, and evidence scope.',
    caution:
      'Threat or intent judgments remain evidence-sensitive and can shift when scope changes from all to latest/session or when stronger runtime evidence is added.',
    drivers,
  }
}


export function buildCapabilityConfidenceSemantics(input: {
  score: number
  findings: number
  groups: string[]
  rulesSource: string | null
}): ConfidenceSemantics {
  return {
    score_kind: 'capability_assessment',
    score: clamp(input.score, 0, 1),
    band: confidenceBand(input.score),
    calibrated: false,
    meaning:
      'Heuristic confidence for recovered capability findings. Higher values mean stronger rule coverage and corroborating evidence, not proof that every capability executed.',
    compare_within:
      'Compare within static capability triage runs that use similar capa rules and the same tool version.',
    caution:
      'Capability matches can overstate intent when only static rule evidence is available. Validate with runtime evidence or deeper function-level analysis when possible.',
    drivers: [
      `findings=${input.findings}`,
      input.groups.length > 0 ? `groups=${input.groups.slice(0, 4).join(',')}` : 'groups=none',
      input.rulesSource ? `rules_source=${input.rulesSource}` : 'rules_source=unknown',
    ],
  }
}

export function buildPeStructureConfidenceSemantics(input: {
  score: number
  backendCount: number
  sections: number
  imports: number
  exports: number
}): ConfidenceSemantics {
  return {
    score_kind: 'pe_structure_analysis',
    score: clamp(input.score, 0, 1),
    band: confidenceBand(input.score),
    calibrated: false,
    meaning:
      'Heuristic confidence for PE structure parsing. Higher values mean multiple parsers and richer section/import/export coverage, not a guarantee that every backend field agrees perfectly.',
    compare_within:
      'Compare within PE structure analysis runs for the same file format and tool version.',
    caution:
      'Lightweight and rebuild-oriented parsers can disagree on malformed samples. Review backend_details when a packed or damaged sample is involved.',
    drivers: [
      `backends=${input.backendCount}`,
      `sections=${input.sections}`,
      `imports=${input.imports}`,
      `exports=${input.exports}`,
    ],
  }
}

export function buildToolchainConfidenceSemantics(input: {
  score: number
  compilerCount: number
  packerCount: number
  protectorCount: number
  backendSource: string | null
}): ConfidenceSemantics {
  return {
    score_kind: 'toolchain_attribution',
    score: clamp(input.score, 0, 1),
    band: confidenceBand(input.score),
    calibrated: false,
    meaning:
      'Heuristic confidence for compiler, packer, and protector attribution. Higher values mean stronger backend evidence and clearer category separation, not certainty that the original toolchain has been uniquely identified.',
    compare_within:
      'Compare within compiler/packer attribution runs produced by the same Detect It Easy backend version.',
    caution:
      'Packed, modified, or partially reconstructed files can blend compiler and protector signatures. Use as routing guidance rather than a final verdict.',
    drivers: [
      `compiler_findings=${input.compilerCount}`,
      `packer_findings=${input.packerCount}`,
      `protector_findings=${input.protectorCount}`,
      input.backendSource ? `backend_source=${input.backendSource}` : 'backend_source=unknown',
    ],
  }
}
