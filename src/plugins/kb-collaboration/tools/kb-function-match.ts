/**
 * kb.function.match MCP tool — Match function signatures across samples
 * to find reused code, shared libraries, and known function patterns.
 * Leverages the knowledge base to propagate names/annotations.
 */

import { z } from 'zod'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
  type ArtifactRef,
  type PluginToolDeps,
} from '../../sdk.js'

const TOOL_NAME = 'kb.function.match'
export const KB_FUNCTION_MATCH_ARTIFACT_TYPE = 'function_match'
export const KB_FUNCTION_MATCH_FORMATS = [
  'artifact',
  'analysis-evidence',
  'function',
  'function-index',
  'function-signature',
  'control-flow-graph',
  'call-graph',
  'strings',
  'constants',
  'code-reuse',
  'knowledge-base',
  'rule',
]
export const KB_COLLABORATION_PLATFORMS = ['cross-platform']
export const KB_COLLABORATION_SAFETY = [
  'passive',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
]
export const KB_FUNCTION_MATCH_CAPABILITIES = [
  'analysis-memory',
  'knowledge-reuse',
  'function-matching',
  'function-signature-correlation',
  'explainable-function-matching',
  'multi-view-similarity',
  'context-aware-matching',
  'code-reuse-detection',
  'annotation-propagation',
  'workflow-plan',
  'workflow-handoff',
  'search-profile',
  'evidence-correlation',
]
export const KB_FUNCTION_MATCH_EVIDENCE = [
  'analysis-memory',
  'functions',
  'symbols',
  'api-calls',
  'strings',
  'control-flow',
  'call-graph',
  'constants',
  'code-reuse',
  'workflow',
  'provenance',
  'search-profile',
]
export const KB_FUNCTION_MATCH_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'analysis.evidence.graph',
  'analysis.notes',
  'rule.library',
  'kb.context.suggest',
  'kb.export',
  'report.generate',
]
export const KB_FUNCTION_MATCH_WORKFLOW_RECIPES = [
  {
    id: 'kb.function-match.reuse-handoff',
    title: 'Knowledge-base function reuse handoff',
    description:
      'Compare function signatures against curated local sample evidence and function_kb entries, surface exact and explainable multi-view reuse, and hand off annotation, evidence-graph, notes, and export follow-ups without network access or sample execution.',
    startsWith: [TOOL_NAME],
    nextTools: KB_FUNCTION_MATCH_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample', 'analysis_evidence', 'function_index'],
    producesArtifacts: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
    evidence: KB_FUNCTION_MATCH_EVIDENCE,
    safety: KB_COLLABORATION_SAFETY,
    runtimeBackends: ['local'],
  },
]
export const KB_COLLABORATION_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noSampleExecution: true,
  notes: [
    'Knowledge-base collaboration uses local database evidence and workspace artifacts only.',
    'Function matching does not execute samples, mutate binaries, or use network access.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noSampleExecution: true
}

const MAX_ID_LENGTH = 512
const MAX_MATCH_AGAINST = 100
const MAX_MATCHES = 1000
const DEFAULT_MAX_REFERENCE_FUNCTIONS = 5000
const HARD_MAX_REFERENCE_FUNCTIONS = 20_000
const MAX_TARGET_FUNCTIONS = 5000
const MAX_PAIR_COMPARISONS = 1_000_000
const MAX_EVIDENCE_RECORDS = 10_000
const MAX_EVIDENCE_SCAN_RECORDS = 20_000
const MAX_EVIDENCE_JSON_BYTES = 16 * 1024 * 1024
const MAX_TOTAL_EVIDENCE_JSON_BYTES = 64 * 1024 * 1024
const MAX_KB_FEATURE_JSON_BYTES = 1024 * 1024
const MAX_KB_PROVENANCE_JSON_BYTES = 8 * 1024 * 1024
const MAX_KB_PROVENANCE_VALUES = 10_000
const MAX_KB_ROW_BYTES = 2 * 1024 * 1024
const MAX_KB_REFERENCE_BYTES = 64 * 1024 * 1024
const MAX_KB_SCAN_ROWS = 20_000
const MAX_FEATURE_VALUES = 512
const MAX_FEATURE_VALUE_LENGTH = 1024
const MAX_CFG_SHAPE_LENGTH = 4096
const MAX_ALTERNATIVES = 3
const LEGACY_REVIEW_CONFIDENCE_CAP = 0.79
const NON_EXACT_CONFIDENCE_CAP = 0.99
const STRONG_SIGNAL_MIN_SCORE = 0.2

const UnitIntervalSchema = z.number().min(0).max(1)
const BoundedIdSchema = z.string().max(MAX_FEATURE_VALUE_LENGTH)
const BoundedFeatureSchema = z.string().max(MAX_FEATURE_VALUE_LENGTH)
const BoundedFeatureListSchema = z.array(BoundedFeatureSchema).max(MAX_FEATURE_VALUES)

const ScoreBreakdownSchema = z.object({
  exact_hash: UnitIntervalSchema,
  api_calls: UnitIntervalSchema,
  strings: UnitIntervalSchema,
  cfg_shape: UnitIntervalSchema,
  crypto_constants: UnitIntervalSchema,
  size: UnitIntervalSchema,
  context: UnitIntervalSchema,
})

const CalibrationSchema = z.object({
  mode: z.enum(['exact_hash', 'legacy_api_size', 'multiview']),
  heuristic_profile: z.literal('rikune.function_match.heuristic.v1'),
  raw_multiview_score: UnitIntervalSchema,
  normalized_multiview_score: UnitIntervalSchema,
  comparable_weight: UnitIntervalSchema,
  matched_evidence_weight: UnitIntervalSchema,
  legacy_score: UnitIntervalSchema.optional(),
  reference_trust: UnitIntervalSchema,
  coverage_factor: UnitIntervalSchema,
  pre_cap_score: UnitIntervalSchema,
  final_score: UnitIntervalSchema,
  independent_signal_count: z.number().int().nonnegative().max(5),
  strong_signal_min_score: UnitIntervalSchema,
  applied_cap: z.enum(['none', 'legacy_review', 'non_exact', 'insufficient_signals']),
  applied_cap_value: UnitIntervalSchema,
})

export const KbFunctionMatchInputSchema = z.object({
  sample_id: z
    .string()
    .trim()
    .min(1)
    .max(MAX_ID_LENGTH)
    .describe('Target sample ID to match functions for'),
  match_against: z
    .array(z.string().trim().min(1).max(MAX_ID_LENGTH))
    .max(MAX_MATCH_AGAINST)
    .optional()
    .describe('Specific sample IDs to match against (or all KB entries if omitted)'),
  min_confidence: z
    .number()
    .min(0)
    .max(1)
    .optional()
    .default(0.7)
    .describe('Minimum similarity score to report a match (0.0-1.0)'),
  max_matches: z
    .number()
    .int()
    .min(1)
    .max(MAX_MATCHES)
    .optional()
    .default(100)
    .describe('Maximum matches to return (1-1000)'),
  max_reference_functions: z
    .number()
    .int()
    .min(1)
    .max(HARD_MAX_REFERENCE_FUNCTIONS)
    .optional()
    .default(DEFAULT_MAX_REFERENCE_FUNCTIONS)
    .describe('Server-bounded maximum reference functions to compare (1-20000)'),
})

export const KbFunctionMatchOutputSchema = createWorkerResultOutputSchema(
  z.object({
    sample_id: BoundedIdSchema,
    target_function_count: z.number().int().nonnegative(),
    reference_function_count: z.number().int().nonnegative(),
    match_count: z.number().int().nonnegative(),
    exact_matches: z.number().int().nonnegative(),
    high_confidence_matches: z.number().int().nonnegative(),
    ambiguous_matches: z.number().int().nonnegative().optional(),
    analysis_limits: z
      .object({
        max_target_functions: z.number().int().positive(),
        max_reference_functions: z.number().int().positive(),
        max_reference_bytes: z.number().int().positive(),
        reference_bytes_selected: z.number().int().nonnegative(),
        max_kb_scan_rows: z.number().int().positive(),
        kb_scan_truncated: z.boolean(),
        max_pair_comparisons: z.number().int().positive(),
        max_evidence_bytes: z.number().int().positive(),
        evidence_bytes_selected: z.number().int().nonnegative(),
        performed_pair_comparisons: z.number().int().nonnegative(),
        target_functions_truncated: z.boolean(),
        reference_functions_truncated: z.boolean(),
        evidence_records_truncated: z.boolean(),
      })
      .optional(),
    diagnostics: z
      .object({
        evidence_records_seen: z.number().int().nonnegative(),
        malformed_evidence_records: z.number().int().nonnegative(),
        oversized_evidence_records: z.number().int().nonnegative(),
        malformed_kb_rows: z.number().int().nonnegative(),
        oversized_kb_rows: z.number().int().nonnegative(),
        kb_rows_scanned: z.number().int().nonnegative(),
        self_referential_kb_rows_excluded: z.number().int().nonnegative(),
      })
      .optional(),
    matching_profile: z.record(z.any()).optional(),
    workflowRecipes: z.array(z.any()).optional(),
    formats: z.array(z.string()).optional(),
    evidence: z.array(z.string()).optional(),
    policy: z.record(z.any()).optional(),
    evidence_summary: z.record(z.any()).optional(),
    workflow_handoff: z.record(z.any()).optional(),
    quality_gates: z.record(z.any()).optional(),
    recommended_next_tools: z.array(z.string()).optional(),
    next_actions: z.array(z.string()).optional(),
    matches: z
      .array(
        z.object({
          target_function: BoundedFeatureSchema,
          target_address: BoundedFeatureSchema,
          matched_function: BoundedFeatureSchema,
          matched_sample_id: BoundedIdSchema,
          matched_address: BoundedFeatureSchema,
          confidence: UnitIntervalSchema,
          similarity: UnitIntervalSchema.optional(),
          legacy_similarity: UnitIntervalSchema.optional(),
          confidence_tier: z.enum(['exact', 'high', 'review']).optional(),
          exact_hash_algorithm: z.enum(['sha256', 'sha512']).optional(),
          reference_source: z.enum(['sample_evidence', 'function_kb']).optional(),
          kb_entry_id: BoundedIdSchema.optional(),
          reference_confidence: UnitIntervalSchema.optional(),
          reference_semantics_source: BoundedFeatureSchema.optional(),
          reference_sample_ids: z.array(BoundedIdSchema).max(MAX_MATCH_AGAINST).optional(),
          match_basis: z.array(BoundedFeatureSchema).max(8).optional(),
          score_breakdown: ScoreBreakdownSchema.optional(),
          score_weights: z.record(UnitIntervalSchema).optional(),
          evidence_coverage: UnitIntervalSchema.optional(),
          comparable_coverage: UnitIntervalSchema.optional(),
          matched_evidence_weight: UnitIntervalSchema.optional(),
          calibration: CalibrationSchema.optional(),
          shared_features: z
            .object({
              api_calls: BoundedFeatureListSchema,
              strings: BoundedFeatureListSchema,
              crypto_constants: BoundedFeatureListSchema,
              cfg_shape: z.string().max(MAX_CFG_SHAPE_LENGTH).optional(),
              callers: BoundedFeatureListSchema,
              callees: BoundedFeatureListSchema,
            })
            .optional(),
          ambiguous: z.boolean().optional(),
          alternative_count: z.number().int().nonnegative().optional(),
          returned_alternative_count: z
            .number()
            .int()
            .nonnegative()
            .max(MAX_ALTERNATIVES)
            .optional(),
          alternatives_truncated: z.boolean().optional(),
          alternatives: z
            .array(
              z.object({
                matched_function: BoundedFeatureSchema,
                matched_sample_id: BoundedIdSchema,
                matched_address: BoundedFeatureSchema,
                confidence: UnitIntervalSchema,
                reference_source: z.enum(['sample_evidence', 'function_kb']),
                kb_entry_id: BoundedIdSchema.optional(),
              })
            )
            .max(MAX_ALTERNATIVES)
            .optional(),
        })
      )
      .max(MAX_MATCHES),
  })
)

export const kbFunctionMatchToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Match function signatures from a sample against the knowledge base and other ' +
    'analyzed samples. Uses exact byte hashes plus deterministic API, string, CFG, ' +
    'constant, size, and call-context evidence to explain reused code candidates ' +
    'before names or annotations are propagated.',
  inputSchema: KbFunctionMatchInputSchema,
  outputSchema: KbFunctionMatchOutputSchema,
  aspects: {
    formats: KB_FUNCTION_MATCH_FORMATS,
    platforms: KB_COLLABORATION_PLATFORMS,
    execution: ['static', 'correlation'],
    safety: KB_COLLABORATION_SAFETY,
    capabilities: KB_FUNCTION_MATCH_CAPABILITIES,
    evidence: KB_FUNCTION_MATCH_EVIDENCE,
  },
  artifacts: [
    {
      type: KB_FUNCTION_MATCH_ARTIFACT_TYPE,
      description:
        'Function signature reuse, exact/high-confidence matches, and analysis-memory handoff',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'analysis-memory', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'functions', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'api-calls', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'control-flow', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'call-graph', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'constants', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'code-reuse', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
  ],
  workflowRecipes: KB_FUNCTION_MATCH_WORKFLOW_RECIPES,
  runtimePolicy: KB_COLLABORATION_RUNTIME_POLICY,
}

interface FunctionSig {
  sample_id: string
  address: string
  name: string
  hash?: string
  hash_algorithm?: string
  size?: number
  api_calls?: string[]
  strings?: string[]
  cfg_shape?: unknown
  crypto_constants?: string[]
  callers?: string[]
  callees?: string[]
  reference_source?: 'sample_evidence' | 'function_kb'
  kb_entry_id?: string
  reference_confidence?: number
  reference_semantics_source?: string
  reference_sample_ids?: string[]
}

interface FunctionMatchScoreBreakdown {
  exact_hash: number
  api_calls: number
  strings: number
  cfg_shape: number
  crypto_constants: number
  size: number
  context: number
}

interface FunctionMatchSharedFeatures {
  api_calls: string[]
  strings: string[]
  crypto_constants: string[]
  cfg_shape?: string
  callers: string[]
  callees: string[]
}

export interface FunctionMatchEntry {
  target_function: string
  target_address: string
  matched_function: string
  matched_sample_id: string
  matched_address: string
  confidence: number
  similarity?: number
  legacy_similarity?: number
  confidence_tier?: 'exact' | 'high' | 'review'
  exact_hash_algorithm?: 'sha256' | 'sha512'
  reference_source?: 'sample_evidence' | 'function_kb'
  kb_entry_id?: string
  reference_confidence?: number
  reference_semantics_source?: string
  reference_sample_ids?: string[]
  match_basis?: string[]
  score_breakdown?: FunctionMatchScoreBreakdown
  score_weights?: Record<string, number>
  evidence_coverage?: number
  comparable_coverage?: number
  matched_evidence_weight?: number
  calibration?: FunctionMatchCalibration
  shared_features?: FunctionMatchSharedFeatures
  ambiguous?: boolean
  alternative_count?: number
  returned_alternative_count?: number
  alternatives_truncated?: boolean
  alternatives?: Array<{
    matched_function: string
    matched_sample_id: string
    matched_address: string
    confidence: number
    reference_source: 'sample_evidence' | 'function_kb'
    kb_entry_id?: string
  }>
}

const MATCHING_MODEL = 'rikune.function_match.multiview.v1'
const HEURISTIC_PROFILE = 'rikune.function_match.heuristic.v1' as const
const AMBIGUITY_MARGIN = 0.03
const SCORE_WEIGHTS = Object.freeze({
  api_calls: 0.28,
  strings: 0.23,
  cfg_shape: 0.23,
  crypto_constants: 0.14,
  context: 0.07,
  size: 0.05,
})

interface FunctionMatchCalibration {
  mode: 'exact_hash' | 'legacy_api_size' | 'multiview'
  heuristic_profile: typeof HEURISTIC_PROFILE
  raw_multiview_score: number
  normalized_multiview_score: number
  comparable_weight: number
  matched_evidence_weight: number
  legacy_score?: number
  reference_trust: number
  coverage_factor: number
  pre_cap_score: number
  final_score: number
  independent_signal_count: number
  strong_signal_min_score: number
  applied_cap: 'none' | 'legacy_review' | 'non_exact' | 'insufficient_signals'
  applied_cap_value: number
}

interface ScoredReference {
  reference: FunctionSig
  confidence: number
  similarity: number
  legacy_similarity?: number
  confidence_tier: 'exact' | 'high' | 'review'
  exact_hash_algorithm?: 'sha256' | 'sha512'
  match_basis: string[]
  score_breakdown: FunctionMatchScoreBreakdown
  evidence_coverage: number
  comparable_coverage: number
  matched_evidence_weight: number
  calibration: FunctionMatchCalibration
  shared_features: FunctionMatchSharedFeatures
}

function roundScore(value: number): number {
  return Math.round(Math.max(0, Math.min(1, value)) * 1_000_000) / 1_000_000
}

function clampConfidence(value: unknown): number | undefined {
  const parsed = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(parsed) ? Math.max(0, Math.min(1, parsed)) : undefined
}

function normalizeText(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : ''
}

function boundedText(value: unknown, maxLength = MAX_FEATURE_VALUE_LENGTH): string {
  return String(value ?? '')
    .trim()
    .slice(0, maxLength)
}

function normalizeApi(value: unknown): string {
  const text = normalizeText(value)
  if (!text) return ''
  const bang = text.lastIndexOf('!')
  if (bang >= 0) return text.slice(bang + 1)
  const colon = text.lastIndexOf(':')
  if (colon >= 0 && /\.(?:dll|so|dylib)$/i.test(text.slice(0, colon))) {
    return text.slice(colon + 1)
  }
  return text
}

function valueLabel(value: unknown): string {
  if (typeof value === 'string' || typeof value === 'number') return String(value).trim()
  if (!value || typeof value !== 'object') return ''
  const record = value as Record<string, unknown>
  for (const key of ['api', 'name', 'target', 'symbol', 'address']) {
    if (typeof record[key] === 'string' || typeof record[key] === 'number') {
      return String(record[key]).trim()
    }
  }
  return ''
}

function stringList(value: unknown, maxValues = MAX_FEATURE_VALUES): string[] {
  if (!Array.isArray(value)) return []
  const seen = new Set<string>()
  const result: string[] = []
  for (const item of value) {
    const label = valueLabel(item).slice(0, MAX_FEATURE_VALUE_LENGTH)
    if (!label) continue
    const key = normalizeText(label)
    if (!key || seen.has(key)) continue
    seen.add(key)
    result.push(label)
    if (result.length >= maxValues) break
  }
  return result
}

interface ParsedStringList {
  ok: boolean
  value: string[]
  error?: string
}

function parseJsonStringList(
  value: unknown,
  options: {
    allowMissing?: boolean
    stringOnly?: boolean
    maxItems?: number
    maxBytes?: number
  } = {}
): ParsedStringList {
  if ((value === null || value === undefined) && options.allowMissing) {
    return { ok: true, value: [] }
  }
  let parsed: unknown = value
  try {
    if (typeof value === 'string') {
      if (value.trim().length === 0) {
        return options.allowMissing
          ? { ok: true, value: [] }
          : { ok: false, value: [], error: 'empty JSON list' }
      }
      if (value.length > (options.maxBytes ?? MAX_KB_FEATURE_JSON_BYTES)) {
        return { ok: false, value: [], error: 'JSON list exceeds the byte limit' }
      }
      parsed = JSON.parse(value)
    }
  } catch {
    return { ok: false, value: [], error: 'malformed JSON' }
  }
  if (!Array.isArray(parsed)) return { ok: false, value: [], error: 'expected a JSON array' }
  if (parsed.length > (options.maxItems ?? MAX_FEATURE_VALUES)) {
    return { ok: false, value: [], error: 'JSON list exceeds the item limit' }
  }
  if (options.stringOnly && parsed.some((item) => typeof item !== 'string')) {
    return { ok: false, value: [], error: 'expected an array of strings' }
  }
  return { ok: true, value: stringList(parsed, options.maxItems ?? MAX_FEATURE_VALUES) }
}

type SupportedHashAlgorithm = 'sha256' | 'sha512'

interface NormalizedDigest {
  algorithm: SupportedHashAlgorithm
  digest: string
}

const HASH_LENGTHS: Record<SupportedHashAlgorithm, number> = {
  sha256: 64,
  sha512: 128,
}

function normalizeHashAlgorithm(value: unknown): SupportedHashAlgorithm | undefined {
  const normalized = normalizeText(value).replace(/[-_]/g, '')
  return normalized === 'sha256' || normalized === 'sha512' ? normalized : undefined
}

function normalizeDigest(
  value: unknown,
  declaredAlgorithm?: unknown
): NormalizedDigest | undefined {
  if (typeof value !== 'string') return undefined
  const text = value.trim()
  let digest = text
  const declaredAlgorithmText =
    typeof declaredAlgorithm === 'string' ? declaredAlgorithm.trim() : ''
  let algorithm = declaredAlgorithmText ? normalizeHashAlgorithm(declaredAlgorithmText) : undefined
  if (declaredAlgorithmText && !algorithm) return undefined
  const qualified = /^([a-z0-9_-]+):([0-9a-f]+)$/i.exec(text)
  if (qualified) {
    const qualifiedAlgorithm = normalizeHashAlgorithm(qualified[1])
    if (!qualifiedAlgorithm || (algorithm && algorithm !== qualifiedAlgorithm)) return undefined
    algorithm = qualifiedAlgorithm
    digest = qualified[2]
  }
  if (!/^[0-9a-f]+$/i.test(digest)) return undefined
  if (!algorithm) {
    algorithm = (Object.entries(HASH_LENGTHS) as Array<[SupportedHashAlgorithm, number]>).find(
      ([, length]) => length === digest.length
    )?.[0]
  }
  if (!algorithm || digest.length !== HASH_LENGTHS[algorithm]) return undefined
  return { algorithm, digest: digest.toLowerCase() }
}

function normalizeSampleIdentity(value: unknown): string {
  const normalized = normalizeText(value)
  const digest = /^(?:sha256:)?([0-9a-f]{64})$/.exec(normalized)?.[1]
  return digest ? `sha256:${digest}` : normalized
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => compareText(a, b))
      .map(([key, nested]) => [key, stableValue(nested)])
  )
}

function normalizeCfgShape(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') {
    const text = value.trim()
    if (!text || /^(?:unknown|none|null|n\/a)$/i.test(text)) return ''
    try {
      return JSON.stringify(stableValue(JSON.parse(text)))
        .toLowerCase()
        .slice(0, MAX_CFG_SHAPE_LENGTH)
    } catch {
      return text.toLowerCase().replace(/\s+/g, '').slice(0, MAX_CFG_SHAPE_LENGTH)
    }
  }
  if (typeof value === 'object') {
    return JSON.stringify(stableValue(value)).toLowerCase().slice(0, MAX_CFG_SHAPE_LENGTH)
  }
  return normalizeText(value).slice(0, MAX_CFG_SHAPE_LENGTH)
}

function parseCfgMetrics(value: string): Map<string, number> {
  const metrics = new Map<string, number>()
  const pattern = /([a-z_][a-z0-9_-]*)["']?\s*[:=]\s*(-?\d+(?:\.\d+)?)/gi
  for (const match of value.matchAll(pattern)) {
    const parsed = Number(match[2])
    if (Number.isFinite(parsed)) metrics.set(match[1].toLowerCase(), parsed)
  }
  return metrics
}

function cfgSimilarity(
  a: unknown,
  b: unknown
): { score: number; shared?: string; comparable: boolean } {
  const left = normalizeCfgShape(a)
  const right = normalizeCfgShape(b)
  if (!left || !right) return { score: 0, comparable: false }
  if (left === right) return { score: 1, shared: left, comparable: true }

  const metricsA = parseCfgMetrics(left)
  const metricsB = parseCfgMetrics(right)
  const commonKeys = [...metricsA.keys()].filter((key) => metricsB.has(key)).sort(compareText)
  if (commonKeys.length < 2) return { score: 0, comparable: true }

  const ratio =
    commonKeys.reduce((sum, key) => {
      const leftValue = Math.abs(metricsA.get(key) ?? 0)
      const rightValue = Math.abs(metricsB.get(key) ?? 0)
      if (leftValue === 0 && rightValue === 0) return sum + 1
      return sum + Math.min(leftValue, rightValue) / Math.max(leftValue, rightValue)
    }, 0) / commonKeys.length
  const coverage = commonKeys.length / Math.max(metricsA.size, metricsB.size)
  return { score: roundScore(ratio * coverage), comparable: true }
}

function listSimilarity(
  a: string[] | undefined,
  b: string[] | undefined,
  normalize: (value: unknown) => string = normalizeText
): { score: number; shared: string[]; comparable: boolean } {
  const left = new Map<string, string>()
  const right = new Set<string>()
  for (const value of a ?? []) {
    const key = normalize(value)
    if (key && !left.has(key)) left.set(key, value)
  }
  for (const value of b ?? []) {
    const key = normalize(value)
    if (key) right.add(key)
  }
  if (left.size === 0 || right.size === 0) return { score: 0, shared: [], comparable: false }
  const commonKeys = [...left.keys()].filter((key) => right.has(key)).sort(compareText)
  const unionSize = new Set([...left.keys(), ...right]).size
  return {
    score: unionSize > 0 ? roundScore(commonKeys.length / unionSize) : 0,
    shared: commonKeys.map((key) => left.get(key) as string),
    comparable: true,
  }
}

function scoreReference(target: FunctionSig, reference: FunctionSig): ScoredReference {
  const emptyShared: FunctionMatchSharedFeatures = {
    api_calls: [],
    strings: [],
    crypto_constants: [],
    callers: [],
    callees: [],
  }
  const emptyBreakdown: FunctionMatchScoreBreakdown = {
    exact_hash: 0,
    api_calls: 0,
    strings: 0,
    cfg_shape: 0,
    crypto_constants: 0,
    size: 0,
    context: 0,
  }

  const targetDigest = normalizeDigest(target.hash, target.hash_algorithm)
  const referenceDigest = normalizeDigest(reference.hash, reference.hash_algorithm)
  if (
    targetDigest &&
    referenceDigest &&
    targetDigest.algorithm === referenceDigest.algorithm &&
    targetDigest.digest === referenceDigest.digest
  ) {
    const calibration: FunctionMatchCalibration = {
      mode: 'exact_hash',
      heuristic_profile: HEURISTIC_PROFILE,
      raw_multiview_score: 0,
      normalized_multiview_score: 0,
      comparable_weight: 1,
      matched_evidence_weight: 1,
      reference_trust: 1,
      coverage_factor: 1,
      pre_cap_score: 1,
      final_score: 1,
      independent_signal_count: 1,
      strong_signal_min_score: STRONG_SIGNAL_MIN_SCORE,
      applied_cap: 'none',
      applied_cap_value: 1,
    }
    return {
      reference,
      confidence: 1,
      similarity: 1,
      confidence_tier: 'exact',
      exact_hash_algorithm: targetDigest.algorithm,
      match_basis: ['exact_hash'],
      score_breakdown: { ...emptyBreakdown, exact_hash: 1 },
      evidence_coverage: 1,
      comparable_coverage: 1,
      matched_evidence_weight: 1,
      calibration,
      shared_features: emptyShared,
    }
  }

  const apis = listSimilarity(target.api_calls, reference.api_calls, normalizeApi)
  const strings = listSimilarity(target.strings, reference.strings)
  const constants = listSimilarity(target.crypto_constants, reference.crypto_constants)
  const cfg = cfgSimilarity(target.cfg_shape, reference.cfg_shape)
  const callers = listSimilarity(target.callers, reference.callers)
  const callees = listSimilarity(target.callees, reference.callees)
  const contextParts = [callers, callees].filter((part) => part.comparable)
  const contextScore =
    contextParts.length > 0
      ? contextParts.reduce((sum, part) => sum + part.score, 0) / contextParts.length
      : 0
  const sizeComparable =
    typeof target.size === 'number' &&
    target.size > 0 &&
    typeof reference.size === 'number' &&
    reference.size > 0
  const sizeScore = sizeComparable
    ? Math.min(target.size as number, reference.size as number) /
      Math.max(target.size as number, reference.size as number)
    : 0

  const score_breakdown: FunctionMatchScoreBreakdown = {
    exact_hash: 0,
    api_calls: apis.score,
    strings: strings.score,
    cfg_shape: cfg.score,
    crypto_constants: constants.score,
    size: roundScore(sizeScore),
    context: roundScore(contextScore),
  }
  const comparability = {
    api_calls: apis.comparable,
    strings: strings.comparable,
    cfg_shape: cfg.comparable,
    crypto_constants: constants.comparable,
    context: contextParts.length > 0,
    size: sizeComparable,
  }
  let comparableWeight = 0
  let rawMultiviewScore = 0
  const matchBasis: string[] = []
  for (const key of Object.keys(SCORE_WEIGHTS) as Array<keyof typeof SCORE_WEIGHTS>) {
    if (comparability[key]) comparableWeight += SCORE_WEIGHTS[key]
    if (score_breakdown[key] > 0) {
      rawMultiviewScore += score_breakdown[key] * SCORE_WEIGHTS[key]
      matchBasis.push(key)
    }
  }

  const independentSignalCount = (
    ['api_calls', 'strings', 'cfg_shape', 'crypto_constants', 'context'] as const
  ).filter((key) => score_breakdown[key] >= STRONG_SIGNAL_MIN_SCORE).length
  const normalizedMultiviewScore = comparableWeight > 0 ? rawMultiviewScore / comparableWeight : 0
  const coverageFactor = 0.6 + 0.4 * comparableWeight
  const multiviewSimilarity = normalizedMultiviewScore * coverageFactor
  const referenceTrust = effectiveReferenceTrust(reference)
  const legacySampleEvidenceScore =
    reference.reference_source !== 'function_kb'
      ? apis.comparable
        ? apis.score * 0.8 + (sizeComparable ? sizeScore * 0.2 : 0)
        : sizeComparable && sizeScore > 0.95
          ? 0.5
          : 0
      : 0
  const useLegacyCalibration =
    independentSignalCount < 2 && legacySampleEvidenceScore > multiviewSimilarity
  const calibratedSimilarity = useLegacyCalibration
    ? legacySampleEvidenceScore
    : multiviewSimilarity
  const preCapScore = calibratedSimilarity * referenceTrust
  let appliedCap: FunctionMatchCalibration['applied_cap'] = 'none'
  let appliedCapValue = 1
  let confidence = preCapScore
  if (reference.reference_source === 'function_kb' && independentSignalCount < 2) {
    appliedCap = 'insufficient_signals'
    appliedCapValue = 0
    confidence = 0
  } else if (useLegacyCalibration) {
    appliedCap = 'legacy_review'
    appliedCapValue = LEGACY_REVIEW_CONFIDENCE_CAP
    confidence = Math.min(confidence, LEGACY_REVIEW_CONFIDENCE_CAP)
  } else if (confidence > NON_EXACT_CONFIDENCE_CAP) {
    appliedCap = 'non_exact'
    appliedCapValue = NON_EXACT_CONFIDENCE_CAP
    confidence = NON_EXACT_CONFIDENCE_CAP
  }
  const roundedConfidence = roundScore(confidence)
  const calibration: FunctionMatchCalibration = {
    mode: useLegacyCalibration ? 'legacy_api_size' : 'multiview',
    heuristic_profile: HEURISTIC_PROFILE,
    raw_multiview_score: roundScore(rawMultiviewScore),
    normalized_multiview_score: roundScore(normalizedMultiviewScore),
    comparable_weight: roundScore(comparableWeight),
    matched_evidence_weight: roundScore(rawMultiviewScore),
    ...(reference.reference_source !== 'function_kb'
      ? { legacy_score: roundScore(legacySampleEvidenceScore) }
      : {}),
    reference_trust: roundScore(referenceTrust),
    coverage_factor: roundScore(coverageFactor),
    pre_cap_score: roundScore(preCapScore),
    final_score: roundedConfidence,
    independent_signal_count: independentSignalCount,
    strong_signal_min_score: STRONG_SIGNAL_MIN_SCORE,
    applied_cap: appliedCap,
    applied_cap_value: appliedCapValue,
  }
  return {
    reference,
    confidence: roundedConfidence,
    similarity: roundScore(calibratedSimilarity),
    ...(reference.reference_source !== 'function_kb'
      ? { legacy_similarity: roundScore(legacySampleEvidenceScore) }
      : {}),
    confidence_tier: roundedConfidence >= 0.8 && independentSignalCount >= 2 ? 'high' : 'review',
    match_basis: matchBasis,
    score_breakdown,
    evidence_coverage: roundScore(rawMultiviewScore),
    comparable_coverage: roundScore(comparableWeight),
    matched_evidence_weight: roundScore(rawMultiviewScore),
    calibration,
    shared_features: {
      api_calls: apis.shared,
      strings: strings.shared,
      crypto_constants: constants.shared,
      ...(cfg.shared ? { cfg_shape: cfg.shared } : {}),
      callers: callers.shared,
      callees: callees.shared,
    },
  }
}

function effectiveReferenceTrust(reference: FunctionSig): number {
  if (reference.reference_source !== 'function_kb') return 1
  return 0.5 + 0.5 * (reference.reference_confidence ?? 0)
}

function compareText(a: string, b: string): number {
  return a === b ? 0 : a < b ? -1 : 1
}

function compareScoredReferences(a: ScoredReference, b: ScoredReference): number {
  if (a.confidence !== b.confidence) return b.confidence - a.confidence
  if (a.similarity !== b.similarity) return b.similarity - a.similarity
  const trustA = effectiveReferenceTrust(a.reference)
  const trustB = effectiveReferenceTrust(b.reference)
  if (trustA !== trustB) return trustB - trustA
  const sourceA = a.reference.reference_source ?? 'sample_evidence'
  const sourceB = b.reference.reference_source ?? 'sample_evidence'
  return (
    compareText(sourceA, sourceB) ||
    compareText(a.reference.sample_id, b.reference.sample_id) ||
    compareText(a.reference.address, b.reference.address) ||
    compareText(a.reference.name, b.reference.name) ||
    compareText(a.reference.kb_entry_id ?? '', b.reference.kb_entry_id ?? '')
  )
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function functionSignatureFromRecord(
  record: Record<string, unknown>,
  sampleId: string,
  referenceSource?: 'sample_evidence' | 'function_kb'
): FunctionSig {
  const semanticEvidence =
    record.semantic_evidence && typeof record.semantic_evidence === 'object'
      ? (record.semantic_evidence as Record<string, unknown>)
      : {}
  const callContext =
    record.call_context && typeof record.call_context === 'object'
      ? (record.call_context as Record<string, unknown>)
      : {}
  const rawSize = record.size ?? record.length
  const parsedSize = typeof rawSize === 'number' ? rawSize : Number(rawSize)
  const address = boundedText(record.address ?? record.entry ?? record.offset ?? '0x0') || '0x0'
  return {
    sample_id: sampleId,
    address,
    name:
      boundedText(record.name ?? `sub_${record.address ?? record.entry ?? 'unknown'}`) ||
      'sub_unknown',
    hash:
      typeof (record.hash ?? record.byte_hash) === 'string'
        ? boundedText(record.hash ?? record.byte_hash, 256)
        : undefined,
    hash_algorithm:
      typeof (record.hash_algorithm ?? record.byte_hash_algorithm ?? record.hash_type) === 'string'
        ? boundedText(record.hash_algorithm ?? record.byte_hash_algorithm ?? record.hash_type, 32)
        : undefined,
    size: Number.isFinite(parsedSize) && parsedSize > 0 ? parsedSize : undefined,
    api_calls: stringList(record.api_calls ?? record.imports ?? record.called_apis ?? record.calls),
    strings: stringList(
      record.strings ?? record.referenced_strings ?? record.string_refs ?? semanticEvidence.strings
    ),
    cfg_shape:
      record.cfg_shape ??
      record.cfg_hash ??
      semanticEvidence.cfg_shape ??
      semanticEvidence.cfg_hash,
    crypto_constants: stringList(record.crypto_constants ?? semanticEvidence.crypto_constants),
    callers: stringList(record.callers ?? callContext.callers),
    callees: stringList(record.callees ?? callContext.callees),
    reference_source: referenceSource,
  }
}

interface FunctionCollection {
  functions: FunctionSig[]
  evidence_records_seen: number
  malformed_evidence_records: number
  evidence_records_truncated: boolean
  functions_truncated: boolean
}

const FUNCTION_EVIDENCE_FAMILIES = ['function_index', 'function_list', 'ghidra_functions'] as const

interface BoundedEvidenceRead {
  entries: unknown[]
  oversized_rows: number
  selected_bytes: number
  truncated: boolean
}

function readBoundedFunctionEvidence(
  database: PluginToolDeps['database'],
  sampleId: string,
  maxRows: number,
  maxTotalBytes: number
): BoundedEvidenceRead {
  if (typeof database.findBoundedAnalysisEvidenceBySample === 'function') {
    const result = database.findBoundedAnalysisEvidenceBySample(sampleId, {
      families: [...FUNCTION_EVIDENCE_FAMILIES],
      maxRows,
      maxScanRows: Math.min(MAX_EVIDENCE_SCAN_RECORDS, Math.max(maxRows, maxRows * 2)),
      maxResultJsonBytes: MAX_EVIDENCE_JSON_BYTES,
      maxTotalResultJsonBytes: maxTotalBytes,
    }) as {
      rows?: unknown[]
      oversized_rows?: unknown
      selected_bytes?: unknown
      truncated?: unknown
    }
    return {
      entries: Array.isArray(result.rows) ? result.rows : [],
      oversized_rows: Math.max(0, Number(result.oversized_rows) || 0),
      selected_bytes: Math.max(0, Number(result.selected_bytes) || 0),
      truncated: result.truncated === true,
    }
  }

  const entries = database.findAnalysisEvidenceBySample(sampleId, undefined, maxRows + 1)
  if (!Array.isArray(entries)) {
    return { entries: [], oversized_rows: 0, selected_bytes: 0, truncated: false }
  }
  const selected: unknown[] = []
  let selectedBytes = 0
  let oversizedRows = 0
  let truncated = entries.length > maxRows
  for (const entry of entries.slice(0, maxRows)) {
    const resultJson =
      entry && typeof entry === 'object'
        ? (entry as Record<string, unknown>).result_json
        : undefined
    const bytes = typeof resultJson === 'string' ? Buffer.byteLength(resultJson, 'utf8') : 0
    if (bytes > MAX_EVIDENCE_JSON_BYTES) {
      oversizedRows += 1
      continue
    }
    if (selectedBytes + bytes > maxTotalBytes) {
      truncated = true
      break
    }
    selectedBytes += bytes
    selected.push(entry)
  }
  return {
    entries: selected,
    oversized_rows: oversizedRows,
    selected_bytes: selectedBytes,
    truncated,
  }
}

function collectFunctionsFromEvidence(
  entries: unknown,
  sampleId: string,
  referenceSource?: 'sample_evidence' | 'function_kb',
  maxFunctions = MAX_TARGET_FUNCTIONS,
  maxEvidenceRecords = MAX_EVIDENCE_RECORDS
): FunctionCollection {
  if (!Array.isArray(entries)) {
    return {
      functions: [],
      evidence_records_seen: 0,
      malformed_evidence_records: entries === null || entries === undefined ? 0 : 1,
      evidence_records_truncated: false,
      functions_truncated: false,
    }
  }
  const functions: FunctionSig[] = []
  let malformedEvidenceRecords = 0
  let functionsTruncated = false
  const boundedEntries = entries.slice(0, maxEvidenceRecords)
  for (const entryValue of boundedEntries) {
    if (!entryValue || typeof entryValue !== 'object') {
      malformedEvidenceRecords += 1
      continue
    }
    const entry = entryValue as Record<string, unknown>
    try {
      if (
        typeof entry.result_json === 'string' &&
        entry.result_json.length > MAX_EVIDENCE_JSON_BYTES
      ) {
        malformedEvidenceRecords += 1
        continue
      }
      const data =
        typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
      const family = String(entry.evidence_family ?? '')
      if (
        !FUNCTION_EVIDENCE_FAMILIES.includes(family as (typeof FUNCTION_EVIDENCE_FAMILIES)[number])
      ) {
        continue
      }
      const payload = data && typeof data === 'object' ? (data as Record<string, unknown>) : {}
      const nestedData =
        payload.data && typeof payload.data === 'object'
          ? (payload.data as Record<string, unknown>)
          : {}
      const records = nestedData.functions ?? payload.functions ?? []
      if (!Array.isArray(records)) {
        malformedEvidenceRecords += 1
        continue
      }
      for (const record of records) {
        if (!record || typeof record !== 'object') {
          malformedEvidenceRecords += 1
          continue
        }
        if (functions.length >= maxFunctions) {
          functionsTruncated = true
          break
        }
        functions.push(
          functionSignatureFromRecord(record as Record<string, unknown>, sampleId, referenceSource)
        )
      }
    } catch {
      malformedEvidenceRecords += 1
    }
  }
  return {
    functions: dedupeFunctionSignatures(functions),
    evidence_records_seen: boundedEntries.length,
    malformed_evidence_records: malformedEvidenceRecords,
    evidence_records_truncated: entries.length > boundedEntries.length,
    functions_truncated: functionsTruncated,
  }
}

function dedupeFunctionSignatures(functions: FunctionSig[]): FunctionSig[] {
  const seen = new Set<string>()
  const result: FunctionSig[] = []
  for (const item of functions) {
    const locationKey =
      item.address !== '0x0'
        ? item.address
        : [item.address, item.hash ?? '', item.name].join('\u0000')
    const key = [
      item.reference_source ?? 'target',
      item.sample_id,
      locationKey,
      item.kb_entry_id ?? '',
    ].join('\u0000')
    if (seen.has(key)) continue
    seen.add(key)
    result.push(item)
  }
  return result
}

interface FunctionKbRow {
  id?: unknown
  features_apis_json?: unknown
  features_strings_json?: unknown
  features_cfg_shape?: unknown
  features_crypto_constants_json?: unknown
  semantics_name?: unknown
  semantics_confidence?: unknown
  semantics_source?: unknown
  samples_json?: unknown
  _row_bytes?: unknown
}

const kbBlobLength = (column: string) => `length(CAST(COALESCE(${column}, '') AS BLOB))`
const KB_LENGTH_FIELDS = [
  ['id', 'id_bytes'],
  ['features_apis_json', 'apis_bytes'],
  ['features_strings_json', 'strings_bytes'],
  ['features_cfg_shape', 'cfg_bytes'],
  ['features_crypto_constants_json', 'constants_bytes'],
  ['semantics_name', 'name_bytes'],
  ['semantics_source', 'source_bytes'],
  ['samples_json', 'samples_bytes'],
] as const
const KB_CANDIDATE_LENGTHS_SQL = KB_LENGTH_FIELDS.map(
  ([column, alias]) => `${kbBlobLength(column)} AS ${alias}`
).join(',\n                  ')
const KB_ROW_BYTES_FROM_LENGTHS_SQL = KB_LENGTH_FIELDS.map(([, alias]) => alias).join(' + ')
const KB_ROW_BOUNDS_FROM_LENGTHS_SQL = [
  'id_bytes <= ?',
  'apis_bytes <= ?',
  'strings_bytes <= ?',
  'cfg_bytes <= ?',
  'constants_bytes <= ?',
  'name_bytes <= ?',
  'source_bytes <= ?',
  'samples_bytes <= ?',
  `(${KB_ROW_BYTES_FROM_LENGTHS_SQL}) <= ?`,
].join(' AND ')
const KB_ROW_BOUNDS_PARAMS = [
  MAX_ID_LENGTH,
  MAX_KB_FEATURE_JSON_BYTES,
  MAX_KB_FEATURE_JSON_BYTES,
  MAX_CFG_SHAPE_LENGTH,
  MAX_KB_FEATURE_JSON_BYTES,
  MAX_FEATURE_VALUE_LENGTH,
  MAX_FEATURE_VALUE_LENGTH,
  MAX_KB_PROVENANCE_JSON_BYTES,
  MAX_KB_ROW_BYTES,
]

type FunctionKbParseResult =
  | { status: 'ok'; signature: FunctionSig }
  | { status: 'malformed'; reason: string }
  | { status: 'self_reference' }

function functionSignatureFromKbRow(
  row: FunctionKbRow,
  targetSampleIdentities: ReadonlySet<string>
): FunctionKbParseResult {
  const id =
    typeof row.id === 'string' && row.id.trim() ? row.id.trim().slice(0, MAX_ID_LENGTH) : ''
  if (!id) return { status: 'malformed', reason: 'missing id' }
  const samples = parseJsonStringList(row.samples_json, {
    stringOnly: true,
    maxItems: MAX_KB_PROVENANCE_VALUES,
    maxBytes: MAX_KB_PROVENANCE_JSON_BYTES,
  })
  if (!samples.ok) {
    return { status: 'malformed', reason: `invalid samples_json: ${samples.error}` }
  }
  if (
    samples.value.some((sampleId) => targetSampleIdentities.has(normalizeSampleIdentity(sampleId)))
  ) {
    return { status: 'self_reference' }
  }
  const apis = parseJsonStringList(row.features_apis_json)
  const strings = parseJsonStringList(row.features_strings_json)
  const constants = parseJsonStringList(row.features_crypto_constants_json, { allowMissing: true })
  if (!apis.ok || !strings.ok || !constants.ok) {
    return {
      status: 'malformed',
      reason: `invalid feature JSON: ${apis.error ?? strings.error ?? constants.error}`,
    }
  }
  if (typeof row.features_cfg_shape !== 'string') {
    return { status: 'malformed', reason: 'invalid features_cfg_shape' }
  }
  return {
    status: 'ok',
    signature: {
      sample_id: `kb:${id}`,
      address: `kb:${id}`,
      name:
        typeof row.semantics_name === 'string' && row.semantics_name.trim()
          ? row.semantics_name.trim().slice(0, MAX_FEATURE_VALUE_LENGTH)
          : `kb_function_${id}`,
      api_calls: apis.value,
      strings: strings.value,
      cfg_shape: row.features_cfg_shape,
      crypto_constants: constants.value,
      reference_source: 'function_kb',
      kb_entry_id: id,
      reference_confidence: clampConfidence(row.semantics_confidence),
      reference_semantics_source:
        typeof row.semantics_source === 'string'
          ? row.semantics_source.slice(0, MAX_FEATURE_VALUE_LENGTH)
          : undefined,
      reference_sample_ids: samples.value
        .slice(0, MAX_MATCH_AGAINST)
        .map((sampleId) => sampleId.slice(0, MAX_ID_LENGTH)),
    },
  }
}

function buildFunctionMatchEntry(
  target: FunctionSig,
  scored: ScoredReference,
  alternatives: ScoredReference[]
): FunctionMatchEntry {
  const reference = scored.reference
  const source = reference.reference_source ?? 'sample_evidence'
  return {
    target_function: target.name,
    target_address: target.address,
    matched_function: reference.name,
    matched_sample_id: reference.sample_id,
    matched_address: reference.address,
    confidence: scored.confidence,
    similarity: scored.similarity,
    ...(scored.legacy_similarity !== undefined
      ? { legacy_similarity: scored.legacy_similarity }
      : {}),
    confidence_tier: scored.confidence_tier,
    ...(scored.exact_hash_algorithm ? { exact_hash_algorithm: scored.exact_hash_algorithm } : {}),
    reference_source: source,
    ...(reference.kb_entry_id ? { kb_entry_id: reference.kb_entry_id } : {}),
    ...(reference.reference_confidence !== undefined
      ? { reference_confidence: reference.reference_confidence }
      : {}),
    ...(reference.reference_semantics_source
      ? { reference_semantics_source: reference.reference_semantics_source }
      : {}),
    ...(reference.reference_sample_ids
      ? { reference_sample_ids: reference.reference_sample_ids }
      : {}),
    match_basis: scored.match_basis,
    score_breakdown: scored.score_breakdown,
    score_weights: { ...SCORE_WEIGHTS },
    evidence_coverage: scored.evidence_coverage,
    comparable_coverage: scored.comparable_coverage,
    matched_evidence_weight: scored.matched_evidence_weight,
    calibration: scored.calibration,
    shared_features: scored.shared_features,
    ambiguous: alternatives.length > 0,
    alternative_count: alternatives.length,
    returned_alternative_count: Math.min(alternatives.length, MAX_ALTERNATIVES),
    alternatives_truncated: alternatives.length > MAX_ALTERNATIVES,
    alternatives: alternatives.slice(0, MAX_ALTERNATIVES).map((alternative) => ({
      matched_function: alternative.reference.name,
      matched_sample_id: alternative.reference.sample_id,
      matched_address: alternative.reference.address,
      confidence: alternative.confidence,
      reference_source: alternative.reference.reference_source ?? 'sample_evidence',
      ...(alternative.reference.kb_entry_id
        ? { kb_entry_id: alternative.reference.kb_entry_id }
        : {}),
    })),
  }
}

function buildRecommendedNextTools(input: {
  exact_matches: number
  high_confidence_matches: number
  match_count: number
}): string[] {
  return uniqueStrings([
    'artifact.read',
    'kb.context.suggest',
    'analysis.notes',
    ...(input.match_count > 0 ? ['analysis.evidence.graph', 'report.generate'] : []),
    ...(input.exact_matches > 0 || input.high_confidence_matches > 0
      ? ['rule.library', 'kb.export']
      : []),
  ])
}

export function enrichKbFunctionMatchResultData(resultData: {
  sample_id: string
  target_function_count: number
  reference_function_count: number
  match_count: number
  exact_matches: number
  high_confidence_matches: number
  matches: FunctionMatchEntry[]
  min_confidence?: number
  match_against?: string[]
  analysis_limits?: {
    max_target_functions: number
    max_reference_functions: number
    max_reference_bytes: number
    reference_bytes_selected: number
    max_kb_scan_rows: number
    kb_scan_truncated: boolean
    max_pair_comparisons: number
    max_evidence_bytes: number
    evidence_bytes_selected: number
    performed_pair_comparisons: number
    target_functions_truncated: boolean
    reference_functions_truncated: boolean
    evidence_records_truncated: boolean
  }
  diagnostics?: {
    evidence_records_seen: number
    malformed_evidence_records: number
    oversized_evidence_records: number
    malformed_kb_rows: number
    oversized_kb_rows: number
    kb_rows_scanned: number
    self_referential_kb_rows_excluded: number
  }
}) {
  const recommendedNextTools = buildRecommendedNextTools(resultData)
  const matchAgainst = resultData.match_against ?? []
  const ambiguousMatches = resultData.matches.filter((match) => match.ambiguous).length
  const referenceSourceCounts = resultData.matches.reduce<Record<string, number>>(
    (counts, match) => {
      const source = match.reference_source ?? 'sample_evidence'
      counts[source] = (counts[source] ?? 0) + 1
      return counts
    },
    {}
  )
  const matchingProfile = {
    schema: 'rikune.kb_function_match.matching_profile.v1',
    model: MATCHING_MODEL,
    explanation_level: 'feature-level',
    weights: SCORE_WEIGHTS,
    ambiguity_margin: AMBIGUITY_MARGIN,
    heuristic_calibration: {
      strong_signal_min_score: STRONG_SIGNAL_MIN_SCORE,
      minimum_independent_signals: 2,
      coverage_factor: '0.6 + 0.4 * comparable_weight',
      normalized_multiview_score: 'raw_multiview_score / comparable_weight',
      reference_trust: 'function_kb: 0.5 + 0.5 * semantics_confidence; sample_evidence: 1',
      legacy_review_cap: LEGACY_REVIEW_CONFIDENCE_CAP,
      non_exact_cap: NON_EXACT_CONFIDENCE_CAP,
    },
    deterministic_tie_break: [
      'confidence_desc',
      'similarity_desc',
      'reference_confidence_desc',
      'reference_source',
      'sample_id',
      'address',
      'name',
      'kb_entry_id',
    ],
    score_interpretation:
      'Only validated byte digests can score 1.0. Non-exact scores use a documented heuristic: normalized multi-view overlap, comparable-evidence coverage, source trust, and a review-only cap for legacy API/size-only matches.',
  }

  return {
    sample_id: resultData.sample_id,
    target_function_count: resultData.target_function_count,
    reference_function_count: resultData.reference_function_count,
    match_count: resultData.match_count,
    exact_matches: resultData.exact_matches,
    high_confidence_matches: resultData.high_confidence_matches,
    ambiguous_matches: ambiguousMatches,
    ...(resultData.analysis_limits ? { analysis_limits: resultData.analysis_limits } : {}),
    ...(resultData.diagnostics ? { diagnostics: resultData.diagnostics } : {}),
    matching_profile: matchingProfile,
    workflowRecipes: KB_FUNCTION_MATCH_WORKFLOW_RECIPES,
    formats: KB_FUNCTION_MATCH_FORMATS,
    evidence: KB_FUNCTION_MATCH_EVIDENCE,
    policy: {
      passive: true,
      no_execute: true,
      no_network: true,
      no_mutation: true,
      no_sample_execution: true,
      no_live_sample: true,
    },
    evidence_summary: {
      schema: 'rikune.kb_function_match.evidence_summary.v1',
      source_tool: TOOL_NAME,
      artifact_type: KB_FUNCTION_MATCH_ARTIFACT_TYPE,
      sample_id: resultData.sample_id,
      evidence_categories: KB_FUNCTION_MATCH_EVIDENCE,
      function_counts: {
        target_functions: resultData.target_function_count,
        reference_functions: resultData.reference_function_count,
        matches: resultData.match_count,
        exact_matches: resultData.exact_matches,
        high_confidence_matches: resultData.high_confidence_matches,
        ambiguous_matches: ambiguousMatches,
      },
      match_scope: {
        match_against: matchAgainst,
        all_kb_entries_requested: matchAgainst.length === 0,
        min_confidence: resultData.min_confidence ?? null,
        reference_source_counts: referenceSourceCounts,
      },
      matching_profile: matchingProfile,
      ...(resultData.analysis_limits ? { analysis_limits: resultData.analysis_limits } : {}),
      ...(resultData.diagnostics ? { diagnostics: resultData.diagnostics } : {}),
      static_only: true,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
    workflow_handoff: {
      schema: 'rikune.kb_function_match.workflow_handoff.v1',
      handoff_mode: 'function_reuse_to_analysis_memory_and_evidence_graph',
      artifact_type: KB_FUNCTION_MATCH_ARTIFACT_TYPE,
      recommended_next_tools: recommendedNextTools,
      artifact_contract: {
        consumes: ['analysis_evidence', 'function_index'],
        produces: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
        expected_consumers: [
          'workflow.search',
          'artifact.read',
          'kb.context.suggest',
          'analysis.evidence.graph',
          'report.generate',
        ],
      },
      routing: [
        {
          goal: 'exact-and-high-confidence-function-reuse',
          priority:
            resultData.exact_matches > 0 || resultData.high_confidence_matches > 0
              ? 'high'
              : 'conditional',
          next_tools: ['analysis.evidence.graph', 'analysis.notes', 'rule.library'],
          required_evidence: ['function signatures', 'matched sample IDs', 'confidence scores'],
          consumes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          produces: ['function_reuse_evidence'],
        },
        {
          goal: 'analysis-memory-context-refresh',
          priority: 'normal',
          next_tools: ['kb.context.suggest', 'analysis.notes', 'kb.export'],
          required_evidence: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          consumes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          produces: ['analysis_memory'],
        },
        {
          goal: 'evidence-graph-and-reporting',
          priority: resultData.match_count > 0 ? 'normal' : 'low',
          next_tools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          consumes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'analysis_report'],
        },
      ],
      dynamic_boundary: {
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        binary_modified_by_tool: false,
      },
    },
    quality_gates: {
      schema: 'rikune.kb_function_match.quality_gates.v1',
      passive_local_kb_match: true,
      target_functions_present: resultData.target_function_count > 0,
      reference_functions_present: resultData.reference_function_count > 0,
      matches_present: resultData.match_count > 0,
      exact_or_high_confidence_matches_present:
        resultData.exact_matches > 0 || resultData.high_confidence_matches > 0,
      feature_level_explanations_present:
        resultData.matches.length > 0 &&
        resultData.matches.every((match) =>
          Boolean(
            match.score_breakdown && match.match_basis && match.shared_features && match.calibration
          )
        ),
      evidence_parse_complete:
        (resultData.diagnostics?.malformed_evidence_records ?? 0) === 0 &&
        (resultData.diagnostics?.oversized_evidence_records ?? 0) === 0,
      reference_set_complete:
        !(resultData.analysis_limits?.reference_functions_truncated ?? false) &&
        !(resultData.analysis_limits?.evidence_records_truncated ?? false),
      ambiguous_matches_review_required: ambiguousMatches > 0,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
      binary_modified_by_tool: false,
    },
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review exact and high-confidence matches before propagating names or annotations.',
      ...(ambiguousMatches > 0
        ? ['Resolve ambiguous candidates using disassembly, CFG, or call-context evidence.']
        : []),
      'Publish function reuse evidence to analysis.evidence.graph when matches are present.',
      'Capture reusable analyst notes before exporting curated knowledge.',
    ],
    matches: resultData.matches,
  }
}

export function createKbFunctionMatchHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (rawArgs: z.input<typeof KbFunctionMatchInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const parsedArgs = KbFunctionMatchInputSchema.safeParse(rawArgs)
      if (!parsedArgs.success) {
        return {
          ok: false,
          errors: [`Invalid ${TOOL_NAME} input: ${parsedArgs.error.message}`],
          metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
        }
      }
      const args = parsedArgs.data
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }
      const targetSampleIdentities = new Set(
        [args.sample_id, sample.id, sample.sha256]
          .map(normalizeSampleIdentity)
          .filter((identity) => identity.length > 0)
      )
      const minConfidence = args.min_confidence ?? 0.7
      const maxMatches = args.max_matches ?? 100
      const requestedMaxReferenceFunctions =
        args.max_reference_functions ?? DEFAULT_MAX_REFERENCE_FUNCTIONS
      const diagnostics = {
        evidence_records_seen: 0,
        malformed_evidence_records: 0,
        oversized_evidence_records: 0,
        malformed_kb_rows: 0,
        oversized_kb_rows: 0,
        kb_rows_scanned: 0,
        self_referential_kb_rows_excluded: 0,
      }

      const targetEvidenceRead = readBoundedFunctionEvidence(
        database,
        args.sample_id,
        MAX_EVIDENCE_RECORDS,
        MAX_TOTAL_EVIDENCE_JSON_BYTES
      )
      const targetCollection = collectFunctionsFromEvidence(
        targetEvidenceRead.entries,
        args.sample_id,
        undefined,
        MAX_TARGET_FUNCTIONS,
        MAX_EVIDENCE_RECORDS
      )
      const targetFunctions = targetCollection.functions
      diagnostics.evidence_records_seen += targetCollection.evidence_records_seen
      diagnostics.malformed_evidence_records += targetCollection.malformed_evidence_records
      diagnostics.oversized_evidence_records += targetEvidenceRead.oversized_rows
      let evidenceBytesSelected = targetEvidenceRead.selected_bytes

      if (targetFunctions.length === 0) {
        return {
          ok: false,
          errors: ['No function data found for target sample. Run function analysis first.'],
        }
      }

      const pairLimitedReferenceFunctions = Math.max(
        1,
        Math.floor(MAX_PAIR_COMPARISONS / targetFunctions.length)
      )
      const effectiveMaxReferenceFunctions = Math.min(
        requestedMaxReferenceFunctions,
        pairLimitedReferenceFunctions
      )
      if (effectiveMaxReferenceFunctions < requestedMaxReferenceFunctions) {
        warnings.push(
          `Reference limit was reduced to ${effectiveMaxReferenceFunctions} by the ${MAX_PAIR_COMPARISONS}-pair comparison budget.`
        )
      }

      let referenceFunctions: FunctionSig[] = []
      const matchSampleIds = uniqueStrings(args.match_against ?? [])
      let referenceFunctionsTruncated = false
      let evidenceRecordsTruncated =
        targetCollection.evidence_records_truncated || targetEvidenceRead.truncated
      let referenceBytesSelected = 0
      let kbScanTruncated = false

      if (matchSampleIds.length === 0) {
        let rows: FunctionKbRow[]
        try {
          const statsRows = database.querySql(
            `
              WITH candidates AS (
                SELECT
                  id,
                  semantics_confidence,
                  ${KB_CANDIDATE_LENGTHS_SQL}
                FROM function_kb
                ORDER BY semantics_confidence DESC, id ASC
                LIMIT ?
              )
              SELECT
                COUNT(*) AS scanned_rows,
                COALESCE(SUM(CASE WHEN (${KB_ROW_BOUNDS_FROM_LENGTHS_SQL}) THEN 0 ELSE 1 END), 0) AS oversized_rows,
                COALESCE(SUM(CASE WHEN (${KB_ROW_BOUNDS_FROM_LENGTHS_SQL}) THEN 1 ELSE 0 END), 0) AS eligible_rows
              FROM candidates
            `,
            [MAX_KB_SCAN_ROWS, ...KB_ROW_BOUNDS_PARAMS, ...KB_ROW_BOUNDS_PARAMS]
          ) as Array<{
            scanned_rows?: unknown
            oversized_rows?: unknown
            eligible_rows?: unknown
          }>
          const scannedRows = Number(statsRows[0]?.scanned_rows)
          const oversizedRows = Number(statsRows[0]?.oversized_rows)
          const eligibleRows = Number(statsRows[0]?.eligible_rows)
          if (Number.isFinite(scannedRows) && scannedRows >= 0) {
            diagnostics.kb_rows_scanned = Math.floor(scannedRows)
            kbScanTruncated = scannedRows >= MAX_KB_SCAN_ROWS
          }
          if (Number.isFinite(oversizedRows) && oversizedRows > 0) {
            diagnostics.oversized_kb_rows = Math.floor(oversizedRows)
          }
          rows = database.querySql(
            `
              WITH candidates AS (
                SELECT
                  id,
                  semantics_confidence,
                  ${KB_CANDIDATE_LENGTHS_SQL}
                FROM function_kb
                ORDER BY semantics_confidence DESC, id ASC
                LIMIT ?
              ),
              eligible AS (
                SELECT
                  id,
                  semantics_confidence,
                  (${KB_ROW_BYTES_FROM_LENGTHS_SQL}) AS row_bytes
                FROM candidates
                WHERE ${KB_ROW_BOUNDS_FROM_LENGTHS_SQL}
              ),
              budgeted AS (
                SELECT
                  id,
                  semantics_confidence,
                  row_bytes,
                  SUM(row_bytes) OVER (
                    ORDER BY semantics_confidence DESC, id ASC
                  ) AS cumulative_bytes
                FROM eligible
              ),
              selected AS (
                SELECT id, semantics_confidence, row_bytes
                FROM budgeted
                WHERE cumulative_bytes <= ?
                ORDER BY semantics_confidence DESC, id ASC
                LIMIT ?
              )
              SELECT
                f.id,
                f.features_apis_json,
                f.features_strings_json,
                f.features_cfg_shape,
                f.features_crypto_constants_json,
                f.semantics_name,
                f.semantics_confidence,
                f.semantics_source,
                f.samples_json,
                selected.row_bytes AS _row_bytes
              FROM selected
              JOIN function_kb AS f ON f.id = selected.id
              ORDER BY selected.semantics_confidence DESC, selected.id ASC
            `,
            [
              MAX_KB_SCAN_ROWS,
              ...KB_ROW_BOUNDS_PARAMS,
              MAX_KB_REFERENCE_BYTES,
              effectiveMaxReferenceFunctions + 1,
            ]
          ) as FunctionKbRow[]
          if (Number.isFinite(eligibleRows)) {
            referenceFunctionsTruncated = eligibleRows > rows.length
          }
          referenceFunctionsTruncated ||= kbScanTruncated
        } catch (error) {
          return {
            ok: false,
            errors: [
              `Function KB could not be read: ${error instanceof Error ? error.message : String(error)}`,
            ],
            metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
          }
        }
        referenceFunctionsTruncated ||= rows.length > effectiveMaxReferenceFunctions
        referenceBytesSelected = rows
          .slice(0, effectiveMaxReferenceFunctions)
          .reduce((sum, row) => {
            const bytes = Number(row._row_bytes)
            return sum + (Number.isFinite(bytes) && bytes > 0 ? Math.floor(bytes) : 0)
          }, 0)
        const malformedReasons = new Set<string>()
        for (const row of rows.slice(0, effectiveMaxReferenceFunctions)) {
          const parsed = functionSignatureFromKbRow(row, targetSampleIdentities)
          if (parsed.status === 'ok') {
            referenceFunctions.push(parsed.signature)
          } else if (parsed.status === 'self_reference') {
            diagnostics.self_referential_kb_rows_excluded += 1
          } else {
            diagnostics.malformed_kb_rows += 1
            if (malformedReasons.size < 3) malformedReasons.add(parsed.reason)
          }
        }
        if (malformedReasons.size > 0) {
          warnings.push(
            `Skipped ${diagnostics.malformed_kb_rows} malformed function_kb row(s): ${[
              ...malformedReasons,
            ].join('; ')}`
          )
        }
      } else {
        let remainingEvidenceRecords = Math.max(
          0,
          MAX_EVIDENCE_RECORDS - diagnostics.evidence_records_seen
        )
        let remainingEvidenceBytes = Math.max(
          0,
          MAX_TOTAL_EVIDENCE_JSON_BYTES - evidenceBytesSelected
        )
        for (const sid of matchSampleIds) {
          if (targetSampleIdentities.has(normalizeSampleIdentity(sid))) continue
          const remainingFunctions = effectiveMaxReferenceFunctions - referenceFunctions.length
          if (
            remainingFunctions <= 0 ||
            remainingEvidenceRecords <= 0 ||
            remainingEvidenceBytes <= 0
          ) {
            referenceFunctionsTruncated ||= remainingFunctions <= 0
            evidenceRecordsTruncated ||=
              remainingEvidenceRecords <= 0 || remainingEvidenceBytes <= 0
            break
          }
          const evidenceRead = readBoundedFunctionEvidence(
            database,
            sid,
            remainingEvidenceRecords,
            remainingEvidenceBytes
          )
          const collection = collectFunctionsFromEvidence(
            evidenceRead.entries,
            sid,
            'sample_evidence',
            remainingFunctions,
            remainingEvidenceRecords
          )
          referenceFunctions.push(...collection.functions)
          diagnostics.evidence_records_seen += collection.evidence_records_seen
          diagnostics.malformed_evidence_records += collection.malformed_evidence_records
          diagnostics.oversized_evidence_records += evidenceRead.oversized_rows
          evidenceBytesSelected += evidenceRead.selected_bytes
          remainingEvidenceRecords = Math.max(
            0,
            remainingEvidenceRecords - collection.evidence_records_seen
          )
          remainingEvidenceBytes = Math.max(0, remainingEvidenceBytes - evidenceRead.selected_bytes)
          referenceFunctionsTruncated ||= collection.functions_truncated
          evidenceRecordsTruncated ||=
            collection.evidence_records_truncated || evidenceRead.truncated
        }
      }
      referenceFunctions = dedupeFunctionSignatures(referenceFunctions).slice(
        0,
        effectiveMaxReferenceFunctions
      )

      if (targetCollection.functions_truncated) {
        warnings.push(`Target function set was truncated at ${MAX_TARGET_FUNCTIONS} functions.`)
      }
      if (referenceFunctionsTruncated) {
        warnings.push(
          `Reference function set was truncated at ${effectiveMaxReferenceFunctions} functions.`
        )
      }
      if (evidenceRecordsTruncated) {
        warnings.push(`Analysis evidence was truncated at ${MAX_EVIDENCE_RECORDS} records.`)
      }
      if (diagnostics.malformed_evidence_records > 0) {
        warnings.push(
          `Skipped ${diagnostics.malformed_evidence_records} malformed analysis evidence record(s).`
        )
      }
      if (diagnostics.oversized_evidence_records > 0) {
        warnings.push(
          `Skipped ${diagnostics.oversized_evidence_records} oversized analysis evidence record(s) before materialization.`
        )
      }
      if (diagnostics.oversized_kb_rows > 0) {
        warnings.push(
          `Skipped ${diagnostics.oversized_kb_rows} oversized function_kb row(s) before materialization.`
        )
      }
      if (kbScanTruncated) {
        warnings.push(`Function KB candidate scan was truncated at ${MAX_KB_SCAN_ROWS} rows.`)
      }
      if (diagnostics.self_referential_kb_rows_excluded > 0) {
        warnings.push(
          `Excluded ${diagnostics.self_referential_kb_rows_excluded} function_kb row(s) associated with the target sample.`
        )
      }

      if (referenceFunctions.length === 0) {
        warnings.push(
          matchSampleIds.length === 0
            ? 'No reference functions found in function_kb. Build or import function knowledge first.'
            : 'No reference functions found for the requested match_against samples.'
        )
      }

      const matches: FunctionMatchEntry[] = []
      for (const target of targetFunctions) {
        const candidates = referenceFunctions
          .map((reference) => scoreReference(target, reference))
          .filter((candidate) => candidate.confidence > 0)
          .sort(compareScoredReferences)
        const best = candidates[0]
        if (!best || best.confidence < minConfidence) continue
        const alternatives = candidates
          .slice(1)
          .filter((candidate) => best.confidence - candidate.confidence <= AMBIGUITY_MARGIN)
        matches.push(buildFunctionMatchEntry(target, best, alternatives))
      }

      matches.sort(
        (a, b) =>
          b.confidence - a.confidence ||
          compareText(a.target_address, b.target_address) ||
          compareText(a.target_function, b.target_function) ||
          compareText(a.matched_sample_id, b.matched_sample_id) ||
          compareText(a.matched_address, b.matched_address) ||
          compareText(a.matched_function, b.matched_function)
      )
      const topMatches = matches.slice(0, maxMatches)

      const resultData = enrichKbFunctionMatchResultData({
        sample_id: args.sample_id,
        target_function_count: targetFunctions.length,
        reference_function_count: referenceFunctions.length,
        match_count: topMatches.length,
        exact_matches: topMatches.filter((match) => match.match_basis?.includes('exact_hash'))
          .length,
        high_confidence_matches: topMatches.filter((match) => match.confidence_tier === 'high')
          .length,
        min_confidence: minConfidence,
        match_against: matchSampleIds,
        analysis_limits: {
          max_target_functions: MAX_TARGET_FUNCTIONS,
          max_reference_functions: effectiveMaxReferenceFunctions,
          max_reference_bytes: MAX_KB_REFERENCE_BYTES,
          reference_bytes_selected: referenceBytesSelected,
          max_kb_scan_rows: MAX_KB_SCAN_ROWS,
          kb_scan_truncated: kbScanTruncated,
          max_pair_comparisons: MAX_PAIR_COMPARISONS,
          max_evidence_bytes: MAX_TOTAL_EVIDENCE_JSON_BYTES,
          evidence_bytes_selected: evidenceBytesSelected,
          performed_pair_comparisons: targetFunctions.length * referenceFunctions.length,
          target_functions_truncated: targetCollection.functions_truncated,
          reference_functions_truncated: referenceFunctionsTruncated,
          evidence_records_truncated: evidenceRecordsTruncated,
        },
        diagnostics,
        matches: topMatches,
      })

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          KB_FUNCTION_MATCH_ARTIFACT_TYPE,
          'kb-function-match',
          resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        /* non-fatal */
      }

      return {
        ok: true,
        data: resultData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
