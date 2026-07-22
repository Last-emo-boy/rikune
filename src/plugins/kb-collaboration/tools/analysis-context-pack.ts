import { createHash } from 'crypto'
import { z } from 'zod'
import type { AnalysisEvidence, DatabaseManager } from '../../../database.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import {
  AnalysisClaimProducerSchema,
  AnalysisClaimSchema,
  loadAnalysisClaimLedgerIndex,
  scopeAnalysisClaimLedgerIndex,
} from '../../../artifacts/analysis-claim-artifacts.js'
import {
  AnalysisCaseIdSchema,
  analysisCaseBlockingIntegrityIssues,
  analysisCaseContextMarker,
  loadAnalysisCaseStateIndex,
  type AnalysisCaseStateIndex,
  type LoadedAnalysisCaseState,
} from '../../../artifacts/analysis-case-artifacts.js'
import { isContextOnlyArtifactType } from '../../../artifacts/context-only-artifacts.js'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
} from '../../sdk.js'

const TOOL_NAME = 'analysis.context.pack'
const MARKER_PREFIX = 'rikune-context-v1.'
const DEFAULT_TOKEN_BUDGET = 4000
const MAX_CONTEXT_ITEMS = 256
const MAX_OMITTED_IDS = 32

const EvidenceScopeSchema = z.enum(['latest', 'all'])
const ClaimScopeSchema = z.enum(['latest', 'all'])

export const AnalysisContextPackInputSchema = z
  .object({
    sample_id: z.string().min(1).describe('Sample identifier for the isolated context pack'),
    goal: z
      .string()
      .min(1)
      .max(1000)
      .describe('Bounded analysis goal that the caller is currently pursuing'),
    token_budget: z
      .number()
      .int()
      .min(256)
      .max(32_000)
      .optional()
      .default(DEFAULT_TOKEN_BUDGET)
      .describe('Approximate JSON token budget for the returned data payload'),
    since_marker: z
      .string()
      .min(1)
      .max(4096)
      .optional()
      .describe('Opaque marker returned by an earlier call for the same sample'),
    evidence_scope: EvidenceScopeSchema.optional().default('latest'),
    claim_scope: ClaimScopeSchema.optional().default('latest'),
    include_case: z.boolean().optional().default(true),
    case_id: AnalysisCaseIdSchema.optional().describe(
      'Optional Case Workspace selector. Required when the sample has multiple cases; a single case is selected automatically.'
    ),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!value.include_case && value.case_id) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['case_id'],
        message: 'case_id cannot be used when include_case=false.',
      })
    }
  })

const ArtifactPointerSchema = z
  .object({
    id: z.string(),
    type: z.string().optional(),
    path: z.string().optional(),
    sha256: z.string().optional(),
  })
  .strict()

const ContextEvidenceBaseSchema = z
  .object({
    evidence_id: z.string(),
    evidence_family: z.string(),
    backend: z.string(),
    mode: z.string(),
    updated_at: z.string(),
    freshness_marker: z.string().nullable(),
    classification_reason: z.string(),
    observation: z.unknown(),
    observation_truncated: z.boolean(),
    provenance: z.record(z.unknown()),
    artifact_refs: z.array(ArtifactPointerSchema),
  })
  .strict()

const PrimaryEvidenceSchema = ContextEvidenceBaseSchema.extend({
  evidence_class: z.literal('primary'),
}).strict()

const DerivedEvidenceSchema = ContextEvidenceBaseSchema.extend({
  evidence_class: z.literal('derived'),
}).strict()

const ContextClaimSchema = z
  .object({
    claim_set_artifact_id: z.string(),
    ledger_revision: z.number().int().positive(),
    created_at: z.string(),
    producer: AnalysisClaimProducerSchema,
    review_required: z.boolean(),
    claim: AnalysisClaimSchema,
  })
  .strict()

const CaseStateContextSchema = z
  .object({
    artifact_id: z.string(),
    case_id: z.string(),
    revision: z.number().int().positive(),
    created_at: z.string(),
    objective: z.string(),
    decisions: z.array(z.unknown()),
    open_questions: z.array(z.unknown()),
    attempted_actions: z.array(z.unknown()),
    active_claim_ids: z.array(z.string()),
    pinned_artifacts: z.array(z.unknown()),
    next_actions: z.array(z.unknown()),
  })
  .strict()

const ContextGapSchema = z
  .object({
    source: z.enum(['primary_evidence', 'derived_evidence', 'claim', 'case_state', 'context']),
    source_id: z.string(),
    text: z.string(),
  })
  .strict()

const ContextQuestionSchema = z
  .object({
    source: z.enum(['primary_evidence', 'derived_evidence', 'claim', 'case_state', 'context']),
    source_id: z.string(),
    text: z.string(),
  })
  .strict()

const RecentChangeSchema = z
  .object({
    kind: z.enum(['primary_evidence', 'derived_evidence', 'claim', 'case_state', 'context']),
    id: z.string(),
    changed_at: z.string(),
  })
  .strict()

const SuggestedArtifactReadSchema = z
  .object({
    artifact_id: z.string(),
    type: z.string().nullable(),
    path: z.string().nullable(),
    sha256: z.string().nullable(),
    priority: z.number().int().min(1).max(4),
    reasons: z.array(z.string()),
  })
  .strict()

const TruncationSectionSchema = z
  .object({
    available_count: z.number().int().nonnegative(),
    included_count: z.number().int().nonnegative(),
    omitted_count: z.number().int().nonnegative(),
    upstream_truncated: z.boolean(),
    upstream_omitted_count: z.number().int().nonnegative(),
    omitted_ids: z.array(z.string()),
    omitted_ids_truncated: z.boolean(),
    estimated_tokens: z.number().int().nonnegative(),
  })
  .strict()

const TruncationManifestSchema = z
  .object({
    token_budget: z.number().int().positive(),
    estimated_tokens: z.number().int().nonnegative(),
    truncated: z.boolean(),
    budget_floor_exceeded: z.boolean(),
    sections: z
      .object({
        coverage_gaps: TruncationSectionSchema,
        unresolved_questions: TruncationSectionSchema,
        primary_evidence: TruncationSectionSchema,
        claims: TruncationSectionSchema,
        case_state: TruncationSectionSchema,
        derived_evidence: TruncationSectionSchema,
        recent_changes: TruncationSectionSchema,
        suggested_artifact_reads: TruncationSectionSchema,
      })
      .strict(),
  })
  .strict()

export const AnalysisContextPackDataSchema = z
  .object({
    sample_id: z.string(),
    goal: z.string(),
    case_id: z.string().nullable(),
    primary_evidence: z.array(PrimaryEvidenceSchema),
    derived_evidence: z.array(DerivedEvidenceSchema),
    claims: z.array(ContextClaimSchema),
    case_state: z.array(CaseStateContextSchema),
    coverage_gaps: z.array(ContextGapSchema),
    unresolved_questions: z.array(ContextQuestionSchema),
    recent_changes: z.array(RecentChangeSchema),
    suggested_artifact_reads: z.array(SuggestedArtifactReadSchema),
    marker: z.string(),
    truncation_manifest: TruncationManifestSchema,
  })
  .strict()

export const AnalysisContextPackOutputSchema = createWorkerResultOutputSchema(
  AnalysisContextPackDataSchema
)

export const analysisContextPackToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a deterministic, token-bounded context snapshot for one sample. Primary and derived evidence remain strictly separated; Claim Ledger, Case State, summaries, and reports are context-only. Use case_id to isolate one Case Workspace; a sole case is auto-selected and multiple cases fail closed without a selector. The opaque marker is bound to the selected case and supports incremental follow-up without running tools or changing analysis state.',
  inputSchema: AnalysisContextPackInputSchema,
  outputSchema: AnalysisContextPackOutputSchema,
  aspects: {
    execution: ['static', 'correlation'],
    capabilities: ['analysis-context', 'claim-ledger', 'incremental-handoff'],
    safety: ['passive', 'no-live-execution', 'no-network', 'deterministic'],
  },
  workflowRecipes: [
    {
      id: 'analysis-context-handoff',
      title: 'Deterministic analysis context handoff',
      description:
        'Pack bounded evidence, active claims, case state, gaps, and follow-up artifact reads before the next reasoning step.',
      startsWith: [TOOL_NAME],
      nextTools: ['artifact.read', 'analysis.claims.apply', 'workflow.run'],
      safety: ['passive', 'no-live-execution', 'no-network'],
    },
  ],
}

type EvidenceClass = 'primary' | 'derived'
type ContextSource = 'primary_evidence' | 'derived_evidence' | 'claim' | 'case_state' | 'context'
type SectionName =
  | 'coverage_gaps'
  | 'unresolved_questions'
  | 'primary_evidence'
  | 'claims'
  | 'case_state'
  | 'derived_evidence'
  | 'recent_changes'
  | 'suggested_artifact_reads'

interface CompactValue {
  value: unknown
  truncated: boolean
}

interface ContextArtifactPointer {
  id: string
  type?: string
  path?: string
  sha256?: string
}

interface ContextEvidenceEntry {
  evidence_class: EvidenceClass
  evidence_id: string
  evidence_family: string
  backend: string
  mode: string
  updated_at: string
  freshness_marker: string | null
  classification_reason: string
  observation: unknown
  observation_truncated: boolean
  provenance: Record<string, unknown>
  artifact_refs: ContextArtifactPointer[]
}

interface ContextClaimEntry {
  claim_set_artifact_id: string
  ledger_revision: number
  created_at: string
  producer: z.infer<typeof AnalysisClaimProducerSchema>
  review_required: boolean
  claim: z.infer<typeof AnalysisClaimSchema>
}

interface CaseStateContextEntry {
  artifact_id: string
  case_id: string
  revision: number
  created_at: string
  objective: string
  decisions: unknown[]
  open_questions: unknown[]
  attempted_actions: unknown[]
  active_claim_ids: string[]
  pinned_artifacts: unknown[]
  next_actions: unknown[]
}

interface ContextTextEntry {
  source: ContextSource
  source_id: string
  text: string
}

interface RecentChangeEntry {
  kind: ContextSource
  id: string
  changed_at: string
}

interface SuggestedArtifactReadEntry {
  artifact_id: string
  type: string | null
  path: string | null
  sha256: string | null
  priority: number
  reasons: string[]
}

interface MarkerPayload {
  version: 1
  sample_id: string
  case_id: string | null
  evidence_cursor: string | null
  claim_revision: number
  case_revision: number
  case_cursor: string | null
  digest: string
}

interface CaseStateSelection {
  entry: LoadedAnalysisCaseState | null
  caseId: string | null
  marker: string
}

interface SectionAvailability {
  totalCount: number
  upstreamOmittedIds: string[]
}

type SectionAvailabilityOverrides = Partial<Record<SectionName, SectionAvailability>>

interface ArtifactReadCandidate {
  artifact_id: string
  type: string | null
  path: string | null
  sha256: string | null
  priority: number
  reasons: Set<string>
}

interface SectionValues {
  coverage_gaps: ContextTextEntry[]
  unresolved_questions: ContextTextEntry[]
  primary_evidence: Array<ContextEvidenceEntry & { evidence_class: 'primary' }>
  claims: ContextClaimEntry[]
  case_state: CaseStateContextEntry[]
  derived_evidence: Array<ContextEvidenceEntry & { evidence_class: 'derived' }>
  recent_changes: RecentChangeEntry[]
  suggested_artifact_reads: SuggestedArtifactReadEntry[]
}

const SECTION_ORDER: SectionName[] = [
  'coverage_gaps',
  'unresolved_questions',
  'primary_evidence',
  'claims',
  'case_state',
  'derived_evidence',
  'recent_changes',
  'suggested_artifact_reads',
]

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stableValue)
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, stableValue(nested)])
    )
  }
  return value
}

function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value))
}

function resolveCaseStateSelection(
  index: AnalysisCaseStateIndex,
  requestedCaseId?: string
): CaseStateSelection {
  const availableCaseIds = Array.from(index.byCaseId.keys()).sort()
  if (requestedCaseId) {
    const entry = index.byCaseId.get(requestedCaseId)
    if (!entry) {
      const available = availableCaseIds.length > 0 ? availableCaseIds.join(', ') : 'none'
      throw new Error(
        `Case not found for sample: ${requestedCaseId}. Available case_id values: ${available}.`
      )
    }
    return {
      entry,
      caseId: requestedCaseId,
      marker: analysisCaseContextMarker(index, requestedCaseId, entry),
    }
  }
  if (availableCaseIds.length > 1) {
    throw new Error(
      `Multiple analysis cases exist for this sample (${availableCaseIds.join(', ')}). Provide case_id to select one; context packing is fail-closed to prevent cross-case mixing.`
    )
  }
  const caseId = availableCaseIds[0] || null
  const entry = caseId ? index.byCaseId.get(caseId) || null : null
  return {
    entry,
    caseId,
    marker: analysisCaseContextMarker(index, caseId, entry),
  }
}

function estimateTokens(value: unknown): number {
  return Math.ceil(Buffer.byteLength(stableJson(value), 'utf8') / 4)
}

function parseJsonRecord(value: string | null | undefined): Record<string, unknown> {
  if (!value) return {}
  try {
    const parsed = JSON.parse(value) as unknown
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {}
  } catch {
    return {}
  }
}

function parseJsonArray(value: string | null | undefined): unknown[] {
  if (!value) return []
  try {
    const parsed = JSON.parse(value) as unknown
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function compactUnknown(value: unknown, depth = 0): CompactValue {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return { value, truncated: false }
  }
  if (typeof value === 'string') {
    if (value.length <= 1200) return { value, truncated: false }
    return { value: value.slice(0, 1200) + '…', truncated: true }
  }
  if (Array.isArray(value)) {
    if (depth >= 4) {
      return { value: `[array:${value.length}]`, truncated: true }
    }
    const selected = value.slice(0, 16).map((entry) => compactUnknown(entry, depth + 1))
    return {
      value: selected.map((entry) => entry.value),
      truncated: value.length > selected.length || selected.some((entry) => entry.truncated),
    }
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
      left.localeCompare(right)
    )
    if (depth >= 4) {
      return { value: `{object:${entries.length}}`, truncated: true }
    }
    const selected = entries.slice(0, 24).map(([key, nested]) => {
      const compact = compactUnknown(nested, depth + 1)
      return { key, ...compact }
    })
    return {
      value: Object.fromEntries(selected.map((entry) => [entry.key, entry.value])),
      truncated: entries.length > selected.length || selected.some((entry) => entry.truncated),
    }
  }
  return { value: `[${typeof value}]`, truncated: true }
}

function artifactIdFromUnknown(value: unknown): string | null {
  if (typeof value === 'string') return value.trim() || null
  if (!value || typeof value !== 'object') return null
  const input = value as Record<string, unknown>
  const id = typeof input.id === 'string' ? input.id : input.artifact_id
  return typeof id === 'string' && id.length > 0 ? id : null
}

function canonicalArtifactPointer(
  database: DatabaseManager,
  sampleId: string,
  value: unknown,
  warnings: string[],
  source: string,
  allowContextOnly = true
): ContextArtifactPointer | null {
  const artifactId = artifactIdFromUnknown(value)
  if (!artifactId) {
    warnings.push(`Skipped malformed artifact reference from ${source}.`)
    return null
  }
  const artifact = database.findArtifact(artifactId)
  if (!artifact) {
    warnings.push(`Skipped missing artifact reference ${artifactId} from ${source}.`)
    return null
  }
  if (artifact.sample_id !== sampleId) {
    warnings.push(
      `Skipped cross-sample artifact reference ${artifactId} from ${source}; context is isolated to ${sampleId}.`
    )
    return null
  }
  if (!allowContextOnly && isContextOnlyArtifactType(artifact.type)) {
    warnings.push(
      `Skipped context-only artifact reference ${artifactId} (${artifact.type}) from ${source}.`
    )
    return null
  }
  return {
    id: artifact.id,
    type: artifact.type,
    path: artifact.path,
    sha256: artifact.sha256,
  }
}

function evidenceCursor(row: Pick<AnalysisEvidence, 'updated_at' | 'id'>): string {
  return `${row.updated_at}\u0000${row.id}`
}

function sortEvidence(rows: AnalysisEvidence[]): AnalysisEvidence[] {
  return [...rows].sort((left, right) => {
    const timeOrder = right.updated_at.localeCompare(left.updated_at)
    return timeOrder !== 0 ? timeOrder : right.id.localeCompare(left.id)
  })
}

function selectEvidence(rows: AnalysisEvidence[], scope: z.infer<typeof EvidenceScopeSchema>) {
  const sorted = sortEvidence(rows)
  if (scope === 'all') {
    return {
      selected: sorted.slice(0, MAX_CONTEXT_ITEMS),
      upstreamOmitted: sorted.slice(MAX_CONTEXT_ITEMS),
    }
  }
  const seen = new Set<string>()
  const latest = sorted.filter((row) => {
    const key = `${row.evidence_family}\u0000${row.backend}\u0000${row.mode}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
  return {
    selected: latest.slice(0, MAX_CONTEXT_ITEMS),
    upstreamOmitted: latest.slice(MAX_CONTEXT_ITEMS),
  }
}

function isContextOnlyEvidence(row: AnalysisEvidence): boolean {
  return /(?:^|[_\-.])(summary|report|claim|case)(?:$|[_\-.])/i.test(row.evidence_family)
}

const TRUSTED_BACKEND_PREVIEW_PRODUCERS = new Set(['rizin', 'upx', 'yara_x'])

function provenanceString(
  provenance: Record<string, unknown>,
  key: 'tool' | 'source_tool'
): string | null {
  const value = provenance[key]
  return typeof value === 'string' && value.length > 0 ? value : null
}

function provenanceSources(provenance: Record<string, unknown>): Set<string> {
  const sources = provenance.sources
  if (!Array.isArray(sources)) return new Set()
  return new Set(sources.filter((value): value is string => typeof value === 'string'))
}

function trustedPrimaryProducer(row: AnalysisEvidence): string | null {
  const provenance = parseJsonRecord(row.provenance_json)
  const producer =
    provenanceString(provenance, 'tool') || provenanceString(provenance, 'source_tool')

  if (
    row.evidence_family === 'strings' &&
    row.backend === 'strings.extract' &&
    producer === 'strings.extract'
  ) {
    return 'strings.extract'
  }

  if (
    row.evidence_family === 'backend_preview' &&
    TRUSTED_BACKEND_PREVIEW_PRODUCERS.has(row.backend) &&
    producer === `${row.backend}.${row.mode}`
  ) {
    return producer
  }

  const sources = provenanceSources(provenance)
  if (
    row.evidence_family === 'unpack_execution' &&
    row.backend === 'upx' &&
    row.mode === 'decompress' &&
    sources.has('upx.inspect')
  ) {
    return 'workflow.analyze:upx-decompress'
  }

  if (
    row.evidence_family === 'debug_session' &&
    row.backend === 'runtime' &&
    row.mode === 'captured' &&
    sources.has('sandbox.execute') &&
    sources.has('workflow.analyze.stage')
  ) {
    return 'workflow.analyze:runtime-capture'
  }

  return null
}

function classifyEvidence(row: AnalysisEvidence): {
  evidenceClass: EvidenceClass
  reason: string
} {
  const trustedProducer = trustedPrimaryProducer(row)
  if (trustedProducer) {
    return {
      evidenceClass: 'primary',
      reason: `trusted_producer:${trustedProducer}`,
    }
  }
  return {
    evidenceClass: 'derived',
    reason: `unverified_producer:${row.evidence_family}:${row.backend}:${row.mode}`,
  }
}

function toContextEvidence(
  row: AnalysisEvidence,
  database: DatabaseManager,
  sampleId: string,
  warnings: string[]
): ContextEvidenceEntry {
  const classification = classifyEvidence(row)
  const result = parseJsonRecord(row.result_json)
  const compact = compactUnknown(result)
  const base = {
    evidence_id: row.id,
    evidence_family: row.evidence_family,
    backend: row.backend,
    mode: row.mode,
    updated_at: row.updated_at,
    freshness_marker: row.freshness_marker,
    classification_reason: classification.reason,
    observation: compact.value,
    observation_truncated: compact.truncated,
    provenance: parseJsonRecord(row.provenance_json),
    artifact_refs: parseJsonArray(row.artifact_refs_json)
      .map((value) =>
        canonicalArtifactPointer(
          database,
          sampleId,
          value,
          warnings,
          `analysis evidence ${row.id}`,
          false
        )
      )
      .filter((entry): entry is NonNullable<typeof entry> => entry !== null)
      .slice(0, 32),
  }
  return classification.evidenceClass === 'primary'
    ? ({ ...base, evidence_class: 'primary' } as const)
    : ({ ...base, evidence_class: 'derived' } as const)
}

function textFromUnknown(value: unknown): string | null {
  if (typeof value === 'string') return value.trim() || null
  if (!value || typeof value !== 'object') return null
  const record = value as Record<string, unknown>
  for (const key of ['text', 'question', 'reason', 'description', 'message', 'domain', 'area']) {
    if (typeof record[key] === 'string' && record[key].trim()) return record[key].trim()
  }
  return null
}

function collectNamedValues(
  value: unknown,
  names: Set<string>,
  output: unknown[],
  depth = 0
): void {
  if (!value || typeof value !== 'object' || depth > 5 || output.length >= MAX_CONTEXT_ITEMS) {
    return
  }
  if (Array.isArray(value)) {
    for (const entry of value.slice(0, 64)) collectNamedValues(entry, names, output, depth + 1)
    return
  }
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (names.has(key.toLowerCase())) {
      output.push(...(Array.isArray(nested) ? nested : [nested]))
      if (output.length >= MAX_CONTEXT_ITEMS) return
    }
    collectNamedValues(nested, names, output, depth + 1)
  }
}

function uniqueContextTexts<T extends ContextTextEntry>(values: T[]): T[] {
  const seen = new Set<string>()
  return values.filter((value) => {
    const key = `${value.source}\u0000${value.source_id}\u0000${value.text}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function markerPayload(input: {
  sampleId: string
  caseId: string | null
  evidenceRows: AnalysisEvidence[]
  claimRevision: number
  caseRevision: number
  caseCursor: string | null
  claimMarker: string
  caseMarker: string
}): MarkerPayload {
  const cursors = input.evidenceRows.map(evidenceCursor).sort()
  const evidenceState = input.evidenceRows
    .map((row) => [
      row.id,
      row.updated_at,
      createHash('sha256')
        .update(
          stableJson([
            row.compatibility_marker,
            row.freshness_marker,
            row.provenance_json,
            row.metadata_json,
            row.result_json,
            row.artifact_refs_json,
          ])
        )
        .digest('hex'),
    ])
    .sort((left, right) => stableJson(left).localeCompare(stableJson(right)))
  const digest = createHash('sha256')
    .update(
      stableJson({
        evidence: evidenceState,
        claim_marker: input.claimMarker,
        case_id: input.caseId,
        case_marker: input.caseMarker,
      })
    )
    .digest('hex')
  return {
    version: 1,
    sample_id: input.sampleId,
    case_id: input.caseId,
    evidence_cursor: cursors[cursors.length - 1] || null,
    claim_revision: input.claimRevision,
    case_revision: input.caseRevision,
    case_cursor: input.caseCursor,
    digest,
  }
}

function encodeMarker(payload: MarkerPayload): string {
  return MARKER_PREFIX + Buffer.from(stableJson(payload), 'utf8').toString('base64url')
}

function decodeMarker(marker: string, sampleId: string, caseId: string | null): MarkerPayload {
  if (!marker.startsWith(MARKER_PREFIX)) throw new Error('since_marker is not a context marker.')
  let parsed: Partial<MarkerPayload>
  try {
    parsed = JSON.parse(
      Buffer.from(marker.slice(MARKER_PREFIX.length), 'base64url').toString('utf8')
    ) as Partial<MarkerPayload>
  } catch {
    throw new Error('since_marker is malformed.')
  }
  if (
    parsed.version !== 1 ||
    parsed.sample_id !== sampleId ||
    (parsed.case_id !== undefined &&
      parsed.case_id !== null &&
      typeof parsed.case_id !== 'string') ||
    (parsed.evidence_cursor !== null && typeof parsed.evidence_cursor !== 'string') ||
    !Number.isInteger(parsed.claim_revision) ||
    !Number.isInteger(parsed.case_revision) ||
    (parsed.case_cursor !== undefined &&
      parsed.case_cursor !== null &&
      typeof parsed.case_cursor !== 'string') ||
    typeof parsed.digest !== 'string' ||
    !/^[a-f0-9]{64}$/.test(parsed.digest)
  ) {
    throw new Error('since_marker does not belong to this sample or is malformed.')
  }
  const markerCaseId = parsed.case_id ?? null
  if (markerCaseId !== caseId) {
    throw new Error(
      `since_marker belongs to case_id=${markerCaseId || 'none'}, not case_id=${caseId || 'none'}.`
    )
  }
  return {
    ...(parsed as MarkerPayload),
    case_id: markerCaseId,
    case_cursor: parsed.case_cursor ?? null,
  }
}

function addArtifactRead(
  sink: Map<string, ArtifactReadCandidate>,
  database: DatabaseManager,
  sampleId: string,
  value: unknown,
  priority: number,
  reason: string,
  warnings: string[]
): void {
  const pointer = canonicalArtifactPointer(database, sampleId, value, warnings, reason, true)
  if (!pointer) return
  const existing = sink.get(pointer.id)
  const candidate: ArtifactReadCandidate = existing || {
    artifact_id: pointer.id,
    type: pointer.type || null,
    path: pointer.path || null,
    sha256: pointer.sha256 || null,
    priority,
    reasons: new Set<string>(),
  }
  candidate.priority = Math.min(candidate.priority, priority)
  candidate.reasons.add(reason)
  sink.set(pointer.id, candidate)
}

function sectionId(section: SectionName, value: unknown): string {
  switch (section) {
    case 'coverage_gaps':
    case 'unresolved_questions': {
      const entry = value as ContextTextEntry
      return `${entry.source}:${entry.source_id}:${createHash('sha1').update(entry.text).digest('hex').slice(0, 12)}`
    }
    case 'primary_evidence':
    case 'derived_evidence':
      return (value as ContextEvidenceEntry).evidence_id
    case 'claims': {
      const entry = value as ContextClaimEntry
      return entry.claim.claim_id || entry.claim_set_artifact_id
    }
    case 'case_state': {
      const entry = value as CaseStateContextEntry
      return `${entry.case_id}:${entry.revision}`
    }
    case 'recent_changes': {
      const entry = value as RecentChangeEntry
      return `${entry.kind}:${entry.id}`
    }
    case 'suggested_artifact_reads':
      return (value as SuggestedArtifactReadEntry).artifact_id
  }
}

function emptySections(): SectionValues {
  return {
    coverage_gaps: [],
    unresolved_questions: [],
    primary_evidence: [],
    claims: [],
    case_state: [],
    derived_evidence: [],
    recent_changes: [],
    suggested_artifact_reads: [],
  }
}

function buildManifest(
  tokenBudget: number,
  available: SectionValues,
  included: SectionValues,
  estimatedTokens: number,
  budgetFloorExceeded: boolean,
  availabilityOverrides: SectionAvailabilityOverrides
): z.infer<typeof TruncationManifestSchema> {
  const sections = Object.fromEntries(
    SECTION_ORDER.map((section) => {
      const includedIds = new Set(included[section].map((value) => sectionId(section, value)))
      const materializedOmittedIds = available[section]
        .map((value) => sectionId(section, value))
        .filter((id) => !includedIds.has(id))
      const availability = availabilityOverrides[section]
      const totalCount = availability?.totalCount ?? available[section].length
      const upstreamOmittedIds = availability?.upstreamOmittedIds ?? []
      const omittedIds = Array.from(new Set([...materializedOmittedIds, ...upstreamOmittedIds]))
      const upstreamOmittedCount = Math.max(0, totalCount - available[section].length)
      return [
        section,
        {
          available_count: totalCount,
          included_count: included[section].length,
          omitted_count: Math.max(0, totalCount - included[section].length),
          upstream_truncated: upstreamOmittedCount > 0,
          upstream_omitted_count: upstreamOmittedCount,
          omitted_ids: omittedIds.slice(0, MAX_OMITTED_IDS),
          omitted_ids_truncated: omittedIds.length > MAX_OMITTED_IDS,
          estimated_tokens: estimateTokens(available[section]),
        },
      ]
    })
  ) as z.infer<typeof TruncationManifestSchema>['sections']
  return {
    token_budget: tokenBudget,
    estimated_tokens: estimatedTokens,
    truncated: SECTION_ORDER.some(
      (section) =>
        included[section].length <
        (availabilityOverrides[section]?.totalCount ?? available[section].length)
    ),
    budget_floor_exceeded: budgetFloorExceeded,
    sections,
  }
}

function assembleData(input: {
  sampleId: string
  goal: string
  caseId: string | null
  marker: string
  tokenBudget: number
  available: SectionValues
  included: SectionValues
  estimatedTokens: number
  budgetFloorExceeded: boolean
  availabilityOverrides: SectionAvailabilityOverrides
}): z.infer<typeof AnalysisContextPackDataSchema> {
  return {
    sample_id: input.sampleId,
    goal: input.goal,
    case_id: input.caseId,
    primary_evidence: input.included.primary_evidence,
    derived_evidence: input.included.derived_evidence,
    claims: input.included.claims,
    case_state: input.included.case_state,
    coverage_gaps: input.included.coverage_gaps,
    unresolved_questions: input.included.unresolved_questions,
    recent_changes: input.included.recent_changes,
    suggested_artifact_reads: input.included.suggested_artifact_reads,
    marker: input.marker,
    truncation_manifest: buildManifest(
      input.tokenBudget,
      input.available,
      input.included,
      input.estimatedTokens,
      input.budgetFloorExceeded,
      input.availabilityOverrides
    ),
  }
}

function packSections(input: {
  sampleId: string
  goal: string
  caseId: string | null
  marker: string
  tokenBudget: number
  available: SectionValues
  availabilityOverrides?: SectionAvailabilityOverrides
}): z.infer<typeof AnalysisContextPackDataSchema> {
  const included = emptySections()
  const availabilityOverrides = input.availabilityOverrides ?? {}
  const createCandidate = (estimatedTokens = 0, budgetFloorExceeded = false) =>
    assembleData({
      ...input,
      included,
      estimatedTokens,
      budgetFloorExceeded,
      availabilityOverrides,
    })

  for (const section of SECTION_ORDER) {
    for (const value of input.available[section]) {
      ;(included[section] as unknown[]).push(value)
      if (estimateTokens(createCandidate()) > input.tokenBudget) {
        ;(included[section] as unknown[]).pop()
      }
    }
  }

  const stableCandidate = (budgetFloorExceeded: boolean) => {
    let estimatedTokens = 0
    let output = createCandidate(estimatedTokens, budgetFloorExceeded)
    for (let attempt = 0; attempt < 12; attempt += 1) {
      const measured = estimateTokens(output)
      if (measured === estimatedTokens) return output
      estimatedTokens = measured
      output = createCandidate(estimatedTokens, budgetFloorExceeded)
    }
    return output
  }
  const removeLowestPriorityItem = (): boolean => {
    for (const section of [...SECTION_ORDER].reverse()) {
      if (included[section].length > 0) {
        ;(included[section] as unknown[]).pop()
        return true
      }
    }
    return false
  }

  while (true) {
    const output = stableCandidate(false)
    if (estimateTokens(output) <= input.tokenBudget) return output
    if (!removeLowestPriorityItem()) {
      return stableCandidate(true)
    }
  }
}

export function createAnalysisContextPackHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: Record<string, unknown>): Promise<WorkerResult> => {
    try {
      const input = AnalysisContextPackInputSchema.parse(args)
      if (!database.findSample(input.sample_id)) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: 0, tool: TOOL_NAME },
        }
      }

      const allEvidenceRows = sortEvidence(database.findAnalysisEvidenceBySample(input.sample_id))
      const evidenceSelection = selectEvidence(allEvidenceRows, input.evidence_scope)
      const selectedRows = evidenceSelection.selected
      const referenceWarnings: string[] = []
      let caseIndex: AnalysisCaseStateIndex | null = null
      let caseLoadWarning: string | null = null
      if (input.include_case) {
        try {
          caseIndex = await loadAnalysisCaseStateIndex(workspaceManager, database, input.sample_id)
        } catch (error) {
          if (input.case_id) {
            throw new Error(
              `Case State context could not be loaded for case_id=${input.case_id}: ${
                error instanceof Error ? error.message : String(error)
              }`
            )
          }
          caseLoadWarning = `Case State context could not be loaded; Claims were withheld: ${
            error instanceof Error ? error.message : String(error)
          }`
        }
      }
      const caseSelection = caseIndex
        ? resolveCaseStateSelection(caseIndex, input.case_id)
        : { entry: null, caseId: null, marker: 'none' }
      const blockingCaseIntegrityIssues = caseIndex
        ? analysisCaseBlockingIntegrityIssues(caseIndex, caseSelection.caseId)
        : []
      const activeClaimIds = !input.include_case
        ? null
        : caseSelection.entry && blockingCaseIntegrityIssues.length === 0
          ? caseSelection.entry.payload.active_claim_ids
          : caseIndex &&
              caseIndex.total_artifact_count === 0 &&
              caseIndex.integrity_issues.length === 0
            ? null
            : []
      const loadedClaimLedger = await loadAnalysisClaimLedgerIndex(
        workspaceManager,
        database,
        input.sample_id,
        activeClaimIds === null
          ? { scope: input.claim_scope, maxArtifacts: MAX_CONTEXT_ITEMS }
          : { scope: input.claim_scope, activeClaimIds }
      )
      const claimLedger = scopeAnalysisClaimLedgerIndex(loadedClaimLedger, activeClaimIds)

      const evidenceEntries = selectedRows
        .filter((row) => !isContextOnlyEvidence(row))
        .map((row) => toContextEvidence(row, database, input.sample_id, referenceWarnings))
      const primaryEvidence = evidenceEntries.filter(
        (
          entry
        ): entry is ContextEvidenceEntry & {
          evidence_class: 'primary'
        } => entry.evidence_class === 'primary'
      )
      const derivedEvidence = evidenceEntries.filter(
        (
          entry
        ): entry is ContextEvidenceEntry & {
          evidence_class: 'derived'
        } => entry.evidence_class === 'derived'
      )

      const claims: ContextClaimEntry[] = Array.from(claimLedger.byClaimId.values())
        .map((entry) => ({
          claim_set_artifact_id: entry.claim_set_artifact_id,
          ledger_revision: entry.ledger_revision,
          created_at: entry.created_at,
          producer: entry.producer,
          review_required: ['inferred', 'contradicted'].includes(entry.claim.status),
          claim: entry.claim,
        }))
        .sort((left, right) => {
          const revisionOrder = right.ledger_revision - left.ledger_revision
          return revisionOrder !== 0
            ? revisionOrder
            : left.claim.claim_id.localeCompare(right.claim.claim_id)
        })

      const rawCaseStates = caseSelection.entry ? [caseSelection.entry] : []
      const caseStates: CaseStateContextEntry[] = rawCaseStates
        .map((entry) => ({
          artifact_id: entry.artifact.id,
          case_id: entry.payload.case_id,
          revision: entry.payload.revision,
          created_at: entry.payload.created_at,
          objective: entry.payload.objective,
          decisions: [...entry.payload.decisions],
          open_questions: [...entry.payload.open_questions],
          attempted_actions: [...entry.payload.attempted_actions],
          active_claim_ids: [...entry.payload.active_claim_ids],
          pinned_artifacts: [...entry.payload.pinned_artifacts],
          next_actions: [...entry.payload.next_actions],
        }))
        .sort((left, right) => {
          const timeOrder = right.created_at.localeCompare(left.created_at)
          return timeOrder !== 0 ? timeOrder : left.case_id.localeCompare(right.case_id)
        })

      const gaps: ContextTextEntry[] = []
      const questions: ContextTextEntry[] = []
      const gapKeys = new Set([
        'coverage_gaps',
        'gaps',
        'missing_evidence',
        'unverified_areas',
        'uncovered_areas',
      ])
      const questionKeys = new Set(['unresolved_questions', 'open_questions', 'questions'])
      for (const row of selectedRows) {
        const result = parseJsonRecord(row.result_json)
        const gapValues: unknown[] = []
        const questionValues: unknown[] = []
        collectNamedValues(result, gapKeys, gapValues)
        collectNamedValues(result, questionKeys, questionValues)
        const outputSource: ContextSource = isContextOnlyEvidence(row)
          ? 'context'
          : classifyEvidence(row).evidenceClass === 'primary'
            ? 'primary_evidence'
            : 'derived_evidence'
        for (const value of gapValues) {
          const text = textFromUnknown(value)
          if (text) gaps.push({ source: outputSource, source_id: row.id, text })
        }
        for (const value of questionValues) {
          const text = textFromUnknown(value)
          if (text) questions.push({ source: outputSource, source_id: row.id, text })
        }
      }
      for (const entry of claims) {
        if (entry.claim.category === 'open_question') {
          questions.push({
            source: 'claim',
            source_id: entry.claim.claim_id,
            text: entry.claim.statement,
          })
        }
        for (const test of entry.claim.falsification_tests) {
          gaps.push({ source: 'claim', source_id: entry.claim.claim_id, text: test })
        }
      }
      for (const entry of caseStates) {
        for (const value of entry.open_questions) {
          const text = textFromUnknown(value)
          if (text) questions.push({ source: 'case_state', source_id: entry.case_id, text })
        }
      }

      const maxClaimRevision = claimLedger.claim_sets.reduce(
        (maximum, entry) => Math.max(maximum, entry.payload.ledger_revision),
        0
      )
      const maxCaseRevision = rawCaseStates.reduce(
        (maximum, entry) => Math.max(maximum, entry.payload.revision),
        0
      )
      const caseCursors = rawCaseStates
        .map((entry) => `${entry.artifact.created_at}\u0000${entry.artifact.id}`)
        .sort()
      const currentCaseCursor = caseCursors[caseCursors.length - 1] || null
      const currentMarkerPayload = markerPayload({
        sampleId: input.sample_id,
        caseId: caseSelection.caseId,
        evidenceRows: allEvidenceRows,
        claimRevision: maxClaimRevision,
        caseRevision: maxCaseRevision,
        caseCursor: currentCaseCursor,
        claimMarker: claimLedger.marker,
        caseMarker: caseSelection.marker,
      })
      const previousMarker = input.since_marker
        ? decodeMarker(input.since_marker, input.sample_id, caseSelection.caseId)
        : null
      const marker = encodeMarker(currentMarkerPayload)

      const recentChanges: RecentChangeEntry[] = []
      for (const row of allEvidenceRows) {
        if (
          !previousMarker?.evidence_cursor ||
          evidenceCursor(row) > previousMarker.evidence_cursor
        ) {
          const kind: ContextSource = isContextOnlyEvidence(row)
            ? 'context'
            : classifyEvidence(row).evidenceClass === 'primary'
              ? 'primary_evidence'
              : 'derived_evidence'
          recentChanges.push({ kind, id: row.id, changed_at: row.updated_at })
        }
      }
      for (const entry of claims) {
        if (!previousMarker || entry.ledger_revision > previousMarker.claim_revision) {
          recentChanges.push({
            kind: 'claim',
            id: entry.claim.claim_id,
            changed_at: entry.created_at,
          })
        }
      }
      for (const entry of rawCaseStates) {
        const cursor = `${entry.artifact.created_at}\u0000${entry.artifact.id}`
        if (!previousMarker || !previousMarker.case_cursor || cursor > previousMarker.case_cursor) {
          recentChanges.push({
            kind: 'case_state',
            id: `${entry.payload.case_id}:${entry.payload.revision}`,
            changed_at: entry.artifact.created_at,
          })
        }
      }
      if (
        previousMarker &&
        previousMarker.digest !== currentMarkerPayload.digest &&
        (currentMarkerPayload.evidence_cursor || '') <= (previousMarker.evidence_cursor || '') &&
        currentMarkerPayload.claim_revision <= previousMarker.claim_revision &&
        currentMarkerPayload.case_revision <= previousMarker.case_revision &&
        (currentMarkerPayload.case_cursor || '') <= (previousMarker.case_cursor || '')
      ) {
        const timestamps = [
          allEvidenceRows[0]?.updated_at,
          claimLedger.latest_created_at,
          caseSelection.entry?.payload.created_at,
        ]
          .filter((value): value is string => typeof value === 'string')
          .sort()
        recentChanges.push({
          kind: 'context',
          id: 'marker-invalidated',
          changed_at: timestamps[timestamps.length - 1] || '1970-01-01T00:00:00.000Z',
        })
      }
      recentChanges.sort((left, right) => {
        const timeOrder = right.changed_at.localeCompare(left.changed_at)
        return timeOrder !== 0 ? timeOrder : left.id.localeCompare(right.id)
      })

      const artifactReads = new Map<string, ArtifactReadCandidate>()
      for (const entry of primaryEvidence) {
        for (const artifact of entry.artifact_refs) {
          addArtifactRead(
            artifactReads,
            database,
            input.sample_id,
            artifact,
            1,
            `primary_evidence:${entry.evidence_id}`,
            referenceWarnings
          )
        }
      }
      for (const entry of claims) {
        for (const reference of [
          ...entry.claim.supporting_evidence,
          ...entry.claim.counter_evidence,
        ]) {
          addArtifactRead(
            artifactReads,
            database,
            input.sample_id,
            reference.artifact_id,
            2,
            `claim:${entry.claim.claim_id}`,
            referenceWarnings
          )
        }
      }
      for (const entry of caseStates) {
        for (const artifact of entry.pinned_artifacts) {
          addArtifactRead(
            artifactReads,
            database,
            input.sample_id,
            artifact,
            2,
            `case_state:${entry.case_id}`,
            referenceWarnings
          )
        }
      }
      for (const entry of derivedEvidence) {
        for (const artifact of entry.artifact_refs) {
          addArtifactRead(
            artifactReads,
            database,
            input.sample_id,
            artifact,
            3,
            `derived_evidence:${entry.evidence_id}`,
            referenceWarnings
          )
        }
      }
      for (const row of selectedRows.filter(isContextOnlyEvidence)) {
        for (const artifact of parseJsonArray(row.artifact_refs_json)) {
          addArtifactRead(
            artifactReads,
            database,
            input.sample_id,
            artifact,
            4,
            `context:${row.id}`,
            referenceWarnings
          )
        }
      }
      const suggestedArtifactReads = Array.from(artifactReads.values())
        .map((entry) => ({
          artifact_id: entry.artifact_id,
          type: entry.type,
          path: entry.path,
          sha256: entry.sha256,
          priority: entry.priority,
          reasons: Array.from(entry.reasons).sort(),
        }))
        .sort((left, right) => {
          const priorityOrder = left.priority - right.priority
          return priorityOrder !== 0
            ? priorityOrder
            : left.artifact_id.localeCompare(right.artifact_id)
        })

      const available: SectionValues = {
        coverage_gaps: uniqueContextTexts(gaps).slice(0, MAX_CONTEXT_ITEMS),
        unresolved_questions: uniqueContextTexts(questions).slice(0, MAX_CONTEXT_ITEMS),
        primary_evidence: primaryEvidence,
        claims,
        case_state: caseStates,
        derived_evidence: derivedEvidence,
        recent_changes: recentChanges.slice(0, MAX_CONTEXT_ITEMS),
        suggested_artifact_reads: suggestedArtifactReads.slice(0, MAX_CONTEXT_ITEMS),
      }
      const scopedEvidenceRows = [
        ...evidenceSelection.selected,
        ...evidenceSelection.upstreamOmitted,
      ].filter((row) => !isContextOnlyEvidence(row))
      const upstreamPrimaryIds = evidenceSelection.upstreamOmitted
        .filter(
          (row) => !isContextOnlyEvidence(row) && classifyEvidence(row).evidenceClass === 'primary'
        )
        .map((row) => row.id)
      const upstreamDerivedIds = evidenceSelection.upstreamOmitted
        .filter(
          (row) => !isContextOnlyEvidence(row) && classifyEvidence(row).evidenceClass === 'derived'
        )
        .map((row) => row.id)
      const availabilityOverrides: SectionAvailabilityOverrides = {
        ...(claimLedger.active_claim_resolution?.status !== undefined &&
        claimLedger.active_claim_resolution.status !== 'complete'
          ? {
              claims: {
                totalCount: claimLedger.active_claim_resolution.requested_claim_ids.length,
                upstreamOmittedIds: claimLedger.active_claim_resolution.requested_claim_ids,
              },
            }
          : {}),
        primary_evidence: {
          totalCount: scopedEvidenceRows.filter(
            (row) => classifyEvidence(row).evidenceClass === 'primary'
          ).length,
          upstreamOmittedIds: upstreamPrimaryIds,
        },
        derived_evidence: {
          totalCount: scopedEvidenceRows.filter(
            (row) => classifyEvidence(row).evidenceClass === 'derived'
          ).length,
          upstreamOmittedIds: upstreamDerivedIds,
        },
      }
      const data = packSections({
        sampleId: input.sample_id,
        goal: input.goal,
        caseId: caseSelection.caseId,
        marker,
        tokenBudget: input.token_budget,
        available,
        availabilityOverrides,
      })
      const warnings = [
        ...claimLedger.warnings,
        ...(caseIndex?.warnings || []),
        ...(caseLoadWarning ? [caseLoadWarning] : []),
        ...referenceWarnings,
      ]
      if (evidenceSelection.upstreamOmitted.length > 0) {
        warnings.push(
          `Context materialization selected ${selectedRows.length} of ${selectedRows.length + evidenceSelection.upstreamOmitted.length} scoped evidence row(s); the manifest records the upstream omissions.`
        )
      }
      if (data.truncation_manifest.budget_floor_exceeded) {
        warnings.push(
          'token_budget is smaller than the fixed context boundary; the manifest and empty partitions were preserved.'
        )
      }

      return AnalysisContextPackOutputSchema.parse({
        ok: true,
        data,
        ...(warnings.length > 0 ? { warnings: Array.from(new Set(warnings)).slice(0, 32) } : {}),
        metrics: { elapsed_ms: 0, tool: TOOL_NAME },
      }) as WorkerResult
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: 0, tool: TOOL_NAME },
      }
    }
  }
}
