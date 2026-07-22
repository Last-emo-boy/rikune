import fs from 'fs/promises'
import { createReadStream } from 'fs'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { hostname } from 'os'
import { z } from 'zod'
import type { ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import {
  withContextWriteLease,
  type ContextWriteLeaseGuard,
} from '../persistence/context-write-lease.js'
import { deriveArtifactSessionTag } from './artifact-inventory.js'
import { ANALYSIS_CASE_STATE_ARTIFACT_TYPE } from './analysis-case-artifacts.js'
import { isContextOnlyArtifactType } from './context-only-artifacts.js'
import { matchesSessionTag, sanitizePathSegment } from '../utils/shared-helpers.js'

export const ANALYSIS_CLAIM_SET_ARTIFACT_TYPE = 'analysis_claim_set'
export const ANALYSIS_CLAIM_SET_SCHEMA = 'rikune.analysis_claim_set.v1'
export const ANALYSIS_CLAIM_OVERLAY_SCHEMA = 'rikune.analysis_claim_overlay.v1'
export const MAX_ANALYSIS_CLAIM_EVIDENCE_REFERENCES = 512
export const ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS = 5 * 60 * 1000
export const MAX_CASE_ACTIVE_CLAIM_SCAN_ARTIFACTS = 512
export const MAX_CASE_ACTIVE_CLAIM_SCAN_BYTES = 128 * 1024 * 1024

export function analysisClaimLedgerWriteLeaseKey(sampleId: string): string {
  return `analysis-claim-ledger:${sampleId}`
}

const MAX_JSON_EVIDENCE_BYTES = 8 * 1024 * 1024
const MAX_JSON_EVIDENCE_BATCH_BYTES = 32 * 1024 * 1024
const MAX_CLAIM_SET_BYTES = 32 * 1024 * 1024
const MAX_EVIDENCE_HASH_BATCH_BYTES = 512 * 1024 * 1024
const MAX_EVIDENCE_ARTIFACTS_PER_BATCH = 512
const MAX_CLAIM_LEDGER_LOCK_BYTES = 4096

export const AnalysisClaimIdSchema = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/, {
    message: 'claim_id must use letters, numbers, dot, underscore, colon, or hyphen.',
  })

const IsoTimestampSchema = z.string().datetime({ offset: true })

export const AnalysisClaimCategorySchema = z.enum([
  'finding',
  'hypothesis',
  'ioc',
  'technique',
  'verdict',
  'open_question',
])

export const AnalysisClaimStatusSchema = z.enum([
  'inferred',
  'corroborated',
  'contradicted',
  'verified',
  'rejected',
])

export const AnalysisClaimSourceSchema = z.enum(['llm', 'analyst', 'imported'])

export const AnalysisClaimReviewDecisionSchema = z.enum([
  'corroborated',
  'contradicted',
  'verified',
  'rejected',
])

const JsonPointerSchema = z
  .string()
  .max(500)
  .refine((value) => value === '' || value.startsWith('/'), {
    message: 'json_pointer must be empty or start with "/".',
  })
  .refine((value) => !/~(?:[^01]|$)/.test(value), {
    message: 'json_pointer contains an invalid "~" escape.',
  })

export const AnalysisClaimEvidenceInputSchema = z
  .object({
    artifact_id: z.string().min(1).max(200),
    json_pointer: JsonPointerSchema.optional(),
    locator: z.string().min(1).max(500).optional(),
    summary: z.string().min(1).max(1200).optional(),
  })
  .strict()

export const AnalysisClaimEvidenceSchema = AnalysisClaimEvidenceInputSchema.extend({
  artifact_type: z.string().min(1),
  artifact_path: z.string().min(1),
  artifact_sha256: z.string().regex(/^[a-f0-9]{64}$/i),
})

export const AnalysisClaimReviewInputSchema = z
  .object({
    decision: AnalysisClaimReviewDecisionSchema,
    reviewer: z.string().min(1).max(200),
    note: z.string().min(1).max(2000).optional(),
  })
  .strict()

export const AnalysisClaimReviewSchema = AnalysisClaimReviewInputSchema.extend({
  reviewed_at: IsoTimestampSchema,
})

const claimEntryFields = {
  category: AnalysisClaimCategorySchema,
  subject: z.string().min(1).max(500),
  statement: z.string().min(1).max(5000),
  status: AnalysisClaimStatusSchema.default('inferred'),
  supporting_evidence: z.array(AnalysisClaimEvidenceInputSchema).max(64).default([]),
  counter_evidence: z.array(AnalysisClaimEvidenceInputSchema).max(64).default([]),
  assumptions: z.array(z.string().min(1).max(1000)).max(32).default([]),
  alternatives: z.array(z.string().min(1).max(1000)).max(32).default([]),
  falsification_tests: z.array(z.string().min(1).max(1200)).max(32).default([]),
  review: AnalysisClaimReviewInputSchema.optional(),
}

type ClaimEntryForValidation = {
  claim_id?: string
  category: z.infer<typeof AnalysisClaimCategorySchema>
  status: z.infer<typeof AnalysisClaimStatusSchema>
  supporting_evidence: z.infer<typeof AnalysisClaimEvidenceInputSchema>[]
  counter_evidence: z.infer<typeof AnalysisClaimEvidenceInputSchema>[]
  review?: z.infer<typeof AnalysisClaimReviewInputSchema> | null
}

function evidenceRefKey(reference: z.infer<typeof AnalysisClaimEvidenceInputSchema>): string {
  return JSON.stringify([
    reference.artifact_id,
    reference.json_pointer ?? null,
    reference.locator ?? null,
  ])
}

function evidenceAnchorId(reference: AnalysisClaimEvidence): string {
  return `evidence:${createHash('sha256').update(evidenceRefKey(reference)).digest('hex').slice(0, 24)}`
}

function validateClaimEntry(value: ClaimEntryForValidation, ctx: z.RefinementCtx): void {
  const supportingKeys = value.supporting_evidence.map(evidenceRefKey)
  const counterKeys = value.counter_evidence.map(evidenceRefKey)

  if (new Set(supportingKeys).size !== supportingKeys.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['supporting_evidence'],
      message: 'supporting_evidence contains duplicate artifact references.',
    })
  }
  if (new Set(counterKeys).size !== counterKeys.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['counter_evidence'],
      message: 'counter_evidence contains duplicate artifact references.',
    })
  }

  const supportingSet = new Set(supportingKeys)
  if (counterKeys.some((key) => supportingSet.has(key))) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['counter_evidence'],
      message: 'The same evidence reference cannot support and counter the same claim.',
    })
  }

  if (
    ['finding', 'ioc', 'technique', 'verdict'].includes(value.category) &&
    value.supporting_evidence.length === 0 &&
    value.status !== 'rejected'
  ) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['supporting_evidence'],
      message: `${value.category} claims require at least one supporting evidence reference.`,
    })
  }

  if (value.status === 'corroborated' && value.supporting_evidence.length === 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['supporting_evidence'],
      message: 'corroborated claims require supporting evidence.',
    })
  }
  if (value.status === 'contradicted' && value.counter_evidence.length === 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['counter_evidence'],
      message: 'contradicted claims require counter evidence.',
    })
  }
  if (value.status === 'verified' && value.supporting_evidence.length === 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['supporting_evidence'],
      message: 'verified claims require supporting evidence.',
    })
  }

  if (value.status === 'inferred' && value.review) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['review'],
      message: 'inferred claims cannot carry a review decision.',
    })
  }
  if (value.status !== 'inferred' && value.review?.decision !== value.status) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['review'],
      message: `${value.status} claims require a matching review decision.`,
    })
  }
}

export const AnalysisClaimDraftSchema = z
  .object({
    claim_id: AnalysisClaimIdSchema.optional(),
    ...claimEntryFields,
  })
  .strict()
  .superRefine(validateClaimEntry)

export const AnalysisClaimSchema = z
  .object({
    claim_id: AnalysisClaimIdSchema,
    source: AnalysisClaimSourceSchema,
    category: AnalysisClaimCategorySchema,
    subject: z.string().min(1).max(500),
    statement: z.string().min(1).max(5000),
    status: AnalysisClaimStatusSchema,
    supporting_evidence: z.array(AnalysisClaimEvidenceSchema).max(64),
    counter_evidence: z.array(AnalysisClaimEvidenceSchema).max(64),
    assumptions: z.array(z.string().min(1).max(1000)).max(32),
    alternatives: z.array(z.string().min(1).max(1000)).max(32),
    falsification_tests: z.array(z.string().min(1).max(1200)).max(32),
    review: AnalysisClaimReviewSchema.nullable(),
  })
  .strict()
  .superRefine(validateClaimEntry)

export const AnalysisClaimProducerSchema = z
  .object({
    kind: AnalysisClaimSourceSchema,
    client_name: z.string().min(1).max(200).nullable(),
    model_name: z.string().min(1).max(200).nullable(),
  })
  .strict()

export const AnalysisClaimValidationResultSchema = z
  .object({
    claim_id: AnalysisClaimIdSchema,
    validation_type: z.literal('evidence_reference_integrity'),
    status: z.enum(['passed', 'not_applicable']),
    validator: z.enum(['analysis.claims.apply', 'analysis.claims.review']),
    validated_at: IsoTimestampSchema,
    supporting_evidence_count: z.number().int().nonnegative(),
    counter_evidence_count: z.number().int().nonnegative(),
    checks: z.array(
      z.enum([
        'artifact_exists',
        'sample_matches',
        'artifact_type_allowed',
        'artifact_readable',
        'artifact_sha256_matches',
        'json_pointer_resolves',
      ])
    ),
    note: z.string().min(1),
  })
  .strict()

type EvidenceIntegrityCheck = z.infer<typeof AnalysisClaimValidationResultSchema>['checks'][number]

export const AnalysisClaimValidationSummarySchema = z
  .object({
    status: z.literal('passed'),
    claim_count: z.number().int().positive(),
    evidence_reference_count: z.number().int().nonnegative(),
    json_pointer_count: z.number().int().nonnegative(),
  })
  .strict()

export const AnalysisClaimSetArtifactSchema = z
  .object({
    schema: z.literal(ANALYSIS_CLAIM_SET_SCHEMA),
    schema_version: z.literal(1),
    sample_id: z.string().min(1),
    ledger_revision: z.number().int().positive(),
    parent_artifact_id: z.string().min(1).max(200).nullable(),
    created_at: IsoTimestampSchema,
    session_tag: z.string().min(1).max(200).nullable(),
    goal: z.string().min(1).max(1000).nullable(),
    producer: AnalysisClaimProducerSchema,
    claims: z.array(AnalysisClaimSchema).min(1).max(100),
    validation_results: z.array(AnalysisClaimValidationResultSchema),
    validation_summary: AnalysisClaimValidationSummarySchema,
  })
  .strict()
  .superRefine((value, ctx) => {
    const claimIds = value.claims.map((claim) => claim.claim_id)
    if (new Set(claimIds).size !== claimIds.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['claims'],
        message: 'claims contains duplicate claim_id values.',
      })
    }

    const validationIds = value.validation_results.map((result) => result.claim_id)
    if (
      new Set(validationIds).size !== validationIds.length ||
      validationIds.length !== claimIds.length ||
      validationIds.some((claimId) => !claimIds.includes(claimId))
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['validation_results'],
        message: 'validation_results must contain exactly one entry for every claim.',
      })
    }

    const validationByClaimId = new Map(
      value.validation_results.map((result) => [result.claim_id, result])
    )
    for (const [index, claim] of value.claims.entries()) {
      if (claim.source !== value.producer.kind) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['claims', index, 'source'],
          message: 'claim source must match producer.kind.',
        })
      }
      if (value.producer.kind !== 'analyst' && claim.status !== 'inferred') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['claims', index, 'status'],
          message: 'LLM/imported producers may only persist inferred claims.',
        })
      }
      if (value.producer.kind !== 'analyst' && claim.review !== null) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['claims', index, 'review'],
          message: 'LLM/imported producers cannot persist review provenance.',
        })
      }
      if (claim.review && Date.parse(claim.review.reviewed_at) > Date.parse(value.created_at)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['claims', index, 'review', 'reviewed_at'],
          message: 'reviewed_at cannot be later than claim-set created_at.',
        })
      }

      const result = validationByClaimId.get(claim.claim_id)
      if (!result) {
        continue
      }
      const expectedValidator =
        value.producer.kind === 'analyst' ? 'analysis.claims.review' : 'analysis.claims.apply'
      if (result.validator !== expectedValidator) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['validation_results'],
          message: `producer.kind=${value.producer.kind} requires validator=${expectedValidator}.`,
        })
      }
      const supportingCount = claim.supporting_evidence.length
      const counterCount = claim.counter_evidence.length
      const evidenceCount = supportingCount + counterCount
      const jsonPointerCount = [...claim.supporting_evidence, ...claim.counter_evidence].filter(
        (reference) => reference.json_pointer !== undefined
      ).length
      if (Date.parse(result.validated_at) > Date.parse(value.created_at)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['validation_results'],
          message: 'validated_at cannot be later than claim-set created_at.',
        })
      }
      if (
        result.supporting_evidence_count !== supportingCount ||
        result.counter_evidence_count !== counterCount ||
        result.status !== (evidenceCount > 0 ? 'passed' : 'not_applicable')
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['validation_results'],
          message: 'validation result counts/status do not match the canonical claim evidence.',
        })
      }
      const requiredChecks: EvidenceIntegrityCheck[] = []
      if (evidenceCount > 0) {
        requiredChecks.push(
          'artifact_exists',
          'sample_matches',
          'artifact_type_allowed',
          'artifact_readable',
          'artifact_sha256_matches'
        )
      }
      if (jsonPointerCount > 0) {
        requiredChecks.push('json_pointer_resolves')
      }
      if (
        result.checks.length !== requiredChecks.length ||
        requiredChecks.some((check) => !result.checks.includes(check))
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['validation_results'],
          message: 'validation result checks do not match the performed evidence checks.',
        })
      }
    }

    const allEvidence = value.claims.flatMap((claim) => [
      ...claim.supporting_evidence,
      ...claim.counter_evidence,
    ])
    if (allEvidence.length > MAX_ANALYSIS_CLAIM_EVIDENCE_REFERENCES) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['claims'],
        message: `claim set may reference at most ${MAX_ANALYSIS_CLAIM_EVIDENCE_REFERENCES} evidence entries.`,
      })
    }
    if (
      value.validation_summary.claim_count !== value.claims.length ||
      value.validation_summary.evidence_reference_count !== allEvidence.length ||
      value.validation_summary.json_pointer_count !==
        allEvidence.filter((reference) => reference.json_pointer !== undefined).length
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['validation_summary'],
        message: 'validation_summary does not match the claim-set contents.',
      })
    }
    if (
      (value.ledger_revision === 1 && value.parent_artifact_id !== null) ||
      (value.ledger_revision > 1 && value.parent_artifact_id === null)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['parent_artifact_id'],
        message: 'ledger revision 1 has no parent; later revisions require a parent artifact.',
      })
    }
  })

export type AnalysisClaimDraft = z.infer<typeof AnalysisClaimDraftSchema>
export type AnalysisClaim = z.infer<typeof AnalysisClaimSchema>
export type AnalysisClaimEvidenceInput = z.infer<typeof AnalysisClaimEvidenceInputSchema>
export type AnalysisClaimEvidence = z.infer<typeof AnalysisClaimEvidenceSchema>
export type AnalysisClaimSetArtifact = z.infer<typeof AnalysisClaimSetArtifactSchema>
export type AnalysisClaimProducer = z.infer<typeof AnalysisClaimProducerSchema>
export type AnalysisClaimValidationResult = z.infer<typeof AnalysisClaimValidationResultSchema>
export type AnalysisClaimScope = 'all' | 'latest' | 'session'

export interface ClaimSetArtifactRef extends ArtifactRef {
  created_at: string
}

export interface LoadedAnalysisClaimSet {
  artifact: ClaimSetArtifactRef
  payload: AnalysisClaimSetArtifact
  session_tags: string[]
}

export interface LoadedAnalysisClaim {
  claim: AnalysisClaim
  claim_set_artifact_id: string
  ledger_revision: number
  created_at: string
  producer: AnalysisClaimProducer
}

export interface AnalysisClaimLedgerIndex {
  byClaimId: Map<string, LoadedAnalysisClaim>
  claim_sets: LoadedAnalysisClaimSet[]
  artifact_ids: string[]
  session_tags: string[]
  earliest_created_at: string | null
  latest_created_at: string | null
  marker: string
  scope_note: string
  total_artifact_count: number
  truncated: boolean
  warnings: string[]
  integrity_issues: AnalysisClaimLedgerIntegrityIssue[]
  active_claim_resolution: AnalysisClaimActiveResolution | null
}

export type AnalysisClaimLedgerIntegrityKind =
  | 'scan_truncated'
  | 'path_outside_workspace'
  | 'invalid_size'
  | 'byte_limit'
  | 'sha256_mismatch'
  | 'invalid_payload'
  | 'unreadable'
  | 'head_revision_mismatch'
  | 'chain_discontinuity'
  | 'duplicate_revision'
  | 'missing_predecessor'
  | 'parent_mismatch'
  | 'scan_limit'
  | 'missing_active_claims'

export interface AnalysisClaimLedgerIntegrityIssue {
  kind: AnalysisClaimLedgerIntegrityKind
  reason: string
  artifact_id: string | null
  artifact_sha256: string | null
  related_artifact_id: string | null
  related_artifact_sha256: string | null
  expected_ledger_revision: number | null
  observed_ledger_revision: number | null
  total_artifact_count: number
}

type AnalysisClaimLedgerIntegrityIssueInput = Pick<
  AnalysisClaimLedgerIntegrityIssue,
  'kind' | 'reason'
> &
  Partial<Omit<AnalysisClaimLedgerIntegrityIssue, 'kind' | 'reason' | 'total_artifact_count'>>

function sortAnalysisClaimLedgerIntegrityIssues(
  issues: AnalysisClaimLedgerIntegrityIssue[]
): AnalysisClaimLedgerIntegrityIssue[] {
  return [...issues].sort((left, right) =>
    JSON.stringify(left).localeCompare(JSON.stringify(right))
  )
}

export type AnalysisClaimActiveResolutionStatus =
  | 'complete'
  | 'scan_limit'
  | 'byte_limit'
  | 'integrity_error'
  | 'missing'

export interface AnalysisClaimActiveResolution {
  status: AnalysisClaimActiveResolutionStatus
  requested_claim_ids: string[]
  unresolved_claim_ids: string[]
  scanned_artifact_count: number
  scanned_bytes: number
}

export interface LoadAnalysisClaimLedgerOptions {
  scope?: AnalysisClaimScope
  sessionTag?: string
  maxArtifacts?: number
  activeClaimIds?: readonly string[]
  maxScanArtifacts?: number
  maxScanBytes?: number
}

interface EvidenceArtifactContext {
  artifact: {
    id: string
    sample_id: string
    type: string
    path: string
    sha256: string
  }
  absolutePath: string
  size: number
  parsedJson?: unknown
  jsonState: 'unparsed' | 'parsed' | 'failed'
  jsonError?: string
}

interface EvidenceValidationCacheEntry {
  context?: EvidenceArtifactContext
  error?: string
}

interface EvidenceValidationBudget {
  jsonBytes: number
  hashBytes: number
  artifactCount: number
}

async function sha256File(filePath: string): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(filePath)
    stream.on('error', reject)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

function pathIsWithin(rootPath: string, candidatePath: string): boolean {
  return candidatePath === rootPath || candidatePath.startsWith(rootPath + path.sep)
}

function decodeJsonPointerToken(value: string): string {
  return value.replace(/~1/g, '/').replace(/~0/g, '~')
}

function jsonPointerResolves(document: unknown, pointer: string): boolean {
  if (pointer === '') {
    return true
  }

  let current = document
  for (const rawToken of pointer.slice(1).split('/')) {
    const token = decodeJsonPointerToken(rawToken)
    if (Array.isArray(current)) {
      if (!/^(0|[1-9][0-9]*)$/.test(token)) {
        return false
      }
      const index = Number(token)
      if (index >= current.length) {
        return false
      }
      current = current[index]
      continue
    }
    if (!current || typeof current !== 'object') {
      return false
    }
    if (!Object.prototype.hasOwnProperty.call(current, token)) {
      return false
    }
    current = (current as Record<string, unknown>)[token]
  }
  return true
}

async function loadEvidenceArtifactContext(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  artifactId: string,
  cache: Map<string, EvidenceValidationCacheEntry>,
  budget: EvidenceValidationBudget
): Promise<EvidenceValidationCacheEntry> {
  const cached = cache.get(artifactId)
  if (cached) {
    return cached
  }

  const artifact = database.findArtifact(artifactId)
  if (!artifact) {
    const result = { error: `Evidence artifact not found: ${artifactId}` }
    cache.set(artifactId, result)
    return result
  }
  if (artifact.sample_id !== sampleId) {
    const result = { error: `Evidence artifact does not belong to sample: ${artifactId}` }
    cache.set(artifactId, result)
    return result
  }
  if (artifact.type === ANALYSIS_CLAIM_SET_ARTIFACT_TYPE) {
    const result = { error: `Claim-set artifacts cannot be used as evidence: ${artifactId}` }
    cache.set(artifactId, result)
    return result
  }
  if (artifact.type === ANALYSIS_CASE_STATE_ARTIFACT_TYPE) {
    const result = {
      error: `Case-state artifacts are context-only and cannot be used as claim evidence: ${artifactId}`,
    }
    cache.set(artifactId, result)
    return result
  }
  if (isContextOnlyArtifactType(artifact.type)) {
    const result = {
      error: `Context-only artifact type cannot be used as claim evidence: ${artifact.type} (${artifactId})`,
    }
    cache.set(artifactId, result)
    return result
  }

  try {
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
    const [workspaceRealPath, artifactRealPath] = await Promise.all([
      fs.realpath(workspace.root),
      fs.realpath(absolutePath),
    ])
    if (!pathIsWithin(workspaceRealPath, artifactRealPath)) {
      const result = { error: `Evidence artifact resolves outside the workspace: ${artifactId}` }
      cache.set(artifactId, result)
      return result
    }
    const stat = await fs.stat(artifactRealPath)
    if (!stat.isFile()) {
      const result = { error: `Evidence artifact is not a regular file: ${artifactId}` }
      cache.set(artifactId, result)
      return result
    }
    if (budget.artifactCount + 1 > MAX_EVIDENCE_ARTIFACTS_PER_BATCH) {
      const result = { error: `Evidence batch exceeds the artifact-count limit at: ${artifactId}` }
      cache.set(artifactId, result)
      return result
    }
    if (budget.hashBytes + stat.size > MAX_EVIDENCE_HASH_BATCH_BYTES) {
      const result = { error: `Evidence batch exceeds the SHA-256 scan budget at: ${artifactId}` }
      cache.set(artifactId, result)
      return result
    }
    budget.artifactCount += 1
    budget.hashBytes += stat.size
    const actualSha256 = await sha256File(artifactRealPath)
    if (actualSha256.toLowerCase() !== artifact.sha256.toLowerCase()) {
      const result = { error: `Evidence artifact SHA-256 mismatch: ${artifactId}` }
      cache.set(artifactId, result)
      return result
    }

    const result: EvidenceValidationCacheEntry = {
      context: {
        artifact,
        absolutePath: artifactRealPath,
        size: stat.size,
        jsonState: 'unparsed',
      },
    }
    cache.set(artifactId, result)
    return result
  } catch {
    const result = { error: `Evidence artifact is not readable: ${artifactId}` }
    cache.set(artifactId, result)
    return result
  }
}

async function validateEvidenceReference(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  reference: AnalysisClaimEvidenceInput,
  cache: Map<string, EvidenceValidationCacheEntry>,
  budget: EvidenceValidationBudget,
  expected?: AnalysisClaimEvidence
): Promise<{ evidence?: AnalysisClaimEvidence; error?: string }> {
  const loaded = await loadEvidenceArtifactContext(
    workspaceManager,
    database,
    sampleId,
    reference.artifact_id,
    cache,
    budget
  )
  if (!loaded.context) {
    return { error: loaded.error || `Evidence artifact is unavailable: ${reference.artifact_id}` }
  }

  const { artifact } = loaded.context
  if (
    expected &&
    (expected.artifact_type !== artifact.type ||
      expected.artifact_path !== artifact.path ||
      expected.artifact_sha256.toLowerCase() !== artifact.sha256.toLowerCase())
  ) {
    return { error: `Evidence artifact metadata changed: ${reference.artifact_id}` }
  }

  if (reference.json_pointer !== undefined) {
    if (loaded.context.jsonState === 'failed') {
      return {
        error:
          loaded.context.jsonError ||
          `Evidence artifact is not valid JSON: ${reference.artifact_id}`,
      }
    }
    if (loaded.context.jsonState === 'unparsed') {
      if (loaded.context.size > MAX_JSON_EVIDENCE_BYTES) {
        loaded.context.jsonState = 'failed'
        loaded.context.jsonError = `Evidence artifact exceeds the JSON-pointer size limit: ${reference.artifact_id}`
        return { error: loaded.context.jsonError }
      }
      if (budget.jsonBytes + loaded.context.size > MAX_JSON_EVIDENCE_BATCH_BYTES) {
        loaded.context.jsonState = 'failed'
        loaded.context.jsonError = `Evidence batch exceeds the JSON-pointer parsing budget at: ${reference.artifact_id}`
        return { error: loaded.context.jsonError }
      }
      try {
        const content = await fs.readFile(loaded.context.absolutePath)
        const actualSha256 = createHash('sha256').update(content).digest('hex')
        if (actualSha256.toLowerCase() !== loaded.context.artifact.sha256.toLowerCase()) {
          loaded.context.jsonState = 'failed'
          loaded.context.jsonError = `Evidence artifact SHA-256 mismatch: ${reference.artifact_id}`
          return { error: loaded.context.jsonError }
        }
        budget.jsonBytes += content.byteLength
        loaded.context.parsedJson = JSON.parse(content.toString('utf8')) as unknown
        loaded.context.jsonState = 'parsed'
      } catch {
        loaded.context.jsonState = 'failed'
        loaded.context.jsonError = `Evidence artifact is not valid JSON: ${reference.artifact_id}`
        return { error: loaded.context.jsonError }
      }
    }
    if (!jsonPointerResolves(loaded.context.parsedJson, reference.json_pointer)) {
      return {
        error: `Evidence JSON pointer does not resolve for ${reference.artifact_id}: ${reference.json_pointer}`,
      }
    }
  }

  return {
    evidence: {
      artifact_id: artifact.id,
      artifact_type: artifact.type,
      artifact_path: artifact.path,
      artifact_sha256: artifact.sha256,
      ...(reference.json_pointer !== undefined ? { json_pointer: reference.json_pointer } : {}),
      ...(reference.locator ? { locator: reference.locator } : {}),
      ...(reference.summary ? { summary: reference.summary } : {}),
    },
  }
}

export async function validateAndCanonicalizeAnalysisClaims(args: {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  sampleId: string
  source: z.infer<typeof AnalysisClaimSourceSchema>
  drafts: Array<AnalysisClaimDraft & { claim_id: string }>
  reviewedAt?: string
}): Promise<{
  claims: AnalysisClaim[]
  validation_results: AnalysisClaimValidationResult[]
  errors: string[]
}> {
  const cache = new Map<string, EvidenceValidationCacheEntry>()
  const budget: EvidenceValidationBudget = { jsonBytes: 0, hashBytes: 0, artifactCount: 0 }
  const errors: string[] = []
  const claims: AnalysisClaim[] = []
  const validationResults: AnalysisClaimValidationResult[] = []
  const reviewedAt = args.reviewedAt || new Date().toISOString()
  const validator = args.source === 'analyst' ? 'analysis.claims.review' : 'analysis.claims.apply'

  for (const draft of args.drafts) {
    if (args.source !== 'analyst' && draft.status !== 'inferred') {
      errors.push(`${draft.claim_id}: only analyst-produced claims may use status=${draft.status}.`)
      continue
    }
    if (args.source !== 'analyst' && draft.review) {
      errors.push(`${draft.claim_id}: only analyst-produced claims may include review provenance.`)
      continue
    }

    const supportingEvidence: AnalysisClaimEvidence[] = []
    const counterEvidence: AnalysisClaimEvidence[] = []
    const errorCountBeforeEvidenceValidation = errors.length
    for (const reference of draft.supporting_evidence) {
      const result = await validateEvidenceReference(
        args.workspaceManager,
        args.database,
        args.sampleId,
        reference,
        cache,
        budget
      )
      if (result.evidence) {
        supportingEvidence.push(result.evidence)
      } else {
        errors.push(`${draft.claim_id}: ${result.error}`)
      }
    }
    for (const reference of draft.counter_evidence) {
      const result = await validateEvidenceReference(
        args.workspaceManager,
        args.database,
        args.sampleId,
        reference,
        cache,
        budget
      )
      if (result.evidence) {
        counterEvidence.push(result.evidence)
      } else {
        errors.push(`${draft.claim_id}: ${result.error}`)
      }
    }

    if (errors.length > errorCountBeforeEvidenceValidation) {
      continue
    }

    const validationCount = supportingEvidence.length + counterEvidence.length
    claims.push({
      claim_id: draft.claim_id,
      source: args.source,
      category: draft.category,
      subject: draft.subject,
      statement: draft.statement,
      status: draft.status,
      supporting_evidence: supportingEvidence,
      counter_evidence: counterEvidence,
      assumptions: draft.assumptions,
      alternatives: draft.alternatives,
      falsification_tests: draft.falsification_tests,
      review: draft.review
        ? {
            ...draft.review,
            reviewed_at: reviewedAt,
          }
        : null,
    })
    validationResults.push({
      claim_id: draft.claim_id,
      validation_type: 'evidence_reference_integrity',
      status: validationCount > 0 ? 'passed' : 'not_applicable',
      validator,
      validated_at: reviewedAt,
      supporting_evidence_count: supportingEvidence.length,
      counter_evidence_count: counterEvidence.length,
      checks:
        validationCount > 0
          ? [
              'artifact_exists',
              'sample_matches',
              'artifact_type_allowed',
              'artifact_readable',
              'artifact_sha256_matches',
              ...(draft.supporting_evidence
                .concat(draft.counter_evidence)
                .some((reference) => reference.json_pointer !== undefined)
                ? (['json_pointer_resolves'] as const)
                : []),
            ]
          : [],
      note:
        validationCount > 0
          ? 'Artifact identity, ownership, file integrity, and requested JSON pointers were validated. Semantic truth was not validated.'
          : 'No artifact evidence references were supplied; semantic truth was not validated.',
    })
  }

  return {
    claims,
    validation_results: validationResults,
    errors,
  }
}

const claimLedgerWriteLocks = new Map<string, Promise<void>>()

const ClaimLedgerLockRecordSchema = z
  .object({
    version: z.literal(1),
    owner_token: z
      .string()
      .max(100)
      .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i, {
        message: 'owner_token must be a UUID.',
      }),
    pid: z.number().int().positive(),
    host_id: z.string().min(1).max(255),
    sample_id: z.string().min(1).max(500),
    acquired_at: IsoTimestampSchema,
  })
  .strict()

type ClaimLedgerLockRecord = z.infer<typeof ClaimLedgerLockRecordSchema>

interface ClaimLedgerLockFileIdentity {
  dev: number
  ino: number
  size: number
  mtimeMs: number
}

interface ClaimLedgerLockSnapshot {
  record: ClaimLedgerLockRecord
  identity: ClaimLedgerLockFileIdentity
}

interface InspectedClaimLedgerLock {
  record: ClaimLedgerLockRecord | null
  identity: ClaimLedgerLockFileIdentity
}

interface OwnedClaimLedgerLock extends ClaimLedgerLockSnapshot {
  handle: Awaited<ReturnType<typeof fs.open>>
}

function claimLockFileIdentity(stat: {
  dev: number
  ino: number
  size: number
  mtimeMs: number
}): ClaimLedgerLockFileIdentity {
  return { dev: stat.dev, ino: stat.ino, size: stat.size, mtimeMs: stat.mtimeMs }
}

function sameClaimLockFile(
  left: ClaimLedgerLockFileIdentity,
  right: ClaimLedgerLockFileIdentity,
  includeMetadata = true
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    (!includeMetadata || (left.size === right.size && left.mtimeMs === right.mtimeMs))
  )
}

async function inspectClaimLedgerLock(lockPath: string): Promise<InspectedClaimLedgerLock | null> {
  let pathStat: Awaited<ReturnType<typeof fs.lstat>>
  try {
    pathStat = await fs.lstat(lockPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error('Claim Ledger lock path is not a regular non-symlink file.')
  }

  const handle = await fs.open(lockPath, 'r')
  try {
    const handleStat = await handle.stat()
    const initialIdentity = claimLockFileIdentity(pathStat)
    const handleIdentity = claimLockFileIdentity(handleStat)
    if (!handleStat.isFile() || !sameClaimLockFile(initialIdentity, handleIdentity, false)) {
      throw new Error('Claim Ledger lock changed while it was being inspected.')
    }
    let record: ClaimLedgerLockRecord | null = null
    if (handleStat.size > 0 && handleStat.size <= MAX_CLAIM_LEDGER_LOCK_BYTES) {
      try {
        const content = await handle.readFile('utf8')
        const parsed = ClaimLedgerLockRecordSchema.safeParse(JSON.parse(content) as unknown)
        record = parsed.success ? parsed.data : null
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error
      }
    }
    let finalPathStat: Awaited<ReturnType<typeof fs.lstat>>
    try {
      finalPathStat = await fs.lstat(lockPath)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw error
    }
    const finalIdentity = claimLockFileIdentity(finalPathStat)
    if (
      finalPathStat.isSymbolicLink() ||
      !finalPathStat.isFile() ||
      !sameClaimLockFile(handleIdentity, finalIdentity)
    ) {
      throw new Error('Claim Ledger lock changed while it was being inspected.')
    }
    return { record, identity: finalIdentity }
  } finally {
    await handle.close().catch(() => undefined)
  }
}

async function readClaimLedgerLock(lockPath: string): Promise<ClaimLedgerLockSnapshot | null> {
  const inspected = await inspectClaimLedgerLock(lockPath)
  if (!inspected) return null
  if (!inspected.record) {
    throw new Error('Claim Ledger lock metadata is malformed.')
  }
  return { record: inspected.record, identity: inspected.identity }
}

function claimLockProcessIsDefinitelyDead(pid: number): boolean {
  if (pid === process.pid) return false
  try {
    process.kill(pid, 0)
    return false
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ESRCH'
  }
}

async function restoreMovedClaimLedgerLock(movedPath: string, lockPath: string): Promise<void> {
  try {
    await fs.link(movedPath, lockPath)
    await fs.unlink(movedPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
}

async function recoverStaleClaimLedgerLock(lockPath: string, sampleId: string): Promise<boolean> {
  const snapshot = await inspectClaimLedgerLock(lockPath)
  if (!snapshot) return true
  const now = Date.now()
  const fileIsStale = now - snapshot.identity.mtimeMs >= ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS

  if (!snapshot.record) {
    if (!fileIsStale) return false
    const confirmation = await inspectClaimLedgerLock(lockPath)
    if (
      !confirmation ||
      confirmation.record !== null ||
      !sameClaimLockFile(confirmation.identity, snapshot.identity)
    ) {
      return false
    }
    const movedPath = `${lockPath}.stale-${randomUUID()}`
    try {
      await fs.rename(lockPath, movedPath)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true
      throw error
    }
    try {
      const moved = await inspectClaimLedgerLock(movedPath)
      if (
        !moved ||
        moved.record !== null ||
        !sameClaimLockFile(moved.identity, snapshot.identity)
      ) {
        await restoreMovedClaimLedgerLock(movedPath, lockPath)
        return false
      }
      await fs.unlink(movedPath)
      return true
    } catch (error) {
      await restoreMovedClaimLedgerLock(movedPath, lockPath).catch(() => undefined)
      throw error
    }
  }

  if (snapshot.record.sample_id !== sampleId) {
    throw new Error('Claim Ledger lock ownership does not match the requested sample.')
  }
  const acquiredAt = Date.parse(snapshot.record.acquired_at)
  const metadataIsStale = now - acquiredAt >= ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS
  const ownerIsLocal = snapshot.record.host_id === hostname()
  if (
    !metadataIsStale ||
    !fileIsStale ||
    (ownerIsLocal && !claimLockProcessIsDefinitelyDead(snapshot.record.pid))
  ) {
    return false
  }

  const confirmation = await inspectClaimLedgerLock(lockPath)
  if (!confirmation) return true
  if (
    !confirmation.record ||
    confirmation.record.owner_token !== snapshot.record.owner_token ||
    confirmation.record.sample_id !== sampleId ||
    !sameClaimLockFile(confirmation.identity, snapshot.identity)
  ) {
    return false
  }
  const movedPath = `${lockPath}.stale-${randomUUID()}`
  try {
    await fs.rename(lockPath, movedPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true
    throw error
  }
  try {
    const moved = await inspectClaimLedgerLock(movedPath)
    if (
      !moved ||
      !moved.record ||
      moved.record.owner_token !== snapshot.record.owner_token ||
      moved.record.sample_id !== sampleId ||
      !sameClaimLockFile(moved.identity, snapshot.identity)
    ) {
      await restoreMovedClaimLedgerLock(movedPath, lockPath)
      return false
    }
    await fs.unlink(movedPath)
    return true
  } catch (error) {
    await restoreMovedClaimLedgerLock(movedPath, lockPath).catch(() => undefined)
    throw error
  }
}

async function removeClaimLedgerLockWithIdentity(
  lockPath: string,
  identity: ClaimLedgerLockFileIdentity
): Promise<void> {
  const movedPath = `${lockPath}.cleanup-${randomUUID()}`
  try {
    await fs.rename(lockPath, movedPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  try {
    const moved = claimLockFileIdentity(await fs.lstat(movedPath))
    if (!sameClaimLockFile(moved, identity, false)) {
      await restoreMovedClaimLedgerLock(movedPath, lockPath)
      return
    }
    await fs.unlink(movedPath)
  } catch (error) {
    await restoreMovedClaimLedgerLock(movedPath, lockPath).catch(() => undefined)
    throw error
  }
}

async function acquireClaimLedgerLock(
  lockPath: string,
  sampleId: string
): Promise<OwnedClaimLedgerLock> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let handle: Awaited<ReturnType<typeof fs.open>> | undefined
    try {
      handle = await fs.open(lockPath, 'wx')
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      const recovered = attempt === 0 && (await recoverStaleClaimLedgerLock(lockPath, sampleId))
      if (recovered) continue
      throw new Error(
        'Claim Ledger is locked by another live or recently-active process; retry after the active writer completes.',
        { cause: error }
      )
    }

    const record: ClaimLedgerLockRecord = {
      version: 1,
      owner_token: randomUUID(),
      pid: process.pid,
      host_id: hostname(),
      sample_id: sampleId,
      acquired_at: new Date().toISOString(),
    }
    try {
      await handle.writeFile(JSON.stringify(record), 'utf8')
      await handle.sync()
      const identity = claimLockFileIdentity(await handle.stat())
      return { handle, record, identity }
    } catch (error) {
      const identity = await handle
        .stat()
        .then(claimLockFileIdentity)
        .catch(() => null)
      await handle.close().catch(() => undefined)
      if (identity) {
        await removeClaimLedgerLockWithIdentity(lockPath, identity).catch(() => undefined)
      }
      throw error
    }
  }
  throw new Error('Claim Ledger lock could not be acquired.')
}

async function releaseClaimLedgerLock(
  lockPath: string,
  owned: OwnedClaimLedgerLock
): Promise<void> {
  await owned.handle.close().catch(() => undefined)
  const movedPath = `${lockPath}.release-${owned.record.owner_token}`
  try {
    await fs.rename(lockPath, movedPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    return
  }
  try {
    const current = await readClaimLedgerLock(movedPath)
    if (
      current &&
      current.record.owner_token === owned.record.owner_token &&
      current.record.sample_id === owned.record.sample_id &&
      sameClaimLockFile(current.identity, owned.identity, false)
    ) {
      await fs.unlink(movedPath)
      return
    }
    await restoreMovedClaimLedgerLock(movedPath, lockPath)
  } catch {
    // Fail closed: preserve an unverified or replaced lock under its quarantine path.
  }
}

async function withClaimLedgerWriteLock<T>(
  sampleId: string,
  workspaceRoot: string,
  database: DatabaseManager,
  operation: (lease: ContextWriteLeaseGuard) => Promise<T>
): Promise<T> {
  const previous = claimLedgerWriteLocks.get(sampleId) || Promise.resolve()
  let release: () => void = () => undefined
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const queued = previous.then(() => gate)
  claimLedgerWriteLocks.set(sampleId, queued)
  await previous

  try {
    return await withContextWriteLease({
      database,
      lockKey: analysisClaimLedgerWriteLeaseKey(sampleId),
      staleMs: ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS,
      label: 'Claim Ledger',
      operation: async (lease) => {
        const lockPath = path.join(workspaceRoot, '.analysis-claim-ledger.lock')
        let ownedLock: OwnedClaimLedgerLock | undefined
        try {
          ownedLock = await acquireClaimLedgerLock(lockPath, sampleId)
          return await operation(lease)
        } finally {
          if (ownedLock) await releaseClaimLedgerLock(lockPath, ownedLock)
        }
      },
    })
  } finally {
    release()
    if (claimLedgerWriteLocks.get(sampleId) === queued) {
      claimLedgerWriteLocks.delete(sampleId)
    }
  }
}

async function validateCanonicalClaimSetEvidence(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  payload: AnalysisClaimSetArtifact
): Promise<string[]> {
  const cache = new Map<string, EvidenceValidationCacheEntry>()
  const budget: EvidenceValidationBudget = { jsonBytes: 0, hashBytes: 0, artifactCount: 0 }
  const errors: string[] = []

  for (const claim of payload.claims) {
    for (const reference of [...claim.supporting_evidence, ...claim.counter_evidence]) {
      const result = await validateEvidenceReference(
        workspaceManager,
        database,
        payload.sample_id,
        reference,
        cache,
        budget,
        reference
      )
      if (!result.evidence) {
        errors.push(`${claim.claim_id}: ${result.error}`)
      }
    }
  }

  return errors
}

async function ensureDirectoryIsNotSymlink(directoryPath: string, label: string): Promise<void> {
  try {
    await fs.mkdir(directoryPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
      throw error
    }
  }
  const stat = await fs.lstat(directoryPath)
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory, not a symlink.`)
  }
}

async function ensureSafeClaimReportDirectory(
  workspace: { root: string; reports: string },
  sessionSegment: string
): Promise<{ workspaceRealPath: string; reportDirRealPath: string }> {
  const workspaceRealPath = await fs.realpath(workspace.root)
  const reportsStat = await fs.lstat(workspace.reports)
  if (!reportsStat.isDirectory() || reportsStat.isSymbolicLink()) {
    throw new Error('Workspace reports directory must be a real directory, not a symlink.')
  }
  const reportsRealPath = await fs.realpath(workspace.reports)
  if (!pathIsWithin(workspaceRealPath, reportsRealPath)) {
    throw new Error('Workspace reports directory resolves outside the workspace.')
  }

  const claimsRoot = path.join(reportsRealPath, 'claims')
  await ensureDirectoryIsNotSymlink(claimsRoot, 'Claim Ledger root directory')
  const claimsRootRealPath = await fs.realpath(claimsRoot)
  if (!pathIsWithin(workspaceRealPath, claimsRootRealPath)) {
    throw new Error('Claim Ledger root directory resolves outside the workspace.')
  }

  const reportDir = path.join(claimsRootRealPath, sessionSegment)
  await ensureDirectoryIsNotSymlink(reportDir, 'Claim Ledger session directory')
  const reportDirRealPath = await fs.realpath(reportDir)
  if (!pathIsWithin(workspaceRealPath, reportDirRealPath)) {
    throw new Error('Claim Ledger report directory resolves outside the workspace.')
  }

  return { workspaceRealPath, reportDirRealPath }
}

export async function persistAnalysisClaimSetArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  payload: AnalysisClaimSetArtifact
): Promise<ArtifactRef> {
  const validatedPayload = AnalysisClaimSetArtifactSchema.parse(payload)
  if (validatedPayload.producer.kind === 'analyst') {
    throw new Error(
      'Analyst claim revisions are fail-closed until a signed operator boundary is configured; this writer cannot persist producer=analyst.'
    )
  }
  const workspace = await workspaceManager.createWorkspace(validatedPayload.sample_id)
  return await withClaimLedgerWriteLock(
    validatedPayload.sample_id,
    workspace.root,
    database,
    async (lease) => {
      const existingArtifacts = database.findArtifactsByType(
        validatedPayload.sample_id,
        ANALYSIS_CLAIM_SET_ARTIFACT_TYPE
      )
      const existingLedger = await loadAnalysisClaimLedgerIndex(
        workspaceManager,
        database,
        validatedPayload.sample_id,
        { scope: 'all' }
      )
      if (
        existingLedger.claim_sets.length !== existingArtifacts.length ||
        existingLedger.warnings.length > 0
      ) {
        throw new Error(
          'Cannot append to Claim Ledger because one or more existing claim-set artifacts are invalid or unreadable.'
        )
      }
      for (const claim of validatedPayload.claims) {
        const previous = existingLedger.byClaimId.get(claim.claim_id)
        if (previous && ['verified', 'rejected'].includes(previous.claim.status)) {
          throw new Error(
            `${claim.claim_id}: terminal reviewed claims cannot be replaced or reopened.`
          )
        }
        if (
          previous &&
          previous.claim.review !== null &&
          validatedPayload.producer.kind !== 'analyst'
        ) {
          throw new Error(
            `${claim.claim_id}: only a trusted analyst revision may replace a reviewed claim.`
          )
        }
      }
      const latest = existingLedger.claim_sets[0] || null
      const expectedRevision = (latest?.payload.ledger_revision || 0) + 1
      const expectedParentId = latest?.artifact.id || null
      if (
        validatedPayload.ledger_revision !== expectedRevision ||
        validatedPayload.parent_artifact_id !== expectedParentId
      ) {
        throw new Error(
          `Claim Ledger revision conflict: expected revision ${expectedRevision} with parent ${expectedParentId || 'null'}.`
        )
      }

      const evidenceErrors = await validateCanonicalClaimSetEvidence(
        workspaceManager,
        database,
        validatedPayload
      )
      if (evidenceErrors.length > 0) {
        throw new Error(`Claim-set evidence validation failed: ${evidenceErrors.join(' ')}`)
      }

      const sessionSegment = sanitizePathSegment(
        validatedPayload.session_tag || undefined,
        'default'
      )
      const { workspaceRealPath, reportDirRealPath } = await ensureSafeClaimReportDirectory(
        workspace,
        sessionSegment
      )

      const artifactId = randomUUID()
      const fileName = `claim_set_r${validatedPayload.ledger_revision}_${Date.now()}_${artifactId.slice(0, 8)}.json`
      const absolutePath = path.join(reportDirRealPath, fileName)
      const temporaryPath = path.join(reportDirRealPath, `.${fileName}.${randomUUID()}.tmp`)
      const serialized = JSON.stringify(validatedPayload, null, 2)
      try {
        await fs.writeFile(temporaryPath, serialized, { encoding: 'utf8', flag: 'wx' })
        lease.assertOwned()
        await fs.rename(temporaryPath, absolutePath)
      } catch (error) {
        await fs.unlink(temporaryPath).catch(() => undefined)
        throw error
      }

      const artifact: ArtifactRef = {
        id: artifactId,
        type: ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
        path: path.relative(workspaceRealPath, absolutePath).replace(/\\/g, '/'),
        sha256: createHash('sha256').update(serialized).digest('hex'),
        mime: 'application/json',
      }
      try {
        const committed = database.insertArtifactIfContextLeaseOwned(
          {
            ...artifact,
            sample_id: validatedPayload.sample_id,
            mime: artifact.mime || null,
            created_at: validatedPayload.created_at,
          },
          lease.lockKey,
          lease.ownerToken
        )
        if (!committed) {
          throw new Error('Claim Ledger lost its context write lease before Artifact commit.')
        }
      } catch (error) {
        await fs.unlink(absolutePath).catch(() => undefined)
        throw error
      }
      return artifact
    }
  )
}

function sessionTagsForClaimSet(artifactPath: string, payload: AnalysisClaimSetArtifact): string[] {
  return Array.from(
    new Set(
      [deriveArtifactSessionTag(artifactPath), payload.session_tag]
        .filter((value): value is string => Boolean(value && value.trim()))
        .map((value) => value.trim())
    )
  )
}

export async function loadAnalysisClaimLedgerIndex(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: LoadAnalysisClaimLedgerOptions = {}
): Promise<AnalysisClaimLedgerIndex> {
  const scope = options.scope || 'all'
  const sessionTag = options.sessionTag?.trim() || null
  const warnings: string[] = []
  const workspace = await workspaceManager.getWorkspace(sampleId)
  const workspaceRealPath = await fs.realpath(workspace.root)
  const loaded: LoadedAnalysisClaimSet[] = []
  const requestedActiveClaimIds =
    options.activeClaimIds === undefined
      ? null
      : Array.from(
          new Set(options.activeClaimIds.map((claimId) => AnalysisClaimIdSchema.parse(claimId)))
        ).sort()
  if (requestedActiveClaimIds && requestedActiveClaimIds.length > 256) {
    throw new Error('activeClaimIds may contain at most 256 Claim IDs.')
  }
  if (requestedActiveClaimIds && scope === 'session') {
    throw new Error('activeClaimIds cannot be combined with claim scope=session.')
  }
  if (requestedActiveClaimIds && options.maxArtifacts !== undefined) {
    throw new Error('activeClaimIds cannot be combined with maxArtifacts.')
  }

  const hasExplicitLimit =
    typeof options.maxArtifacts === 'number' &&
    Number.isInteger(options.maxArtifacts) &&
    options.maxArtifacts > 0
  const activeScanArtifactLimit = Math.min(
    options.maxScanArtifacts ?? MAX_CASE_ACTIVE_CLAIM_SCAN_ARTIFACTS,
    MAX_CASE_ACTIVE_CLAIM_SCAN_ARTIFACTS
  )
  const activeScanByteLimit = Math.min(
    options.maxScanBytes ?? MAX_CASE_ACTIVE_CLAIM_SCAN_BYTES,
    MAX_CASE_ACTIVE_CLAIM_SCAN_BYTES
  )
  if (
    requestedActiveClaimIds &&
    (!Number.isInteger(activeScanArtifactLimit) || activeScanArtifactLimit <= 0)
  ) {
    throw new Error('maxScanArtifacts must be a positive integer.')
  }
  if (
    requestedActiveClaimIds &&
    (!Number.isInteger(activeScanByteLimit) || activeScanByteLimit <= 0)
  ) {
    throw new Error('maxScanBytes must be a positive integer.')
  }

  const allArtifacts = requestedActiveClaimIds
    ? null
    : database.findArtifactsByType(sampleId, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
  const totalArtifactCount = requestedActiveClaimIds
    ? database.countArtifactsByType(sampleId, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    : allArtifacts!.length
  const integrityIssues: AnalysisClaimLedgerIntegrityIssue[] = []
  const addIntegrityIssue = (issue: AnalysisClaimLedgerIntegrityIssueInput): void => {
    warnings.push(issue.reason)
    integrityIssues.push({
      kind: issue.kind,
      reason: issue.reason,
      artifact_id: issue.artifact_id ?? null,
      artifact_sha256: issue.artifact_sha256?.toLowerCase() ?? null,
      related_artifact_id: issue.related_artifact_id ?? null,
      related_artifact_sha256: issue.related_artifact_sha256?.toLowerCase() ?? null,
      expected_ledger_revision: issue.expected_ledger_revision ?? null,
      observed_ledger_revision: issue.observed_ledger_revision ?? null,
      total_artifact_count: totalArtifactCount,
    })
  }
  const artifactCandidates = requestedActiveClaimIds
    ? requestedActiveClaimIds.length > 0
      ? database.findArtifactsByTypeLimited(
          sampleId,
          ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
          activeScanArtifactLimit
        )
      : []
    : hasExplicitLimit
      ? allArtifacts!.slice(0, options.maxArtifacts)
      : allArtifacts!
  const nonActiveScanTruncated =
    requestedActiveClaimIds === null && artifactCandidates.length < totalArtifactCount
  if (nonActiveScanTruncated) {
    const firstOmittedArtifact = allArtifacts![artifactCandidates.length] || null
    addIntegrityIssue({
      kind: 'scan_truncated',
      reason: `Claim ledger scan is incomplete: selected ${artifactCandidates.length} of ${totalArtifactCount} artifact(s).`,
      artifact_id: firstOmittedArtifact?.id,
      artifact_sha256: firstOmittedArtifact?.sha256,
    })
  }

  const unresolvedActiveClaimIds = new Set(requestedActiveClaimIds || [])
  let activeResolutionStatus: AnalysisClaimActiveResolutionStatus | null = null
  let activeScanArtifactCount = 0
  let activeScanBytes = 0
  let previousStrictEntry: LoadedAnalysisClaimSet | null = null

  for (const artifact of artifactCandidates) {
    try {
      const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
      const artifactRealPath = await fs.realpath(absolutePath)
      if (!pathIsWithin(workspaceRealPath, artifactRealPath)) {
        addIntegrityIssue({
          kind: 'path_outside_workspace',
          reason: `Skipped claim set that resolves outside the workspace: ${artifact.id}`,
          artifact_id: artifact.id,
          artifact_sha256: artifact.sha256,
        })
        if (requestedActiveClaimIds) {
          activeResolutionStatus = 'integrity_error'
          break
        }
        continue
      }
      const stat = await fs.stat(artifactRealPath)
      if (!stat.isFile() || stat.size > MAX_CLAIM_SET_BYTES) {
        addIntegrityIssue({
          kind: 'invalid_size',
          reason: `Skipped invalid-size claim set artifact: ${artifact.id}`,
          artifact_id: artifact.id,
          artifact_sha256: artifact.sha256,
        })
        if (requestedActiveClaimIds) {
          activeResolutionStatus = 'integrity_error'
          break
        }
        continue
      }
      if (requestedActiveClaimIds && activeScanBytes + stat.size > activeScanByteLimit) {
        addIntegrityIssue({
          kind: 'byte_limit',
          reason: `Claim ledger strict scan reached the ${activeScanByteLimit}-byte safe scan budget before artifact ${artifact.id}.`,
          artifact_id: artifact.id,
          artifact_sha256: artifact.sha256,
        })
        activeResolutionStatus = 'byte_limit'
        break
      }
      if (requestedActiveClaimIds) {
        activeScanArtifactCount += 1
        activeScanBytes += stat.size
      }
      const content = await fs.readFile(artifactRealPath)
      const actualSha256 = createHash('sha256').update(content).digest('hex')
      if (actualSha256.toLowerCase() !== artifact.sha256.toLowerCase()) {
        addIntegrityIssue({
          kind: 'sha256_mismatch',
          reason: `Skipped claim set with SHA-256 mismatch: ${artifact.id}`,
          artifact_id: artifact.id,
          artifact_sha256: artifact.sha256,
        })
        if (requestedActiveClaimIds) {
          activeResolutionStatus = 'integrity_error'
          break
        }
        continue
      }
      const parsed = AnalysisClaimSetArtifactSchema.safeParse(
        JSON.parse(content.toString('utf8')) as unknown
      )
      if (!parsed.success || parsed.data.sample_id !== sampleId) {
        addIntegrityIssue({
          kind: 'invalid_payload',
          reason: `Skipped invalid claim set artifact: ${artifact.id}`,
          artifact_id: artifact.id,
          artifact_sha256: artifact.sha256,
        })
        if (requestedActiveClaimIds) {
          activeResolutionStatus = 'integrity_error'
          break
        }
        continue
      }
      const entry: LoadedAnalysisClaimSet = {
        artifact: {
          id: artifact.id,
          type: artifact.type,
          path: artifact.path,
          sha256: artifact.sha256,
          ...(artifact.mime ? { mime: artifact.mime } : {}),
          created_at: artifact.created_at,
        },
        payload: parsed.data,
        session_tags: sessionTagsForClaimSet(artifact.path, parsed.data),
      }
      if (requestedActiveClaimIds) {
        if (!previousStrictEntry) {
          if (entry.payload.ledger_revision !== totalArtifactCount) {
            addIntegrityIssue({
              kind: 'head_revision_mismatch',
              reason: `Claim ledger strict scan expected head revision ${totalArtifactCount}, received revision ${entry.payload.ledger_revision} from ${entry.artifact.id}.`,
              artifact_id: entry.artifact.id,
              artifact_sha256: entry.artifact.sha256,
              expected_ledger_revision: totalArtifactCount,
              observed_ledger_revision: entry.payload.ledger_revision,
            })
            activeResolutionStatus = 'integrity_error'
            break
          }
        } else if (
          entry.payload.ledger_revision !== previousStrictEntry.payload.ledger_revision - 1 ||
          previousStrictEntry.payload.parent_artifact_id !== entry.artifact.id
        ) {
          addIntegrityIssue({
            kind: 'chain_discontinuity',
            reason: `Claim ledger strict scan found a discontinuity between revision ${previousStrictEntry.payload.ledger_revision} (${previousStrictEntry.artifact.id}) and revision ${entry.payload.ledger_revision} (${entry.artifact.id}).`,
            artifact_id: entry.artifact.id,
            artifact_sha256: entry.artifact.sha256,
            related_artifact_id: previousStrictEntry.artifact.id,
            related_artifact_sha256: previousStrictEntry.artifact.sha256,
            expected_ledger_revision: previousStrictEntry.payload.ledger_revision - 1,
            observed_ledger_revision: entry.payload.ledger_revision,
          })
          activeResolutionStatus = 'integrity_error'
          break
        }
        previousStrictEntry = entry
      }
      loaded.push(entry)
      if (requestedActiveClaimIds) {
        for (const claim of entry.payload.claims) {
          unresolvedActiveClaimIds.delete(claim.claim_id)
        }
        if (unresolvedActiveClaimIds.size === 0) {
          activeResolutionStatus = 'complete'
          break
        }
      }
    } catch {
      addIntegrityIssue({
        kind: 'unreadable',
        reason: `Skipped unreadable claim set artifact: ${artifact.id}`,
        artifact_id: artifact.id,
        artifact_sha256: artifact.sha256,
      })
      if (requestedActiveClaimIds) {
        activeResolutionStatus = 'integrity_error'
        break
      }
    }
  }

  if (requestedActiveClaimIds && activeResolutionStatus === null) {
    if (unresolvedActiveClaimIds.size === 0) {
      activeResolutionStatus = 'complete'
    } else if (activeScanArtifactCount >= activeScanArtifactLimit) {
      activeResolutionStatus = 'scan_limit'
    } else {
      activeResolutionStatus = 'missing'
    }
  }
  if (requestedActiveClaimIds && activeResolutionStatus === 'scan_limit') {
    addIntegrityIssue({
      kind: 'scan_limit',
      reason: `Claim ledger strict scan reached the ${activeScanArtifactLimit}-artifact safe scan limit.`,
      artifact_id: previousStrictEntry?.artifact.id,
      artifact_sha256: previousStrictEntry?.artifact.sha256,
      observed_ledger_revision: previousStrictEntry?.payload.ledger_revision,
    })
  } else if (requestedActiveClaimIds && activeResolutionStatus === 'missing') {
    addIntegrityIssue({
      kind: 'missing_active_claims',
      reason: `Claim ledger strict scan reached the complete ledger without resolving: ${Array.from(unresolvedActiveClaimIds).sort().join(', ')}.`,
      artifact_id: previousStrictEntry?.artifact.id,
      artifact_sha256: previousStrictEntry?.artifact.sha256,
      observed_ledger_revision: previousStrictEntry?.payload.ledger_revision,
    })
  }
  if (requestedActiveClaimIds && activeResolutionStatus !== 'complete') {
    const unresolved = Array.from(unresolvedActiveClaimIds).sort()
    const boundary =
      activeResolutionStatus === 'scan_limit'
        ? `the ${activeScanArtifactLimit}-artifact safe scan limit`
        : activeResolutionStatus === 'byte_limit'
          ? `the ${activeScanByteLimit}-byte safe scan budget`
          : activeResolutionStatus === 'missing'
            ? 'the complete Claim Ledger'
            : 'Claim Ledger integrity validation'
    warnings.push(
      `Case-active Claim resolution stopped at ${boundary}; all requested Claims were withheld${unresolved.length > 0 ? ` (unresolved: ${unresolved.join(', ')})` : ''}.`
    )
  }

  loaded.sort((left, right) => {
    const revisionOrder = right.payload.ledger_revision - left.payload.ledger_revision
    if (revisionOrder !== 0) {
      return revisionOrder
    }
    const createdAtOrder = right.payload.created_at.localeCompare(left.payload.created_at)
    return createdAtOrder !== 0 ? createdAtOrder : right.artifact.id.localeCompare(left.artifact.id)
  })

  if (!requestedActiveClaimIds) {
    const byRevision = new Map<number, LoadedAnalysisClaimSet>()
    for (const entry of [...loaded].reverse()) {
      const existing = byRevision.get(entry.payload.ledger_revision)
      if (existing) {
        addIntegrityIssue({
          kind: 'duplicate_revision',
          reason: `Duplicate claim ledger revision ${entry.payload.ledger_revision}: ${existing.artifact.id}, ${entry.artifact.id}`,
          artifact_id: entry.artifact.id,
          artifact_sha256: entry.artifact.sha256,
          related_artifact_id: existing.artifact.id,
          related_artifact_sha256: existing.artifact.sha256,
          expected_ledger_revision: entry.payload.ledger_revision,
          observed_ledger_revision: entry.payload.ledger_revision,
        })
        continue
      }
      byRevision.set(entry.payload.ledger_revision, entry)
      if (entry.payload.ledger_revision > 1) {
        const previous = byRevision.get(entry.payload.ledger_revision - 1)
        if (!previous) {
          addIntegrityIssue({
            kind: 'missing_predecessor',
            reason: `Claim ledger revision ${entry.payload.ledger_revision} has no loaded predecessor.`,
            artifact_id: entry.artifact.id,
            artifact_sha256: entry.artifact.sha256,
            expected_ledger_revision: entry.payload.ledger_revision - 1,
            observed_ledger_revision: entry.payload.ledger_revision,
          })
        } else if (entry.payload.parent_artifact_id !== previous.artifact.id) {
          addIntegrityIssue({
            kind: 'parent_mismatch',
            reason: `Claim ledger revision ${entry.payload.ledger_revision} does not reference its predecessor.`,
            artifact_id: entry.artifact.id,
            artifact_sha256: entry.artifact.sha256,
            related_artifact_id: previous.artifact.id,
            related_artifact_sha256: previous.artifact.sha256,
            expected_ledger_revision: entry.payload.ledger_revision - 1,
            observed_ledger_revision: entry.payload.ledger_revision,
          })
        }
      }
    }
  }

  let mergeEntries = loaded
  let selected = loaded
  if (scope === 'session') {
    selected = sessionTag
      ? loaded.filter((entry) => matchesSessionTag(entry.session_tags, sessionTag))
      : []
    mergeEntries = selected
    if (!sessionTag) {
      warnings.push('sessionTag is required when claim scope=session.')
    }
  }

  let byClaimId = new Map<string, LoadedAnalysisClaim>()
  for (const entry of mergeEntries) {
    for (const claim of entry.payload.claims) {
      if (!byClaimId.has(claim.claim_id)) {
        byClaimId.set(claim.claim_id, {
          claim,
          claim_set_artifact_id: entry.artifact.id,
          ledger_revision: entry.payload.ledger_revision,
          created_at: entry.payload.created_at,
          producer: entry.payload.producer,
        })
      }
    }
  }
  if (scope === 'latest') {
    const activeArtifactIds = new Set(
      Array.from(byClaimId.values()).map((claim) => claim.claim_set_artifact_id)
    )
    selected = loaded.filter((entry) => activeArtifactIds.has(entry.artifact.id))
  }

  if (requestedActiveClaimIds) {
    if (activeResolutionStatus === 'complete') {
      const activeByClaimId = new Map<string, LoadedAnalysisClaim>()
      for (const claimId of requestedActiveClaimIds) {
        const claim = byClaimId.get(claimId)
        if (claim) activeByClaimId.set(claimId, claim)
      }
      byClaimId = activeByClaimId
      const activeArtifactIds = new Set(
        Array.from(byClaimId.values()).map((claim) => claim.claim_set_artifact_id)
      )
      selected = loaded.filter((entry) => activeArtifactIds.has(entry.artifact.id))
    } else {
      byClaimId = new Map()
      selected = []
    }
  }

  const createdAt = selected.map((entry) => entry.payload.created_at).sort()
  const activeClaimResolution: AnalysisClaimActiveResolution | null = requestedActiveClaimIds
    ? {
        status: activeResolutionStatus!,
        requested_claim_ids: requestedActiveClaimIds,
        unresolved_claim_ids: Array.from(unresolvedActiveClaimIds).sort(),
        scanned_artifact_count: activeScanArtifactCount,
        scanned_bytes: activeScanBytes,
      }
    : null
  const truncated = activeClaimResolution
    ? activeClaimResolution.status !== 'complete'
    : nonActiveScanTruncated
  const orderedIntegrityIssues = sortAnalysisClaimLedgerIntegrityIssues(integrityIssues)
  const baseMarker =
    selected.length > 0
      ? selected.map((entry) => `${entry.artifact.id}:${entry.artifact.sha256}`).join('|')
      : 'none'
  const markerIntegrityState =
    orderedIntegrityIssues.length > 0 || truncated
      ? {
          total_artifact_count: totalArtifactCount,
          truncated,
          active_claim_resolution: activeClaimResolution,
          integrity_issues: orderedIntegrityIssues,
        }
      : null
  const marker = markerIntegrityState
    ? `${baseMarker}:integrity:${createHash('sha256')
        .update(JSON.stringify(markerIntegrityState))
        .digest('hex')}`
    : baseMarker
  return {
    byClaimId,
    claim_sets: selected,
    artifact_ids: selected.map((entry) => entry.artifact.id),
    session_tags: Array.from(new Set(selected.flatMap((entry) => entry.session_tags))),
    earliest_created_at: createdAt[0] || null,
    latest_created_at: createdAt[createdAt.length - 1] || null,
    marker,
    scope_note: activeClaimResolution
      ? activeClaimResolution.status === 'complete'
        ? `Resolved ${byClaimId.size} Case-active Claim(s) after scanning ${activeClaimResolution.scanned_artifact_count} of ${totalArtifactCount} Claim Ledger artifact(s).`
        : `Withheld all ${activeClaimResolution.requested_claim_ids.length} Case-active Claim(s) because strict resolution ended with status=${activeClaimResolution.status}.`
      : selected.length > 0
        ? `Selected ${selected.length} claim set artifact(s) containing the active claim revisions using scope=${scope}${sessionTag ? ` selector=${sessionTag}` : ''}.`
        : `No claim set artifacts matched scope=${scope}${sessionTag ? ` selector=${sessionTag}` : ''}.`,
    total_artifact_count: totalArtifactCount,
    truncated,
    warnings,
    integrity_issues: orderedIntegrityIssues,
    active_claim_resolution: activeClaimResolution,
  }
}

export function scopeAnalysisClaimLedgerIndex(
  index: AnalysisClaimLedgerIndex,
  activeClaimIds: readonly string[] | null
): AnalysisClaimLedgerIndex {
  if (activeClaimIds === null) {
    return index
  }

  const selectedClaimIds = Array.from(new Set(activeClaimIds)).sort()
  const resolvedByClaimId = new Map<string, LoadedAnalysisClaim>()
  const missingClaimIds: string[] = []
  for (const claimId of selectedClaimIds) {
    const entry = index.byClaimId.get(claimId)
    if (entry) {
      resolvedByClaimId.set(claimId, entry)
    } else {
      missingClaimIds.push(claimId)
    }
  }

  const activeResolution = index.active_claim_resolution
  const resolutionMatchesSelection =
    activeResolution !== null &&
    activeResolution.requested_claim_ids.length === selectedClaimIds.length &&
    activeResolution.requested_claim_ids.every(
      (claimId, index) => claimId === selectedClaimIds[index]
    )
  const resolutionFailed = resolutionMatchesSelection && activeResolution.status !== 'complete'
  const withholdAll = resolutionFailed || missingClaimIds.length > 0
  const byClaimId = withholdAll ? new Map<string, LoadedAnalysisClaim>() : resolvedByClaimId

  const selectedArtifactIds = new Set(
    Array.from(byClaimId.values()).map((entry) => entry.claim_set_artifact_id)
  )
  const claimSets = index.claim_sets.filter((entry) => selectedArtifactIds.has(entry.artifact.id))
  const selectedEntries = Array.from(byClaimId.values())
  const createdAt = selectedEntries.map((entry) => entry.created_at).sort()
  const markerState = withholdAll
    ? {
        active_claim_ids: selectedClaimIds,
        total_artifact_count: index.total_artifact_count,
        resolution: resolutionFailed
          ? {
              status: activeResolution.status,
              unresolved_claim_ids: activeResolution.unresolved_claim_ids,
              scanned_artifact_count: activeResolution.scanned_artifact_count,
              scanned_bytes: activeResolution.scanned_bytes,
            }
          : {
              status: 'missing' as const,
              unresolved_claim_ids: missingClaimIds,
              scanned_artifact_count: null,
              scanned_bytes: null,
            },
        integrity_issues: index.integrity_issues,
      }
    : selectedClaimIds.map((claimId) => {
        const entry = byClaimId.get(claimId)!
        return {
          claim_id: claimId,
          claim_set_artifact_id: entry.claim_set_artifact_id,
          ledger_revision: entry.ledger_revision,
          created_at: entry.created_at,
          producer: entry.producer,
          claim: entry.claim,
        }
      })
  const marker =
    selectedClaimIds.length > 0
      ? `case:${createHash('sha256').update(JSON.stringify(markerState)).digest('hex')}`
      : 'none'
  const warnings = [...index.warnings]
  if (withholdAll) {
    const unresolvedClaimIds = resolutionFailed
      ? activeResolution.unresolved_claim_ids
      : missingClaimIds
    warnings.push(
      `Case active_claim_ids could not be resolved completely; the entire Case Claim view was withheld${unresolvedClaimIds.length > 0 ? ` (unresolved: ${unresolvedClaimIds.join(', ')})` : ''}.`
    )
  }

  return {
    ...index,
    byClaimId,
    claim_sets: claimSets,
    artifact_ids: claimSets.map((entry) => entry.artifact.id),
    session_tags: Array.from(new Set(claimSets.flatMap((entry) => entry.session_tags))),
    earliest_created_at: createdAt[0] || null,
    latest_created_at: createdAt[createdAt.length - 1] || null,
    marker,
    scope_note: withholdAll
      ? `Withheld all ${selectedClaimIds.length} Case-active Claim(s).`
      : `Selected ${byClaimId.size} of ${selectedClaimIds.length} Case-active Claim(s).`,
    truncated: index.truncated || withholdAll,
    warnings: Array.from(new Set(warnings)),
  }
}

export interface AnalysisClaimOverlay {
  schema: typeof ANALYSIS_CLAIM_OVERLAY_SCHEMA
  claim_sets: Array<{
    artifact_id: string
    ledger_revision: number
    created_at: string
    session_tag: string | null
  }>
  claims: Array<{
    claim_id: string
    claim_set_artifact_id: string
    category: z.infer<typeof AnalysisClaimCategorySchema>
    subject: string
    statement: string
    status: z.infer<typeof AnalysisClaimStatusSchema>
    source: z.infer<typeof AnalysisClaimSourceSchema>
    assumptions: string[]
    alternatives: string[]
    falsification_tests: string[]
    review: z.infer<typeof AnalysisClaimReviewSchema> | null
  }>
  evidence_anchors: Array<AnalysisClaimEvidence & { anchor_id: string }>
  edges: Array<{
    from: string
    to: string
    relation: 'contains_claim' | 'supported_by' | 'countered_by'
    json_pointer: string | null
    locator: string | null
  }>
  unresolved_refs: Array<{
    claim_id: string
    artifact_id: string
    relation: 'supported_by' | 'countered_by'
    reason: string
  }>
  summary: {
    claim_set_count: number
    claim_count: number
    evidence_anchor_count: number
    supporting_edge_count: number
    counter_edge_count: number
    inferred_count: number
    verified_count: number
    rejected_count: number
    analyst_review_required: boolean
  }
  warnings: string[]
}

export async function buildAnalysisClaimOverlay(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  index: AnalysisClaimLedgerIndex
): Promise<AnalysisClaimOverlay> {
  const cache = new Map<string, EvidenceValidationCacheEntry>()
  const budget: EvidenceValidationBudget = { jsonBytes: 0, hashBytes: 0, artifactCount: 0 }
  const claims = Array.from(index.byClaimId.values())
  const anchors = new Map<string, AnalysisClaimEvidence & { anchor_id: string }>()
  const edges: AnalysisClaimOverlay['edges'] = []
  const unresolvedRefs: AnalysisClaimOverlay['unresolved_refs'] = []

  for (const loaded of claims) {
    edges.push({
      from: `claim_set:${loaded.claim_set_artifact_id}`,
      to: `claim:${loaded.claim.claim_id}`,
      relation: 'contains_claim',
      json_pointer: null,
      locator: null,
    })

    for (const [relation, references] of [
      ['supported_by', loaded.claim.supporting_evidence],
      ['countered_by', loaded.claim.counter_evidence],
    ] as const) {
      for (const reference of references) {
        const result = await validateEvidenceReference(
          workspaceManager,
          database,
          sampleId,
          reference,
          cache,
          budget,
          reference
        )
        if (!result.evidence) {
          unresolvedRefs.push({
            claim_id: loaded.claim.claim_id,
            artifact_id: reference.artifact_id,
            relation,
            reason: result.error || 'Evidence reference is unavailable.',
          })
          continue
        }
        const key = evidenceRefKey(result.evidence)
        const anchorId = evidenceAnchorId(result.evidence)
        anchors.set(key, { anchor_id: anchorId, ...result.evidence })
        edges.push({
          from: `claim:${loaded.claim.claim_id}`,
          to: anchorId,
          relation,
          json_pointer: result.evidence.json_pointer ?? null,
          locator: result.evidence.locator ?? null,
        })
      }
    }
  }

  const overlayClaims = claims.map((loaded) => ({
    claim_id: loaded.claim.claim_id,
    claim_set_artifact_id: loaded.claim_set_artifact_id,
    category: loaded.claim.category,
    subject: loaded.claim.subject,
    statement: loaded.claim.statement,
    status: loaded.claim.status,
    source: loaded.claim.source,
    assumptions: loaded.claim.assumptions,
    alternatives: loaded.claim.alternatives,
    falsification_tests: loaded.claim.falsification_tests,
    review: loaded.claim.review,
  }))
  const warnings = [...index.warnings]
  if (unresolvedRefs.length > 0) {
    warnings.push(`${unresolvedRefs.length} claim evidence reference(s) could not be resolved.`)
  }

  return {
    schema: ANALYSIS_CLAIM_OVERLAY_SCHEMA,
    claim_sets: index.claim_sets.map((entry) => ({
      artifact_id: entry.artifact.id,
      ledger_revision: entry.payload.ledger_revision,
      created_at: entry.payload.created_at,
      session_tag: entry.payload.session_tag,
    })),
    claims: overlayClaims,
    evidence_anchors: Array.from(anchors.values()),
    edges,
    unresolved_refs: unresolvedRefs,
    summary: {
      claim_set_count: index.claim_sets.length,
      claim_count: overlayClaims.length,
      evidence_anchor_count: anchors.size,
      supporting_edge_count: edges.filter((edge) => edge.relation === 'supported_by').length,
      counter_edge_count: edges.filter((edge) => edge.relation === 'countered_by').length,
      inferred_count: overlayClaims.filter((claim) => claim.status === 'inferred').length,
      verified_count: overlayClaims.filter((claim) => claim.status === 'verified').length,
      rejected_count: overlayClaims.filter((claim) => claim.status === 'rejected').length,
      analyst_review_required:
        unresolvedRefs.length > 0 ||
        overlayClaims.some((claim) => ['inferred', 'contradicted'].includes(claim.status)),
    },
    warnings,
  }
}
