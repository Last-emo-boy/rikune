import fs from 'fs/promises'
import { createReadStream } from 'fs'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { deriveArtifactSessionTag } from './artifact-inventory.js'
import { matchesSessionTag, sanitizePathSegment } from '../utils/shared-helpers.js'

export const ANALYSIS_CLAIM_SET_ARTIFACT_TYPE = 'analysis_claim_set'
export const ANALYSIS_CLAIM_SET_SCHEMA = 'rikune.analysis_claim_set.v1'
export const ANALYSIS_CLAIM_OVERLAY_SCHEMA = 'rikune.analysis_claim_overlay.v1'
export const MAX_ANALYSIS_CLAIM_EVIDENCE_REFERENCES = 512

const MAX_JSON_EVIDENCE_BYTES = 8 * 1024 * 1024
const MAX_JSON_EVIDENCE_BATCH_BYTES = 32 * 1024 * 1024
const MAX_CLAIM_SET_BYTES = 32 * 1024 * 1024
const MAX_EVIDENCE_HASH_BATCH_BYTES = 512 * 1024 * 1024
const MAX_EVIDENCE_ARTIFACTS_PER_BATCH = 512

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
}

export interface LoadAnalysisClaimLedgerOptions {
  scope?: AnalysisClaimScope
  sessionTag?: string
  maxArtifacts?: number
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

async function withClaimLedgerWriteLock<T>(
  sampleId: string,
  workspaceRoot: string,
  operation: () => Promise<T>
): Promise<T> {
  const previous = claimLedgerWriteLocks.get(sampleId) || Promise.resolve()
  let release: () => void = () => undefined
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const queued = previous.then(() => gate)
  claimLedgerWriteLocks.set(sampleId, queued)
  await previous
  const lockPath = path.join(workspaceRoot, '.analysis-claim-ledger.lock')
  let lockHandle: Awaited<ReturnType<typeof fs.open>> | undefined

  try {
    try {
      lockHandle = await fs.open(lockPath, 'wx')
      await lockHandle.writeFile(
        JSON.stringify({
          pid: process.pid,
          sample_id: sampleId,
          acquired_at: new Date().toISOString(),
        })
      )
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new Error(
          'Claim Ledger is locked by another process; retry after the active writer completes.'
        )
      }
      throw error
    }
    return await operation()
  } finally {
    if (lockHandle) {
      await lockHandle.close().catch(() => undefined)
      await fs.unlink(lockPath).catch(() => undefined)
    }
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
  return await withClaimLedgerWriteLock(validatedPayload.sample_id, workspace.root, async () => {
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

    const sessionSegment = sanitizePathSegment(validatedPayload.session_tag || undefined, 'default')
    const { workspaceRealPath, reportDirRealPath } = await ensureSafeClaimReportDirectory(
      workspace,
      sessionSegment
    )

    const artifactId = randomUUID()
    const fileName = `claim_set_r${validatedPayload.ledger_revision}_${Date.now()}_${artifactId.slice(0, 8)}.json`
    const absolutePath = path.join(reportDirRealPath, fileName)
    const serialized = JSON.stringify(validatedPayload, null, 2)
    await fs.writeFile(absolutePath, serialized, { encoding: 'utf8', flag: 'wx' })

    const artifact: ArtifactRef = {
      id: artifactId,
      type: ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
      path: path.relative(workspaceRealPath, absolutePath).replace(/\\/g, '/'),
      sha256: createHash('sha256').update(serialized).digest('hex'),
      mime: 'application/json',
    }
    try {
      database.insertArtifact({
        ...artifact,
        sample_id: validatedPayload.sample_id,
        mime: artifact.mime || null,
        created_at: validatedPayload.created_at,
      })
    } catch (error) {
      await fs.unlink(absolutePath).catch(() => undefined)
      throw error
    }
    return artifact
  })
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
  const allArtifacts = database.findArtifactsByType(sampleId, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
  const hasExplicitLimit =
    typeof options.maxArtifacts === 'number' &&
    Number.isInteger(options.maxArtifacts) &&
    options.maxArtifacts > 0
  const artifactCandidates = hasExplicitLimit
    ? allArtifacts.slice(0, options.maxArtifacts)
    : allArtifacts
  const truncated = artifactCandidates.length < allArtifacts.length
  if (truncated) {
    warnings.push(
      `Claim ledger scan is incomplete: selected ${artifactCandidates.length} of ${allArtifacts.length} artifact(s).`
    )
  }

  for (const artifact of artifactCandidates) {
    try {
      const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
      const artifactRealPath = await fs.realpath(absolutePath)
      if (!pathIsWithin(workspaceRealPath, artifactRealPath)) {
        warnings.push(`Skipped claim set that resolves outside the workspace: ${artifact.id}`)
        continue
      }
      const stat = await fs.stat(artifactRealPath)
      if (!stat.isFile() || stat.size > MAX_CLAIM_SET_BYTES) {
        warnings.push(`Skipped invalid-size claim set artifact: ${artifact.id}`)
        continue
      }
      const content = await fs.readFile(artifactRealPath)
      const actualSha256 = createHash('sha256').update(content).digest('hex')
      if (actualSha256.toLowerCase() !== artifact.sha256.toLowerCase()) {
        warnings.push(`Skipped claim set with SHA-256 mismatch: ${artifact.id}`)
        continue
      }
      const parsed = AnalysisClaimSetArtifactSchema.safeParse(
        JSON.parse(content.toString('utf8')) as unknown
      )
      if (!parsed.success || parsed.data.sample_id !== sampleId) {
        warnings.push(`Skipped invalid claim set artifact: ${artifact.id}`)
        continue
      }
      loaded.push({
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
      })
    } catch {
      warnings.push(`Skipped unreadable claim set artifact: ${artifact.id}`)
    }
  }

  loaded.sort((left, right) => {
    const revisionOrder = right.payload.ledger_revision - left.payload.ledger_revision
    if (revisionOrder !== 0) {
      return revisionOrder
    }
    const createdAtOrder = right.payload.created_at.localeCompare(left.payload.created_at)
    return createdAtOrder !== 0 ? createdAtOrder : right.artifact.id.localeCompare(left.artifact.id)
  })

  const byRevision = new Map<number, LoadedAnalysisClaimSet>()
  for (const entry of [...loaded].reverse()) {
    const existing = byRevision.get(entry.payload.ledger_revision)
    if (existing) {
      warnings.push(
        `Duplicate claim ledger revision ${entry.payload.ledger_revision}: ${existing.artifact.id}, ${entry.artifact.id}`
      )
      continue
    }
    byRevision.set(entry.payload.ledger_revision, entry)
    if (entry.payload.ledger_revision > 1) {
      const previous = byRevision.get(entry.payload.ledger_revision - 1)
      if (!previous) {
        warnings.push(
          `Claim ledger revision ${entry.payload.ledger_revision} has no loaded predecessor.`
        )
      } else if (entry.payload.parent_artifact_id !== previous.artifact.id) {
        warnings.push(
          `Claim ledger revision ${entry.payload.ledger_revision} does not reference its predecessor.`
        )
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

  const byClaimId = new Map<string, LoadedAnalysisClaim>()
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

  const createdAt = selected.map((entry) => entry.payload.created_at).sort()
  return {
    byClaimId,
    claim_sets: selected,
    artifact_ids: selected.map((entry) => entry.artifact.id),
    session_tags: Array.from(new Set(selected.flatMap((entry) => entry.session_tags))),
    earliest_created_at: createdAt[0] || null,
    latest_created_at: createdAt[createdAt.length - 1] || null,
    marker:
      selected.length > 0
        ? selected.map((entry) => `${entry.artifact.id}:${entry.artifact.sha256}`).join('|')
        : 'none',
    scope_note:
      selected.length > 0
        ? `Selected ${selected.length} claim set artifact(s) containing the active claim revisions using scope=${scope}${sessionTag ? ` selector=${sessionTag}` : ''}.`
        : `No claim set artifacts matched scope=${scope}${sessionTag ? ` selector=${sessionTag}` : ''}.`,
    total_artifact_count: allArtifacts.length,
    truncated,
    warnings,
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
