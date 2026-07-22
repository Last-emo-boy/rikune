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
import { matchesSessionTag, sanitizePathSegment } from '../utils/shared-helpers.js'

export const ANALYSIS_CASE_STATE_ARTIFACT_TYPE = 'analysis_case_state'
export const ANALYSIS_CASE_STATE_SCHEMA = 'rikune.analysis_case_state.v1'
export const ANALYSIS_CASE_STATE_ARTIFACT_ROLE = 'context_only'
export const ANALYSIS_CASE_STATE_LOCK_STALE_MS = 5 * 60 * 1000

const MAX_CASE_STATE_BYTES = 4 * 1024 * 1024
const MAX_REFERENCE_HASH_BYTES = 512 * 1024 * 1024
const MAX_REFERENCE_COUNT = 256
const MAX_CASE_STATE_LOCK_BYTES = 4096
const CASE_STATE_CASE_PARTITION_SEGMENT = 'by-case'
const CASE_STATE_CASE_KEY_PATTERN = /^[a-f0-9]{64}$/
const CASE_STATE_SAFE_PATH_SEGMENT_PATTERN = /^[a-z0-9._-]{1,64}$/
const CASE_STATE_PARTITION_FILE_PATTERN =
  /^[a-z0-9][a-z0-9._-]{0,63}_r[1-9][0-9]*_[a-f0-9]{8}-[a-f0-9]{3}\.json$/

const IsoTimestampSchema = z.string().datetime({ offset: true })

const forbiddenContextPatterns: Array<{ pattern: RegExp; message: string }> = [
  {
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
    message: 'private key material is not allowed in case-state text.',
  },
  {
    pattern: /\bauthorization\s*:\s*bearer\s+\S+/i,
    message: 'authorization credentials are not allowed in case-state text.',
  },
  {
    pattern: /\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*["']?\S{8,}/i,
    message: 'credential-like assignments are not allowed in case-state text.',
  },
  {
    pattern: /\b(?:system|developer)\s+prompt\s*:/i,
    message: 'prompts are not allowed in case-state text.',
  },
  {
    pattern: /\b(?:chain[- ]of[- ]thought|hidden reasoning|internal reasoning)\s*:/i,
    message: 'private reasoning is not allowed in case-state text.',
  },
]

function safeCaseText(maxLength: number) {
  return z
    .string()
    .trim()
    .min(1)
    .max(maxLength)
    .superRefine((value, ctx) => {
      for (const forbidden of forbiddenContextPatterns) {
        if (forbidden.pattern.test(value)) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: forbidden.message })
        }
      }
    })
}

export const AnalysisCaseSampleIdSchema = safeCaseText(500)
export const AnalysisCaseIdSchema = safeCaseText(200).refine(
  (value) => /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value),
  {
    message: 'case_id must use letters, numbers, dot, underscore, colon, or hyphen.',
  }
)
export const AnalysisCaseSessionTagSchema = safeCaseText(200)
export const AnalysisCaseAgentNameSchema = safeCaseText(200)
export const AnalysisCaseToolNameSchema = safeCaseText(200)
export const AnalysisCaseArtifactIdSchema = safeCaseText(200)
const AnalysisCaseArtifactTypeSchema = safeCaseText(200)
const AnalysisCaseArtifactPathSchema = safeCaseText(2000)
const AnalysisCaseClaimIdSchema = safeCaseText(200)
const AnalysisCaseSha256Schema = safeCaseText(64).refine((value) => /^[a-f0-9]{64}$/i.test(value), {
  message: 'value must be a SHA-256 digest.',
})

export const AnalysisCaseAttemptOutcomeSchema = z.enum(['completed', 'failed', 'queued', 'skipped'])

export const AnalysisCaseArtifactReferenceSchema = z
  .object({
    artifact_id: AnalysisCaseArtifactIdSchema,
    artifact_type: AnalysisCaseArtifactTypeSchema,
    artifact_path: AnalysisCaseArtifactPathSchema,
    artifact_sha256: AnalysisCaseSha256Schema,
  })
  .strict()

export const AnalysisCaseAttemptedActionDraftSchema = z
  .object({
    tool: AnalysisCaseToolNameSchema,
    args_fingerprint: AnalysisCaseSha256Schema.refine((value) => /^[a-f0-9]{64}$/i.test(value), {
      message: 'args_fingerprint must be a SHA-256 digest, never raw tool arguments.',
    }),
    outcome: AnalysisCaseAttemptOutcomeSchema,
    result_artifact_ids: z.array(AnalysisCaseArtifactIdSchema).max(64).default([]),
    summary: safeCaseText(1200).optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (new Set(value.result_artifact_ids).size !== value.result_artifact_ids.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['result_artifact_ids'],
        message: 'result_artifact_ids contains duplicate values.',
      })
    }
  })

export const AnalysisCaseAttemptedActionSchema = z
  .object({
    tool: AnalysisCaseToolNameSchema,
    args_fingerprint: AnalysisCaseSha256Schema,
    outcome: AnalysisCaseAttemptOutcomeSchema,
    result_artifacts: z.array(AnalysisCaseArtifactReferenceSchema).max(64),
    summary: safeCaseText(1200).optional(),
  })
  .strict()

export const AnalysisCaseStateDraftSchema = z
  .object({
    objective: safeCaseText(2000),
    decisions: z.array(safeCaseText(1200)).max(64).default([]),
    open_questions: z.array(safeCaseText(1200)).max(64).default([]),
    attempted_actions: z.array(AnalysisCaseAttemptedActionDraftSchema).max(128).default([]),
    active_claim_ids: z.array(AnalysisCaseClaimIdSchema).max(256).default([]),
    pinned_artifact_ids: z.array(AnalysisCaseArtifactIdSchema).max(128).default([]),
    next_actions: z.array(safeCaseText(1200)).max(64).default([]),
  })
  .strict()
  .superRefine((value, ctx) => {
    for (const [field, values] of [
      ['active_claim_ids', value.active_claim_ids],
      ['pinned_artifact_ids', value.pinned_artifact_ids],
    ] as const) {
      if (new Set(values).size !== values.length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [field],
          message: `${field} contains duplicate values.`,
        })
      }
    }
  })

export const AnalysisCaseProducerSchema = z
  .object({
    kind: z.literal('external_agent'),
    agent_name: AnalysisCaseAgentNameSchema.nullable(),
  })
  .strict()

export const AnalysisCaseStateArtifactSchema = z
  .object({
    schema: z.literal(ANALYSIS_CASE_STATE_SCHEMA),
    schema_version: z.literal(1),
    artifact_role: z.literal(ANALYSIS_CASE_STATE_ARTIFACT_ROLE),
    sample_id: AnalysisCaseSampleIdSchema,
    case_id: AnalysisCaseIdSchema,
    revision: z.number().int().positive(),
    parent_artifact_id: AnalysisCaseArtifactIdSchema.nullable(),
    created_at: IsoTimestampSchema,
    session_tag: AnalysisCaseSessionTagSchema.nullable(),
    objective: safeCaseText(2000),
    decisions: z.array(safeCaseText(1200)).max(64),
    open_questions: z.array(safeCaseText(1200)).max(64),
    attempted_actions: z.array(AnalysisCaseAttemptedActionSchema).max(128),
    active_claim_ids: z.array(AnalysisCaseClaimIdSchema).max(256),
    pinned_artifacts: z.array(AnalysisCaseArtifactReferenceSchema).max(128),
    next_actions: z.array(safeCaseText(1200)).max(64),
    producer: AnalysisCaseProducerSchema,
  })
  .strict()
  .superRefine((value, ctx) => {
    if ((value.revision === 1) !== (value.parent_artifact_id === null)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['parent_artifact_id'],
        message: 'revision 1 has no parent; later revisions require a parent artifact.',
      })
    }
    if (new Set(value.active_claim_ids).size !== value.active_claim_ids.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['active_claim_ids'],
        message: 'active_claim_ids contains duplicate values.',
      })
    }
    const pinnedIds = value.pinned_artifacts.map((reference) => reference.artifact_id)
    if (new Set(pinnedIds).size !== pinnedIds.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['pinned_artifacts'],
        message: 'pinned_artifacts contains duplicate artifact references.',
      })
    }
    for (const [actionIndex, action] of value.attempted_actions.entries()) {
      const resultIds = action.result_artifacts.map((reference) => reference.artifact_id)
      if (new Set(resultIds).size !== resultIds.length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['attempted_actions', actionIndex, 'result_artifacts'],
          message: 'result_artifacts contains duplicate artifact references.',
        })
      }
    }
  })

export type AnalysisCaseArtifactReference = z.infer<typeof AnalysisCaseArtifactReferenceSchema>
export type AnalysisCaseAttemptedActionDraft = z.infer<
  typeof AnalysisCaseAttemptedActionDraftSchema
>
export type AnalysisCaseAttemptedAction = z.infer<typeof AnalysisCaseAttemptedActionSchema>
export type AnalysisCaseStateDraft = z.infer<typeof AnalysisCaseStateDraftSchema>
export type AnalysisCaseProducer = z.infer<typeof AnalysisCaseProducerSchema>
export type AnalysisCaseStateArtifact = z.infer<typeof AnalysisCaseStateArtifactSchema>

export interface CanonicalizedAnalysisCaseState {
  attempted_actions: AnalysisCaseAttemptedAction[]
  pinned_artifacts: AnalysisCaseArtifactReference[]
  errors: string[]
}

export interface AnalysisCaseStateArtifactRef extends ArtifactRef {
  created_at: string
}

export interface LoadedAnalysisCaseState {
  artifact: AnalysisCaseStateArtifactRef
  payload: AnalysisCaseStateArtifact
  session_tags: string[]
}

export interface LoadAnalysisCaseStateOptions {
  caseId?: string
  sessionTag?: string
  maxArtifacts?: number
}

export interface AnalysisCaseStateIndex {
  byCaseId: Map<string, LoadedAnalysisCaseState>
  case_states: LoadedAnalysisCaseState[]
  artifact_ids: string[]
  session_tags: string[]
  earliest_created_at: string | null
  latest_created_at: string | null
  marker: string
  scope_note: string
  warnings: string[]
  integrity_issues: AnalysisCaseStateIntegrityIssue[]
  truncated: boolean
  total_artifact_count: number
}

export interface AnalysisCaseStateIntegrityIssue {
  artifact_id: string | null
  attributed_case_key: string | null
  message: string
}

function pathIsWithin(rootPath: string, candidatePath: string): boolean {
  return candidatePath === rootPath || candidatePath.startsWith(rootPath + path.sep)
}

export function analysisCaseKey(caseId: string): string {
  return createHash('sha256').update(caseId).digest('hex')
}

export function analysisCaseStateWriteLeaseKey(sampleId: string, caseId: string): string {
  return `analysis-case-state:${sampleId}:${analysisCaseKey(caseId)}`
}

export function analysisCaseBlockingIntegrityIssues(
  index: AnalysisCaseStateIndex,
  selectedCaseId: string | null
): AnalysisCaseStateIntegrityIssue[] {
  if (!selectedCaseId) {
    return [...index.integrity_issues]
  }
  const selectedCaseKey = analysisCaseKey(selectedCaseId)
  return index.integrity_issues.filter(
    (issue) => issue.attributed_case_key === null || issue.attributed_case_key === selectedCaseKey
  )
}

export function analysisCaseContextMarker(
  index: AnalysisCaseStateIndex,
  selectedCaseId: string | null,
  entry: LoadedAnalysisCaseState | null
): string {
  const baseMarker = entry ? `${entry.artifact.id}:${entry.artifact.sha256}` : 'none'
  const integrityState = analysisCaseBlockingIntegrityIssues(index, selectedCaseId)
    .map((issue) => ({
      artifact_id: issue.artifact_id,
      attributed_case_key: issue.attributed_case_key,
      message: issue.message,
    }))
    .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)))
  if (integrityState.length === 0) {
    return baseMarker
  }
  const integrityDigest = createHash('sha256').update(JSON.stringify(integrityState)).digest('hex')
  return `${baseMarker}:integrity:${integrityDigest}`
}

function attributedCaseKeyFromArtifactPath(artifactPath: string): string | null {
  const normalized = artifactPath.replace(/\\/g, '/')
  if (path.posix.isAbsolute(normalized)) return null
  const segments = normalized.split('/')
  if (
    segments.length !== 6 ||
    segments.some((segment) => !segment || segment === '.' || segment === '..') ||
    segments[0] !== 'reports' ||
    segments[1] !== 'cases' ||
    !CASE_STATE_SAFE_PATH_SEGMENT_PATTERN.test(segments[2]) ||
    segments[3] !== CASE_STATE_CASE_PARTITION_SEGMENT ||
    !CASE_STATE_CASE_KEY_PATTERN.test(segments[4]) ||
    !CASE_STATE_PARTITION_FILE_PATTERN.test(segments[5])
  ) {
    return null
  }
  return segments[4]
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

interface ReferenceValidationBudget {
  artifactIds: Set<string>
  hashBytes: number
}

async function canonicalizeArtifactReference(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  artifactId: string,
  budget: ReferenceValidationBudget
): Promise<{ reference?: AnalysisCaseArtifactReference; error?: string }> {
  const artifact = database.findArtifact(artifactId)
  if (!artifact) {
    return { error: `Artifact not found: ${artifactId}` }
  }
  if (artifact.sample_id !== sampleId) {
    return { error: `Artifact does not belong to sample: ${artifactId}` }
  }
  if (artifact.type === ANALYSIS_CASE_STATE_ARTIFACT_TYPE) {
    return {
      error: `Case-state artifacts cannot be pinned or recorded as action results: ${artifactId}`,
    }
  }

  try {
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
    const [workspaceRealPath, artifactRealPath] = await Promise.all([
      fs.realpath(workspace.root),
      fs.realpath(absolutePath),
    ])
    if (!pathIsWithin(workspaceRealPath, artifactRealPath)) {
      return { error: `Artifact resolves outside the workspace: ${artifactId}` }
    }
    const stat = await fs.stat(artifactRealPath)
    if (!stat.isFile()) {
      return { error: `Artifact is not a regular file: ${artifactId}` }
    }
    if (!budget.artifactIds.has(artifactId)) {
      if (budget.artifactIds.size + 1 > MAX_REFERENCE_COUNT) {
        return { error: `Case state exceeds the ${MAX_REFERENCE_COUNT}-artifact reference limit.` }
      }
      if (budget.hashBytes + stat.size > MAX_REFERENCE_HASH_BYTES) {
        return { error: `Case-state references exceed the SHA-256 scan budget at: ${artifactId}` }
      }
      budget.artifactIds.add(artifactId)
      budget.hashBytes += stat.size
      const actualSha256 = await sha256File(artifactRealPath)
      if (actualSha256.toLowerCase() !== artifact.sha256.toLowerCase()) {
        return { error: `Artifact SHA-256 mismatch: ${artifactId}` }
      }
    }
    return {
      reference: {
        artifact_id: artifact.id,
        artifact_type: artifact.type,
        artifact_path: artifact.path,
        artifact_sha256: artifact.sha256,
      },
    }
  } catch (error) {
    return {
      error: `Artifact is unreadable: ${artifactId} (${error instanceof Error ? error.message : String(error)})`,
    }
  }
}

export async function validateAndCanonicalizeAnalysisCaseState(input: {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  sampleId: string
  draft: AnalysisCaseStateDraft
}): Promise<CanonicalizedAnalysisCaseState> {
  const draft = AnalysisCaseStateDraftSchema.parse(input.draft)
  const budget: ReferenceValidationBudget = { artifactIds: new Set(), hashBytes: 0 }
  const errors: string[] = []
  const cache = new Map<string, Awaited<ReturnType<typeof canonicalizeArtifactReference>>>()

  const resolve = async (artifactId: string) => {
    const cached = cache.get(artifactId)
    if (cached) return cached
    const result = await canonicalizeArtifactReference(
      input.workspaceManager,
      input.database,
      input.sampleId,
      artifactId,
      budget
    )
    cache.set(artifactId, result)
    return result
  }

  const pinnedArtifacts: AnalysisCaseArtifactReference[] = []
  for (const [index, artifactId] of draft.pinned_artifact_ids.entries()) {
    const result = await resolve(artifactId)
    if (result.reference) pinnedArtifacts.push(result.reference)
    else errors.push(`pinned_artifact_ids[${index}]: ${result.error}`)
  }

  const attemptedActions: AnalysisCaseAttemptedAction[] = []
  for (const [actionIndex, action] of draft.attempted_actions.entries()) {
    const resultArtifacts: AnalysisCaseArtifactReference[] = []
    for (const [referenceIndex, artifactId] of action.result_artifact_ids.entries()) {
      const result = await resolve(artifactId)
      if (result.reference) resultArtifacts.push(result.reference)
      else {
        errors.push(
          `attempted_actions[${actionIndex}].result_artifact_ids[${referenceIndex}]: ${result.error}`
        )
      }
    }
    attemptedActions.push({
      tool: action.tool,
      args_fingerprint: action.args_fingerprint,
      outcome: action.outcome,
      result_artifacts: resultArtifacts,
      ...(action.summary ? { summary: action.summary } : {}),
    })
  }

  return {
    attempted_actions: attemptedActions,
    pinned_artifacts: pinnedArtifacts,
    errors,
  }
}

function sessionTagsForCaseState(
  artifactPath: string,
  payload: AnalysisCaseStateArtifact
): string[] {
  return Array.from(
    new Set(
      [deriveArtifactSessionTag(artifactPath), payload.session_tag]
        .filter((value): value is string => Boolean(value && value.trim()))
        .map((value) => value.trim())
    )
  )
}

export async function loadAnalysisCaseStateIndex(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: LoadAnalysisCaseStateOptions = {}
): Promise<AnalysisCaseStateIndex> {
  const warnings: string[] = []
  const integrityIssues: AnalysisCaseStateIntegrityIssue[] = []
  const addIntegrityIssue = (
    artifactId: string | null,
    attributedCaseKey: string | null,
    message: string
  ) => {
    warnings.push(message)
    integrityIssues.push({
      artifact_id: artifactId,
      attributed_case_key: attributedCaseKey,
      message,
    })
  }
  const workspace = await workspaceManager.getWorkspace(sampleId)
  const workspaceRealPath = await fs.realpath(workspace.root)
  const allArtifacts = database.findArtifactsByType(sampleId, ANALYSIS_CASE_STATE_ARTIFACT_TYPE)
  const hasExplicitLimit =
    typeof options.maxArtifacts === 'number' &&
    Number.isInteger(options.maxArtifacts) &&
    options.maxArtifacts > 0
  const candidates = hasExplicitLimit ? allArtifacts.slice(0, options.maxArtifacts) : allArtifacts
  const truncated = candidates.length < allArtifacts.length
  if (truncated) {
    addIntegrityIssue(
      null,
      null,
      `Case-state scan is incomplete: selected ${candidates.length} of ${allArtifacts.length} artifact(s).`
    )
  }

  const loaded: LoadedAnalysisCaseState[] = []
  for (const artifact of candidates) {
    const attributedCaseKey = attributedCaseKeyFromArtifactPath(artifact.path)
    try {
      const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
      const artifactRealPath = await fs.realpath(absolutePath)
      if (!pathIsWithin(workspaceRealPath, artifactRealPath)) {
        addIntegrityIssue(
          artifact.id,
          attributedCaseKey,
          `Skipped case state that resolves outside the workspace: ${artifact.id}`
        )
        continue
      }
      const stat = await fs.stat(artifactRealPath)
      if (!stat.isFile() || stat.size > MAX_CASE_STATE_BYTES) {
        addIntegrityIssue(
          artifact.id,
          attributedCaseKey,
          `Skipped invalid-size case-state artifact: ${artifact.id}`
        )
        continue
      }
      const content = await fs.readFile(artifactRealPath)
      const actualSha256 = createHash('sha256').update(content).digest('hex')
      if (actualSha256.toLowerCase() !== artifact.sha256.toLowerCase()) {
        addIntegrityIssue(
          artifact.id,
          attributedCaseKey,
          `Skipped case state with SHA-256 mismatch: ${artifact.id}`
        )
        continue
      }
      const parsed = AnalysisCaseStateArtifactSchema.safeParse(
        JSON.parse(content.toString('utf8')) as unknown
      )
      if (!parsed.success || parsed.data.sample_id !== sampleId) {
        addIntegrityIssue(
          artifact.id,
          attributedCaseKey,
          `Skipped invalid case-state artifact: ${artifact.id}`
        )
        continue
      }
      const payloadCaseKey = analysisCaseKey(parsed.data.case_id)
      if (attributedCaseKey && attributedCaseKey !== payloadCaseKey) {
        addIntegrityIssue(
          artifact.id,
          null,
          `Skipped case state whose path partition does not match payload case_id: ${artifact.id}`
        )
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
        session_tags: sessionTagsForCaseState(artifact.path, parsed.data),
      })
    } catch {
      addIntegrityIssue(
        artifact.id,
        attributedCaseKey,
        `Skipped unreadable case-state artifact: ${artifact.id}`
      )
    }
  }

  loaded.sort((left, right) => {
    const createdAtOrder = right.payload.created_at.localeCompare(left.payload.created_at)
    if (createdAtOrder !== 0) return createdAtOrder
    const caseOrder = left.payload.case_id.localeCompare(right.payload.case_id)
    if (caseOrder !== 0) return caseOrder
    const revisionOrder = right.payload.revision - left.payload.revision
    return revisionOrder !== 0 ? revisionOrder : right.artifact.id.localeCompare(left.artifact.id)
  })

  const entriesByCase = new Map<string, LoadedAnalysisCaseState[]>()
  for (const entry of loaded) {
    const entries = entriesByCase.get(entry.payload.case_id) || []
    entries.push(entry)
    entriesByCase.set(entry.payload.case_id, entries)
  }
  for (const [caseId, entries] of entriesByCase) {
    const byRevision = new Map<number, LoadedAnalysisCaseState>()
    for (const entry of [...entries].sort(
      (left, right) => left.payload.revision - right.payload.revision
    )) {
      const existing = byRevision.get(entry.payload.revision)
      if (existing) {
        addIntegrityIssue(
          entry.artifact.id,
          analysisCaseKey(caseId),
          `Duplicate case-state revision ${caseId}@${entry.payload.revision}: ${existing.artifact.id}, ${entry.artifact.id}`
        )
        continue
      }
      byRevision.set(entry.payload.revision, entry)
      if (entry.payload.revision > 1) {
        const previous = byRevision.get(entry.payload.revision - 1)
        if (!previous) {
          addIntegrityIssue(
            entry.artifact.id,
            analysisCaseKey(caseId),
            `Case state ${caseId}@${entry.payload.revision} has no loaded predecessor.`
          )
        } else if (entry.payload.parent_artifact_id !== previous.artifact.id) {
          addIntegrityIssue(
            entry.artifact.id,
            analysisCaseKey(caseId),
            `Case state ${caseId}@${entry.payload.revision} does not reference its predecessor.`
          )
        }
      }
    }
  }

  const caseId = options.caseId ? AnalysisCaseIdSchema.parse(options.caseId) : null
  const sessionTag = options.sessionTag
    ? AnalysisCaseSessionTagSchema.parse(options.sessionTag)
    : null
  const selected = loaded.filter(
    (entry) =>
      (!caseId || entry.payload.case_id === caseId) &&
      (!sessionTag || matchesSessionTag(entry.session_tags, sessionTag))
  )
  const byCaseId = new Map<string, LoadedAnalysisCaseState>()
  for (const entry of selected) {
    const current = byCaseId.get(entry.payload.case_id)
    if (!current || entry.payload.revision > current.payload.revision) {
      byCaseId.set(entry.payload.case_id, entry)
    }
  }
  const createdAt = selected.map((entry) => entry.payload.created_at).sort()
  return {
    byCaseId,
    case_states: selected,
    artifact_ids: selected.map((entry) => entry.artifact.id),
    session_tags: Array.from(new Set(selected.flatMap((entry) => entry.session_tags))).sort(),
    earliest_created_at: createdAt[0] || null,
    latest_created_at: createdAt[createdAt.length - 1] || null,
    marker:
      selected.length > 0
        ? selected.map((entry) => `${entry.artifact.id}:${entry.artifact.sha256}`).join('|')
        : 'none',
    scope_note:
      selected.length > 0
        ? `Selected ${selected.length} immutable case-state artifact(s)${caseId ? ` for case_id=${caseId}` : ''}${sessionTag ? ` using session=${sessionTag}` : ''}.`
        : `No case-state artifacts matched${caseId ? ` case_id=${caseId}` : ''}${sessionTag ? ` session=${sessionTag}` : ''}.`,
    warnings,
    integrity_issues: integrityIssues,
    truncated,
    total_artifact_count: allArtifacts.length,
  }
}

const caseStateWriteLocks = new Map<string, Promise<void>>()

const CaseStateLockRecordSchema = z
  .object({
    version: z.literal(1),
    owner_token: safeCaseText(100).refine(
      (value) =>
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value),
      { message: 'owner_token must be a UUID.' }
    ),
    pid: z.number().int().positive(),
    host_id: safeCaseText(255),
    sample_id: AnalysisCaseSampleIdSchema,
    case_id: AnalysisCaseIdSchema,
    acquired_at: IsoTimestampSchema,
  })
  .strict()

type CaseStateLockRecord = z.infer<typeof CaseStateLockRecordSchema>

interface CaseStateLockFileIdentity {
  dev: number
  ino: number
  size: number
  mtimeMs: number
}

interface CaseStateLockSnapshot {
  record: CaseStateLockRecord
  identity: CaseStateLockFileIdentity
}

interface InspectedCaseStateLock {
  record: CaseStateLockRecord | null
  identity: CaseStateLockFileIdentity
}

interface OwnedCaseStateLock extends CaseStateLockSnapshot {
  handle: Awaited<ReturnType<typeof fs.open>>
}

function lockFileIdentity(stat: {
  dev: number
  ino: number
  size: number
  mtimeMs: number
}): CaseStateLockFileIdentity {
  return { dev: stat.dev, ino: stat.ino, size: stat.size, mtimeMs: stat.mtimeMs }
}

function sameLockFile(
  left: CaseStateLockFileIdentity,
  right: CaseStateLockFileIdentity,
  includeMetadata = true
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    (!includeMetadata || (left.size === right.size && left.mtimeMs === right.mtimeMs))
  )
}

async function inspectCaseStateLock(lockPath: string): Promise<InspectedCaseStateLock | null> {
  let pathStat: Awaited<ReturnType<typeof fs.lstat>>
  try {
    pathStat = await fs.lstat(lockPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error('Case-state lock path is not a regular non-symlink file.')
  }

  const handle = await fs.open(lockPath, 'r')
  try {
    const handleStat = await handle.stat()
    const initialIdentity = lockFileIdentity(pathStat)
    const handleIdentity = lockFileIdentity(handleStat)
    if (!handleStat.isFile() || !sameLockFile(initialIdentity, handleIdentity, false)) {
      throw new Error('Case-state lock changed while it was being inspected.')
    }
    let record: CaseStateLockRecord | null = null
    if (handleStat.size > 0 && handleStat.size <= MAX_CASE_STATE_LOCK_BYTES) {
      try {
        const content = await handle.readFile('utf8')
        const parsed = CaseStateLockRecordSchema.safeParse(JSON.parse(content) as unknown)
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
    const finalIdentity = lockFileIdentity(finalPathStat)
    if (
      finalPathStat.isSymbolicLink() ||
      !finalPathStat.isFile() ||
      !sameLockFile(handleIdentity, finalIdentity)
    ) {
      throw new Error('Case-state lock changed while it was being inspected.')
    }
    return { record, identity: finalIdentity }
  } finally {
    await handle.close().catch(() => undefined)
  }
}

async function readCaseStateLock(lockPath: string): Promise<CaseStateLockSnapshot | null> {
  const inspected = await inspectCaseStateLock(lockPath)
  if (!inspected) return null
  if (!inspected.record) {
    throw new Error('Case-state lock metadata is malformed.')
  }
  return { record: inspected.record, identity: inspected.identity }
}

function processIsDefinitelyDead(pid: number): boolean {
  if (pid === process.pid) return false
  try {
    process.kill(pid, 0)
    return false
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ESRCH'
  }
}

function lockOwnershipMatches(
  record: CaseStateLockRecord,
  sampleId: string,
  caseId: string
): boolean {
  return record.sample_id === sampleId && record.case_id === caseId
}

async function recoverStaleCaseStateLock(
  lockPath: string,
  sampleId: string,
  caseId: string
): Promise<boolean> {
  const snapshot = await inspectCaseStateLock(lockPath)
  if (!snapshot) return true
  const now = Date.now()
  const fileIsStale = now - snapshot.identity.mtimeMs >= ANALYSIS_CASE_STATE_LOCK_STALE_MS

  if (!snapshot.record) {
    if (!fileIsStale) return false
    const confirmation = await inspectCaseStateLock(lockPath)
    if (
      !confirmation ||
      confirmation.record !== null ||
      !sameLockFile(confirmation.identity, snapshot.identity)
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
      const moved = await inspectCaseStateLock(movedPath)
      if (!moved || moved.record !== null || !sameLockFile(moved.identity, snapshot.identity)) {
        await restoreMovedCaseStateLock(movedPath, lockPath)
        return false
      }
      await fs.unlink(movedPath)
      return true
    } catch (error) {
      await restoreMovedCaseStateLock(movedPath, lockPath).catch(() => undefined)
      throw error
    }
  }

  if (!lockOwnershipMatches(snapshot.record, sampleId, caseId)) {
    throw new Error('Case-state lock ownership does not match the requested sample/case.')
  }
  const acquiredAt = Date.parse(snapshot.record.acquired_at)
  const metadataIsStale = now - acquiredAt >= ANALYSIS_CASE_STATE_LOCK_STALE_MS
  const ownerIsLocal = snapshot.record.host_id === hostname()
  if (
    !metadataIsStale ||
    !fileIsStale ||
    (ownerIsLocal && !processIsDefinitelyDead(snapshot.record.pid))
  ) {
    return false
  }

  const confirmation = await inspectCaseStateLock(lockPath)
  if (!confirmation) return true
  if (
    !confirmation.record ||
    confirmation.record.owner_token !== snapshot.record.owner_token ||
    !lockOwnershipMatches(confirmation.record, sampleId, caseId) ||
    !sameLockFile(confirmation.identity, snapshot.identity)
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
    const moved = await inspectCaseStateLock(movedPath)
    if (
      !moved ||
      !moved.record ||
      moved.record.owner_token !== snapshot.record.owner_token ||
      !lockOwnershipMatches(moved.record, sampleId, caseId) ||
      !sameLockFile(moved.identity, snapshot.identity)
    ) {
      await restoreMovedCaseStateLock(movedPath, lockPath)
      return false
    }
    await fs.unlink(movedPath)
    return true
  } catch (error) {
    await restoreMovedCaseStateLock(movedPath, lockPath).catch(() => undefined)
    throw error
  }
}

async function restoreMovedCaseStateLock(movedPath: string, lockPath: string): Promise<void> {
  try {
    await fs.link(movedPath, lockPath)
    await fs.unlink(movedPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
}

async function removeCaseStateLockWithIdentity(
  lockPath: string,
  identity: CaseStateLockFileIdentity
): Promise<void> {
  const movedPath = `${lockPath}.cleanup-${randomUUID()}`
  try {
    await fs.rename(lockPath, movedPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  try {
    const moved = lockFileIdentity(await fs.lstat(movedPath))
    if (!sameLockFile(moved, identity, false)) {
      await restoreMovedCaseStateLock(movedPath, lockPath)
      return
    }
    await fs.unlink(movedPath)
  } catch (error) {
    await restoreMovedCaseStateLock(movedPath, lockPath).catch(() => undefined)
    throw error
  }
}

async function acquireCaseStateLock(
  lockPath: string,
  sampleId: string,
  caseId: string
): Promise<OwnedCaseStateLock> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let handle: Awaited<ReturnType<typeof fs.open>> | undefined
    try {
      handle = await fs.open(lockPath, 'wx')
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      const recovered =
        attempt === 0 && (await recoverStaleCaseStateLock(lockPath, sampleId, caseId))
      if (recovered) continue
      throw new Error('Case state is locked by another live or recently-active process.', {
        cause: error,
      })
    }

    const record: CaseStateLockRecord = {
      version: 1,
      owner_token: randomUUID(),
      pid: process.pid,
      host_id: hostname(),
      sample_id: sampleId,
      case_id: caseId,
      acquired_at: new Date().toISOString(),
    }
    try {
      await handle.writeFile(JSON.stringify(record), 'utf8')
      await handle.sync()
      const identity = lockFileIdentity(await handle.stat())
      return { handle, record, identity }
    } catch (error) {
      const identity = await handle
        .stat()
        .then(lockFileIdentity)
        .catch(() => null)
      await handle.close().catch(() => undefined)
      if (identity) {
        await removeCaseStateLockWithIdentity(lockPath, identity).catch(() => undefined)
      }
      throw error
    }
  }
  throw new Error('Case state lock could not be acquired.')
}

async function releaseCaseStateLock(lockPath: string, owned: OwnedCaseStateLock): Promise<void> {
  await owned.handle.close().catch(() => undefined)
  const movedPath = `${lockPath}.release-${owned.record.owner_token}`
  try {
    await fs.rename(lockPath, movedPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    return
  }
  try {
    const current = await readCaseStateLock(movedPath)
    if (
      current &&
      current.record.owner_token === owned.record.owner_token &&
      lockOwnershipMatches(current.record, owned.record.sample_id, owned.record.case_id) &&
      sameLockFile(current.identity, owned.identity, false)
    ) {
      await fs.unlink(movedPath)
      return
    }
    await restoreMovedCaseStateLock(movedPath, lockPath)
  } catch {
    // Fail closed: preserve an unverified or replaced lock under its quarantine path.
  }
}

async function withCaseStateWriteLock<T>(
  sampleId: string,
  caseId: string,
  workspaceRoot: string,
  database: DatabaseManager,
  operation: (lease: ContextWriteLeaseGuard) => Promise<T>
): Promise<T> {
  const key = `${sampleId}:${caseId}`
  const previous = caseStateWriteLocks.get(key) ?? Promise.resolve()
  let release: () => void = () => undefined
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const queued = previous.then(() => gate)
  caseStateWriteLocks.set(key, queued)
  await previous

  try {
    return await withContextWriteLease({
      database,
      lockKey: analysisCaseStateWriteLeaseKey(sampleId, caseId),
      staleMs: ANALYSIS_CASE_STATE_LOCK_STALE_MS,
      label: 'Case state',
      operation: async (lease) => {
        const lockId = createHash('sha256').update(caseId).digest('hex').slice(0, 20)
        const lockPath = path.join(workspaceRoot, `.analysis-case-${lockId}.lock`)
        let ownedLock: OwnedCaseStateLock | undefined
        try {
          ownedLock = await acquireCaseStateLock(lockPath, sampleId, caseId)
          return await operation(lease)
        } finally {
          if (ownedLock) await releaseCaseStateLock(lockPath, ownedLock)
        }
      },
    })
  } finally {
    release()
    if (caseStateWriteLocks.get(key) === queued) caseStateWriteLocks.delete(key)
  }
}

async function ensureDirectoryIsNotSymlink(directoryPath: string, label: string): Promise<void> {
  try {
    await fs.mkdir(directoryPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
  const stat = await fs.lstat(directoryPath)
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory, not a symlink.`)
  }
}

async function ensureSafeCaseReportDirectory(
  workspace: { root: string; reports: string },
  sessionSegment: string,
  caseId: string
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
  const casesRoot = path.join(reportsRealPath, 'cases')
  await ensureDirectoryIsNotSymlink(casesRoot, 'Case-state root directory')
  const casesRootRealPath = await fs.realpath(casesRoot)
  if (!pathIsWithin(workspaceRealPath, casesRootRealPath)) {
    throw new Error('Case-state root directory resolves outside the workspace.')
  }
  const reportDir = path.join(casesRootRealPath, sessionSegment)
  await ensureDirectoryIsNotSymlink(reportDir, 'Case-state session directory')
  const reportDirRealPath = await fs.realpath(reportDir)
  if (!pathIsWithin(workspaceRealPath, reportDirRealPath)) {
    throw new Error('Case-state session directory resolves outside the workspace.')
  }
  const partitionRoot = path.join(reportDirRealPath, CASE_STATE_CASE_PARTITION_SEGMENT)
  await ensureDirectoryIsNotSymlink(partitionRoot, 'Case-state partition directory')
  const partitionRootRealPath = await fs.realpath(partitionRoot)
  if (!pathIsWithin(workspaceRealPath, partitionRootRealPath)) {
    throw new Error('Case-state partition directory resolves outside the workspace.')
  }
  const caseDirectory = path.join(partitionRootRealPath, analysisCaseKey(caseId))
  await ensureDirectoryIsNotSymlink(caseDirectory, 'Case-state case directory')
  const caseDirectoryRealPath = await fs.realpath(caseDirectory)
  if (!pathIsWithin(workspaceRealPath, caseDirectoryRealPath)) {
    throw new Error('Case-state case directory resolves outside the workspace.')
  }
  return { workspaceRealPath, reportDirRealPath: caseDirectoryRealPath }
}

async function validateCanonicalReferences(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  payload: AnalysisCaseStateArtifact
): Promise<string[]> {
  const references = [
    ...payload.pinned_artifacts,
    ...payload.attempted_actions.flatMap((action) => action.result_artifacts),
  ]
  const budget: ReferenceValidationBudget = { artifactIds: new Set(), hashBytes: 0 }
  const cache = new Map<string, Awaited<ReturnType<typeof canonicalizeArtifactReference>>>()
  const errors: string[] = []
  for (const reference of references) {
    let result = cache.get(reference.artifact_id)
    if (!result) {
      result = await canonicalizeArtifactReference(
        workspaceManager,
        database,
        payload.sample_id,
        reference.artifact_id,
        budget
      )
      cache.set(reference.artifact_id, result)
    }
    if (!result.reference) {
      errors.push(result.error || `Artifact reference is invalid: ${reference.artifact_id}`)
      continue
    }
    if (JSON.stringify(result.reference) !== JSON.stringify(reference)) {
      errors.push(`Artifact reference metadata is stale or forged: ${reference.artifact_id}`)
    }
  }
  return errors
}

export async function persistAnalysisCaseStateArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  payload: AnalysisCaseStateArtifact
): Promise<ArtifactRef> {
  const validatedPayload = AnalysisCaseStateArtifactSchema.parse(payload)
  const workspace = await workspaceManager.createWorkspace(validatedPayload.sample_id)
  return await withCaseStateWriteLock(
    validatedPayload.sample_id,
    validatedPayload.case_id,
    workspace.root,
    database,
    async (lease) => {
      const existingArtifacts = database.findArtifactsByType(
        validatedPayload.sample_id,
        ANALYSIS_CASE_STATE_ARTIFACT_TYPE
      )
      const index = await loadAnalysisCaseStateIndex(
        workspaceManager,
        database,
        validatedPayload.sample_id
      )
      const targetCaseKey = analysisCaseKey(validatedPayload.case_id)
      const blockingIssues = index.integrity_issues.filter(
        (issue) => issue.attributed_case_key === null || issue.attributed_case_key === targetCaseKey
      )
      const accountedArtifactIds = new Set([
        ...index.case_states.map((entry) => entry.artifact.id),
        ...index.integrity_issues
          .map((issue) => issue.artifact_id)
          .filter((artifactId): artifactId is string => artifactId !== null),
      ])
      const hasUnaccountedArtifact = existingArtifacts.some(
        (artifact) => !accountedArtifactIds.has(artifact.id)
      )
      if (blockingIssues.length > 0 || hasUnaccountedArtifact) {
        throw new Error(
          'Cannot append case state because the target Case history or an existing case-state artifact with unknown attribution is invalid or unreadable.'
        )
      }
      const latest = index.byCaseId.get(validatedPayload.case_id) || null
      const expectedRevision = (latest?.payload.revision || 0) + 1
      const expectedParentId = latest?.artifact.id || null
      if (
        validatedPayload.revision !== expectedRevision ||
        validatedPayload.parent_artifact_id !== expectedParentId
      ) {
        throw new Error(
          `Case-state revision conflict: expected revision ${expectedRevision} with parent ${expectedParentId || 'null'}.`
        )
      }
      const referenceErrors = await validateCanonicalReferences(
        workspaceManager,
        database,
        validatedPayload
      )
      if (referenceErrors.length > 0) {
        throw new Error(`Case-state reference validation failed: ${referenceErrors.join(' ')}`)
      }

      const sessionSegment = sanitizePathSegment(
        validatedPayload.session_tag || undefined,
        'default'
      )
      const { workspaceRealPath, reportDirRealPath } = await ensureSafeCaseReportDirectory(
        workspace,
        sessionSegment,
        validatedPayload.case_id
      )
      const artifactId = randomUUID()
      const caseSegment = sanitizePathSegment(validatedPayload.case_id, 'case')
      const fileName = `${caseSegment}_r${validatedPayload.revision}_${artifactId.slice(0, 12)}.json`
      const absolutePath = path.join(reportDirRealPath, fileName)
      const temporaryPath = path.join(reportDirRealPath, `.${fileName}.${randomUUID()}.tmp`)
      const serialized = JSON.stringify(validatedPayload, null, 2)
      const serializedBytes = Buffer.byteLength(serialized, 'utf8')
      if (serializedBytes > MAX_CASE_STATE_BYTES) {
        throw new Error(
          `Case-state payload exceeds the ${MAX_CASE_STATE_BYTES}-byte persistence limit.`
        )
      }
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
        type: ANALYSIS_CASE_STATE_ARTIFACT_TYPE,
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
          throw new Error('Case state lost its context write lease before Artifact commit.')
        }
      } catch (error) {
        await fs.unlink(absolutePath).catch(() => undefined)
        throw error
      }
      return artifact
    }
  )
}
