import { createHash } from 'crypto'
import { createReadStream } from 'fs'
import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { CreateMessageRequest } from '@modelcontextprotocol/sdk/types.js'
import { extractTextBlocks } from '../utils/sampling-helpers.js'
import type { ArtifactRef, ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager, Artifact, Function as DbFunction } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { SamplingClient } from '../core/registrar.js'
import { createReportSummarizeHandler } from '../plugins/reporting/tools/report-summarize.js'
import { loadSemanticFunctionExplanationIndex } from '../artifacts/semantic-name-suggestion-artifacts.js'
import {
  loadAnalysisClaimLedgerIndex,
  scopeAnalysisClaimLedgerIndex,
  type AnalysisClaimLedgerIndex,
} from '../artifacts/analysis-claim-artifacts.js'
import {
  AnalysisCaseIdSchema,
  analysisCaseBlockingIntegrityIssues,
  analysisCaseContextMarker,
  loadAnalysisCaseStateIndex,
  type AnalysisCaseStateIndex,
  type LoadedAnalysisCaseState,
} from '../artifacts/analysis-case-artifacts.js'
import { isContextOnlyArtifactType } from '../artifacts/context-only-artifacts.js'
import {
  SUMMARY_DEEP_DIGEST_ARTIFACT_TYPE,
  SUMMARY_FINAL_DIGEST_ARTIFACT_TYPE,
  SUMMARY_STATIC_DIGEST_ARTIFACT_TYPE,
  SUMMARY_TRIAGE_DIGEST_ARTIFACT_TYPE,
  loadSummaryDigestArtifactSelection,
  persistSummaryDigestArtifact,
  type SummaryStage,
} from '../artifacts/summary-artifacts.js'
import {
  SummaryArtifactRefSchema,
  TriageStageDigestSchema,
  StaticStageDigestSchema,
  DeepStageDigestSchema,
  FinalStageDigestSchema,
  FunctionExplanationPreviewSchema,
  ExplanationGraphSummarySchema,
  ClaimLedgerContextSummarySchema,
  CaseStateContextSummarySchema,
  TopFunctionDigestSchema,
  SUMMARY_CONTEXT_LIMITS,
  SummaryDigestReuseFingerprintSchema,
  type SummaryDigestReuseFingerprint,
  buildArtifactRefFromParts,
  buildDeepStageDigest,
  buildFinalStageDigest,
  buildStaticStageDigest,
  buildTriageStageDigest,
} from '../artifacts/summary-digests.js'
import { dedupeArtifactRefs, dedupeStrings } from '../utils/shared-helpers.js'
import { GhidraExecutionSummarySchema } from '../ghidra/ghidra-execution-summary.js'
import {
  CoverageEnvelopeSchema,
  buildCoverageEnvelope,
  classifySampleSizeTier,
  deriveAnalysisBudgetProfile,
} from '../analysis/analysis-coverage.js'
import { getAnalysisRunSummary, createOrReuseAnalysisRun } from '../analysis/analysis-run-state.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'

const TOOL_NAME = 'workflow.summarize'

const WorkflowSummarizeStageSchema = z.enum(['triage', 'static', 'deep', 'final'])

const SummarySamplingPayloadSchema = z
  .object({
    executive_summary: z.string(),
    analyst_summary: z.string(),
    key_findings: z.array(z.string()),
    next_steps: z.array(z.string()),
    unresolved_unknowns: z.array(z.string()),
  })
  .strict()

const PersistedSummaryVisibilitySchema = z.object({
  persisted_run_id: z.string().nullable(),
  reused_stage_artifacts: z.boolean(),
  loaded_run_stages: z.array(z.string()),
  deferred_requirements: z.array(z.string()),
})

export const WorkflowSummarizeInputSchema = z
  .object({
    sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
    through_stage: WorkflowSummarizeStageSchema.default('final').describe(
      'Execute summary generation through this stage and stop there. Stop at triage/static/deep for bounded medium/large-sample reporting, or use final for the full compact staged summary.'
    ),
    session_tag: z
      .string()
      .optional()
      .describe('Optional summary digest session tag used for persisted stage artifact reuse.'),
    case_id: AnalysisCaseIdSchema.optional().describe(
      'Optional Case Workspace selector for final synthesis and digest reuse. Required when the sample has multiple cases; a single case is selected automatically.'
    ),
    reuse_digests: z
      .boolean()
      .default(true)
      .describe(
        'Reuse persisted summary-stage digest artifacts when a matching recent/session-scoped artifact exists.'
      ),
    synthesis_mode: z
      .enum(['auto', 'deterministic', 'sampling'])
      .default('auto')
      .describe(
        'Final-stage synthesis mode. auto prefers client-mediated sampling when available, otherwise deterministic.'
      ),
    force_refresh: z
      .boolean()
      .default(false)
      .describe('Rebuild stage digests instead of reusing cached summary artifacts.'),
    evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Runtime evidence scope forwarded to the compact report builder.'),
    evidence_session_tag: z
      .string()
      .optional()
      .describe('Optional runtime evidence session selector used when evidence_scope=session.'),
    static_scope: z
      .enum(['all', 'latest', 'session'])
      .default('latest')
      .describe('Static-analysis artifact scope forwarded to the compact report builder.'),
    static_session_tag: z
      .string()
      .optional()
      .describe('Optional static-analysis session selector used when static_scope=session.'),
    semantic_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Semantic explanation artifact scope forwarded to the compact report builder.'),
    semantic_session_tag: z
      .string()
      .optional()
      .describe('Optional semantic explanation selector used when semantic_scope=session.'),
    compare_evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .optional()
      .describe(
        'Optional baseline runtime evidence scope passed through to compact report generation.'
      ),
    compare_evidence_session_tag: z.string().optional(),
    compare_static_scope: z
      .enum(['all', 'latest', 'session'])
      .optional()
      .describe(
        'Optional baseline static-analysis scope passed through to compact report generation.'
      ),
    compare_static_session_tag: z.string().optional(),
    compare_semantic_scope: z
      .enum(['all', 'latest', 'session'])
      .optional()
      .describe('Optional baseline semantic scope passed through to compact report generation.'),
    compare_semantic_session_tag: z.string().optional(),
  })
  .refine(
    (value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()),
    {
      message: 'evidence_session_tag is required when evidence_scope=session',
      path: ['evidence_session_tag'],
    }
  )
  .refine(
    (value) => value.static_scope !== 'session' || Boolean(value.static_session_tag?.trim()),
    {
      message: 'static_session_tag is required when static_scope=session',
      path: ['static_session_tag'],
    }
  )
  .refine(
    (value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()),
    {
      message: 'semantic_session_tag is required when semantic_scope=session',
      path: ['semantic_session_tag'],
    }
  )
  .refine(
    (value) =>
      value.compare_evidence_scope !== 'session' ||
      Boolean(value.compare_evidence_session_tag?.trim()),
    {
      message: 'compare_evidence_session_tag is required when compare_evidence_scope=session',
      path: ['compare_evidence_session_tag'],
    }
  )
  .refine(
    (value) =>
      value.compare_static_scope !== 'session' || Boolean(value.compare_static_session_tag?.trim()),
    {
      message: 'compare_static_session_tag is required when compare_static_scope=session',
      path: ['compare_static_session_tag'],
    }
  )
  .refine(
    (value) =>
      value.compare_semantic_scope !== 'session' ||
      Boolean(value.compare_semantic_session_tag?.trim()),
    {
      message: 'compare_semantic_session_tag is required when compare_semantic_scope=session',
      path: ['compare_semantic_session_tag'],
    }
  )

export const WorkflowSummarizeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      through_stage: WorkflowSummarizeStageSchema,
      detail_level: z.literal('compact'),
      tool_surface_role: ToolSurfaceRoleSchema,
      preferred_primary_tools: z.array(z.string()),
      completed_stages: z.array(WorkflowSummarizeStageSchema),
      stages: z.object({
        triage: TriageStageDigestSchema.optional(),
        static: StaticStageDigestSchema.optional(),
        deep: DeepStageDigestSchema.optional(),
        final: FinalStageDigestSchema.optional(),
      }),
      stage_artifacts: z.object({
        triage: SummaryArtifactRefSchema.optional(),
        static: SummaryArtifactRefSchema.optional(),
        deep: SummaryArtifactRefSchema.optional(),
        final: SummaryArtifactRefSchema.optional(),
      }),
      synthesis: z.object({
        requested_mode: z.enum(['auto', 'deterministic', 'sampling']),
        resolved_mode: z.enum(['deterministic', 'sampling']),
        sampling_available: z.boolean(),
        used_existing_stage_artifacts: z.boolean(),
        model_name: z.string().nullable(),
      }),
      explanation_graphs: z.array(ExplanationGraphSummarySchema).optional(),
      explanation_artifacts: z.array(SummaryArtifactRefSchema).optional(),
      claim_context: ClaimLedgerContextSummarySchema.optional(),
      case_context: CaseStateContextSummarySchema.optional(),
      review_required: z.boolean().optional(),
      unresolved_questions: z
        .array(z.string().max(1200))
        .max(SUMMARY_CONTEXT_LIMITS.unresolved_questions)
        .optional(),
      persisted_state_visibility: PersistedSummaryVisibilitySchema.optional(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .extend(CoverageEnvelopeSchema.shape)
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const workflowSummarizeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compatibility staged reporting workflow. Builds or reuses bounded triage/static/deep/final digest artifacts and returns compact final reporting output by stage. ' +
    'Its persisted summaries are context-only and cannot be used as Claim evidence. ' +
    'Final synthesis is isolated to case_id; a sole Case Workspace is auto-selected and multiple cases fail closed without a selector. ' +
    'Prefer workflow.search for the primary AI-facing routing path, then use artifact.read for persisted supporting detail. ' +
    'Read coverage_level, completion_state, known_findings, suspected_findings, unverified_areas, and upgrade_paths on the result before treating the summary as complete. ' +
    '\n\nDecision guide:\n' +
    '- Use when: you want staged digest artifacts, resumable summary generation, or a final compact summary.\n' +
    '- Best for: medium/large samples or any run that already progressed through queued analysis stages.\n' +
    '- Do not use when: you only need a single deterministic digest snapshot; report.summarize is enough.\n' +
    '- Typical next step: use artifact.read or artifacts.list on returned stage_artifacts for supporting detail.\n' +
    '- Common mistake: expecting the workflow to inline raw backend payloads instead of returning digest artifacts.',
  inputSchema: WorkflowSummarizeInputSchema,
  outputSchema: WorkflowSummarizeOutputSchema,
  aspects: {
    formats: ['artifact', 'report'],
    platforms: ['all', 'cross-platform'],
    execution: ['static', 'correlation'],
    safety: ['passive'],
  },
  artifacts: [
    {
      type: SUMMARY_TRIAGE_DIGEST_ARTIFACT_TYPE,
      description: 'Context-only triage summary digest',
      mime: 'application/json',
    },
    {
      type: SUMMARY_STATIC_DIGEST_ARTIFACT_TYPE,
      description: 'Context-only static summary digest',
      mime: 'application/json',
    },
    {
      type: SUMMARY_DEEP_DIGEST_ARTIFACT_TYPE,
      description: 'Context-only deep summary digest',
      mime: 'application/json',
    },
    {
      type: SUMMARY_FINAL_DIGEST_ARTIFACT_TYPE,
      description: 'Context-only final summary digest',
      mime: 'application/json',
    },
  ],
}

function extractCoverage(payload: unknown): z.infer<typeof CoverageEnvelopeSchema> | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }
  const parsed = CoverageEnvelopeSchema.safeParse(payload)
  return parsed.success ? parsed.data : null
}

interface WorkflowSummarizeDependencies {
  reportSummarizeHandler?: (args: ToolArgs) => Promise<WorkerResult>
  samplingRequester?: (params: CreateMessageRequest['params']) => Promise<any>
  clientCapabilitiesProvider?: () => { sampling?: unknown } | undefined
  clientVersionProvider?: () => { name?: string; version?: string } | undefined
}

function toolMetrics(startTime: number) {
  return {
    elapsed_ms: Date.now() - startTime,
    tool: TOOL_NAME,
  }
}

function artifactRefFromArtifact(artifact: Artifact, stage: SummaryStage) {
  return buildArtifactRefFromParts({
    id: artifact.id,
    type: artifact.type,
    path: artifact.path,
    sha256: artifact.sha256,
    mime: artifact.mime,
    metadata: {
      summary_stage: stage,
    },
  })
}

function sourceArtifactRefsOnly(refs: ArtifactRef[]): ArtifactRef[] {
  return dedupeArtifactRefs(refs).filter((ref) => !isContextOnlyArtifactType(ref.type))
}

function applySamplingNarrative(
  deterministicDigest: z.infer<typeof FinalStageDigestSchema>,
  sampled: z.infer<typeof SummarySamplingPayloadSchema>,
  modelName: string | null
): z.infer<typeof FinalStageDigestSchema> {
  return FinalStageDigestSchema.parse({
    ...deterministicDigest,
    synthesis_mode: 'sampling',
    model_name: modelName,
    executive_summary: sampled.executive_summary,
    analyst_summary: sampled.analyst_summary,
    next_steps: sampled.next_steps.slice(0, 5),
    unresolved_unknowns: sampled.unresolved_unknowns.slice(0, 5),
    // 有证据支撑的字段只从确定性摘要重建。采样候选发现仅为兼容解析，不能进入证据谱系。
    key_findings: [...deterministicDigest.key_findings],
    known_findings: [...deterministicDigest.known_findings],
    suspected_findings: [...deterministicDigest.suspected_findings],
    unverified_areas: [...deterministicDigest.unverified_areas],
    coverage_gaps: [...deterministicDigest.coverage_gaps],
    source_artifact_refs: sourceArtifactRefsOnly(
      deterministicDigest.source_artifact_refs as ArtifactRef[]
    ),
  })
}

function getArtifactMap(database: DatabaseManager, sampleId: string) {
  return new Map(database.findArtifacts(sampleId).map((item) => [item.id, item]))
}

function parseSummaryJsonCandidate(rawText: string) {
  const candidates: string[] = []
  const start = rawText.indexOf('{')
  const end = rawText.lastIndexOf('}')
  if (start >= 0 && end > start) {
    candidates.push(rawText.slice(start, end + 1))
  }
  candidates.push(rawText)

  for (const candidate of candidates) {
    try {
      return SummarySamplingPayloadSchema.parse(JSON.parse(candidate))
    } catch {
      continue
    }
  }

  throw new Error(
    'Sampling response could not be parsed as strict JSON summary payload. Return JSON only.'
  )
}

function buildSamplingRequest(
  triageDigest: z.infer<typeof TriageStageDigestSchema>,
  staticDigest: z.infer<typeof StaticStageDigestSchema> | null,
  deepDigest: z.infer<typeof DeepStageDigestSchema> | null,
  summaryContext: FinalSummaryContext
): CreateMessageRequest['params'] {
  const systemPrompt = [
    'You are an evidence-grounded reverse-engineering reporting assistant.',
    'Return strict JSON only.',
    'Do not call tools.',
    'Do not include markdown, commentary, or code fences.',
    'Use only the supplied staged digests and context-only analysis state.',
    'Treat Claim Ledger and Case State as analyst context, never as underlying evidence.',
    'Preserve uncertainty explicitly.',
  ].join(' ')

  const taskPrompt = JSON.stringify(
    {
      task: 'Synthesize a compact final analyst summary from staged digests only.',
      output_contract: {
        executive_summary: 'string',
        analyst_summary: 'string',
        key_findings: ['string'],
        next_steps: ['string'],
        unresolved_unknowns: ['string'],
      },
      boundary_rules: [
        'Do not claim skipped stages were completed.',
        'Preserve the distinction between known findings, suspected findings, and unverified areas from the digests.',
        'Claim Ledger and Case State are context-only: do not present them as source evidence or copy their artifact identifiers into findings.',
        'Preserve review-required state and unresolved questions in the analyst narrative without resolving them speculatively.',
      ],
      digests: {
        triage: triageDigest,
        static: staticDigest,
        deep: deepDigest,
      },
      analysis_context: {
        claim_context: summaryContext.claimContext,
        case_context: summaryContext.caseContext,
        review_required: summaryContext.reviewRequired,
        unresolved_questions: summaryContext.unresolvedQuestions,
      },
    },
    null,
    2
  )

  return {
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: taskPrompt,
        },
      },
    ],
    systemPrompt,
    maxTokens: 1200,
    temperature: 0.2,
    modelPreferences: {
      intelligencePriority: 0.6,
      speedPriority: 0.4,
      costPriority: 0.4,
    },
  }
}

function buildTopFunctions(functions: DbFunction[]) {
  return functions.map((item) =>
    TopFunctionDigestSchema.parse({
      address: item.address,
      name: item.name || null,
      score: typeof item.score === 'number' ? item.score : null,
      summary: item.summary || null,
    })
  )
}

async function loadFunctionExplanationSummaries(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options?: { scope?: 'all' | 'latest' | 'session'; sessionTag?: string }
) {
  const index = await loadSemanticFunctionExplanationIndex(workspaceManager, database, sampleId, {
    scope: options?.scope,
    sessionTag: options?.sessionTag,
  })
  const explanations = Array.from(index.byAddress.values())
  explanations.sort((a, b) => {
    if (b.confidence !== a.confidence) {
      return b.confidence - a.confidence
    }
    return (b.created_at || '').localeCompare(a.created_at || '')
  })
  return explanations.slice(0, 6).map((item) =>
    FunctionExplanationPreviewSchema.parse({
      address: item.address,
      function: item.function,
      behavior: item.behavior,
      summary: item.summary,
      confidence: item.confidence,
      rewrite_guidance: (item.rewrite_guidance || []).slice(0, 4),
      source: item.model_name || item.client_name || null,
    })
  )
}

type ClaimLedgerContextSummary = z.infer<typeof ClaimLedgerContextSummarySchema>
type CaseStateContextSummary = z.infer<typeof CaseStateContextSummarySchema>

interface FinalSummaryContext {
  claimContext: ClaimLedgerContextSummary
  caseContext: CaseStateContextSummary
  reviewRequired: boolean
  unresolvedQuestions: string[]
}

function normalizedSelector(value: string | null | undefined): string | null {
  const normalized = value?.trim()
  return normalized ? normalized : null
}

interface SummaryFingerprintBaseState {
  sourceArtifacts: Array<{
    id: string
    type: string
    path: string
    sha256: string
    mime: string | null
    created_at: string
  }>
  evidenceStateSha256: string
  functionStateSha256: string
  analysisStateSha256: string
  analysisRunStateSha256: string
  analysisRunStageStateSha256: string
  artifactIntegrityWarnings: string[]
}

function hashSummaryFingerprintState(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex')
}

function summaryPathIsWithin(rootPath: string, candidatePath: string): boolean {
  return candidatePath === rootPath || candidatePath.startsWith(rootPath + path.sep)
}

async function hashSummarySourceFile(artifactPath: string): Promise<string> {
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(artifactPath)) {
    hash.update(chunk)
  }
  return hash.digest('hex')
}

async function loadSummaryFingerprintBaseState(input: {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  sampleId: string
}): Promise<SummaryFingerprintBaseState> {
  const artifactRows = input.database
    .findArtifacts(input.sampleId)
    .filter((artifact) => !isContextOnlyArtifactType(artifact.type))
  const sourceArtifacts = artifactRows
    .map((artifact) => ({
      id: artifact.id,
      type: artifact.type,
      path: artifact.path,
      sha256: artifact.sha256.toLowerCase(),
      mime: artifact.mime,
      created_at: artifact.created_at,
    }))
    .sort((left, right) => {
      const idOrder = left.id.localeCompare(right.id)
      return idOrder !== 0 ? idOrder : left.sha256.localeCompare(right.sha256)
    })
  const workspace = await input.workspaceManager.createWorkspace(input.sampleId)
  const workspaceRealPath = await fs.realpath(workspace.root)
  const artifactIntegrityWarnings: string[] = []
  for (const artifact of artifactRows) {
    try {
      const absolutePath = input.workspaceManager.normalizePath(workspace.root, artifact.path)
      const artifactRealPath = await fs.realpath(absolutePath)
      if (!summaryPathIsWithin(workspaceRealPath, artifactRealPath)) {
        throw new Error('path resolves outside the workspace')
      }
      const stat = await fs.stat(artifactRealPath)
      if (!stat.isFile()) {
        throw new Error('path is not a regular file')
      }
      const actualSha256 = await hashSummarySourceFile(artifactRealPath)
      if (actualSha256.toLowerCase() !== artifact.sha256.toLowerCase()) {
        throw new Error('actual SHA-256 does not match the artifact record')
      }
    } catch (error) {
      artifactIntegrityWarnings.push(
        `Summary digest source artifact ${artifact.id} failed integrity validation: ${
          error instanceof Error ? error.message : String(error)
        }.`
      )
    }
  }
  const evidenceState = input.database
    .findAnalysisEvidenceBySample(input.sampleId)
    .filter((row) => row.evidence_family !== 'summary')
    .map((row) => ({
      id: row.id,
      evidence_family: row.evidence_family,
      backend: row.backend,
      mode: row.mode,
      compatibility_marker: row.compatibility_marker,
      freshness_marker: row.freshness_marker,
      updated_at: row.updated_at,
      provenance_json: row.provenance_json,
      metadata_json: row.metadata_json,
      result_json: row.result_json,
      artifact_refs_json: row.artifact_refs_json,
    }))
    .sort((left, right) => left.id.localeCompare(right.id))
  const functionState = input.database
    .findFunctions(input.sampleId)
    .map((entry) => ({
      sample_id: entry.sample_id,
      address: entry.address,
      name: entry.name,
      size: entry.size,
      score: entry.score,
      tags: entry.tags,
      summary: entry.summary,
      caller_count: entry.caller_count,
      callee_count: entry.callee_count,
      is_entry_point: entry.is_entry_point,
      is_exported: entry.is_exported,
      callees: entry.callees,
    }))
    .sort((left, right) => left.address.localeCompare(right.address))
  const analysisState = input.database
    .findAnalysesBySample(input.sampleId)
    .map((entry) => ({
      id: entry.id,
      sample_id: entry.sample_id,
      stage: entry.stage,
      backend: entry.backend,
      status: entry.status,
      started_at: entry.started_at,
      finished_at: entry.finished_at,
      output_json: entry.output_json,
      metrics_json: entry.metrics_json,
    }))
    .sort((left, right) => left.id.localeCompare(right.id))
  const analysisRunState = input.database
    .findAnalysisRunsBySample(input.sampleId)
    .map((entry) => ({
      id: entry.id,
      sample_id: entry.sample_id,
      sample_sha256: entry.sample_sha256,
      goal: entry.goal,
      depth: entry.depth,
      backend_policy: entry.backend_policy,
      compatibility_marker: entry.compatibility_marker,
      pipeline_version: entry.pipeline_version,
      sample_size_tier: entry.sample_size_tier,
      analysis_budget_profile: entry.analysis_budget_profile,
      status: entry.status,
      latest_stage: entry.latest_stage,
      stage_plan_json: entry.stage_plan_json,
      artifact_refs_json: entry.artifact_refs_json,
      metadata_json: entry.metadata_json,
      created_at: entry.created_at,
      updated_at: entry.updated_at,
      finished_at: entry.finished_at,
      reused_from_run_id: entry.reused_from_run_id,
    }))
    .sort((left, right) => left.id.localeCompare(right.id))
  const analysisRunStageState = analysisRunState
    .flatMap((run) => input.database.findAnalysisRunStages(run.id))
    .map((entry) => ({
      run_id: entry.run_id,
      stage: entry.stage,
      status: entry.status,
      execution_state: entry.execution_state,
      tool: entry.tool,
      job_id: entry.job_id,
      result_json: entry.result_json,
      artifact_refs_json: entry.artifact_refs_json,
      coverage_json: entry.coverage_json,
      metadata_json: entry.metadata_json,
      created_at: entry.created_at,
      updated_at: entry.updated_at,
      started_at: entry.started_at,
      finished_at: entry.finished_at,
    }))
    .sort((left, right) => {
      const runOrder = left.run_id.localeCompare(right.run_id)
      return runOrder !== 0 ? runOrder : left.stage.localeCompare(right.stage)
    })

  return {
    sourceArtifacts,
    evidenceStateSha256: hashSummaryFingerprintState(evidenceState),
    functionStateSha256: hashSummaryFingerprintState(functionState),
    analysisStateSha256: hashSummaryFingerprintState(analysisState),
    analysisRunStateSha256: hashSummaryFingerprintState(analysisRunState),
    analysisRunStageStateSha256: hashSummaryFingerprintState(analysisRunStageState),
    artifactIntegrityWarnings,
  }
}

function buildSummaryReuseFingerprint(input: {
  baseState: SummaryFingerprintBaseState
  request: z.infer<typeof WorkflowSummarizeInputSchema>
  stage: SummaryStage
  resolvedSynthesisMode: 'deterministic' | 'sampling'
  summaryContext?: FinalSummaryContext
}): SummaryDigestReuseFingerprint {
  const fingerprintInput = {
    schema_version: 1 as const,
    stage: input.stage,
    resolved_synthesis_mode:
      input.stage === 'final' ? input.resolvedSynthesisMode : 'deterministic',
    input: {
      through_stage: input.request.through_stage,
      summary_session_tag: normalizedSelector(input.request.session_tag),
      case_id:
        input.stage === 'final'
          ? input.summaryContext?.caseContext.case_id || normalizedSelector(input.request.case_id)
          : null,
      evidence_scope: input.request.evidence_scope,
      evidence_session_tag: normalizedSelector(input.request.evidence_session_tag),
      static_scope: input.request.static_scope,
      static_session_tag: normalizedSelector(input.request.static_session_tag),
      semantic_scope: input.request.semantic_scope,
      semantic_session_tag: normalizedSelector(input.request.semantic_session_tag),
      compare_evidence_scope: input.request.compare_evidence_scope || null,
      compare_evidence_session_tag: normalizedSelector(input.request.compare_evidence_session_tag),
      compare_static_scope: input.request.compare_static_scope || null,
      compare_static_session_tag: normalizedSelector(input.request.compare_static_session_tag),
      compare_semantic_scope: input.request.compare_semantic_scope || null,
      compare_semantic_session_tag: normalizedSelector(input.request.compare_semantic_session_tag),
    },
    source_artifacts: input.baseState.sourceArtifacts,
    source_integrity_valid: input.baseState.artifactIntegrityWarnings.length === 0,
    evidence_state_sha256: input.baseState.evidenceStateSha256,
    function_state_sha256: input.baseState.functionStateSha256,
    analysis_state_sha256: input.baseState.analysisStateSha256,
    analysis_run_state_sha256: input.baseState.analysisRunStateSha256,
    analysis_run_stage_state_sha256: input.baseState.analysisRunStageStateSha256,
    claim_context_marker: input.summaryContext?.claimContext.marker || null,
    case_context_marker: input.summaryContext?.caseContext.marker || null,
    context_review_required: input.summaryContext?.reviewRequired ?? null,
  }
  return SummaryDigestReuseFingerprintSchema.parse({
    ...fingerprintInput,
    fingerprint_sha256: createHash('sha256').update(JSON.stringify(fingerprintInput)).digest('hex'),
  })
}

interface SelectedCaseState {
  entry: LoadedAnalysisCaseState | null
  marker: string
}

function truncateContextText(value: string, limit: number): string {
  const normalized = value.trim()
  if (normalized.length <= limit) {
    return normalized
  }
  const suffix = '... [truncated]'
  return `${normalized.slice(0, Math.max(0, limit - suffix.length))}${suffix}`
}

function emptyClaimLedgerContext(): ClaimLedgerContextSummary {
  return ClaimLedgerContextSummarySchema.parse({
    artifact_role: 'context_only',
    marker: 'none',
    claim_set_count: 0,
    active_claim_count: 0,
    included_claim_count: 0,
    status_counts: {
      inferred: 0,
      corroborated: 0,
      contradicted: 0,
      verified: 0,
      rejected: 0,
    },
    claims: [],
    truncated: false,
  })
}

function emptyCaseStateContext(): CaseStateContextSummary {
  return CaseStateContextSummarySchema.parse({
    artifact_role: 'context_only',
    marker: 'none',
    available: false,
    case_id: null,
    revision: null,
    objective: null,
    decision_count: 0,
    decisions: [],
    open_question_count: 0,
    open_questions: [],
    attempted_action_count: 0,
    attempted_actions: [],
    next_action_count: 0,
    next_actions: [],
    active_claim_count: 0,
    pinned_artifact_count: 0,
    truncated: false,
  })
}

function buildClaimLedgerContext(index: AnalysisClaimLedgerIndex): {
  summary: ClaimLedgerContextSummary
  reviewRequired: boolean
  unresolvedQuestions: string[]
} {
  const activeClaims = Array.from(index.byClaimId.values())
  const reviewRequired =
    index.truncated ||
    activeClaims.some(({ claim }) => ['inferred', 'contradicted'].includes(claim.status))
  const unresolvedQuestions = activeClaims
    .filter(
      ({ claim }) =>
        claim.category === 'open_question' && !['verified', 'rejected'].includes(claim.status)
    )
    .map(({ claim }) => truncateContextText(claim.statement, 1200))

  const orderedClaims = [...activeClaims].sort((left, right) => {
    const leftReview = ['inferred', 'contradicted'].includes(left.claim.status) ? 1 : 0
    const rightReview = ['inferred', 'contradicted'].includes(right.claim.status) ? 1 : 0
    if (rightReview !== leftReview) {
      return rightReview - leftReview
    }
    const leftQuestion = left.claim.category === 'open_question' ? 1 : 0
    const rightQuestion = right.claim.category === 'open_question' ? 1 : 0
    if (rightQuestion !== leftQuestion) {
      return rightQuestion - leftQuestion
    }
    if (right.ledger_revision !== left.ledger_revision) {
      return right.ledger_revision - left.ledger_revision
    }
    return left.claim.claim_id.localeCompare(right.claim.claim_id)
  })
  const includedClaims = orderedClaims.slice(0, SUMMARY_CONTEXT_LIMITS.claims)
  const statusCounts = {
    inferred: 0,
    corroborated: 0,
    contradicted: 0,
    verified: 0,
    rejected: 0,
  }
  for (const { claim } of activeClaims) {
    statusCounts[claim.status] += 1
  }

  return {
    summary: ClaimLedgerContextSummarySchema.parse({
      artifact_role: 'context_only',
      marker: index.marker,
      claim_set_count: index.claim_sets.length,
      active_claim_count: activeClaims.length,
      included_claim_count: includedClaims.length,
      status_counts: statusCounts,
      claims: includedClaims.map(({ claim }) => ({
        claim_id: claim.claim_id,
        category: claim.category,
        subject: truncateContextText(claim.subject, 500),
        statement: truncateContextText(claim.statement, 1200),
        status: claim.status,
        source: claim.source,
        review_required: ['inferred', 'contradicted'].includes(claim.status),
      })),
      truncated: index.truncated || activeClaims.length > includedClaims.length,
    }),
    reviewRequired,
    unresolvedQuestions,
  }
}

function selectCaseState(
  index: AnalysisCaseStateIndex,
  requestedCaseId?: string
): SelectedCaseState {
  const availableCaseIds = Array.from(index.byCaseId.keys()).sort()
  if (requestedCaseId) {
    const entry = index.byCaseId.get(requestedCaseId)
    if (!entry) {
      const available = availableCaseIds.length > 0 ? availableCaseIds.join(', ') : 'none'
      throw new Error(
        `Case not found for sample: ${requestedCaseId}. Available case_id values: ${available}.`
      )
    }
    return { entry, marker: analysisCaseContextMarker(index, requestedCaseId, entry) }
  }
  if (availableCaseIds.length > 1) {
    throw new Error(
      `Multiple analysis cases exist for this sample (${availableCaseIds.join(', ')}). Provide case_id to select one; final synthesis is fail-closed to prevent cross-case mixing.`
    )
  }
  const entry = availableCaseIds[0] ? index.byCaseId.get(availableCaseIds[0]) || null : null
  return {
    entry,
    marker: analysisCaseContextMarker(index, entry?.payload.case_id || null, entry),
  }
}

function buildCaseStateContext(
  index: AnalysisCaseStateIndex,
  requestedCaseId?: string
): {
  summary: CaseStateContextSummary
  unresolvedQuestions: string[]
  activeClaimIds: string[] | null
} {
  const selected = selectCaseState(index, requestedCaseId)
  if (!selected.entry) {
    const caseStateConfirmedAbsent =
      index.total_artifact_count === 0 && index.integrity_issues.length === 0
    return {
      summary: {
        ...emptyCaseStateContext(),
        marker: selected.marker,
        truncated: index.truncated,
      },
      unresolvedQuestions: [],
      activeClaimIds: caseStateConfirmedAbsent ? null : [],
    }
  }

  const { payload } = selected.entry
  const decisions = payload.decisions
    .map((item) => truncateContextText(item, 1200))
    .slice(0, SUMMARY_CONTEXT_LIMITS.case_decisions)
  const openQuestions = payload.open_questions
    .map((item) => truncateContextText(item, 1200))
    .slice(0, SUMMARY_CONTEXT_LIMITS.case_open_questions)
  const attemptedActions = payload.attempted_actions
    .map((action) =>
      truncateContextText(
        `${action.tool}: ${action.outcome}${action.summary ? ` — ${action.summary}` : ''}`,
        1200
      )
    )
    .slice(0, SUMMARY_CONTEXT_LIMITS.case_attempted_actions)
  const nextActions = payload.next_actions
    .map((item) => truncateContextText(item, 1200))
    .slice(0, SUMMARY_CONTEXT_LIMITS.case_next_actions)
  const truncated =
    index.truncated ||
    decisions.length < payload.decisions.length ||
    openQuestions.length < payload.open_questions.length ||
    attemptedActions.length < payload.attempted_actions.length ||
    nextActions.length < payload.next_actions.length

  return {
    summary: CaseStateContextSummarySchema.parse({
      artifact_role: 'context_only',
      marker: selected.marker,
      available: true,
      case_id: payload.case_id,
      revision: payload.revision,
      objective: truncateContextText(payload.objective, 1200),
      decision_count: payload.decisions.length,
      decisions,
      open_question_count: payload.open_questions.length,
      open_questions: openQuestions,
      attempted_action_count: payload.attempted_actions.length,
      attempted_actions: attemptedActions,
      next_action_count: payload.next_actions.length,
      next_actions: nextActions,
      active_claim_count: payload.active_claim_ids.length,
      pinned_artifact_count: payload.pinned_artifacts.length,
      truncated,
    }),
    unresolvedQuestions: payload.open_questions.map((item) => truncateContextText(item, 1200)),
    activeClaimIds:
      analysisCaseBlockingIntegrityIssues(index, payload.case_id).length === 0
        ? [...payload.active_claim_ids]
        : [],
  }
}

function caseStateRequiresReview(
  index: AnalysisCaseStateIndex,
  selectedCaseId: string | null
): boolean {
  return analysisCaseBlockingIntegrityIssues(index, selectedCaseId).length > 0
}

export function createWorkflowSummarizeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  mcpServer?: SamplingClient,
  deps?: WorkflowSummarizeDependencies
) {
  const reportSummarizeHandler =
    deps?.reportSummarizeHandler ||
    createReportSummarizeHandler(workspaceManager, database, cacheManager)
  const samplingRequester =
    deps?.samplingRequester ||
    (mcpServer
      ? (params: CreateMessageRequest['params']) => mcpServer.createMessage(params)
      : undefined)
  const clientCapabilitiesProvider =
    deps?.clientCapabilitiesProvider ||
    (mcpServer ? () => mcpServer.getClientCapabilities() : undefined)
  const clientVersionProvider =
    deps?.clientVersionProvider || (mcpServer ? () => mcpServer.getClientVersion() : undefined)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const warnings: string[] = []

    try {
      const input = WorkflowSummarizeInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: toolMetrics(startTime),
        }
      }
      const samplingAvailable = Boolean(
        clientCapabilitiesProvider?.()?.sampling && samplingRequester
      )
      const samplingRequested =
        input.synthesis_mode === 'sampling' ||
        (input.synthesis_mode === 'auto' && samplingAvailable)
      const resolvedSynthesisModeForReuse: 'deterministic' | 'sampling' =
        samplingRequested && samplingAvailable ? 'sampling' : 'deterministic'

      // Check if there's a persisted analysis run for this sample
      // If found, consume run state and stage artifacts instead of rerunning analysis
      const runs = database.findAnalysisRunsBySample(input.sample_id)
      const latestRun =
        runs.length > 0 ? runs.sort((a, b) => b.updated_at.localeCompare(a.updated_at))[0] : null

      // Initialize stage tracking variables
      const completedStages: SummaryStage[] = []
      const stageArtifacts: Partial<Record<SummaryStage, ArtifactRef>> = {}

      if (latestRun && latestRun.status !== 'created') {
        warnings.push(
          `Consuming persisted analysis run state (run_id: ${latestRun.id}, status: ${latestRun.status}, latest_stage: ${latestRun.latest_stage || 'none'}).`
        )

        // Map run stages to summary stages
        const stageMap: Record<string, SummaryStage> = {
          fast_profile: 'triage',
          enrich_static: 'static',
          function_map: 'deep',
          reconstruct: 'deep',
          dynamic_plan: 'triage',
          dynamic_execute: 'triage',
          summarize: 'final',
        }

        // Load stage artifacts from run state
        const runStages = database.findAnalysisRunStages(latestRun.id)
        for (const stage of runStages) {
          if (stage.status === 'completed' && stage.artifact_refs_json) {
            const summaryStage = stageMap[stage.stage]
            if (summaryStage && !stageArtifacts[summaryStage]) {
              try {
                const artifactRefs = JSON.parse(stage.artifact_refs_json) as ArtifactRef[]
                if (artifactRefs.length > 0) {
                  stageArtifacts[summaryStage] = artifactRefs[0]
                  completedStages.push(summaryStage)
                  warnings.push(
                    `Loaded ${summaryStage} stage artifacts from run stage ${stage.stage}.`
                  )
                }
              } catch {
                // Ignore JSON parse errors, continue without this stage's artifacts
              }
            }
          }
        }
      }

      const sampleSizeTier = classifySampleSizeTier(sample.size || 0)
      const analysisBudgetProfile = deriveAnalysisBudgetProfile(
        input.through_stage === 'final'
          ? 'deep'
          : input.through_stage === 'triage'
            ? 'safe'
            : 'balanced',
        sampleSizeTier
      )
      const persistedStateVisibility = PersistedSummaryVisibilitySchema.parse({
        persisted_run_id: latestRun?.id || null,
        reused_stage_artifacts: false,
        loaded_run_stages: latestRun
          ? database.findAnalysisRunStages(latestRun.id).map((stage) => stage.stage)
          : [],
        deferred_requirements: latestRun
          ? []
          : ['analysis_run: no persisted staged analysis run was available for this sample.'],
      })

      const artifactMap = getArtifactMap(database, input.sample_id)
      const stageDigests: Partial<Record<SummaryStage, unknown>> = {}
      const effectiveReuse = input.reuse_digests && !input.force_refresh
      let reusedAnyStage = false
      let compactReportResult: WorkerResult | null = null
      let finalSummaryContextPromise: Promise<FinalSummaryContext> | null = null
      let summaryFingerprintBaseStatePromise: Promise<SummaryFingerprintBaseState> | null = null
      const getSummaryFingerprintBaseState = (): Promise<SummaryFingerprintBaseState> => {
        if (summaryFingerprintBaseStatePromise === null) {
          summaryFingerprintBaseStatePromise = loadSummaryFingerprintBaseState({
            workspaceManager,
            database,
            sampleId: input.sample_id,
          })
        }
        return summaryFingerprintBaseStatePromise
      }
      const publishSummarySourceIntegrityWarnings = (baseState: SummaryFingerprintBaseState) => {
        for (const warning of baseState.artifactIntegrityWarnings) {
          if (!warnings.includes(warning)) warnings.push(warning)
        }
      }
      const currentStageArtifactRefs = () =>
        Object.values(stageArtifacts).filter((item): item is ArtifactRef => Boolean(item))

      const getFinalSummaryContext = async (): Promise<FinalSummaryContext> => {
        if (finalSummaryContextPromise !== null) {
          return finalSummaryContextPromise
        }
        finalSummaryContextPromise = (async () => {
          await workspaceManager.createWorkspace(input.sample_id)
          let claimContext = emptyClaimLedgerContext()
          let caseContext = emptyCaseStateContext()
          let claimReviewRequired = false
          let caseReviewRequired = false
          let claimQuestions: string[] = []
          let caseQuestions: string[] = []
          let activeClaimIds: string[] | null = null
          const [caseResult] = await Promise.allSettled([
            loadAnalysisCaseStateIndex(workspaceManager, database, input.sample_id),
          ])

          if (caseResult.status === 'fulfilled') {
            const built = buildCaseStateContext(caseResult.value, input.case_id)
            caseContext = built.summary
            caseReviewRequired =
              built.summary.truncated ||
              caseStateRequiresReview(caseResult.value, built.summary.case_id)
            caseQuestions = built.unresolvedQuestions
            activeClaimIds = built.activeClaimIds
            warnings.push(...caseResult.value.warnings.map((item) => `Case State context: ${item}`))
          } else {
            if (input.case_id) {
              throw new Error(
                `Case State context could not be loaded for case_id=${input.case_id}: ${
                  caseResult.reason instanceof Error
                    ? caseResult.reason.message
                    : String(caseResult.reason)
                }`
              )
            }
            caseReviewRequired = true
            activeClaimIds = []
            warnings.push(
              `Case State context could not be loaded: ${
                caseResult.reason instanceof Error
                  ? caseResult.reason.message
                  : String(caseResult.reason)
              }`
            )
          }

          const [claimResult] = await Promise.allSettled([
            loadAnalysisClaimLedgerIndex(
              workspaceManager,
              database,
              input.sample_id,
              activeClaimIds === null
                ? { scope: 'all', maxArtifacts: 64 }
                : { scope: 'all', activeClaimIds }
            ),
          ])

          if (claimResult.status === 'fulfilled') {
            const scopedClaimLedger = scopeAnalysisClaimLedgerIndex(
              claimResult.value,
              activeClaimIds
            )
            const built = buildClaimLedgerContext(scopedClaimLedger)
            claimContext = built.summary
            claimReviewRequired =
              built.reviewRequired ||
              built.summary.truncated ||
              scopedClaimLedger.warnings.length > 0
            claimQuestions = built.unresolvedQuestions
            warnings.push(
              ...scopedClaimLedger.warnings.map((item) => `Claim Ledger context: ${item}`)
            )
          } else {
            claimReviewRequired = true
            warnings.push(
              `Claim Ledger context could not be loaded: ${
                claimResult.reason instanceof Error
                  ? claimResult.reason.message
                  : String(claimResult.reason)
              }`
            )
          }

          const unresolvedQuestions = dedupeStrings([...claimQuestions, ...caseQuestions])
            .map((item) => truncateContextText(item, 1200))
            .slice(0, SUMMARY_CONTEXT_LIMITS.unresolved_questions)
          return {
            claimContext,
            caseContext,
            reviewRequired: claimReviewRequired || caseReviewRequired,
            unresolvedQuestions,
          }
        })()
        return finalSummaryContextPromise
      }

      const getCompactReportData = async () => {
        if (compactReportResult) {
          return compactReportResult
        }
        compactReportResult = await reportSummarizeHandler({
          sample_id: input.sample_id,
          mode: 'triage',
          detail_level: 'compact',
          force_refresh: input.force_refresh,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag,
          static_scope: input.static_scope,
          static_session_tag: input.static_session_tag,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag,
          compare_evidence_scope: input.compare_evidence_scope,
          compare_evidence_session_tag: input.compare_evidence_session_tag,
          compare_static_scope: input.compare_static_scope,
          compare_static_session_tag: input.compare_static_session_tag,
          compare_semantic_scope: input.compare_semantic_scope,
          compare_semantic_session_tag: input.compare_semantic_session_tag,
        })
        // report.summarize may persist new source artifacts (for example explanation graphs).
        // Refresh the memoized fingerprint snapshot before persisting rebuilt digests so those
        // report-side effects do not make the new digest immediately stale on the next request.
        summaryFingerprintBaseStatePromise = null
        warnings.push(...(compactReportResult.warnings || []))
        return compactReportResult
      }

      const loadReusedStage = async <TSchema extends z.ZodTypeAny>(
        stage: SummaryStage,
        schema: TSchema,
        accept?: (payload: z.infer<TSchema>) => boolean,
        summaryContext?: FinalSummaryContext
      ): Promise<z.infer<TSchema> | null> => {
        if (!effectiveReuse) {
          return null
        }
        const selection = await loadSummaryDigestArtifactSelection<unknown>(
          workspaceManager,
          database,
          input.sample_id,
          stage,
          {
            scope: input.session_tag
              ? 'session'
              : stage === 'final' && input.case_id
                ? 'all'
                : 'latest',
            sessionTag: input.session_tag,
          }
        )
        if (selection.artifacts.length === 0) {
          return null
        }
        const baseState = await getSummaryFingerprintBaseState()
        if (baseState.artifactIntegrityWarnings.length > 0) {
          publishSummarySourceIntegrityWarnings(baseState)
          warnings.push(
            `Skipped persisted ${stage} summary digest because source artifact integrity validation failed.`
          )
          return null
        }
        const expectedFingerprint = buildSummaryReuseFingerprint({
          baseState,
          request: input,
          stage,
          resolvedSynthesisMode: resolvedSynthesisModeForReuse,
          summaryContext,
        })
        let rejectedByContextMarker = false
        let rejectedLegacyFingerprint = false
        let rejectedByFingerprint = false
        for (const candidate of selection.artifacts) {
          try {
            const parsed = schema.parse(candidate.payload)
            if (accept && !accept(parsed)) {
              rejectedByContextMarker = true
              continue
            }
            if (!parsed.reuse_fingerprint) {
              rejectedLegacyFingerprint = true
              continue
            }
            if (
              parsed.reuse_fingerprint.fingerprint_sha256 !==
                expectedFingerprint.fingerprint_sha256 ||
              JSON.stringify(parsed.reuse_fingerprint) !== JSON.stringify(expectedFingerprint)
            ) {
              rejectedByFingerprint = true
              continue
            }
            const artifact = artifactMap.get(candidate.artifact_id)
            if (artifact) {
              stageArtifacts[stage] = artifactRefFromArtifact(artifact, stage)
            }
            reusedAnyStage = true
            warnings.push(
              `Reused persisted ${stage} summary digest from ${candidate.created_at || 'latest available artifact'}.`
            )
            return parsed
          } catch {
            continue
          }
        }
        if (rejectedByContextMarker) {
          warnings.push(
            `Skipped persisted ${stage} summary digest because its context marker is stale.`
          )
        }
        if (rejectedLegacyFingerprint) {
          warnings.push(
            `Skipped persisted ${stage} summary digest because it has no compatible reuse fingerprint.`
          )
        }
        if (rejectedByFingerprint) {
          warnings.push(
            `Skipped persisted ${stage} summary digest because its input/source fingerprint is stale.`
          )
        }
        return null
      }

      const persistStage = async <TPayload extends object>(
        stage: SummaryStage,
        payload: TPayload,
        summaryContext?: FinalSummaryContext,
        resolvedSynthesisMode = resolvedSynthesisModeForReuse
      ): Promise<TPayload & { reuse_fingerprint: SummaryDigestReuseFingerprint }> => {
        const baseState = await getSummaryFingerprintBaseState()
        publishSummarySourceIntegrityWarnings(baseState)
        const persistedPayload = {
          ...payload,
          reuse_fingerprint: buildSummaryReuseFingerprint({
            baseState,
            request: input,
            stage,
            resolvedSynthesisMode,
            summaryContext,
          }),
        }
        const artifact = await persistSummaryDigestArtifact(
          workspaceManager,
          database,
          input.sample_id,
          stage,
          persistedPayload,
          input.session_tag
        )
        stageArtifacts[stage] = artifact
        return persistedPayload
      }

      const ensureTriageStage = async () => {
        if (stageDigests.triage) {
          return stageDigests.triage as z.infer<typeof TriageStageDigestSchema>
        }
        const reused = await loadReusedStage('triage', TriageStageDigestSchema)
        if (reused) {
          stageDigests.triage = reused
          completedStages.push('triage')
          return reused
        }

        const report = await getCompactReportData()
        if (!report.ok || !report.data) {
          throw new Error((report.errors || ['report.summarize failed']).join('; '))
        }
        const data = report.data as any
        const triageDigest = buildTriageStageDigest({
          sample_id: input.sample_id,
          session_tag: input.session_tag || null,
          summary: String(data.summary || ''),
          confidence: Number(data.confidence || 0),
          threat_level: data.threat_level,
          iocs: data.iocs || {
            suspicious_imports: [],
            suspicious_strings: [],
            yara_matches: [],
          },
          evidence: Array.isArray(data.evidence) ? data.evidence : [],
          evidence_lineage: data.evidence_lineage,
          confidence_semantics: data.confidence_semantics,
          recommendation: String(data.recommendation || ''),
          source_artifact_refs: Array.isArray(data.artifact_refs?.supporting)
            ? sourceArtifactRefsOnly(data.artifact_refs.supporting as ArtifactRef[])
            : [],
          coverage: extractCoverage(data) || undefined,
        })
        const persistedTriageDigest = await persistStage('triage', triageDigest)
        stageDigests.triage = persistedTriageDigest
        completedStages.push('triage')
        return persistedTriageDigest
      }

      const ensureStaticStage = async () => {
        if (stageDigests.static) {
          return stageDigests.static as z.infer<typeof StaticStageDigestSchema>
        }
        const reused = await loadReusedStage('static', StaticStageDigestSchema)
        if (reused) {
          stageDigests.static = reused
          completedStages.push('static')
          return reused
        }
        const report = await getCompactReportData()
        if (!report.ok || !report.data) {
          throw new Error((report.errors || ['report.summarize failed']).join('; '))
        }
        const data = report.data as any
        const staticDigest = buildStaticStageDigest({
          sample_id: input.sample_id,
          session_tag: input.session_tag || null,
          binary_profile_summary: data.binary_profile_summary || undefined,
          rust_profile_summary: data.rust_profile_summary || undefined,
          static_capability_summary: data.static_capability_summary || undefined,
          pe_structure_summary: data.pe_structure_summary || undefined,
          compiler_packer_summary: data.compiler_packer_summary || undefined,
          semantic_explanation_summary: data.semantic_explanation_summary || undefined,
          key_findings: dedupeStrings([
            data.binary_profile_summary?.summary,
            data.rust_profile_summary?.summary,
            data.static_capability_summary?.summary,
            data.pe_structure_summary?.summary,
            data.compiler_packer_summary?.summary,
            data.semantic_explanation_summary?.summary,
            data.packed_state ? `Packed state: ${data.packed_state}.` : null,
            data.unpack_state ? `Unpack state: ${data.unpack_state}.` : null,
            ...(Array.isArray(data.unpack_debug_diffs)
              ? data.unpack_debug_diffs.flatMap((item: any) =>
                  Array.isArray(item.findings) ? item.findings.slice(0, 2) : []
                )
              : []),
          ]),
          recommendation: String(data.recommendation || ''),
          source_artifact_refs: Array.isArray(data.artifact_refs?.supporting)
            ? sourceArtifactRefsOnly(data.artifact_refs.supporting as ArtifactRef[])
            : [],
          coverage: extractCoverage(data) || undefined,
        })
        const persistedStaticDigest = await persistStage('static', staticDigest)
        stageDigests.static = persistedStaticDigest
        completedStages.push('static')
        return persistedStaticDigest
      }

      const ensureDeepStage = async () => {
        if (stageDigests.deep) {
          return stageDigests.deep as z.infer<typeof DeepStageDigestSchema>
        }
        const reused = await loadReusedStage('deep', DeepStageDigestSchema)
        if (reused) {
          stageDigests.deep = reused
          completedStages.push('deep')
          return reused
        }
        const report = await getCompactReportData()
        if (!report.ok || !report.data) {
          throw new Error((report.errors || ['report.summarize failed']).join('; '))
        }
        const data = report.data as any
        const topFunctions = buildTopFunctions(database.findFunctionsByScore(input.sample_id, 8))
        const functionExplanations = await loadFunctionExplanationSummaries(
          workspaceManager,
          database,
          input.sample_id,
          {
            scope: input.semantic_scope,
            sessionTag: input.semantic_session_tag,
          }
        )
        const ghidraExecution = data.ghidra_execution
          ? GhidraExecutionSummarySchema.parse(data.ghidra_execution)
          : null
        const analysisGaps = dedupeStrings([
          ...(Array.isArray(ghidraExecution?.warnings) ? ghidraExecution.warnings : []),
          ...(topFunctions.length === 0
            ? ['No scored functions are currently persisted for deep-stage review.']
            : []),
          ...(functionExplanations.length === 0
            ? ['No semantic function explanations are currently persisted.']
            : []),
          ...(data.packed_state && data.packed_state !== 'not_packed'
            ? [
                `Packed/debug progression is still relevant: packed_state=${data.packed_state}, unpack_state=${data.unpack_state || 'unknown'}.`,
              ]
            : []),
        ])
        const deepDigest = buildDeepStageDigest({
          sample_id: input.sample_id,
          session_tag: input.session_tag || null,
          summary: ghidraExecution
            ? `Deep-stage digest summarizes persisted Ghidra execution plus ${topFunctions.length} scored function(s).`
            : `Deep-stage digest summarizes persisted reconstruction context plus ${topFunctions.length} scored function(s).`,
          ghidra_execution: ghidraExecution,
          top_functions: topFunctions,
          function_explanations: functionExplanations,
          analysis_gaps: analysisGaps,
          recommendation:
            topFunctions.length > 0
              ? 'Use artifact.read on referenced summary or reconstruction artifacts before requesting broader narrative output.'
              : 'Run ghidra.analyze or workflow.reconstruct to produce deeper persisted artifacts before relying on deep-stage synthesis.',
          source_artifact_refs: sourceArtifactRefsOnly([
            ...(Array.isArray(data.artifact_refs?.supporting)
              ? (data.artifact_refs.supporting as ArtifactRef[])
              : []),
            ...(Array.isArray(data.artifact_refs?.supporting)
              ? (data.artifact_refs.supporting as ArtifactRef[]).filter(
                  (item) => typeof item.type === 'string' && item.type === 'analysis_diff_digest'
                )
              : []),
          ]),
          coverage: buildCoverageEnvelope({
            coverageLevel: 'deep_static',
            completionState: topFunctions.length > 0 ? 'completed' : 'bounded',
            sampleSizeTier,
            analysisBudgetProfile,
            coverageGaps: [
              ...analysisGaps.map((item) => ({
                domain: 'deep_analysis_gap',
                status: 'degraded' as const,
                reason: item,
              })),
              ...(topFunctions.length === 0
                ? [
                    {
                      domain: 'decompilation',
                      status: 'missing' as const,
                      reason: 'No scored functions were available for the deep-stage digest.',
                    },
                  ]
                : []),
              {
                domain: 'reconstruction_export',
                status: 'missing' as const,
                reason: 'Deep-stage digest does not include source-like reconstruction export.',
              },
            ],
            knownFindings: topFunctions
              .slice(0, 3)
              .map((item) => `${item.address}: ${item.name || 'function'}`),
            suspectedFindings: analysisGaps,
            unverifiedAreas: [
              'Source-like reconstruction and runtime verification remain outside the deep-stage digest.',
            ],
            upgradePaths: [
              {
                tool: 'workflow.reconstruct',
                purpose: 'Continue from deep-stage context into reconstruction export.',
                closes_gaps: ['reconstruction_export'],
                expected_coverage_gain:
                  'Adds export artifacts and validation notes beyond the deep-stage digest.',
                cost_tier: 'high',
              },
            ],
          }),
        })
        const persistedDeepDigest = await persistStage('deep', deepDigest)
        stageDigests.deep = persistedDeepDigest
        completedStages.push('deep')
        return persistedDeepDigest
      }

      const ensureFinalStage = async () => {
        if (stageDigests.final) {
          return stageDigests.final as z.infer<typeof FinalStageDigestSchema>
        }
        const summaryContext = await getFinalSummaryContext()
        const reused = await loadReusedStage(
          'final',
          FinalStageDigestSchema,
          (payload) =>
            payload.claim_context.marker === summaryContext.claimContext.marker &&
            payload.case_context.marker === summaryContext.caseContext.marker,
          summaryContext
        )
        if (reused) {
          stageDigests.final = reused
          completedStages.push('final')
          return reused
        }
        const triageDigest = await ensureTriageStage()
        const staticDigest = await ensureStaticStage()
        const deepDigest = await ensureDeepStage()
        const compactReport = await getCompactReportData()
        const compactReportData =
          compactReport.ok && compactReport.data
            ? (compactReport.data as Record<string, unknown>)
            : {}
        const explanationGraphs = Array.isArray(compactReportData.explanation_graphs)
          ? compactReportData.explanation_graphs
          : undefined
        const explanationArtifacts =
          compactReportData.artifact_refs &&
          typeof compactReportData.artifact_refs === 'object' &&
          Array.isArray(
            (compactReportData.artifact_refs as Record<string, unknown>).explanation_graphs
          )
            ? ((compactReportData.artifact_refs as Record<string, unknown>)
                .explanation_graphs as ArtifactRef[])
            : undefined
        const shouldUseSampling = samplingRequested
        let finalDigest = buildFinalStageDigest({
          sample_id: input.sample_id,
          session_tag: input.session_tag || null,
          triage: triageDigest,
          staticDigest,
          deepDigest,
          stage_artifact_refs: currentStageArtifactRefs(),
          synthesis_mode: shouldUseSampling ? 'sampling' : 'deterministic',
          explanation_graphs: Array.isArray(explanationGraphs) ? explanationGraphs : undefined,
          explanation_artifact_refs: explanationArtifacts,
          claim_context: summaryContext.claimContext,
          case_context: summaryContext.caseContext,
          review_required: summaryContext.reviewRequired,
          unresolved_questions: summaryContext.unresolvedQuestions,
          source_artifact_refs: sourceArtifactRefsOnly([
            ...(triageDigest.source_artifact_refs as ArtifactRef[]),
            ...(staticDigest.source_artifact_refs as ArtifactRef[]),
            ...(deepDigest.source_artifact_refs as ArtifactRef[]),
          ]),
        })

        if (shouldUseSampling) {
          if (!samplingAvailable) {
            warnings.push(
              'Requested sampling synthesis, but the connected MCP client did not advertise sampling support. Falling back to deterministic synthesis.'
            )
            finalDigest = buildFinalStageDigest({
              sample_id: input.sample_id,
              session_tag: input.session_tag || null,
              triage: triageDigest,
              staticDigest,
              deepDigest,
              stage_artifact_refs: currentStageArtifactRefs(),
              synthesis_mode: 'deterministic',
              explanation_graphs: Array.isArray(explanationGraphs) ? explanationGraphs : undefined,
              explanation_artifact_refs: explanationArtifacts,
              claim_context: summaryContext.claimContext,
              case_context: summaryContext.caseContext,
              review_required: summaryContext.reviewRequired,
              unresolved_questions: summaryContext.unresolvedQuestions,
              source_artifact_refs: sourceArtifactRefsOnly([
                ...(triageDigest.source_artifact_refs as ArtifactRef[]),
                ...(staticDigest.source_artifact_refs as ArtifactRef[]),
                ...(deepDigest.source_artifact_refs as ArtifactRef[]),
              ]),
            })
          } else {
            try {
              const samplingResult = await samplingRequester(
                buildSamplingRequest(triageDigest, staticDigest, deepDigest, summaryContext)
              )
              const responseText = extractTextBlocks(samplingResult)
              const parsed = parseSummaryJsonCandidate(responseText)
              finalDigest = applySamplingNarrative(
                finalDigest,
                parsed,
                samplingResult?.model || null
              )
            } catch (error) {
              warnings.push(
                error instanceof Error
                  ? `${error.message} Falling back to deterministic synthesis.`
                  : 'Sampling synthesis failed; falling back to deterministic synthesis.'
              )
              finalDigest = buildFinalStageDigest({
                sample_id: input.sample_id,
                session_tag: input.session_tag || null,
                triage: triageDigest,
                staticDigest,
                deepDigest,
                stage_artifact_refs: currentStageArtifactRefs(),
                synthesis_mode: 'deterministic',
                explanation_graphs: Array.isArray(explanationGraphs)
                  ? explanationGraphs
                  : undefined,
                explanation_artifact_refs: explanationArtifacts,
                claim_context: summaryContext.claimContext,
                case_context: summaryContext.caseContext,
                review_required: summaryContext.reviewRequired,
                unresolved_questions: summaryContext.unresolvedQuestions,
                source_artifact_refs: sourceArtifactRefsOnly([
                  ...(triageDigest.source_artifact_refs as ArtifactRef[]),
                  ...(staticDigest.source_artifact_refs as ArtifactRef[]),
                  ...(deepDigest.source_artifact_refs as ArtifactRef[]),
                ]),
              })
            }
          }
        }

        const persistedFinalDigest = await persistStage(
          'final',
          finalDigest,
          summaryContext,
          finalDigest.synthesis_mode
        )
        stageDigests.final = persistedFinalDigest
        completedStages.push('final')
        return persistedFinalDigest
      }

      await ensureTriageStage()
      if (
        input.through_stage === 'static' ||
        input.through_stage === 'deep' ||
        input.through_stage === 'final'
      ) {
        await ensureStaticStage()
      }
      if (input.through_stage === 'deep' || input.through_stage === 'final') {
        await ensureDeepStage()
      }
      if (input.through_stage === 'final') {
        await ensureFinalStage()
      }

      const finalStage = stageDigests.final as z.infer<typeof FinalStageDigestSchema> | undefined
      const currentCoverage =
        extractCoverage(finalStage) ||
        extractCoverage(stageDigests.deep) ||
        extractCoverage(stageDigests.static) ||
        extractCoverage(stageDigests.triage) ||
        buildCoverageEnvelope({
          coverageLevel:
            input.through_stage === 'triage'
              ? 'quick'
              : input.through_stage === 'static'
                ? 'static_core'
                : 'deep_static',
          completionState: input.through_stage === 'final' ? 'completed' : 'bounded',
          sampleSizeTier,
          analysisBudgetProfile,
          unverifiedAreas: [
            'Coverage boundary could not be derived from persisted stage artifacts.',
          ],
        })
      const resolvedMode = finalStage?.synthesis_mode || 'deterministic'
      const recommendedNextTools =
        input.through_stage === 'final'
          ? ['artifact.read', 'artifacts.list', 'report.generate']
          : input.through_stage === 'deep'
            ? ['workflow.search', 'artifact.read', 'workflow.reconstruct']
            : ['workflow.search', 'artifact.read', 'ghidra.analyze', 'workflow.reconstruct']
      const nextActions =
        input.through_stage === 'final'
          ? [
              'Use artifact.read on stage_artifacts.final or the referenced supporting artifacts when you need deeper supporting detail.',
              'Read explanation_artifacts when you want bounded semantic graphs that explain findings, omissions, and next-stage escalation.',
              'Use artifacts.list with path_prefix=reports/summary to inspect persisted staged digests.',
            ]
          : [
              `Use workflow.search to select the next reporting/synthesis path when you need deeper synthesis beyond through_stage=${input.through_stage}.`,
              'Use artifact.read or artifacts.list on the returned stage_artifacts for supporting detail instead of requesting a monolithic inline payload.',
              'When explanation_artifacts are present, prefer them over decorative graph export requests because they carry provenance, confidence, and omission boundaries.',
            ]

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          through_stage: input.through_stage,
          detail_level: 'compact',
          tool_surface_role: 'compatibility',
          preferred_primary_tools: ['workflow.search', 'artifact.read'],
          completed_stages: completedStages,
          stages: {
            ...(stageDigests.triage ? { triage: stageDigests.triage as any } : {}),
            ...(stageDigests.static ? { static: stageDigests.static as any } : {}),
            ...(stageDigests.deep ? { deep: stageDigests.deep as any } : {}),
            ...(stageDigests.final ? { final: stageDigests.final as any } : {}),
          },
          stage_artifacts: {
            ...(stageArtifacts.triage ? { triage: stageArtifacts.triage } : {}),
            ...(stageArtifacts.static ? { static: stageArtifacts.static } : {}),
            ...(stageArtifacts.deep ? { deep: stageArtifacts.deep } : {}),
            ...(stageArtifacts.final ? { final: stageArtifacts.final } : {}),
          },
          synthesis: {
            requested_mode: input.synthesis_mode,
            resolved_mode: resolvedMode,
            sampling_available: samplingAvailable,
            used_existing_stage_artifacts: reusedAnyStage,
            model_name: finalStage?.model_name || null,
          },
          ...(finalStage?.explanation_graphs
            ? { explanation_graphs: finalStage.explanation_graphs }
            : {}),
          ...(finalStage?.explanation_artifact_refs
            ? { explanation_artifacts: finalStage.explanation_artifact_refs }
            : {}),
          ...(finalStage
            ? {
                claim_context: finalStage.claim_context,
                case_context: finalStage.case_context,
                review_required: finalStage.review_required,
                unresolved_questions: finalStage.unresolved_questions,
              }
            : {}),
          persisted_state_visibility: {
            ...persistedStateVisibility,
            reused_stage_artifacts: reusedAnyStage,
          },
          ...currentCoverage,
          recommended_next_tools: recommendedNextTools,
          next_actions: nextActions,
        },
        warnings: warnings.length > 0 ? dedupeStrings(warnings) : undefined,
        metrics: toolMetrics(startTime),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: toolMetrics(startTime),
      }
    }
  }
}
