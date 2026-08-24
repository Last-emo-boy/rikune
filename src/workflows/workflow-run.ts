import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import {
  AnalysisIntentDepthSchema,
  AnalysisIntentGoalSchema,
  BackendPolicySchema,
} from '../intent-routing.js'
import {
  AnalysisExecutionStateSchema,
  AnalysisPipelineStageSchema,
  AnalysisRecoveryStateSchema,
  AnalysisStageStatusSchema,
} from '../analysis/analysis-run-state.js'
import { toStringArray } from '../utils/shared-helpers.js'
import { isStaticDockerProfile } from '../core/static-profile-lock.js'

const TOOL_NAME = 'workflow.run'
const ARTIFACT_SELECTOR_LIMIT = 12
const STAGE_STATUS_LIMIT = 16
const WorkflowRunActionSchema = z.enum(['request_upload', 'start', 'status', 'promote'])
const RoutedToolSchema = z.enum([
  'sample.request_upload',
  'workflow.analyze.start',
  'workflow.analyze.status',
  'workflow.analyze.promote',
])

const ArtifactReadSelectorSchema = z.object({
  selector_id: z.string(),
  sample_id: z.string(),
  artifact_id: z.string(),
  artifact_type: z.string(),
  path: z.string(),
  sha256: z.string().optional(),
  mime: z.string().nullable().optional(),
  stage: z.string().nullable(),
  source: z.enum(['stage', 'run']),
  suggested_read_mode: z.enum(['profile', 'summary', 'content']),
  read_args: z.object({
    sample_id: z.string(),
    artifact_id: z.string(),
    read_mode: z.enum(['profile', 'summary', 'content']),
  }),
})

const ArtifactSelectorSummarySchema = z.object({
  total_artifact_refs: z.number().int().nonnegative(),
  selectable_artifact_refs: z.number().int().nonnegative(),
  selector_count: z.number().int().nonnegative(),
  omitted_count: z.number().int().nonnegative(),
  latest_stage: z.string().nullable(),
  by_type: z.record(z.number().int().nonnegative()),
  by_stage: z.record(z.number().int().nonnegative()),
})

const CompactStageStatusSchema = z
  .object({
    stage: AnalysisPipelineStageSchema,
    status: AnalysisStageStatusSchema,
    execution_state: AnalysisExecutionStateSchema.nullable().optional(),
    recovery_state: AnalysisRecoveryStateSchema,
    job_id: z.string().nullable().optional(),
  })
  .strict()

export const workflowRunInputSchema = z
  .object({
    action: WorkflowRunActionSchema.default('start').describe(
      'Whitelisted workflow action. request_upload creates an upload session, start creates/reuses a plan, status reads a plan, promote queues deeper stages.'
    ),
    filename: z
      .string()
      .optional()
      .describe('Optional original filename for action=request_upload.'),
    ttl_seconds: z
      .number()
      .int()
      .min(30)
      .max(3600)
      .default(300)
      .describe('Upload token TTL for action=request_upload.'),
    sample_id: z.string().optional().describe('Required for action=start.'),
    plan_id: z
      .string()
      .optional()
      .describe('External plan ID. Internally this maps to analysis_runs.id/run_id.'),
    goal: AnalysisIntentGoalSchema.default('triage').describe('Analysis goal for action=start.'),
    depth: AnalysisIntentDepthSchema.default('balanced').describe(
      'Analysis depth for action=start.'
    ),
    backend_policy: BackendPolicySchema.default('auto').describe(
      'Backend routing policy for action=start.'
    ),
    allow_transformations: z
      .boolean()
      .default(false)
      .describe('Allow transform-capable later stages when explicitly promoted.'),
    allow_live_execution: z
      .boolean()
      .default(false)
      .describe('Allow live-execution-capable routing only when downstream policy permits it.'),
    stages: z
      .array(AnalysisPipelineStageSchema)
      .optional()
      .describe('Optional promoted stages for action=promote.'),
    through_stage: AnalysisPipelineStageSchema.optional().describe(
      'Optional terminal stage for action=promote.'
    ),
    force_refresh: z.boolean().default(false).describe('Bypass reusable run/stage results.'),
    include_raw_result: z
      .boolean()
      .default(false)
      .describe(
        'Include the wrapped workflow result for debugging. Defaults false to keep output compact.'
      ),
  })
  .superRefine((input, ctx) => {
    if (input.action === 'start' && !input.sample_id) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['sample_id'],
        message: 'sample_id is required when action=start',
      })
    }
    if ((input.action === 'status' || input.action === 'promote') && !input.plan_id) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['plan_id'],
        message: `plan_id is required when action=${input.action}`,
      })
    }
  })

export const workflowRunOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      result_mode: z.literal('workflow_run'),
      action: WorkflowRunActionSchema,
      routed_tool: RoutedToolSchema,
      upload_url: z.string().optional(),
      status_url: z.string().optional(),
      token: z.string().optional(),
      expires_at: z.string().optional(),
      ttl_seconds: z.number().optional(),
      plan_id: z.string().optional(),
      sample_id: z.string().optional(),
      status: z.string().optional(),
      execution_state: z.string().optional(),
      current_stage: z.string().optional(),
      latest_stage: z.string().optional(),
      coverage_level: z.string().optional(),
      completion_state: z.string().optional(),
      coverage_gaps: z.array(z.any()).optional(),
      upgrade_paths: z.array(z.any()).optional(),
      deferred_jobs: z.array(z.any()).optional(),
      recoverable_stages: z.array(z.any()).optional(),
      stage_statuses: z.array(CompactStageStatusSchema).max(STAGE_STATUS_LIMIT).optional(),
      function_index_ready: z.boolean().optional(),
      artifact_selectors: z.array(ArtifactReadSelectorSchema).optional(),
      artifact_selector_summary: ArtifactSelectorSummarySchema.optional(),
      recommended_workflow_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
      routed_result: z.any().optional(),
      message: z.string(),
    })
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

export const workflowRunToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Minimal execution gateway for Rikune staged workflows. ' +
    'Use after workflow.search selects the staged analysis path. ' +
    'It only routes to whitelisted workflow actions: request_upload, start, status, and promote. ' +
    'It uses plan_id externally and maps it to the persisted analysis run internally. ' +
    'It does not accept arbitrary tool names and does not expose specialist tools.',
  inputSchema: workflowRunInputSchema,
  outputSchema: workflowRunOutputSchema,
  aspects: {
    execution: ['orchestration'],
    capabilities: ['staged-analysis', 'workflow-routing', 'plan-management'],
    safety: ['bounded', 'whitelisted-routing'],
  },
  workflowRecipes: [
    {
      id: 'rikune.workflow.run',
      title: 'Rikune staged workflow execution',
      startsWith: ['workflow.run'],
      nextTools: ['workflow.search', 'workflow.run'],
      evidence: ['analysis-run-state'],
      safety: ['bounded', 'whitelisted-routing'],
    },
  ],
}

type WorkflowHandler = (args: ToolArgs) => Promise<WorkerResult>

interface WorkflowRunHandlers {
  requestUpload: WorkflowHandler
  start: WorkflowHandler
  status: WorkflowHandler
  promote: WorkflowHandler
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value : undefined
}

function arrayValue(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined
}

function recordArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> =>
          item !== null && typeof item === 'object' && !Array.isArray(item)
      )
    : []
}

function routedToolFor(action: z.infer<typeof WorkflowRunActionSchema>) {
  if (action === 'request_upload') return 'sample.request_upload' as const
  if (action === 'status') return 'workflow.analyze.status' as const
  if (action === 'promote') return 'workflow.analyze.promote' as const
  return 'workflow.analyze.start' as const
}

function routedArgs(input: z.infer<typeof workflowRunInputSchema>): ToolArgs {
  if (input.action === 'request_upload') {
    return {
      ...(input.filename ? { filename: input.filename } : {}),
      ttl_seconds: input.ttl_seconds,
    }
  }
  if (input.action === 'status') {
    return { run_id: input.plan_id }
  }
  if (input.action === 'promote') {
    return {
      run_id: input.plan_id,
      ...(input.stages ? { stages: input.stages } : {}),
      ...(input.through_stage ? { through_stage: input.through_stage } : {}),
      force_refresh: input.force_refresh,
    }
  }
  return {
    sample_id: input.sample_id,
    goal: input.goal,
    depth: input.depth,
    backend_policy: input.backend_policy,
    allow_transformations: input.allow_transformations,
    allow_live_execution: input.allow_live_execution,
    force_refresh: input.force_refresh,
  }
}

function normalizeRecommendedWorkflowTools(items: unknown): string[] {
  const mapped: string[] = []
  for (const item of toStringArray(items)) {
    if (
      item === 'workflow.run' ||
      item.startsWith('workflow.analyze.') ||
      item === 'workflow.triage' ||
      item === 'workflow.analyze.auto' ||
      item === 'sample.request_upload' ||
      item === 'sample.ingest' ||
      item === 'task.status'
    ) {
      mapped.push('workflow.run')
    } else if (
      item === 'workflow.search' ||
      item === 'tools.discover' ||
      item === 'tool.help' ||
      item === 'tool.readiness' ||
      item === 'plugin.list' ||
      item === 'workflow.summarize' ||
      item === 'report.generate' ||
      item === 'graphviz.render'
    ) {
      mapped.push('workflow.search')
    } else if (item === 'artifact.read') {
      mapped.push('artifact.read')
    } else if (item.startsWith('artifact.')) {
      mapped.push('artifact.read')
    } else {
      mapped.push('workflow.search')
    }
  }
  return Array.from(new Set(mapped))
}

function normalizeWorkflowNextAction(action: string): string {
  return action
    .replaceAll('workflow.analyze.start', 'workflow.run action=start')
    .replaceAll('workflow.analyze.status', 'workflow.run action=status')
    .replaceAll('workflow.analyze.promote', 'workflow.run action=promote')
    .replaceAll('sample.request_upload', 'workflow.run action=request_upload')
    .replaceAll('tools.discover action=list', 'workflow.search')
    .replaceAll('tools.discover action=recommend', 'workflow.search')
    .replaceAll('tools.discover', 'workflow.search')
}

function artifactValueScore(type: string, artifactPath: string): number {
  const normalized = `${type} ${artifactPath}`.toLowerCase()
  const weightedSignals: Array<[string, number]> = [
    ['ghidra_functions', 60],
    ['backend_rizin_functions', 55],
    ['function_map', 45],
    ['reconstruct', 40],
    ['decompile', 36],
    ['function', 32],
    ['cfg', 30],
    ['xrefs', 28],
    ['capability', 24],
    ['context_link', 24],
    ['crypto_identification', 22],
    ['pe_structure', 20],
    ['elf_structure', 20],
    ['summary', 18],
    ['report', 18],
    ['evidence', 18],
    ['graph', 18],
    ['manifest', 16],
    ['triage', 14],
    ['trace', 14],
    ['yara', 12],
    ['sbom', 12],
    ['vuln', 12],
    ['diff', 12],
    ['unpack', 10],
    ['profile', 8],
    ['enriched_string', 4],
  ]
  return weightedSignals.reduce(
    (score, [signal, weight]) => score + (normalized.includes(signal) ? weight : 0),
    0
  )
}

function suggestedReadMode(type: string, artifactPath: string): 'profile' | 'summary' | 'content' {
  const normalized = `${type} ${artifactPath}`.toLowerCase()
  if (
    ['evidence', 'graph', 'manifest', 'handoff', 'profile', 'sbom', 'vuln', 'yara'].some((signal) =>
      normalized.includes(signal)
    )
  ) {
    return 'profile'
  }
  if (['report', 'summary', 'digest', 'triage'].some((signal) => normalized.includes(signal))) {
    return 'summary'
  }
  return 'content'
}

function normalizeArtifactRef(
  value: unknown,
  params: {
    sampleId: string
    stage: string | null
    source: 'stage' | 'run'
    order: number
  }
): (z.infer<typeof ArtifactReadSelectorSchema> & { score: number; order: number }) | null {
  const item = asRecord(value)
  const artifactId = stringValue(item.id)
  const artifactType = stringValue(item.type)
  const artifactPath = stringValue(item.path)
  if (!artifactId || !artifactType || !artifactPath) {
    return null
  }

  const readMode = suggestedReadMode(artifactType, artifactPath)
  const selector = {
    selector_id: `${params.source}:${params.stage ?? 'run'}:${artifactId}`,
    sample_id: params.sampleId,
    artifact_id: artifactId,
    artifact_type: artifactType,
    path: artifactPath,
    sha256: stringValue(item.sha256),
    mime: typeof item.mime === 'string' ? item.mime : item.mime === null ? null : undefined,
    stage: params.stage,
    source: params.source,
    suggested_read_mode: readMode,
    read_args: {
      sample_id: params.sampleId,
      artifact_id: artifactId,
      read_mode: readMode,
    },
    score: artifactValueScore(artifactType, artifactPath),
    order: params.order,
  }
  return selector
}

function buildArtifactSelectorPayload(params: {
  run: Record<string, unknown>
  sampleId?: string
  latestStage?: string
}): {
  artifact_selectors?: z.infer<typeof ArtifactReadSelectorSchema>[]
  artifact_selector_summary?: z.infer<typeof ArtifactSelectorSummarySchema>
} {
  const sampleId = params.sampleId
  if (!sampleId) return {}

  const latestStage = params.latestStage ?? stringValue(params.run.latest_stage) ?? null
  const candidates: Array<
    z.infer<typeof ArtifactReadSelectorSchema> & { score: number; order: number }
  > = []
  let order = 0
  let rawArtifactRefCount = 0

  for (const stage of recordArray(params.run.stages)) {
    const stageName = stringValue(stage.stage)
    const artifactRefs = arrayValue(stage.artifact_refs) ?? []
    rawArtifactRefCount += artifactRefs.length
    for (const artifact of artifactRefs) {
      const selector = normalizeArtifactRef(artifact, {
        sampleId,
        stage: stageName ?? null,
        source: 'stage',
        order,
      })
      order += 1
      if (selector) candidates.push(selector)
    }
  }

  const runArtifactRefs = arrayValue(params.run.artifact_refs) ?? []
  rawArtifactRefCount += runArtifactRefs.length
  for (const artifact of runArtifactRefs) {
    const selector = normalizeArtifactRef(artifact, {
      sampleId,
      stage: null,
      source: 'run',
      order,
    })
    order += 1
    if (selector) candidates.push(selector)
  }

  if (candidates.length === 0) return {}

  const deduped = new Map<
    string,
    z.infer<typeof ArtifactReadSelectorSchema> & { score: number; order: number }
  >()
  for (const candidate of candidates) {
    const key = candidate.artifact_id || `${candidate.artifact_type}:${candidate.path}`
    const existing = deduped.get(key)
    if (
      !existing ||
      (existing.source === 'run' && candidate.source === 'stage') ||
      (existing.stage !== latestStage && candidate.stage === latestStage)
    ) {
      deduped.set(key, candidate)
    }
  }

  const allSelectors = Array.from(deduped.values()).sort((left, right) => {
    const leftLatest = left.stage === latestStage ? 1 : 0
    const rightLatest = right.stage === latestStage ? 1 : 0
    if (leftLatest !== rightLatest) return rightLatest - leftLatest
    const leftStage = left.source === 'stage' ? 1 : 0
    const rightStage = right.source === 'stage' ? 1 : 0
    if (leftStage !== rightStage) return rightStage - leftStage
    if (left.score !== right.score) return right.score - left.score
    return left.order - right.order
  })
  const limited = allSelectors.slice(0, ARTIFACT_SELECTOR_LIMIT)
  const byType: Record<string, number> = {}
  const byStage: Record<string, number> = {}
  for (const selector of allSelectors) {
    byType[selector.artifact_type] = (byType[selector.artifact_type] ?? 0) + 1
    const stageKey = selector.stage ?? 'run'
    byStage[stageKey] = (byStage[stageKey] ?? 0) + 1
  }

  return {
    artifact_selectors: limited.map(({ score: _score, order: _order, ...selector }) => selector),
    artifact_selector_summary: {
      total_artifact_refs: rawArtifactRefCount,
      selectable_artifact_refs: allSelectors.length,
      selector_count: limited.length,
      omitted_count: Math.max(0, allSelectors.length - limited.length),
      latest_stage: latestStage,
      by_type: byType,
      by_stage: byStage,
    },
  }
}

function buildCompactStagePayload(run: Record<string, unknown>): {
  stage_statuses?: z.infer<typeof CompactStageStatusSchema>[]
  function_index_ready?: boolean
} {
  const stageStatuses: z.infer<typeof CompactStageStatusSchema>[] = []
  let functionIndexReady: boolean | undefined

  for (const stage of recordArray(run.stages).slice(0, STAGE_STATUS_LIMIT)) {
    const parsed = CompactStageStatusSchema.safeParse({
      stage: stage.stage,
      status: stage.status,
      execution_state:
        typeof stage.execution_state === 'string' || stage.execution_state === null
          ? stage.execution_state
          : undefined,
      recovery_state: typeof stage.recovery_state === 'string' ? stage.recovery_state : 'none',
      job_id: typeof stage.job_id === 'string' || stage.job_id === null ? stage.job_id : undefined,
    })
    if (parsed.success) stageStatuses.push(parsed.data)

    if (stage.stage === 'function_map') {
      const metadata = asRecord(stage.metadata)
      if (typeof metadata.function_index_ready === 'boolean') {
        functionIndexReady = metadata.function_index_ready
      }
    }
  }

  return {
    ...(stageStatuses.length > 0 ? { stage_statuses: stageStatuses } : {}),
    ...(functionIndexReady !== undefined ? { function_index_ready: functionIndexReady } : {}),
  }
}

function compactWorkflowRunData(params: {
  input: z.infer<typeof workflowRunInputSchema>
  routedTool: z.infer<typeof RoutedToolSchema>
  result: WorkerResult
}) {
  const { input, routedTool, result } = params
  const data = asRecord(result.data)
  const run = asRecord(data.run)
  const uploadUrl = stringValue(data.upload_url)
  const planId = stringValue(data.run_id) ?? stringValue(run.id) ?? input.plan_id
  const sampleId = stringValue(data.sample_id) ?? stringValue(run.sample_id) ?? input.sample_id
  const status = stringValue(data.status) ?? stringValue(run.status)
  const latestStage = stringValue(run.latest_stage)
  const artifactSelectorPayload = buildArtifactSelectorPayload({ run, sampleId, latestStage })
  const compactStagePayload = buildCompactStagePayload(run)

  return {
    result_mode: 'workflow_run' as const,
    action: input.action,
    routed_tool: routedTool,
    upload_url: uploadUrl,
    status_url: stringValue(data.status_url),
    token: stringValue(data.token),
    expires_at: stringValue(data.expires_at),
    ttl_seconds: typeof data.ttl_seconds === 'number' ? data.ttl_seconds : undefined,
    plan_id: planId,
    sample_id: sampleId,
    status,
    execution_state: stringValue(data.execution_state),
    current_stage: stringValue(data.current_stage),
    latest_stage: latestStage,
    coverage_level: stringValue(data.coverage_level),
    completion_state: stringValue(data.completion_state),
    coverage_gaps: arrayValue(data.coverage_gaps),
    upgrade_paths: arrayValue(data.upgrade_paths),
    deferred_jobs: arrayValue(data.deferred_jobs),
    recoverable_stages: arrayValue(data.recoverable_stages),
    ...compactStagePayload,
    ...artifactSelectorPayload,
    recommended_workflow_tools: normalizeRecommendedWorkflowTools(data.recommended_next_tools),
    next_actions: toStringArray(data.next_actions).map(normalizeWorkflowNextAction),
    ...(input.include_raw_result ? { routed_result: result } : {}),
    message: uploadUrl
      ? `${input.action} routed through ${routedTool}; upload_url is ready.`
      : planId
        ? `${input.action} routed through ${routedTool}; plan_id=${planId}.`
        : `${input.action} routed through ${routedTool}.`,
  }
}

export function createWorkflowRunHandler(handlers: WorkflowRunHandlers) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = workflowRunInputSchema.parse(args)
      if (isStaticDockerProfile()) {
        if (
          input.action === 'start' &&
          (input.goal !== 'static' || input.allow_transformations || input.allow_live_execution)
        ) {
          throw new Error(
            'E_STATIC_PROFILE_CONTRACT: start requires goal=static, allow_transformations=false, allow_live_execution=false'
          )
        }
        if (
          input.action === 'promote' &&
          (input.stages !== undefined ||
            input.through_stage !== 'function_map' ||
            input.allow_transformations ||
            input.allow_live_execution)
        ) {
          throw new Error(
            'E_STATIC_PROFILE_CONTRACT: promote requires exactly through_stage=function_map and forbids stages/live execution/transformations'
          )
        }
      }
      const routedTool = routedToolFor(input.action)
      const handler =
        input.action === 'request_upload'
          ? handlers.requestUpload
          : input.action === 'status'
            ? handlers.status
            : input.action === 'promote'
              ? handlers.promote
              : handlers.start
      const result = await handler(routedArgs(input))

      if (!result.ok) {
        return {
          ok: false,
          errors: result.errors ?? [`${routedTool} failed`],
          warnings: result.warnings,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      return {
        ok: true,
        data: compactWorkflowRunData({ input, routedTool, result }),
        warnings: result.warnings,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
