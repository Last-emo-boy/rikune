import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import {
  AnalysisIntentDepthSchema,
  AnalysisIntentGoalSchema,
  BackendPolicySchema,
} from '../intent-routing.js'
import { AnalysisPipelineStageSchema } from '../analysis/analysis-run-state.js'
import { toStringArray } from '../utils/shared-helpers.js'

const TOOL_NAME = 'workflow.run'
const WorkflowRunActionSchema = z.enum(['request_upload', 'start', 'status', 'promote'])
const RoutedToolSchema = z.enum([
  'sample.request_upload',
  'workflow.analyze.start',
  'workflow.analyze.status',
  'workflow.analyze.promote',
])

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
