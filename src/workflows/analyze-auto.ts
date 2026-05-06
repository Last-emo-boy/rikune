import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import { dedupeStrings } from '../utils/shared-helpers.js'
import {
  AnalysisIntentDepthSchema,
  AnalysisIntentGoalSchema,
  BackendPolicySchema,
  BackendRoutingMetadataSchema,
  buildIntentBackendPlan,
  mergeRoutingMetadata,
} from '../intent-routing.js'
import {
  CoverageEnvelopeSchema,
  buildBudgetDowngradeReasons,
  buildCoverageEnvelope,
  classifySampleSizeTier,
  deriveAnalysisBudgetProfile,
  mergeCoverageEnvelope,
} from '../analysis/analysis-coverage.js'
import { resolveAnalysisBackends } from '../static-backend-discovery.js'
import {
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
} from './analyze-pipeline.js'
import type { PolicyGuard } from '../policy-guard.js'
import type { SamplingClient } from '../core/registrar.js'

const TOOL_NAME = 'workflow.analyze.auto'

export const analyzeAutoWorkflowInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  goal: AnalysisIntentGoalSchema.default('triage').describe(
    'Analyst intent. The server routes to an appropriate workflow or safe dynamic path.'
  ),
  depth: AnalysisIntentDepthSchema.default('balanced').describe(
    'Controls how aggressively the server selects safe corroborating backends. Prefer safe/balanced first for medium or larger samples; reserve deep for smaller or already-triaged samples.'
  ),
  backend_policy: BackendPolicySchema.default('auto').describe(
    'Controls whether newer installed backends are preferred, suppressed, or only used when needed.'
  ),
  allow_transformations: z
    .boolean()
    .default(false)
    .describe(
      'Keep false for routine analysis. True only permits later explicit transform-capable follow-ups; it does not auto-run them.'
    ),
  allow_live_execution: z
    .boolean()
    .default(false)
    .describe(
      'Dynamic routing still defaults to readiness and safe simulation first. Wine/live execution stays manual-only even when this flag is true.'
    ),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache in delegated workflows when supported.'),
  raw_result_mode: z
    .enum(['compact', 'full'])
    .default('compact')
    .describe(
      'Compatibility option accepted by older clients. workflow.analyze.auto now routes through workflow.analyze.start/promote and keeps staged outputs compact.'
    ),
  include_cfg: z
    .boolean()
    .default(false)
    .describe(
      'Compatibility option accepted by older clients. Deeper CFG work is selected through workflow.analyze.promote stages.'
    ),
})

export const analyzeAutoWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      goal: AnalysisIntentGoalSchema,
      depth: AnalysisIntentDepthSchema,
      backend_policy: BackendPolicySchema,
      routed_tool: z.string(),
      status: z.string().optional(),
      job_id: z.string().optional(),
      polling_guidance: z.any().optional(),
      routed_result: z.any().optional(),
      dynamic_preflight: z.any().optional(),
      sandbox: z.any().optional(),
      backend_enrichments: z
        .object({
          qiling: z.any().optional(),
          panda: z.any().optional(),
        })
        .optional(),
      result_mode: z.enum(['delegated', 'queued', 'completed']),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .extend(CoverageEnvelopeSchema.shape)
    .extend(BackendRoutingMetadataSchema.shape)
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

export const analyzeAutoWorkflowToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Intent-routed analysis entrypoint. Prefer this when the user asks for analysis, reverse engineering, dynamic checks, or reporting without naming a specific workflow or backend. ' +
    'The server chooses an existing workflow layer and only selects safe corroborating backends automatically. ' +
    'This router delegates to workflow.analyze.start and, for non-triage goals, workflow.analyze.promote; it does not launch legacy heavyweight workflows directly. ' +
    'Read coverage_level, completion_state, coverage_gaps, and upgrade_paths on the result before assuming a deeper stage was reached. ' +
    '\n\nDecision guide:\n' +
    '- Use when: the user says analyze / triage / reverse / dynamic / summarize without specifying an exact backend.\n' +
    '- Small-sample default: goal=triage with depth=balanced is usually the best first call; inspect recommended_next_tools before escalating.\n' +
    '- Large-sample default: expect a persisted run with bounded output first; prefer workflow.analyze.status and workflow.analyze.promote over direct heavyweight tools.\n' +
    '- Do not use when: the user explicitly names a backend wrapper such as rizin.analyze or retdec.decompile.\n' +
    '- Typical next step: inspect routed_tool and routing metadata, then continue with task.status, artifact.read, or the recommended_next_tools.\n' +
    '- Common mistake: assuming allow_live_execution automatically launches Wine; live execution remains approval-gated.',
  inputSchema: analyzeAutoWorkflowInputSchema,
  outputSchema: analyzeAutoWorkflowOutputSchema,
}

interface AnalyzeAutoWorkflowDependencies {
  analyzeStartHandler?: ReturnType<typeof createAnalyzeWorkflowStartHandler>
  analyzePromoteHandler?: ReturnType<typeof createAnalyzeWorkflowPromoteHandler>
  resolveBackends?: typeof resolveAnalysisBackends
}

function extractRoutingMetadata(
  payload: unknown
): z.infer<typeof BackendRoutingMetadataSchema> | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }

  const parsed = BackendRoutingMetadataSchema.safeParse(payload)
  return parsed.success ? parsed.data : null
}

function extractCoverageEnvelope(payload: unknown): z.infer<typeof CoverageEnvelopeSchema> | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }

  const parsed = CoverageEnvelopeSchema.safeParse(payload)
  return parsed.success ? parsed.data : null
}

export function createAnalyzeAutoWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  policyGuard: PolicyGuard,
  server?: SamplingClient,
  dependencies: AnalyzeAutoWorkflowDependencies = {},
  jobQueue?: JobQueue
) {
  const analyzeStartHandler =
    dependencies.analyzeStartHandler ||
    createAnalyzeWorkflowStartHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      server,
      {},
      jobQueue
    )
  const analyzePromoteHandler =
    dependencies.analyzePromoteHandler ||
    createAnalyzeWorkflowPromoteHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      server,
      {},
      jobQueue
    )

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = analyzeAutoWorkflowInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const sampleSizeTier = classifySampleSizeTier(sample.size || 0)
      const analysisBudgetProfile = deriveAnalysisBudgetProfile(input.depth, sampleSizeTier)
      const budgetDowngradeReasons = buildBudgetDowngradeReasons({
        requestedDepth: input.depth,
        sampleSizeTier,
        analysisBudgetProfile,
      })

      const readiness = (dependencies.resolveBackends || resolveAnalysisBackends)()
      const fallbackRouting = buildIntentBackendPlan({
        goal: input.goal,
        depth: input.depth,
        backendPolicy: input.backend_policy,
        allowTransformations: input.allow_transformations,
        allowLiveExecution: input.allow_live_execution,
        readiness,
      })

      const startDelegated = await analyzeStartHandler({
        sample_id: input.sample_id,
        goal: input.goal,
        depth: input.depth,
        backend_policy: input.backend_policy,
        allow_transformations: input.allow_transformations,
        allow_live_execution: input.allow_live_execution,
        force_refresh: input.force_refresh,
      })
      if (!startDelegated.ok || !startDelegated.data) {
        return {
          ok: false,
          errors: startDelegated.errors || ['workflow.analyze.start failed'],
          warnings: startDelegated.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const startPayload =
        startDelegated.data && typeof startDelegated.data === 'object'
          ? (startDelegated.data as Record<string, unknown>)
          : {}
      const startRouting = extractRoutingMetadata(startDelegated.data) || fallbackRouting
      const startCoverage =
        extractCoverageEnvelope(startDelegated.data) ||
        buildCoverageEnvelope({
          coverageLevel: 'quick',
          completionState: 'bounded',
          sampleSizeTier,
          analysisBudgetProfile,
          downgradeReasons: budgetDowngradeReasons,
        })

      if (input.goal === 'triage') {
        return {
          ok: true,
          data: mergeRoutingMetadata(
            mergeCoverageEnvelope(
              {
                ...startPayload,
                sample_id: input.sample_id,
                goal: input.goal,
                depth: input.depth,
                backend_policy: input.backend_policy,
                routed_tool: 'workflow.analyze.start',
                routed_result: startPayload.stage_result,
                result_mode: startPayload.execution_state === 'queued' ? 'queued' : 'completed',
                recommended_next_tools: (startPayload.recommended_next_tools as string[]) || [
                  'workflow.analyze.promote',
                  'workflow.analyze.status',
                ],
                next_actions: (startPayload.next_actions as string[]) || [
                  'Promote the persisted run instead of repeating fast-profile analysis when you need deeper stages.',
                ],
              },
              startCoverage
            ),
            startRouting
          ),
          warnings: startDelegated.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const throughStage =
        input.goal === 'reverse'
          ? 'reconstruct'
          : input.goal === 'report'
            ? 'summarize'
            : input.goal === 'dynamic'
              ? input.allow_live_execution
                ? 'dynamic_execute'
                : 'dynamic_plan'
              : analysisBudgetProfile === 'quick'
                ? 'enrich_static'
                : 'function_map'

      const runId = typeof startPayload.run_id === 'string' ? startPayload.run_id : ''
      if (!runId) {
        return {
          ok: false,
          errors: ['workflow.analyze.start did not return a run_id for promotion.'],
          warnings: startDelegated.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const promoteDelegated = await analyzePromoteHandler({
        run_id: runId,
        through_stage: throughStage,
        force_refresh: input.force_refresh,
      })
      if (!promoteDelegated.ok || !promoteDelegated.data) {
        return {
          ok: false,
          errors: promoteDelegated.errors || ['workflow.analyze.promote failed'],
          warnings: [...(startDelegated.warnings || []), ...(promoteDelegated.warnings || [])],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const promotePayload =
        promoteDelegated.data && typeof promoteDelegated.data === 'object'
          ? (promoteDelegated.data as Record<string, unknown>)
          : {}
      const promoteRouting = extractRoutingMetadata(promoteDelegated.data) || startRouting
      const promoteCoverage = extractCoverageEnvelope(promoteDelegated.data) || startCoverage

      return {
        ok: true,
        data: mergeRoutingMetadata(
          mergeCoverageEnvelope(
            {
              ...promotePayload,
              sample_id: input.sample_id,
              goal: input.goal,
              depth: input.depth,
              backend_policy: input.backend_policy,
              routed_tool: 'workflow.analyze.promote',
              routed_result: promotePayload.stage_result || promotePayload,
              result_mode: promotePayload.execution_state === 'queued' ? 'queued' : 'completed',
              recommended_next_tools: (promotePayload.recommended_next_tools as string[]) || [
                'workflow.analyze.status',
                'workflow.analyze.promote',
              ],
              next_actions: (promotePayload.next_actions as string[]) || [
                'Use workflow.analyze.status to monitor the persisted run instead of rerunning heavyweight workflows.',
              ],
            },
            promoteCoverage
          ),
          promoteRouting
        ),
        warnings: dedupeStrings([
          ...(startDelegated.warnings || []),
          ...(promoteDelegated.warnings || []),
        ]),
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
