import { z } from 'zod'
import type { PluginAspects, ToolDefinition, WorkerResult, WorkflowRecipeSpec } from './sdk.js'

export interface BackendPlanStep {
  id: string
  title: string
  purpose: string
  inputs: string[]
  outputs: string[]
  safety: string[]
}

export interface BackendPlanCandidate {
  id: string
  name: string
  source: string
  role: string
  readiness: 'metadata_only' | 'optional_external' | 'future_worker'
  notes: string[]
}

export interface BackendPlanSpec {
  pluginId: string
  toolName: string
  title: string
  description: string
  backendName: string
  formats: string[]
  platforms: string[]
  architectures: string[]
  capabilities: string[]
  evidence: string[]
  artifactType: string
  category: string
  recipe: WorkflowRecipeSpec
  defaultStages: BackendPlanStep[]
  optionalToolCandidates: BackendPlanCandidate[]
  recommendedNextTools: string[]
  safetyNotes: string[]
}

export const BackendPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID used only for plan context.'),
  goals: z
    .array(z.string())
    .optional()
    .default([])
    .describe(
      'Optional analyst goals for the plan, for example cfg, symbolic, lifting, or decompile.'
    ),
  static_evidence: z
    .array(z.string())
    .optional()
    .default([])
    .describe('Optional existing static evidence tags or artifact IDs to map into the plan.'),
  requested_outputs: z
    .array(z.string())
    .optional()
    .default([])
    .describe('Optional desired outputs. This planner never runs the backend.'),
})

export const BackendPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  evidence: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

export function buildBackendPlanAspects(spec: BackendPlanSpec): PluginAspects {
  return {
    formats: spec.formats,
    platforms: spec.platforms,
    architectures: spec.architectures,
    execution: ['static', 'triage', 'decompilation', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: spec.capabilities,
    evidence: uniqueStrings([...spec.evidence, 'workflow', 'provenance']),
  }
}

export function createBackendPlanToolDefinition(spec: BackendPlanSpec): ToolDefinition {
  return {
    name: spec.toolName,
    description: spec.description,
    inputSchema: BackendPlanInputSchema,
    outputSchema: BackendPlanOutputSchema,
    aspects: buildBackendPlanAspects(spec),
    artifacts: [
      {
        type: spec.artifactType,
        description: `${spec.backendName} passive backend integration plan`,
      },
    ],
    evidence: uniqueStrings([...spec.evidence, 'workflow', 'provenance']).map((category) => ({
      category,
      artifactTypes: [spec.artifactType],
    })),
    workflowRecipes: [spec.recipe],
  }
}

export function buildBackendPlan(
  spec: BackendPlanSpec,
  input: z.infer<typeof BackendPlanInputSchema>
) {
  const goals = uniqueStrings(input.goals ?? [])
  const staticEvidence = uniqueStrings(input.static_evidence ?? [])
  const requestedOutputs = uniqueStrings(input.requested_outputs ?? [])
  const stages = spec.defaultStages.map((stage) => ({
    ...stage,
    selected:
      goals.length === 0 ||
      goals.some((goal) =>
        [stage.id, stage.title, stage.purpose, ...stage.outputs]
          .join(' ')
          .toLowerCase()
          .includes(goal.toLowerCase())
      ),
  }))

  return {
    sample_id: input.sample_id ?? null,
    backend: spec.backendName,
    status: 'plan_only',
    goals,
    requested_outputs: requestedOutputs,
    static_correlation: {
      provided_evidence: staticEvidence,
      recommended_inputs: uniqueStrings(spec.defaultStages.flatMap((stage) => stage.inputs)),
    },
    stages,
    optional_tool_candidates: spec.optionalToolCandidates,
    output_artifacts: uniqueStrings([
      spec.artifactType,
      ...spec.defaultStages.flatMap((stage) => stage.outputs),
      ...requestedOutputs,
    ]),
    recommended_next_tools: spec.recommendedNextTools,
    next_actions: [
      'Run tool.readiness for the selected backend before adding an execution worker.',
      'Use existing static artifacts as inputs; do not re-run heavy backends during default triage.',
      'Implement a bounded worker and fixture tests before enabling actual backend invocation.',
    ],
    safety_notes: [
      'No backend process was started.',
      'No sample was executed, emulated, lifted, decompiled, networked, or mounted.',
      ...spec.safetyNotes,
    ],
    execution_semantics: {
      requested_mode: 'plan_only',
      actual_mode: 'plan_only',
      backend: spec.toolName,
      live_execution: false,
      reason: `${spec.backendName} integration plan generated locally.`,
    },
    policy: {
      passive: true,
      no_execute: true,
      no_backend_start: true,
      no_network: true,
    },
    summary: `${spec.backendName} plan prepared with ${stages.length} stage(s) and ${spec.optionalToolCandidates.length} optional backend candidate(s).`,
  }
}

export function createBackendPlanHandler(spec: BackendPlanSpec) {
  return async (args: z.infer<typeof BackendPlanInputSchema>): Promise<WorkerResult> => {
    const input = BackendPlanInputSchema.parse(args)
    return {
      ok: true,
      data: buildBackendPlan(spec, input),
      evidence: [
        {
          id: `${spec.pluginId}:backend-plan:${input.sample_id ?? 'unspecified'}`,
          category: 'workflow',
          source: spec.pluginId,
          toolName: spec.toolName,
          sampleId: input.sample_id,
          confidence: 1,
          metadata: {
            planning_only: true,
            backend: spec.backendName,
            artifact_type: spec.artifactType,
          },
        },
      ],
      metrics: {
        elapsed_ms: 0,
        tool: spec.toolName,
      },
    }
  }
}
