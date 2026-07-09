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

function buildBlockedExecutionReasons(spec: BackendPlanSpec): string[] {
  return uniqueStrings([
    'default_mode_is_plan_only',
    'external_backend_not_invoked_by_planner',
    'bounded_worker_contract_required',
    'explicit_analyst_opt_in_required',
    'fixture_and_timeout_guard_required',
    ...spec.safetyNotes.map((note) => note.toLowerCase().replace(/[^a-z0-9]+/g, '_')),
  ]).slice(0, 12)
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
  data: z.record(z.string(), z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  evidence: z.array(z.any()).optional(),
  metrics: z.record(z.string(), z.any()).optional(),
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
  const selectedStages = stages.filter((stage) => stage.selected)
  const contractStages = selectedStages.length > 0 ? selectedStages : spec.defaultStages
  const selectedStageIds = selectedStages.map((stage) => stage.id)
  const blockedExecutionReasons = buildBlockedExecutionReasons(spec)
  const handoffRequirements = uniqueStrings([
    'Pin backend version, binary path, container image, or local worker checkout.',
    'Declare strict input artifact types, size limits, timeout limits, and output artifact schema.',
    'Add fixture-backed tests for success, unsupported input, timeout, and malformed backend output.',
    'Route execution through tool.readiness and require explicit analyst opt-in before backend start.',
    'Keep network, mount, mutation, debugger attach, solver, emulator, and interpreter access disabled unless separately approved.',
  ])
  const futureWorkerContract = {
    status: 'not_implemented',
    contract_version: 'backend-worker.v1',
    backend: spec.backendName,
    readiness: 'future_worker_required',
    required_inputs: uniqueStrings(contractStages.flatMap((stage) => stage.inputs)),
    expected_outputs: uniqueStrings([
      spec.artifactType,
      ...contractStages.flatMap((stage) => stage.outputs),
      ...requestedOutputs,
    ]),
    handoff_requirements: handoffRequirements,
    acceptance_criteria: [
      'Worker refuses to run without explicit backend path/version metadata.',
      'Worker accepts only local workspace artifacts and bounded ranges or files.',
      'Worker returns structured artifacts, evidence refs, metrics, warnings, and policy metadata.',
      'Worker tests prove no backend starts from discovery, readiness, help, profile, or default plan paths.',
    ],
  }

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
    selected_stage_ids: selectedStageIds,
    selected_stage_count: selectedStages.length,
    blocked_execution_reasons: blockedExecutionReasons,
    handoff_requirements: handoffRequirements,
    future_worker_contract: futureWorkerContract,
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
    summary: `${spec.backendName} plan prepared with ${selectedStages.length}/${stages.length} selected stage(s) and ${spec.optionalToolCandidates.length} optional backend candidate(s).`,
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
