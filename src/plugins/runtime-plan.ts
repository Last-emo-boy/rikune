import { z } from 'zod'
import type { DynamicRuntimePolicy, PluginAspects, ToolDefinition, WorkerResult } from './sdk.js'

export interface RuntimeBackendPlan {
  backend: string
  purpose: string
  readiness_checks: string[]
  setup_tools: string[]
  execution_tools: string[]
  evidence: string[]
  limitations?: string[]
}

export interface RuntimeSessionTemplate {
  id: string
  backend: string
  purpose: string
  template_only: true
  explicit_opt_in_required: true
  live_execution: false
  isolation: {
    required: true
    profile: string
    notes: string[]
  }
  network: {
    default_policy: 'disabled'
    allowed_after_opt_in: string[]
  }
  mounts: Array<{
    name: string
    mode: 'ro' | 'rw'
    required: boolean
    path_template: string
  }>
  artifacts: Array<{
    type: string
    evidence: string[]
    required: boolean
  }>
  readiness_checks: string[]
  setup_tools: string[]
  execution_tools: string[]
  teardown: string[]
  safety_notes: string[]
}

export interface RuntimePlanSpec {
  pluginId: string
  toolName: string
  description: string
  platform: string
  formats: string[]
  runtimes: string[]
  capabilities: string[]
  evidence: string[]
  recommendedStaticTools: string[]
  recommendedControlTools: string[]
  backends: RuntimeBackendPlan[]
  staticCorrelation: string[]
  safetyNotes: string[]
  nextActions: string[]
}

export const RuntimePlanInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample ID used to render runtime command templates.'),
  file_type: z.string().optional().describe('Optional known file type or profile tag.'),
  goals: z
    .array(z.string())
    .optional()
    .default([])
    .describe(
      'Optional dynamic-analysis goals, for example behavior, crypto, filesystem, network.'
    ),
  requested_backends: z
    .array(z.string())
    .optional()
    .default([])
    .describe('Optional backend preference list. This tool only returns a plan.'),
  static_evidence: z
    .array(z.string())
    .optional()
    .default([])
    .describe('Optional static evidence tags to map into runtime probes.'),
  include_command_templates: z
    .boolean()
    .optional()
    .default(true)
    .describe('Include non-executed command templates for explicit runtime handoff.'),
})

export const RuntimePlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.string(), z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  evidence: z.array(z.any()).optional(),
  metrics: z.record(z.string(), z.any()).optional(),
})

export type RuntimePlanInput = z.infer<typeof RuntimePlanInputSchema>

export function buildRuntimePlanAspects(spec: RuntimePlanSpec): PluginAspects {
  return {
    formats: spec.formats,
    platforms: [spec.platform],
    execution: ['dynamic'],
    runtimes: spec.runtimes,
    safety: [
      'passive',
      'opt_in_dynamic',
      'requires_isolation',
      'no_live_sample_by_default',
      'no_network_by_default',
    ],
    capabilities: spec.capabilities,
    evidence: spec.evidence,
  }
}

export function buildRuntimePlanPolicy(spec: RuntimePlanSpec): DynamicRuntimePolicy {
  return {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: true,
    allowedBackends: spec.runtimes as DynamicRuntimePolicy['allowedBackends'],
    maxRuntimeMs: 120_000,
    networkPolicy: 'disabled',
    notes: [
      `${spec.toolName} is a passive planning/readiness tool; it never starts a runtime backend.`,
      ...spec.safetyNotes,
    ],
  }
}

export function createRuntimePlanToolDefinition(spec: RuntimePlanSpec): ToolDefinition {
  const artifactType = `${spec.pluginId.replace(/-/g, '_')}_runtime_plan`
  return {
    name: spec.toolName,
    description: spec.description,
    inputSchema: RuntimePlanInputSchema,
    outputSchema: RuntimePlanOutputSchema,
    aspects: buildRuntimePlanAspects(spec),
    artifacts: [
      {
        type: artifactType,
        description: `Passive ${spec.platform} runtime readiness and execution plan.`,
      },
    ],
    evidence: spec.evidence.map((category) => ({
      category,
      artifactTypes: [artifactType],
    })),
    workflowRecipes: [
      {
        id: `${spec.platform}.runtime.opt-in`,
        title: `${spec.platform} runtime opt-in session template`,
        startsWith: [spec.toolName, 'tool.readiness'],
        nextTools: uniqueStrings([
          ...spec.recommendedControlTools,
          ...spec.backends.flatMap((backend) => [
            ...backend.setup_tools,
            ...backend.execution_tools,
          ]),
        ]),
        requiredArtifacts: spec.recommendedStaticTools,
        producesArtifacts: [
          artifactType,
          ...spec.evidence.map((item) => `${spec.platform}_${item}`),
        ],
        evidence: spec.evidence,
        safety: [
          'passive',
          'opt_in_dynamic',
          'requires_isolation',
          'no_live_sample_by_default',
          'no_network_by_default',
        ],
        runtimeBackends: spec.runtimes,
      },
    ],
    runtimePolicy: buildRuntimePlanPolicy(spec),
  }
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function selectBackends(spec: RuntimePlanSpec, requestedBackends: string[]): RuntimeBackendPlan[] {
  if (requestedBackends.length === 0) {
    return spec.backends
  }
  const requested = requestedBackends.map((backend) => backend.toLowerCase().replace(/_/g, '-'))
  const matched = spec.backends.filter((plan) =>
    requested.some((backend) => plan.backend.toLowerCase().replace(/_/g, '-') === backend)
  )
  return matched.length > 0 ? matched : spec.backends
}

function commandTemplatesFor(
  spec: RuntimePlanSpec,
  backends: RuntimeBackendPlan[],
  sampleId?: string
) {
  return backends.map((backend) => ({
    backend: backend.backend,
    status: 'template_only',
    sample_id: sampleId ?? null,
    commands: backend.execution_tools.map((tool) => ({
      tool,
      args: {
        ...(sampleId ? { sample_id: sampleId } : {}),
        backend: backend.backend,
        mode: 'manual_runtime',
      },
    })),
  }))
}

function sessionTemplatesFor(
  spec: RuntimePlanSpec,
  backends: RuntimeBackendPlan[],
  sampleId?: string
): RuntimeSessionTemplate[] {
  return backends.map((backend) => ({
    id: `${spec.platform}.${backend.backend}.opt-in-session`,
    backend: backend.backend,
    purpose: backend.purpose,
    template_only: true,
    explicit_opt_in_required: true,
    live_execution: false,
    isolation: {
      required: true,
      profile: `${spec.platform}-${backend.backend}-isolated`,
      notes: [
        'Create or select an isolated runtime before executing this template.',
        'Do not reuse analyst host state as the runtime workspace.',
      ],
    },
    network: {
      default_policy: 'disabled',
      allowed_after_opt_in: ['disabled', 'record_only', 'simulated'],
    },
    mounts: [
      {
        name: 'sample',
        mode: 'ro',
        required: Boolean(sampleId),
        path_template: sampleId
          ? `workspace://samples/${sampleId}`
          : 'workspace://samples/{sample_id}',
      },
      {
        name: 'artifacts',
        mode: 'rw',
        required: true,
        path_template: `workspace://artifacts/runtime/${spec.platform}/${backend.backend}/{session_id}`,
      },
    ],
    artifacts: [
      {
        type: `${spec.platform}_${backend.backend.replace(/-/g, '_')}_runtime_session`,
        evidence: backend.evidence,
        required: true,
      },
    ],
    readiness_checks: backend.readiness_checks,
    setup_tools: backend.setup_tools,
    execution_tools: backend.execution_tools,
    teardown: [
      'Stop runtime task and collect declared artifacts.',
      'Restore snapshot or discard ephemeral runtime workspace.',
      'Keep network logs and runtime traces attached to provenance metadata.',
    ],
    safety_notes: [
      'This is a non-executed template for an explicit later handoff.',
      ...(backend.limitations ?? []),
      ...spec.safetyNotes,
    ],
  }))
}

export function buildRuntimePlan(spec: RuntimePlanSpec, input: RuntimePlanInput) {
  const goals = uniqueStrings(input.goals ?? [])
  const staticEvidence = uniqueStrings(input.static_evidence ?? [])
  const backends = selectBackends(spec, input.requested_backends ?? [])
  const evidencePlan = uniqueStrings(backends.flatMap((backend) => backend.evidence))
  const setupTools = uniqueStrings(backends.flatMap((backend) => backend.setup_tools))
  const executionTools = uniqueStrings(backends.flatMap((backend) => backend.execution_tools))
  const includeTemplates = input.include_command_templates !== false
  const sessionTemplates = includeTemplates
    ? sessionTemplatesFor(spec, backends, input.sample_id)
    : []

  return {
    sample_id: input.sample_id ?? null,
    file_type: input.file_type ?? null,
    platform: spec.platform,
    formats: spec.formats,
    goals,
    requested_backends: input.requested_backends ?? [],
    selected_backends: backends,
    readiness: {
      status: 'plan_only',
      live_execution: false,
      opt_in_required: true,
      requires_isolation: true,
      allowed_backends: spec.runtimes,
      backend_missing: false,
      policy_denied: true,
      reason:
        'This tool only builds a runtime plan. Live execution requires explicit opt-in and an isolated backend selected outside this handler.',
    },
    policy: buildRuntimePlanPolicy(spec),
    static_correlation: {
      provided_evidence: staticEvidence,
      mapping: spec.staticCorrelation,
      recommended_static_tools: spec.recommendedStaticTools,
    },
    evidence_plan: evidencePlan,
    session_templates: sessionTemplates,
    command_templates: includeTemplates ? commandTemplatesFor(spec, backends, input.sample_id) : [],
    recommended_next_tools: uniqueStrings([
      ...spec.recommendedStaticTools,
      ...spec.recommendedControlTools,
      ...setupTools,
      ...executionTools,
      'tool.readiness',
    ]),
    next_actions: spec.nextActions,
    safety_notes: [
      'No runtime backend was started.',
      'No sample was installed, executed, attached, mounted, traced, or networked.',
      ...spec.safetyNotes,
    ],
    execution_semantics: {
      requested_mode: 'plan_only',
      actual_mode: 'plan_only',
      backend: spec.toolName,
      live_execution: false,
      reason: 'Platform runtime plan generated locally.',
    },
  }
}

export function createRuntimePlanHandler(spec: RuntimePlanSpec) {
  return async (args: RuntimePlanInput): Promise<WorkerResult> => ({
    ok: true,
    data: buildRuntimePlan(spec, args),
    evidence: [
      {
        id: `${spec.pluginId}:runtime-plan:${args.sample_id ?? 'unspecified'}`,
        category: 'timeline',
        source: spec.pluginId,
        toolName: spec.toolName,
        sampleId: args.sample_id,
        confidence: 1,
        metadata: {
          planning_only: true,
          platform: spec.platform,
          runtimes: spec.runtimes,
        },
      },
    ],
    metrics: {
      tool: spec.toolName,
      elapsed_ms: 0,
    },
  })
}
