import { z } from 'zod'
import type { BackendWorkerContract, PluginAspects, ToolDefinition, WorkerResult } from './sdk.js'
import { buildBackendWorkerRequest, runBackendWorker } from '../worker/backend-worker-client.js'

export const FrontierWorkerInputSchema = z.object({
  sample_id: z.string().optional(),
  path: z.string().optional().describe('Local workspace artifact path.'),
  source_path: z.string().optional().describe('Alias for path when chaining artifacts.'),
  output_path: z
    .string()
    .optional()
    .describe('Optional output artifact path for configured workers.'),
  mode: z
    .enum(['builtin', 'external', 'delegated-runtime'])
    .optional()
    .default('builtin')
    .describe(
      'builtin uses the safe built-in adapter; external requires configured backend metadata.'
    ),
  preview: z.boolean().optional().default(true),
  timeout_ms: z.number().int().positive().max(600_000).optional(),
  max_input_bytes: z.number().int().positive().optional(),
  goals: z.array(z.string()).optional().default([]),
  artifacts: z.array(z.string()).optional().default([]),
  profile: z.record(z.any()).optional(),
  passes: z.array(z.string()).optional().default([]),
  target: z
    .object({
      architecture: z.string().optional(),
      function: z.string().optional(),
      address: z.string().optional(),
      range: z.string().optional(),
    })
    .passthrough()
    .optional(),
  approved: z.boolean().optional().default(false),
})

export const FrontierWorkerOutputSchema = z
  .object({
    ok: z.boolean(),
    data: z.record(z.any()).optional(),
    warnings: z.array(z.string()).optional(),
    errors: z.array(z.string()).optional(),
    artifacts: z.array(z.any()).optional(),
    evidence: z.array(z.any()).optional(),
    metrics: z.record(z.any()).optional(),
  })
  .passthrough()

export interface FrontierWorkerToolSpec {
  pluginId: string
  toolName: string
  description: string
  backendName: string
  adapter: string
  backendKind?: BackendWorkerContract['backendKind']
  envVar?: string
  aspects: PluginAspects
  artifacts: Array<{ type: string; description?: string }>
  evidence: Array<{ category: string; artifactTypes?: string[] }>
  workflowRecipe: NonNullable<ToolDefinition['workflowRecipes']>[number]
  policy?: BackendWorkerContract['policy']
  readinessSetupActions?: string[]
  fixtureData: Record<string, unknown>
  recommendedNextTools: string[]
}

export function createFrontierWorkerContract(spec: FrontierWorkerToolSpec): BackendWorkerContract {
  return {
    version: 'backend-worker.v1',
    backendName: spec.backendName,
    backendKind: spec.backendKind ?? 'external',
    adapter: spec.adapter,
    availability: spec.backendKind === 'builtin' ? 'builtin' : 'optional',
    envVar: spec.envVar,
    supportedModes:
      spec.backendKind === 'delegated-runtime'
        ? ['delegated-runtime']
        : spec.backendKind === 'builtin'
          ? ['builtin']
          : ['builtin', 'external'],
    defaultMode: spec.backendKind === 'delegated-runtime' ? 'delegated-runtime' : 'builtin',
    inputArtifactTypes: ['local_artifact'],
    outputArtifactTypes: spec.artifacts.map((artifact) => artifact.type),
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: spec.backendKind === 'delegated-runtime',
      requiresIsolation: spec.backendKind === 'delegated-runtime',
      noNetwork: true,
      noMutation: true,
      noLiveExecution: spec.backendKind !== 'delegated-runtime',
      defaultTimeoutMs: 30_000,
      maxInputBytes: 5 * 1024 * 1024,
      maxOutputBytes: 10 * 1024 * 1024,
      ...spec.policy,
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: spec.readinessSetupActions ?? [],
      missingBackendBehavior:
        'The worker returns backend_missing or uses builtin fixture-safe mode; readiness never starts the backend.',
    },
  }
}

export function createFrontierWorkerToolDefinition(spec: FrontierWorkerToolSpec): ToolDefinition {
  return {
    name: spec.toolName,
    description: spec.description,
    inputSchema: FrontierWorkerInputSchema,
    outputSchema: FrontierWorkerOutputSchema,
    aspects: spec.aspects,
    artifacts: spec.artifacts,
    evidence: spec.evidence,
    workflowRecipes: [spec.workflowRecipe],
    runtimePolicy:
      spec.backendKind === 'delegated-runtime'
        ? {
            passiveByDefault: true,
            requiresUserOptIn: true,
            requiresIsolation: true,
            networkPolicy: 'disabled',
            maxRuntimeMs: spec.policy?.defaultTimeoutMs ?? 30_000,
            notes: ['Runtime worker requires explicit opt-in and delegated isolation.'],
          }
        : undefined,
    workerBackend: createFrontierWorkerContract(spec),
  }
}

export function createFrontierWorkerHandler(spec: FrontierWorkerToolSpec) {
  return async (args: z.infer<typeof FrontierWorkerInputSchema>): Promise<WorkerResult> => {
    const input = FrontierWorkerInputSchema.parse(args)
    const definition = createFrontierWorkerToolDefinition(spec)
    const backend = definition.workerBackend!
    const request = buildBackendWorkerRequest({
      tool: spec.toolName,
      backend,
      args: input,
    })
    const result = await runBackendWorker(request, {
      mode: input.mode,
      timeoutMs: input.timeout_ms,
      approved: input.approved,
      fixtureData: {
        plugin_id: spec.pluginId,
        recommended_next_tools: spec.recommendedNextTools,
        ...spec.fixtureData,
      },
    })

    if (result.ok && result.data && typeof result.data === 'object') {
      result.data = {
        ...(result.data as Record<string, unknown>),
        selected_passes: input.passes,
        goals: input.goals,
        target: input.target ?? null,
      }
    }

    return result
  }
}
