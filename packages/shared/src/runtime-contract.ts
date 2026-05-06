import { z } from 'zod'

export interface ArtifactRef {
  id: string
  type: string
  path: string
  sha256: string
  mime?: string
  metadata?: Record<string, unknown>
}

export interface RuntimeExecutionSemantics {
  requested_mode?: RuntimeExecutionMode | string
  actual_mode?: RuntimeExecutionMode | string
  backend?: string
  live_execution?: boolean
  reason?: string
}

export interface WorkerResult {
  ok: boolean
  status?: 'completed' | 'queued' | 'blocked' | 'degraded' | 'failed'
  data?: unknown
  errors?: string[]
  warnings?: string[]
  setup_actions?: unknown[]
  required_user_inputs?: unknown[]
  artifacts?: ArtifactRef[]
  metrics?: Record<string, unknown>
  execution_semantics?: RuntimeExecutionSemantics
}

export type RuntimeBackendType = 'python-worker' | 'spawn' | 'inline'

export type RuntimeExecutionMode =
  | 'plan_only'
  | 'safe_simulation'
  | 'emulation'
  | 'live_sandbox'
  | 'live_hyperv'
  | 'manual_runtime'

export interface RuntimeFallbackRule {
  mode: RuntimeExecutionMode
  reason?: string
}

export interface ToolRuntimeContract {
  type: RuntimeBackendType
  handler: string
  modes?: RuntimeExecutionMode[]
  requiredProfiles?: string[]
  requiredTools?: string[]
  optionalTools?: string[]
  produces?: string[]
  timeoutMs?: number
  fallback?: RuntimeFallbackRule[]
}

export interface RuntimeBackendCapability extends ToolRuntimeContract {
  description?: string
  requiresSample?: boolean
}

export const RuntimeExecutionModeSchema = z.enum([
  'plan_only',
  'safe_simulation',
  'emulation',
  'live_sandbox',
  'live_hyperv',
  'manual_runtime',
])

export const RuntimeFallbackRuleSchema = z.object({
  mode: RuntimeExecutionModeSchema,
  reason: z.string().optional(),
})

export const ToolRuntimeContractSchema = z.object({
  type: z.enum(['python-worker', 'spawn', 'inline']),
  handler: z.string(),
  modes: z.array(RuntimeExecutionModeSchema).optional(),
  requiredProfiles: z.array(z.string()).optional(),
  requiredTools: z.array(z.string()).optional(),
  optionalTools: z.array(z.string()).optional(),
  produces: z.array(z.string()).optional(),
  timeoutMs: z.number().int().positive().optional(),
  fallback: z.array(RuntimeFallbackRuleSchema).optional(),
})

export const RuntimeBackendCapabilitySchema = ToolRuntimeContractSchema.extend({
  description: z.string().optional(),
  requiresSample: z.boolean().optional(),
})

export const RuntimeDelegationFailureCategorySchema = z.enum([
  'runtime_unavailable',
  'unsupported_runtime_contract',
  'runtime_recovery_failed',
  'tool_specific_execution_failed',
])

export type RuntimeDelegationFailureCategory = z.infer<
  typeof RuntimeDelegationFailureCategorySchema
>

export const RuntimeDelegationFailureDataSchema = z.object({
  status: z.enum(['setup_required', 'failed']),
  failure_category: RuntimeDelegationFailureCategorySchema,
  summary: z.string(),
  runtime_plane: z
    .enum(['runtime_endpoint', 'host_agent', 'runtime_node', 'runtime_capability', 'tool_backend'])
    .optional(),
  execution_semantics: z
    .object({
      requested_mode: z.string().optional(),
      actual_mode: z.string().optional(),
      backend: z.string().optional(),
      live_execution: z.boolean().optional(),
      reason: z.string().optional(),
    })
    .optional(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  runtime_endpoint: z.string().nullable().optional(),
  required_runtime_contract: ToolRuntimeContractSchema.optional(),
  available_runtime_backends: z.array(RuntimeBackendCapabilitySchema).optional(),
})

export const RuntimeDelegationFailureResultSchema = z.object({
  ok: z.boolean(),
  data: RuntimeDelegationFailureDataSchema,
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})
