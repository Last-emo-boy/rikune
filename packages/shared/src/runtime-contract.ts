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
  evidence?: unknown[]
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

export type RuntimeIsolationBackend =
  | 'local'
  | 'docker'
  | 'windows-sandbox'
  | 'hyperv'
  | 'windows-host-agent'
  | 'wine'
  | 'speakeasy'
  | 'qiling'
  | 'unicorn'
  | 'frida'
  | 'frida-server'
  | 'adb'
  | 'android-emulator'
  | 'lldb'
  | 'gdb'
  | 'strace'
  | 'ltrace'
  | 'dtrace'
  | 'fs-usage'
  | 'sandbox-exec'
  | 'codesign-runtime'
  | 'idevice-tools'
  | 'ebpf'
  | 'seccomp'
  | 'ptrace'
  | 'wasmtime'

export type RuntimeNetworkPolicy = 'disabled' | 'record_only' | 'restricted' | 'allowed'

export interface DynamicRuntimePolicy {
  passiveByDefault?: boolean
  requiresUserOptIn?: boolean
  requiresIsolation?: boolean
  allowedBackends?: RuntimeIsolationBackend[]
  maxRuntimeMs?: number
  networkPolicy?: RuntimeNetworkPolicy
  notes?: string[]
}

export interface RuntimeIsolationRequirement {
  required?: boolean
  backends?: RuntimeIsolationBackend[]
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
  capabilities?: string[]
  safety?: string[]
  policy?: DynamicRuntimePolicy
  isolation?: RuntimeIsolationRequirement
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

export const RuntimeIsolationBackendSchema = z.enum([
  'local',
  'docker',
  'windows-sandbox',
  'hyperv',
  'windows-host-agent',
  'wine',
  'speakeasy',
  'qiling',
  'unicorn',
  'frida',
  'frida-server',
  'adb',
  'android-emulator',
  'lldb',
  'gdb',
  'strace',
  'ltrace',
  'dtrace',
  'fs-usage',
  'sandbox-exec',
  'codesign-runtime',
  'idevice-tools',
  'ebpf',
  'seccomp',
  'ptrace',
  'wasmtime',
])

export const RuntimeNetworkPolicySchema = z.enum([
  'disabled',
  'record_only',
  'restricted',
  'allowed',
])

export const DynamicRuntimePolicySchema = z
  .object({
    passiveByDefault: z.boolean().optional(),
    requiresUserOptIn: z.boolean().optional(),
    requiresIsolation: z.boolean().optional(),
    allowedBackends: z.array(RuntimeIsolationBackendSchema).optional(),
    maxRuntimeMs: z.number().int().positive().optional(),
    networkPolicy: RuntimeNetworkPolicySchema.optional(),
    notes: z.array(z.string()).optional(),
  })
  .passthrough()

export const RuntimeIsolationRequirementSchema = z
  .object({
    required: z.boolean().optional(),
    backends: z.array(RuntimeIsolationBackendSchema).optional(),
    reason: z.string().optional(),
  })
  .passthrough()

export const ToolRuntimeContractSchema = z
  .object({
    type: z.enum(['python-worker', 'spawn', 'inline']),
    handler: z.string().min(1, 'String must contain at least 1 character'),
    modes: z.array(RuntimeExecutionModeSchema).optional(),
    requiredProfiles: z.array(z.string()).optional(),
    requiredTools: z.array(z.string()).optional(),
    optionalTools: z.array(z.string()).optional(),
    produces: z.array(z.string()).optional(),
    capabilities: z.array(z.string()).optional(),
    safety: z.array(z.string()).optional(),
    policy: DynamicRuntimePolicySchema.optional(),
    isolation: RuntimeIsolationRequirementSchema.optional(),
    timeoutMs: z.number().int().positive().optional(),
    fallback: z.array(RuntimeFallbackRuleSchema).optional(),
  })
  .passthrough()

export const RuntimeBackendCapabilitySchema = ToolRuntimeContractSchema.extend({
  description: z.string().optional(),
  requiresSample: z.boolean().optional(),
}).passthrough()

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
