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

function uniqueContractValues(values: readonly string[] | undefined): string[] {
  return Array.from(new Set((values ?? []).filter((value) => value.trim().length > 0)))
}

function collectMissingContractValues(
  field: 'modes' | 'requiredTools',
  capability: RuntimeBackendCapability,
  contract: ToolRuntimeContract
): string[] {
  const required = uniqueContractValues(contract[field] as string[] | undefined)
  if (required.length === 0) {
    return []
  }

  const available = uniqueContractValues(capability[field] as string[] | undefined)
  if (available.length === 0) {
    return [`${field}: runtime capability does not declare ${field}`]
  }

  const missing = required.filter((value) => !available.includes(value))
  return missing.length > 0 ? [`${field}: missing ${missing.join(', ')}`] : []
}

function collectMissingIsolationSupport(
  capability: RuntimeBackendCapability,
  contract: ToolRuntimeContract
): string[] {
  const required = contract.isolation
  if (!required) {
    return []
  }

  const available = capability.isolation
  const mismatches: string[] = []
  if (typeof required.required === 'boolean' && available?.required !== required.required) {
    mismatches.push('isolation.required: runtime capability does not match requirement')
  }

  const requiredBackends = uniqueContractValues(required.backends)
  if (requiredBackends.length > 0) {
    const availableBackends = uniqueContractValues(available?.backends)
    if (availableBackends.length === 0) {
      mismatches.push('isolation.backends: runtime capability does not declare isolation backends')
    } else {
      const missing = requiredBackends.filter((backend) => !availableBackends.includes(backend))
      if (missing.length > 0) {
        mismatches.push(`isolation.backends: missing ${missing.join(', ')}`)
      }
    }
  }

  return mismatches
}

function collectMissingPolicySupport(
  capability: RuntimeBackendCapability,
  contract: ToolRuntimeContract
): string[] {
  const required = contract.policy
  if (!required) {
    return []
  }

  const available = capability.policy
  const mismatches: string[] = []
  const booleanFields = ['passiveByDefault', 'requiresUserOptIn', 'requiresIsolation'] as const
  for (const field of booleanFields) {
    if (typeof required[field] === 'boolean' && available?.[field] !== required[field]) {
      mismatches.push(`policy.${field}: runtime capability does not match requirement`)
    }
  }

  if (
    typeof required.networkPolicy === 'string' &&
    available?.networkPolicy !== required.networkPolicy
  ) {
    mismatches.push('policy.networkPolicy: runtime capability does not match requirement')
  }

  if (typeof required.maxRuntimeMs === 'number') {
    if (
      typeof available?.maxRuntimeMs !== 'number' ||
      available.maxRuntimeMs < required.maxRuntimeMs
    ) {
      mismatches.push('policy.maxRuntimeMs: runtime capability budget is below requirement')
    }
  }

  const requiredBackends = uniqueContractValues(required.allowedBackends)
  if (requiredBackends.length > 0) {
    const availableBackends = uniqueContractValues(available?.allowedBackends)
    if (availableBackends.length === 0) {
      mismatches.push(
        'policy.allowedBackends: runtime capability does not declare allowed backends'
      )
    } else {
      const missing = requiredBackends.filter((backend) => !availableBackends.includes(backend))
      if (missing.length > 0) {
        mismatches.push(`policy.allowedBackends: missing ${missing.join(', ')}`)
      }
    }
  }

  return mismatches
}

export function getRuntimeContractSupportMismatches(
  capability: RuntimeBackendCapability,
  contract: ToolRuntimeContract
): string[] {
  const mismatches: string[] = []
  if (capability.type !== contract.type) {
    mismatches.push(`type: expected ${contract.type}, got ${capability.type}`)
  }
  if (capability.handler !== contract.handler) {
    mismatches.push(`handler: expected ${contract.handler}, got ${capability.handler}`)
  }

  if (mismatches.length > 0) {
    return mismatches
  }

  return [
    ...collectMissingContractValues('modes', capability, contract),
    ...collectMissingContractValues('requiredTools', capability, contract),
    ...collectMissingIsolationSupport(capability, contract),
    ...collectMissingPolicySupport(capability, contract),
  ]
}

export function isRuntimeContractSupportedByCapability(
  capability: RuntimeBackendCapability,
  contract: ToolRuntimeContract
): boolean {
  return getRuntimeContractSupportMismatches(capability, contract).length === 0
}

export function findRuntimeBackendCapability(
  capabilities: RuntimeBackendCapability[],
  contract: ToolRuntimeContract
): RuntimeBackendCapability | undefined {
  return capabilities.find((capability) =>
    isRuntimeContractSupportedByCapability(capability, contract)
  )
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
