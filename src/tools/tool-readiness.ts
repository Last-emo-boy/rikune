import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../types.js'
import type { PluginManager } from '../core/plugins.js'
import type {
  RuntimeBackendCapability,
  RuntimeContractValidationResult,
} from '../runtime-client/runtime-client.js'
import {
  getLocalDynamicToolPolicy,
  type LocalDynamicToolPolicy,
} from '../runtime-client/dynamic-tool-policy.js'
import {
  buildRuntimeToolSupportSummary,
  getRuntimeDelegatedToolContract,
} from '../runtime-client/runtime-tool-support.js'
import { ToolSurfaceRoleSchema, buildToolSurfaceGuidance } from '../tool-surface-guidance.js'
import { buildToolAspectSummary } from './tool-aspect-matrix.js'
import { checkBackendWorkerReadiness } from '../worker/backend-worker-client.js'

const TOOL_NAME = 'tool.readiness'

export const toolReadinessInputSchema = z.object({
  tool_name: z.string().min(1).describe('Exact canonical tool name to inspect'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Force-refresh runtime capability cache when safe to do so'),
})

type RuntimeClientLike = {
  getEndpoint?(): string
  validateRuntimeContract?(
    contract: NonNullable<ToolDefinition['runtime']>,
    options?: { forceRefresh?: boolean }
  ): Promise<RuntimeContractValidationResult>
}

type RuntimeReadiness =
  | 'ready'
  | 'runtime_not_started'
  | 'runtime_unreachable'
  | 'runtime_capability_missing'

type AspectMetadata = Record<string, unknown>

type PluginMetadata = {
  id?: string
  name?: string
  description?: string
  aspects?: AspectMetadata
  runtimePolicy?: ToolDefinition['runtimePolicy']
}

const ToolReadinessDataSchema = z
  .object({
    tool_name: z.string(),
    result_mode: z.literal('tool_readiness'),
    readiness: z.enum([
      'ready',
      'unknown_tool',
      'runtime_not_started',
      'runtime_unreachable',
      'runtime_capability_missing',
    ]),
    execution_path: z.enum(['local', 'delegated', 'none']),
    runtime_plane: z.string().nullable(),
    tool_surface_role: ToolSurfaceRoleSchema.nullable(),
    preferred_primary_tools: z.array(z.string()),
    aspects: z.record(z.string(), z.array(z.string())).nullable().optional(),
    aspect_coverage: z.array(z.string()).optional(),
    format_matrix: z.record(z.string(), z.any()).optional(),
    artifact_declarations: z.array(z.any()).optional(),
    evidence_declarations: z.array(z.any()).optional(),
    workflow_recipes: z.array(z.any()).optional(),
    runtime_policy: z.any().nullable().optional(),
    runtime_contract_policy: z.any().nullable().optional(),
    runtime_isolation: z.any().nullable().optional(),
    worker_backend: z.any().nullable().optional(),
    worker_backend_readiness: z.any().nullable().optional(),
    runtime_policy_status: z.any().nullable().optional(),
    opt_in_required: z.boolean().optional(),
    policy_denied: z.boolean().optional(),
    isolation_missing: z.boolean().optional(),
    backend_missing: z.boolean().optional(),
    policy_gates: z.any().nullable().optional(),
    required_runtime_contract: z.any().nullable(),
    runtime_tool_contract: z.any().nullable().optional(),
    runtime_tool_support: z.array(z.any()).optional(),
    runtime_tool_summary: z.any().optional(),
    supported_runtime_tools: z.array(z.string()).optional(),
    missing_runtime_tools: z.array(z.string()).optional(),
    local_dynamic_policy: z.string().nullable().optional(),
    available_runtime_backends: z.array(z.any()),
    execution_semantics: z.record(z.string(), z.any()),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  })
  .passthrough()

export const toolReadinessOutputSchema = z.object({
  ok: z.boolean(),
  data: ToolReadinessDataSchema.optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
})

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function resolvePluginDefinition(
  pluginManager: PluginManager,
  pluginId: string | null
): PluginMetadata | null {
  if (!pluginId) return null
  const manager = pluginManager as PluginManager & {
    getPlugin?: (id: string) => PluginMetadata | undefined
    getDiscoveredPlugins?: () => PluginMetadata[]
  }
  return (
    manager.getPlugin?.(pluginId) ??
    manager.getDiscoveredPlugins?.().find((plugin) => plugin.id === pluginId) ??
    null
  )
}

function buildToolMetadata(tool: ToolDefinition, plugin: PluginMetadata | null) {
  const aspectSummary = buildToolAspectSummary(tool, {
    pluginAspects: plugin?.aspects,
    pluginRuntimePolicy: plugin?.runtimePolicy,
  })
  const runtimePolicy = tool.runtimePolicy ?? tool.runtime?.policy ?? plugin?.runtimePolicy ?? null
  const runtimeIsolation = tool.runtime?.isolation ?? null
  const policyGates =
    runtimePolicy || runtimeIsolation || tool.runtime
      ? {
          passive_by_default: runtimePolicy?.passiveByDefault ?? Boolean(tool.runtime),
          requires_user_opt_in: runtimePolicy?.requiresUserOptIn ?? Boolean(tool.runtime),
          requires_isolation:
            runtimePolicy?.requiresIsolation ?? runtimeIsolation?.required ?? Boolean(tool.runtime),
          allowed_backends: runtimePolicy?.allowedBackends ?? runtimeIsolation?.backends ?? [],
          network_policy: runtimePolicy?.networkPolicy ?? null,
          max_runtime_ms: runtimePolicy?.maxRuntimeMs ?? tool.runtime?.timeoutMs ?? null,
          notes: runtimePolicy?.notes ?? [],
        }
      : null

  return {
    aspects: aspectSummary.aspects,
    aspect_coverage: aspectSummary.aspect_coverage,
    format_matrix: aspectSummary.format_matrix,
    artifact_declarations: aspectSummary.artifact_declarations,
    evidence_declarations: aspectSummary.evidence_declarations,
    workflow_recipes: aspectSummary.workflow_recipes,
    worker_backend: aspectSummary.worker_backend,
    worker_backend_readiness: tool.workerBackend
      ? checkBackendWorkerReadiness(tool.workerBackend)
      : null,
    runtime_policy: runtimePolicy,
    runtime_contract_policy: tool.runtime?.policy ?? null,
    runtime_isolation: runtimeIsolation,
    policy_gates: policyGates,
  }
}

function collectRuntimeBackendTags(capabilities: RuntimeBackendCapability[]): string[] {
  const tags: string[] = []
  for (const capability of capabilities) {
    tags.push(capability.type, capability.handler)
    if (capability.description) tags.push(capability.description)
    tags.push(...(capability.capabilities ?? []))
    tags.push(...(capability.safety ?? []))
    tags.push(...(capability.policy?.allowedBackends ?? []))
    tags.push(...(capability.isolation?.backends ?? []))
  }
  return uniqueStrings(tags.map((tag) => tag.toLowerCase().replace(/_/g, '-')))
}

function buildRuntimePolicyStatus(params: {
  metadata: ReturnType<typeof buildToolMetadata>
  runtimeRequired?: boolean
  readiness?: RuntimeReadiness | 'unknown_tool'
  capabilities?: RuntimeBackendCapability[]
  runtimeEndpoint?: string | null
}) {
  const gates = params.metadata.policy_gates as {
    passive_by_default?: boolean
    requires_user_opt_in?: boolean
    requires_isolation?: boolean
    allowed_backends?: string[]
    network_policy?: string | null
    max_runtime_ms?: number | null
    notes?: string[]
  } | null

  if (!gates) {
    return {
      runtime_policy_status: null,
      opt_in_required: false,
      policy_denied: false,
      isolation_missing: false,
      backend_missing: false,
    }
  }

  if (!params.runtimeRequired) {
    return {
      runtime_policy_status: {
        passive_by_default: gates.passive_by_default ?? true,
        opt_in_required: false,
        policy_denied: false,
        requires_isolation: Boolean(gates.requires_isolation),
        isolation_missing: false,
        backend_missing: false,
        allowed_backends: uniqueStrings((gates.allowed_backends ?? []).map(String)),
        matched_backends: [],
        available_backend_tags: [],
        network_policy: gates.network_policy ?? null,
        max_runtime_ms: gates.max_runtime_ms ?? null,
        readiness: params.readiness ?? null,
        reasons: [],
        notes: [
          ...(gates.notes ?? []),
          'Policy is advisory for this local readiness/control-plane tool because it has no runtime contract.',
        ],
      },
      opt_in_required: false,
      policy_denied: false,
      isolation_missing: false,
      backend_missing: false,
    }
  }

  const capabilities = params.capabilities ?? []
  const allowedBackends = uniqueStrings((gates.allowed_backends ?? []).map(String))
  const capabilityTags = collectRuntimeBackendTags(capabilities)
  const matchedBackends = allowedBackends.filter((backend) => {
    const normalized = backend.toLowerCase().replace(/_/g, '-')
    return capabilityTags.some((tag) => tag === normalized || tag.includes(normalized))
  })

  const optInRequired = Boolean(gates.requires_user_opt_in)
  const requiresIsolation = Boolean(gates.requires_isolation)
  const hasRuntimeEndpoint = Boolean(params.runtimeEndpoint)
  const backendMissing =
    allowedBackends.length > 0 &&
    matchedBackends.length === 0 &&
    (capabilities.length === 0 || params.readiness !== 'ready')
  const isolationMissing = requiresIsolation && matchedBackends.length === 0
  const policyDenied = optInRequired || backendMissing || isolationMissing
  const reasons: string[] = []
  if (optInRequired) {
    reasons.push('opt_in_required')
  }
  if (backendMissing) {
    reasons.push(hasRuntimeEndpoint ? 'backend_missing' : 'runtime_endpoint_missing')
  }
  if (isolationMissing) {
    reasons.push('isolation_missing')
  }

  return {
    runtime_policy_status: {
      passive_by_default: gates.passive_by_default ?? true,
      opt_in_required: optInRequired,
      policy_denied: policyDenied,
      requires_isolation: requiresIsolation,
      isolation_missing: isolationMissing,
      backend_missing: backendMissing,
      allowed_backends: allowedBackends,
      matched_backends: matchedBackends,
      available_backend_tags: capabilityTags,
      network_policy: gates.network_policy ?? null,
      max_runtime_ms: gates.max_runtime_ms ?? null,
      readiness: params.readiness ?? null,
      reasons,
      notes: gates.notes ?? [],
    },
    opt_in_required: optInRequired,
    policy_denied: policyDenied,
    isolation_missing: isolationMissing,
    backend_missing: backendMissing,
  }
}

function runtimeContractLabel(contract: ToolDefinition['runtime'] | null | undefined): string {
  return contract ? `${contract.type}/${contract.handler}` : 'none'
}

function classifyRuntimeReadinessPlane(
  readiness: RuntimeReadiness,
  runtimeEndpoint: string | null
): 'runtime_endpoint' | 'runtime_node' | 'runtime_capability' {
  if (readiness === 'runtime_not_started') {
    return 'runtime_endpoint'
  }

  if (readiness === 'runtime_capability_missing' || readiness === 'ready') {
    return 'runtime_capability'
  }

  return runtimeEndpoint ? 'runtime_node' : 'runtime_endpoint'
}

function buildExecutionSemantics(params: {
  tool: ToolDefinition
  readiness: RuntimeReadiness | 'unknown_tool'
  executionPath: 'local' | 'delegated' | 'none'
  localDynamicPolicy?: LocalDynamicToolPolicy | null
  runtimeMode?: string
  runtimeEndpoint?: string | null
  runtimePlane?: string | null
  reason: string
}) {
  const contract = params.tool.runtime ?? null
  return {
    readiness_probe: 'passive',
    requested_mode:
      params.runtimeMode || (params.executionPath === 'local' ? 'local' : 'manual_runtime'),
    actual_mode:
      params.executionPath === 'local'
        ? 'local'
        : params.readiness === 'ready'
          ? 'delegated_ready'
          : 'plan_only',
    execution_path: params.executionPath,
    backend: contract ? runtimeContractLabel(contract) : params.tool.name,
    live_execution: false,
    target_requires_delegated_runtime: Boolean(contract),
    local_dynamic_policy: params.localDynamicPolicy ?? null,
    runtime_endpoint: params.runtimeEndpoint ?? null,
    runtime_plane: params.runtimePlane ?? null,
    reason: params.reason,
  }
}

export const toolReadinessToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Inspect whether a registered MCP tool is locally runnable, requires a runtime backend, or is currently blocked by missing runtime capability or plugin availability.',
  inputSchema: toolReadinessInputSchema,
  outputSchema: toolReadinessOutputSchema,
}

function localRuntimePlane(policy: LocalDynamicToolPolicy | null): string {
  switch (policy) {
    case 'artifact-generation':
      return 'local_artifact_generation'
    case 'artifact-import':
      return 'local_artifact_import'
    case 'control-plane':
      return 'local_control_plane'
    case 'dependency-report':
      return 'local_dependency_report'
    case 'planning':
      return 'local_planning'
    case 'post-processing':
      return 'local_post_processing'
    default:
      return 'local_tool'
  }
}

function localDynamicPolicyGuidance(policy: LocalDynamicToolPolicy | null): {
  reason: string
  warnings?: string[]
  recommendedNextTools: string[]
  nextActions: string[]
} {
  switch (policy) {
    case 'artifact-generation':
      return {
        reason:
          'This dynamic-domain tool generates reusable scripts or artifacts locally; it does not execute the sample.',
        recommendedNextTools: ['tool.help', 'dynamic.runtime.status'],
        nextActions: [
          'Use the generated artifact with a runtime-delegated tool when live sample execution is required.',
        ],
      }
    case 'artifact-import':
      return {
        reason:
          'This dynamic-domain tool imports previously captured runtime artifacts locally; it does not attach to a runtime backend.',
        recommendedNextTools: ['dynamic.runtime.status', 'tool.help'],
        nextActions: [
          'Collect the source runtime artifact first, then use this tool to normalize it into the workspace.',
        ],
      }
    case 'control-plane':
      return {
        reason:
          'This dynamic-domain tool inspects or controls runtime state locally; it does not run a sample by itself.',
        recommendedNextTools: ['dynamic.runtime.status', 'tool.help', 'plugin.list'],
        nextActions: [
          'Use this tool for runtime control-plane work; call a runtime-delegated sample execution tool for live analysis.',
        ],
      }
    case 'dependency-report':
      return {
        reason:
          'This dynamic-domain tool reports dependency setup locally; it does not run a sample.',
        recommendedNextTools: ['dynamic.runtime.status', 'system.health', 'tool.help'],
        nextActions: [
          'Use the dependency report to prepare the runtime environment before live execution.',
        ],
      }
    case 'planning':
      return {
        reason:
          'This dynamic-domain tool builds a plan or command template locally; it does not execute the sample.',
        recommendedNextTools: [
          'dynamic.runtime.status',
          'runtime.debug.session.start',
          'tool.help',
        ],
        nextActions: [
          'Review the plan output, then dispatch the chosen runtime-delegated tool when execution is required.',
        ],
      }
    case 'post-processing':
      return {
        reason:
          'This dynamic-domain tool post-processes existing evidence locally; it does not execute the sample.',
        recommendedNextTools: ['dynamic.runtime.status', 'tool.help'],
        nextActions: [
          'Capture or import the source evidence first, then use this tool for attribution or summarization.',
        ],
      }
    default:
      return {
        reason:
          'This readiness probe only inspected registration and plugin state; it did not execute the target tool.',
        recommendedNextTools: ['tool.help', 'plugin.list'],
        nextActions: [
          'This tool executes on the current MCP server and does not require a delegated runtime backend.',
        ],
      }
  }
}

function buildLocalReadyPayload(
  tool: ToolDefinition,
  pluginStatus?: Record<string, unknown>,
  pluginDefinition: PluginMetadata | null = null,
  localDynamicPolicy: LocalDynamicToolPolicy | null = null
) {
  const surfaceGuidance = buildToolSurfaceGuidance(tool.name, {
    runtimeRequired: Boolean(tool.runtime),
  })
  const guidance = localDynamicPolicyGuidance(localDynamicPolicy)
  const runtimePlane = localRuntimePlane(localDynamicPolicy)
  const toolMetadata = buildToolMetadata(tool, pluginDefinition)
  const runtimePolicyStatus = buildRuntimePolicyStatus({
    metadata: toolMetadata,
    runtimeRequired: false,
    readiness: 'ready',
    capabilities: [],
    runtimeEndpoint: null,
  })

  return {
    ok: true,
    warnings: guidance.warnings,
    data: {
      tool_name: tool.name,
      result_mode: 'tool_readiness',
      readiness: 'ready',
      execution_path: 'local',
      runtime_plane: runtimePlane,
      tool_surface_role: surfaceGuidance.tool_surface_role,
      preferred_primary_tools: surfaceGuidance.preferred_primary_tools,
      ...toolMetadata,
      ...runtimePolicyStatus,
      plugin: pluginStatus ?? null,
      runtime_contract: null,
      required_runtime_contract: null,
      local_dynamic_policy: localDynamicPolicy,
      available_runtime_backends: [],
      runtime: {
        required: false,
        endpoint: null,
        capability_advertised: null,
        local_dynamic_policy: localDynamicPolicy,
        available_runtime_backends: [],
      },
      execution_semantics: buildExecutionSemantics({
        tool,
        readiness: 'ready',
        executionPath: 'local',
        runtimePlane,
        localDynamicPolicy,
        reason: guidance.reason,
      }),
      recommended_next_tools: uniqueStrings([
        ...surfaceGuidance.preferred_primary_tools,
        ...guidance.recommendedNextTools,
      ]),
      next_actions: guidance.nextActions,
    },
  } satisfies WorkerResult
}

function buildRuntimeGuidance(
  readiness: RuntimeReadiness,
  tool: ToolDefinition,
  runtimeEndpoint: string | null,
  capabilities: RuntimeBackendCapability[]
) {
  switch (readiness) {
    case 'ready':
      return {
        recommended_next_tools: ['dynamic.runtime.status', 'tool.help', tool.name],
        next_actions: [
          `Runtime contract ${tool.runtime?.type}/${tool.runtime?.handler} is advertised by the active runtime endpoint.`,
          'Use dynamic.runtime.status to confirm control-plane health before dispatching additional live work.',
        ],
      }
    case 'runtime_not_started':
      return {
        recommended_next_tools: ['dynamic.runtime.status', 'runtime.debug.session.start'],
        next_actions: [
          'The tool requires a runtime backend, but no active runtime endpoint is currently attached.',
          'In remote-sandbox mode, this check is intentionally passive and does not cold-start Windows Sandbox or Hyper-V.',
        ],
      }
    case 'runtime_unreachable':
      return {
        recommended_next_tools: ['dynamic.runtime.status', 'dynamic.dependencies', 'system.health'],
        next_actions: [
          runtimeEndpoint
            ? `Runtime endpoint ${runtimeEndpoint} is configured but capability checks failed.`
            : 'Runtime backend validation could not reach a configured endpoint.',
          'Inspect runtime and host-agent health before retrying delegated execution.',
        ],
      }
    case 'runtime_capability_missing':
    default:
      return {
        recommended_next_tools: ['dynamic.runtime.status', 'dynamic.toolkit.status', 'tool.help'],
        next_actions: [
          `The active runtime does not advertise ${tool.runtime?.type}/${tool.runtime?.handler}.`,
          capabilities.length > 0
            ? 'Inspect the advertised runtime backends and select a compatible tool or reconnect a different runtime.'
            : 'The runtime did not return any advertised backends.',
        ],
      }
  }
}

export function createToolReadinessHandler(
  getToolDefinitions: () => ToolDefinition[],
  getPluginManager: () => PluginManager,
  options: {
    runtimeClient?: RuntimeClientLike | null
    runtimeMode?: string
  } = {}
) {
  return async (args: z.infer<typeof toolReadinessInputSchema>): Promise<WorkerResult> => {
    const tool = getToolDefinitions().find((entry) => entry.name === args.tool_name)
    if (!tool) {
      return {
        ok: false,
        errors: [`Tool not found: ${args.tool_name}`],
        data: {
          tool_name: args.tool_name,
          result_mode: 'tool_readiness',
          readiness: 'unknown_tool',
          execution_path: 'none',
          runtime_plane: 'tool_registry',
          tool_surface_role: null,
          preferred_primary_tools: [],
          required_runtime_contract: null,
          available_runtime_backends: [],
          execution_semantics: {
            readiness_probe: 'passive',
            requested_mode: 'tool_registry_lookup',
            actual_mode: 'not_registered',
            execution_path: 'none',
            backend: args.tool_name,
            live_execution: false,
            target_requires_delegated_runtime: false,
            runtime_endpoint: null,
            runtime_plane: 'tool_registry',
            reason: 'The requested tool is not registered in the current MCP surface.',
          },
          recommended_next_tools: ['workflow.search', 'tool.help', 'plugin.list'],
          next_actions: [
            'Use workflow.search with the requested capability or tool name to find the matching profile before exposing specialist tools.',
            'Verify the canonical tool name and whether the corresponding plugin is loaded.',
          ],
        },
      }
    }

    const pluginManager = getPluginManager()
    const pluginId = pluginManager.getPluginForTool(tool.name) || null
    const pluginStatus = pluginId
      ? pluginManager.getStatuses().find((status) => status.id === pluginId) || null
      : null
    const pluginDefinition = resolvePluginDefinition(pluginManager, pluginId)
    const pluginPayload = pluginStatus
      ? {
          id: pluginStatus.id,
          status: pluginStatus.status,
          execution_domain: pluginStatus.executionDomain ?? 'both',
          reason_code: pluginStatus.reasonCode ?? null,
          status_detail: pluginStatus.statusDetail ?? null,
          aspects: pluginDefinition?.aspects ?? null,
          runtime_policy: pluginDefinition?.runtimePolicy ?? null,
          quality_warnings: pluginStatus.qualityWarnings ?? [],
        }
      : null

    if (!tool.runtime) {
      const localDynamicPolicy =
        pluginPayload?.execution_domain === 'dynamic'
          ? (getLocalDynamicToolPolicy(tool.name) ?? null)
          : null
      return buildLocalReadyPayload(
        tool,
        pluginPayload ?? undefined,
        pluginDefinition,
        localDynamicPolicy
      )
    }

    const runtimeMode = options.runtimeMode || 'disabled'
    const runtimeClient = options.runtimeClient ?? null
    const runtimeEndpoint = runtimeClient?.getEndpoint?.() || null
    const surfaceGuidance = buildToolSurfaceGuidance(tool.name, {
      runtimeRequired: Boolean(tool.runtime),
    })
    const runtimeToolContract = getRuntimeDelegatedToolContract(tool.name)
    const toolMetadata = buildToolMetadata(tool, pluginDefinition)

    if (runtimeMode === 'remote-sandbox' && !runtimeEndpoint) {
      const guidance = buildRuntimeGuidance('runtime_not_started', tool, runtimeEndpoint, [])
      const runtimePlane = classifyRuntimeReadinessPlane('runtime_not_started', runtimeEndpoint)
      const runtimePolicyStatus = buildRuntimePolicyStatus({
        metadata: toolMetadata,
        runtimeRequired: true,
        readiness: 'runtime_not_started',
        capabilities: [],
        runtimeEndpoint,
      })
      return {
        ok: false,
        warnings: [
          'Runtime readiness remains passive in remote-sandbox mode and does not start Windows Sandbox or Hyper-V.',
        ],
        data: {
          tool_name: tool.name,
          result_mode: 'tool_readiness',
          readiness: 'runtime_not_started',
          execution_path: 'delegated',
          runtime_plane: runtimePlane,
          tool_surface_role: surfaceGuidance.tool_surface_role,
          preferred_primary_tools: surfaceGuidance.preferred_primary_tools,
          ...toolMetadata,
          ...runtimePolicyStatus,
          plugin: pluginPayload,
          runtime_contract: tool.runtime,
          required_runtime_contract: tool.runtime,
          runtime_tool_contract: runtimeToolContract,
          ...buildRuntimeToolSupportSummary([]),
          available_runtime_backends: [],
          runtime: {
            required: true,
            mode: runtimeMode,
            endpoint: null,
            capability_advertised: null,
            available_runtime_backends: [],
          },
          execution_semantics: buildExecutionSemantics({
            tool,
            readiness: 'runtime_not_started',
            executionPath: 'delegated',
            runtimeMode,
            runtimeEndpoint,
            runtimePlane,
            reason:
              'The tool requires a delegated runtime backend, but no runtime endpoint is attached.',
          }),
          recommended_next_tools: uniqueStrings([
            ...surfaceGuidance.preferred_primary_tools,
            ...guidance.recommended_next_tools,
          ]),
          next_actions: guidance.next_actions,
        },
      }
    }

    if (!runtimeClient?.validateRuntimeContract) {
      const guidance = buildRuntimeGuidance('runtime_unreachable', tool, runtimeEndpoint, [])
      const runtimePlane = classifyRuntimeReadinessPlane('runtime_unreachable', runtimeEndpoint)
      const runtimePolicyStatus = buildRuntimePolicyStatus({
        metadata: toolMetadata,
        runtimeRequired: true,
        readiness: 'runtime_unreachable',
        capabilities: [],
        runtimeEndpoint,
      })
      return {
        ok: false,
        warnings: ['No runtime client is configured for delegated runtime validation.'],
        data: {
          tool_name: tool.name,
          result_mode: 'tool_readiness',
          readiness: 'runtime_unreachable',
          execution_path: 'delegated',
          runtime_plane: runtimePlane,
          tool_surface_role: surfaceGuidance.tool_surface_role,
          preferred_primary_tools: surfaceGuidance.preferred_primary_tools,
          ...toolMetadata,
          ...runtimePolicyStatus,
          plugin: pluginPayload,
          runtime_contract: tool.runtime,
          required_runtime_contract: tool.runtime,
          runtime_tool_contract: runtimeToolContract,
          ...buildRuntimeToolSupportSummary([]),
          available_runtime_backends: [],
          runtime: {
            required: true,
            mode: runtimeMode,
            endpoint: runtimeEndpoint,
            capability_advertised: null,
            available_runtime_backends: [],
          },
          execution_semantics: buildExecutionSemantics({
            tool,
            readiness: 'runtime_unreachable',
            executionPath: 'delegated',
            runtimeMode,
            runtimeEndpoint,
            runtimePlane,
            reason: 'No runtime client is configured for delegated runtime validation.',
          }),
          recommended_next_tools: uniqueStrings([
            ...surfaceGuidance.preferred_primary_tools,
            ...guidance.recommended_next_tools,
          ]),
          next_actions: guidance.next_actions,
        },
      }
    }

    const validation = await runtimeClient.validateRuntimeContract(tool.runtime, {
      forceRefresh: args.force_refresh,
    })
    const capabilities = validation.capabilities ?? []
    const readiness =
      validation.supported === true
        ? 'ready'
        : validation.supported === false
          ? 'runtime_capability_missing'
          : 'runtime_unreachable'
    const guidance = buildRuntimeGuidance(readiness, tool, runtimeEndpoint, capabilities)
    const runtimePlane = classifyRuntimeReadinessPlane(readiness, runtimeEndpoint)
    const runtimeToolSupportSummary = buildRuntimeToolSupportSummary(capabilities)
    const runtimePolicyStatus = buildRuntimePolicyStatus({
      metadata: toolMetadata,
      runtimeRequired: true,
      readiness,
      capabilities,
      runtimeEndpoint,
    })

    return {
      ok: readiness === 'ready',
      warnings:
        readiness === 'runtime_unreachable'
          ? ['Runtime capability validation failed or returned no definitive answer.']
          : undefined,
      data: {
        tool_name: tool.name,
        result_mode: 'tool_readiness',
        readiness,
        execution_path: 'delegated',
        runtime_plane: runtimePlane,
        tool_surface_role: surfaceGuidance.tool_surface_role,
        preferred_primary_tools: surfaceGuidance.preferred_primary_tools,
        ...toolMetadata,
        ...runtimePolicyStatus,
        plugin: pluginPayload,
        runtime_contract: tool.runtime,
        required_runtime_contract: tool.runtime,
        runtime_tool_contract: runtimeToolContract,
        ...runtimeToolSupportSummary,
        available_runtime_backends: capabilities,
        runtime: {
          required: true,
          mode: runtimeMode,
          endpoint: runtimeEndpoint,
          capability_advertised: validation.supported,
          matched_runtime_backend: validation.capability ?? null,
          available_runtime_backends: capabilities,
        },
        execution_semantics: buildExecutionSemantics({
          tool,
          readiness,
          executionPath: 'delegated',
          runtimeMode,
          runtimeEndpoint,
          runtimePlane,
          reason:
            readiness === 'ready'
              ? `Runtime contract ${runtimeContractLabel(tool.runtime)} is advertised by the active runtime endpoint.`
              : readiness === 'runtime_capability_missing'
                ? `The active runtime does not advertise ${runtimeContractLabel(tool.runtime)}.`
                : 'Runtime capability validation failed or returned no definitive answer.',
        }),
        recommended_next_tools: uniqueStrings([
          ...surfaceGuidance.preferred_primary_tools,
          ...guidance.recommended_next_tools,
        ]),
        next_actions: guidance.next_actions,
      },
    }
  }
}
