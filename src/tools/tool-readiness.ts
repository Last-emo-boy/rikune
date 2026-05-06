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
import { ToolSurfaceRoleSchema, buildToolSurfaceGuidance } from '../tool-surface-guidance.js'

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
    required_runtime_contract: z.any().nullable(),
    local_dynamic_policy: z.string().nullable().optional(),
    available_runtime_backends: z.array(z.any()),
    execution_semantics: z.record(z.any()),
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
    case 'legacy-local-worker':
      return 'local_dynamic_worker'
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
    case 'legacy-local-worker':
      return {
        reason:
          'This dynamic-domain tool currently uses an analyzer-side local worker/helper rather than a delegated Runtime Node backend.',
        warnings: [
          'This dynamic tool is not runtime-delegated yet; confirm host isolation policy before running it on untrusted samples.',
        ],
        recommendedNextTools: ['dynamic.runtime.status', 'dynamic.behavior.capture', 'tool.help'],
        nextActions: [
          'Prefer runtime-delegated tools when live sample execution or strict isolation is required.',
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
  localDynamicPolicy: LocalDynamicToolPolicy | null = null
) {
  const surfaceGuidance = buildToolSurfaceGuidance(tool.name)
  const guidance = localDynamicPolicyGuidance(localDynamicPolicy)
  const runtimePlane = localRuntimePlane(localDynamicPolicy)

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
          recommended_next_tools: ['tool.help', 'plugin.list', 'tools.discover'],
          next_actions: [
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
    const pluginPayload = pluginStatus
      ? {
          id: pluginStatus.id,
          status: pluginStatus.status,
          execution_domain: pluginStatus.executionDomain ?? 'both',
          reason_code: pluginStatus.reasonCode ?? null,
          status_detail: pluginStatus.statusDetail ?? null,
        }
      : null

    if (!tool.runtime) {
      const localDynamicPolicy =
        pluginPayload?.execution_domain === 'dynamic'
          ? (getLocalDynamicToolPolicy(tool.name) ?? null)
          : null
      return buildLocalReadyPayload(tool, pluginPayload ?? undefined, localDynamicPolicy)
    }

    const runtimeMode = options.runtimeMode || 'disabled'
    const runtimeClient = options.runtimeClient ?? null
    const runtimeEndpoint = runtimeClient?.getEndpoint?.() || null
    const surfaceGuidance = buildToolSurfaceGuidance(tool.name)

    if (runtimeMode === 'remote-sandbox' && !runtimeEndpoint) {
      const guidance = buildRuntimeGuidance('runtime_not_started', tool, runtimeEndpoint, [])
      const runtimePlane = classifyRuntimeReadinessPlane('runtime_not_started', runtimeEndpoint)
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
          plugin: pluginPayload,
          runtime_contract: tool.runtime,
          required_runtime_contract: tool.runtime,
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
          plugin: pluginPayload,
          runtime_contract: tool.runtime,
          required_runtime_contract: tool.runtime,
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
        plugin: pluginPayload,
        runtime_contract: tool.runtime,
        required_runtime_contract: tool.runtime,
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
