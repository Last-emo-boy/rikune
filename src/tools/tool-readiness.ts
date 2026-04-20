import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../types.js'
import type { PluginManager } from '../core/plugins.js'
import type {
  RuntimeBackendCapability,
  RuntimeContractValidationResult,
} from '../runtime-client/runtime-client.js'

const TOOL_NAME = 'tool.readiness'

export const toolReadinessInputSchema = z.object({
  tool_name: z.string().min(1).describe('Exact canonical tool name to inspect'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Force-refresh runtime capability cache when safe to do so'),
})

export const toolReadinessOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
})

type RuntimeClientLike = {
  getEndpoint?(): string
  validateRuntimeContract?(
    contract: NonNullable<ToolDefinition['runtime']>,
    options?: { forceRefresh?: boolean }
  ): Promise<RuntimeContractValidationResult>
}

export const toolReadinessToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Inspect whether a registered MCP tool is locally runnable, requires a runtime backend, or is currently blocked by missing runtime capability or plugin availability.',
  inputSchema: toolReadinessInputSchema,
  outputSchema: toolReadinessOutputSchema,
}

function buildLocalReadyPayload(tool: ToolDefinition, pluginStatus?: Record<string, unknown>) {
  return {
    ok: true,
    data: {
      tool_name: tool.name,
      readiness: 'ready',
      execution_path: 'local',
      plugin: pluginStatus ?? null,
      runtime_contract: null,
      runtime: {
        required: false,
        endpoint: null,
        capability_advertised: null,
        available_runtime_backends: [],
      },
      recommended_next_tools: ['tool.help', 'plugin.list'],
      next_actions: [
        'This tool executes on the current MCP server and does not require a delegated runtime backend.',
      ],
    },
  } satisfies WorkerResult
}

function buildRuntimeGuidance(
  readiness: 'ready' | 'runtime_not_started' | 'runtime_unreachable' | 'runtime_capability_missing',
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
          readiness: 'unknown_tool',
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
      return buildLocalReadyPayload(tool, pluginPayload ?? undefined)
    }

    const runtimeMode = options.runtimeMode || 'disabled'
    const runtimeClient = options.runtimeClient ?? null
    const runtimeEndpoint = runtimeClient?.getEndpoint?.() || null

    if (runtimeMode === 'remote-sandbox' && !runtimeEndpoint) {
      const guidance = buildRuntimeGuidance('runtime_not_started', tool, runtimeEndpoint, [])
      return {
        ok: false,
        warnings: [
          'Runtime readiness remains passive in remote-sandbox mode and does not start Windows Sandbox or Hyper-V.',
        ],
        data: {
          tool_name: tool.name,
          readiness: 'runtime_not_started',
          execution_path: 'delegated',
          plugin: pluginPayload,
          runtime_contract: tool.runtime,
          runtime: {
            required: true,
            mode: runtimeMode,
            endpoint: null,
            capability_advertised: null,
            available_runtime_backends: [],
          },
          ...guidance,
        },
      }
    }

    if (!runtimeClient?.validateRuntimeContract) {
      const guidance = buildRuntimeGuidance('runtime_unreachable', tool, runtimeEndpoint, [])
      return {
        ok: false,
        warnings: ['No runtime client is configured for delegated runtime validation.'],
        data: {
          tool_name: tool.name,
          readiness: 'runtime_unreachable',
          execution_path: 'delegated',
          plugin: pluginPayload,
          runtime_contract: tool.runtime,
          runtime: {
            required: true,
            mode: runtimeMode,
            endpoint: runtimeEndpoint,
            capability_advertised: null,
            available_runtime_backends: [],
          },
          ...guidance,
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

    return {
      ok: readiness === 'ready',
      warnings:
        readiness === 'runtime_unreachable'
          ? ['Runtime capability validation failed or returned no definitive answer.']
          : undefined,
      data: {
        tool_name: tool.name,
        readiness,
        execution_path: 'delegated',
        plugin: pluginPayload,
        runtime_contract: tool.runtime,
        runtime: {
          required: true,
          mode: runtimeMode,
          endpoint: runtimeEndpoint,
          capability_advertised: validation.supported,
          matched_runtime_backend: validation.capability ?? null,
          available_runtime_backends: capabilities,
        },
        ...guidance,
      },
    }
  }
}
