/**
 * Runtime Hyper-V control tool.
 *
 * This is an analyzer-side control-plane wrapper over Windows Host Agent
 * `/hyperv/*` endpoints. It does not execute samples and does not open Windows
 * Sandbox; it only manages a configured Hyper-V runtime VM.
 */

import { z } from 'zod'
import type { PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'runtime.hyperv.control'

export const RuntimeHyperVControlInputSchema = z.object({
  action: z
    .enum(['status', 'checkpoints', 'create_checkpoint', 'restore', 'stop'])
    .optional()
    .default('status')
    .describe('Hyper-V control action routed through Windows Host Agent.'),
  host_agent_endpoint: z.string().url().optional().describe('Override Windows Host Agent endpoint. Defaults to runtime.hostAgentEndpoint.'),
  host_agent_api_key: z.string().optional().describe('Override Windows Host Agent API key. Defaults to runtime.hostAgentApiKey.'),
  runtime_api_key: z.string().optional().describe('Runtime Node API key passed through when restore waits for runtime health. Defaults to runtime.apiKey.'),
  snapshot_name: z.string().optional().describe('Checkpoint name for restore or create_checkpoint. Restore defaults to Host Agent HOST_AGENT_HYPERV_SNAPSHOT_NAME.'),
  start: z.boolean().optional().default(true).describe('Start VM after restore.'),
  wait_for_runtime: z.boolean().optional().default(true).describe('Wait for Runtime Node health after restore when endpoint is configured.'),
  timeout_ms: z.number().int().min(1000).max(10 * 60 * 1000).optional().default(120_000),
})

const RuntimeHyperVControlOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const runtimeHyperVControlToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Control a configured Hyper-V Runtime VM through Windows Host Agent. Supports status, checkpoint listing, checkpoint creation, checkpoint restore, and VM stop without running a sample.',
  inputSchema: RuntimeHyperVControlInputSchema,
  outputSchema: RuntimeHyperVControlOutputSchema,
}

function getRuntimeConfig(deps: PluginToolDeps): Record<string, any> {
  return deps.config?.runtime || {}
}

function getAuthHeader(apiKey?: string): Record<string, string> {
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : {}
}

async function fetchHostAgentJson(
  endpoint: string,
  path: string,
  options: {
    method?: 'GET' | 'POST'
    apiKey?: string
    body?: Record<string, unknown>
    timeoutMs?: number
  } = {}
): Promise<{ ok: boolean; status: number; body: any; text: string; error?: string }> {
  const url = new URL(path, endpoint).toString()
  const response = await fetch(url, {
    method: options.method || 'GET',
    headers: {
      ...getAuthHeader(options.apiKey),
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: AbortSignal.timeout(options.timeoutMs || 30_000),
  })
  const text = await response.text()
  let body: any = null
  if (text.trim()) {
    try {
      body = JSON.parse(text)
    } catch {
      body = { text }
    }
  }
  return {
    ok: response.ok,
    status: response.status,
    body,
    text,
    error: response.ok ? undefined : body?.error || body?.message || text || `HTTP ${response.status}`,
  }
}

function resolveHostAgentEndpoint(deps: PluginToolDeps, inputEndpoint?: string): string | undefined {
  const runtime = getRuntimeConfig(deps)
  return inputEndpoint || runtime.hostAgentEndpoint
}

function resolveHostAgentApiKey(deps: PluginToolDeps, inputKey?: string): string | undefined {
  const runtime = getRuntimeConfig(deps)
  return inputKey || runtime.hostAgentApiKey
}

function resolveRuntimeApiKey(deps: PluginToolDeps, inputKey?: string): string | undefined {
  const runtime = getRuntimeConfig(deps)
  return inputKey || runtime.apiKey
}

function actionPath(action: z.infer<typeof RuntimeHyperVControlInputSchema>['action']): string {
  switch (action) {
    case 'checkpoints':
      return '/hyperv/checkpoints'
    case 'create_checkpoint':
      return '/hyperv/checkpoints'
    case 'restore':
      return '/hyperv/restore'
    case 'stop':
      return '/hyperv/stop'
    case 'status':
    default:
      return '/hyperv/status'
  }
}

function buildRequestBody(input: z.infer<typeof RuntimeHyperVControlInputSchema>, runtimeApiKey?: string): Record<string, unknown> | undefined {
  if (input.action === 'create_checkpoint') {
    return { snapshotName: input.snapshot_name }
  }
  if (input.action !== 'restore') {
    return input.action === 'stop' ? {} : undefined
  }
  return {
    snapshotName: input.snapshot_name,
    start: input.start,
    waitForRuntime: input.wait_for_runtime,
    timeoutMs: input.timeout_ms,
    runtimeApiKey,
  }
}

function guidanceFor(action: z.infer<typeof RuntimeHyperVControlInputSchema>['action'], resultOk: boolean) {
  if (resultOk && action === 'restore') {
    return {
      recommended_next_tools: ['dynamic.runtime.status', 'runtime.debug.session.start', 'dynamic.behavior.capture'],
      next_actions: [
        'Confirm the Runtime Node endpoint is healthy with dynamic.runtime.status.',
        'Use runtime.debug.session.start with manual_endpoint or remote-sandbox configuration to bind this VM runtime to a sample session.',
      ],
    }
  }
  if (resultOk && action === 'create_checkpoint') {
    return {
      recommended_next_tools: ['runtime.hyperv.control', 'dynamic.runtime.status'],
      next_actions: [
        'Use runtime.hyperv.control(action=checkpoints) to confirm the checkpoint is available.',
        'Restore this checkpoint before rerunning a destructive or long-running dynamic analysis path.',
      ],
    }
  }
  if (resultOk && action === 'checkpoints') {
    return {
      recommended_next_tools: ['runtime.hyperv.control', 'dynamic.runtime.status'],
      next_actions: ['Restore a known clean checkpoint before live dynamic analysis when repeatability matters.'],
    }
  }
  return {
    recommended_next_tools: ['dynamic.runtime.status', 'dynamic.dependencies', 'system.health'],
    next_actions: [
      'Inspect Host Agent Hyper-V status and configuration before live execution.',
      'Verify HOST_AGENT_HYPERV_VM_NAME, HOST_AGENT_HYPERV_RUNTIME_ENDPOINT, and optional checkpoint settings.',
    ],
  }
}

export function createRuntimeHyperVControlHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    const input = RuntimeHyperVControlInputSchema.parse(args || {})
    const hostAgentEndpoint = resolveHostAgentEndpoint(deps, input.host_agent_endpoint)
    const hostAgentApiKey = resolveHostAgentApiKey(deps, input.host_agent_api_key)
    const runtimeApiKey = resolveRuntimeApiKey(deps, input.runtime_api_key)

    if (!hostAgentEndpoint) {
      return {
        ok: false,
        data: {
          status: 'setup_required',
          failure_category: 'host_agent_not_configured',
          summary: 'runtime.hostAgentEndpoint is required for runtime.hyperv.control.',
          recommended_next_tools: ['dynamic.runtime.status', 'system.health'],
          next_actions: [
            'Start the Windows Host Agent in the logged-on user session or configure RUNTIME_HOST_AGENT_ENDPOINT.',
            'Use dynamic.runtime.status to confirm the control plane before retrying Hyper-V actions.',
          ],
        },
        errors: ['runtime.hostAgentEndpoint is not configured.'],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }

    try {
      const body = buildRequestBody(input, runtimeApiKey)
      const response = await fetchHostAgentJson(hostAgentEndpoint, actionPath(input.action), {
        method: input.action === 'status' || input.action === 'checkpoints' ? 'GET' : 'POST',
        apiKey: hostAgentApiKey,
        body,
        timeoutMs: input.timeout_ms,
      })
      const guidance = guidanceFor(input.action, response.ok && response.body?.ok !== false)
      const ok = response.ok && response.body?.ok !== false
      return {
        ok,
        data: {
          action: input.action,
          host_agent_endpoint: hostAgentEndpoint,
          http_status: response.status,
          result: response.body,
          ...guidance,
        },
        errors: ok ? undefined : [response.error || `Host Agent Hyper-V action failed: ${input.action}`],
        warnings:
          response.ok && response.body?.backend && response.body.backend !== 'hyperv-vm'
            ? [`Host Agent backend is ${response.body.backend}; Hyper-V control endpoints may be unavailable until HOST_AGENT_BACKEND=hyperv-vm.`]
            : undefined,
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return {
        ok: false,
        data: {
          action: input.action,
          host_agent_endpoint: hostAgentEndpoint,
          status: 'failed',
          failure_category: 'host_agent_request_failed',
          recommended_next_tools: ['dynamic.runtime.status', 'system.health'],
          next_actions: [
            'Verify the Windows Host Agent process is reachable from the analyzer.',
            'Check Host Agent logs and Hyper-V feature availability on the Windows host.',
          ],
        },
        errors: [`Host Agent Hyper-V request failed: ${message}`],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
