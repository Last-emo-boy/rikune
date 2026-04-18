/**
 * dynamic.toolkit.status tool.
 *
 * Read-only Runtime Node toolkit inventory. This checks what debugging,
 * telemetry, dump, network, and manual GUI tools are visible inside the
 * selected runtime without launching Sandbox/Hyper-V or executing a sample.
 */

import { z } from 'zod'
import type { PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'dynamic.toolkit.status'

interface FetchStatus {
  ok: boolean
  status: number
  body: any
  error?: string
}

export const DynamicToolkitStatusInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample id used to find persisted runtime debug sessions.'),
  session_id: z.string().optional().describe('Optional runtime debug session id used to resolve a Runtime Node endpoint.'),
  runtime_endpoint: z.string().url().optional().describe('Override Runtime Node endpoint. Defaults to runtime.endpoint or persisted debug-session metadata.'),
  runtime_api_key: z.string().optional().describe('Override Runtime Node API key. Defaults to runtime.apiKey.'),
  limit: z.number().int().min(1).max(200).optional().default(20),
})

const DynamicToolkitStatusOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const dynamicToolkitStatusToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Read-only Runtime Node toolkit inventory for CDB/WinDbg, ProcDump, ProcMon, Sysmon, TTD, x64dbg, dnSpyEx, Frida, dotnet, and FakeNet-style tooling. Does not start Sandbox/Hyper-V or execute samples.',
  inputSchema: DynamicToolkitStatusInputSchema,
  outputSchema: DynamicToolkitStatusOutputSchema,
  runtimeBackendHint: { type: 'inline', handler: 'executeRuntimeToolProbe' },
}

function getRuntimeConfig(deps: PluginToolDeps): Record<string, any> {
  return deps.config?.runtime || {}
}

function getAuthHeader(apiKey?: string): Record<string, string> {
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : {}
}

function parseJsonObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'string') {
    return {}
  }
  try {
    const parsed = JSON.parse(value)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {}
  } catch {
    return {}
  }
}

async function fetchJsonStatus(
  url: string,
  headers: Record<string, string>,
  timeoutMs = 10_000
): Promise<FetchStatus> {
  try {
    const response = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(timeoutMs),
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
      error: response.ok ? undefined : body?.error || body?.message || text || `HTTP ${response.status}`,
    }
  } catch (error) {
    return {
      ok: false,
      status: 0,
      body: null,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

function persistedSessionRows(deps: PluginToolDeps, input: z.infer<typeof DynamicToolkitStatusInputSchema>): any[] {
  const db = deps.database
  const rows: any[] = []
  if (input.session_id && typeof db?.findDebugSession === 'function') {
    const row = db.findDebugSession(input.session_id)
    if (row) rows.push(row)
  }
  if (input.sample_id && typeof db?.findDebugSessionsBySample === 'function') {
    for (const row of db.findDebugSessionsBySample(input.sample_id, input.limit)) {
      if (!rows.some((existing) => existing?.id === row?.id)) rows.push(row)
    }
  }
  return rows
}

function resolveRuntimeEndpoint(
  deps: PluginToolDeps,
  input: z.infer<typeof DynamicToolkitStatusInputSchema>,
  rows: any[]
): { endpoint?: string; source: string } {
  const runtime = getRuntimeConfig(deps)
  if (input.runtime_endpoint) {
    return { endpoint: input.runtime_endpoint, source: 'input.runtime_endpoint' }
  }
  if (typeof runtime.endpoint === 'string' && runtime.endpoint.trim()) {
    return { endpoint: runtime.endpoint, source: 'config.runtime.endpoint' }
  }
  for (const row of rows) {
    const metadata = parseJsonObject(row?.metadata_json)
    if (typeof metadata.endpoint === 'string' && metadata.endpoint.length > 0) {
      return { endpoint: metadata.endpoint, source: `debug_session:${row.id}` }
    }
  }
  return { source: 'none' }
}

function toolkitSummary(inventory: any): Record<string, unknown> {
  const tools = Array.isArray(inventory?.tools) ? inventory.tools : []
  const profiles = Array.isArray(inventory?.profiles) ? inventory.profiles : []
  return {
    available_tools: tools.filter((tool: any) => tool?.available).map((tool: any) => tool.id),
    missing_tools: tools.filter((tool: any) => !tool?.available).map((tool: any) => tool.id),
    ready_profiles: profiles.filter((profile: any) => profile?.status === 'ready').map((profile: any) => profile.id),
    partial_profiles: profiles.filter((profile: any) => profile?.status === 'partial').map((profile: any) => profile.id),
    missing_profiles: profiles.filter((profile: any) => profile?.status === 'missing').map((profile: any) => profile.id),
  }
}

function buildGuidance(status: 'ready' | 'partial' | 'not_configured', inventory: any) {
  const summary = toolkitSummary(inventory)
  if (status === 'ready') {
    const recommended = ['dynamic.deep_plan', 'runtime.debug.command', 'dynamic.behavior.capture']
    if ((summary.ready_profiles as string[]).includes('debugger_cdb')) recommended.push('debug.session.inspect')
    if ((summary.ready_profiles as string[]).includes('network_lab')) recommended.push('debug.network.plan')
    if ((summary.ready_profiles as string[]).includes('dotnet_runtime')) recommended.push('debug.managed.plan')
    if ((summary.ready_profiles as string[]).includes('manual_gui_debug')) recommended.push('runtime.hyperv.control')
    if ((summary.ready_profiles as string[]).includes('manual_gui_debug')) recommended.push('debug.gui.handoff')
    return {
      recommended_next_tools: Array.from(new Set(recommended)),
      next_actions: [
        'Choose a dynamic.deep_plan profile before running expensive instrumentation.',
        'Use runtime.debug.command for CDB-backed debugger commands when debugger_cdb is ready.',
        'Use dynamic.behavior.capture first when the goal is behavior evidence rather than breakpoint control.',
      ],
    }
  }
  if (status === 'partial') {
    return {
      recommended_next_tools: ['dynamic.runtime.status', 'dynamic.deep_plan', 'runtime.debug.session.start'],
      next_actions: [
        'Runtime Node is reachable, but toolkit inventory is incomplete; use the missing tool install hints before deep debug profiles.',
        'Behavior capture and native execution can still run without optional ProcMon/Sysmon/CDB tooling.',
      ],
    }
  }
  return {
    recommended_next_tools: ['dynamic.runtime.status', 'runtime.debug.session.start', 'dynamic.dependencies'],
    next_actions: [
      'Configure runtime.endpoint, start a runtime debug session, or attach a manual Runtime Node before querying runtime-side tools.',
      'This probe is read-only and will not launch Windows Sandbox by itself.',
    ],
  }
}

export function createDynamicToolkitStatusHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    const input = DynamicToolkitStatusInputSchema.parse(args || {})
    const runtime = getRuntimeConfig(deps)
    const rows = persistedSessionRows(deps, input)
    const runtimeApiKey = input.runtime_api_key || runtime.apiKey
    const endpointResolution = resolveRuntimeEndpoint(deps, input, rows)

    if (!endpointResolution.endpoint) {
      const guidance = buildGuidance('not_configured', null)
      return {
        ok: false,
        data: {
          status: 'not_configured',
          runtime_endpoint: null,
          runtime_endpoint_source: endpointResolution.source,
          toolkit: null,
          ...guidance,
        },
        warnings: ['No Runtime Node endpoint is configured or persisted for this request.'],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }

    const headers = getAuthHeader(runtimeApiKey)
    const [health, capabilities, toolkit] = await Promise.all([
      fetchJsonStatus(new URL('/health', endpointResolution.endpoint).toString(), headers),
      fetchJsonStatus(new URL('/capabilities', endpointResolution.endpoint).toString(), headers),
      fetchJsonStatus(new URL('/toolkit', endpointResolution.endpoint).toString(), headers),
    ])
    const inventory = toolkit.ok ? toolkit.body?.data : null
    const status: 'ready' | 'partial' = toolkit.ok ? 'ready' : 'partial'
    const guidance = buildGuidance(status, inventory)
    const warnings = [
      !health.ok ? `Runtime health check failed: ${health.error || 'unknown error'}` : null,
      !capabilities.ok ? `Runtime capabilities check failed: ${capabilities.error || 'unknown error'}` : null,
      !toolkit.ok ? `Runtime toolkit check failed: ${toolkit.error || 'unknown error'}` : null,
    ].filter((entry): entry is string => Boolean(entry))

    return {
      ok: toolkit.ok,
      data: {
        status,
        runtime_endpoint: endpointResolution.endpoint,
        runtime_endpoint_source: endpointResolution.source,
        runtime_health: health.body || (health.ok ? null : { ok: false, status: health.status, error: health.error }),
        runtime_capabilities: capabilities.body?.data?.runtime_backends || [],
        toolkit: inventory,
        toolkit_summary: toolkitSummary(inventory),
        ...guidance,
      },
      warnings: warnings.length > 0 ? warnings : undefined,
      metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
    }
  }
}
