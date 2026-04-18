/**
 * Dynamic runtime status aggregation.
 *
 * This tool is intentionally read-only: it does not start Windows Sandbox,
 * Hyper-V, or Runtime Node. It gives MCP clients one stable status surface for
 * deciding whether to start a session, reuse a runtime, or fall back to static
 * analysis.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'dynamic.runtime.status'

interface RuntimeBackendCapability {
  type: 'python-worker' | 'spawn' | 'inline'
  handler: string
  description?: string
  requiresSample?: boolean
}

interface RuntimeSessionSummary {
  session_id: string
  sample_id?: string
  sample_sha256?: string
  status?: string
  debug_state?: string
  backend?: string | null
  current_phase?: string | null
  endpoint?: string | null
  sandbox_id?: string | null
  last_task_id?: string | null
  artifact_count: number
  artifact_refs: ArtifactRef[]
  created_at?: string
  updated_at?: string
  finished_at?: string | null
}

interface FetchStatus {
  ok: boolean
  status: number
  body: any
  error?: string
}

export const DynamicRuntimeStatusInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample id used to list persisted runtime debug sessions.'),
  session_id: z.string().optional().describe('Optional runtime debug session id used to resolve the Runtime Node endpoint from persisted metadata.'),
  runtime_endpoint: z.string().url().optional().describe('Override Runtime Node endpoint. Defaults to runtime.endpoint or the latest persisted session endpoint.'),
  runtime_api_key: z.string().optional().describe('Override Runtime Node API key. Defaults to runtime.apiKey.'),
  host_agent_endpoint: z.string().url().optional().describe('Override Windows Host Agent endpoint. Defaults to runtime.hostAgentEndpoint.'),
  host_agent_api_key: z.string().optional().describe('Override Windows Host Agent API key. Defaults to runtime.hostAgentApiKey.'),
  limit: z.number().int().min(1).max(200).optional().default(20),
})

const DynamicRuntimeStatusOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const dynamicRuntimeStatusToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Read-only dynamic runtime control-plane status. Aggregates configured Runtime Node health, Runtime Node capabilities, Windows Host Agent health, Hyper-V/Sandbox diagnostics, and persisted runtime debug sessions without launching a sandbox.',
  inputSchema: DynamicRuntimeStatusInputSchema,
  outputSchema: DynamicRuntimeStatusOutputSchema,
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

function parseArtifactRefs(value: unknown): ArtifactRef[] {
  if (!value || typeof value !== 'string') {
    return []
  }
  try {
    const parsed = JSON.parse(value)
    if (!Array.isArray(parsed)) {
      return []
    }
    return parsed.filter((entry): entry is ArtifactRef =>
      entry &&
      typeof entry === 'object' &&
      typeof (entry as ArtifactRef).id === 'string' &&
      typeof (entry as ArtifactRef).type === 'string' &&
      typeof (entry as ArtifactRef).path === 'string' &&
      typeof (entry as ArtifactRef).sha256 === 'string'
    )
  } catch {
    return []
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

function normalizeRuntimeCapabilities(value: unknown): RuntimeBackendCapability[] {
  const entries = Array.isArray(value)
    ? value
    : Array.isArray((value as any)?.data?.runtime_backends)
      ? (value as any).data.runtime_backends
      : []

  const capabilities: RuntimeBackendCapability[] = []
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') {
      continue
    }
    const candidate = entry as Partial<RuntimeBackendCapability>
    if (
      (candidate.type === 'python-worker' || candidate.type === 'spawn' || candidate.type === 'inline') &&
      typeof candidate.handler === 'string'
    ) {
      capabilities.push({
        type: candidate.type,
        handler: candidate.handler,
        description: typeof candidate.description === 'string' ? candidate.description : undefined,
        requiresSample: typeof candidate.requiresSample === 'boolean' ? candidate.requiresSample : undefined,
      })
    }
  }
  return capabilities
}

function normalizePersistedSession(row: any): RuntimeSessionSummary {
  const metadata = parseJsonObject(row?.metadata_json)
  const artifactRefs = parseArtifactRefs(row?.artifact_refs_json)
  return {
    session_id: String(row?.id || ''),
    sample_id: typeof row?.sample_id === 'string' ? row.sample_id : undefined,
    sample_sha256: typeof row?.sample_sha256 === 'string' ? row.sample_sha256 : undefined,
    status: typeof row?.status === 'string' ? row.status : undefined,
    debug_state: typeof row?.debug_state === 'string' ? row.debug_state : undefined,
    backend: typeof row?.backend === 'string' ? row.backend : null,
    current_phase: typeof row?.current_phase === 'string' ? row.current_phase : null,
    endpoint: typeof metadata.endpoint === 'string' ? metadata.endpoint : null,
    sandbox_id: typeof metadata.sandbox_id === 'string' ? metadata.sandbox_id : null,
    last_task_id: typeof metadata.last_task_id === 'string' ? metadata.last_task_id : null,
    artifact_count: artifactRefs.length,
    artifact_refs: artifactRefs,
    created_at: typeof row?.created_at === 'string' ? row.created_at : undefined,
    updated_at: typeof row?.updated_at === 'string' ? row.updated_at : undefined,
    finished_at: typeof row?.finished_at === 'string' ? row.finished_at : null,
  }
}

function findPersistedSessions(deps: PluginToolDeps, input: z.infer<typeof DynamicRuntimeStatusInputSchema>): RuntimeSessionSummary[] {
  const db = deps.database
  const rows: any[] = []

  if (input.session_id && typeof db?.findDebugSession === 'function') {
    const row = db.findDebugSession(input.session_id)
    if (row) {
      rows.push(row)
    }
  }

  if (input.sample_id && typeof db?.findDebugSessionsBySample === 'function') {
    for (const row of db.findDebugSessionsBySample(input.sample_id, input.limit)) {
      if (!rows.some((existing) => existing?.id === row?.id)) {
        rows.push(row)
      }
    }
  } else if (input.sample_id && typeof db?.findLatestDebugSessionBySample === 'function') {
    const row = db.findLatestDebugSessionBySample(input.sample_id)
    if (row && !rows.some((existing) => existing?.id === row?.id)) {
      rows.push(row)
    }
  }

  return rows
    .map(normalizePersistedSession)
    .filter((session) => session.session_id.length > 0)
}

function resolveRuntimeEndpoint(
  deps: PluginToolDeps,
  input: z.infer<typeof DynamicRuntimeStatusInputSchema>,
  sessions: RuntimeSessionSummary[]
): { endpoint?: string; source: string } {
  const runtime = getRuntimeConfig(deps)
  if (input.runtime_endpoint) {
    return { endpoint: input.runtime_endpoint, source: 'input.runtime_endpoint' }
  }
  if (typeof runtime.endpoint === 'string' && runtime.endpoint.trim().length > 0) {
    return { endpoint: runtime.endpoint, source: 'config.runtime.endpoint' }
  }
  const sessionWithEndpoint = sessions.find((session) => typeof session.endpoint === 'string' && session.endpoint.length > 0)
  if (sessionWithEndpoint?.endpoint) {
    return { endpoint: sessionWithEndpoint.endpoint, source: `debug_session:${sessionWithEndpoint.session_id}` }
  }
  return { source: 'none' }
}

function resolveHostAgentEndpoint(
  deps: PluginToolDeps,
  input: z.infer<typeof DynamicRuntimeStatusInputSchema>
): { endpoint?: string; source: string } {
  const runtime = getRuntimeConfig(deps)
  if (input.host_agent_endpoint) {
    return { endpoint: input.host_agent_endpoint, source: 'input.host_agent_endpoint' }
  }
  if (typeof runtime.hostAgentEndpoint === 'string' && runtime.hostAgentEndpoint.trim().length > 0) {
    return { endpoint: runtime.hostAgentEndpoint, source: 'config.runtime.hostAgentEndpoint' }
  }
  return { source: 'none' }
}

function runtimeMode(deps: PluginToolDeps): string {
  const runtime = getRuntimeConfig(deps)
  return typeof runtime.mode === 'string' ? runtime.mode : 'disabled'
}

function buildStatus(params: {
  runtimeEndpoint?: string
  runtimeHealth: FetchStatus | null
  hostAgentHealth: FetchStatus | null
  sessions: RuntimeSessionSummary[]
}): 'ready' | 'partial' | 'not_configured' {
  if (params.runtimeHealth?.ok) {
    return 'ready'
  }
  if (params.hostAgentHealth?.ok || params.runtimeEndpoint || params.sessions.length > 0) {
    return 'partial'
  }
  return 'not_configured'
}

function hasCapability(capabilities: RuntimeBackendCapability[], type: RuntimeBackendCapability['type'], handler: string): boolean {
  return capabilities.some((capability) => capability.type === type && capability.handler === handler)
}

function buildBackendInterface(params: {
  runtimeEndpoint?: string
  runtimeHealth: FetchStatus | null
  hostAgentEndpoint?: string
  hostAgentHealth: FetchStatus | null
  capabilities: RuntimeBackendCapability[]
  sessions: RuntimeSessionSummary[]
}) {
  const runtimeOnline = Boolean(params.runtimeEndpoint && params.runtimeHealth?.ok)
  const hostAgentBody = params.hostAgentHealth?.body
  const hypervConfigured = Boolean(
    hostAgentBody &&
    typeof hostAgentBody === 'object' &&
    (
      (hostAgentBody as any).backend === 'hyperv-vm' ||
      ((hostAgentBody as any).hyperv && (hostAgentBody as any).hyperv.configured !== false)
    )
  )
  return {
    host_agent_configured: Boolean(params.hostAgentEndpoint),
    host_agent_online: Boolean(params.hostAgentHealth?.ok),
    hyperv_configured: hypervConfigured,
    runtime_configured: Boolean(params.runtimeEndpoint),
    runtime_online: runtimeOnline,
    can_start_runtime_session: Boolean(params.hostAgentEndpoint && params.hostAgentHealth?.ok),
    can_query_runtime: runtimeOnline,
    can_upload_sample: runtimeOnline,
    can_execute_runtime_command: runtimeOnline && params.capabilities.length > 0,
    can_download_artifacts: runtimeOnline,
    can_stop_host_agent_session: Boolean(params.hostAgentEndpoint && params.sessions.some((session) => session.sandbox_id)),
    supported_backends: {
      debug_session: hasCapability(params.capabilities, 'inline', 'executeDebugSession'),
      sandbox_execute: hasCapability(params.capabilities, 'inline', 'executeSandboxExecute'),
      dynamic_memory_dump: hasCapability(params.capabilities, 'inline', 'executeDynamicMemoryDump'),
      behavior_capture: hasCapability(params.capabilities, 'inline', 'executeBehaviorCapture'),
      managed_safe_run: hasCapability(params.capabilities, 'inline', 'executeManagedSafeRun'),
      runtime_tool_probe: hasCapability(params.capabilities, 'inline', 'executeRuntimeToolProbe'),
      frida_runtime: hasCapability(params.capabilities, 'python-worker', 'frida_worker.py'),
    },
  }
}

function buildGuidance(params: {
  status: 'ready' | 'partial' | 'not_configured'
  backendInterface: ReturnType<typeof buildBackendInterface>
  capabilities: RuntimeBackendCapability[]
}) {
  if (params.status === 'ready') {
    const recommended = ['dynamic.runtime.status', 'dynamic.toolkit.status', 'dynamic.deep_plan', 'runtime.debug.session.status', 'runtime.debug.command']
    if (params.backendInterface.supported_backends.frida_runtime) {
      recommended.push('frida.runtime.instrument')
    }
    if (params.backendInterface.supported_backends.sandbox_execute) {
      recommended.push('sandbox.execute')
    }
    if (params.backendInterface.supported_backends.behavior_capture) {
      recommended.push('dynamic.behavior.capture')
    }
    if (params.backendInterface.hyperv_configured) {
      recommended.push('runtime.hyperv.control')
    }
    return {
      recommended_next_tools: recommended,
      next_actions: [
        'Reuse the existing runtime endpoint for dynamic commands instead of launching another sandbox.',
        'Check capability support before selecting debug.session.*, sandbox.execute, dynamic.memory_dump, managed.safe_run, or Frida instrumentation.',
      ],
    }
  }

  if (params.backendInterface.host_agent_online) {
    const recommended = ['runtime.debug.session.start', 'dynamic.dependencies', 'workflow.analyze.start']
    if (params.backendInterface.hyperv_configured) {
      recommended.unshift('runtime.hyperv.control')
    }
    return {
      recommended_next_tools: recommended,
      next_actions: [
        'Start a runtime debug session only when live execution is needed; dynamic planning can continue without launching Sandbox or Hyper-V.',
        'Use dynamic.dependencies to verify local and runtime-side prerequisites before long-running dynamic work.',
      ],
    }
  }

  if (params.backendInterface.host_agent_configured || params.backendInterface.runtime_configured) {
    return {
      recommended_next_tools: ['dynamic.runtime.status', 'dynamic.dependencies', 'system.health'],
      next_actions: [
        'Inspect the returned runtime_health and host_agent_health errors, then restart the unavailable service before retrying live execution.',
        'Continue static or dynamic-plan workflows while the runtime plane is unavailable.',
      ],
    }
  }

  return {
    recommended_next_tools: ['runtime.debug.session.start', 'dynamic.dependencies', 'workflow.analyze.start'],
    next_actions: [
      'Configure runtime.hostAgentEndpoint for Windows Host Agent backed Sandbox or Hyper-V execution, or runtime.endpoint for a manual Runtime Node.',
      'Use workflow.analyze.start or workflow.analyze.promote(dynamic_plan) when live execution is not required.',
    ],
  }
}

export function createDynamicRuntimeStatusHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    const input = DynamicRuntimeStatusInputSchema.parse(args || {})
    const runtime = getRuntimeConfig(deps)
    const sessions = findPersistedSessions(deps, input)
    const runtimeApiKey = input.runtime_api_key || runtime.apiKey
    const hostAgentApiKey = input.host_agent_api_key || runtime.hostAgentApiKey
    const runtimeResolution = resolveRuntimeEndpoint(deps, input, sessions)
    const hostAgentResolution = resolveHostAgentEndpoint(deps, input)

    const [runtimeHealth, runtimeCapabilitiesResult, hostAgentHealth] = await Promise.all([
      runtimeResolution.endpoint
        ? fetchJsonStatus(new URL('/health', runtimeResolution.endpoint).toString(), getAuthHeader(runtimeApiKey))
        : Promise.resolve(null),
      runtimeResolution.endpoint
        ? fetchJsonStatus(new URL('/capabilities', runtimeResolution.endpoint).toString(), getAuthHeader(runtimeApiKey))
        : Promise.resolve(null),
      hostAgentResolution.endpoint
        ? fetchJsonStatus(new URL('/sandbox/health', hostAgentResolution.endpoint).toString(), getAuthHeader(hostAgentApiKey))
        : Promise.resolve(null),
    ])

    const runtimeCapabilities = runtimeCapabilitiesResult?.ok
      ? normalizeRuntimeCapabilities(runtimeCapabilitiesResult.body)
      : []
    const status = buildStatus({
      runtimeEndpoint: runtimeResolution.endpoint,
      runtimeHealth,
      hostAgentHealth,
      sessions,
    })
    const backendInterface = buildBackendInterface({
      runtimeEndpoint: runtimeResolution.endpoint,
      runtimeHealth,
      hostAgentEndpoint: hostAgentResolution.endpoint,
      hostAgentHealth,
      capabilities: runtimeCapabilities,
      sessions,
    })
    const guidance = buildGuidance({ status, backendInterface, capabilities: runtimeCapabilities })
    const warnings: string[] = []

    if (runtimeResolution.endpoint && !runtimeHealth?.ok) {
      warnings.push(`Runtime Node health check failed: ${runtimeHealth?.error || 'unknown error'}`)
    }
    if (runtimeResolution.endpoint && !runtimeCapabilitiesResult?.ok) {
      warnings.push(`Runtime Node capabilities check failed: ${runtimeCapabilitiesResult?.error || 'unknown error'}`)
    }
    if (hostAgentResolution.endpoint && !hostAgentHealth?.ok) {
      warnings.push(`Host Agent health check failed: ${hostAgentHealth?.error || 'unknown error'}`)
    }

    return {
      ok: status !== 'not_configured',
      data: {
        status,
        runtime_mode: runtimeMode(deps),
        runtime_endpoint: runtimeResolution.endpoint || null,
        runtime_endpoint_source: runtimeResolution.source,
        runtime_health: runtimeHealth?.body || (runtimeHealth ? { ok: false, status: runtimeHealth.status, error: runtimeHealth.error } : null),
        runtime_capabilities: runtimeCapabilities,
        runtime_capabilities_raw: runtimeCapabilitiesResult?.body || null,
        host_agent_endpoint: hostAgentResolution.endpoint || null,
        host_agent_endpoint_source: hostAgentResolution.source,
        host_agent_health: hostAgentHealth?.body || (hostAgentHealth ? { ok: false, status: hostAgentHealth.status, error: hostAgentHealth.error } : null),
        sessions,
        session_count: sessions.length,
        active_session_count: sessions.filter((session) =>
          ['planned', 'armed', 'capturing', 'approval_gated'].includes(session.debug_state || '')
        ).length,
        artifact_count: sessions.reduce((sum, session) => sum + session.artifact_count, 0),
        backend_interface: backendInterface,
        recommended_next_tools: guidance.recommended_next_tools,
        next_actions: guidance.next_actions,
      },
      warnings: warnings.length > 0 ? warnings : undefined,
      metrics: {
        elapsed_ms: Date.now() - started,
        tool: TOOL_NAME,
      },
    }
  }
}
