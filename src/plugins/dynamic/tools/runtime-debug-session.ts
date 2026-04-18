/**
 * Runtime debug session tools.
 *
 * These tools expose the runtime plane explicitly: start a Host Agent backed
 * runtime, inspect its health, stop it, and dispatch approved Runtime Node
 * commands without requiring a sample execution tool to be called first.
 */

import fs from 'fs'
import http from 'http'
import https from 'https'
import os from 'os'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import { resolveRuntimeSidecarUploads, type RuntimeSidecarUpload } from '../../../runtime-client/sidecar-staging.js'

const SESSION_START_TOOL = 'runtime.debug.session.start'
const SESSION_STATUS_TOOL = 'runtime.debug.session.status'
const SESSION_STOP_TOOL = 'runtime.debug.session.stop'
const COMMAND_TOOL = 'runtime.debug.command'

interface RuntimeDebugSession {
  sessionId: string
  sandboxId?: string
  endpoint: string
  backend?: string
  startedAt: string
  stoppedAt?: string
  status?: string
  debugState?: string
  sampleId?: string
  sampleSha256?: string
  persisted?: boolean
  lastTaskId?: string
  lastHealth?: unknown
  capabilities?: RuntimeBackendCapability[] | null
  artifactRefs?: ArtifactRef[]
  hypervPolicy?: Record<string, unknown>
}

const sessions = new Map<string, RuntimeDebugSession>()

interface RuntimeBackendCapability {
  type: 'python-worker' | 'spawn' | 'inline'
  handler: string
  description?: string
  requiresSample?: boolean
}

const RuntimeBackendHintSchema = z.object({
  type: z.enum(['python-worker', 'spawn', 'inline']),
  handler: z.string().min(1),
})

export const RuntimeDebugSessionStartInputSchema = z.object({
  host_agent_endpoint: z.string().url().optional().describe('Override Host Agent endpoint. Defaults to runtime.hostAgentEndpoint.'),
  host_agent_api_key: z.string().optional().describe('Override Host Agent API key. Defaults to runtime.hostAgentApiKey.'),
  runtime_api_key: z.string().optional().describe('Runtime Node API key to pass through to the runtime. Defaults to runtime.apiKey.'),
  sample_id: z.string().optional().describe('Optional sample id to bind this runtime debug session to the persisted debug session table.'),
  timeout_ms: z.number().int().min(1000).max(10 * 60 * 1000).optional().default(120_000),
  manual_endpoint: z.string().url().optional().describe('Attach to an already running Runtime Node instead of asking Host Agent to start one.'),
  hyperv_retention_policy: z
    .enum(['clean_rollback', 'stop_only', 'preserve_dirty'])
    .optional()
    .describe('High-level Hyper-V release policy. clean_rollback restores a checkpoint on release, stop_only powers off the VM, preserve_dirty leaves the VM state available for manual review.'),
  hyperv_snapshot_name: z.string().optional().describe('Optional Hyper-V checkpoint name forwarded to Host Agent when backend=hyperv-vm.'),
  hyperv_restore_on_start: z.boolean().optional().describe('Override Hyper-V restore-on-start policy for this session.'),
  hyperv_restore_on_release: z.boolean().optional().describe('Override Hyper-V restore-on-release policy for this session.'),
  hyperv_stop_on_release: z.boolean().optional().describe('Override Hyper-V stop-on-release policy for this session. Use false to preserve dirty VM state after release.'),
})

export const RuntimeDebugSessionStatusInputSchema = z.object({
  session_id: z.string().optional().describe('Runtime debug session id. Omit to list tracked sessions and Host Agent health.'),
  sample_id: z.string().optional().describe('Optional sample id used to include persisted runtime debug sessions for this sample.'),
  limit: z.number().int().min(1).max(200).optional().default(20),
  host_agent_endpoint: z.string().url().optional(),
  host_agent_api_key: z.string().optional(),
  runtime_api_key: z.string().optional(),
})

export const RuntimeDebugSessionStopInputSchema = z.object({
  session_id: z.string().describe('Runtime debug session id returned by runtime.debug.session.start'),
  host_agent_endpoint: z.string().url().optional(),
  host_agent_api_key: z.string().optional(),
})

export const RuntimeDebugCommandInputSchema = z.object({
  session_id: z.string().describe('Runtime debug session id returned by runtime.debug.session.start'),
  tool: z
    .string()
    .min(1)
    .default('debug.session.inspect')
    .describe('Runtime tool name to execute, e.g. debug.session.start, debug.session.inspect, sandbox.execute, dynamic.memory_dump.'),
  sample_id: z.string().optional().describe('Optional sample id. When provided, the sample is uploaded to the runtime inbox for this task.'),
  sidecar_paths: z
    .array(z.string())
    .optional()
    .default([])
    .describe('Optional local sidecar files, such as DLLs or config files, to stage next to the sample inside the Runtime Node.'),
  auto_stage_sidecars: z
    .boolean()
    .optional()
    .default(true)
    .describe('Best-effort scan of the sample directory for common sidecar files (.dll, .config, .json, .dat, etc.) before upload.'),
  max_sidecars: z.number().int().min(0).max(256).optional().default(32),
  sidecar_max_total_bytes: z.number().int().min(0).max(1024 * 1024 * 1024).optional().default(128 * 1024 * 1024),
  args: z.record(z.string(), z.unknown()).optional().default({}),
  runtime_backend_hint: RuntimeBackendHintSchema.optional().describe('Runtime backend hint. Defaults to inline/executeDebugSession for debug.session.* tools.'),
  runtime_api_key: z.string().optional(),
  timeout_ms: z.number().int().min(1000).max(30 * 60 * 1000).optional().default(120_000),
})

const RuntimeDebugOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const runtimeDebugSessionStartToolDefinition: ToolDefinition = {
  name: SESSION_START_TOOL,
  description:
    'Start or attach to a runtime debug session. In remote-sandbox mode this asks the Windows Host Agent to start the selected backend (Windows Sandbox or Hyper-V VM) and returns a session id plus Runtime Node endpoint.',
  inputSchema: RuntimeDebugSessionStartInputSchema,
  outputSchema: RuntimeDebugOutputSchema,
}

export const runtimeDebugSessionStatusToolDefinition: ToolDefinition = {
  name: SESSION_STATUS_TOOL,
  description:
    'Inspect runtime debug session health, tracked sessions, Host Agent backend state, and Runtime Node /health output.',
  inputSchema: RuntimeDebugSessionStatusInputSchema,
  outputSchema: RuntimeDebugOutputSchema,
}

export const runtimeDebugSessionStopToolDefinition: ToolDefinition = {
  name: SESSION_STOP_TOOL,
  description:
    'Stop or release a runtime debug session through the Windows Host Agent. Hyper-V sessions honor Host Agent backend stop policy.',
  inputSchema: RuntimeDebugSessionStopInputSchema,
  outputSchema: RuntimeDebugOutputSchema,
}

export const runtimeDebugCommandToolDefinition: ToolDefinition = {
  name: COMMAND_TOOL,
  description:
    'Dispatch a Runtime Node command into an existing debug session. This reuses the Runtime Node /execute contract and supports debug.session.*, sandbox.execute, dynamic.behavior.capture, dynamic.memory_dump, managed.safe_run, and other advertised runtime handlers.',
  inputSchema: RuntimeDebugCommandInputSchema,
  outputSchema: RuntimeDebugOutputSchema,
}

function getRuntimeConfig(deps: PluginToolDeps) {
  return deps.config?.runtime || {}
}

function getAuthHeader(apiKey?: string): Record<string, string> {
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : {}
}

async function fetchJson(
  url: string,
  options: RequestInit = {},
  timeoutMs = 30_000
): Promise<{ status: number; ok: boolean; body: any; text: string }> {
  const res = await fetch(url, {
    ...options,
    signal: options.signal ?? AbortSignal.timeout(timeoutMs),
  })
  const text = await res.text()
  let body: any = null
  if (text.trim()) {
    try {
      body = JSON.parse(text)
    } catch {
      body = null
    }
  }
  return { status: res.status, ok: res.ok, body, text }
}

async function runtimeHealth(endpoint: string, runtimeApiKey?: string): Promise<unknown> {
  const healthUrl = new URL('/health', endpoint).toString()
  const response = await fetchJson(
    healthUrl,
    { headers: getAuthHeader(runtimeApiKey) },
    10_000
  )
  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      error: response.body?.error || response.text || `HTTP ${response.status}`,
    }
  }
  return response.body
}

function resolveHostAgentEndpoint(inputEndpoint: string | undefined, deps: PluginToolDeps): string | undefined {
  const runtime = getRuntimeConfig(deps)
  return inputEndpoint || runtime.hostAgentEndpoint
}

function resolveHostAgentApiKey(inputKey: string | undefined, deps: PluginToolDeps): string | undefined {
  const runtime = getRuntimeConfig(deps)
  return inputKey || runtime.hostAgentApiKey
}

function resolveRuntimeApiKey(inputKey: string | undefined, deps: PluginToolDeps): string | undefined {
  const runtime = getRuntimeConfig(deps)
  return inputKey || runtime.apiKey
}

function resolveHyperVStartPolicy(input: z.infer<typeof RuntimeDebugSessionStartInputSchema>): {
  hypervSnapshotName?: string
  hypervRestoreOnStart?: boolean
  hypervRestoreOnRelease?: boolean
  hypervStopOnRelease?: boolean
  requestedPolicy?: string
} {
  let hypervRestoreOnStart = input.hyperv_restore_on_start
  let hypervRestoreOnRelease = input.hyperv_restore_on_release
  let hypervStopOnRelease = input.hyperv_stop_on_release

  switch (input.hyperv_retention_policy) {
    case 'clean_rollback':
      hypervRestoreOnStart ??= true
      hypervRestoreOnRelease ??= true
      hypervStopOnRelease ??= true
      break
    case 'stop_only':
      hypervRestoreOnRelease ??= false
      hypervStopOnRelease ??= true
      break
    case 'preserve_dirty':
      hypervRestoreOnRelease ??= false
      hypervStopOnRelease ??= false
      break
  }

  return {
    requestedPolicy: input.hyperv_retention_policy,
    hypervSnapshotName: input.hyperv_snapshot_name,
    hypervRestoreOnStart,
    hypervRestoreOnRelease,
    hypervStopOnRelease,
  }
}

function buildDefaultRuntimeBackendHint(tool: string): z.infer<typeof RuntimeBackendHintSchema> | undefined {
  if (tool.startsWith('debug.session.')) {
    return { type: 'inline', handler: 'executeDebugSession' }
  }
  if (tool === 'sandbox.execute') {
    return { type: 'inline', handler: 'executeSandboxExecute' }
  }
  if (tool === 'dynamic.memory_dump') {
    return { type: 'inline', handler: 'executeDynamicMemoryDump' }
  }
  if (tool === 'dynamic.behavior.capture') {
    return { type: 'inline', handler: 'executeBehaviorCapture' }
  }
  if (tool === 'debug.procdump.capture') {
    return { type: 'inline', handler: 'executeProcDumpCapture' }
  }
  if (tool === 'debug.telemetry.capture') {
    return { type: 'inline', handler: 'executeTelemetryCapture' }
  }
  if (tool === 'managed.safe_run') {
    return { type: 'inline', handler: 'executeManagedSafeRun' }
  }
  return undefined
}

function isSampleBoundRuntimeTool(tool: string): boolean {
  return (
    tool.startsWith('debug.session.') ||
    tool === 'sandbox.execute' ||
    tool === 'dynamic.behavior.capture' ||
    tool === 'dynamic.memory_dump' ||
    tool === 'managed.safe_run'
  )
}

function sanitizePathSegment(segment: string, fallback = 'runtime'): string {
  const cleaned = segment.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 96)
  return cleaned || fallback
}

function guessMime(filename: string): string {
  const lower = filename.toLowerCase()
  if (lower.endsWith('.json')) return 'application/json'
  if (lower.endsWith('.txt')) return 'text/plain'
  if (lower.endsWith('.log')) return 'text/plain'
  if (lower.endsWith('.html')) return 'text/html'
  if (lower.endsWith('.png')) return 'image/png'
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg'
  return 'application/octet-stream'
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

function extractSha256FromSampleId(sampleId: string): string | null {
  const match = /^sha256:([a-f0-9]{64})$/i.exec(sampleId)
  return match ? match[1].toLowerCase() : null
}

function buildRuntimeDebugGuidance(status: string): Record<string, unknown> {
  return {
    recommended_next_tools: [
      COMMAND_TOOL,
      SESSION_STATUS_TOOL,
      SESSION_STOP_TOOL,
      'dynamic.trace.import',
      'dynamic.memory.import',
    ],
    next_actions: status === 'captured'
      ? [
          'Review imported runtime_debug_artifact records with artifact.read or artifacts.list.',
          'Use dynamic.trace.import or dynamic.memory.import when the runtime command produced trace or dump outputs.',
        ]
      : [
          'Dispatch a runtime.debug.command using one of the advertised Runtime Node backend handlers.',
          'Call runtime.debug.session.status before long-running commands to confirm runtime health and capabilities.',
        ],
  }
}

function buildSessionMetadata(session: RuntimeDebugSession, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    runtime_debug_schema: 'v1',
    endpoint: session.endpoint,
    sandbox_id: session.sandboxId ?? null,
    backend: session.backend ?? null,
    started_at: session.startedAt,
    stopped_at: session.stoppedAt ?? null,
    last_task_id: session.lastTaskId ?? null,
    last_health: session.lastHealth ?? null,
    capabilities: session.capabilities ?? null,
    hyperv_policy: session.hypervPolicy ?? null,
    ...extra,
  }
}

function resolveSampleMetadata(deps: PluginToolDeps, sampleId: string): { sampleId: string; sha256: string } | null {
  const sample = deps.database?.findSample?.(sampleId)
  if (sample && typeof sample.sha256 === 'string') {
    return { sampleId, sha256: sample.sha256 }
  }

  if (deps.database?.findSample) {
    return null
  }

  const sha256 = extractSha256FromSampleId(sampleId)
  return sha256 ? { sampleId, sha256 } : null
}

async function persistRuntimeSession(
  deps: PluginToolDeps,
  session: RuntimeDebugSession,
  sampleId: string | undefined,
  updates: {
    status?: string
    debugState?: string
    phase?: string
    finishedAt?: string | null
    metadata?: Record<string, unknown>
  } = {}
): Promise<void> {
  const db = deps.database
  if (!db?.insertDebugSession || !db?.updateDebugSession || !sampleId) {
    return
  }

  const sample = resolveSampleMetadata(deps, sampleId)
  if (!sample) {
    return
  }

  const now = new Date().toISOString()
  const artifactRefs = session.artifactRefs || []
  const status = updates.status || 'armed'
  const debugState = updates.debugState || (status === 'captured' ? 'captured' : status === 'capturing' ? 'capturing' : 'armed')
  const phase = updates.phase || 'runtime_ready'
  const metadataJson = JSON.stringify(buildSessionMetadata(session, updates.metadata), null, 2)
  const guidanceJson = JSON.stringify(buildRuntimeDebugGuidance(status), null, 2)
  const artifactRefsJson = JSON.stringify(artifactRefs, null, 2)
  const existing = db.findDebugSession?.(session.sessionId)

  if (existing) {
    db.updateDebugSession(session.sessionId, {
      status,
      debug_state: debugState,
      backend: session.backend ?? existing.backend ?? null,
      current_phase: phase,
      artifact_refs_json: artifactRefsJson,
      guidance_json: guidanceJson,
      metadata_json: metadataJson,
      updated_at: now,
      finished_at: updates.finishedAt === undefined ? existing.finished_at : updates.finishedAt,
    })
  } else {
    db.insertDebugSession({
      id: session.sessionId,
      run_id: null,
      sample_id: sample.sampleId,
      sample_sha256: sample.sha256,
      status,
      debug_state: debugState,
      backend: session.backend ?? null,
      current_phase: phase,
      session_tag: `runtime-debug-${session.sessionId.slice(0, 8)}`,
      artifact_refs_json: artifactRefsJson,
      guidance_json: guidanceJson,
      metadata_json: metadataJson,
      created_at: session.startedAt,
      updated_at: now,
      finished_at: updates.finishedAt ?? null,
    })
  }

  session.persisted = true
  session.status = status
  session.debugState = debugState
  session.sampleId = sample.sampleId
  session.sampleSha256 = sample.sha256
}

function restorePersistedSession(deps: PluginToolDeps, sessionId: string): RuntimeDebugSession | undefined {
  const row = deps.database?.findDebugSession?.(sessionId)
  if (!row) {
    return undefined
  }

  const metadata = parseJsonObject(row.metadata_json)
  const endpoint = typeof metadata.endpoint === 'string' ? metadata.endpoint : undefined
  if (!endpoint) {
    return undefined
  }

  const session: RuntimeDebugSession = {
    sessionId: row.id,
    endpoint,
    sandboxId: typeof metadata.sandbox_id === 'string' ? metadata.sandbox_id : undefined,
    backend: typeof metadata.backend === 'string' ? metadata.backend : row.backend ?? undefined,
    startedAt: row.created_at,
    stoppedAt: typeof metadata.stopped_at === 'string' ? metadata.stopped_at : row.finished_at ?? undefined,
    status: row.status,
    debugState: row.debug_state,
    sampleId: row.sample_id,
    sampleSha256: row.sample_sha256,
    persisted: true,
    lastTaskId: typeof metadata.last_task_id === 'string' ? metadata.last_task_id : undefined,
    lastHealth: metadata.last_health,
    capabilities: Array.isArray(metadata.capabilities) ? metadata.capabilities as RuntimeBackendCapability[] : null,
    artifactRefs: parseArtifactRefs(row.artifact_refs_json),
    hypervPolicy: metadata.hyperv_policy && typeof metadata.hyperv_policy === 'object'
      ? metadata.hyperv_policy as Record<string, unknown>
      : undefined,
  }
  sessions.set(sessionId, session)
  return session
}

function getRuntimeDebugSession(deps: PluginToolDeps, sessionId: string): RuntimeDebugSession | undefined {
  return sessions.get(sessionId) || restorePersistedSession(deps, sessionId)
}

function normalizePersistedDebugSession(row: any): Record<string, unknown> {
  const metadata = parseJsonObject(row?.metadata_json)
  return {
    sessionId: row?.id,
    sample_id: row?.sample_id,
    sample_sha256: row?.sample_sha256,
    status: row?.status,
    debug_state: row?.debug_state,
    backend: row?.backend,
    current_phase: row?.current_phase,
    session_tag: row?.session_tag,
    artifact_refs: parseArtifactRefs(row?.artifact_refs_json),
    endpoint: typeof metadata.endpoint === 'string' ? metadata.endpoint : null,
    sandbox_id: typeof metadata.sandbox_id === 'string' ? metadata.sandbox_id : null,
    last_task_id: typeof metadata.last_task_id === 'string' ? metadata.last_task_id : null,
    hyperv_policy: metadata.hyperv_policy && typeof metadata.hyperv_policy === 'object' ? metadata.hyperv_policy : null,
    created_at: row?.created_at,
    updated_at: row?.updated_at,
    finished_at: row?.finished_at,
  }
}

async function runtimeCapabilities(endpoint: string, runtimeApiKey?: string): Promise<RuntimeBackendCapability[] | null> {
  const capabilitiesUrl = new URL('/capabilities', endpoint).toString()
  const response = await fetchJson(
    capabilitiesUrl,
    { headers: getAuthHeader(runtimeApiKey) },
    10_000
  )
  if (!response.ok) {
    return null
  }
  const entries = response.body?.data?.runtime_backends
  if (!Array.isArray(entries)) {
    return null
  }

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

function findRuntimeCapability(
  capabilities: RuntimeBackendCapability[] | null | undefined,
  hint: z.infer<typeof RuntimeBackendHintSchema> | undefined
): RuntimeBackendCapability | undefined {
  if (!hint || !capabilities) {
    return undefined
  }
  return capabilities.find((entry) => entry.type === hint.type && entry.handler === hint.handler)
}

function buildUnsupportedRuntimeHintResult(
  session: RuntimeDebugSession,
  hint: z.infer<typeof RuntimeBackendHintSchema>,
  capabilities: RuntimeBackendCapability[],
  elapsedMs: number
): WorkerResult {
  const summary = `Runtime does not advertise support for backend hint ${hint.type}/${hint.handler}.`
  return {
    ok: false,
    data: {
      status: 'setup_required',
      failure_category: 'unsupported_runtime_backend_hint',
      summary,
      recommended_next_tools: [SESSION_STATUS_TOOL, 'dynamic.dependencies', 'system.health'],
      next_actions: [
        'Call runtime.debug.session.status to inspect the connected runtime capabilities.',
        'Reconnect a Runtime Node that advertises the required backend handler before retrying this command.',
      ],
      runtime_endpoint: session.endpoint,
      required_runtime_backend_hint: hint,
      available_runtime_backends: capabilities,
    },
    errors: [summary],
    metrics: { elapsed_ms: elapsedMs, tool: COMMAND_TOOL },
  }
}

function collectRuntimeArtifactNames(value: unknown): string[] {
  const names = new Set<string>()
  const seen = new WeakSet<object>()

  const addName = (candidate: unknown) => {
    if (typeof candidate !== 'string' || candidate.trim().length === 0) {
      return
    }
    const basename = path.win32.basename(path.posix.basename(candidate.trim()))
    if (!basename || basename === '.' || basename === '..' || basename.includes('\0') || basename.includes('/') || basename.includes('\\')) {
      return
    }
    names.add(basename)
  }

  const visit = (node: unknown, depth: number) => {
    if (depth > 8 || !node) {
      return
    }
    if (Array.isArray(node)) {
      for (const item of node) {
        visit(item, depth + 1)
      }
      return
    }
    if (typeof node !== 'object') {
      return
    }
    if (seen.has(node)) {
      return
    }
    seen.add(node)

    const record = node as Record<string, unknown>
    if (typeof record.name === 'string') addName(record.name)
    if (typeof record.path === 'string') addName(record.path)
    if (typeof record.filename === 'string') addName(record.filename)

    for (const key of ['artifactRefs', 'artifact_refs', 'artifacts']) {
      const nested = record[key]
      if (Array.isArray(nested)) {
        visit(nested, depth + 1)
      }
    }

    for (const nested of Object.values(record)) {
      if (nested && typeof nested === 'object') {
        visit(nested, depth + 1)
      }
    }
  }

  visit(value, 0)
  return Array.from(names)
}

async function downloadRuntimeArtifact(
  endpoint: string,
  runtimeApiKey: string | undefined,
  taskId: string,
  artifactName: string,
  downloadDir: string
): Promise<string> {
  const basename = path.win32.basename(path.posix.basename(artifactName))
  const safeName = sanitizePathSegment(basename, 'artifact.bin')
  const url = new URL(`/download/${encodeURIComponent(taskId)}/${encodeURIComponent(basename)}`, endpoint).toString()
  const response = await fetch(url, {
    headers: getAuthHeader(runtimeApiKey),
    signal: AbortSignal.timeout(60_000),
  })
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    throw new Error(`Runtime artifact download failed for ${safeName}: HTTP ${response.status}${text ? ` ${text}` : ''}`)
  }
  const bytes = Buffer.from(await response.arrayBuffer())
  const destPath = path.join(downloadDir, safeName)
  await fs.promises.writeFile(destPath, bytes)
  return destPath
}

async function persistRuntimeDebugArtifacts(
  deps: PluginToolDeps,
  sampleId: string | undefined,
  sessionId: string,
  taskId: string,
  toolName: string,
  downloadedPaths: string[]
): Promise<ArtifactRef[]> {
  if (!sampleId || downloadedPaths.length === 0 || !deps.workspaceManager || !deps.database?.insertArtifact) {
    return []
  }

  const persisted: ArtifactRef[] = []
  const workspace = await deps.workspaceManager.createWorkspace(sampleId)
  const reportDir = path.join(workspace.reports, 'runtime_debug', sanitizePathSegment(sessionId))
  await fs.promises.mkdir(reportDir, { recursive: true })

  for (const srcPath of downloadedPaths) {
    const basename = path.basename(srcPath)
    const destName = `${sanitizePathSegment(toolName)}_${taskId}_${sanitizePathSegment(basename, 'artifact.bin')}`
    const destPath = path.join(reportDir, destName)
    await fs.promises.copyFile(srcPath, destPath)
    const content = await fs.promises.readFile(destPath)
    const sha256 = createHash('sha256').update(content).digest('hex')
    const relativePath = path.relative(workspace.root, destPath).replace(/\\/g, '/')
    const artifactId = randomUUID()
    const createdAt = new Date().toISOString()
    const mime = guessMime(basename)

    deps.database.insertArtifact({
      id: artifactId,
      sample_id: sampleId,
      type: 'runtime_debug_artifact',
      path: relativePath,
      sha256,
      mime,
      created_at: createdAt,
    })

    persisted.push({
      id: artifactId,
      type: 'runtime_debug_artifact',
      path: relativePath,
      sha256,
      mime,
      metadata: {
        runtime_debug_session_id: sessionId,
        runtime_task_id: taskId,
        runtime_tool: toolName,
      },
    })
  }

  return persisted
}

function sanitizeRuntimeUploadName(value: string, fallback: string): string {
  const basename = path
    .basename((value || fallback).replace(/\\/g, '/'))
    .replace(/[<>:"|?*\x00-\x1f]/g, '_')
    .replace(/^\.+$/, '')
    .slice(0, 160)
  return basename || fallback
}

async function uploadRuntimeFile(
  endpoint: string,
  runtimeApiKey: string | undefined,
  taskId: string,
  filePath: string,
  filename: string,
  role: 'primary' | 'sidecar',
): Promise<void> {
  const url = new URL('/upload', endpoint)
  url.searchParams.set('taskId', taskId)
  url.searchParams.set('filename', sanitizeRuntimeUploadName(filename, role === 'primary' ? `${taskId}.sample` : 'sidecar.bin'))
  url.searchParams.set('role', role)
  const transport = url.protocol === 'https:' ? https : http
  const stat = fs.statSync(filePath)
  const headers: Record<string, string> = {
    'Content-Type': 'application/octet-stream',
    'Content-Length': stat.size.toString(),
    ...getAuthHeader(runtimeApiKey),
  }

  await new Promise<void>((resolve, reject) => {
    const req = transport.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: 'POST',
        headers,
        timeout: 120_000,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf-8')
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve()
            return
          }
          reject(new Error(`Runtime upload failed: HTTP ${res.statusCode || 0}${body ? ` ${body}` : ''}`))
        })
      }
    )
    req.on('error', reject)
    req.on('timeout', () => req.destroy(new Error('Runtime upload timed out')))
    fs.createReadStream(filePath).pipe(req)
  })
}

async function uploadSample(
  endpoint: string,
  runtimeApiKey: string | undefined,
  taskId: string,
  samplePath: string,
  sidecars: RuntimeSidecarUpload[] = [],
): Promise<number> {
  await uploadRuntimeFile(endpoint, runtimeApiKey, taskId, samplePath, path.basename(samplePath), 'primary')
  if (sidecars.length > 0) {
    const health = await runtimeHealth(endpoint, runtimeApiKey).catch(() => null) as any
    if (health?.features?.sidecarUpload !== true) {
      return 0
    }
  }
  for (const sidecar of sidecars) {
    await uploadRuntimeFile(endpoint, runtimeApiKey, taskId, sidecar.path, sidecar.name || path.basename(sidecar.path), 'sidecar')
  }
  return sidecars.length
}

async function pollRuntimeTask(
  endpoint: string,
  runtimeApiKey: string | undefined,
  taskId: string,
  timeoutMs: number
): Promise<unknown> {
  const started = Date.now()
  while (Date.now() - started < timeoutMs + 30_000) {
    const statusUrl = new URL(`/tasks/${encodeURIComponent(taskId)}`, endpoint).toString()
    const status = await fetchJson(statusUrl, { headers: getAuthHeader(runtimeApiKey) }, 30_000)
    if (!status.ok) {
      throw new Error(`Runtime task status failed: HTTP ${status.status}${status.text ? ` ${status.text}` : ''}`)
    }
    if (status.body?.status === 'completed' || status.body?.status === 'failed' || status.body?.status === 'cancelled') {
      return status.body
    }
    await new Promise((resolve) => setTimeout(resolve, 2000))
  }
  throw new Error(`Runtime task timed out after ${timeoutMs + 30_000}ms`)
}

export function createRuntimeDebugSessionStartHandler(deps: PluginToolDeps) {
  return async (rawArgs: unknown): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const input = RuntimeDebugSessionStartInputSchema.parse(rawArgs)
      const runtimeApiKey = resolveRuntimeApiKey(input.runtime_api_key, deps)

      if (input.manual_endpoint) {
        const health = await runtimeHealth(input.manual_endpoint, runtimeApiKey)
        const sessionId = randomUUID()
        const session: RuntimeDebugSession = {
          sessionId,
          endpoint: input.manual_endpoint,
          backend: 'manual',
          startedAt: new Date().toISOString(),
          lastHealth: health,
          artifactRefs: [],
        }
        await persistRuntimeSession(deps, session, input.sample_id)
        sessions.set(sessionId, session)
        return {
          ok: true,
          data: { session, health, persistent: session.persisted === true, tracked_sessions: sessions.size },
          metrics: { elapsed_ms: Date.now() - start, tool: SESSION_START_TOOL },
        }
      }

      const hostAgentEndpoint = resolveHostAgentEndpoint(input.host_agent_endpoint, deps)
      const hostAgentApiKey = resolveHostAgentApiKey(input.host_agent_api_key, deps)
      if (!hostAgentEndpoint) {
        return {
          ok: false,
          errors: ['runtime.hostAgentEndpoint is not configured. Provide host_agent_endpoint or use manual_endpoint.'],
          metrics: { elapsed_ms: Date.now() - start, tool: SESSION_START_TOOL },
        }
      }

      const startUrl = new URL('/sandbox/start', hostAgentEndpoint).toString()
      const hypervStartPolicy = resolveHyperVStartPolicy(input)
      const response = await fetchJson(
        startUrl,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...getAuthHeader(hostAgentApiKey) },
          body: JSON.stringify({
            timeoutMs: input.timeout_ms,
            runtimeApiKey,
            hypervSnapshotName: hypervStartPolicy.hypervSnapshotName,
            hypervRestoreOnStart: hypervStartPolicy.hypervRestoreOnStart,
            hypervRestoreOnRelease: hypervStartPolicy.hypervRestoreOnRelease,
            hypervStopOnRelease: hypervStartPolicy.hypervStopOnRelease,
          }),
        },
        input.timeout_ms + 15_000
      )
      if (!response.ok || response.body?.ok !== true || !response.body?.endpoint) {
        return {
          ok: false,
          data: {
            host_agent: response.body || null,
            diagnostics: response.body?.diagnostics || null,
          },
          errors: [
            `Host Agent failed to start runtime: HTTP ${response.status}${response.text ? ` ${response.text}` : ''}`,
          ],
          metrics: { elapsed_ms: Date.now() - start, tool: SESSION_START_TOOL },
        }
      }

      const health = await runtimeHealth(response.body.endpoint, runtimeApiKey).catch((err) => ({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      }))
      const sessionId = randomUUID()
      const session: RuntimeDebugSession = {
        sessionId,
        sandboxId: response.body.sandboxId,
        endpoint: response.body.endpoint,
        backend: response.body.backend || response.body.runtimeBackend || 'host-agent',
        startedAt: new Date().toISOString(),
        lastHealth: health,
        artifactRefs: [],
        hypervPolicy:
          response.body.hyperv && typeof response.body.hyperv === 'object'
            ? {
                requestedPolicy: hypervStartPolicy.requestedPolicy ?? null,
                ...(response.body.hyperv as Record<string, unknown>),
              }
            : undefined,
      }
      await persistRuntimeSession(deps, session, input.sample_id)
      sessions.set(sessionId, session)
      return {
        ok: true,
        data: { session, health, persistent: session.persisted === true, tracked_sessions: sessions.size },
        metrics: { elapsed_ms: Date.now() - start, tool: SESSION_START_TOOL },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [err instanceof Error ? err.message : String(err)],
        metrics: { elapsed_ms: Date.now() - start, tool: SESSION_START_TOOL },
      }
    }
  }
}

export function createRuntimeDebugSessionStatusHandler(deps: PluginToolDeps) {
  return async (rawArgs: unknown): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const input = RuntimeDebugSessionStatusInputSchema.parse(rawArgs)
      const runtimeApiKey = resolveRuntimeApiKey(input.runtime_api_key, deps)
      const selected = input.session_id ? getRuntimeDebugSession(deps, input.session_id) : undefined
      const runtime = selected
        ? await runtimeHealth(selected.endpoint, runtimeApiKey).catch((err) => ({
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          }))
        : null
      if (selected) {
        selected.lastHealth = runtime
        const capabilities = await runtimeCapabilities(selected.endpoint, runtimeApiKey).catch(() => null)
        selected.capabilities = capabilities
        if (!selected.stoppedAt && selected.status !== 'captured' && selected.status !== 'correlated') {
          await persistRuntimeSession(deps, selected, selected.sampleId, {
            status: selected.status || 'armed',
            debugState: selected.debugState || 'armed',
            phase: 'runtime_health_checked',
            metadata: { status_checked_at: new Date().toISOString() },
          })
        }
      }

      const hostAgentEndpoint = resolveHostAgentEndpoint(input.host_agent_endpoint, deps)
      const hostAgentApiKey = resolveHostAgentApiKey(input.host_agent_api_key, deps)
      let hostAgent: unknown = null
      if (hostAgentEndpoint) {
        hostAgent = await fetchJson(
          new URL('/sandbox/health', hostAgentEndpoint).toString(),
          { headers: getAuthHeader(hostAgentApiKey) },
          10_000
        ).then((res) => res.body || { ok: res.ok, status: res.status }).catch((err) => ({
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        }))
      }

      return {
        ok: true,
        data: {
          session: selected || null,
          runtime,
          host_agent: hostAgent,
          persisted_sessions: input.sample_id && deps.database?.findDebugSessionsBySample
            ? deps.database.findDebugSessionsBySample(input.sample_id, input.limit).map(normalizePersistedDebugSession)
            : [],
          tracked_sessions: Array.from(sessions.values()),
        },
        metrics: { elapsed_ms: Date.now() - start, tool: SESSION_STATUS_TOOL },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [err instanceof Error ? err.message : String(err)],
        metrics: { elapsed_ms: Date.now() - start, tool: SESSION_STATUS_TOOL },
      }
    }
  }
}

export function createRuntimeDebugSessionStopHandler(deps: PluginToolDeps) {
  return async (rawArgs: unknown): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const input = RuntimeDebugSessionStopInputSchema.parse(rawArgs)
      const session = getRuntimeDebugSession(deps, input.session_id)
      if (!session) {
        return {
          ok: false,
          errors: [`Runtime debug session not found: ${input.session_id}`],
          metrics: { elapsed_ms: Date.now() - start, tool: SESSION_STOP_TOOL },
        }
      }

      let hostAgentResult: unknown = null
      if (session.sandboxId) {
        const hostAgentEndpoint = resolveHostAgentEndpoint(input.host_agent_endpoint, deps)
        const hostAgentApiKey = resolveHostAgentApiKey(input.host_agent_api_key, deps)
        if (!hostAgentEndpoint) {
          return {
            ok: false,
            errors: ['Cannot stop Host Agent backed session because runtime.hostAgentEndpoint is not configured.'],
            metrics: { elapsed_ms: Date.now() - start, tool: SESSION_STOP_TOOL },
          }
        }
        const response = await fetchJson(
          new URL('/sandbox/stop', hostAgentEndpoint).toString(),
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...getAuthHeader(hostAgentApiKey) },
            body: JSON.stringify({ sandboxId: session.sandboxId }),
          },
          30_000
        )
        hostAgentResult = response.body || { ok: response.ok, status: response.status, text: response.text }
        if (!response.ok || response.body?.ok === false) {
          return {
            ok: false,
            data: { session, host_agent: hostAgentResult },
            errors: [`Host Agent failed to stop session: HTTP ${response.status}`],
            metrics: { elapsed_ms: Date.now() - start, tool: SESSION_STOP_TOOL },
          }
        }
      }

      session.stoppedAt = new Date().toISOString()
      await persistRuntimeSession(deps, session, session.sampleId, {
        status: 'captured',
        debugState: 'captured',
        phase: 'runtime_released',
        finishedAt: session.stoppedAt,
        metadata: { stopped_by: SESSION_STOP_TOOL },
      })
      sessions.delete(input.session_id)
      return {
        ok: true,
        data: { stopped_session: session, host_agent: hostAgentResult, tracked_sessions: sessions.size },
        metrics: { elapsed_ms: Date.now() - start, tool: SESSION_STOP_TOOL },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [err instanceof Error ? err.message : String(err)],
        metrics: { elapsed_ms: Date.now() - start, tool: SESSION_STOP_TOOL },
      }
    }
  }
}

export function createRuntimeDebugCommandHandler(deps: PluginToolDeps) {
  return async (rawArgs: unknown): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const input = RuntimeDebugCommandInputSchema.parse(rawArgs)
      const session = getRuntimeDebugSession(deps, input.session_id)
      if (!session) {
        return {
          ok: false,
          errors: [`Runtime debug session not found: ${input.session_id}`],
          metrics: { elapsed_ms: Date.now() - start, tool: COMMAND_TOOL },
        }
      }

      const runtimeApiKey = resolveRuntimeApiKey(input.runtime_api_key, deps)
      const taskId = randomUUID()
      let sidecarWarnings: string[] = []
      let stagedSidecarCount = 0
      const runtimeBackendHint = input.runtime_backend_hint || buildDefaultRuntimeBackendHint(input.tool)
      if (!input.sample_id && isSampleBoundRuntimeTool(input.tool)) {
        return {
          ok: false,
          errors: [`sample_id is required when dispatching sample-bound runtime tool ${input.tool}.`],
          metrics: { elapsed_ms: Date.now() - start, tool: COMMAND_TOOL },
        }
      }

      if (runtimeBackendHint) {
        const capabilities = await runtimeCapabilities(session.endpoint, runtimeApiKey).catch(() => null)
        session.capabilities = capabilities
        if (capabilities && !findRuntimeCapability(capabilities, runtimeBackendHint)) {
          await persistRuntimeSession(deps, session, input.sample_id || session.sampleId, {
            status: 'approval_gated',
            debugState: 'approval_gated',
            phase: 'runtime_capability_mismatch',
            metadata: { required_runtime_backend_hint: runtimeBackendHint },
          })
          return buildUnsupportedRuntimeHintResult(
            session,
            runtimeBackendHint,
            capabilities,
            Date.now() - start
          )
        }
      }

      await persistRuntimeSession(deps, session, input.sample_id || session.sampleId, {
        status: 'capturing',
        debugState: 'capturing',
        phase: `runtime_command:${input.tool}`,
        metadata: { task_id: taskId, runtime_backend_hint: runtimeBackendHint ?? null },
      })

      if (input.sample_id) {
        if (!deps.resolvePrimarySamplePath || !deps.workspaceManager) {
          return {
            ok: false,
            errors: ['Sample upload is unavailable because resolvePrimarySamplePath/workspaceManager is not wired.'],
            metrics: { elapsed_ms: Date.now() - start, tool: COMMAND_TOOL },
          }
        }
        const resolved = await deps.resolvePrimarySamplePath(deps.workspaceManager, input.sample_id)
        const sidecarResolution = await resolveRuntimeSidecarUploads(resolved.samplePath, {
          sidecarPaths: input.sidecar_paths,
          autoStageSidecars: input.auto_stage_sidecars,
          maxSidecars: input.max_sidecars,
          maxTotalBytes: input.sidecar_max_total_bytes,
        })
        sidecarWarnings = sidecarResolution.warnings
        stagedSidecarCount = await uploadSample(session.endpoint, runtimeApiKey, taskId, resolved.samplePath, sidecarResolution.sidecars)
        if (sidecarResolution.sidecars.length > 0 && stagedSidecarCount === 0) {
          sidecarWarnings = [
            ...sidecarWarnings,
            'Runtime Node does not advertise sidecar upload support; sidecar files were not staged.',
          ]
        }
      }

      const executeUrl = new URL('/execute', session.endpoint).toString()
      const submit = await fetchJson(
        executeUrl,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...getAuthHeader(runtimeApiKey) },
          body: JSON.stringify({
            taskId,
            sampleId: input.sample_id || `runtime-debug-session-${input.session_id}`,
            tool: input.tool,
            args: input.args,
            timeoutMs: input.timeout_ms,
            ...(runtimeBackendHint ? { runtimeBackendHint } : {}),
          }),
        },
        30_000
      )
      if (submit.status !== 202 || submit.body?.ok !== true) {
        return {
          ok: false,
          data: { submit: submit.body || submit.text, task_id: taskId },
          errors: [`Runtime command submission failed: HTTP ${submit.status}`],
          metrics: { elapsed_ms: Date.now() - start, tool: COMMAND_TOOL },
        }
      }

      const task = await pollRuntimeTask(session.endpoint, runtimeApiKey, taskId, input.timeout_ms)
      session.lastTaskId = taskId

      let persistedArtifacts: ArtifactRef[] = []
      const artifactNames = collectRuntimeArtifactNames(task)
      if (artifactNames.length > 0) {
        const downloadDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rikune-runtime-debug-'))
        try {
          const downloadedPaths: string[] = []
          for (const artifactName of artifactNames) {
            downloadedPaths.push(await downloadRuntimeArtifact(session.endpoint, runtimeApiKey, taskId, artifactName, downloadDir))
          }
          persistedArtifacts = await persistRuntimeDebugArtifacts(
            deps,
            input.sample_id || session.sampleId,
            session.sessionId,
            taskId,
            input.tool,
            downloadedPaths
          )
        } finally {
          await fs.promises.rm(downloadDir, { recursive: true, force: true }).catch(() => {})
        }
      }
      if (persistedArtifacts.length > 0) {
        session.artifactRefs = [...(session.artifactRefs || []), ...persistedArtifacts]
      }
      await persistRuntimeSession(deps, session, input.sample_id || session.sampleId, {
        status: 'captured',
        debugState: 'captured',
        phase: `runtime_command_completed:${input.tool}`,
        metadata: {
          task_id: taskId,
          runtime_backend_hint: runtimeBackendHint ?? null,
          staged_sidecar_count: stagedSidecarCount,
          sidecar_warnings: sidecarWarnings,
        },
      })

      return {
        ok: true,
        artifacts: persistedArtifacts.length > 0 ? persistedArtifacts : undefined,
        data: {
          session,
          task_id: taskId,
          tool: input.tool,
          runtime_backend_hint: runtimeBackendHint,
          staged_sidecar_count: stagedSidecarCount,
          sidecar_warnings: sidecarWarnings,
          persisted_artifacts: persistedArtifacts,
          task,
        },
        metrics: { elapsed_ms: Date.now() - start, tool: COMMAND_TOOL },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [err instanceof Error ? err.message : String(err)],
        metrics: { elapsed_ms: Date.now() - start, tool: COMMAND_TOOL },
      }
    }
  }
}
