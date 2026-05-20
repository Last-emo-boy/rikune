/**
 * Dashboard API — serves JSON data for the web dashboard.
 *
 * Endpoints:
 *   GET /api/v1/dashboard/overview          — server overview (uptime, version, tool/plugin counts)
 *   GET /api/v1/dashboard/tools             — full tool listing with categories
 *   GET /api/v1/dashboard/plugins           — plugin statuses
 *   GET /api/v1/dashboard/samples           — recent samples
 *   GET /api/v1/dashboard/samples/:id       — sample detail with analyses & artifacts
 *   GET /api/v1/dashboard/analyses          — recent analyses
 *   GET /api/v1/dashboard/runs              — persisted staged analysis runs
 *   GET /api/v1/dashboard/runs/:id          — staged analysis run detail
 *   GET /api/v1/dashboard/artifacts         — artifact listing with type/sample filter
 *   GET /api/v1/dashboard/artifacts/:id/content — artifact file content for rendering
 *   GET /api/v1/dashboard/semantic          — semantic review artifact summaries
 *   GET /api/v1/dashboard/workers           — worker pool stats
 *   GET /api/v1/dashboard/config            — config diagnostics
 *   GET /api/v1/dashboard/system            — host/process information
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { createHash } from 'crypto'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import type { DatabaseManager } from '../../database.js'
import type { ToolDefinition, PromptDefinition, ArtifactRef } from '../../types.js'
import type { WorkspaceManager } from '../../workspace-manager.js'
import { validateConfig, type ValidationReport } from '../../config-validator.js'
import { config } from '../../config.js'
import { getActiveSseClients, eventBus } from '../sse-events.js'
import { logger, logRingBuffer, type LogEntry } from '../../logger.js'
import type { PluginStatus } from '../../plugins/sdk.js'
import type { RuntimeSseEvent } from '../../runtime-client/index.js'
import type { JobQueue } from '../../job-queue.js'
import { extractRuntimeTaskStatusFromEvent } from '@rikune/shared'
import {
  normalizeAnalysisRunStatus,
  normalizeAnalysisStageStatus,
  normalizeJobQueueStatus,
  normalizeRuntimeEventStatus,
} from '../../analysis/analysis-run-state.js'
import {
  SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE,
  SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE,
  SEMANTIC_MODULE_REVIEW_PREPARE_BUNDLE_ARTIFACT_TYPE,
  SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE,
  SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE,
  SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE,
} from '../../artifacts/semantic-name-suggestion-artifacts.js'
import { buildSampleReuseHints } from '../../analysis/reuse-hints.js'

const SERVER_START_TIME = Date.now()
const TASK_TTL_MS = 30 * 60 * 1000
const MAX_DASHBOARD_JSON_SUMMARY_BYTES = 2 * 1024 * 1024

type RuntimeTaskStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'

const RUNTIME_TASK_LIFECYCLE = {
  persistenceFileName: '.runtime-task-store.json',
  persistenceScope: 'runtime-outbox',
  terminalTaskTtlMs: TASK_TTL_MS,
  cleanupBehavior: 'terminal-tasks-purge-outbox-and-state',
  recoveryBehavior: 'queued-and-running-marked-failed-on-restart',
  terminalStatuses: ['completed', 'failed', 'cancelled'] as const,
  persistedStatuses: ['queued', 'running', 'completed', 'failed', 'cancelled'] as const,
} as const

export interface DashboardDeps {
  server: {
    getToolDefinitions(): ToolDefinition[]
    getPromptDefinitions(): PromptDefinition[]
  } | null
  database: DatabaseManager
  workspaceManager?: WorkspaceManager
  runtimeClient?: {
    health(): Promise<{
      ok: boolean
      role: string
      isolation: string
      mode: string
      pid: number
    } | null>
    getEndpoint?(): string
    subscribeEvents?: (options: {
      taskId?: string
      onOpen?: () => void
      onEvent: (event: RuntimeSseEvent) => void
      onError?: (error: Error) => void
    }) => { close(): void }
  } | null
  jobQueue?: Pick<JobQueue, 'getQueueLength' | 'listStatuses'>
  getPluginStatuses?: () => PluginStatus[]
}

interface RuntimeEventSnapshot {
  connected: boolean
  lastEventAt: string | null
  lastEvent: RuntimeSseEvent | null
  recentEvents: RuntimeSseEvent[]
  lastError: string | null
  endpoint: string | null
}

interface RuntimeEventView extends RuntimeSseEvent {
  normalized_status: ReturnType<typeof normalizeRuntimeEventStatus>
}

const RUNTIME_EVENT_HISTORY_LIMIT = 25
const SEMANTIC_ARTIFACT_TYPES = [
  SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE,
  SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE,
  SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE,
  SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE,
  SEMANTIC_MODULE_REVIEW_PREPARE_BUNDLE_ARTIFACT_TYPE,
  SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE,
] as const

type SemanticArtifactType = (typeof SEMANTIC_ARTIFACT_TYPES)[number]

const SEMANTIC_ARTIFACT_KIND: Record<SemanticArtifactType, string> = {
  [SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE]: 'name_suggestions',
  [SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE]: 'name_prepare_bundle',
  [SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE]: 'explanation_prepare_bundle',
  [SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE]: 'function_explanations',
  [SEMANTIC_MODULE_REVIEW_PREPARE_BUNDLE_ARTIFACT_TYPE]: 'module_review_prepare_bundle',
  [SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE]: 'module_reviews',
}

interface DashboardArtifactRow {
  id: string
  sample_id: string
  type: string
  path: string
  sha256: string
  mime: string | null
  created_at: string
}

interface SemanticPayloadSummary {
  payload_kind: string | null
  entry_count: number | null
  session_tag: string | null
  client_name: string | null
  model_name: string | null
  prepare_artifact_id: string | null
  prompt_name: string | null
  payload_created_at: string | null
  schema_version: number | string | null
  read_error: string | null
}

interface DashboardRunRow {
  id: string
  sample_id: string
  sample_sha256: string
  goal: string
  depth: string
  backend_policy: string
  pipeline_version: string
  sample_size_tier: string | null
  analysis_budget_profile: string | null
  status: string
  latest_stage: string | null
  stage_plan_json: string | null
  artifact_refs_json: string | null
  metadata_json: string | null
  created_at: string
  updated_at: string
  finished_at: string | null
  reused_from_run_id: string | null
  last_accessed_at: string | null
}

interface DashboardRunStageRow {
  run_id: string
  stage: string
  status: string
  execution_state: string | null
  tool: string | null
  job_id: string | null
  result_json: string | null
  artifact_refs_json: string | null
  coverage_json: string | null
  metadata_json: string | null
  created_at: string
  updated_at: string
  started_at: string | null
  finished_at: string | null
}

interface SemanticRunSummary {
  artifact_count: number
  by_type: Record<string, number>
  session_tags: string[]
  latest_created_at: string | null
  name_suggestion_artifacts: number
  explanation_artifacts: number
  module_review_artifacts: number
  prepare_bundle_artifacts: number
  waiting_for_llm_stages: number
  applied_stages: number
  recoverable_review_stages: number
  accepted_count: number
  rejected_count: number
  prepare_artifact_ids: string[]
  apply_artifact_ids: string[]
  semantic_stages: SemanticStageSummary[]
  reconstruct_consumed: boolean
  consumed_artifact_ids: string[]
  consumed_session_tags: string[]
  usage_notes: string[]
}

interface SemanticStageSummary {
  stage: string
  status: string
  review_state: string | null
  review_status: string | null
  session_tag: string | null
  prepare_artifact_id: string | null
  apply_artifact_id: string | null
  accepted_count: number
  rejected_count: number
  updated_at: string
}

interface SemanticArtifactRunLink {
  run_id: string
  stage: string
  review_state: string | null
  review_status: string | null
  updated_at: string
}

let _deps: DashboardDeps | null = null
let runtimeEventSubscription: { close(): void } | null = null
const runtimeEventSnapshot: RuntimeEventSnapshot = {
  connected: false,
  lastEventAt: null,
  lastEvent: null,
  recentEvents: [],
  lastError: null,
  endpoint: null,
}

export function initDashboard(deps: DashboardDeps): void {
  _deps = deps

  runtimeEventSubscription?.close()
  runtimeEventSubscription = null
  runtimeEventSnapshot.connected = false
  runtimeEventSnapshot.lastEventAt = null
  runtimeEventSnapshot.lastEvent = null
  runtimeEventSnapshot.recentEvents = []
  runtimeEventSnapshot.lastError = null
  runtimeEventSnapshot.endpoint = deps.runtimeClient?.getEndpoint?.() ?? null

  if (deps.runtimeClient?.subscribeEvents) {
    runtimeEventSubscription = deps.runtimeClient.subscribeEvents({
      onOpen: () => {
        runtimeEventSnapshot.connected = true
        runtimeEventSnapshot.lastError = null
        runtimeEventSnapshot.endpoint =
          deps.runtimeClient?.getEndpoint?.() ?? runtimeEventSnapshot.endpoint
      },
      onEvent: (event) => {
        runtimeEventSnapshot.connected = true
        runtimeEventSnapshot.lastError = null
        runtimeEventSnapshot.lastEventAt = new Date().toISOString()
        runtimeEventSnapshot.lastEvent = event
        runtimeEventSnapshot.endpoint =
          deps.runtimeClient?.getEndpoint?.() ?? runtimeEventSnapshot.endpoint
        runtimeEventSnapshot.recentEvents = [...runtimeEventSnapshot.recentEvents, event].slice(
          -RUNTIME_EVENT_HISTORY_LIMIT
        )
        eventBus.publish('runtime-events', 'status', {
          event: event.event,
          id: event.id ?? null,
          data: event.data,
          received_at: runtimeEventSnapshot.lastEventAt,
        })
      },
      onError: (error) => {
        runtimeEventSnapshot.connected = false
        runtimeEventSnapshot.lastError = error.message
        eventBus.publish('runtime-events', 'error', {
          message: error.message,
          endpoint: deps.runtimeClient?.getEndpoint?.() ?? runtimeEventSnapshot.endpoint,
          timestamp: new Date().toISOString(),
        })
      },
    })
  }

  // Forward new log entries to SSE stream so the dashboard can display them in real time
  logRingBuffer.onEntry((entry: LogEntry) => {
    eventBus.publish('server-logs', 'log', {
      level: entry.levelLabel,
      time: entry.time,
      msg: entry.msg,
    })
  })
}

function sendJson(
  res: ServerResponse,
  status: number,
  data: unknown,
  req?: IncomingMessage,
  cacheSecs = 0
): void {
  const body = JSON.stringify(data)
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }

  if (cacheSecs > 0) {
    headers['Cache-Control'] = `private, max-age=${cacheSecs}`
    const etag = '"' + createHash('md5').update(body).digest('hex').slice(0, 16) + '"'
    headers['ETag'] = etag
    if (req && req.headers['if-none-match'] === etag) {
      res.writeHead(304, headers)
      res.end()
      return
    }
  } else {
    headers['Cache-Control'] = 'no-cache'
  }

  res.writeHead(status, headers)
  res.end(body)
}

// ══════════════════════════════════════════════════════════════════════════
// Route handler
// ══════════════════════════════════════════════════════════════════════════

export function handleDashboardApi(
  req: IncomingMessage,
  res: ServerResponse,
  pathname: string,
  _searchParams: URLSearchParams
): boolean {
  if (!pathname.startsWith('/api/v1/dashboard')) return false

  const route = pathname.replace('/api/v1/dashboard', '') || '/'

  // Handle parameterized routes first
  const sampleDetailMatch = route.match(/^\/samples\/(.+)$/)
  if (sampleDetailMatch) {
    handleSampleDetail(res, decodeURIComponent(sampleDetailMatch[1])).catch((err) => {
      logger.error({ err }, 'Dashboard: sample detail handler failed')
      if (!res.writableEnded) {
        sendJson(res, 500, { error: 'Failed to load sample detail' })
      }
    })
    return true
  }

  const artifactContentMatch = route.match(/^\/artifacts\/(.+)\/content$/)
  if (artifactContentMatch) {
    handleArtifactContent(res, decodeURIComponent(artifactContentMatch[1])).catch((err) => {
      logger.error({ err }, 'Dashboard: artifact content handler failed')
      if (!res.writableEnded) {
        sendJson(res, 500, { error: 'Internal error reading artifact' })
      }
    })
    return true
  }

  const runDetailMatch = route.match(/^\/runs\/(.+)$/)
  if (runDetailMatch) {
    handleRunDetail(res, decodeURIComponent(runDetailMatch[1]))
    return true
  }

  switch (route) {
    case '/overview':
      handleOverview(res)
      return true
    case '/tools':
      handleTools(res, req)
      return true
    case '/plugins':
      handlePlugins(res, req)
      return true
    case '/samples':
      handleSamples(res, _searchParams)
      return true
    case '/analyses':
      handleAnalyses(res, _searchParams)
      return true
    case '/runs':
      handleRuns(res, _searchParams)
      return true
    case '/artifacts':
      handleArtifacts(res, _searchParams)
      return true
    case '/semantic':
      handleSemantic(res, _searchParams).catch((err) => {
        logger.error({ err }, 'Dashboard: semantic artifact handler failed')
        if (!res.writableEnded) {
          sendJson(res, 500, { error: 'Internal error reading semantic artifacts' })
        }
      })
      return true
    case '/workers':
      handleWorkers(res)
      return true
    case '/config':
      handleConfig(res, req)
      return true
    case '/logs':
      handleLogs(res, _searchParams)
      return true
    case '/system':
      handleSystem(res, req)
      return true
    default:
      sendJson(res, 404, { error: 'Dashboard route not found' })
      return true
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Individual handlers
// ══════════════════════════════════════════════════════════════════════════

function handleOverview(res: ServerResponse): void {
  const tools = _deps?.server?.getToolDefinitions() ?? []
  const prompts = _deps?.server?.getPromptDefinitions() ?? []
  let pluginStatuses: PluginStatus[] = []
  try {
    pluginStatuses = safeGetPluginStatuses()
  } catch {
    /* not initialized */
  }

  const loaded = pluginStatuses.filter((p) => p.status === 'loaded').length
  const sseClients = getActiveSseClients()

  // Query recent sample count
  let sampleCount = 0
  let recentAnalyses = 0
  try {
    const countResult =
      _deps?.database?.querySql<{ cnt: number }>('SELECT COUNT(*) as cnt FROM samples') ?? []
    sampleCount = countResult[0]?.cnt ?? 0

    const recentResult =
      _deps?.database?.querySql<{ cnt: number }>(
        `SELECT COUNT(*) as cnt FROM samples WHERE created_at > datetime('now', '-24 hours')`
      ) ?? []
    recentAnalyses = recentResult[0]?.cnt ?? 0
  } catch {
    /* table may not exist yet */
  }

  sendJson(res, 200, {
    server: {
      version: '1.1.0',
      uptime_seconds: Math.floor((Date.now() - SERVER_START_TIME) / 1000),
      uptime_human: formatUptime(Date.now() - SERVER_START_TIME),
      started_at: new Date(SERVER_START_TIME).toISOString(),
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    counts: {
      tools: tools.length,
      prompts: prompts.length,
      plugins_total: pluginStatuses.length,
      plugins_loaded: loaded,
      samples: sampleCount,
      recent_analyses_24h: recentAnalyses,
      sse_clients: sseClients,
    },
    memory: {
      rss_mb: Math.round(process.memoryUsage().rss / 1024 / 1024),
      heap_used_mb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      heap_total_mb: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
      system_total_mb: Math.round(os.totalmem() / 1024 / 1024),
    },
  })
}

function handleTools(res: ServerResponse, req?: IncomingMessage): void {
  const tools = _deps?.server?.getToolDefinitions() ?? []

  // Categorize tools by prefix
  const categories = new Map<string, Array<{ name: string; description: string }>>()
  for (const t of tools) {
    const dotIdx = t.name.indexOf('.')
    const category = dotIdx > 0 ? t.name.substring(0, dotIdx) : 'core'
    if (!categories.has(category)) categories.set(category, [])
    categories.get(category).push({ name: t.name, description: t.description })
  }

  const result = Array.from(categories.entries())
    .map(([category, items]) => ({ category, count: items.length, tools: items }))
    .sort((a, b) => b.count - a.count)

  sendJson(res, 200, { total: tools.length, categories: result }, req, 30)
}

function handlePlugins(res: ServerResponse, req?: IncomingMessage): void {
  const statuses = safeGetPluginStatuses()

  const data = {
    total: statuses.length,
    loaded: statuses.filter((s) => s.status === 'loaded').length,
    skipped: statuses.filter((s) => s.status.startsWith('skipped')).length,
    errored: statuses.filter((s) => s.status === 'error').length,
    quality_warning_count: statuses.reduce(
      (sum, s) => sum + (s.qualityWarnings?.length ?? 0),
      0
    ),
    plugins: statuses.map((s) => ({
      id: s.id,
      name: s.name,
      version: s.version ?? null,
      description: s.description ?? null,
      status: s.status,
      normalized_status: s.controlPlaneStatus ?? normalizePluginControlPlaneStatus(s.status),
      reason_code: s.reasonCode ?? null,
      status_detail: s.statusDetail ?? s.error ?? null,
      tool_count: s.tools.length,
      tools: s.tools,
      error: s.error ?? null,
      quality_warning_count: s.qualityWarnings?.length ?? 0,
      quality_warnings: s.qualityWarnings ?? [],
      dependency_checks:
        s.depChecks?.map((dep) => ({
          name: dep.dep.name,
          type: dep.dep.type,
          required: dep.dep.required,
          available: dep.available,
          resolved_path: dep.resolvedPath ?? null,
          version: dep.version ?? null,
          error: dep.error ?? null,
        })) ?? [],
    })),
  }
  sendJson(res, 200, data, req, 15)
}

function getSearchTerm(params: URLSearchParams): string | null {
  const search = params.get('search')?.trim().toLowerCase()
  return search && search.length > 0 ? search : null
}

function appendTextSearchClause(
  clauses: string[],
  sqlParams: unknown[],
  columns: string[],
  search: string | null
): void {
  if (!search) {
    return
  }

  clauses.push(`(${columns.map((column) => `LOWER(COALESCE(${column}, '')) LIKE ?`).join(' OR ')})`)
  for (let i = 0; i < columns.length; i++) {
    sqlParams.push(`%${search}%`)
  }
}

function handleSamples(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '50', 10) || 50, 200)
  const offset = parseInt(params.get('offset') || '0', 10) || 0
  const search = getSearchTerm(params)

  let samples: unknown[] = []
  let total = 0
  try {
    let where = ''
    const sqlParams: unknown[] = []
    const clauses: string[] = []
    appendTextSearchClause(
      clauses,
      sqlParams,
      ['id', 'sha256', 'md5', 'file_type', 'source'],
      search
    )
    if (clauses.length) where = ' WHERE ' + clauses.join(' AND ')

    const countResult =
      _deps?.database?.querySql<{ cnt: number }>(
        `SELECT COUNT(*) as cnt FROM samples${where}`,
        sqlParams
      ) ?? []
    total = countResult[0]?.cnt ?? 0

    samples =
      _deps?.database?.querySql(
        `SELECT id, sha256, size, file_type, source, created_at FROM samples${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
        [...sqlParams, limit, offset]
      ) ?? []
  } catch {
    /* table may not exist */
  }

  sendJson(res, 200, { total, offset, limit, samples })
}

function handleWorkers(res: ServerResponse): void {
  const jobs = _deps?.jobQueue?.listStatuses?.() ?? []
  const normalizedJobs = jobs.map((job) => ({
    ...job,
    normalized_status: normalizeJobQueueStatus(job.status),
  }))
  const queuedJobs = normalizedJobs.filter((job) => job.normalized_status === 'pending')
  const runningJobs = normalizedJobs.filter((job) => job.normalized_status === 'active')
  const terminalJobs = normalizedJobs.filter((job) =>
    ['completed', 'failed', 'cancelled', 'recoverable'].includes(job.normalized_status)
  )
  const pluginStatuses = safeGetPluginStatuses()
  const pluginCounts = summarizePluginStatuses(pluginStatuses)
  const runtimeLastEvent = toRuntimeEventView(runtimeEventSnapshot.lastEvent)
  const runtimeRecentEvents = runtimeEventSnapshot.recentEvents.map((event) =>
    toRuntimeEventView(event)
  )

  sendJson(res, 200, {
    runtime: {
      connected: runtimeEventSnapshot.connected,
      endpoint: runtimeEventSnapshot.endpoint,
      lifecycle: RUNTIME_TASK_LIFECYCLE,
      last_event_at: runtimeEventSnapshot.lastEventAt,
      last_error: runtimeEventSnapshot.lastError,
      last_event: runtimeLastEvent,
      recent_events: runtimeRecentEvents,
      normalized_status:
        runtimeLastEvent?.normalized_status ??
        (runtimeEventSnapshot.connected ? 'active' : 'pending'),
    },
    jobs: {
      total: normalizedJobs.length,
      queue_depth: _deps?.jobQueue?.getQueueLength?.() ?? queuedJobs.length,
      queued: queuedJobs.length,
      running: runningJobs.length,
      terminal: terminalJobs.length,
      by_status: normalizedJobs.reduce<Record<string, number>>((acc, job) => {
        acc[job.normalized_status] = (acc[job.normalized_status] ?? 0) + 1
        return acc
      }, {}),
      recent: normalizedJobs.slice(0, 10),
    },
    plugins: pluginCounts,
    process: {
      pid: process.pid,
      uptime_seconds: Math.floor(process.uptime()),
      cpu_usage: process.cpuUsage(),
    },
    system: {
      total_memory_gb: Math.round((os.totalmem() / 1024 / 1024 / 1024) * 10) / 10,
      free_memory_gb: Math.round((os.freemem() / 1024 / 1024 / 1024) * 10) / 10,
      cpus: os.cpus().length,
      load_average: os.loadavg(),
    },
  })
}

function handleConfig(res: ServerResponse, req?: IncomingMessage): void {
  let report: ValidationReport | null = null
  try {
    report = validateConfig(config)
  } catch (err) {
    logger.warn({ err }, 'Dashboard: config validation failed')
  }

  const data = {
    validation: report,
    active: {
      server_port: config.server.port,
      api_port: config.api.port,
      api_enabled: config.api.enabled,
      database_type: config.database.type,
      workspace_root: config.workspace.root,
      cache_enabled: config.cache.enabled,
      log_level: config.logging.level,
      ghidra_enabled: config.workers.ghidra.enabled,
      static_enabled: config.workers.static.enabled,
      dotnet_enabled: config.workers.dotnet.enabled,
      sandbox_enabled: config.workers.sandbox.enabled,
      frida_enabled: config.workers.frida.enabled,
    },
  }
  sendJson(res, 200, data, req, 30)
}

function safeGetPluginStatuses(): PluginStatus[] {
  try {
    return _deps?.getPluginStatuses?.() ?? []
  } catch {
    return []
  }
}

function summarizePluginStatuses(statuses: PluginStatus[]): Record<string, number> {
  return statuses.reduce<Record<string, number>>((acc, status) => {
    const normalized = status.controlPlaneStatus ?? normalizePluginControlPlaneStatus(status.status)
    acc[status.status] = (acc[status.status] ?? 0) + 1
    acc[normalized] = (acc[normalized] ?? 0) + 1
    if (status.reasonCode) {
      const reasonKey = `reason:${status.reasonCode}`
      acc[reasonKey] = (acc[reasonKey] ?? 0) + 1
    }
    return acc
  }, {})
}

function normalizePluginControlPlaneStatus(
  status: PluginStatus['status']
): 'completed' | 'cancelled' | 'failed' {
  switch (status) {
    case 'loaded':
      return 'completed'
    case 'skipped-disabled':
      return 'cancelled'
    case 'skipped-check':
    case 'skipped-deps':
    case 'error':
      return 'failed'
  }
}

function toRuntimeEventView(event: RuntimeSseEvent | null): RuntimeEventView | null {
  if (!event) {
    return null
  }
  return {
    ...event,
    normalized_status: normalizeRuntimeEventStatus(
      event.event,
      extractRuntimeTaskStatusFromEvent(event) ?? null
    ),
  }
}

// ── Logs ────────────────────────────────────────────────────────────────

const LEVEL_NAME_TO_NUM: Record<string, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
}

function handleLogs(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '100', 10) || 100, 500)
  const levelParam = params.get('level')?.toLowerCase()
  const minLevel = levelParam ? (LEVEL_NAME_TO_NUM[levelParam] ?? undefined) : undefined

  const entries = logRingBuffer.getRecent(limit, minLevel)
  sendJson(res, 200, { logs: entries, total: entries.length })
}

function handleSystem(res: ServerResponse, req?: IncomingMessage): void {
  const data = {
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    node: process.version,
    pid: process.pid,
    cpus: os.cpus().map((c) => ({ model: c.model, speed: c.speed })),
    memory: {
      total_gb: Math.round((os.totalmem() / 1024 / 1024 / 1024) * 10) / 10,
      free_gb: Math.round((os.freemem() / 1024 / 1024 / 1024) * 10) / 10,
      usage_percent: Math.round((1 - os.freemem() / os.totalmem()) * 100),
    },
    uptime_host_seconds: Math.floor(os.uptime()),
    uptime_process_seconds: Math.floor(process.uptime()),
    env: {
      NODE_ENV: process.env.NODE_ENV ?? 'development',
      LOG_LEVEL: process.env.LOG_LEVEL ?? 'info',
    },
  }
  sendJson(res, 200, data, req, 10)
}

// ══════════════════════════════════════════════════════════════════════════
// Sample detail
// ══════════════════════════════════════════════════════════════════════════

async function handleSampleDetail(res: ServerResponse, sampleId: string): Promise<void> {
  try {
    const sample = _deps?.database?.findSample(sampleId)
    if (!sample) {
      sendJson(res, 404, { error: 'Sample not found' })
      return
    }

    const analyses =
      _deps?.database?.querySql<{
        id: string
        stage: string
        backend: string
        status: string
        started_at: string | null
        finished_at: string | null
      }>(
        'SELECT id, stage, backend, status, started_at, finished_at FROM analyses WHERE sample_id = ? ORDER BY started_at DESC',
        [sampleId]
      ) ?? []

    const artifacts =
      _deps?.database?.querySql<{
        id: string
        type: string
        path: string
        mime: string | null
        created_at: string
      }>(
        'SELECT id, type, path, mime, created_at FROM artifacts WHERE sample_id = ? ORDER BY created_at DESC',
        [sampleId]
      ) ?? []

    const functions =
      _deps?.database?.querySql<{
        address: string
        name: string | null
        size: number | null
        score: number | null
      }>(
        'SELECT address, name, size, score FROM functions WHERE sample_id = ? ORDER BY score DESC LIMIT 20',
        [sampleId]
      ) ?? []

    const functionCount =
      _deps?.database?.querySql<{ cnt: number }>(
        'SELECT COUNT(*) as cnt FROM functions WHERE sample_id = ?',
        [sampleId]
      ) ?? []
    const reuseHints = _deps?.database
      ? await buildSampleReuseHints({
          database: _deps.database,
          jobQueue: _deps.jobQueue,
          sampleId,
          sampleSha256: sample.sha256,
          limit: 8,
        })
      : null

    sendJson(res, 200, {
      sample,
      analyses,
      artifacts,
      functions: { top: functions, total: functionCount[0]?.cnt ?? 0 },
      reuse_hints: reuseHints,
    })
  } catch {
    sendJson(res, 500, { error: 'Failed to load sample detail' })
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Analyses listing
// ══════════════════════════════════════════════════════════════════════════

function handleAnalyses(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '50', 10) || 50, 200)
  const offset = parseInt(params.get('offset') || '0', 10) || 0
  const sampleId = params.get('sample_id')
  const status = params.get('status')

  try {
    let where = ''
    const sqlParams: unknown[] = []
    const clauses: string[] = []
    if (sampleId) {
      clauses.push('sample_id = ?')
      sqlParams.push(sampleId)
    }
    if (status) {
      clauses.push('status = ?')
      sqlParams.push(status)
    }
    if (clauses.length) where = ' WHERE ' + clauses.join(' AND ')

    const countResult =
      _deps?.database?.querySql<{ cnt: number }>(
        `SELECT COUNT(*) as cnt FROM analyses${where}`,
        sqlParams
      ) ?? []
    const total = countResult[0]?.cnt ?? 0

    const analyses =
      _deps?.database?.querySql(
        `SELECT id, sample_id, stage, backend, status, started_at, finished_at FROM analyses${where} ORDER BY started_at DESC LIMIT ? OFFSET ?`,
        [...sqlParams, limit, offset]
      ) ?? []

    sendJson(res, 200, { total, offset, limit, analyses })
  } catch {
    sendJson(res, 200, { total: 0, offset, limit, analyses: [] })
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Persisted staged analysis runs
// ══════════════════════════════════════════════════════════════════════════

function handleRuns(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '30', 10) || 30, 100)
  const offset = parseInt(params.get('offset') || '0', 10) || 0
  const sampleId = params.get('sample_id')
  const status = params.get('status')
  const search = getSearchTerm(params)

  try {
    let where = ''
    const sqlParams: unknown[] = []
    const clauses: string[] = []
    if (sampleId) {
      clauses.push('sample_id = ?')
      sqlParams.push(sampleId)
    }
    if (status) {
      clauses.push('status = ?')
      sqlParams.push(status)
    }
    appendTextSearchClause(
      clauses,
      sqlParams,
      [
        'id',
        'sample_id',
        'sample_sha256',
        'goal',
        'depth',
        'backend_policy',
        'status',
        'latest_stage',
      ],
      search
    )
    if (clauses.length) where = ' WHERE ' + clauses.join(' AND ')

    const total =
      _deps?.database?.querySql<{ cnt: number }>(
        `SELECT COUNT(*) as cnt FROM analysis_runs${where}`,
        sqlParams
      )[0]?.cnt ?? 0
    const rows =
      _deps?.database?.querySql<DashboardRunRow>(
        `SELECT * FROM analysis_runs${where} ORDER BY datetime(updated_at) DESC LIMIT ? OFFSET ?`,
        [...sqlParams, limit, offset]
      ) ?? []
    const statusCounts =
      _deps?.database?.querySql<{ status: string; cnt: number }>(
        `SELECT status, COUNT(*) as cnt FROM analysis_runs${where} GROUP BY status ORDER BY cnt DESC`,
        sqlParams
      ) ?? []
    const goalCounts =
      _deps?.database?.querySql<{ goal: string; cnt: number }>(
        `SELECT goal, COUNT(*) as cnt FROM analysis_runs${where} GROUP BY goal ORDER BY cnt DESC`,
        sqlParams
      ) ?? []

    const runs = rows.map((run) => buildRunView(run, false))
    sendJson(res, 200, {
      total,
      offset,
      limit,
      counts: {
        by_status: toCountMap(statusCounts, 'status'),
        by_goal: toCountMap(goalCounts, 'goal'),
      },
      runs,
    })
  } catch {
    sendJson(res, 200, {
      total: 0,
      offset,
      limit,
      counts: { by_status: {}, by_goal: {} },
      runs: [],
    })
  }
}

function handleRunDetail(res: ServerResponse, runId: string): void {
  try {
    const rows =
      _deps?.database?.querySql<DashboardRunRow>('SELECT * FROM analysis_runs WHERE id = ?', [
        runId,
      ]) ?? []
    const run = rows[0]
    if (!run) {
      sendJson(res, 404, { error: 'Analysis run not found' })
      return
    }
    sendJson(res, 200, { run: buildRunView(run, true) })
  } catch {
    sendJson(res, 500, { error: 'Failed to load analysis run' })
  }
}

function buildRunView(run: DashboardRunRow, includeStageResults: boolean) {
  const stages =
    _deps?.database?.querySql<DashboardRunStageRow>(
      'SELECT * FROM analysis_run_stages WHERE run_id = ? ORDER BY datetime(created_at) ASC, stage ASC',
      [run.id]
    ) ?? []
  const stageViews = stages.map((stage) => buildRunStageView(stage, includeStageResults))
  const semantic = buildSemanticRunSummary(run.sample_id, stages)
  const control = buildRunControlSummary(run, stages, stageViews)

  return {
    id: run.id,
    sample_id: run.sample_id,
    sample_sha256: run.sample_sha256,
    goal: run.goal,
    depth: run.depth,
    backend_policy: run.backend_policy,
    pipeline_version: run.pipeline_version,
    sample_size_tier: run.sample_size_tier,
    analysis_budget_profile: run.analysis_budget_profile,
    status: run.status,
    normalized_status: normalizeAnalysisRunStatus(run.status as any),
    latest_stage: run.latest_stage,
    stage_plan: parseDashboardJson<string[]>(run.stage_plan_json, []),
    artifact_refs: parseDashboardJson<ArtifactRef[]>(run.artifact_refs_json, []),
    metadata: parseDashboardJson<Record<string, unknown>>(run.metadata_json, {}),
    created_at: run.created_at,
    updated_at: run.updated_at,
    finished_at: run.finished_at,
    reused_from_run_id: run.reused_from_run_id,
    last_accessed_at: run.last_accessed_at,
    stages: stageViews,
    stage_summary: buildDashboardStageSummary(stageViews),
    provenance_digest: buildDashboardRunProvenanceDigest(run, stages),
    stage_counts: stageViews.reduce<Record<string, number>>((acc, stage) => {
      acc[stage.status] = (acc[stage.status] ?? 0) + 1
      acc[stage.normalized_status] = (acc[stage.normalized_status] ?? 0) + 1
      return acc
    }, {}),
    ...control,
    semantic,
  }
}

function buildDashboardStageSummary(stageViews: Array<ReturnType<typeof buildRunStageView>>) {
  return stageViews.slice(0, 16).map((stage) => ({
    stage: stage.stage,
    status: stage.status,
    normalized_status: stage.normalized_status,
    execution_state: stage.execution_state,
    summary: stage.result_summary?.summary ?? null,
    artifact_count: stage.artifact_count,
    recommended_next_tools: stage.result_summary?.recommended_next_tools ?? [],
  }))
}

function buildDashboardRunProvenanceDigest(
  run: DashboardRunRow,
  stages: DashboardRunStageRow[]
) {
  const artifactIds = new Set<string>()
  for (const ref of parseDashboardJson<ArtifactRef[]>(run.artifact_refs_json, [])) {
    if (ref.id) artifactIds.add(ref.id)
  }
  for (const stage of stages) {
    for (const ref of parseDashboardJson<ArtifactRef[]>(stage.artifact_refs_json, [])) {
      if (ref.id) artifactIds.add(ref.id)
    }
    collectArtifactIdsFromPayload(
      parseDashboardJson<unknown>(stage.result_json, null),
      artifactIds
    )
  }

  return {
    stage_count: stages.length,
    completed_stage_count: stages.filter((stage) => stage.status === 'completed').length,
    artifact_ref_count: artifactIds.size,
    selected_artifact_ids: Array.from(artifactIds).slice(0, 24),
  }
}

function buildRunStageView(stage: DashboardRunStageRow, includeResult: boolean) {
  const artifactRefs = parseDashboardJson<ArtifactRef[]>(stage.artifact_refs_json, [])
  const metadata = parseDashboardJson<Record<string, unknown>>(stage.metadata_json, {})
  const parsedResult = parseDashboardJson<Record<string, unknown>>(stage.result_json, {})
  const result = includeResult ? parsedResult : undefined
  const resultSummary = stage.result_json ? summarizeStageResult(parsedResult) : undefined

  return {
    stage: stage.stage,
    status: stage.status,
    normalized_status: normalizeAnalysisStageStatus(stage.status as any),
    execution_state: stage.execution_state,
    tool: stage.tool,
    job_id: stage.job_id,
    artifact_count: artifactRefs.length,
    artifact_refs: artifactRefs,
    metadata,
    ...(result !== undefined ? { result } : {}),
    ...(resultSummary ? { result_summary: resultSummary } : {}),
    created_at: stage.created_at,
    updated_at: stage.updated_at,
    started_at: stage.started_at,
    finished_at: stage.finished_at,
  }
}

function buildRunControlSummary(
  run: DashboardRunRow,
  stages: DashboardRunStageRow[],
  stageViews: Array<ReturnType<typeof buildRunStageView>>
) {
  const latestStage =
    stages.find((stage) => stage.stage === run.latest_stage) ?? stages[stages.length - 1]
  const latestStageView =
    stageViews.find((stage) => stage.stage === latestStage?.stage) ??
    stageViews[stageViews.length - 1]
  const latestResult = latestStage
    ? parseDashboardJson<Record<string, unknown>>(latestStage.result_json, {})
    : {}
  const latestCoverage = latestStage
    ? extractDashboardCoverage(latestStage.coverage_json, latestResult)
    : null
  const latestSummary =
    latestStage && latestStage.result_json ? summarizeStageResult(latestResult) : null
  const deferredJobs = stageViews
    .filter((stage) => stage.status === 'queued' || stage.status === 'running')
    .map((stage) => ({
      stage: stage.stage,
      status: stage.status,
      normalized_status: stage.normalized_status,
      job_id: stage.job_id,
      tool: stage.tool,
      updated_at: stage.updated_at,
    }))
  const recoverableStages = stages
    .filter((stage) => stage.status === 'recoverable' || stage.status === 'interrupted')
    .map((stage) => {
      const metadata = parseDashboardJson<Record<string, unknown>>(stage.metadata_json, {})
      const result = parseDashboardJson<Record<string, unknown>>(stage.result_json, {})
      return {
        stage: stage.stage,
        status: stage.status,
        job_id: stage.job_id,
        reason:
          asNonEmptyString(metadata.recovery_reason) ||
          asNonEmptyString(result.summary) ||
          asNonEmptyString(result.error) ||
          'Stage can be resumed or re-promoted from persisted run state.',
        updated_at: stage.updated_at,
      }
    })
  const upgradeTools = Array.isArray(latestCoverage?.upgrade_paths)
    ? latestCoverage.upgrade_paths
        .map((item) => (isRecord(item) ? asNonEmptyString(item.tool) : null))
        .filter((item): item is string => Boolean(item))
    : []
  const recommendedNextTools = uniqueDashboardStrings([
    ...(latestSummary?.recommended_next_tools || []),
    ...upgradeTools,
    ...(deferredJobs.length > 0 ? ['workflow.analyze.status'] : []),
    ...(recoverableStages.length > 0 ? ['workflow.analyze.promote'] : []),
    'workflow.analyze.status',
  ]).slice(0, 10)
  const nextActions = uniqueDashboardStrings([
    ...(latestSummary?.next_actions || []),
    ...(deferredJobs.length > 0
      ? ['Poll workflow.analyze.status until queued stages leave the active set.']
      : []),
    ...(recoverableStages.length > 0
      ? ['Re-promote only the recoverable stages that are still needed.']
      : []),
    latestCoverage?.completion_state && latestCoverage.completion_state !== 'completed'
      ? 'Inspect coverage_gaps before treating this run as complete.'
      : null,
  ]).slice(0, 8)

  return {
    current_stage_summary: latestStageView?.result_summary ?? latestSummary,
    coverage_level: asNonEmptyString(latestCoverage?.coverage_level),
    completion_state: asNonEmptyString(latestCoverage?.completion_state),
    coverage_gaps: Array.isArray(latestCoverage?.coverage_gaps) ? latestCoverage.coverage_gaps : [],
    upgrade_paths: Array.isArray(latestCoverage?.upgrade_paths) ? latestCoverage.upgrade_paths : [],
    recommended_next_tools: recommendedNextTools,
    next_actions: nextActions,
    deferred_jobs: deferredJobs,
    recoverable_stages: recoverableStages,
  }
}

function extractDashboardCoverage(
  coverageJson: string | null | undefined,
  result: Record<string, unknown>
): Record<string, unknown> | null {
  const coverage = parseDashboardJson<Record<string, unknown> | null>(coverageJson, null)
  if (coverage && typeof coverage.coverage_level === 'string') {
    return coverage
  }
  if (typeof result.coverage_level === 'string') {
    return result
  }
  return null
}

function uniqueDashboardStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values.filter(
        (value): value is string => typeof value === 'string' && value.trim().length > 0
      )
    )
  )
}

function summarizeStageResult(result: Record<string, unknown>) {
  const stageOutputs = isRecord(result.stage_outputs) ? result.stage_outputs : {}
  return {
    summary: asNonEmptyString(result.summary),
    status: asNonEmptyString(result.status),
    output_keys: Object.keys(stageOutputs),
    recommended_next_tools: Array.isArray(result.recommended_next_tools)
      ? result.recommended_next_tools.filter((item) => typeof item === 'string').slice(0, 8)
      : [],
    next_actions: Array.isArray(result.next_actions)
      ? result.next_actions.filter((item) => typeof item === 'string').slice(0, 4)
      : [],
  }
}

function buildSemanticRunSummary(
  sampleId: string,
  stages: DashboardRunStageRow[]
): SemanticRunSummary {
  const rows =
    _deps?.database?.querySql<{ type: string; path: string; created_at: string; cnt: number }>(
      `SELECT type, path, created_at, 1 as cnt FROM artifacts WHERE sample_id = ? AND type IN (${SEMANTIC_ARTIFACT_TYPES.map(
        () => '?'
      ).join(', ')}) ORDER BY datetime(created_at) DESC`,
      [sampleId, ...SEMANTIC_ARTIFACT_TYPES]
    ) ?? []

  const byType: Record<string, number> = {}
  const sessionTags = new Set<string>()
  let latestCreatedAt: string | null = null
  for (const row of rows) {
    byType[row.type] = (byType[row.type] ?? 0) + 1
    const tag = deriveSemanticSessionTag(row.path)
    if (tag) sessionTags.add(tag)
    if (!latestCreatedAt || row.created_at > latestCreatedAt) {
      latestCreatedAt = row.created_at
    }
  }

  const usage = collectSemanticUsageFromStages(stages)
  const semanticStages = summarizeSemanticStages(stages)
  return {
    artifact_count: rows.length,
    by_type: byType,
    session_tags: Array.from(sessionTags),
    latest_created_at: latestCreatedAt,
    name_suggestion_artifacts: byType[SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE] ?? 0,
    explanation_artifacts: byType[SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE] ?? 0,
    module_review_artifacts: byType[SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE] ?? 0,
    prepare_bundle_artifacts:
      (byType[SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE] ?? 0) +
      (byType[SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE] ?? 0) +
      (byType[SEMANTIC_MODULE_REVIEW_PREPARE_BUNDLE_ARTIFACT_TYPE] ?? 0),
    waiting_for_llm_stages: semanticStages.filter(
      (stage) => stage.review_state === 'waiting_for_llm'
    ).length,
    applied_stages: semanticStages.filter((stage) => stage.review_state === 'applied').length,
    recoverable_review_stages: semanticStages.filter(
      (stage) => stage.status === 'recoverable' || stage.review_state === 'recoverable'
    ).length,
    accepted_count: semanticStages.reduce((sum, stage) => sum + stage.accepted_count, 0),
    rejected_count: semanticStages.reduce((sum, stage) => sum + stage.rejected_count, 0),
    prepare_artifact_ids: semanticStages
      .map((stage) => stage.prepare_artifact_id)
      .filter((id): id is string => typeof id === 'string' && id.length > 0),
    apply_artifact_ids: semanticStages
      .map((stage) => stage.apply_artifact_id)
      .filter((id): id is string => typeof id === 'string' && id.length > 0),
    semantic_stages: semanticStages,
    reconstruct_consumed: usage.consumedArtifactIds.length > 0 || usage.sessionTags.length > 0,
    consumed_artifact_ids: usage.consumedArtifactIds,
    consumed_session_tags: usage.sessionTags,
    usage_notes: usage.notes,
  }
}

function summarizeSemanticStages(stages: DashboardRunStageRow[]): SemanticStageSummary[] {
  return stages
    .filter((stage) => isSemanticPipelineStage(stage.stage))
    .map((stage) => {
      const metadata = parseDashboardJson<Record<string, unknown>>(stage.metadata_json, {})
      return {
        stage: stage.stage,
        status: stage.status,
        review_state: asNonEmptyString(metadata.semantic_review_state),
        review_status: asNonEmptyString(metadata.review_status),
        session_tag: asNonEmptyString(metadata.session_tag),
        prepare_artifact_id: asNonEmptyString(metadata.prepare_artifact_id),
        apply_artifact_id: asNonEmptyString(metadata.apply_artifact_id),
        accepted_count: asFiniteNumber(metadata.accepted_count),
        rejected_count: asFiniteNumber(metadata.rejected_count),
        updated_at: stage.updated_at,
      }
    })
}

function isSemanticPipelineStage(stage: string): boolean {
  return (
    stage === 'semantic_name_review' ||
    stage === 'semantic_explain_review' ||
    stage === 'semantic_module_review'
  )
}

function asFiniteNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function collectSemanticUsageFromStages(stages: DashboardRunStageRow[]) {
  const consumedArtifactIds = new Set<string>()
  const sessionTags = new Set<string>()
  const notes = new Set<string>()

  for (const stage of stages) {
    const result = parseDashboardJson<unknown>(stage.result_json, null)
    collectSemanticUsage(result, consumedArtifactIds, sessionTags, notes)
  }

  return {
    consumedArtifactIds: Array.from(consumedArtifactIds),
    sessionTags: Array.from(sessionTags),
    notes: Array.from(notes),
  }
}

function collectSemanticUsage(
  payload: unknown,
  consumedArtifactIds: Set<string>,
  sessionTags: Set<string>,
  notes: Set<string>,
  seen = new Set<unknown>()
): void {
  if (!payload || typeof payload !== 'object' || seen.has(payload)) {
    return
  }
  seen.add(payload)

  if (Array.isArray(payload)) {
    for (const item of payload) {
      collectSemanticUsage(item, consumedArtifactIds, sessionTags, notes, seen)
    }
    return
  }

  const record = payload as Record<string, unknown>
  const semanticSessionTag = asNonEmptyString(record.semantic_session_tag)
  if (semanticSessionTag) {
    sessionTags.add(semanticSessionTag)
    notes.add(`semantic_session_tag=${semanticSessionTag}`)
  }
  const semanticScope = asNonEmptyString(record.semantic_scope)
  if (semanticScope) {
    notes.add(`semantic_scope=${semanticScope}`)
  }
  for (const key of [
    'semantic_name_marker',
    'semantic_explanation_marker',
    'semantic_module_review_marker',
  ]) {
    const marker = asNonEmptyString(record[key])
    if (marker && marker !== 'none') {
      notes.add(`${key}=present`)
    }
  }

  for (const key of ['semantic_names', 'semantic_explanations', 'semantic_module_reviews']) {
    const value = record[key]
    if (!isRecord(value)) {
      continue
    }
    const artifactIds = Array.isArray(value.artifact_ids) ? value.artifact_ids : []
    for (const id of artifactIds) {
      if (typeof id === 'string' && id.trim()) consumedArtifactIds.add(id.trim())
    }
    const tags = Array.isArray(value.session_tags) ? value.session_tags : []
    for (const tag of tags) {
      if (typeof tag === 'string' && tag.trim()) sessionTags.add(tag.trim())
    }
  }

  for (const value of Object.values(record)) {
    collectSemanticUsage(value, consumedArtifactIds, sessionTags, notes, seen)
  }
}

function parseDashboardJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value || !value.trim()) {
    return fallback
  }
  try {
    return JSON.parse(value) as T
  } catch {
    return fallback
  }
}

function toCountMap<T extends Record<string, unknown> & { cnt: number }>(
  rows: T[],
  keyName: keyof T
): Record<string, number> {
  return rows.reduce<Record<string, number>>((acc, row) => {
    const key = String(row[keyName] || 'unknown')
    const count = typeof row.cnt === 'number' ? row.cnt : 0
    acc[key] = count
    return acc
  }, {})
}

// ══════════════════════════════════════════════════════════════════════════
// Artifacts listing
// ══════════════════════════════════════════════════════════════════════════

function handleArtifacts(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '50', 10) || 50, 200)
  const offset = parseInt(params.get('offset') || '0', 10) || 0
  const sampleId = params.get('sample_id')
  const type = params.get('type')
  const search = getSearchTerm(params)

  try {
    let where = ''
    const sqlParams: unknown[] = []
    const clauses: string[] = []
    if (sampleId) {
      clauses.push('sample_id = ?')
      sqlParams.push(sampleId)
    }
    if (type) {
      clauses.push('type = ?')
      sqlParams.push(type)
    }
    appendTextSearchClause(
      clauses,
      sqlParams,
      ['id', 'sample_id', 'type', 'path', 'sha256', 'mime'],
      search
    )
    if (clauses.length) where = ' WHERE ' + clauses.join(' AND ')

    const countResult =
      _deps?.database?.querySql<{ cnt: number }>(
        `SELECT COUNT(*) as cnt FROM artifacts${where}`,
        sqlParams
      ) ?? []
    const total = countResult[0]?.cnt ?? 0

    const artifacts =
      _deps?.database?.querySql(
        `SELECT id, sample_id, type, path, sha256, mime, created_at FROM artifacts${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
        [...sqlParams, limit, offset]
      ) ?? []

    // Get distinct types for filter menu
    const types =
      _deps?.database?.querySql<{ type: string; cnt: number }>(
        'SELECT type, COUNT(*) as cnt FROM artifacts GROUP BY type ORDER BY cnt DESC'
      ) ?? []

    sendJson(res, 200, { total, offset, limit, artifacts, types })
  } catch {
    sendJson(res, 200, { total: 0, offset, limit, artifacts: [], types: [] })
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Semantic review artifact listing
// ══════════════════════════════════════════════════════════════════════════

async function handleSemantic(res: ServerResponse, params: URLSearchParams): Promise<void> {
  const limit = Math.min(parseInt(params.get('limit') || '50', 10) || 50, 200)
  const offset = parseInt(params.get('offset') || '0', 10) || 0
  const sampleId = params.get('sample_id')
  const type = params.get('type')
  const search = getSearchTerm(params)
  const placeholders = SEMANTIC_ARTIFACT_TYPES.map(() => '?').join(', ')
  const summaryLimit = 500

  try {
    let where = ''
    const sqlParams: unknown[] = [...SEMANTIC_ARTIFACT_TYPES]
    const clauses: string[] = [`type IN (${placeholders})`]

    if (sampleId) {
      clauses.push('sample_id = ?')
      sqlParams.push(sampleId)
    }
    if (type) {
      clauses.push('type = ?')
      sqlParams.push(type)
    }
    appendTextSearchClause(
      clauses,
      sqlParams,
      ['id', 'sample_id', 'type', 'path', 'sha256', 'mime'],
      search
    )
    if (clauses.length) where = ' WHERE ' + clauses.join(' AND ')

    const countResult =
      _deps?.database?.querySql<{ cnt: number }>(
        `SELECT COUNT(*) as cnt FROM artifacts${where}`,
        sqlParams
      ) ?? []
    const total = countResult[0]?.cnt ?? 0

    const rows =
      _deps?.database?.querySql<DashboardArtifactRow>(
        `SELECT id, sample_id, type, path, sha256, mime, created_at FROM artifacts${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
        [...sqlParams, limit, offset]
      ) ?? []

    const summaryRows =
      _deps?.database?.querySql<DashboardArtifactRow>(
        `SELECT id, sample_id, type, path, sha256, mime, created_at FROM artifacts${where} ORDER BY created_at DESC LIMIT ?`,
        [...sqlParams, summaryLimit]
      ) ?? []

    const typeRows =
      _deps?.database?.querySql<{ type: string; cnt: number }>(
        `SELECT type, COUNT(*) as cnt FROM artifacts${where} GROUP BY type ORDER BY cnt DESC`,
        sqlParams
      ) ?? []

    const runLinks = buildSemanticArtifactRunLinkMap()
    const summaryViews: Array<
      DashboardArtifactRow & {
        semantic: SemanticPayloadSummary
        run_link: SemanticArtifactRunLink | null
      }
    > = []
    for (const row of summaryRows) {
      summaryViews.push(await buildSemanticArtifactView(row, runLinks))
    }

    const summaryById = new Map(summaryViews.map((item) => [item.id, item]))
    const artifacts: Array<
      DashboardArtifactRow & {
        semantic: SemanticPayloadSummary
        run_link: SemanticArtifactRunLink | null
      }
    > = []
    for (const row of rows) {
      artifacts.push(summaryById.get(row.id) ?? (await buildSemanticArtifactView(row, runLinks)))
    }

    const byType = typeRows.reduce<Record<string, number>>((acc, row) => {
      acc[row.type] = row.cnt
      return acc
    }, {})
    const bySession: Record<string, number> = {}
    const byModel: Record<string, number> = {}
    const byClient: Record<string, number> = {}
    let entriesTotal = 0

    for (const item of summaryViews) {
      incrementCount(bySession, item.semantic.session_tag || 'untagged')
      if (item.semantic.model_name) incrementCount(byModel, item.semantic.model_name)
      if (item.semantic.client_name) incrementCount(byClient, item.semantic.client_name)
      entriesTotal += item.semantic.entry_count ?? 0
    }

    sendJson(res, 200, {
      total,
      offset,
      limit,
      summary_limit: summaryLimit,
      summary_sampled: summaryViews.length,
      counts: {
        by_type: byType,
        by_session: bySession,
        by_model: byModel,
        by_client: byClient,
        entries_sampled: entriesTotal,
      },
      types: typeRows,
      artifacts,
    })
  } catch {
    sendJson(res, 200, {
      total: 0,
      offset,
      limit,
      summary_limit: summaryLimit,
      summary_sampled: 0,
      counts: {
        by_type: {},
        by_session: {},
        by_model: {},
        by_client: {},
        entries_sampled: 0,
      },
      types: [],
      artifacts: [],
    })
  }
}

async function buildSemanticArtifactView(
  artifact: DashboardArtifactRow,
  runLinks: Map<string, SemanticArtifactRunLink> = new Map()
): Promise<
  DashboardArtifactRow & {
    semantic: SemanticPayloadSummary
    run_link: SemanticArtifactRunLink | null
  }
> {
  const { payload, error } = await readDashboardArtifactJson(artifact)
  return {
    ...artifact,
    semantic: {
      ...summarizeSemanticPayload(artifact, payload),
      read_error: error,
    },
    run_link: runLinks.get(artifact.id) ?? null,
  }
}

function buildSemanticArtifactRunLinkMap(): Map<string, SemanticArtifactRunLink> {
  const output = new Map<string, SemanticArtifactRunLink>()
  const stages =
    _deps?.database?.querySql<DashboardRunStageRow>(
      `SELECT * FROM analysis_run_stages WHERE stage IN (?, ?, ?)`,
      ['semantic_name_review', 'semantic_explain_review', 'semantic_module_review']
    ) ?? []

  for (const stage of stages) {
    const metadata = parseDashboardJson<Record<string, unknown>>(stage.metadata_json, {})
    const link: SemanticArtifactRunLink = {
      run_id: stage.run_id,
      stage: stage.stage,
      review_state: asNonEmptyString(metadata.semantic_review_state),
      review_status: asNonEmptyString(metadata.review_status),
      updated_at: stage.updated_at,
    }
    const ids = new Set<string>()
    for (const key of ['prepare_artifact_id', 'apply_artifact_id']) {
      const id = asNonEmptyString(metadata[key])
      if (id) ids.add(id)
    }
    for (const ref of parseDashboardJson<ArtifactRef[]>(stage.artifact_refs_json, [])) {
      if (ref?.id) ids.add(ref.id)
    }
    collectArtifactIdsFromPayload(parseDashboardJson<unknown>(stage.result_json, null), ids)
    for (const id of ids) {
      output.set(id, link)
    }
  }

  return output
}

function collectArtifactIdsFromPayload(
  payload: unknown,
  output: Set<string>,
  seen = new Set<unknown>()
): void {
  if (!payload || typeof payload !== 'object' || seen.has(payload)) {
    return
  }
  seen.add(payload)

  if (Array.isArray(payload)) {
    for (const item of payload) collectArtifactIdsFromPayload(item, output, seen)
    return
  }

  const record = payload as Record<string, unknown>
  if (typeof record.artifact_id === 'string' && record.artifact_id.trim()) {
    output.add(record.artifact_id.trim())
  }
  if (typeof record.prepare_artifact_id === 'string' && record.prepare_artifact_id.trim()) {
    output.add(record.prepare_artifact_id.trim())
  }
  if (Array.isArray(record.artifact_ids)) {
    for (const id of record.artifact_ids) {
      if (typeof id === 'string' && id.trim()) output.add(id.trim())
    }
  }
  for (const value of Object.values(record)) {
    collectArtifactIdsFromPayload(value, output, seen)
  }
}

async function readDashboardArtifactJson(
  artifact: DashboardArtifactRow
): Promise<{ payload: unknown | null; error: string | null }> {
  if (!_deps?.workspaceManager) {
    return { payload: null, error: 'workspace_unavailable' }
  }

  try {
    const workspace = await _deps.workspaceManager.getWorkspace(artifact.sample_id)
    const absPath = _deps.workspaceManager.normalizePath(workspace.root, artifact.path)
    const workspaceRoot = path.resolve(_deps.workspaceManager.getWorkspaceRoot())
    const resolvedPath = path.resolve(absPath)

    if (!isPathWithin(workspaceRoot, resolvedPath)) {
      return { payload: null, error: 'path_outside_workspace' }
    }

    const stat = await fs.stat(resolvedPath)
    if (stat.size > MAX_DASHBOARD_JSON_SUMMARY_BYTES) {
      return { payload: null, error: 'payload_too_large' }
    }

    return { payload: JSON.parse(await fs.readFile(resolvedPath, 'utf-8')), error: null }
  } catch (err) {
    return { payload: null, error: err instanceof Error ? err.message : String(err) }
  }
}

function summarizeSemanticPayload(
  artifact: DashboardArtifactRow,
  payload: unknown
): Omit<SemanticPayloadSummary, 'read_error'> {
  const record = isRecord(payload) ? payload : {}
  const semanticType = isSemanticArtifactType(artifact.type) ? artifact.type : null
  const payloadKind = semanticType ? SEMANTIC_ARTIFACT_KIND[semanticType] : null

  return {
    payload_kind: payloadKind,
    entry_count: inferSemanticEntryCount(record),
    session_tag: asNonEmptyString(record.session_tag) ?? deriveSemanticSessionTag(artifact.path),
    client_name:
      asNonEmptyString(record.client_name) ?? getNestedString(record, ['client', 'name']),
    model_name:
      asNonEmptyString(record.model_name) ??
      asNonEmptyString(record.model) ??
      getNestedString(record, ['sampling', 'model']),
    prepare_artifact_id:
      asNonEmptyString(record.prepare_artifact_id) ??
      getNestedString(record, ['prepare', 'artifact_id']),
    prompt_name:
      asNonEmptyString(record.prompt_name) ?? getNestedString(record, ['prompt', 'name']),
    payload_created_at:
      asNonEmptyString(record.created_at) ?? asNonEmptyString(record.generated_at),
    schema_version:
      typeof record.schema_version === 'number' || typeof record.schema_version === 'string'
        ? record.schema_version
        : null,
  }
}

function inferSemanticEntryCount(record: Record<string, unknown>): number | null {
  for (const key of ['suggestions', 'explanations', 'reviews', 'functions', 'modules', 'items']) {
    const value = record[key]
    if (Array.isArray(value)) {
      return value.length
    }
  }
  return null
}

function deriveSemanticSessionTag(artifactPath: string): string | null {
  const parts = artifactPath.replace(/\\/g, '/').split('/').filter(Boolean)
  const semanticDirIndex = parts.findIndex((part) => part === 'semantic_naming')
  if (semanticDirIndex >= 0 && parts[semanticDirIndex + 1]) {
    return parts[semanticDirIndex + 1]
  }
  return null
}

function isSemanticArtifactType(type: string): type is SemanticArtifactType {
  return (SEMANTIC_ARTIFACT_TYPES as readonly string[]).includes(type)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asNonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null
}

function getNestedString(record: Record<string, unknown>, pathParts: string[]): string | null {
  let current: unknown = record
  for (const part of pathParts) {
    if (!isRecord(current)) {
      return null
    }
    current = current[part]
  }
  return asNonEmptyString(current)
}

function incrementCount(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1
}

function isPathWithin(parentPath: string, childPath: string): boolean {
  const relativePath = path.relative(parentPath, childPath)
  return relativePath === '' || (!relativePath.startsWith('..') && !path.isAbsolute(relativePath))
}

// ══════════════════════════════════════════════════════════════════════════
// Artifact content (for report viewer)
// ══════════════════════════════════════════════════════════════════════════

async function handleArtifactContent(res: ServerResponse, artifactId: string): Promise<void> {
  try {
    const artifact = _deps?.database?.findArtifact(artifactId)
    if (!artifact) {
      sendJson(res, 404, { error: 'Artifact not found' })
      return
    }

    if (!_deps?.workspaceManager) {
      sendJson(res, 500, { error: 'Workspace manager not available' })
      return
    }

    const workspace = await (
      _deps as { workspaceManager: WorkspaceManager }
    ).workspaceManager.getWorkspace(artifact.sample_id)
    const absPath = _deps.workspaceManager.normalizePath(workspace.root, artifact.path)

    // Security: verify path is inside workspace
    const workspaceRoot = _deps.workspaceManager.getWorkspaceRoot()
    const resolvedPath = path.resolve(absPath)
    if (!resolvedPath.startsWith(path.resolve(workspaceRoot))) {
      sendJson(res, 403, { error: 'Path outside workspace' })
      return
    }

    const stat = await fs.stat(resolvedPath)
    const MAX_RENDER_SIZE = 2 * 1024 * 1024 // 2MB

    if (stat.size > MAX_RENDER_SIZE) {
      sendJson(res, 200, {
        artifact_id: artifact.id,
        type: artifact.type,
        path: artifact.path,
        mime: artifact.mime,
        size: stat.size,
        truncated: true,
        content: null,
        error: `File too large for inline rendering (${(stat.size / 1024 / 1024).toFixed(1)} MB)`,
      })
      return
    }

    const raw = await fs.readFile(resolvedPath)

    // Detect if text or binary
    const isText = isTextContent(raw, artifact.path, artifact.mime)

    if (isText) {
      const content = raw.toString('utf-8')
      let parsed: unknown = null
      const ext = path.extname(artifact.path).toLowerCase()

      if (ext === '.json' || artifact.mime === 'application/json') {
        try {
          parsed = JSON.parse(content)
        } catch {
          /* not valid JSON */
        }
      }

      sendJson(res, 200, {
        artifact_id: artifact.id,
        type: artifact.type,
        path: artifact.path,
        mime: artifact.mime,
        size: stat.size,
        truncated: false,
        encoding: 'utf8',
        content,
        parsed_json: parsed,
        format: detectFormat(artifact.path, artifact.mime, content),
      })
    } else {
      sendJson(res, 200, {
        artifact_id: artifact.id,
        type: artifact.type,
        path: artifact.path,
        mime: artifact.mime,
        size: stat.size,
        truncated: false,
        encoding: 'base64',
        content: raw.toString('base64'),
        format: 'binary',
      })
    }
  } catch (err) {
    logger.warn({ err, artifactId }, 'Dashboard: failed to read artifact content')
    sendJson(res, 404, { error: 'Artifact file not found on disk' })
  }
}

function isTextContent(buf: Buffer, filePath: string, mime: string | null): boolean {
  const textExtensions = new Set([
    '.txt',
    '.md',
    '.json',
    '.xml',
    '.html',
    '.htm',
    '.csv',
    '.log',
    '.yaml',
    '.yml',
    '.toml',
    '.ini',
    '.cfg',
    '.conf',
    '.c',
    '.h',
    '.cpp',
    '.py',
    '.js',
    '.ts',
    '.java',
    '.rs',
    '.dot',
    '.svg',
    '.yar',
    '.yara',
    '.rule',
    '.sig',
  ])
  const ext = path.extname(filePath).toLowerCase()
  if (textExtensions.has(ext)) return true
  if (mime?.startsWith('text/')) return true
  if (mime === 'application/json' || mime === 'application/xml') return true

  // Heuristic: check first 1KB for null bytes
  const sample = buf.subarray(0, Math.min(buf.length, 1024))
  for (let i = 0; i < sample.length; i++) {
    if (sample[i] === 0) return false
  }
  return true
}

function detectFormat(filePath: string, mime: string | null, content: string): string {
  const ext = path.extname(filePath).toLowerCase()
  if (ext === '.md' || ext === '.markdown') return 'markdown'
  if (ext === '.json' || mime === 'application/json') return 'json'
  if (ext === '.html' || ext === '.htm' || mime === 'text/html') return 'html'
  if (ext === '.xml' || mime === 'application/xml') return 'xml'
  if (ext === '.svg') return 'svg'
  if (ext === '.dot') return 'dot'
  if (ext === '.csv') return 'csv'
  if (ext === '.yaml' || ext === '.yml') return 'yaml'
  if (['.c', '.h', '.cpp', '.py', '.js', '.ts', '.java', '.rs'].includes(ext)) return 'code'
  return 'text'
}

// ══════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════

function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  const parts: string[] = []
  if (d > 0) parts.push(`${d}d`)
  if (h > 0) parts.push(`${h}h`)
  if (m > 0) parts.push(`${m}m`)
  parts.push(`${sec}s`)
  return parts.join(' ')
}
