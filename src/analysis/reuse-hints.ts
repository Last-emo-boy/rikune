import type { DatabaseManager, Sample } from '../database.js'
import type { JobQueue } from '../job-queue.js'

type JobQueueWithStatuses = Pick<JobQueue, 'listStatuses'> & {
  listStatuses?: (status?: string) => unknown[]
}

export interface BuildSampleReuseHintsInput {
  database: DatabaseManager
  jobQueue?: JobQueueWithStatuses | null
  sampleId: string
  sampleSha256?: string | null
  intendedTool?: string | null
  functionAddress?: string | null
  functionName?: string | null
  limit?: number
}

export interface SampleReuseHints {
  sample_id: string
  intended_tool?: string
  function_query?: {
    address?: string
    name?: string
    matches: Array<{
      address: string
      name: string | null
      size: number | null
      score: number | null
      summary?: string | null
    }>
  }
  active_jobs: Array<Record<string, unknown>>
  recent_jobs: Array<Record<string, unknown>>
  analysis_runs: Array<Record<string, unknown>>
  recent_analyses: Array<Record<string, unknown>>
  cache: {
    sample_sha256: string | null
    entry_count: number
    recent_entries: Array<Record<string, unknown>>
  }
  recommended_next_tools: string[]
  next_actions: string[]
  summary: string
}

const ACTIVE_JOB_STATUSES = new Set(['queued', 'running'])
const TERMINAL_JOB_STATUSES = new Set(['completed', 'failed', 'cancelled', 'interrupted'])

function parseJson(value: unknown): unknown {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return undefined
  }
  try {
    return JSON.parse(value)
  } catch {
    return undefined
  }
}

function normalizeJob(row: Record<string, unknown>): Record<string, unknown> {
  const args = parseJson(row.args_json) || row.args
  const result = parseJson(row.result_json) || row.result
  return {
    id: row.id,
    tool: row.tool,
    sample_id: row.sample_id || row.sampleId,
    status: row.status,
    progress: row.progress,
    created_at: row.created_at || row.createdAt,
    started_at: row.started_at || row.startedAt,
    finished_at: row.finished_at || row.finishedAt,
    updated_at: row.updated_at || row.updatedAt,
    error: row.error,
    args,
    has_result: Boolean(result),
  }
}

function uniqueById(rows: Array<Record<string, unknown>>): Array<Record<string, unknown>> {
  const out = new Map<string, Record<string, unknown>>()
  for (const row of rows) {
    const id = typeof row.id === 'string' ? row.id : null
    if (!id || out.has(id)) {
      continue
    }
    out.set(id, row)
  }
  return Array.from(out.values())
}

function compactAnalysisRun(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id,
    goal: row.goal,
    depth: row.depth,
    backend_policy: row.backend_policy,
    status: row.status,
    latest_stage: row.latest_stage,
    updated_at: row.updated_at,
    finished_at: row.finished_at,
    reused_from_run_id: row.reused_from_run_id,
  }
}

function compactAnalysis(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id,
    stage: row.stage,
    backend: row.backend,
    status: row.status,
    started_at: row.started_at,
    finished_at: row.finished_at,
  }
}

function buildFunctionMatches(
  database: DatabaseManager,
  sampleId: string,
  address?: string | null,
  name?: string | null,
  limit = 10
): SampleReuseHints['function_query'] | undefined {
  if (!address && !name) {
    return undefined
  }

  const finder = database as DatabaseManager & {
    findFunctions?: (sampleId: string) => Array<Record<string, unknown>>
  }
  const functions = typeof finder.findFunctions === 'function' ? finder.findFunctions(sampleId) : []
  const nameNeedle = name?.toLowerCase().trim() || null
  const addressNeedle = address?.toLowerCase().trim() || null

  const matches = functions
    .filter((fn) => {
      const fnAddress = String(fn.address || '').toLowerCase()
      const fnName = String(fn.name || '').toLowerCase()
      return (
        (addressNeedle && fnAddress === addressNeedle) ||
        (nameNeedle && fnName.includes(nameNeedle))
      )
    })
    .slice(0, limit)
    .map((fn) => ({
      address: String(fn.address || ''),
      name: typeof fn.name === 'string' ? fn.name : null,
      size: typeof fn.size === 'number' ? fn.size : null,
      score: typeof fn.score === 'number' ? fn.score : null,
      summary: typeof fn.summary === 'string' ? fn.summary : null,
    }))

  return {
    ...(address ? { address } : {}),
    ...(name ? { name } : {}),
    matches,
  }
}

function addUnique(target: string[], values: string[]): void {
  for (const value of values) {
    if (!target.includes(value)) {
      target.push(value)
    }
  }
}

export async function buildSampleReuseHints(
  input: BuildSampleReuseHintsInput
): Promise<SampleReuseHints> {
  const limit = Math.max(1, Math.min(input.limit ?? 10, 50))
  const sample =
    input.sampleSha256 !== undefined ? null : (input.database.findSample?.(input.sampleId) ?? null)
  const sampleSha256 = input.sampleSha256 ?? sample?.sha256 ?? null

  const persistedJobs =
    typeof input.database.findJobsBySample === 'function'
      ? input.database.findJobsBySample(input.sampleId, Math.max(limit * 2, 20))
      : []
  const liveJobs =
    typeof input.jobQueue?.listStatuses === 'function'
      ? input.jobQueue
          .listStatuses()
          .filter(
            (row: any) => row?.sampleId === input.sampleId || row?.sample_id === input.sampleId
          )
      : []
  const jobs = uniqueById([...liveJobs, ...persistedJobs].map((row: any) => normalizeJob(row)))
  const intendedTool = input.intendedTool || undefined
  const relevantJobs = intendedTool ? jobs.filter((job) => job.tool === intendedTool) : jobs
  const activeJobs = relevantJobs
    .filter((job) => ACTIVE_JOB_STATUSES.has(String(job.status)))
    .slice(0, limit)
  const recentJobs = relevantJobs
    .filter((job) => TERMINAL_JOB_STATUSES.has(String(job.status)))
    .slice(0, limit)

  const analysisRuns =
    typeof input.database.findAnalysisRunsBySample === 'function'
      ? input.database
          .findAnalysisRunsBySample(input.sampleId)
          .slice(0, limit)
          .map((run: any) => compactAnalysisRun(run))
      : []
  const recentAnalyses =
    typeof input.database.findAnalysesBySample === 'function'
      ? input.database
          .findAnalysesBySample(input.sampleId)
          .slice(0, limit)
          .map((analysis: any) => compactAnalysis(analysis))
      : []

  const cacheEntries =
    sampleSha256 && typeof input.database.getCacheEntriesBySample === 'function'
      ? await input.database.getCacheEntriesBySample(sampleSha256)
      : []
  const functionQuery = buildFunctionMatches(
    input.database,
    input.sampleId,
    input.functionAddress,
    input.functionName,
    limit
  )

  const recommendedNextTools: string[] = []
  const nextActions: string[] = []
  if (activeJobs.length > 0) {
    addUnique(recommendedNextTools, ['task.status'])
    nextActions.push(
      'A compatible job is already queued or running; poll task.status instead of starting the same heavy analysis again.'
    )
  }
  if (recentJobs.some((job) => job.status === 'completed')) {
    addUnique(recommendedNextTools, ['task.status'])
    nextActions.push(
      'A completed job exists for this sample/tool; inspect task.status with include_result=true before rerunning.'
    )
  }
  if (analysisRuns.length > 0) {
    addUnique(recommendedNextTools, ['workflow.analyze.status'])
    nextActions.push(
      'A staged analysis run already exists; inspect workflow.analyze.status before promoting or restarting stages.'
    )
  }
  if (cacheEntries.length > 0) {
    nextActions.push(
      'Cached evidence exists for this sample; prefer reuse_cached=true unless the source evidence changed.'
    )
  }
  if (functionQuery && functionQuery.matches.length > 0) {
    addUnique(recommendedNextTools, ['analysis.context.link', 'code.function.decompile'])
    nextActions.push(
      'Function index entries match the query; reuse function-level context before requesting a full reconstruction.'
    )
  }
  if (intendedTool) {
    addUnique(recommendedNextTools, [intendedTool])
  }
  if (recommendedNextTools.length === 0) {
    addUnique(recommendedNextTools, ['workflow.analyze.start'])
    nextActions.push('No prior compatible work was found; starting a new analysis is reasonable.')
  }

  const summaryParts = [
    activeJobs.length > 0 ? `${activeJobs.length} active job(s)` : null,
    recentJobs.length > 0 ? `${recentJobs.length} recent terminal job(s)` : null,
    analysisRuns.length > 0 ? `${analysisRuns.length} staged run(s)` : null,
    cacheEntries.length > 0
      ? `${cacheEntries.length} cache entr${cacheEntries.length === 1 ? 'y' : 'ies'}`
      : null,
  ].filter((item): item is string => Boolean(item))

  return {
    sample_id: input.sampleId,
    ...(intendedTool ? { intended_tool: intendedTool } : {}),
    ...(functionQuery ? { function_query: functionQuery } : {}),
    active_jobs: activeJobs,
    recent_jobs: recentJobs,
    analysis_runs: analysisRuns,
    recent_analyses: recentAnalyses,
    cache: {
      sample_sha256: sampleSha256,
      entry_count: cacheEntries.length,
      recent_entries: cacheEntries.slice(0, limit).map((entry) => ({
        key: entry.key,
        expires_at: entry.expires_at,
      })),
    },
    recommended_next_tools: recommendedNextTools.slice(0, 8),
    next_actions: nextActions.slice(0, 6),
    summary:
      summaryParts.length > 0
        ? `Found ${summaryParts.join(', ')} for this sample.`
        : 'No prior queued, completed, staged, or cached analysis was found for this sample.',
  }
}
