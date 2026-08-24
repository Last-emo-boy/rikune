/**
 * Job Queue - Priority queue with DB persistence
 *
 * Implements requirements 21.1 and 21.2:
 * - Task enqueueing with unique job_id
 * - Priority-based task ordering
 * - Job status tracking and cancellation
 * - DB-backed persistence — survives process restarts
 */

import { randomUUID } from 'crypto'
import { EventEmitter } from 'events'
import type { DatabaseManager } from '../database.js'
import type { Job, JobStatus, JobStatusType, JobResult, RetryPolicy } from '../types.js'
import { logger } from '../logger.js'
import type {
  SampleOperationGate,
  SharedSampleOperationLease,
} from '../sample/sample-operation-gate.js'
import { SampleOperationLeaseLostError } from '../sample/sample-operation-gate.js'
import {
  assertStaticAnalysisRunContract,
  assertStaticQueuedJob,
  isStaticDockerProfile,
} from '../core/static-profile-lock.js'
import type { AnalysisPipelineStage } from '../analysis/analysis-run-state.js'

// Re-export types for convenience
export { JobPriority } from '../types.js'
export type {
  Job,
  JobStatus,
  JobStatusType,
  JobResult,
  JobMetrics,
  RetryPolicy,
  ArtifactRef,
} from '../types.js'

/**
 * Estimated duration for common tools (in milliseconds)
 * Used for async job pattern to provide honest time estimates
 * Tasks: mcp-async-job-pattern 1.2
 */
export const TOOL_DURATION_ESTIMATES: Record<string, number> = {
  // Ghidra tools (5-30 minutes)
  'ghidra.analyze': 30 * 60 * 1000,

  // Workflows (10-60 minutes)
  'workflow.reconstruct': 40 * 60 * 1000,
  'workflow.triage': 10 * 60 * 1000,
  'workflow.deep_static': 25 * 60 * 1000,
  'workflow.summarize': 15 * 60 * 1000,

  // String tools (2-10 minutes)
  'strings.floss.decode': 5 * 60 * 1000,

  // Threat intelligence enrichment (5-15 minutes)
  'attack.map': 10 * 60 * 1000,

  // Default estimate (5 minutes)
  default: 5 * 60 * 1000,
} as const

/**
 * Internal job entry with status tracking
 */
interface JobEntry {
  job: Job
  status: JobStatusType
  progress?: number
  progressStage?: string
  startedAt?: string
  finishedAt?: string
  error?: string
  cancelReason?: string
  result?: JobResult
}

export interface JobQueueOptions {
  /** Test/embedded override; production defaults remain at least 60 seconds. */
  jobClaimTtlMs?: number
  heartbeatIntervalMs?: number
  restorePageSize?: number
}

export type JobSettlementOutcome =
  | {
      committed: true
      status: 'completed' | 'failed' | 'interrupted' | 'retry_wait'
    }
  | {
      committed: false
      reason: 'missing' | 'claim_lost' | 'already_cancelled'
      status?: JobStatusType
    }

const ACTIVE_JOB_STATUSES = ['queued', 'retry_wait', 'running', 'cancelling'] as const
const TERMINAL_JOB_STATUSES = ['completed', 'failed', 'cancelled', 'interrupted'] as const

/**
 * In-memory job queue with priority support
 *
 * Features:
 * - Priority-based ordering
 * - Job status tracking
 * - Cancellation support
 * - Event-based completion notifications
 */
export class JobQueue extends EventEmitter {
  private jobs: Map<string, JobEntry> = new Map()
  private queue: Job[] = []
  private operationLeases: Map<string, SharedSampleOperationLease> = new Map()
  private retryTimers = new Map<string, { timer: NodeJS.Timeout; attempt: number }>()
  private claimTokens = new Map<string, string>()
  private claimLostJobs = new Set<string>()
  private operationHeartbeatTimer: NodeJS.Timeout | null = null
  private closed = false
  private readonly ownerInstanceId: string
  private readonly ownerBootId: string
  private readonly jobClaimTtlMs: number
  private readonly restorePageSize: number
  private readonly defaultRetryPolicy: RetryPolicy = {
    maxRetries: 3,
    backoffMs: 1000,
    retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED', 'E_WORKER_UNAVAILABLE'],
  }

  constructor(
    private readonly database?: DatabaseManager,
    private readonly sampleOperationGate?: SampleOperationGate,
    options: JobQueueOptions = {}
  ) {
    super()
    this.ownerInstanceId = sampleOperationGate?.instanceId ?? randomUUID()
    this.ownerBootId = sampleOperationGate?.bootId ?? randomUUID()
    this.jobClaimTtlMs =
      options.jobClaimTtlMs ?? Math.max(60_000, sampleOperationGate?.instanceTtlMs ?? 60_000)
    this.restorePageSize = options.restorePageSize ?? 500
    if (!Number.isInteger(this.jobClaimTtlMs) || this.jobClaimTtlMs < 100) {
      throw new Error('Job claim TTL must be at least 100ms.')
    }
    if (!Number.isInteger(this.restorePageSize) || this.restorePageSize < 1) {
      throw new Error('Job restore page size must be positive.')
    }
    if (sampleOperationGate || database) {
      const intervalMs =
        options.heartbeatIntervalMs ??
        (sampleOperationGate
          ? Math.max(100, Math.floor(sampleOperationGate.sharedLeaseTtlMs / 3))
          : Math.floor(this.jobClaimTtlMs / 3))
      if (!Number.isInteger(intervalMs) || intervalMs < 10) {
        throw new Error('Job claim heartbeat interval must be at least 10ms.')
      }
      this.operationHeartbeatTimer = setInterval(() => {
        for (const [jobId, lease] of this.operationLeases) {
          try {
            lease.heartbeat()
          } catch (error) {
            logger.error({ job_id: jobId, error }, 'Job lost its sample operation lease')
            this.handleSampleLeaseLoss(jobId, error)
          }
        }
        if (this.database) {
          const now = new Date()
          const nowIso = now.toISOString()
          const claimUntil = new Date(now.getTime() + this.jobClaimTtlMs).toISOString()
          for (const [jobId, claimToken] of this.claimTokens) {
            let heartbeat: { owned: boolean; status?: string }
            try {
              heartbeat = this.database.heartbeatJobClaim({
                jobId,
                ownerInstanceId: this.ownerInstanceId,
                ownerBootId: this.ownerBootId,
                claimToken,
                claimUntil,
                now: nowIso,
              })
            } catch (error) {
              logger.warn({ job_id: jobId, error }, 'Durable job claim heartbeat failed; retrying')
              continue
            }
            if (!heartbeat.owned) {
              const entry = this.jobs.get(jobId)
              this.claimTokens.delete(jobId)
              this.claimLostJobs.add(jobId)
              if (entry && (entry.status === 'running' || entry.status === 'cancelling')) {
                entry.status = 'cancelling'
                entry.error = 'E_JOB_CLAIM_LOST: durable execution claim was lost'
              } else {
                this.cleanupLostClaim(jobId)
              }
              this.emit('job:reaped', [jobId], 0)
              continue
            }
            if (heartbeat.status === 'cancelling') {
              const entry = this.jobs.get(jobId)
              if (entry && entry.status !== 'cancelling') {
                entry.status = 'cancelling'
                entry.error = 'E_CANCELLED: cancellation requested by another server instance'
                this.emit('job:reaped', [jobId], 0)
              }
            }
          }
          try {
            this.reconcileExpiredClaims()
          } catch (error) {
            logger.warn({ error }, 'Durable expired-claim reconciliation failed; retrying')
          }
        }
      }, intervalMs)
      this.operationHeartbeatTimer.unref()
    }
  }

  private assertStaticJobContract(
    tool: string,
    args: Record<string, unknown>,
    sampleId: string
  ): void {
    assertStaticQueuedJob(tool, args)
    if (!this.database) {
      throw new Error('E_STATIC_PROFILE_CONTRACT: static queued work requires a database')
    }
    if (typeof args.run_id !== 'string' || typeof args.stage !== 'string') {
      throw new Error('E_STATIC_PROFILE_CONTRACT: static queued work is missing run_id or stage')
    }
    const run = this.database.findAnalysisRun(args.run_id)
    assertStaticAnalysisRunContract({
      run,
      stage: args.stage as AnalysisPipelineStage,
      jobSampleId: sampleId,
      getStageStatus: (stage) =>
        this.database?.findAnalysisRunStage(args.run_id as string, stage)?.status,
    })
  }

  private acquireJobLease(jobId: string, sampleId: string): void {
    if (!this.sampleOperationGate || this.operationLeases.has(jobId)) return
    this.operationLeases.set(jobId, this.sampleOperationGate.acquireShared([sampleId]))
  }

  private assertJobLease(jobId: string): void {
    if (!this.sampleOperationGate) return
    const lease = this.operationLeases.get(jobId)
    if (!lease) {
      throw new SampleOperationLeaseLostError(
        `E_SAMPLE_LEASE_LOST: job ${jobId} has no queue-owned sample lease`
      )
    }
    lease.assertOwned()
  }

  private releaseJobLease(jobId: string): void {
    const lease = this.operationLeases.get(jobId)
    if (!lease) return
    this.operationLeases.delete(jobId)
    lease.release()
  }

  private clearRetryTimer(jobId: string): void {
    const retry = this.retryTimers.get(jobId)
    if (retry) clearTimeout(retry.timer)
    this.retryTimers.delete(jobId)
  }

  /** Local cleanup after durable ownership has moved elsewhere. Never writes DB state. */
  private cleanupLostClaim(jobId: string): void {
    this.clearRetryTimer(jobId)
    this.claimTokens.delete(jobId)
    this.claimLostJobs.delete(jobId)
    this.queue = this.queue.filter((job) => job.id !== jobId)
    const entry = this.jobs.get(jobId)
    const persisted = this.database?.findJob(jobId)
    if (entry) {
      const persistedStatus = persisted?.status as JobStatusType | undefined
      entry.status = persistedStatus ?? 'interrupted'
      entry.error = persisted?.error ?? 'E_JOB_CLAIM_LOST: durable execution claim was lost'
      entry.finishedAt = persisted?.finished_at ?? entry.finishedAt
    }
    this.releaseJobLease(jobId)
    this.emit('job:claim-lost', jobId)
  }

  private handleSampleLeaseLoss(jobId: string, error: unknown): void {
    const entry = this.jobs.get(jobId)
    if (!entry) {
      this.releaseJobLease(jobId)
      return
    }
    const reason = `E_SAMPLE_LEASE_LOST: ${error instanceof Error ? error.message : String(error)}`
    if (entry.status === 'queued' || entry.status === 'retry_wait') {
      try {
        const persisted = this.database?.requestJobCancellation(jobId, reason)
        if (this.database && persisted !== 'cancelled') return
      } catch (persistenceError) {
        logger.warn(
          { job_id: jobId, error: persistenceError },
          'Failed to cancel lease-lost queued job'
        )
        return
      }
      this.clearRetryTimer(jobId)
      this.claimTokens.delete(jobId)
      this.queue = this.queue.filter((job) => job.id !== jobId)
      entry.status = 'cancelled'
      entry.error = reason
      entry.finishedAt = new Date().toISOString()
      this.releaseJobLease(jobId)
      this.emit('job:cancelled', jobId, reason)
      return
    }
    if (entry.status !== 'running') return
    try {
      this.updateOwnedJobStatus(jobId, {
        expectedStatuses: ['running'],
        status: 'cancelling',
        progress: entry.progress,
        error: reason,
      })
    } catch (persistenceError) {
      if (!(persistenceError instanceof SampleOperationLeaseLostError)) {
        logger.warn({ job_id: jobId, error: persistenceError }, 'Failed to fence lease-lost worker')
        return
      }
      this.claimTokens.delete(jobId)
      this.claimLostJobs.add(jobId)
    }
    entry.status = 'cancelling'
    entry.error = reason
    this.emit('job:reaped', [jobId], 0)
  }

  private parsePersistedJobResult(row: any, status: JobStatusType): JobResult | undefined {
    if (!row.result_json) return undefined
    try {
      const parsed = JSON.parse(row.result_json) as unknown
      if (
        parsed !== null &&
        typeof parsed === 'object' &&
        (parsed as { jobId?: unknown }).jobId === row.id &&
        typeof (parsed as { ok?: unknown }).ok === 'boolean' &&
        Array.isArray((parsed as { errors?: unknown }).errors) &&
        Array.isArray((parsed as { warnings?: unknown }).warnings) &&
        Array.isArray((parsed as { artifacts?: unknown }).artifacts) &&
        (parsed as { metrics?: unknown }).metrics !== null &&
        typeof (parsed as { metrics?: unknown }).metrics === 'object'
      ) {
        return parsed as JobResult
      }

      // Legacy rows stored only the tool payload. Preserve their historical
      // status shape without double-wrapping newly persisted JobResult values.
      return {
        jobId: row.id,
        ok: status === 'completed',
        data: parsed,
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 0, peakRssMb: 0 },
      }
    } catch {
      return undefined
    }
  }

  private materializePersistedJob(row: any): boolean {
    let args: Record<string, unknown>
    try {
      args = typeof row.args_json === 'string' ? JSON.parse(row.args_json) : (row.args ?? {})
    } catch {
      return false
    }
    let retryPolicy = this.defaultRetryPolicy
    try {
      const parsed = row.retry_policy_json ? JSON.parse(row.retry_policy_json) : null
      if (
        parsed &&
        Number.isSafeInteger(parsed.maxRetries) &&
        parsed.maxRetries >= 0 &&
        Number.isSafeInteger(parsed.backoffMs) &&
        parsed.backoffMs >= 0 &&
        Array.isArray(parsed.retryableErrors) &&
        parsed.retryableErrors.every((value: unknown) => typeof value === 'string')
      ) {
        retryPolicy = parsed as RetryPolicy
      }
    } catch {
      // Legacy rows use the bounded default.
    }
    const status = row.status as JobStatusType
    const job: Job = {
      id: row.id,
      type: row.type,
      tool: row.tool,
      sampleId: row.sample_id,
      args,
      priority: row.priority,
      timeout: row.timeout,
      createdAt: row.created_at,
      estimatedDurationMs: row.estimated_duration_ms ?? undefined,
      attempts: Number.isSafeInteger(row.retry_count) && row.retry_count >= 0 ? row.retry_count : 0,
      retryPolicy,
    }
    const result = this.parsePersistedJobResult(row, status)
    this.jobs.set(row.id, {
      job,
      status,
      progress: row.progress ?? undefined,
      startedAt: row.started_at ?? undefined,
      finishedAt: row.finished_at ?? undefined,
      error: row.error ?? undefined,
      result,
    })
    this.queue = this.queue.filter((queued) => queued.id !== row.id)
    if (status === 'queued') this.queue.push(job)
    return true
  }

  /**
   * A rolling observer never owns a foreign execution claim, so its in-memory
   * view is only a cache. Refresh it synchronously before exposing status or
   * result data; this also notices a foreign retry becoming queued again.
   */
  private refreshForeignJob(jobId: string): JobEntry | undefined {
    const current = this.jobs.get(jobId)
    if (!this.database || this.claimTokens.has(jobId)) return current
    const persisted = this.database.findJob(jobId)
    if (!persisted) return current
    if (this.materializePersistedJob(persisted)) return this.jobs.get(jobId)

    // Invalid persisted args must never be executable, but a rolling observer
    // can still expose the authoritative durable status without mutating it.
    if (current && persisted.status) {
      current.status = persisted.status as JobStatusType
      current.progress = persisted.progress ?? undefined
      current.startedAt = persisted.started_at ?? undefined
      current.finishedAt = persisted.finished_at ?? undefined
      current.error = persisted.error ?? undefined
      current.result = this.parsePersistedJobResult(persisted, current.status)
      if (current.status !== 'queued') {
        this.queue = this.queue.filter((job) => job.id !== jobId)
      }
    }
    return current
  }

  /** Adopt a remote cancellation without mistaking our still-live claim for loss. */
  private adoptOwnedCancellation(jobId: string, entry: JobEntry): boolean {
    if (!this.database) return false
    const claimToken = this.claimTokens.get(jobId)
    if (!claimToken) return false
    const persisted = this.database.findJob(jobId)
    if (
      persisted?.status !== 'cancelling' ||
      persisted.owner_instance_id !== this.ownerInstanceId ||
      persisted.owner_boot_id !== this.ownerBootId ||
      persisted.claim_token !== claimToken
    ) {
      return false
    }
    entry.status = 'cancelling'
    entry.error =
      persisted.error ?? 'E_CANCELLED: cancellation requested by another server instance'
    return true
  }

  /** Reconcile claims that expired after this process completed bootstrap. */
  reconcileExpiredClaims(now: string = new Date().toISOString()): {
    queued: number
    interrupted: number
  } {
    if (!this.database) return { queued: 0, interrupted: 0 }
    let queued = 0
    let interrupted = 0
    for (;;) {
      const rows = this.database.findExpiredClaimedJobs(now, this.restorePageSize)
      if (rows.length === 0) break
      let changed = 0
      for (const row of rows) {
        const reason = 'E_TIMEOUT: durable job execution claim expired during reconciliation'
        const recovered = this.database.recoverExpiredJobClaim(row.id, now, reason)
        if (!recovered) continue
        changed++
        const wasLocallyOwned = this.claimTokens.has(row.id)
        if (recovered === 'queued') {
          this.clearRetryTimer(row.id)
          this.claimTokens.delete(row.id)
          this.claimLostJobs.delete(row.id)
          this.releaseJobLease(row.id)
          const persisted = this.database.findJob(row.id)
          if (!persisted) continue
          try {
            if (isStaticDockerProfile()) {
              const args =
                typeof persisted.args_json === 'string'
                  ? JSON.parse(persisted.args_json)
                  : (persisted.args ?? {})
              this.assertStaticJobContract(persisted.tool, args, persisted.sample_id)
            }
            if (!this.materializePersistedJob(persisted)) {
              throw new Error('E_JOB_RECOVERY_INVALID: persisted job arguments are not valid JSON')
            }
            queued++
          } catch (error) {
            const failure = error instanceof Error ? error.message : String(error)
            if (this.database.markJobInterrupted(row.id, failure)) {
              this.database.markAnalysisStagesInterruptedByJob(row.id, failure)
              const terminal = this.database.findJob(row.id)
              if (terminal) this.materializePersistedJob(terminal)
              interrupted++
            }
          }
        } else {
          this.clearRetryTimer(row.id)
          this.claimTokens.delete(row.id)
          this.database.markAnalysisStagesInterruptedByJob(row.id, reason)
          interrupted++
          if (wasLocallyOwned) {
            this.claimLostJobs.add(row.id)
            const entry = this.jobs.get(row.id)
            if (entry) {
              entry.status = 'cancelling'
              entry.error = 'E_JOB_CLAIM_LOST: durable execution claim expired'
            }
            this.emit('job:reaped', [row.id], 0)
          } else {
            this.claimLostJobs.delete(row.id)
            const persisted = this.database.findJob(row.id)
            if (persisted) this.materializePersistedJob(persisted)
            this.releaseJobLease(row.id)
          }
        }
      }
      if (changed === 0 || rows.length < this.restorePageSize) break
    }
    this.sortQueue()
    return { queued, interrupted }
  }

  private updateOwnedJobStatus(
    jobId: string,
    input: {
      expectedStatuses: string[]
      status: string
      progress?: number
      error?: string
      result?: unknown
      clearClaim?: boolean
      retryCount?: number
    }
  ): void {
    if (!this.database) return
    const claimToken = this.claimTokens.get(jobId)
    if (
      !claimToken ||
      !this.database.updateOwnedJobStatus({
        jobId,
        ownerInstanceId: this.ownerInstanceId,
        ownerBootId: this.ownerBootId,
        claimToken,
        ...input,
      })
    ) {
      throw new SampleOperationLeaseLostError(
        `E_JOB_CLAIM_LOST: job ${jobId} no longer owns its durable execution claim`
      )
    }
    if (input.clearClaim) this.claimTokens.delete(jobId)
  }

  /** Release queue-owned leases during graceful shutdown. */
  close(): void {
    this.closed = true
    if (this.operationHeartbeatTimer) clearInterval(this.operationHeartbeatTimer)
    this.operationHeartbeatTimer = null
    for (const jobId of [...this.retryTimers.keys()]) {
      this.clearRetryTimer(jobId)
      const entry = this.jobs.get(jobId)
      if (entry?.status === 'retry_wait' && this.claimTokens.has(jobId)) {
        try {
          this.updateOwnedJobStatus(jobId, {
            expectedStatuses: ['retry_wait'],
            status: 'queued',
            progress: entry.progress,
            clearClaim: true,
          })
          entry.status = 'queued'
          entry.startedAt = undefined
        } catch (error) {
          if (error instanceof SampleOperationLeaseLostError) {
            this.claimLostJobs.add(jobId)
            this.cleanupLostClaim(jobId)
          } else {
            logger.warn({ job_id: jobId, error }, 'Failed to abandon retry wait during queue close')
          }
        }
      }
      this.releaseJobLease(jobId)
    }
    this.claimTokens.clear()
    this.claimLostJobs.clear()
    for (const jobId of [...this.operationLeases.keys()]) this.releaseJobLease(jobId)
  }

  /**
   * Restore in-memory state from the database on startup.
   *
   * - `queued` jobs are re-added to the priority queue.
   * - `running`/`cancelling` jobs are marked as `interrupted` (their worker died).
   * - persisted work outside the baked static DAG is interrupted, never requeued.
   * - terminal jobs are loaded for status lookup.
   *
   * Call this once during bootstrap, *before* the server starts accepting requests.
   */
  restoreFromDatabase(): { restored: number; interrupted: number } {
    if (!this.database) {
      return { restored: 0, interrupted: 0 }
    }

    let restored = 0
    let interrupted = 0

    const loadActiveRows = (): any[] => {
      const rows: any[] = []
      let cursor: { createdAt: string; id: string } | undefined
      for (;;) {
        const page = this.database!.findJobsByStatusesPage(
          [...ACTIVE_JOB_STATUSES],
          this.restorePageSize,
          cursor
        )
        rows.push(...page)
        if (page.length < this.restorePageSize) break
        const last = page[page.length - 1]
        cursor = { createdAt: last.created_at, id: last.id }
      }
      return rows
    }

    // 1. Reconcile active rows. A live foreign claim is checked before JSON
    // parsing or static validation, so a rolling observer cannot mutate it.
    for (const original of loadActiveRows()) {
      let row = original
      const now = new Date().toISOString()
      if (row.status !== 'queued') {
        const claimIsLive =
          typeof row.claim_token === 'string' &&
          typeof row.claim_until === 'string' &&
          row.claim_until > now
        if (claimIsLive) continue

        if (typeof row.claim_token === 'string') {
          const reason = 'E_TIMEOUT: durable job execution claim expired before recovery'
          const recovered = this.database.recoverExpiredJobClaim(row.id, now, reason)
          if (recovered === 'interrupted') {
            this.database.markAnalysisStagesInterruptedByJob(row.id, reason)
            interrupted++
            continue
          }
          if (recovered !== 'queued') continue
          row = this.database.findJob(row.id)
          if (!row) continue
        } else if (row.status === 'retry_wait') {
          this.database.updateJobStatus(row.id, 'queued', row.progress)
          row = this.database.findJob(row.id)
          if (!row) continue
        } else {
          const reason = 'E_TIMEOUT: legacy job worker was active when server restarted'
          if (this.database.markJobInterrupted(row.id, reason)) {
            this.database.markAnalysisStagesInterruptedByJob(row.id, reason)
            interrupted++
          }
          continue
        }
      }

      let args: Record<string, unknown>
      try {
        args = typeof row.args_json === 'string' ? JSON.parse(row.args_json) : (row.args ?? {})
        if (isStaticDockerProfile()) {
          this.assertStaticJobContract(row.tool, args, row.sample_id)
        }
      } catch (error) {
        const reason =
          error instanceof Error
            ? error.message
            : 'E_JOB_RECOVERY_INVALID: persisted job arguments are not valid JSON'
        if (this.database.markJobInterrupted(row.id, reason)) {
          this.database.markAnalysisStagesInterruptedByJob(row.id, reason)
          interrupted++
        }
      }
    }

    // 2. Active work is paginated independently so terminal history can never
    // evict an older queued job. Terminal status cache remains deliberately bounded.
    const activeRows = loadActiveRows()
    const terminalRows = this.database.findJobsByStatuses([...TERMINAL_JOB_STATUSES], 5000)
    for (const row of [...activeRows, ...terminalRows]) {
      if (this.materializePersistedJob(row)) restored++
    }

    this.sortQueue()

    if (restored > 0 || interrupted > 0) {
      logger.info({ restored, interrupted }, 'Job queue restored from database')
    }

    return { restored, interrupted }
  }

  /**
   * Enqueue a new job
   *
   * @param job - Job configuration (id will be generated if not provided)
   * @returns Job ID
   */
  enqueue(
    job: Omit<Job, 'id' | 'createdAt' | 'attempts' | 'retryPolicy'> & { retryPolicy?: RetryPolicy }
  ): string {
    // Static admission is checked before UUID allocation, lease acquisition,
    // in-memory writes, persistence, or events. A forbidden job therefore has
    // a strict zero-mutation rejection path.
    if (isStaticDockerProfile())
      this.assertStaticJobContract(job.tool, job.args || {}, job.sampleId)
    const jobId = randomUUID()
    const fullJob: Job = {
      ...job,
      id: jobId,
      createdAt: new Date().toISOString(),
      attempts: 0,
      retryPolicy: job.retryPolicy || this.defaultRetryPolicy,
    }

    const entry: JobEntry = {
      job: fullJob,
      status: 'queued',
    }

    this.acquireJobLease(jobId, fullJob.sampleId)
    try {
      this.jobs.set(jobId, entry)
      this.queue.push(fullJob)
      this.database?.createJob({
        id: jobId,
        type: fullJob.type,
        tool: fullJob.tool,
        sampleId: fullJob.sampleId,
        args: fullJob.args,
        priority: fullJob.priority,
        timeout: fullJob.timeout,
        estimatedDurationMs: fullJob.estimatedDurationMs,
        retryPolicy: fullJob.retryPolicy,
      })
      this.assertJobLease(jobId)
    } catch (error) {
      this.jobs.delete(jobId)
      this.queue = this.queue.filter((item) => item.id !== jobId)
      this.releaseJobLease(jobId)
      throw error
    }

    // Sort queue by priority (descending)
    this.sortQueue()

    this.emit('job:enqueued', jobId)

    return jobId
  }

  /**
   * Get job status
   *
   * @param jobId - Job identifier
   * @returns Job status or undefined if not found
   */
  getStatus(jobId: string): JobStatus | undefined {
    const entry = this.refreshForeignJob(jobId)
    if (!entry) {
      return undefined
    }

    return {
      id: jobId,
      status: entry.status,
      progress: entry.progress,
      progressStage: entry.progressStage,
      startedAt: entry.startedAt,
      finishedAt: entry.finishedAt,
      error: entry.error,
    }
  }

  /**
   * Cancel a job
   *
   * @param jobId - Job identifier
   * @returns True if job was cancelled, false if not found or already completed
   */
  cancel(jobId: string, reason?: string): boolean {
    // A rolling observer may have cached retry_wait while the owner already
    // requeued and started the next attempt. Branch on the durable view so the
    // reported cancellation outcome matches the mutation that actually won.
    const entry = this.refreshForeignJob(jobId)
    if (!entry) {
      return false
    }

    // Can only cancel queued or running jobs. A live worker moves through
    // cancelling and retains its lease until complete() confirms exit.
    if (entry.status !== 'queued' && entry.status !== 'retry_wait' && entry.status !== 'running') {
      return false
    }

    const previousStatus = entry.status
    const workerIsAbsent = previousStatus === 'queued' || previousStatus === 'retry_wait'
    const cancellationError = reason ? `Cancelled: ${reason}` : 'Cancelled by user'
    if (previousStatus === 'queued') {
      const persisted = this.database?.requestJobCancellation(jobId, cancellationError)
      if (this.database && persisted !== 'cancelled') return false
    } else if (previousStatus === 'retry_wait') {
      if (this.database && this.claimTokens.has(jobId)) {
        try {
          this.updateOwnedJobStatus(jobId, {
            expectedStatuses: ['retry_wait'],
            status: 'cancelled',
            progress: entry.progress,
            error: cancellationError,
            clearClaim: true,
          })
        } catch (error) {
          if (!(error instanceof SampleOperationLeaseLostError)) throw error
          const persisted = this.database.requestJobCancellation(jobId, cancellationError)
          if (persisted !== 'cancelled') return false
        }
      } else if (this.database) {
        const persisted = this.database.requestJobCancellation(jobId, cancellationError)
        if (persisted !== 'cancelled') return false
      }
    } else {
      if (this.database && this.claimTokens.has(jobId)) {
        const claimToken = this.claimTokens.get(jobId)
        try {
          this.updateOwnedJobStatus(jobId, {
            expectedStatuses: ['running'],
            status: 'cancelling',
            progress: entry.progress,
            error: cancellationError,
          })
        } catch (error) {
          if (!(error instanceof SampleOperationLeaseLostError)) throw error
          const persisted = this.database.findJob(jobId)
          const sameOwnerAlreadyCancelling =
            persisted?.status === 'cancelling' &&
            persisted.owner_instance_id === this.ownerInstanceId &&
            persisted.owner_boot_id === this.ownerBootId &&
            persisted.claim_token === claimToken
          if (!sameOwnerAlreadyCancelling) {
            this.claimTokens.delete(jobId)
            this.claimLostJobs.add(jobId)
            entry.status = 'cancelling'
            entry.error = 'E_JOB_CLAIM_LOST: durable execution claim was lost during cancellation'
            this.emit('job:reaped', [jobId], 0)
            return false
          }
        }
      } else if (this.database) {
        const persisted = this.database.requestJobCancellation(jobId, cancellationError)
        if (persisted !== 'cancelling') return false
      }
    }

    this.clearRetryTimer(jobId)
    if (previousStatus === 'retry_wait') {
      this.claimTokens.delete(jobId)
      this.claimLostJobs.delete(jobId)
    }
    if (workerIsAbsent) this.queue = this.queue.filter((j) => j.id !== jobId)
    entry.cancelReason = reason
    entry.error = cancellationError
    entry.status = workerIsAbsent ? 'cancelled' : 'cancelling'
    if (workerIsAbsent) entry.finishedAt = new Date().toISOString()

    this.emit('job:cancelled', jobId, reason)

    // A cancelled running worker still owns the shared lease until it reports
    // exit through complete(); this prevents deletion racing worker teardown.
    if (workerIsAbsent) this.releaseJobLease(jobId)

    return true
  }

  /**
   * Register a completion callback for a job
   *
   * @param jobId - Job identifier
   * @param callback - Callback function to invoke when job completes
   */
  onComplete(jobId: string, callback: (result: JobResult) => void): void {
    const handler = (completedJobId: string, result: JobResult) => {
      if (completedJobId === jobId) {
        callback(result)
        this.removeListener('job:completed', handler)
        this.removeListener('job:failed', handler)
      }
    }

    this.on('job:completed', handler)
    this.on('job:failed', handler)
  }

  /**
   * Get the next job from the queue (highest priority)
   *
   * @returns Next job or undefined if queue is empty
   */
  dequeue(): Job | undefined {
    const job = this.queue[0]
    if (!job) {
      return undefined
    }
    return this.startQueuedJob(job.id)
  }

  /**
   * Inspect queued jobs without mutating queue order.
   */
  listQueuedJobs(): Job[] {
    return [...this.queue]
  }

  /**
   * Start a specific queued job by id.
   */
  startQueuedJob(jobId: string): Job | undefined {
    const index = this.queue.findIndex((job) => job.id === jobId)
    if (index < 0) {
      return undefined
    }

    const job = this.queue[index]
    // Defense in depth for in-memory corruption or a caller that restored a
    // queue without using restoreFromDatabase(). Validate before splicing or
    // changing status/persistence.
    if (isStaticDockerProfile())
      this.assertStaticJobContract(job.tool, job.args || {}, job.sampleId)
    const entry = this.jobs.get(job.id)
    if (!entry || entry.status !== 'queued') {
      this.queue.splice(index, 1)
      return undefined
    }

    const acquiredLeaseHere = !this.operationLeases.has(job.id)
    try {
      this.acquireJobLease(job.id, job.sampleId)
      this.assertJobLease(job.id)
    } catch (error) {
      if (acquiredLeaseHere) this.releaseJobLease(job.id)
      throw error
    }

    const startedAt = new Date()
    const claimToken = randomUUID()
    if (
      this.database &&
      !this.database.claimQueuedJob({
        jobId: job.id,
        ownerInstanceId: this.ownerInstanceId,
        ownerBootId: this.ownerBootId,
        claimToken,
        claimUntil: new Date(startedAt.getTime() + this.jobClaimTtlMs).toISOString(),
        now: startedAt.toISOString(),
      })
    ) {
      this.queue.splice(index, 1)
      this.releaseJobLease(job.id)
      const persisted = this.database.findJob(job.id)
      if (persisted?.status) entry.status = persisted.status as JobStatusType
      return undefined
    }

    this.queue.splice(index, 1)
    if (this.database) this.claimTokens.set(job.id, claimToken)
    entry.status = 'running'
    entry.startedAt = startedAt.toISOString()
    this.emit('job:started', job.id)
    return job
  }

  /**
   * Mark a job as completed
   *
   * Requirements: 21.4, 21.5, 28.2 - Job completion with retry logic
   *
   * @param jobId - Job identifier
   * @param result - Job execution result
   */
  complete(jobId: string, result: JobResult): JobSettlementOutcome {
    const entry = this.jobs.get(jobId)
    if (!entry) {
      return { committed: false, reason: 'missing' }
    }

    if (this.claimLostJobs.has(jobId)) {
      this.cleanupLostClaim(jobId)
      return {
        committed: false,
        reason: 'claim_lost',
        status: this.jobs.get(jobId)?.status,
      }
    }

    if (entry.status === 'running') this.adoptOwnedCancellation(jobId, entry)

    if (entry.status === 'cancelled') {
      this.releaseJobLease(jobId)
      return { committed: false, reason: 'already_cancelled', status: 'cancelled' }
    }

    if (entry.status === 'cancelling') {
      const reason = entry.error || 'E_CANCELLED: worker exited after cancellation'
      const elapsedMs = entry.startedAt
        ? Math.max(0, Date.now() - new Date(entry.startedAt).getTime())
        : result.metrics.elapsedMs
      const interruptedResult: JobResult = {
        jobId,
        ok: false,
        data: undefined,
        errors: [reason],
        warnings: result.warnings || [],
        artifacts: [],
        metrics: { elapsedMs, peakRssMb: result.metrics.peakRssMb || 0 },
      }
      try {
        this.updateOwnedJobStatus(jobId, {
          expectedStatuses: ['cancelling'],
          status: 'interrupted',
          error: reason,
          result: interruptedResult,
          clearClaim: true,
        })
      } catch (error) {
        if (!(error instanceof SampleOperationLeaseLostError)) throw error
        this.claimLostJobs.add(jobId)
        this.cleanupLostClaim(jobId)
        return {
          committed: false,
          reason: 'claim_lost',
          status: this.jobs.get(jobId)?.status,
        }
      }
      entry.status = 'interrupted'
      entry.finishedAt = new Date().toISOString()
      entry.result = interruptedResult
      this.emit('job:interrupted', jobId, interruptedResult)
      this.emit('job:failed', jobId, interruptedResult)
      this.releaseJobLease(jobId)
      return { committed: true, status: 'interrupted' }
    }

    try {
      this.assertJobLease(jobId)
    } catch (error) {
      if (this.closed || !(error instanceof SampleOperationLeaseLostError)) throw error
      this.handleSampleLeaseLoss(jobId, error)
      if (this.jobs.get(jobId)?.status === 'cancelling') {
        return this.complete(jobId, result)
      }
      throw error
    }

    // Check if job should be retried on failure
    if (!result.ok && this.shouldRetry(entry.job, result)) {
      if (!this.retryJob(entry.job) && this.jobs.get(jobId)?.status === 'cancelling') {
        return this.complete(jobId, result)
      }
      if (this.jobs.get(jobId)?.status === 'retry_wait') {
        return { committed: true, status: 'retry_wait' }
      }
      return {
        committed: false,
        reason: 'claim_lost',
        status: this.jobs.get(jobId)?.status,
      }
    }

    // Mark as completed or failed (no more retries)
    const terminalStatus = result.ok ? 'completed' : 'failed'
    const terminalError = result.ok ? entry.error : result.errors.join('; ')
    try {
      this.updateOwnedJobStatus(jobId, {
        expectedStatuses: ['running'],
        status: terminalStatus,
        progress: entry.progress,
        error: terminalError,
        result: result.ok ? result : undefined,
        clearClaim: true,
      })
    } catch (error) {
      if (!(error instanceof SampleOperationLeaseLostError)) throw error
      if (this.adoptOwnedCancellation(jobId, entry)) {
        return this.complete(jobId, result)
      }
      this.claimLostJobs.add(jobId)
      this.cleanupLostClaim(jobId)
      return {
        committed: false,
        reason: 'claim_lost',
        status: this.jobs.get(jobId)?.status,
      }
    }
    entry.status = terminalStatus
    entry.finishedAt = new Date().toISOString()
    entry.result = result
    entry.error = terminalError

    const eventName = result.ok ? 'job:completed' : 'job:failed'
    this.emit(eventName, jobId, result)
    this.releaseJobLease(jobId)
    return { committed: true, status: terminalStatus }
  }

  /**
   * Check if a failed job should be retried
   *
   * Requirements: 21.5, 28.2 - Retry policy evaluation
   *
   * @param job - Job that failed
   * @param result - Job execution result
   * @returns True if job should be retried
   */
  private shouldRetry(job: Job, result: JobResult): boolean {
    // Check if we've exceeded max retries
    if (job.attempts >= job.retryPolicy.maxRetries) {
      return false
    }

    // Check if any error is retryable
    const hasRetryableError = result.errors.some((error) =>
      job.retryPolicy.retryableErrors.some((retryableError) => error.includes(retryableError))
    )

    return hasRetryableError
  }

  /**
   * Retry a failed job with exponential backoff
   *
   * Requirements: 21.5, 28.2 - Exponential backoff retry
   *
   * @param job - Job to retry
   */
  private retryJob(job: Job): boolean {
    const entry = this.jobs.get(job.id)
    if (!entry || entry.status !== 'running') {
      throw new Error(`E_JOB_RETRY_STATE: job ${job.id} is not running`)
    }
    const nextAttempt = job.attempts + 1
    const backoffMs = job.retryPolicy.backoffMs * Math.pow(2, nextAttempt - 1)
    try {
      this.updateOwnedJobStatus(job.id, {
        expectedStatuses: ['running'],
        status: 'retry_wait',
        progress: entry.progress,
        retryCount: nextAttempt,
      })
    } catch (error) {
      if (!(error instanceof SampleOperationLeaseLostError)) throw error
      if (this.adoptOwnedCancellation(job.id, entry)) return false
      this.claimLostJobs.add(job.id)
      this.cleanupLostClaim(job.id)
      return false
    }
    job.attempts = nextAttempt
    entry.status = 'retry_wait'
    entry.error = undefined

    const expectedAttempt = job.attempts
    const timer = setTimeout(() => {
      const retry = this.retryTimers.get(job.id)
      const entry = this.jobs.get(job.id)
      if (
        !retry ||
        retry.timer !== timer ||
        retry.attempt !== expectedAttempt ||
        !entry ||
        entry.status !== 'retry_wait' ||
        entry.job.attempts !== expectedAttempt
      ) {
        return
      }
      this.retryTimers.delete(job.id)
      try {
        this.requeue(job)
        if (this.jobs.get(job.id)?.status === 'queued') {
          this.emit('job:retry', job.id, job.attempts, backoffMs)
        }
      } catch (error) {
        logger.warn({ job_id: job.id, error }, 'Retry timer lost its durable job claim')
        this.claimLostJobs.add(job.id)
        this.cleanupLostClaim(job.id)
      }
    }, backoffMs)
    this.retryTimers.set(job.id, { timer, attempt: expectedAttempt })

    // Emit retry scheduled event
    this.emit('job:retry-scheduled', job.id, job.attempts, backoffMs)
    return true
  }

  /**
   * Calculate exponential backoff delay
   *
   * Requirements: 21.5, 28.2 - Exponential backoff calculation
   *
   * Formula: baseBackoff * (2 ^ (attempts - 1))
   *
   * @param job - Job to calculate backoff for
   * @returns Backoff delay in milliseconds
   */
  private calculateBackoff(job: Job): number {
    const baseBackoff = job.retryPolicy.backoffMs
    const exponentialFactor = Math.pow(2, job.attempts - 1)
    return baseBackoff * exponentialFactor
  }

  /**
   * Update job progress
   *
   * @param jobId - Job identifier
   * @param progress - Progress percentage (0-100)
   * @param stage - Optional named stage (e.g. 'decompiling', 'extracting strings')
   */
  updateProgress(jobId: string, progress: number, stage?: string): void {
    const entry = this.jobs.get(jobId)
    if (entry && entry.status === 'running') {
      this.assertJobLease(jobId)
      entry.progress = Math.max(0, Math.min(100, progress))
      if (stage !== undefined) {
        entry.progressStage = stage
      }
      this.updateOwnedJobStatus(jobId, {
        expectedStatuses: ['running'],
        status: 'running',
        progress: entry.progress,
      })
      this.emit('job:progress', jobId, entry.progress, entry.progressStage)
    }
  }

  /**
   * Get queue length
   *
   * @returns Number of jobs in queue (not including running jobs)
   */
  getQueueLength(): number {
    return this.queue.length
  }

  /**
   * Get all jobs with a specific status
   *
   * @param status - Job status to filter by
   * @returns Array of job statuses
   */
  getJobsByStatus(status: JobStatusType): JobStatus[] {
    const results: JobStatus[] = []

    for (const jobId of [...this.jobs.keys()]) this.refreshForeignJob(jobId)

    for (const [jobId, entry] of this.jobs.entries()) {
      if (this.retryTimers.has(jobId)) continue
      if (entry.status === status) {
        results.push({
          id: jobId,
          status: entry.status,
          progress: entry.progress,
          progressStage: entry.progressStage,
          startedAt: entry.startedAt,
          finishedAt: entry.finishedAt,
          error: entry.error,
        })
      }
    }

    return results
  }

  /**
   * Get full job status list with lightweight execution context.
   */
  listStatuses(status?: JobStatusType): Array<
    JobStatus & {
      tool: string
      sampleId: string
      attempts: number
      timeout: number
      createdAt: string
      updatedAt?: string
      args: Record<string, unknown>
      estimatedDurationMs?: number
      cancelReason?: string
    }
  > {
    const rows: Array<
      JobStatus & {
        tool: string
        sampleId: string
        attempts: number
        timeout: number
        createdAt: string
        updatedAt?: string
        args: Record<string, unknown>
        estimatedDurationMs?: number
        cancelReason?: string
      }
    > = []

    for (const jobId of [...this.jobs.keys()]) this.refreshForeignJob(jobId)

    for (const [jobId, entry] of this.jobs.entries()) {
      if (status && entry.status !== status) {
        continue
      }
      rows.push({
        id: jobId,
        status: entry.status,
        progress: entry.progress,
        startedAt: entry.startedAt,
        finishedAt: entry.finishedAt,
        error: entry.error,
        tool: entry.job.tool,
        sampleId: entry.job.sampleId,
        attempts: entry.job.attempts,
        timeout: entry.job.timeout,
        createdAt: entry.job.createdAt,
        updatedAt: entry.finishedAt || entry.startedAt || entry.job.createdAt,
        args: entry.job.args,
        estimatedDurationMs: entry.job.estimatedDurationMs,
        cancelReason: entry.cancelReason,
      })
    }

    rows.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    return rows
  }

  /**
   * Get job result
   *
   * @param jobId - Job identifier
   * @returns Job result or undefined if not found or not completed
   */
  getResult(jobId: string): JobResult | undefined {
    const entry = this.refreshForeignJob(jobId)
    return entry?.result
  }

  /**
   * Clear completed jobs older than specified age
   *
   * @param maxAgeMs - Maximum age in milliseconds
   * @returns Number of jobs cleared
   */
  clearOldJobs(maxAgeMs: number): number {
    const now = Date.now()
    let cleared = 0

    for (const [jobId, entry] of this.jobs.entries()) {
      if (
        entry.status === 'completed' ||
        entry.status === 'failed' ||
        entry.status === 'cancelled' ||
        entry.status === 'interrupted'
      ) {
        if (entry.finishedAt) {
          const finishedTime = new Date(entry.finishedAt).getTime()
          if (now - finishedTime > maxAgeMs) {
            this.jobs.delete(jobId)
            cleared++
          }
        }
      }
    }

    return cleared
  }

  /**
   * Begin cancellation for stale workers. The lease remains held until the
   * runner observes worker exit and calls complete(), which finalizes the job
   * as interrupted. Emits `job:reaped` so the runner can abort its controller.
   */
  reapStaleRunningJobs(maxRuntimeMs: number, nowMs: number = Date.now()): string[] {
    const reaped: string[] = []
    for (const [jobId, entry] of this.jobs.entries()) {
      if (entry.status !== 'running' || !entry.startedAt) {
        continue
      }
      const startedAtMs = new Date(entry.startedAt).getTime()
      if (!Number.isFinite(startedAtMs)) {
        continue
      }
      const elapsed = nowMs - startedAtMs
      if (elapsed <= maxRuntimeMs) {
        continue
      }

      const reason = `E_TIMEOUT: stale running job reaped after ${elapsed}ms`
      let cancellationAccepted = !this.database
      if (this.database && this.claimTokens.has(jobId)) {
        const claimToken = this.claimTokens.get(jobId)
        try {
          this.updateOwnedJobStatus(jobId, {
            expectedStatuses: ['running'],
            status: 'cancelling',
            progress: entry.progress,
            error: reason,
          })
          cancellationAccepted = true
        } catch (error) {
          if (!(error instanceof SampleOperationLeaseLostError)) {
            logger.warn({ job_id: jobId, error }, 'Stale job cancellation persistence failed')
            continue
          }
          const persisted = this.database.findJob(jobId)
          const stillOwnsCancellingClaim =
            persisted?.status === 'cancelling' &&
            persisted.owner_instance_id === this.ownerInstanceId &&
            persisted.owner_boot_id === this.ownerBootId &&
            persisted.claim_token === claimToken
          if (stillOwnsCancellingClaim) {
            cancellationAccepted = true
          } else {
            this.claimTokens.delete(jobId)
            this.claimLostJobs.add(jobId)
            entry.status = 'cancelling'
            entry.error = 'E_JOB_CLAIM_LOST: durable execution claim was lost while reaping'
            reaped.push(jobId)
            continue
          }
        }
      } else if (this.database) {
        let persisted: 'cancelled' | 'cancelling' | null
        try {
          persisted = this.database.requestJobCancellation(jobId, reason)
        } catch (error) {
          logger.warn({ job_id: jobId, error }, 'Foreign stale job cancellation failed')
          continue
        }
        if (persisted === 'cancelling') {
          cancellationAccepted = true
        } else {
          this.refreshForeignJob(jobId)
          continue
        }
      }
      if (!cancellationAccepted) continue
      entry.status = 'cancelling'
      entry.error = reason
      reaped.push(jobId)
    }

    if (reaped.length > 0) {
      this.emit('job:reaped', reaped, maxRuntimeMs)
    }
    return reaped
  }

  /**
   * Get total number of jobs tracked
   *
   * @returns Total job count
   */
  getTotalJobs(): number {
    return this.jobs.size
  }

  /**
   * Re-enqueue a job for retry (used by retry mechanism)
   *
   * Requirements: 21.5, 28.2 - Failure retry mechanism
   *
   * @param job - Job to re-enqueue (with updated attempts count)
   */
  requeue(job: Job): void {
    if (isStaticDockerProfile())
      this.assertStaticJobContract(job.tool, job.args || {}, job.sampleId)
    const entry = this.jobs.get(job.id)
    if (!entry || entry.status !== 'retry_wait') {
      throw new Error(`E_JOB_REQUEUE_STATE: job ${job.id} is not in retry_wait state`)
    }
    this.assertJobLease(job.id)
    try {
      this.updateOwnedJobStatus(job.id, {
        expectedStatuses: ['retry_wait'],
        status: 'queued',
        progress: 0,
        clearClaim: true,
      })
    } catch (error) {
      if (!(error instanceof SampleOperationLeaseLostError)) throw error
      this.claimLostJobs.add(job.id)
      this.cleanupLostClaim(job.id)
      return
    }

    // Publish local state only after the durable CAS succeeds.
    entry.job = job
    entry.status = 'queued'
    entry.error = undefined
    entry.startedAt = undefined
    entry.finishedAt = undefined

    // Add back to queue
    this.queue.push(job)
    this.sortQueue()

    this.emit('job:requeued', job.id, job.attempts)
  }

  /**
   * Sort queue by priority (descending)
   */
  private sortQueue(): void {
    this.queue.sort((a, b) => {
      // Higher priority first
      if (a.priority !== b.priority) {
        return b.priority - a.priority
      }
      // If same priority, FIFO (earlier created first)
      return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
    })
  }
}
