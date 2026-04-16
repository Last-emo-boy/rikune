/**
 * Job Queue - Priority queue with DB persistence
 *
 * Implements requirements 21.1 and 21.2:
 * - Task enqueueing with unique job_id
 * - Priority-based task ordering
 * - Job status tracking and cancellation
 * - DB-backed persistence — survives process restarts
 */

import { randomUUID } from 'crypto';
import { EventEmitter } from 'events';
import type { DatabaseManager } from '../database.js';
import type {
  Job,
  JobStatus,
  JobStatusType,
  JobResult,
  RetryPolicy
} from '../types.js';
import { logger } from '../logger.js';

// Re-export types for convenience
export { JobPriority } from '../types.js';
export type {
  Job,
  JobStatus,
  JobStatusType,
  JobResult,
  JobMetrics,
  RetryPolicy,
  ArtifactRef
} from '../types.js';

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
  
  // Default estimate (5 minutes)
  'default': 5 * 60 * 1000,
} as const;

/**
 * Internal job entry with status tracking
 */
interface JobEntry {
  job: Job;
  status: JobStatusType;
  progress?: number;
  progressStage?: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  cancelReason?: string;
  result?: JobResult;
}

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
  private jobs: Map<string, JobEntry> = new Map();
  private queue: Job[] = [];
  private readonly defaultRetryPolicy: RetryPolicy = {
    maxRetries: 3,
    backoffMs: 1000,
    retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED', 'E_WORKER_UNAVAILABLE']
  };

  constructor(private readonly database?: DatabaseManager) {
    super();
  }

  /**
   * Restore in-memory state from the database on startup.
   *
   * - `queued` jobs are re-added to the priority queue.
   * - `running` jobs are marked as `interrupted` (they were orphaned by a crash).
   * - `completed`/`failed`/`cancelled`/`interrupted` jobs are loaded for status lookup.
   *
   * Call this once during bootstrap, *before* the server starts accepting requests.
   */
  restoreFromDatabase(): { restored: number; interrupted: number } {
    if (!this.database) {
      return { restored: 0, interrupted: 0 }
    }

    let restored = 0
    let interrupted = 0

    // 1. Interrupt orphaned running jobs
    const runningRows = this.database.findJobsByStatus('running')
    for (const row of runningRows) {
      const reason = 'E_TIMEOUT: job was running when server restarted'
      this.database.markJobInterrupted(row.id, reason)
      interrupted++
    }

    // 2. Restore all non-cleaned-up jobs into memory
    const allRows = this.database.findJobsByStatuses(
      ['queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted'],
      5000,
    )

    for (const row of allRows) {
      const job: Job = {
        id: row.id,
        type: row.type,
        tool: row.tool,
        sampleId: row.sample_id,
        args: typeof row.args_json === 'string' ? JSON.parse(row.args_json) : (row.args ?? {}),
        priority: row.priority,
        timeout: row.timeout,
        createdAt: row.created_at,
        estimatedDurationMs: row.estimated_duration_ms ?? undefined,
        attempts: 0,
        retryPolicy: this.defaultRetryPolicy,
      }

      // Determine the actual status (running ones were already interrupted above)
      const status: JobStatusType = row.status === 'running' ? 'interrupted' : row.status

      const entry: JobEntry = {
        job,
        status,
        progress: row.progress ?? undefined,
        startedAt: row.started_at ?? undefined,
        finishedAt: row.finished_at ?? undefined,
        error: row.error ?? undefined,
        result: row.result_json
          ? { jobId: row.id, ok: status === 'completed', data: JSON.parse(row.result_json), errors: [], warnings: [], artifacts: [], metrics: { elapsedMs: 0, peakRssMb: 0 } }
          : undefined,
      }

      this.jobs.set(row.id, entry)

      // Re-queue jobs that were waiting
      if (status === 'queued') {
        this.queue.push(job)
      }

      restored++
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
  enqueue(job: Omit<Job, 'id' | 'createdAt' | 'attempts' | 'retryPolicy'> & { retryPolicy?: RetryPolicy }): string {
    const jobId = randomUUID();
    const fullJob: Job = {
      ...job,
      id: jobId,
      createdAt: new Date().toISOString(),
      attempts: 0,
      retryPolicy: job.retryPolicy || this.defaultRetryPolicy
    };

    const entry: JobEntry = {
      job: fullJob,
      status: 'queued'
    };

    this.jobs.set(jobId, entry);
    this.queue.push(fullJob);
    this.database?.createJob({
      id: jobId,
      type: fullJob.type,
      tool: fullJob.tool,
      sampleId: fullJob.sampleId,
      args: fullJob.args,
      priority: fullJob.priority,
      timeout: fullJob.timeout,
      estimatedDurationMs: fullJob.estimatedDurationMs,
    })
    
    // Sort queue by priority (descending)
    this.sortQueue();

    this.emit('job:enqueued', jobId);
    
    return jobId;
  }

  /**
   * Get job status
   * 
   * @param jobId - Job identifier
   * @returns Job status or undefined if not found
   */
  getStatus(jobId: string): JobStatus | undefined {
    const entry = this.jobs.get(jobId);
    if (!entry) {
      return undefined;
    }

    return {
      id: jobId,
      status: entry.status,
      progress: entry.progress,
      progressStage: entry.progressStage,
      startedAt: entry.startedAt,
      finishedAt: entry.finishedAt,
      error: entry.error
    };
  }

  /**
   * Cancel a job
   * 
   * @param jobId - Job identifier
   * @returns True if job was cancelled, false if not found or already completed
   */
  cancel(jobId: string, reason?: string): boolean {
    const entry = this.jobs.get(jobId);
    if (!entry) {
      return false;
    }

    // Can only cancel queued or running jobs
    if (entry.status !== 'queued' && entry.status !== 'running') {
      return false;
    }

    // Remove from queue if still queued
    if (entry.status === 'queued') {
      this.queue = this.queue.filter(j => j.id !== jobId);
    }

    // Update status
    entry.status = 'cancelled';
    entry.finishedAt = new Date().toISOString();
    entry.cancelReason = reason;
    entry.error = reason ? `Cancelled: ${reason}` : 'Cancelled by user';
    this.database?.updateJobStatus(jobId, 'cancelled', entry.progress, entry.error);

    this.emit('job:cancelled', jobId, reason);
    
    return true;
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
        callback(result);
        this.removeListener('job:completed', handler);
        this.removeListener('job:failed', handler);
      }
    };

    this.on('job:completed', handler);
    this.on('job:failed', handler);
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

    const [job] = this.queue.splice(index, 1)
    const entry = this.jobs.get(job.id)
    if (entry) {
      entry.status = 'running'
      entry.startedAt = new Date().toISOString()
      this.database?.updateJobStatus(job.id, 'running', 0)
      this.emit('job:started', job.id)
    }
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
  complete(jobId: string, result: JobResult): void {
    const entry = this.jobs.get(jobId);
    if (!entry) {
      return;
    }

    // Check if job should be retried on failure
    if (!result.ok && this.shouldRetry(entry.job, result)) {
      this.retryJob(entry.job);
      return;
    }

    // Mark as completed or failed (no more retries)
    entry.status = result.ok ? 'completed' : 'failed';
    entry.finishedAt = new Date().toISOString();
    entry.result = result;
    
    if (!result.ok) {
      entry.error = result.errors.join('; ');
    }

    if (result.ok) {
      this.database?.setJobResult(jobId, result);
    } else {
      this.database?.updateJobStatus(jobId, 'failed', entry.progress, entry.error);
    }

    const eventName = result.ok ? 'job:completed' : 'job:failed';
    this.emit(eventName, jobId, result);
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
      return false;
    }

    // Check if any error is retryable
    const hasRetryableError = result.errors.some(error => 
      job.retryPolicy.retryableErrors.some(retryableError => 
        error.includes(retryableError)
      )
    );

    return hasRetryableError;
  }

  /**
   * Retry a failed job with exponential backoff
   * 
   * Requirements: 21.5, 28.2 - Exponential backoff retry
   * 
   * @param job - Job to retry
   */
  private retryJob(job: Job): void {
    // Increment attempts counter
    job.attempts += 1;

    // Calculate exponential backoff delay
    const backoffMs = this.calculateBackoff(job);

    // Schedule retry after backoff delay
    setTimeout(() => {
      this.requeue(job);
      this.emit('job:retry', job.id, job.attempts, backoffMs);
    }, backoffMs);

    // Emit retry scheduled event
    this.emit('job:retry-scheduled', job.id, job.attempts, backoffMs);
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
    const baseBackoff = job.retryPolicy.backoffMs;
    const exponentialFactor = Math.pow(2, job.attempts - 1);
    return baseBackoff * exponentialFactor;
  }

  /**
   * Update job progress
   * 
   * @param jobId - Job identifier
   * @param progress - Progress percentage (0-100)
   * @param stage - Optional named stage (e.g. 'decompiling', 'extracting strings')
   */
  updateProgress(jobId: string, progress: number, stage?: string): void {
    const entry = this.jobs.get(jobId);
    if (entry && entry.status === 'running') {
      entry.progress = Math.max(0, Math.min(100, progress));
      if (stage !== undefined) {
        entry.progressStage = stage;
      }
      this.database?.updateJobStatus(jobId, 'running', entry.progress);
      this.emit('job:progress', jobId, entry.progress, entry.progressStage);
    }
  }

  /**
   * Get queue length
   * 
   * @returns Number of jobs in queue (not including running jobs)
   */
  getQueueLength(): number {
    return this.queue.length;
  }

  /**
   * Get all jobs with a specific status
   * 
   * @param status - Job status to filter by
   * @returns Array of job statuses
   */
  getJobsByStatus(status: JobStatusType): JobStatus[] {
    const results: JobStatus[] = [];
    
    for (const [jobId, entry] of this.jobs.entries()) {
      if (entry.status === status) {
        results.push({
          id: jobId,
          status: entry.status,
          progress: entry.progress,
          progressStage: entry.progressStage,
          startedAt: entry.startedAt,
          finishedAt: entry.finishedAt,
          error: entry.error
        });
      }
    }
    
    return results;
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

    rows.sort(
      (a, b) =>
        new Date(b.createdAt).getTime() -
        new Date(a.createdAt).getTime()
    )
    return rows
  }

  /**
   * Get job result
   * 
   * @param jobId - Job identifier
   * @returns Job result or undefined if not found or not completed
   */
  getResult(jobId: string): JobResult | undefined {
    const entry = this.jobs.get(jobId);
    return entry?.result;
  }

  /**
   * Clear completed jobs older than specified age
   * 
   * @param maxAgeMs - Maximum age in milliseconds
   * @returns Number of jobs cleared
   */
  clearOldJobs(maxAgeMs: number): number {
    const now = Date.now();
    let cleared = 0;

    for (const [jobId, entry] of this.jobs.entries()) {
      if (
        entry.status === 'completed' ||
        entry.status === 'failed' ||
        entry.status === 'cancelled' ||
        entry.status === 'interrupted'
      ) {
        if (entry.finishedAt) {
          const finishedTime = new Date(entry.finishedAt).getTime();
          if (now - finishedTime > maxAgeMs) {
            this.jobs.delete(jobId);
            cleared++;
          }
        }
      }
    }

    return cleared;
  }

  /**
   * Mark stale running jobs as interrupted.
   * Emits `job:reaped` with affected job ids for observability.
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

      entry.status = 'interrupted'
      entry.finishedAt = new Date(nowMs).toISOString()
      entry.error = `E_TIMEOUT: stale running job reaped after ${elapsed}ms`
      if (!entry.result) {
        entry.result = {
          jobId,
          ok: false,
          data: undefined,
          errors: [entry.error],
          warnings: [],
          artifacts: [],
          metrics: {
            elapsedMs: elapsed,
            peakRssMb: 0,
          },
        }
      }
      this.database?.markJobInterrupted(jobId, entry.error, entry.result)
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
    return this.jobs.size;
  }

  /**
   * Re-enqueue a job for retry (used by retry mechanism)
   * 
   * Requirements: 21.5, 28.2 - Failure retry mechanism
   * 
   * @param job - Job to re-enqueue (with updated attempts count)
   */
  requeue(job: Job): void {
    // Update the job entry
    const entry = this.jobs.get(job.id);
    if (entry) {
      entry.job = job;
      entry.status = 'queued';
      entry.error = undefined;
      entry.startedAt = undefined;
      entry.finishedAt = undefined;
      this.database?.updateJobStatus(job.id, 'queued', 0);
    }

    // Add back to queue
    this.queue.push(job);
    this.sortQueue();

    this.emit('job:requeued', job.id, job.attempts);
  }

  /**
   * Sort queue by priority (descending)
   */
  private sortQueue(): void {
    this.queue.sort((a, b) => {
      // Higher priority first
      if (a.priority !== b.priority) {
        return b.priority - a.priority;
      }
      // If same priority, FIFO (earlier created first)
      return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
    });
  }
}
