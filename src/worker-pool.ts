/**
 * Worker Pool - Manages concurrent worker processes
 *
 * Implements requirements 21.3, 27.2 and operational constraint 4:
 * - Worker process management
 * - Task allocation and status updates
 * - Concurrency control (max 4 Ghidra analyses by default)
 */

import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { JobQueue } from './job-queue.js'
import type { Job, JobResult } from './types.js'

type WorkerType = 'static' | 'decompile' | 'dotnet' | 'sandbox'

export interface WorkerPoolConfig {
  maxStaticWorkers?: number
  maxDecompileWorkers?: number
  maxDotNetWorkers?: number
  maxSandboxWorkers?: number
  testExecutor?: (job: Job) => Promise<JobResult>
}

interface WorkerInfo {
  id: string
  type: WorkerType
  busy: boolean
  currentJobId?: string
  lastHeartbeat: number
  startedAt?: number
  timeoutHandle?: ReturnType<typeof setTimeout>
}

interface WorkerTypeStats {
  max: number
  busy: number
  idle: number
}

export interface WorkerPoolStats {
  isRunning: boolean
  queueLength: number
  workers: {
    static: WorkerTypeStats
    decompile: WorkerTypeStats
    dotnet: WorkerTypeStats
    sandbox: WorkerTypeStats
  }
}

export class WorkerPool extends EventEmitter {
  private running = false
  private workers = new Map<string, WorkerInfo>()
  private heartbeats = new Map<string, number>()
  private maxWorkers: Record<WorkerType, number>
  private jobQueue: JobQueue
  private allocationInterval?: ReturnType<typeof setInterval>
  private testExecutor?: (job: Job) => Promise<JobResult>

  constructor(jobQueue: JobQueue, config?: WorkerPoolConfig) {
    super()
    this.jobQueue = jobQueue
    this.maxWorkers = {
      static: config?.maxStaticWorkers ?? 8,
      decompile: config?.maxDecompileWorkers ?? 4,
      dotnet: config?.maxDotNetWorkers ?? 4,
      sandbox: config?.maxSandboxWorkers ?? 2,
    }
    this.testExecutor = config?.testExecutor
  }

  start(): void {
    if (this.running) return
    this.running = true
    this.emit('pool:started')
    this.allocateJobs()
    this.allocationInterval = setInterval(() => this.allocateJobs(), 1000)
  }

  async stop(): Promise<void> {
    if (!this.running) return
    this.running = false
    if (this.allocationInterval) {
      clearInterval(this.allocationInterval)
      this.allocationInterval = undefined
    }
    // Clear all timeout handles
    for (const w of this.workers.values()) {
      if (w.timeoutHandle) clearTimeout(w.timeoutHandle)
    }
    this.workers.clear()
    this.emit('pool:stopped')
  }

  getStats(): WorkerPoolStats {
    const stats: WorkerPoolStats = {
      isRunning: this.running,
      queueLength: 0,
      workers: {
        static: { max: this.maxWorkers.static, busy: 0, idle: 0 },
        decompile: { max: this.maxWorkers.decompile, busy: 0, idle: 0 },
        dotnet: { max: this.maxWorkers.dotnet, busy: 0, idle: 0 },
        sandbox: { max: this.maxWorkers.sandbox, busy: 0, idle: 0 },
      },
    }

    for (const w of this.workers.values()) {
      const s = stats.workers[w.type]
      if (w.busy) s.busy++
      else s.idle++
    }

    // Count pending jobs in queue
    const allStatuses = ['queued'] as const
    for (const status of allStatuses) {
      try {
        const jobs = (this.jobQueue as any).jobs as Map<string, any> | undefined
        if (jobs) {
          for (const entry of jobs.values()) {
            if (entry.status === status) stats.queueLength++
          }
        }
      } catch { /* ignore */ }
    }
    // Fallback: count from queue array
    try {
      const queue = (this.jobQueue as any).queue as any[] | undefined
      if (queue) stats.queueLength = queue.length
    } catch { /* ignore */ }

    return stats
  }

  updateHeartbeat(workerId: string): void {
    this.heartbeats.set(workerId, Date.now())
  }

  private getWorkerTypeForJobType(type: string): WorkerType {
    switch (type) {
      case 'decompile': return 'decompile'
      case 'dotnet': return 'dotnet'
      case 'sandbox': return 'sandbox'
      default: return 'static'
    }
  }

  private countBusyWorkers(type: WorkerType): number {
    let count = 0
    for (const w of this.workers.values()) {
      if (w.type === type && w.busy) count++
    }
    return count
  }

  private findIdleWorker(type: WorkerType): WorkerInfo | undefined {
    for (const w of this.workers.values()) {
      if (w.type === type && !w.busy) return w
    }
    return undefined
  }

  private allocateJobs(): void {
    if (!this.running) return

    // Try to dequeue and assign jobs
    let job: Job | undefined
    while ((job = this.jobQueue.dequeue()) !== undefined) {
      const workerType = this.getWorkerTypeForJobType(job.type)
      const busy = this.countBusyWorkers(workerType)

      if (busy >= this.maxWorkers[workerType]) {
        // Can't allocate - no capacity. Re-enqueue.
        this.jobQueue.requeue(job)
        break
      }

      // Find or create a worker
      let worker = this.findIdleWorker(workerType)
      if (!worker) {
        const workerId = `worker-${randomUUID().slice(0, 8)}`
        worker = {
          id: workerId,
          type: workerType,
          busy: false,
          lastHeartbeat: Date.now(),
        }
        this.workers.set(workerId, worker)
        this.emit('worker:created', workerId, workerType)
      }

      worker.busy = true
      worker.currentJobId = job.id
      worker.startedAt = Date.now()

      // Job is already marked as running by dequeue() -> startQueuedJob()
      this.emit('worker:job:started', worker.id, job.id)

      // Set up timeout if specified
      if (job.timeout && job.timeout > 0) {
        const capturedJob = job
        const capturedWorker = worker
        worker.timeoutHandle = setTimeout(() => {
          this.handleJobTimeout(capturedWorker, capturedJob)
        }, job.timeout)
      }

      this.executeJob(worker, job)
    }
  }

  private async executeJob(worker: WorkerInfo, job: Job): Promise<void> {
    try {
      let result: JobResult

      if (this.testExecutor) {
        result = await this.testExecutor(job)
      } else {
        // Default: simulate quick success
        result = {
          jobId: job.id,
          ok: true,
          data: {},
          errors: [],
          warnings: [],
          artifacts: [],
          metrics: { elapsedMs: Date.now() - (worker.startedAt || Date.now()), peakRssMb: 0 },
        }
      }

      if (worker.timeoutHandle) {
        clearTimeout(worker.timeoutHandle)
        worker.timeoutHandle = undefined
      }

      worker.busy = false
      worker.currentJobId = undefined

      this.jobQueue.complete(job.id, result)
      this.emit('worker:job:completed', worker.id, job.id, result)

      // Check for more work
      if (this.running) {
        this.allocateJobs()
      }
    } catch (error: any) {
      if (worker.timeoutHandle) {
        clearTimeout(worker.timeoutHandle)
        worker.timeoutHandle = undefined
      }

      worker.busy = false
      worker.currentJobId = undefined

      const errorMsg = error?.message || String(error)
      const retryPolicy = job.retryPolicy
      const attempts = job.attempts ?? 0

      if (retryPolicy && attempts < retryPolicy.maxRetries) {
        const isRetryable = retryPolicy.retryableErrors.some(e => errorMsg.includes(e))
        if (isRetryable) {
          const nextAttempt = attempts + 1
          job.attempts = nextAttempt
          this.emit('worker:job:retrying', worker.id, job.id, nextAttempt)

          // Exponential backoff
          const backoff = retryPolicy.backoffMs * Math.pow(2, attempts)
          setTimeout(() => {
            this.jobQueue.requeue(job)
            if (this.running) this.allocateJobs()
          }, backoff)
          return
        }
      }

      const failResult: JobResult = {
        jobId: job.id,
        ok: false,
        data: {},
        errors: [errorMsg],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: Date.now() - (worker.startedAt || Date.now()), peakRssMb: 0 },
      }
      this.jobQueue.complete(job.id, failResult)
      this.emit('worker:job:failed', worker.id, job.id, errorMsg)

      if (this.running) {
        this.allocateJobs()
      }
    }
  }

  private handleJobTimeout(worker: WorkerInfo, job: Job): void {
    const elapsed = Date.now() - (worker.startedAt || Date.now())

    worker.busy = false
    worker.currentJobId = undefined
    worker.timeoutHandle = undefined

    this.emit('worker:job:timeout', worker.id, job.id, elapsed)
    this.emit('worker:terminated', worker.id, worker.type)

    const retryPolicy = job.retryPolicy
    const attempts = job.attempts ?? 0

    if (retryPolicy && attempts < retryPolicy.maxRetries) {
      const isRetryable = retryPolicy.retryableErrors.some(e => 'E_TIMEOUT'.includes(e) || e.includes('timeout'))
      if (isRetryable) {
        const nextAttempt = attempts + 1
        job.attempts = nextAttempt
        this.emit('worker:job:retrying', worker.id, job.id, nextAttempt)

        const backoff = retryPolicy.backoffMs * Math.pow(2, attempts)
        setTimeout(() => {
          this.jobQueue.requeue(job)
          if (this.running) this.allocateJobs()
        }, backoff)
        return
      }
    }

    const failResult: JobResult = {
      jobId: job.id,
      ok: false,
      data: {},
      errors: [`E_TIMEOUT: Job timed out after ${job.timeout}ms (elapsed: ${elapsed}ms)`],
      warnings: [],
      artifacts: [],
      metrics: { elapsedMs: elapsed, peakRssMb: 0 },
    }
    this.jobQueue.complete(job.id, failResult)
  }
}
