import { EventEmitter } from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { describe, test, expect, beforeEach, jest } from '@jest/globals'

const capturedSignals = new Map<string, AbortSignal | undefined>()

function workerResult() {
  return {
    ok: true,
    data: { completed: true },
    errors: [],
    warnings: [],
    artifacts: [],
    metrics: { elapsed_ms: 1 },
  }
}

function handlerFactory(tool: string) {
  return jest.fn(() => async (_args: unknown, abortSignal?: AbortSignal) => {
    capturedSignals.set(tool, abortSignal)
    return workerResult()
  })
}

const mockDeepStaticWorkflow = jest.fn(async (...args: unknown[]) => {
  const callbacks = args[5] as { abortSignal?: AbortSignal } | undefined
  capturedSignals.set('workflow.deep_static', callbacks?.abortSignal)
  return { ok: true, data: { completed: true }, errors: [], warnings: [] }
})
const mockReconstructFactory = handlerFactory('workflow.reconstruct')
const mockStringsExtractFactory = handlerFactory('strings.extract')
const mockStringsFlossFactory = handlerFactory('strings.floss.decode')
const mockBinaryRoleFactory = handlerFactory('binary.role.profile')
const mockContextLinkFactory = handlerFactory('analysis.context.link')
const mockCryptoIdentifyFactory = handlerFactory('crypto.identify')
const mockAttackMapFactory = handlerFactory('attack.map')
const mockSemanticReviewFactory = handlerFactory('workflow.semantic_name_review')
const mockExplanationReviewFactory = handlerFactory('workflow.function_explanation_review')
const mockModuleReviewFactory = handlerFactory('workflow.module_reconstruction_review')

jest.unstable_mockModule('../../src/workflows/deep-static.js', () => ({
  deepStaticWorkflow: mockDeepStaticWorkflow,
}))
jest.unstable_mockModule('../../src/workflows/reconstruct.js', () => ({
  createReconstructWorkflowHandler: mockReconstructFactory,
}))
jest.unstable_mockModule('../../src/plugins/strings/tools/strings-extract.js', () => ({
  createStringsExtractHandler: mockStringsExtractFactory,
}))
jest.unstable_mockModule('../../src/plugins/strings/tools/strings-floss-decode.js', () => ({
  createStringsFlossDecodeHandler: mockStringsFlossFactory,
}))
jest.unstable_mockModule('../../src/plugins/static-triage/tools/binary-role-profile.js', () => ({
  createBinaryRoleProfileHandler: mockBinaryRoleFactory,
}))
jest.unstable_mockModule('../../src/plugins/static-triage/tools/analysis-context-link.js', () => ({
  createAnalysisContextLinkHandler: mockContextLinkFactory,
}))
jest.unstable_mockModule('../../src/plugins/static-triage/tools/crypto-identify.js', () => ({
  createCryptoIdentifyHandler: mockCryptoIdentifyFactory,
}))
jest.unstable_mockModule('../../src/plugins/threat-intel/tools/attack-map.js', () => ({
  createAttackMapHandler: mockAttackMapFactory,
}))
jest.unstable_mockModule('../../src/workflows/semantic-name-review.js', () => ({
  createSemanticNameReviewWorkflowHandler: mockSemanticReviewFactory,
}))
jest.unstable_mockModule('../../src/workflows/function-explanation-review.js', () => ({
  createFunctionExplanationReviewWorkflowHandler: mockExplanationReviewFactory,
}))
jest.unstable_mockModule('../../src/workflows/module-reconstruction-review.js', () => ({
  createModuleReconstructionReviewWorkflowHandler: mockModuleReviewFactory,
}))

const selectNextJob = jest.fn()
const recordCompletion = jest.fn()
const recordInterruption = jest.fn()

jest.unstable_mockModule('../../src/analysis/analysis-budget-scheduler.js', () => ({
  AnalysisBudgetScheduler: class {
    selectNextJob = selectNextJob
    recordCompletion = recordCompletion
    recordInterruption = recordInterruption
  },
  findWorkerReuseTelemetry: jest.fn(() => null),
  getRuntimeMemoryUsageMb: jest.fn(() => 64),
}))

jest.unstable_mockModule('../../src/worker/decompiler-worker.js', () => {
  class GhidraProcessError extends Error {
    errorCode: string

    constructor(message: string, errorCode = 'E_GHIDRA') {
      super(message)
      this.errorCode = errorCode
    }
  }

  return {
    GhidraProcessError,
    DecompilerWorker: class {
      analyze = jest.fn()
      createJobResult = jest.fn()
      createErrorJobResult = jest.fn((jobId: string, error: Error, elapsedMs: number) => ({
        jobId,
        ok: false,
        data: null,
        errors: [error.message],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs, peakRssMb: 0 },
      }))
    },
  }
})

jest.unstable_mockModule('../../src/workflows/analyze-pipeline.js', () => ({
  ANALYSIS_STAGE_JOB_TOOL: 'workflow.analyze.stage',
  createAnalyzePipelineStageContext: jest.fn(() => ({})),
  executeQueuedAnalysisStage: jest.fn(),
}))

jest.unstable_mockModule('../../src/core/static-profile-lock.js', () => ({
  assertStaticAnalysisRunContract: jest.fn(),
  assertStaticQueuedJob: jest.fn(),
  assertStaticWorkflowStage: jest.fn(),
  isStaticDockerProfile: jest.fn(() => false),
}))

jest.unstable_mockModule('../../src/logger.js', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
  logDebug: jest.fn(),
}))

const { AnalysisTaskRunner } = await import('../../src/analysis/analysis-task-runner.js')
const { logger: mockLogger } = await import('../../src/logger.js')
const { DatabaseManager, DATABASE_FIXTURE_CAPABILITY } = await import('../../src/database.js')
const { JobQueue } = await import('../../src/job-queue.js')

interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T | PromiseLike<T>) => void
  reject: (error: unknown) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: Deferred<T>['resolve']
  let reject!: Deferred<T>['reject']
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function makeJob(tool: string, id = `job-${tool}`) {
  return {
    id,
    type: 'static',
    tool,
    sampleId: 'sha256:test',
    args: {},
    priority: 5,
    status: 'queued',
    progress: 0,
    createdAt: new Date().toISOString(),
    startedAt: null,
    completedAt: null,
    timeout: 60_000,
    retryCount: 0,
    retryPolicy: { maxRetries: 0, backoffMs: 0, retryableErrors: [] },
  } as any
}

function makeSelection(job: ReturnType<typeof makeJob>) {
  return {
    job,
    plan: {
      execution_bucket: 'static',
      cost_class: 'bounded',
      worker_family: 'test',
      expected_rss_mb: 64,
    },
  }
}

function makeQueue() {
  const queue = new EventEmitter() as EventEmitter & Record<string, any>
  const statuses = new Map<string, Record<string, unknown>>()
  queue.statuses = statuses
  queue.updateProgress = jest.fn()
  queue.startQueuedJob = jest.fn()
  queue.complete = jest.fn((jobId: string, result: ReturnType<typeof completedJobResult>) => {
    const status = result.ok ? 'completed' : 'failed'
    statuses.set(jobId, {
      id: jobId,
      status,
      ...(result.ok ? {} : { error: result.errors.join('; ') }),
    })
    return { committed: true, status }
  })
  queue.getStatus = jest.fn((jobId: string) => statuses.get(jobId))
  queue.reapStaleRunningJobs = jest.fn(() => [])
  return queue
}

function makeRunner(queue = makeQueue(), options: Record<string, unknown> = {}) {
  const policyGuard = {
    checkPermission: jest.fn(async () => ({ allowed: true, reason: 'test allowed' })),
    auditLog: jest.fn(async () => undefined),
  }
  const runner = new AnalysisTaskRunner(
    queue as any,
    {} as any,
    {} as any,
    {} as any,
    policyGuard as any,
    options
  )
  return { runner, queue }
}

function completedJobResult(jobId: string) {
  return {
    jobId,
    ok: true,
    data: { completed: true },
    errors: [],
    warnings: [],
    artifacts: [],
    metrics: { elapsedMs: 1, peakRssMb: 0 },
  }
}

describe('AnalysisTaskRunner cancellation', () => {
  beforeEach(() => {
    capturedSignals.clear()
    selectNextJob.mockReset()
    recordCompletion.mockReset()
    recordInterruption.mockReset()
    jest.clearAllMocks()
  })

  test.each([
    'workflow.deep_static',
    'workflow.reconstruct',
    'strings.extract',
    'strings.floss.decode',
    'binary.role.profile',
    'analysis.context.link',
    'crypto.identify',
    'attack.map',
    'workflow.semantic_name_review',
    'workflow.function_explanation_review',
    'workflow.module_reconstruction_review',
  ])('%s forwards the queued AbortSignal to its workflow boundary', async (tool) => {
    const { runner } = makeRunner()
    const controller = new AbortController()

    await (runner as any).executeJob(makeJob(tool), controller.signal)

    expect(capturedSignals.get(tool)).toBe(controller.signal)
  })

  test('job:cancelled aborts the active executor and waits for its teardown before completing', async () => {
    const job = makeJob('workflow.reconstruct', 'job-cancel')
    const { runner, queue } = makeRunner()
    const started = deferred<AbortSignal>()
    const teardown = deferred<void>()
    const events: string[] = []

    selectNextJob.mockReturnValue(makeSelection(job))
    queue.startQueuedJob.mockReturnValue(job)
    queue.complete.mockImplementation(() => {
      events.push('complete')
      return { committed: true, status: 'completed' }
    })
    ;(runner as any).queuedExecutors.set(
      job.tool,
      jest.fn(async (_job: unknown, abortSignal: AbortSignal) => {
        started.resolve(abortSignal)
        await new Promise<void>((resolve) => {
          abortSignal.addEventListener('abort', () => resolve(), { once: true })
        })
        events.push('abort-observed')
        await teardown.promise
        events.push('teardown-complete')
        return completedJobResult(job.id)
      })
    )

    const processing = (runner as any).processNext() as Promise<void>
    const signal = await started.promise
    queue.emit('job:cancelled', job.id)

    expect(signal.aborted).toBe(true)
    await Promise.resolve()
    expect(events).toEqual(['abort-observed'])

    teardown.resolve()
    await processing
    expect(events).toEqual(['abort-observed', 'teardown-complete', 'complete'])
  })

  test('stale-job reaping delivers cancellation to the active executor and drains it', async () => {
    const job = makeJob('workflow.reconstruct', 'job-reaped')
    const { runner, queue } = makeRunner(undefined, { staleRunningMs: 25 })
    const started = deferred<AbortSignal>()

    selectNextJob.mockReturnValue(makeSelection(job))
    queue.startQueuedJob.mockReturnValue(job)
    queue.reapStaleRunningJobs.mockReturnValue([job.id])
    ;(runner as any).queuedExecutors.set(
      job.tool,
      jest.fn(async (_job: unknown, abortSignal: AbortSignal) => {
        started.resolve(abortSignal)
        await new Promise<void>((resolve) => {
          abortSignal.addEventListener('abort', () => resolve(), { once: true })
        })
        return completedJobResult(job.id)
      })
    )

    const processing = (runner as any).processNext() as Promise<void>
    const signal = await started.promise
    ;(runner as any).reapStaleRunning()

    expect(queue.reapStaleRunningJobs).toHaveBeenCalledWith(25)
    expect(signal.aborted).toBe(true)
    await processing
    expect(queue.complete).toHaveBeenCalledTimes(1)
  })

  test('a failed reaper tick is contained and the next tick still succeeds', () => {
    const { runner, queue } = makeRunner(undefined, { staleRunningMs: 25 })
    const sqliteBusy = new Error('SQLITE_BUSY: database is locked')
    queue.reapStaleRunningJobs
      .mockImplementationOnce(() => {
        throw sqliteBusy
      })
      .mockReturnValueOnce([])

    expect(() => (runner as any).reapStaleRunning()).not.toThrow()
    expect(() => (runner as any).reapStaleRunning()).not.toThrow()

    expect(queue.reapStaleRunningJobs).toHaveBeenCalledTimes(2)
    expect(mockLogger.error).toHaveBeenCalledWith(
      { error: sqliteBusy },
      'Analysis runner reaper cycle failed'
    )
  })

  test('stop aborts first and resolves only after executor teardown and queue completion', async () => {
    const job = makeJob('workflow.reconstruct', 'job-stop')
    const { runner, queue } = makeRunner()
    const started = deferred<AbortSignal>()
    const teardown = deferred<void>()
    const events: string[] = []

    selectNextJob.mockReturnValue(makeSelection(job))
    queue.startQueuedJob.mockReturnValue(job)
    queue.complete.mockImplementation(() => {
      events.push('complete')
      return { committed: true, status: 'completed' }
    })
    ;(runner as any).queuedExecutors.set(
      job.tool,
      jest.fn(async (_job: unknown, abortSignal: AbortSignal) => {
        started.resolve(abortSignal)
        await new Promise<void>((resolve) => {
          abortSignal.addEventListener('abort', () => resolve(), { once: true })
        })
        events.push('abort-observed')
        await teardown.promise
        events.push('teardown-complete')
        return completedJobResult(job.id)
      })
    )

    const processing = (runner as any).processNext() as Promise<void>
    const signal = await started.promise
    let stopSettled = false
    const stopping = runner.stop().then(() => {
      stopSettled = true
      events.push('stop-resolved')
    })

    expect(signal.aborted).toBe(true)
    await Promise.resolve()
    expect(stopSettled).toBe(false)
    expect(events).toEqual(['abort-observed'])

    teardown.resolve()
    await Promise.all([processing, stopping])
    expect(events).toEqual(['abort-observed', 'teardown-complete', 'complete', 'stop-resolved'])
  })

  test('stop drains a hanging delegated runtime client through the same stage signal', async () => {
    const job = makeJob('workflow.reconstruct', 'job-runtime-stop')
    const started = deferred<AbortSignal>()
    const teardown = deferred<void>()
    const events: string[] = []
    const runtimeClient = {
      execute: jest.fn(async (_request: unknown, options?: { signal?: AbortSignal }) => {
        const signal = options?.signal
        if (!signal) throw new Error('missing runtime AbortSignal')
        started.resolve(signal)
        await new Promise<void>((resolve) => {
          signal.addEventListener('abort', () => resolve(), { once: true })
        })
        events.push('runtime-abort-observed')
        await teardown.promise
        events.push('runtime-teardown-complete')
        return workerResult()
      }),
      uploadSample: jest.fn(async () => undefined),
      downloadArtifacts: jest.fn(async () => []),
      recover: jest.fn(async () => true),
    }
    const { runner, queue } = makeRunner(undefined, {
      runtimeClientProvider: () => runtimeClient,
    })
    selectNextJob.mockReturnValue(makeSelection(job))
    queue.startQueuedJob.mockReturnValue(job)
    queue.complete.mockImplementation(() => {
      events.push('complete')
      return { committed: true, status: 'completed' }
    })
    const dependencies = (runner as any).createAnalyzePipelineDependencies()
    ;(runner as any).queuedExecutors.set(
      job.tool,
      jest.fn(async (_job: unknown, abortSignal: AbortSignal) => {
        await dependencies.sandboxExecute({}, abortSignal)
        return completedJobResult(job.id)
      })
    )

    const processing = (runner as any).processNext() as Promise<void>
    const signal = await started.promise
    let stopSettled = false
    const stopping = runner.stop().then(() => {
      stopSettled = true
      events.push('stop-resolved')
    })

    expect(signal.aborted).toBe(true)
    await Promise.resolve()
    expect(stopSettled).toBe(false)
    expect(events).toEqual(['runtime-abort-observed'])

    teardown.resolve()
    await Promise.all([processing, stopping])
    expect(events).toEqual([
      'runtime-abort-observed',
      'runtime-teardown-complete',
      'complete',
      'stop-resolved',
    ])
    expect(runtimeClient.downloadArtifacts).not.toHaveBeenCalled()
    expect(runtimeClient.recover).not.toHaveBeenCalled()
  })

  test('cancellation fencing records interruption only after the durable interrupted status', async () => {
    const job = makeJob('workflow.reconstruct', 'job-cancelled-before-resolve')
    const { runner, queue } = makeRunner()
    const started = deferred<AbortSignal>()

    selectNextJob.mockReturnValue(makeSelection(job))
    queue.startQueuedJob.mockReturnValue(job)
    queue.complete.mockImplementation((jobId: string) => {
      queue.statuses.set(jobId, {
        id: jobId,
        status: 'interrupted',
        error: 'E_CANCELLED: worker exited after cancellation',
      })
      return { committed: true, status: 'interrupted' }
    })
    ;(runner as any).queuedExecutors.set(
      job.tool,
      jest.fn(async (_job: unknown, abortSignal: AbortSignal) => {
        started.resolve(abortSignal)
        await new Promise<void>((resolve) => {
          abortSignal.addEventListener('abort', () => resolve(), { once: true })
        })
        return completedJobResult(job.id)
      })
    )

    const processing = (runner as any).processNext() as Promise<void>
    await started.promise
    queue.emit('job:cancelled', job.id)
    await processing

    expect(queue.complete).toHaveBeenCalledTimes(1)
    expect(recordCompletion).not.toHaveBeenCalled()
    expect(recordInterruption).toHaveBeenCalledWith(
      expect.objectContaining({
        jobId: job.id,
        reason: 'E_CANCELLED: worker exited after cancellation',
        interruptionCause: 'cancelled',
      })
    )
    expect(queue.complete.mock.invocationCallOrder[0]).toBeLessThan(
      recordInterruption.mock.invocationCallOrder[0]
    )
  })

  test('recordCompletion failure cannot prevent the durable terminal transition', async () => {
    const job = makeJob('workflow.reconstruct', 'job-telemetry-completion-failure')
    const { runner, queue } = makeRunner()
    const telemetryError = new Error('scheduler completion persistence failed')

    selectNextJob.mockReturnValue(makeSelection(job))
    queue.startQueuedJob.mockReturnValue(job)
    recordCompletion.mockImplementationOnce(() => {
      throw telemetryError
    })
    ;(runner as any).queuedExecutors.set(
      job.tool,
      jest.fn(async () => completedJobResult(job.id))
    )

    await expect((runner as any).processNext()).resolves.toBeUndefined()

    expect(queue.statuses.get(job.id)).toMatchObject({ status: 'completed' })
    expect(queue.complete).toHaveBeenCalledTimes(1)
    expect(queue.complete.mock.invocationCallOrder[0]).toBeLessThan(
      recordCompletion.mock.invocationCallOrder[0]
    )
    expect(mockLogger.error).toHaveBeenCalledWith(
      expect.objectContaining({
        job_id: job.id,
        durable_status: 'completed',
        error: telemetryError,
      }),
      'Analysis scheduler telemetry write failed'
    )
  })

  test('completion and interruption telemetry failures remain contained and the next tick runs', async () => {
    const completedJob = makeJob('workflow.reconstruct', 'job-telemetry-completed')
    const failedJob = makeJob('workflow.reconstruct', 'job-telemetry-interrupted')
    const jobs = new Map([
      [completedJob.id, completedJob],
      [failedJob.id, failedJob],
    ])
    const { runner, queue } = makeRunner()

    selectNextJob
      .mockReturnValueOnce(makeSelection(completedJob))
      .mockReturnValueOnce(makeSelection(failedJob))
    queue.startQueuedJob.mockImplementation((jobId: string) => jobs.get(jobId))
    recordCompletion.mockImplementationOnce(() => {
      throw new Error('completion telemetry unavailable')
    })
    recordInterruption.mockImplementationOnce(() => {
      throw new Error('interruption telemetry unavailable')
    })
    ;(runner as any).queuedExecutors.set(
      completedJob.tool,
      jest.fn(async (job: { id: string }) => {
        if (job.id === failedJob.id) throw new Error('worker failed on the second tick')
        return completedJobResult(job.id)
      })
    )

    await expect((runner as any).processNext()).resolves.toBeUndefined()
    await expect((runner as any).processNext()).resolves.toBeUndefined()

    expect(queue.statuses.get(completedJob.id)).toMatchObject({ status: 'completed' })
    expect(queue.statuses.get(failedJob.id)).toMatchObject({
      status: 'failed',
      error: 'worker failed on the second tick',
    })
    expect(queue.complete).toHaveBeenCalledTimes(2)
    expect(recordCompletion).toHaveBeenCalledTimes(1)
    expect(recordInterruption).toHaveBeenCalledTimes(1)
    expect((runner as any).activeControllers.size).toBe(0)
  })

  test('a stale runner never attributes the foreign winner completion after dual-queue takeover', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-runner-claim-loss-'))
    const databasePath = path.join(root, 'database.db')
    const databaseA = new DatabaseManager(databasePath)
    const sampleId = `sha256:${'a'.repeat(64)}`
    databaseA.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 1,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'runner-claim-loss-test',
    })
    const databaseB = new DatabaseManager(databasePath)
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    const policyGuard = {
      checkPermission: jest.fn(async () => ({ allowed: true, reason: 'test allowed' })),
      auditLog: jest.fn(async () => undefined),
    }
    const runner = new AnalysisTaskRunner(
      queueA,
      databaseA,
      {} as any,
      undefined,
      policyGuard as any
    )
    const releaseStaleWorker = deferred<void>()
    const staleWorkerStarted = deferred<void>()

    try {
      const jobId = queueA.enqueue({
        type: 'static',
        tool: 'workflow.reconstruct',
        sampleId,
        args: {},
        priority: 5,
        timeout: 60_000,
        retryPolicy: { maxRetries: 0, backoffMs: 0, retryableErrors: [] },
      })
      const job = queueA.listQueuedJobs()[0]
      selectNextJob.mockReturnValue(makeSelection(job as any))
      ;(runner as any).queuedExecutors.set(
        job.tool,
        jest.fn(async () => {
          staleWorkerStarted.resolve()
          await releaseStaleWorker.promise
          return completedJobResult(jobId)
        })
      )
      const staleComplete = jest.spyOn(queueA, 'complete')
      const processing = (runner as any).processNext() as Promise<void>
      await staleWorkerStarted.promise

      databaseA.runSql(
        `UPDATE jobs
         SET status = 'queued', started_at = NULL,
             owner_instance_id = NULL, owner_boot_id = NULL, claim_token = NULL,
             claim_until = NULL, claim_heartbeat_at = NULL
         WHERE id = ?`,
        [jobId]
      )
      expect(queueB.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 0 })
      expect(queueB.startQueuedJob(jobId)?.id).toBe(jobId)
      expect(
        queueB.complete(jobId, {
          ...completedJobResult(jobId),
          data: { owner: 'queue-b' },
        })
      ).toEqual({ committed: true, status: 'completed' })

      releaseStaleWorker.resolve()
      await processing

      expect(staleComplete.mock.results[0]?.value).toEqual({
        committed: false,
        reason: 'claim_lost',
        status: 'completed',
      })
      expect(recordCompletion).not.toHaveBeenCalled()
      expect(recordInterruption).not.toHaveBeenCalled()
      expect(databaseA.findJob(jobId)?.result_json).toContain('queue-b')
    } finally {
      releaseStaleWorker.resolve()
      await runner.stop()
      queueB.close()
      queueA.close()
      databaseB.close()
      databaseA.close()
      fs.rmSync(root, { recursive: true, force: true })
    }
  })
})
