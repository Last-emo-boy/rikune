import { afterEach, describe, expect, test } from '@jest/globals'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseManager, DATABASE_FIXTURE_CAPABILITY } from '../../src/database.js'
import { JobPriority, JobQueue } from '../../src/job-queue.js'
import { SampleOperationGate } from '../../src/sample/sample-operation-gate.js'

const SAMPLE_ID = `sha256:${'d'.repeat(64)}`

describe('JobQueue durable multi-instance claims', () => {
  const cleanups: Array<() => void> = []

  afterEach(() => {
    while (cleanups.length > 0) cleanups.pop()?.()
  })

  function createDatabases(): {
    root: string
    databaseA: DatabaseManager
    databaseB: DatabaseManager
  } {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-job-claim-'))
    const databasePath = path.join(root, 'database.db')
    const databaseA = new DatabaseManager(databasePath)
    databaseA.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: 'd'.repeat(64),
      md5: 'e'.repeat(32),
      size: 1,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'durable-job-test',
    })
    const databaseB = new DatabaseManager(databasePath)
    cleanups.push(() => {
      databaseB.close()
      databaseA.close()
      fs.rmSync(root, { recursive: true, force: true })
    })
    return { root, databaseA, databaseB }
  }

  function enqueue(queue: JobQueue): string {
    return queue.enqueue({
      type: 'analysis',
      tool: 'test.tool',
      sampleId: SAMPLE_ID,
      args: {},
      priority: JobPriority.NORMAL,
      timeout: 5_000,
      retryPolicy: { maxRetries: 2, backoffMs: 123_456, retryableErrors: ['E_TIMEOUT'] },
    })
  }

  function failedResult(jobId: string) {
    return {
      jobId,
      ok: false,
      errors: ['E_TIMEOUT'],
      warnings: [],
      artifacts: [],
      metrics: { elapsedMs: 1, peakRssMb: 1 },
    }
  }

  async function waitUntil(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (!predicate() && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    expect(predicate()).toBe(true)
  }

  test('two queues sharing SQLite have exactly one queued-to-running winner', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    expect(queueB.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 0 })

    expect(queueA.startQueuedJob(jobId)?.id).toBe(jobId)
    expect(queueB.startQueuedJob(jobId)).toBeUndefined()
    expect(databaseA.findJob(jobId)).toEqual(
      expect.objectContaining({
        status: 'running',
        claim_token: expect.any(String),
        owner_instance_id: expect.any(String),
      })
    )
  })

  test('startup leaves another live owner running and only interrupts an expired claim', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    cleanups.push(() => queueA.close())
    const jobId = enqueue(queueA)
    expect(queueA.startQueuedJob(jobId)?.id).toBe(jobId)

    const liveObserver = new JobQueue(databaseB)
    cleanups.push(() => liveObserver.close())
    expect(liveObserver.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 0 })
    expect(liveObserver.getStatus(jobId)?.status).toBe('running')
    expect(liveObserver.listQueuedJobs()).toHaveLength(0)

    databaseA.runSql('UPDATE jobs SET claim_until = ? WHERE id = ?', [
      new Date(0).toISOString(),
      jobId,
    ])
    const recovery = new JobQueue(databaseB)
    cleanups.push(() => recovery.close())
    expect(recovery.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 1 })
    expect(databaseB.findJob(jobId)?.status).toBe('interrupted')
  })

  test('crash recovery preserves retry count and the exact retry policy', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    cleanups.push(() => queueA.close())
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    queueA.complete(jobId, {
      jobId,
      ok: false,
      errors: ['E_TIMEOUT'],
      warnings: [],
      artifacts: [],
      metrics: { elapsedMs: 1, peakRssMb: 1 },
    })
    expect(databaseA.findJob(jobId)).toEqual(
      expect.objectContaining({ status: 'retry_wait', retry_count: 1 })
    )
    databaseA.runSql('UPDATE jobs SET claim_until = ? WHERE id = ?', [
      new Date(0).toISOString(),
      jobId,
    ])

    const recovery = new JobQueue(databaseB)
    cleanups.push(() => recovery.close())
    expect(recovery.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 0 })
    expect(recovery.listQueuedJobs()[0]).toEqual(
      expect.objectContaining({
        attempts: 1,
        retryPolicy: {
          maxRetries: 2,
          backoffMs: 123_456,
          retryableErrors: ['E_TIMEOUT'],
        },
      })
    )
  })

  test('periodically reconciles a foreign claim that expires after bootstrap', async () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA, undefined, {
      jobClaimTtlMs: 100,
      heartbeatIntervalMs: 20,
    })
    const queueB = new JobQueue(databaseB, undefined, {
      jobClaimTtlMs: 100,
      heartbeatIntervalMs: 20,
    })
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    expect(queueB.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 0 })

    queueA.close()
    await waitUntil(() => databaseB.findJob(jobId)?.status === 'interrupted')
    expect(queueB.getStatus(jobId)?.status).toBe('interrupted')
  })

  test('graceful close durably requeues retry_wait without waiting for claim expiry', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    queueA.complete(jobId, failedResult(jobId))
    expect(databaseA.findJob(jobId)?.status).toBe('retry_wait')

    queueA.close()
    expect(databaseA.findJob(jobId)).toEqual(
      expect.objectContaining({ status: 'queued', claim_token: null })
    )
    expect(queueB.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 0 })
    expect(queueB.listQueuedJobs().map((job) => job.id)).toContain(jobId)
  })

  test('a non-owner can terminally cancel retry_wait and the owner cleans up', async () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA, undefined, {
      heartbeatIntervalMs: 20,
      jobClaimTtlMs: 200,
    })
    const queueB = new JobQueue(databaseB, undefined, {
      heartbeatIntervalMs: 20,
      jobClaimTtlMs: 200,
    })
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    queueA.complete(jobId, failedResult(jobId))
    queueB.restoreFromDatabase()

    expect(queueB.cancel(jobId, 'remote cancel')).toBe(true)
    expect(databaseB.findJob(jobId)).toEqual(
      expect.objectContaining({ status: 'cancelled', claim_token: null })
    )
    await waitUntil(() => queueA.getStatus(jobId)?.status === 'cancelled')
  })

  test('claim loss after worker exit keeps durable owner state and releases the sample lease', () => {
    const { databaseA, databaseB } = createDatabases()
    const gateA = new SampleOperationGate(databaseA, {
      instanceId: 'claim-loss-owner',
      bootId: 'claim-loss-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    const queueA = new JobQueue(databaseA, gateA)
    cleanups.push(() => {
      queueA.close()
      gateA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    databaseA.runSql('UPDATE jobs SET claim_until = ? WHERE id = ?', [
      new Date(0).toISOString(),
      jobId,
    ])
    expect(
      databaseB.recoverExpiredJobClaim(jobId, new Date().toISOString(), 'foreign recovery')
    ).toBe('interrupted')

    expect(() =>
      queueA.complete(jobId, {
        jobId,
        ok: true,
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1, peakRssMb: 1 },
      })
    ).not.toThrow()
    expect(databaseA.findJob(jobId)?.status).toBe('interrupted')
    expect(queueA.getStatus(jobId)?.status).toBe('interrupted')
    expect(
      databaseA.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
        [SAMPLE_ID]
      )?.count
    ).toBe(0)
  })

  test('a late settlement reports claim loss after another queue takes over and completes', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    expect(queueA.startQueuedJob(jobId)?.id).toBe(jobId)

    // Deterministically model an expired-claim takeover while queue A's worker
    // is still running. Queue B then owns and commits the durable result.
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
    const winnerResult = {
      jobId,
      ok: true,
      data: { owner: 'queue-b' },
      errors: [] as string[],
      warnings: [] as string[],
      artifacts: [],
      metrics: { elapsedMs: 1, peakRssMb: 1 },
    }
    expect(queueB.complete(jobId, winnerResult)).toEqual({
      committed: true,
      status: 'completed',
    })

    const lateOutcome = queueA.complete(jobId, {
      ...winnerResult,
      data: { owner: 'stale-queue-a' },
    })

    expect(lateOutcome).toEqual({
      committed: false,
      reason: 'claim_lost',
      status: 'completed',
    })
    expect(databaseA.findJob(jobId)?.result_json).toBe(JSON.stringify(winnerResult))
  })

  test('a durable CAS loser releases its pre-enqueue sample lease', () => {
    const { databaseA, databaseB } = createDatabases()
    const gateA = new SampleOperationGate(databaseA, {
      instanceId: 'cas-owner-a',
      bootId: 'cas-boot-a',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    const gateB = new SampleOperationGate(databaseB, {
      instanceId: 'cas-owner-b',
      bootId: 'cas-boot-b',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    const queueA = new JobQueue(databaseA, gateA)
    const queueB = new JobQueue(databaseB, gateB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
      gateB.close()
      gateA.close()
    })
    const jobId = enqueue(queueA)
    queueB.restoreFromDatabase()
    expect(queueB.startQueuedJob(jobId)?.id).toBe(jobId)
    expect(queueA.startQueuedJob(jobId)).toBeUndefined()
    expect(
      databaseA.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
        [SAMPLE_ID]
      )?.count
    ).toBe(1)
    queueB.complete(jobId, {
      jobId,
      ok: true,
      errors: [],
      warnings: [],
      artifacts: [],
      metrics: { elapsedMs: 1, peakRssMb: 1 },
    })
    expect(
      databaseA.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
        [SAMPLE_ID]
      )?.count
    ).toBe(0)
  })

  test('live claimed invalid JSON is never interrupted by a rolling observer', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    databaseA.runSql('UPDATE jobs SET args_json = ? WHERE id = ?', ['{invalid', jobId])

    expect(queueB.restoreFromDatabase()).toEqual({ restored: 0, interrupted: 0 })
    expect(
      databaseA.queryOneSql<{ status: string }>('SELECT status FROM jobs WHERE id = ?', [jobId])
        ?.status
    ).toBe('running')
  })

  test('active restore pagination cannot be crowded out by terminal history', () => {
    const { databaseA, databaseB } = createDatabases()
    const producer = new JobQueue(databaseA)
    cleanups.push(() => producer.close())
    const activeIds = Array.from({ length: 5 }, () => enqueue(producer))
    for (let index = 0; index < 10; index++) {
      const terminalId = enqueue(producer)
      producer.startQueuedJob(terminalId)
      producer.complete(terminalId, {
        jobId: terminalId,
        ok: true,
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1, peakRssMb: 1 },
      })
    }
    const observer = new JobQueue(databaseB, undefined, { restorePageSize: 2 })
    cleanups.push(() => observer.close())

    observer.restoreFromDatabase()
    expect(
      observer
        .listQueuedJobs()
        .map((job) => job.id)
        .sort()
    ).toEqual(activeIds.sort())
  })

  test('a rolling observer refreshes foreign completion and preserves the exact result shape', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    expect(queueB.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 0 })
    expect(queueB.getStatus(jobId)?.status).toBe('running')

    const result = {
      jobId,
      ok: true,
      data: { verdict: 'exact-result' },
      errors: [] as string[],
      warnings: ['bounded warning'],
      artifacts: [],
      metrics: { elapsedMs: 7, peakRssMb: 2 },
    }
    queueA.complete(jobId, result)

    expect(queueB.getStatus(jobId)?.status).toBe('completed')
    expect(queueB.getResult(jobId)).toEqual(result)
    expect(queueB.listStatuses().find((row) => row.id === jobId)?.status).toBe('completed')
  })

  test('a rolling observer refreshes a foreign retry_wait after it is durably requeued', async () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = queueA.enqueue({
      type: 'analysis',
      tool: 'test.tool',
      sampleId: SAMPLE_ID,
      args: {},
      priority: JobPriority.NORMAL,
      timeout: 5_000,
      retryPolicy: { maxRetries: 1, backoffMs: 20, retryableErrors: ['E_TIMEOUT'] },
    })
    queueA.startQueuedJob(jobId)
    queueA.complete(jobId, failedResult(jobId))
    expect(queueB.restoreFromDatabase()).toEqual({ restored: 1, interrupted: 0 })
    expect(queueB.getStatus(jobId)?.status).toBe('retry_wait')

    await waitUntil(() => databaseA.findJob(jobId)?.status === 'queued')
    expect(queueB.getStatus(jobId)?.status).toBe('queued')
    expect(queueB.listQueuedJobs().map((job) => job.id)).toContain(jobId)
  })

  test('a stale retry_wait observer cancels the foreign running retry truthfully', async () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = queueA.enqueue({
      type: 'analysis',
      tool: 'test.tool',
      sampleId: SAMPLE_ID,
      args: {},
      priority: JobPriority.NORMAL,
      timeout: 5_000,
      retryPolicy: { maxRetries: 1, backoffMs: 20, retryableErrors: ['E_TIMEOUT'] },
    })
    queueA.startQueuedJob(jobId)
    queueA.complete(jobId, failedResult(jobId))
    queueB.restoreFromDatabase()
    expect(queueB.getStatus(jobId)?.status).toBe('retry_wait')
    await waitUntil(() => databaseA.findJob(jobId)?.status === 'queued')
    expect(queueA.startQueuedJob(jobId)?.id).toBe(jobId)

    expect(queueB.cancel(jobId, 'stale observer cancel')).toBe(true)
    expect(databaseB.findJob(jobId)?.status).toBe('cancelling')
    queueA.complete(jobId, failedResult(jobId))
    expect(databaseA.findJob(jobId)?.status).toBe('interrupted')
  })

  test('remote cancellation racing a stale reaper is accepted without losing the owner claim', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    queueB.restoreFromDatabase()

    expect(queueB.cancel(jobId, 'remote request')).toBe(true)
    expect(() => queueA.reapStaleRunningJobs(0, Date.now() + 1_000)).not.toThrow()
    expect(queueA.getStatus(jobId)?.status).toBe('cancelling')
    queueA.complete(jobId, failedResult(jobId))
    expect(databaseA.findJob(jobId)).toEqual(
      expect.objectContaining({ status: 'interrupted', claim_token: null })
    )
  })

  test('the owner accepts a repeated remote cancellation before its next heartbeat', () => {
    const { databaseA, databaseB } = createDatabases()
    const queueA = new JobQueue(databaseA)
    const queueB = new JobQueue(databaseB)
    cleanups.push(() => {
      queueB.close()
      queueA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    queueB.restoreFromDatabase()

    expect(queueB.cancel(jobId, 'remote request')).toBe(true)
    let ownerOutcome = false
    expect(() => {
      ownerOutcome = queueA.cancel(jobId, 'owner repeat')
    }).not.toThrow()
    expect(ownerOutcome).toBe(true)
    expect(queueA.getStatus(jobId)?.status).toBe('cancelling')
    queueA.complete(jobId, failedResult(jobId))
    expect(databaseA.findJob(jobId)?.status).toBe('interrupted')
  })

  test('lost sample lease cancels the worker claim and converges without restart', async () => {
    const { databaseA } = createDatabases()
    const gateA = new SampleOperationGate(databaseA, {
      instanceId: 'sample-lease-loss-owner',
      bootId: 'sample-lease-loss-boot',
      sharedLeaseTtlMs: 300,
      instanceTtlMs: 600,
      startHeartbeat: false,
    })
    const queueA = new JobQueue(databaseA, gateA, {
      heartbeatIntervalMs: 20,
      jobClaimTtlMs: 300,
    })
    cleanups.push(() => {
      queueA.close()
      gateA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    databaseA.runSql('DELETE FROM sample_operation_leases WHERE sample_id = ?', [SAMPLE_ID])

    await waitUntil(() => queueA.getStatus(jobId)?.status === 'cancelling')
    expect(databaseA.findJob(jobId)?.status).toBe('cancelling')
    expect(() => queueA.complete(jobId, failedResult(jobId))).not.toThrow()
    expect(databaseA.findJob(jobId)).toEqual(
      expect.objectContaining({ status: 'interrupted', claim_token: null })
    )
    expect(
      databaseA.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
        [SAMPLE_ID]
      )?.count
    ).toBe(0)
  })

  test('worker completion detects lease loss before the next heartbeat tick', () => {
    const { databaseA } = createDatabases()
    const gateA = new SampleOperationGate(databaseA, {
      instanceId: 'immediate-lease-loss-owner',
      bootId: 'immediate-lease-loss-boot',
      sharedLeaseTtlMs: 900,
      instanceTtlMs: 1_800,
      startHeartbeat: false,
    })
    const queueA = new JobQueue(databaseA, gateA, {
      heartbeatIntervalMs: 300,
      jobClaimTtlMs: 900,
    })
    cleanups.push(() => {
      queueA.close()
      gateA.close()
    })
    const jobId = enqueue(queueA)
    queueA.startQueuedJob(jobId)
    databaseA.runSql('DELETE FROM sample_operation_leases WHERE sample_id = ?', [SAMPLE_ID])

    expect(() => queueA.complete(jobId, failedResult(jobId))).not.toThrow()
    expect(databaseA.findJob(jobId)).toEqual(
      expect.objectContaining({ status: 'interrupted', claim_token: null })
    )
  })
})
