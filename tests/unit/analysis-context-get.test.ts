import { DATABASE_FIXTURE_CAPABILITY } from '../../src/database.js'
import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { JobQueue } from '../../src/job-queue.js'
import { createAnalysisContextGetHandler } from '../../src/tools/analysis-context-get.js'

describe('analysis.context.get tool', () => {
  let tempDir: string
  let database: DatabaseManager
  let cacheManager: CacheManager
  let jobQueue: JobQueue

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'analysis-context-get-test-'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    cacheManager = new CacheManager(path.join(tempDir, 'cache'), database)
    jobQueue = new JobQueue(database)
  })

  afterEach(async () => {
    jobQueue.close()
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should return reuse hints for active jobs and sample cache entries', async () => {
    const sampleId = `sha256:${'a'.repeat(64)}`
    const sampleSha = 'a'.repeat(64)
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: sampleSha,
      md5: 'b'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: '2026-01-01T00:00:00.000Z',
      source: 'test',
    })
    await cacheManager.setCachedResult('cache:test-context', { ok: true }, undefined, sampleSha)
    const jobId = jobQueue.enqueue({
      type: 'static',
      tool: 'attack.map',
      sampleId,
      args: { sample_id: sampleId },
      priority: 5,
      timeout: 600000,
    })

    const handler = createAnalysisContextGetHandler(database, jobQueue)
    const result = await handler({ sample_id: sampleId, intended_tool: 'attack.map' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.result_mode).toBe('preflight')
    expect(data.reuse_hints.active_jobs).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: jobId, tool: 'attack.map' })])
    )
    expect(data.reuse_hints.cache.entry_count).toBe(1)
    expect(data.recommended_next_tools).toContain('task.status')
  })
})
