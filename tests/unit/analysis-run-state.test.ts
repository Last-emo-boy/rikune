import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { createOrReuseAnalysisRun, upsertAnalysisRunStage } from '../../src/analysis/analysis-run-state.js'

describe('analysis run state', () => {
  let database: DatabaseManager
  let testDbPath: string
  const sampleId = 'sha256:' + '8'.repeat(64)

  beforeEach(() => {
    testDbPath = path.join(process.cwd(), 'test-analysis-run-state.db')
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    database = new DatabaseManager(testDbPath)
    database.insertSample({
      id: sampleId,
      sha256: '8'.repeat(64),
      md5: '8'.repeat(32),
      size: 4096,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    })
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
  })

  test('preserves queued job id when a stage transitions without resupplying it', () => {
    const sample = database.findSample(sampleId)
    expect(sample).toBeTruthy()
    const runState = createOrReuseAnalysisRun(database, {
      sample: sample!,
      goal: 'static',
      depth: 'balanced',
      backendPolicy: 'auto',
    })

    upsertAnalysisRunStage(database, {
      runId: runState.run.id,
      stage: 'function_map',
      status: 'queued',
      executionState: 'queued',
      tool: 'workflow.analyze.stage',
      jobId: 'job-123',
      metadata: { execution_bucket: 'heavy' },
    })

    upsertAnalysisRunStage(database, {
      runId: runState.run.id,
      stage: 'function_map',
      status: 'running',
      executionState: 'queued',
      tool: 'workflow.analyze.stage',
      metadata: { force_refresh: false },
    })

    const row = database.findAnalysisRunStage(runState.run.id, 'function_map')
    expect(row?.job_id).toBe('job-123')
    expect(JSON.parse(row?.metadata_json || '{}')).toMatchObject({
      execution_bucket: 'heavy',
      force_refresh: false,
    })
  })
})
