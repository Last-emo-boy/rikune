import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import {
  createOrReuseAnalysisRun,
  getAnalysisRunSummary,
  upsertAnalysisRunStage,
} from '../../src/analysis/analysis-run-state.js'

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

  test('does not reuse runs across live execution or transformation policy changes', () => {
    const sample = database.findSample(sampleId)
    expect(sample).toBeTruthy()

    const baseline = createOrReuseAnalysisRun(database, {
      sample: sample!,
      goal: 'dynamic',
      depth: 'balanced',
      backendPolicy: 'auto',
      allowLiveExecution: false,
      allowTransformations: false,
    })

    const liveEnabled = createOrReuseAnalysisRun(database, {
      sample: sample!,
      goal: 'dynamic',
      depth: 'balanced',
      backendPolicy: 'auto',
      allowLiveExecution: true,
      allowTransformations: false,
    })

    const transformationsEnabled = createOrReuseAnalysisRun(database, {
      sample: sample!,
      goal: 'dynamic',
      depth: 'balanced',
      backendPolicy: 'auto',
      allowLiveExecution: false,
      allowTransformations: true,
    })

    expect(liveEnabled.reused).toBe(false)
    expect(transformationsEnabled.reused).toBe(false)
    expect(liveEnabled.run.id).not.toBe(baseline.run.id)
    expect(transformationsEnabled.run.id).not.toBe(baseline.run.id)
    expect(liveEnabled.compatibilityMarker).not.toBe(baseline.compatibilityMarker)
    expect(transformationsEnabled.compatibilityMarker).not.toBe(baseline.compatibilityMarker)
  })

  test('keeps a multi-stage run partial when only fast_profile completed', () => {
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
      stage: 'fast_profile',
      status: 'completed',
      executionState: 'completed',
      tool: 'workflow.analyze.start',
      result: { summary: 'Fast profile completed' },
      finishedAt: new Date().toISOString(),
    })

    const summary = getAnalysisRunSummary(database, runState.run.id)
    const persisted = database.findAnalysisRun(runState.run.id)

    expect(summary?.stage_plan).toEqual([
      'fast_profile',
      'enrich_static',
      'function_map',
      'summarize',
    ])
    expect(summary?.status).toBe('partial')
    expect(summary?.finished_at).toBeNull()
    expect(persisted?.status).toBe('partial')
    expect(persisted?.finished_at).toBeNull()
  })
})
