import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createGhidraAnalyzeHandler } from '../../src/tools/ghidra-analyze.js'

describe('ghidra.analyze tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-ghidra-analyze')
    testDbPath = path.join(process.cwd(), 'test-ghidra-analyze.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
  })

  function insertSample(sampleId: string, hashChar: string) {
    database.insertSample({
      id: sampleId,
      sha256: hashChar.repeat(64),
      md5: hashChar.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })
  }

  test('should reuse completed analysis instead of queueing a new job', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    insertSample(sampleId, '1')

    database.insertAnalysis({
      id: 'analysis-reuse-1',
      sample_id: sampleId,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'done',
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      output_json: JSON.stringify({
        function_count: 42,
        project_path: 'workspaces/sample/ghidra/project_reuse',
        project_key: 'reuse_key',
        readiness: {
          function_index: { available: true, status: 'ready' },
          decompile: { available: true, status: 'ready' },
          cfg: { available: true, status: 'ready' },
        },
      }),
      metrics_json: null,
    })

    const enqueue = jest.fn(async () => 'job-should-not-be-used')
    const handler = createGhidraAnalyzeHandler(
      workspaceManager,
      database,
      { enqueue } as any
    )

    const result = await handler({ sample_id: sampleId })
    const payload = JSON.parse(String(result.content[0]?.text || '{}'))

    expect(payload.ok).toBe(true)
    expect(payload.data.analysis_id).toBe('analysis-reuse-1')
    expect(payload.data.status).toBe('reused')
    expect(payload.data.function_count).toBe(42)
    expect(enqueue).not.toHaveBeenCalled()
  })

  test('should return matching job_id when queueing a fresh analysis', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    insertSample(sampleId, '2')

    const enqueue = jest.fn(async () => 'job-123')
    const handler = createGhidraAnalyzeHandler(
      workspaceManager,
      database,
      { enqueue } as any
    )

    const result = await handler({
      sample_id: sampleId,
      options: { timeout: 60, max_cpu: '2' },
    })
    const payload = JSON.parse(String(result.content[0]?.text || '{}'))

    expect(payload.ok).toBe(true)
    expect(payload.data.analysis_id).toBe('job-123')
    expect(payload.data.job_id).toBe('job-123')
    expect(payload.data.status).toBe('queued')
    expect(enqueue).toHaveBeenCalledTimes(1)
  })
})
