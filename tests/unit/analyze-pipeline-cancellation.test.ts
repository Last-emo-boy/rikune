import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { CacheManager } from '../../src/cache-manager.js'
import { DATABASE_FIXTURE_CAPABILITY, DatabaseManager } from '../../src/database.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import {
  createOrReuseAnalysisRun,
  type AnalysisPipelineStage,
} from '../../src/analysis/analysis-run-state.js'
import {
  createAnalyzePipelineStageContext,
  executeQueuedAnalysisStage,
  type AnalyzePipelineDependencies,
} from '../../src/workflows/analyze-pipeline.js'

const SAMPLE_HASH = '9'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

function workerResult(data: Record<string, unknown> = { completed: true }) {
  return {
    ok: true,
    data,
    errors: [],
    warnings: [],
    artifacts: [],
    metrics: { elapsed_ms: 1 },
  }
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

describe('queued analyze pipeline cancellation', () => {
  let tempRoot: string
  let database: DatabaseManager
  let workspaceManager: WorkspaceManager
  let cacheManager: CacheManager
  let policyGuard: PolicyGuard

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-pipeline-cancel-'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    cacheManager = new CacheManager(path.join(tempRoot, 'cache'), database)
    policyGuard = new PolicyGuard(path.join(tempRoot, 'audit.log'))
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '9'.repeat(32),
      size: 16,
      file_type: 'PE',
      created_at: new Date('2026-08-23T00:00:00.000Z').toISOString(),
      source: 'pipeline-cancellation-test',
    })
    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), Buffer.from('MZtest'))
  })

  afterEach(() => {
    database.close()
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  function createRun(
    stage: AnalysisPipelineStage,
    options: { allowLiveExecution?: boolean; allowTransformations?: boolean } = {}
  ) {
    const sample = database.findSample(SAMPLE_ID)
    if (!sample) throw new Error('missing sample fixture')
    return createOrReuseAnalysisRun(database, {
      sample,
      goal: stage === 'dynamic_plan' || stage === 'dynamic_execute' ? 'dynamic' : 'reverse',
      depth: 'balanced',
      backendPolicy: 'auto',
      forceRefresh: true,
      stagePlan: [stage],
      allowLiveExecution: options.allowLiveExecution,
      allowTransformations: options.allowTransformations,
    }).run
  }

  async function execute(
    stage: AnalysisPipelineStage,
    dependencies: AnalyzePipelineDependencies,
    signal: AbortSignal,
    options: { allowLiveExecution?: boolean; allowTransformations?: boolean } = {}
  ) {
    const run = createRun(stage, options)
    const context = createAnalyzePipelineStageContext(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      dependencies
    )
    const result = await executeQueuedAnalysisStage(context, { run_id: run.id, stage }, signal)
    return { result, run }
  }

  test('function_map forwards the same signal to Ghidra and Rizin', async () => {
    const controller = new AbortController()
    const ghidraAnalyze = jest.fn(async (_args, signal) =>
      workerResult({
        analysis_id: 'analysis-1',
        status: 'completed',
        result_mode: 'completed',
        function_count: 1,
        function_index_ready: true,
      })
    )
    const rizinAnalyze = jest.fn(async () => workerResult({ functions: [] }))

    const { result } = await execute(
      'function_map',
      { ghidraAnalyze, rizinAnalyze },
      controller.signal
    )

    expect(result.ok).toBe(true)
    expect(ghidraAnalyze.mock.calls[0]?.[1]).toBe(controller.signal)
    expect(rizinAnalyze.mock.calls[0]?.[1]).toBe(controller.signal)
  })

  test('reconstruct forwards the same signal to primary, angr, and RetDec handlers', async () => {
    const controller = new AbortController()
    const reconstructWorkflow = jest.fn(async () => workerResult())
    const angrAnalyze = jest.fn(async () => workerResult())
    const retdecDecompile = jest.fn(async () => workerResult())

    const { result } = await execute(
      'reconstruct',
      { reconstructWorkflow, angrAnalyze, retdecDecompile },
      controller.signal
    )

    expect(result.ok).toBe(true)
    for (const handler of [reconstructWorkflow, angrAnalyze, retdecDecompile]) {
      expect(handler.mock.calls[0]?.[1]).toBe(controller.signal)
    }
  })

  test.each([
    ['semantic_name_review', 'semanticNameReviewWorkflow'],
    ['semantic_explain_review', 'functionExplanationReviewWorkflow'],
    ['semantic_module_review', 'moduleReconstructionReviewWorkflow'],
  ] as const)('%s forwards the same signal to its semantic workflow', async (stage, key) => {
    const controller = new AbortController()
    const handler = jest.fn(async () => workerResult({ review: { review_status: 'no_targets' } }))

    const { result } = await execute(
      stage,
      { [key]: handler } as AnalyzePipelineDependencies,
      controller.signal
    )

    expect(result.ok).toBe(true)
    expect(handler.mock.calls[0]?.[1]).toBe(controller.signal)
  })

  test('dynamic_plan forwards the same signal through every planning handler', async () => {
    const controller = new AbortController()
    const handlers = {
      staticBehaviorClassify: jest.fn(async () => workerResult()),
      dynamicDependencies: jest.fn(async () => workerResult()),
      qilingInspect: jest.fn(async () => workerResult()),
      pandaInspect: jest.fn(async () => workerResult()),
      breakpointSmart: jest.fn(async () => workerResult()),
      dynamicDeepPlan: jest.fn(async () => workerResult()),
      traceCondition: jest.fn(async () => workerResult()),
    }

    const { result } = await execute('dynamic_plan', handlers, controller.signal)

    expect(result.ok).toBe(true)
    for (const handler of Object.values(handlers)) {
      expect(handler.mock.calls[0]?.[1]).toBe(controller.signal)
    }
  })

  test('dynamic_execute forwards the stage signal to sandbox execution', async () => {
    const controller = new AbortController()
    const sandboxExecute = jest.fn(async () => workerResult({ status: 'completed' }))

    const { result } = await execute('dynamic_execute', { sandboxExecute }, controller.signal, {
      allowLiveExecution: true,
    })

    expect(result.ok).toBe(true)
    expect(sandboxExecute.mock.calls[0]?.[1]).toBe(controller.signal)
  })

  test('summarize forwards the stage signal to the summarize workflow', async () => {
    const controller = new AbortController()
    const workflowSummarize = jest.fn(async () => workerResult())

    const { result } = await execute('summarize', { workflowSummarize }, controller.signal)

    expect(result.ok).toBe(true)
    expect(workflowSummarize.mock.calls[0]?.[1]).toBe(controller.signal)
  })

  test('abort waits for real stage-handler teardown before persisting partial state', async () => {
    const controller = new AbortController()
    const started = deferred<AbortSignal>()
    const teardown = deferred<void>()
    const events: string[] = []
    const workflowSummarize = jest.fn(async (_args, signal?: AbortSignal) => {
      if (!signal) throw new Error('missing AbortSignal')
      started.resolve(signal)
      await new Promise<void>((resolve) => {
        signal.addEventListener('abort', () => resolve(), { once: true })
      })
      events.push('abort-observed')
      await teardown.promise
      events.push('teardown-complete')
      return workerResult()
    })
    const run = createRun('summarize')
    const context = createAnalyzePipelineStageContext(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      { workflowSummarize }
    )
    let settled = false
    const executing = executeQueuedAnalysisStage(
      context,
      { run_id: run.id, stage: 'summarize' },
      controller.signal
    ).finally(() => {
      settled = true
    })

    const receivedSignal = await started.promise
    controller.abort(new Error('cancel stage'))
    await Promise.resolve()

    expect(receivedSignal).toBe(controller.signal)
    expect(settled).toBe(false)
    expect(events).toEqual(['abort-observed'])

    teardown.resolve()
    const result = await executing
    expect(result.ok).toBe(false)
    expect(events).toEqual(['abort-observed', 'teardown-complete'])
    expect(database.findAnalysisRunStage(run.id, 'summarize')).toMatchObject({
      status: 'partial',
      execution_state: 'partial',
    })
  })

  test('default lazy summarize handler preserves a pre-aborted signal', async () => {
    const context = createAnalyzePipelineStageContext(
      workspaceManager,
      database,
      cacheManager,
      policyGuard
    )
    const controller = new AbortController()
    controller.abort(new Error('cancel before lazy load'))

    await expect(
      context.dependencies.workflowSummarize?.(
        { sample_id: SAMPLE_ID, through_stage: 'final' },
        controller.signal
      )
    ).rejects.toMatchObject({ name: 'AbortError' })
  })
})
