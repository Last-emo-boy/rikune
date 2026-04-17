/**
 * Integration tests for workflows
 */

import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { CacheManager } from '../../src/cache-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { JobQueue } from '../../src/job-queue.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import {
  ANALYSIS_STAGE_JOB_TOOL,
  createAnalyzePipelineStageContext,
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
  createAnalyzeWorkflowStatusHandler,
  executeQueuedAnalysisStage,
} from '../../src/workflows/analyze-pipeline.js'

function makeUnavailableBackendResolution() {
  return {
    capa_cli: { available: false },
    capa_rules: { available: false },
    die: { available: false },
    graphviz: { available: false },
    rizin: { available: false },
    upx: { available: false },
    wine: { available: false },
    winedbg: { available: false },
    frida_cli: { available: false },
    yara_x: { available: false },
    qiling: { available: false },
    angr: { available: false },
    panda: { available: false },
    retdec: { available: false },
  } as any
}

describe('Workflow Integration', () => {
  let testDir: string
  let database: DatabaseManager
  let workspaceManager: WorkspaceManager
  let policyGuard: PolicyGuard
  let cacheManager: CacheManager
  let jobQueue: JobQueue

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'workflow-integration-'))
    database = new DatabaseManager(path.join(testDir, 'test.db'))
    workspaceManager = new WorkspaceManager(path.join(testDir, 'workspaces'))
    policyGuard = new PolicyGuard(path.join(testDir, 'audit.log'))
    cacheManager = new CacheManager(path.join(testDir, 'cache'), database)
    jobQueue = new JobQueue(database)

    database.insertSample({
      id: `sha256:${'a'.repeat(64)}`,
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date('2026-04-17T00:00:00.000Z').toISOString(),
      source: 'integration-test',
    })
  })

  afterEach(() => {
    database.close()
    fs.rmSync(testDir, { recursive: true, force: true })
  })

  test('starts, reuses, and promotes a persisted staged analysis run', async () => {
    const sharedDependencies = {
      peFingerprint: async () => ({
        ok: true,
        data: {
          format: 'pe',
          arch: 'x86_64',
        },
      }),
      runtimeDetect: async () => ({
        ok: true,
        data: {
          runtime: 'native',
        },
      }),
      peImportsExtract: async () => ({
        ok: true,
        data: {
          imports: {
            kernel32: ['CreateFileW', 'WriteFile'],
          },
        },
      }),
      stringsExtract: async () => ({
        ok: true,
        data: {
          strings: [
            { string: 'http://example.invalid/c2' },
            { string: 'cmd.exe /c whoami' },
          ],
        },
      }),
      yaraScan: async () => ({
        ok: true,
        data: {
          matches: [{ rule: 'suspicious_downloader' }],
        },
      }),
      packerDetect: async () => ({
        ok: true,
        data: {
          packed: false,
          confidence: 0.02,
        },
      }),
      compilerPackerDetect: async () => ({
        ok: true,
        data: {
          summary: null,
          packer_findings: [],
        },
      }),
      binaryRoleProfile: async () => ({
        ok: true,
        data: {
          role: 'loader',
          confidence: 0.81,
        },
      }),
      resolveBackends: () => makeUnavailableBackendResolution(),
    }

    const start = createAnalyzeWorkflowStartHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      sharedDependencies,
      jobQueue
    )
    const status = createAnalyzeWorkflowStatusHandler(database, sharedDependencies, jobQueue)
    const promote = createAnalyzeWorkflowPromoteHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      sharedDependencies,
      jobQueue
    )

    const startResult = await start({
      sample_id: `sha256:${'a'.repeat(64)}`,
      goal: 'triage',
      depth: 'balanced',
      backend_policy: 'auto',
      allow_transformations: false,
      allow_live_execution: false,
      force_refresh: false,
    })

    expect(startResult.ok).toBe(true)
    const started = startResult.data as any
    expect(started.reused).toBe(false)
    expect(started.execution_state).toBe('completed')
    expect(started.current_stage).toBe('fast_profile')
    expect(started.run.run_id).toBe(started.run_id)
    expect(started.run.sample_id).toBe(`sha256:${'a'.repeat(64)}`)
    expect(started.run.stage_plan).toEqual([
      'fast_profile',
      'enrich_static',
      'function_map',
      'summarize',
    ])
    expect(started.stage_result.summary).toContain('Fast profile completed')
    expect(started.recommended_next_tools).toContain('workflow.analyze.promote')
    expect(started.deferred_jobs).toEqual([])

    const reuseResult = await start({
      sample_id: `sha256:${'a'.repeat(64)}`,
      goal: 'triage',
      depth: 'balanced',
      backend_policy: 'auto',
      allow_transformations: false,
      allow_live_execution: false,
      force_refresh: false,
    })

    expect(reuseResult.ok).toBe(true)
    const reused = reuseResult.data as any
    expect(reused.reused).toBe(true)
    expect(reused.execution_state).toBe('reused')
    expect(reused.run_id).toBe(started.run_id)

    const promoteResult = await promote({
      run_id: started.run_id,
      through_stage: 'function_map',
      force_refresh: false,
    })

    expect(promoteResult.ok).toBe(true)
    const promoted = promoteResult.data as any
    expect(promoted.execution_state).toBe('queued')
    expect(promoted.stage_result.queued_stages).toEqual(['enrich_static', 'function_map'])
    expect(promoted.deferred_jobs).toHaveLength(2)
    expect(promoted.deferred_jobs.map((job: any) => job.stage)).toEqual([
      'enrich_static',
      'function_map',
    ])

    const queuedJobs = jobQueue.listQueuedJobs()
    expect(queuedJobs).toHaveLength(2)
    expect(queuedJobs.every((job) => job.tool === ANALYSIS_STAGE_JOB_TOOL)).toBe(true)

    const enrichStage = database.findAnalysisRunStage(started.run_id, 'enrich_static')
    const functionMapStage = database.findAnalysisRunStage(started.run_id, 'function_map')
    expect(enrichStage?.status).toBe('queued')
    expect(enrichStage?.tool).toBe(ANALYSIS_STAGE_JOB_TOOL)
    expect(functionMapStage?.status).toBe('queued')
    expect(functionMapStage?.tool).toBe(ANALYSIS_STAGE_JOB_TOOL)

    const statusResult = await status({ run_id: started.run_id })

    expect(statusResult.ok).toBe(true)
    const current = statusResult.data as any
    expect(current.execution_state).toBe('queued')
    expect(current.run.status).toBe('queued')
    expect(current.run.latest_stage).toBe('function_map')
    expect(current.deferred_jobs).toHaveLength(2)
    expect(current.deferred_jobs.map((job: any) => job.stage)).toEqual([
      'enrich_static',
      'function_map',
    ])
    expect(current.recommended_next_tools).toContain('workflow.analyze.status')
  })

  test('records bounded dynamic_execute output when runtime-backed sandbox execution is unsupported', async () => {
    const sharedDependencies = {
      peFingerprint: async () => ({
        ok: true,
        data: {
          format: 'pe',
          arch: 'x86_64',
        },
      }),
      runtimeDetect: async () => ({
        ok: true,
        data: {
          runtime: 'native',
        },
      }),
      peImportsExtract: async () => ({ ok: true, data: { imports: {} } }),
      stringsExtract: async () => ({ ok: true, data: { strings: [] } }),
      yaraScan: async () => ({ ok: true, data: { matches: [] } }),
      packerDetect: async () => ({ ok: true, data: { packed: false, confidence: 0.01 } }),
      compilerPackerDetect: async () => ({ ok: true, data: { summary: null, packer_findings: [] } }),
      binaryRoleProfile: async () => ({ ok: true, data: { role: 'loader', confidence: 0.72 } }),
      resolveBackends: () => makeUnavailableBackendResolution(),
      dynamicDependencies: async () => ({
        ok: true,
        data: { status: 'ready', recommended_next_tools: ['dynamic.dependencies'] },
      }),
      qilingInspect: async () => ({ ok: true, data: { status: 'ready' } }),
      pandaInspect: async () => ({ ok: true, data: { status: 'ready' } }),
      breakpointSmart: async () => ({ ok: true, data: { breakpoints: [] } }),
      traceCondition: async () => ({ ok: true, data: { conditions: [] } }),
      sandboxExecute: async () => ({
        ok: true,
        data: {
          status: 'setup_required',
          failure_category: 'unsupported_runtime_backend_hint',
          summary: 'Runtime does not advertise support for backend hint inline/executeSandboxExecute.',
          recommended_next_tools: ['dynamic.dependencies', 'system.health', 'workflow.analyze.start'],
          next_actions: ['Connect a runtime that advertises inline/executeSandboxExecute support before retrying sandbox execution.'],
          required_runtime_backend_hint: { type: 'inline', handler: 'executeSandboxExecute' },
          available_runtime_backends: [
            {
              type: 'spawn',
              handler: 'native.sample.execute',
              description: 'Execute uploaded samples directly.',
              requiresSample: true,
            },
          ],
        },
      }),
    }

    const start = createAnalyzeWorkflowStartHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      sharedDependencies,
      jobQueue
    )
    const promote = createAnalyzeWorkflowPromoteHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      sharedDependencies,
      jobQueue
    )
    const status = createAnalyzeWorkflowStatusHandler(database, sharedDependencies, jobQueue)
    const stageContext = createAnalyzePipelineStageContext(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      sharedDependencies,
      jobQueue
    )

    const startResult = await start({
      sample_id: `sha256:${'a'.repeat(64)}`,
      goal: 'dynamic',
      depth: 'balanced',
      backend_policy: 'auto',
      allow_transformations: false,
      allow_live_execution: true,
      force_refresh: false,
    })
    expect(startResult.ok).toBe(true)
    const started = startResult.data as any
    expect(started.run.stage_plan).toEqual(['fast_profile', 'dynamic_plan', 'dynamic_execute', 'summarize'])

    const promoteResult = await promote({
      run_id: started.run_id,
      through_stage: 'dynamic_execute',
      force_refresh: false,
    })
    expect(promoteResult.ok).toBe(true)

    const queuedDynamicPlan = jobQueue.listQueuedJobs().find((job) => job.args.stage === 'dynamic_plan')
    expect(queuedDynamicPlan).toBeDefined()
    jobQueue.startQueuedJob(queuedDynamicPlan!.id)
    const dynamicPlanResult = await executeQueuedAnalysisStage(stageContext, {
      run_id: started.run_id,
      stage: 'dynamic_plan',
      force_refresh: false,
    })
    jobQueue.complete(queuedDynamicPlan!.id, dynamicPlanResult)
    expect(dynamicPlanResult.ok).toBe(true)

    const queuedDynamicExecute = jobQueue.listQueuedJobs().find((job) => job.args.stage === 'dynamic_execute')
    expect(queuedDynamicExecute).toBeDefined()
    jobQueue.startQueuedJob(queuedDynamicExecute!.id)
    const dynamicExecuteResult = await executeQueuedAnalysisStage(stageContext, {
      run_id: started.run_id,
      stage: 'dynamic_execute',
      force_refresh: false,
    })
    jobQueue.complete(queuedDynamicExecute!.id, dynamicExecuteResult)

    expect(dynamicExecuteResult.ok).toBe(true)
    expect((dynamicExecuteResult.data as any)?.stage).toBe('dynamic_execute')
    expect((dynamicExecuteResult.data as any)?.status).toBe('partial')
    expect((dynamicExecuteResult.data as any)?.execution_state).toBe('partial')
    expect((dynamicExecuteResult.data as any)?.stage_outputs?.sandbox).toMatchObject({
      status: 'setup_required',
      failure_category: 'unsupported_runtime_backend_hint',
    })

    const dynamicExecuteStage = database.findAnalysisRunStage(started.run_id, 'dynamic_execute')
    expect(dynamicExecuteStage?.status).toBe('completed')
    expect(dynamicExecuteStage?.tool).toBe(ANALYSIS_STAGE_JOB_TOOL)

    const statusResult = await status({ run_id: started.run_id })
    expect(statusResult.ok).toBe(true)
    const current = statusResult.data as any
    expect(current.run.latest_stage).toBe('dynamic_execute')
    expect(current.stage_result.stage).toBe('dynamic_execute')
    expect(current.stage_result.status).toBe('partial')
    expect(current.stage_result.stage_outputs.sandbox.failure_category).toBe('unsupported_runtime_backend_hint')
    expect(current.stage_result.stage_outputs.sandbox.recommended_next_tools).toContain('workflow.analyze.start')
  })
})
