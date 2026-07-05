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
  createOrReuseAnalysisRun,
  upsertAnalysisRunStage,
} from '../../src/analysis/analysis-run-state.js'
import {
  ANALYSIS_STAGE_JOB_TOOL,
  createAnalyzePipelineStageContext,
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
  createAnalyzeWorkflowStatusHandler,
  executeQueuedAnalysisStage,
} from '../../src/workflows/analyze-pipeline.js'

const goldenManifest = JSON.parse(
  fs.readFileSync(
    path.join(process.cwd(), 'tests', 'fixtures', 'golden-samples.manifest.json'),
    'utf8'
  )
) as { fixtures: Array<Record<string, any>> }

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

  test('builds the default Ghidra stage handler with complete plugin dependencies', async () => {
    const stageContext = createAnalyzePipelineStageContext(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      { resolveBackends: () => makeUnavailableBackendResolution() },
      jobQueue
    )

    const result = await stageContext.dependencies.ghidraAnalyze!({
      sample_id: `sha256:${'c'.repeat(64)}`,
    })
    const payload = JSON.parse(String((result as any).content?.[0]?.text || '{}'))

    expect(payload.ok).toBe(false)
    expect(payload.errors[0]).toContain(`Sample not found: sha256:${'c'.repeat(64)}`)
  })

  test('starts, reuses, and promotes a persisted staged analysis run', async () => {
    const peFixture = goldenManifest.fixtures.find(
      (fixture) => fixture.id === 'synthetic-pe-fast-profile'
    )
    expect(peFixture?.expected_signals.stage_plan).toEqual([
      'fast_profile',
      'enrich_static',
      'function_map',
      'summarize',
    ])

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
          strings: [{ string: 'http://example.invalid/c2' }, { string: 'cmd.exe /c whoami' }],
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
    expect(started.recommended_next_tools).toContain('artifacts.list')
    expect(started.recommended_next_tools).toContain('artifact.read')
    expect(started.recommended_next_tools).toContain('report.summarize')
    expect(started.evidence_state).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          evidence_family: 'backend_preview',
          backend: 'workflow.analyze.start',
          state: 'fresh',
          provenance: expect.objectContaining({
            source_tool: 'workflow.analyze.start',
            validation_tools: expect.arrayContaining(['workflow.analyze.status']),
          }),
        }),
      ])
    )
    expect(started.evidence_state.map((entry: any) => entry.evidence_family)).toEqual(
      expect.arrayContaining(peFixture?.expected_signals.evidence_families)
    )
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
    expect(promoted.stage_result.queued_stages).toEqual(['enrich_static'])
    expect(promoted.stage_result.blocked_stages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          stage: 'function_map',
          blocked_by_stage: 'enrich_static',
        }),
      ])
    )
    expect(promoted.deferred_jobs).toHaveLength(1)
    expect(promoted.deferred_jobs.map((job: any) => job.stage)).toEqual(['enrich_static'])

    const queuedJobs = jobQueue.listQueuedJobs()
    expect(queuedJobs).toHaveLength(1)
    expect(queuedJobs.every((job) => job.tool === ANALYSIS_STAGE_JOB_TOOL)).toBe(true)

    const enrichStage = database.findAnalysisRunStage(started.run_id, 'enrich_static')
    const functionMapStage = database.findAnalysisRunStage(started.run_id, 'function_map')
    expect(enrichStage?.status).toBe('queued')
    expect(enrichStage?.tool).toBe(ANALYSIS_STAGE_JOB_TOOL)
    expect(functionMapStage).toBeUndefined()

    const statusResult = await status({ run_id: started.run_id })

    expect(statusResult.ok).toBe(true)
    const current = statusResult.data as any
    expect(current.execution_state).toBe('queued')
    expect(current.run.status).toBe('queued')
    expect(current.run.latest_stage).toBe('enrich_static')
    expect(current.deferred_jobs).toHaveLength(1)
    expect(current.deferred_jobs.map((job: any) => job.stage)).toEqual(['enrich_static'])
    expect(current.recommended_next_tools).toContain('workflow.analyze.status')
    expect(current.next_actions[0]).toContain('workflow.run action=status')
  })

  test('keeps function_map partial while the internal Ghidra analysis job is queued', async () => {
    const sample = database.findSample(`sha256:${'a'.repeat(64)}`)
    expect(sample).toBeDefined()
    const { run } = createOrReuseAnalysisRun(database, {
      sample: sample!,
      goal: 'reverse',
      depth: 'balanced',
      backendPolicy: 'auto',
      forceRefresh: true,
    })
    upsertAnalysisRunStage(database, {
      runId: run.id,
      stage: 'enrich_static',
      status: 'completed',
      executionState: 'completed',
      result: { stage: 'enrich_static', status: 'ready' },
    })

    const stageContext = createAnalyzePipelineStageContext(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      {
        ghidraAnalyze: async () => ({
          ok: true,
          data: {
            analysis_id: 'ghidra-job-1',
            job_id: 'ghidra-job-1',
            status: 'queued',
            result_mode: 'queued',
            function_count: 0,
          },
        }),
        rizinAnalyze: async () => ({
          ok: true,
          data: { functions: [] },
        }),
        resolveBackends: () => makeUnavailableBackendResolution(),
      },
      jobQueue
    )

    const result = await executeQueuedAnalysisStage(stageContext, {
      run_id: run.id,
      stage: 'function_map',
      force_refresh: false,
    })

    expect(result.ok).toBe(true)
    expect((result.data as any).status).toBe('waiting_for_ghidra')
    expect((result.data as any).execution_state).toBe('partial')
    expect(result.warnings.join(' ')).toContain('function_map remains partial')

    const stage = database.findAnalysisRunStage(run.id, 'function_map')
    expect(stage?.status).toBe('partial')
    expect(stage?.execution_state).toBe('partial')
    const metadata = JSON.parse(stage?.metadata_json || '{}')
    expect(metadata).toMatchObject({
      ghidra_job_id: 'ghidra-job-1',
      ghidra_status: 'queued',
      function_index_ready: false,
    })
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
      compilerPackerDetect: async () => ({
        ok: true,
        data: { summary: null, packer_findings: [] },
      }),
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
          failure_category: 'unsupported_runtime_contract',
          summary:
            'Runtime does not advertise support for runtime contract inline/executeSandboxExecute.',
          recommended_next_tools: [
            'dynamic.dependencies',
            'system.health',
            'workflow.analyze.start',
          ],
          next_actions: [
            'Connect a runtime that advertises inline/executeSandboxExecute support before retrying sandbox execution.',
          ],
          required_runtime_contract: { type: 'inline', handler: 'executeSandboxExecute' },
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
    expect(started.run.stage_plan).toEqual([
      'fast_profile',
      'dynamic_plan',
      'dynamic_execute',
      'summarize',
    ])

    const promoteResult = await promote({
      run_id: started.run_id,
      through_stage: 'dynamic_execute',
      force_refresh: false,
    })
    expect(promoteResult.ok).toBe(true)

    const queuedDynamicPlan = jobQueue
      .listQueuedJobs()
      .find((job) => job.args.stage === 'dynamic_plan')
    expect(queuedDynamicPlan).toBeDefined()
    jobQueue.startQueuedJob(queuedDynamicPlan!.id)
    const dynamicPlanResult = await executeQueuedAnalysisStage(stageContext, {
      run_id: started.run_id,
      stage: 'dynamic_plan',
      force_refresh: false,
    })
    jobQueue.complete(queuedDynamicPlan!.id, dynamicPlanResult)
    expect(dynamicPlanResult.ok).toBe(true)
    expect((dynamicPlanResult.data as any)?.execution_semantics).toMatchObject({
      actual_mode: 'plan_only',
      live_execution_started: false,
      allow_live_execution: true,
    })

    const promoteExecuteResult = await promote({
      run_id: started.run_id,
      through_stage: 'dynamic_execute',
      force_refresh: false,
    })
    expect(promoteExecuteResult.ok).toBe(true)
    expect((promoteExecuteResult.data as any).stage_result.queued_stages).toEqual([
      'dynamic_execute',
    ])

    const queuedDynamicExecute = jobQueue
      .listQueuedJobs()
      .find((job) => job.args.stage === 'dynamic_execute')
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
      failure_category: 'unsupported_runtime_contract',
    })
    expect((dynamicExecuteResult.data as any)?.execution_semantics).toMatchObject({
      actual_mode: 'setup_required',
      live_execution_started: false,
      allow_live_execution: true,
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
    expect(current.stage_result.stage_outputs.sandbox.failure_category).toBe(
      'unsupported_runtime_contract'
    )
    expect(current.stage_result.stage_outputs.sandbox.recommended_next_tools).toContain(
      'workflow.analyze.start'
    )
    expect(current.runtime_sessions.length).toBeGreaterThanOrEqual(1)
  })

  test('records queued semantic review stages as partial while waiting for LLM sampling', async () => {
    const sampleId = `sha256:${'a'.repeat(64)}`
    const sample = database.findSample(sampleId)
    if (!sample) {
      throw new Error('sample fixture missing')
    }
    const { run } = createOrReuseAnalysisRun(database, {
      sample,
      goal: 'reverse',
      depth: 'balanced',
      backendPolicy: 'auto',
    })
    for (const stage of ['enrich_static', 'function_map', 'reconstruct'] as const) {
      upsertAnalysisRunStage(database, {
        runId: run.id,
        stage,
        status: 'completed',
        executionState: 'completed',
        result: { stage, status: 'ready' },
      })
    }
    let capturedArgs: Record<string, unknown> | null = null
    const prepareArtifact = {
      id: 'semantic-prepare-1',
      type: 'semantic_name_prepare_bundle',
      path: 'reports/semantic_naming/reviewA/prepare.json',
      sha256: 'prepare-sha',
      mime: 'application/json',
    }
    const stageContext = createAnalyzePipelineStageContext(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      {
        semanticNameReviewWorkflow: async (args) => {
          capturedArgs = args
          return {
            ok: true,
            data: {
              review: {
                review_status: 'prompt_contract_only',
                prepare: { artifact_id: prepareArtifact.id },
                sampling: { attempted: false },
                apply: { accepted_count: 0, rejected_count: 0 },
              },
            },
            warnings: ['MCP sampling client unavailable'],
            artifacts: [prepareArtifact],
          }
        },
      },
      jobQueue
    )

    const result = await executeQueuedAnalysisStage(stageContext, {
      run_id: run.id,
      stage: 'semantic_name_review',
      force_refresh: false,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings).toContain('MCP sampling client unavailable')
    expect((result.data as any).status).toBe('waiting_for_llm')
    expect((result.data as any).execution_state).toBe('partial')
    expect((result.data as any).semantic_review.semantic_review_state).toBe('waiting_for_llm')
    expect((result.data as any).recommended_next_tools).toEqual([
      'prompts/get',
      'code.function.rename.apply',
      'workflow.analyze.promote',
    ])
    expect(capturedArgs).toMatchObject({
      sample_id: sampleId,
      session_tag: `analysis_${run.id}_semantic_name_review`,
      auto_apply: true,
      reuse_cached: true,
    })

    const stage = database.findAnalysisRunStage(run.id, 'semantic_name_review')
    expect(stage?.status).toBe('partial')
    expect(stage?.execution_state).toBe('partial')
    expect(stage?.tool).toBe(ANALYSIS_STAGE_JOB_TOOL)
    expect(JSON.parse(stage?.artifact_refs_json || '[]')).toEqual([prepareArtifact])
    const metadata = JSON.parse(stage?.metadata_json || '{}')
    expect(metadata).toMatchObject({
      semantic_review_stage: 'semantic_name_review',
      semantic_review_state: 'waiting_for_llm',
      review_status: 'prompt_contract_only',
      workflow_tool: 'workflow.semantic_name_review',
      prepare_artifact_id: prepareArtifact.id,
      accepted_count: 0,
      rejected_count: 0,
    })
  })
})
