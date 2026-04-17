import { afterEach, beforeEach, describe, expect, test, jest } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { createAnalyzeAutoWorkflowHandler } from '../../src/workflows/analyze-auto.js'

jest.setTimeout(30000)

describe('workflow.analyze.auto coverage boundaries', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let policyGuard: PolicyGuard
  let tempRoot: string

  beforeEach(async () => {
    tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'analyze-auto-coverage-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'test.db'))
    cacheManager = new CacheManager(path.join(tempRoot, 'cache'), database)
    policyGuard = new PolicyGuard(path.join(tempRoot, 'audit.log'))
  })

  afterEach(async () => {
    database.close()
    await fs.promises.rm(tempRoot, { recursive: true, force: true })
  })

  test('should expose quick coverage boundaries for triage routing', async () => {
    const sampleId = `sha256:${'1'.repeat(64)}`
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 512 * 1024,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createAnalyzeAutoWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      {
        analyzeStartHandler: async () => ({
          ok: true,
          data: {
            run_id: 'run-1',
            execution_state: 'completed',
            stage_result: { summary: 'Quick triage summary.' },
            recommended_next_tools: ['ghidra.analyze'],
            next_actions: ['continue'],
            coverage_level: 'quick',
            completion_state: 'bounded',
            sample_size_tier: 'small',
            analysis_budget_profile: 'balanced',
            downgrade_reasons: [],
            coverage_gaps: [
              { domain: 'ghidra_analysis', status: 'missing', reason: 'Quick triage does not include a queued decompiler pass.' },
            ],
            confidence_by_domain: {},
            known_findings: [],
            suspected_findings: [],
            unverified_areas: [],
            upgrade_paths: [
              { tool: 'ghidra.analyze', purpose: 'Recover function-level attribution.', closes_gaps: ['ghidra_analysis'], expected_coverage_gain: 'Adds decompiler-backed function discovery.', cost_tier: 'high', availability: 'ready', prerequisites: [], blockers: [] },
            ],
            backend_policy: 'auto',
            backend_considered: [],
            backend_selected: [],
            backend_skipped: [],
            backend_escalation_reasons: [],
            manual_only_backends: [],
          },
        }),
      }
    )

    const result = await handler({ sample_id: sampleId, goal: 'triage' })
    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.coverage_level).toBe('quick')
    expect(data.completion_state).toBe('bounded')
    expect(data.coverage_gaps.some((item: any) => item.domain === 'ghidra_analysis')).toBe(true)
    expect(data.upgrade_paths.some((item: any) => item.tool === 'ghidra.analyze')).toBe(true)
  })

  test('should expose queued bounded coverage for large static routing', async () => {
    const sampleId = `sha256:${'2'.repeat(64)}`
    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 12 * 1024 * 1024,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createAnalyzeAutoWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      {
        analyzeStartHandler: async () => ({
          ok: true,
          data: {
            run_id: 'run-2',
            execution_state: 'completed',
            stage_result: {},
            recommended_next_tools: ['workflow.analyze.promote'],
            next_actions: ['promote'],
          },
        }),
        analyzePromoteHandler: async () => ({
          ok: true,
          data: {
            execution_state: 'queued',
            stage_result: { status: 'queued', job_id: 'job-static-1' },
            recommended_next_tools: ['task.status'],
            next_actions: ['poll'],
            coverage_level: 'static_core',
            completion_state: 'queued',
            sample_size_tier: 'large',
            analysis_budget_profile: 'balanced',
            downgrade_reasons: [],
            coverage_gaps: [
              { domain: 'decompilation', status: 'queued', reason: 'Deep static analysis is queued.' },
            ],
            confidence_by_domain: {},
            known_findings: [],
            suspected_findings: [],
            unverified_areas: [],
            upgrade_paths: [
              { tool: 'task.status', purpose: 'Poll queued job.', closes_gaps: ['decompilation'], expected_coverage_gain: 'Completes decompilation.', cost_tier: 'low', availability: 'ready', prerequisites: [], blockers: [] },
            ],
            backend_policy: 'auto',
            backend_considered: [],
            backend_selected: [],
            backend_skipped: [],
            backend_escalation_reasons: [],
            manual_only_backends: [],
          },
        }),
      }
    )

    const result = await handler({ sample_id: sampleId, goal: 'static', depth: 'deep' })
    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.coverage_level).toBe('static_core')
    expect(data.completion_state).toBe('queued')
    expect(data.sample_size_tier).toBe('large')
    expect(data.analysis_budget_profile).toBe('balanced')
    expect(data.coverage_gaps.some((item: any) => item.status === 'queued')).toBe(true)
    expect(data.upgrade_paths[0].tool).toBe('task.status')
  })

  test('should expose completed reconstruction coverage for deep reverse routing', async () => {
    const sampleId = `sha256:${'3'.repeat(64)}`
    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 900 * 1024,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createAnalyzeAutoWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      {
        analyzeStartHandler: async () => ({
          ok: true,
          data: {
            run_id: 'run-3',
            execution_state: 'completed',
            stage_result: {},
            recommended_next_tools: ['workflow.analyze.promote'],
            next_actions: ['promote'],
          },
        }),
        analyzePromoteHandler: async () => ({
          ok: true,
          data: {
            execution_state: 'completed',
            stage_result: { selected_path: 'native', degraded: false },
            recommended_next_tools: ['artifact.read'],
            next_actions: ['inspect export'],
            coverage_level: 'reconstruction',
            completion_state: 'completed',
            sample_size_tier: 'small',
            analysis_budget_profile: 'deep',
            downgrade_reasons: [],
            coverage_gaps: [],
            confidence_by_domain: {},
            known_findings: [],
            suspected_findings: [],
            unverified_areas: [],
            upgrade_paths: [
              { tool: 'artifact.read', purpose: 'Inspect export artifacts.', closes_gaps: [], expected_coverage_gain: 'Access reconstruction output.', cost_tier: 'low', availability: 'ready', prerequisites: [], blockers: [] },
            ],
            backend_policy: 'auto',
            backend_considered: [],
            backend_selected: [],
            backend_skipped: [],
            backend_escalation_reasons: [],
            manual_only_backends: [],
          },
        }),
      }
    )

    const result = await handler({ sample_id: sampleId, goal: 'reverse', depth: 'deep' })
    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.coverage_level).toBe('reconstruction')
    expect(data.completion_state).toBe('completed')
    expect(data.sample_size_tier).toBe('small')
    expect(data.upgrade_paths.some((item: any) => item.tool === 'artifact.read')).toBe(true)
  })
})
