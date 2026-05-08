import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { PolicyGuard } = await import('../../dist/policy-guard.js')
const { createAnalyzeAutoWorkflowHandler } = await import('../../dist/workflows/analyze-auto.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'analysis-coverage-boundaries-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')
const auditPath = path.join(tempRoot, 'audit.log')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)
const policyGuard = new PolicyGuard(auditPath)

try {
  const sampleId = `sha256:${'d'.repeat(64)}`
  database.insertSample({
    id: sampleId,
    sha256: 'd'.repeat(64),
    md5: 'd'.repeat(32),
    size: 25 * 1024 * 1024,
    file_type: 'PE32+',
    created_at: new Date().toISOString(),
    source: 'integration-test',
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
          run_id: 'run-large-static',
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
          stage_result: { status: 'queued', job_id: 'job-large-static' },
          recommended_next_tools: ['task.status'],
          next_actions: ['poll'],
          coverage_level: 'static_core',
          completion_state: 'queued',
          sample_size_tier: 'oversized',
          analysis_budget_profile: 'balanced',
          downgrade_reasons: [
            'Sample size tier oversized downgraded requested deep analysis to a balanced budget profile.',
          ],
          coverage_gaps: [
            {
              domain: 'decompilation',
              status: 'queued',
              reason: 'Deep static analysis is queued.',
            },
          ],
          confidence_by_domain: {},
          known_findings: [],
          suspected_findings: [],
          unverified_areas: [],
          upgrade_paths: [
            {
              tool: 'task.status',
              purpose: 'Poll queued job.',
              closes_gaps: ['decompilation'],
              expected_coverage_gain: 'Completes decompilation.',
              cost_tier: 'low',
              availability: 'ready',
              prerequisites: [],
              blockers: [],
            },
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

  const result = await handler({
    sample_id: sampleId,
    goal: 'static',
    depth: 'deep',
  })

  assert.equal(result.ok, true)
  assert.equal(result.data.routed_tool, 'workflow.analyze.promote')
  assert.equal(result.data.sample_size_tier, 'oversized')
  assert.equal(result.data.analysis_budget_profile, 'balanced')
  assert.equal(result.data.coverage_level, 'static_core')
  assert.equal(result.data.completion_state, 'queued')
  assert.ok(
    result.data.downgrade_reasons.some((item) =>
      item.includes('downgraded requested deep analysis')
    )
  )
  assert.ok(result.data.coverage_gaps.some((item) => item.status === 'queued'))
  assert.ok(result.data.upgrade_paths.some((item) => item.tool === 'task.status'))

  console.log('analysis coverage boundaries integration checks passed')
} finally {
  database.close()
  await fs.rm(tempRoot, { recursive: true, force: true })
}
