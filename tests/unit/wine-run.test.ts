import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import path from 'path'

import { DatabaseManager } from '../../src/database.js'
import { createWineRunHandler } from '../../src/plugins/wine/tools/wine-run.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'

const FORBIDDEN_PROFILE_NEXT_TOOLS = ['sandbox.execute', 'tool.help', 'tools.discover']

function backendsWithWineAvailable() {
  const unavailable = {
    available: false,
    source: 'none',
    path: null,
    version: null,
    checked_candidates: [],
    error: null,
  }
  return {
    capa_cli: unavailable,
    capa_rules: { available: false, source: 'none', path: null, error: null },
    die: unavailable,
    graphviz: unavailable,
    rizin: unavailable,
    upx: unavailable,
    wine: {
      available: true,
      source: 'config',
      path: '/usr/bin/wine',
      version: 'wine-9.0',
      checked_candidates: ['wine'],
      error: null,
    },
    winedbg: {
      available: true,
      source: 'config',
      path: '/usr/bin/winedbg',
      version: 'wine-9.0',
      checked_candidates: ['winedbg'],
      error: null,
    },
    frida_cli: unavailable,
    yara_x: unavailable,
    qiling: unavailable,
    angr: unavailable,
    panda: unavailable,
    retdec: unavailable,
  }
}

describe('wine.run execution gate', () => {
  const testRoot = path.join(process.cwd(), 'test-wine-run')
  const workspaceRoot = path.join(testRoot, 'workspaces')
  const dbPath = path.join(testRoot, 'test.db')
  const sampleSha = 'e'.repeat(64)
  const sampleId = `sha256:${sampleSha}`

  let database: DatabaseManager
  let workspaceManager: WorkspaceManager

  beforeEach(async () => {
    if (fs.existsSync(testRoot)) {
      fs.rmSync(testRoot, { recursive: true, force: true })
    }
    fs.mkdirSync(testRoot, { recursive: true })

    database = new DatabaseManager(dbPath)
    workspaceManager = new WorkspaceManager(workspaceRoot)

    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: sampleSha,
      md5: 'f'.repeat(32),
      size: 32,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), Buffer.from('MZtest'))
  })

  afterEach(() => {
    database.close()
    if (fs.existsSync(testRoot)) {
      fs.rmSync(testRoot, { recursive: true, force: true })
    }
  })

  test('preflight does not call the runner or recommend live execution alternatives', async () => {
    let runnerCalled = false
    const handler = createWineRunHandler(workspaceManager, database, {
      resolveBackends: backendsWithWineAvailable,
      executeCommand: async () => {
        runnerCalled = true
        throw new Error('wine runner should not be called during preflight')
      },
    })

    const result = await handler({ sample_id: sampleId, mode: 'preflight' })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.status).toBe('ready')
    expect(data.summary).toContain('without launching the sample')
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['windows.runtime.plan', 'dynamic.dependencies', 'tool.readiness'])
    )
    expect(data.recommended_next_tools[0]).toBe('windows.runtime.plan')
    expect(data.recommended_next_tools).not.toContain('wine.run')
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.wine_compatibility.quality_gates.v1',
        passive_preflight_only: true,
        sample_executed_by_tool: false,
        approval_required_for_live_execution: true,
        current_mode_requires_approval: false,
        network_disabled_by_default: true,
        wine_not_windows_ground_truth: true,
      })
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.wine_compatibility.evidence_summary.v1',
        profile: 'wine.compatibility',
        confidence: 'readiness-only',
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.wine_compatibility.workflow_handoff.v1',
        routing: expect.objectContaining({
          activation_boundary: 'result-scoped',
          preferred_next_tools: data.recommended_next_tools,
        }),
      })
    )
    for (const forbidden of FORBIDDEN_PROFILE_NEXT_TOOLS) {
      expect(data.recommended_next_tools).not.toContain(forbidden)
    }
    expect(runnerCalled).toBe(false)
  })

  test('run mode denies execution without approval and does not call the runner', async () => {
    let runnerCalled = false
    const handler = createWineRunHandler(workspaceManager, database, {
      resolveBackends: backendsWithWineAvailable,
      executeCommand: async () => {
        runnerCalled = true
        throw new Error('wine runner should not be called when approved=false')
      },
    })

    const result = await handler({ sample_id: sampleId, mode: 'run', approved: false })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.status).toBe('denied')
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['windows.runtime.plan', 'pe.structure.analyze', 'tool.readiness'])
    )
    expect(data.recommended_next_tools[0]).toBe('windows.runtime.plan')
    expect(data.recommended_next_tools).not.toContain('wine.run')
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.wine_compatibility.quality_gates.v1',
        passive_preflight_only: false,
        sample_executed_by_tool: false,
        approval_required_for_live_execution: true,
        current_mode_requires_approval: true,
        approved_execution: false,
        network_disabled_by_default: true,
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.objectContaining({
        activation_boundary: 'result-scoped',
        preferred_next_tools: data.recommended_next_tools,
      })
    )
    for (const forbidden of FORBIDDEN_PROFILE_NEXT_TOOLS) {
      expect(data.recommended_next_tools).not.toContain(forbidden)
    }
    expect(result.warnings).toContain('Wine execution requires approved=true.')
    expect(runnerCalled).toBe(false)
  })

  test('approved runs recommend artifact and registry follow-up without trace import', async () => {
    let runnerCalled = false
    const handler = createWineRunHandler(workspaceManager, database, {
      resolveBackends: backendsWithWineAvailable,
      executeCommand: async () => {
        runnerCalled = true
        return {
          stdout: 'wine stdout',
          stderr: '',
          exitCode: 0,
          timedOut: false,
        }
      },
    })

    const result = await handler({
      sample_id: sampleId,
      mode: 'run',
      approved: true,
      persist_artifact: false,
    })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.status).toBe('ready')
    expect(data.approved).toBe(true)
    expect(data.execution.exit_code).toBe(0)
    expect(data.recommended_next_tools).toEqual(['artifact.read', 'wine.reg'])
    expect(data.recommended_next_tools).not.toContain('dynamic.trace.import')
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.wine_compatibility.quality_gates.v1',
        sample_executed_by_tool: true,
        approval_required_for_live_execution: true,
        current_mode_requires_approval: true,
        approved_execution: true,
        artifact_persisted: false,
      })
    )
    expect(data.evidence_summary.confidence).toBe('compatibility-signal')
    expect(runnerCalled).toBe(true)
  })
})
