import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createFridaScriptGenerateHandler,
  fridaScriptGenerateToolDefinition,
} from '../../src/plugins/frida/tools/frida-script-generate.js'

describe('frida.script.generate', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'f'.repeat(64)}`

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'frida-script-generate-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    database.insertSample({
      id: sampleId,
      sha256: 'f'.repeat(64),
      md5: 'f'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('declares passive hook planning workflow metadata', () => {
    expect(fridaScriptGenerateToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'plan_only',
        'no_live_sample_by_default',
        'no_backend_started',
        'no_script_injection',
        'approval_required_for_live_execution',
      ])
    )
    expect(fridaScriptGenerateToolDefinition.artifacts).toEqual([
      expect.objectContaining({ type: 'frida_script' }),
    ])
    expect(fridaScriptGenerateToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'frida.passive-hook-plan',
        startsWith: ['frida.script.generate'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'workflow.search',
          'tool.readiness',
          'dynamic.runtime.status',
        ]),
        producesArtifacts: ['frida_script'],
        runtimeBackends: expect.arrayContaining(['frida', 'frida-server']),
      })
    )
    expect(fridaScriptGenerateToolDefinition.workflowRecipes?.[0].nextTools).not.toEqual(
      expect.arrayContaining([
        'dynamic.trace',
        'frida.attach',
        'dynamic.memory_dump',
        'dynamic.auto_hook',
        'frida.script.inject',
        'frida.trace.capture',
        'frida.runtime.instrument',
      ])
    )
    expect(fridaScriptGenerateToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: false,
        requiresIsolation: false,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
  })

  test('returns a passive handoff envelope and keeps top-level next tools narrow', async () => {
    const handler = createFridaScriptGenerateHandler(workspaceManager, database)

    const result = await handler({
      sample_id: sampleId,
      hook_targets: ['crypto', 'network'],
      include_imports: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.frida_script_generate.v1')
    expect(data.total_hooks).toBeGreaterThan(0)
    expect(data.recommended_next_tools).toEqual(['artifact.read', 'workflow.search'])
    expect(data.recommended_next_tools).not.toEqual(
      expect.arrayContaining(['dynamic.trace', 'frida.attach', 'frida.script.inject'])
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.frida_script_generate.evidence_summary.v1',
        source_tool: 'frida.script.generate',
        artifact_type: 'frida_script',
        script_count: 2,
        total_hooks: data.total_hooks,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.frida_script_generate.quality_gates.v1',
        passive_generation_only: true,
        sample_executed_by_tool: false,
        backend_started: false,
        frida_attached: false,
        script_injected: false,
        readiness_required_before_injection: true,
        approval_required_for_live_execution: true,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.frida_script_generate.workflow_handoff.v1',
        handoff_mode: 'frida_hook_plan_to_runtime_instrumentation',
        artifact_type: 'frida_script',
        recommended_next_tools: ['artifact.read', 'workflow.search'],
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'explicit-frida-injection-or-trace-capture',
          next_tools: ['frida.script.inject', 'frida.trace.capture', 'frida.runtime.instrument'],
        }),
      ])
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        backend_started: false,
        frida_attached: false,
        script_injected: false,
        trace_capture_started: false,
      })
    )
    expect(result.artifacts?.[0]).toEqual(expect.objectContaining({ type: 'frida_script' }))

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persisted = JSON.parse(
      await fs.readFile(path.join(workspace.root, result.artifacts![0].path), 'utf8')
    )
    expect(persisted.combined_script).toContain('AUTO-GENERATED Frida hook script')
    expect(persisted.scripts.length).toBe(2)
    expect(persisted.workflow_handoff.schema).toBe(
      'rikune.frida_script_generate.workflow_handoff.v1'
    )
    expect(persisted.quality_gates.passive_generation_only).toBe(true)
  })
})
