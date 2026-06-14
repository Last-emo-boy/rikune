import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createRizinAnalyzeHandler,
  rizinAnalyzeToolDefinition,
} from '../../src/plugins/rizin/tools/rizin-analyze.js'

const unavailable = {
  available: false,
  source: 'none',
  path: null,
  version: null,
  checked_candidates: [],
  error: null,
}

function backendResolution() {
  return {
    capa_cli: unavailable,
    capa_rules: { available: false, source: 'none', path: null, error: null },
    die: unavailable,
    graphviz: unavailable,
    rizin: {
      available: true,
      source: 'config',
      path: '/opt/rizin/bin/rizin',
      version: '0.8.2',
      checked_candidates: ['rizin'],
      error: null,
    },
    upx: unavailable,
    wine: unavailable,
    winedbg: unavailable,
    frida_cli: unavailable,
    yara_x: unavailable,
    qiling: unavailable,
    angr: unavailable,
    panda: unavailable,
    retdec: unavailable,
  }
}

describe('rizin.analyze', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'1'.repeat(64)}`

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'rizin-analyze-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 4096,
      file_type: 'ELF executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(
      path.join(workspace.original, 'sample.elf'),
      Buffer.from([0x7f, 0x45, 0x4c, 0x46])
    )
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('declares read-only preview workflow and optional backend readiness metadata', () => {
    expect(rizinAnalyzeToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'rizin.readonly-preview',
        startsWith: ['rizin.analyze'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'workflow.search',
          'code.cross_decompiler.consensus',
          'analysis.evidence.graph',
        ]),
        producesArtifacts: expect.arrayContaining(['backend_rizin_functions']),
        safety: expect.arrayContaining(['passive', 'read_only', 'no_network_by_default']),
      })
    )
    expect(rizinAnalyzeToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(rizinAnalyzeToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'rizin',
        backendKind: 'external',
        adapter: 'rizin.readonly.preview',
        envVar: 'RIZIN_PATH',
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
          missingBackendBehavior: 'Return setup_required without running any backend command.',
        }),
      })
    )
  })

  test('returns a standard handoff envelope and keeps top-level next tools narrow', async () => {
    const handler = createRizinAnalyzeHandler(workspaceManager, database, {
      resolveBackends: backendResolution,
      executeCommand: async () => ({
        stdout: JSON.stringify([
          { name: 'main', offset: 4096 },
          { name: 'decrypt_config', offset: 8192 },
          { name: 'dispatch', offset: 12288 },
        ]),
        stderr: '',
        exitCode: 0,
        timedOut: false,
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      operation: 'functions',
      max_items: 2,
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.rizin_preview.v1')
    expect(data.item_count).toBe(3)
    expect(data.preview).toHaveLength(2)
    expect(data.recommended_next_tools).toEqual(['artifact.read', 'workflow.search'])
    expect(data.recommended_next_tools).not.toEqual(
      expect.arrayContaining(['code.function.disassemble', 'code.xrefs.analyze'])
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.rizin_preview.evidence_summary.v1',
        source_tool: 'rizin.analyze',
        artifact_type: 'backend_rizin_functions',
        operation: 'functions',
        item_count: 3,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.rizin_preview.workflow_handoff.v1',
        handoff_mode: 'rizin_preview_to_cross_backend_review',
        artifact_type: 'backend_rizin_functions',
        recommended_next_tools: ['artifact.read', 'workflow.search'],
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'cross-backend-corroboration',
          next_tools: ['code.cross_decompiler.consensus', 'analysis.evidence.graph'],
        }),
      ])
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.rizin_preview.quality_gates.v1',
        passive_static_analysis: true,
        read_only_backend: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(result.artifacts?.[0]).toEqual(
      expect.objectContaining({ type: 'backend_rizin_functions' })
    )

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persisted = JSON.parse(
      await fs.readFile(path.join(workspace.root, result.artifacts![0].path), 'utf8')
    )
    expect(persisted.schema).toBe('rikune.rizin_preview.v1')
    expect(persisted.workflow_handoff.schema).toBe('rikune.rizin_preview.workflow_handoff.v1')
    expect(persisted.quality_gates.passive_static_analysis).toBe(true)
    expect(persisted.raw_rizin_result).toHaveLength(3)
  })
})
