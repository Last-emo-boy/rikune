import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  angrAnalyzeToolDefinition,
  createAngrAnalyzeHandler,
} from '../../src/plugins/angr/tools/angr-analyze.js'

const unavailable = {
  available: false,
  source: 'none',
  path: null,
  version: null,
  checked_candidates: [],
  error: null,
}

function backendResolution(angr = unavailable) {
  return {
    capa_cli: unavailable,
    capa_rules: { available: false, source: 'none', path: null, error: null },
    die: unavailable,
    graphviz: unavailable,
    rizin: unavailable,
    upx: unavailable,
    wine: unavailable,
    winedbg: unavailable,
    frida_cli: unavailable,
    yara_x: unavailable,
    qiling: unavailable,
    angr,
    panda: unavailable,
    retdec: unavailable,
  }
}

describe('angr.analyze', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'3'.repeat(64)}`

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'angr-analyze-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'sample.exe'), Buffer.from('MZangr'))
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('declares CFGFast workflow, evidence, and optional angr backend metadata', () => {
    expect(angrAnalyzeToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['pe', 'elf', 'macho', 'shellcode']),
        execution: expect.arrayContaining(['static', 'triage']),
        runtimes: ['angr'],
        safety: expect.arrayContaining(['passive', 'read_only', 'no_network_by_default']),
        capabilities: expect.arrayContaining([
          'cfg',
          'function-discovery',
          'symbolic-execution',
          'workflow-handoff',
        ]),
      })
    )
    expect(angrAnalyzeToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'backend_angr_cfg_fast',
        }),
      ])
    )
    expect(angrAnalyzeToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'structure',
          artifactTypes: ['backend_angr_cfg_fast'],
        }),
      ])
    )
    expect(angrAnalyzeToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'angr.cfgfast-handoff',
        startsWith: ['angr.analyze'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'workflow.search',
          'code.functions.smart_recover',
          'analysis.evidence.graph',
        ]),
        producesArtifacts: ['backend_angr_cfg_fast'],
        safety: expect.arrayContaining(['passive', 'read_only', 'no_network_by_default']),
      })
    )
    expect(angrAnalyzeToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(angrAnalyzeToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'angr',
        backendKind: 'external',
        adapter: 'angr.cfgfast.preview',
        envVar: 'ANGR_PYTHON',
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
          missingBackendBehavior:
            'Return setup_required without importing angr or running analysis.',
        }),
      })
    )
  })

  test('returns a standard CFGFast handoff envelope and persists it as an artifact', async () => {
    const handler = createAngrAnalyzeHandler(workspaceManager, database, {
      resolveBackends: () =>
        backendResolution({
          available: true,
          source: 'config',
          path: '/opt/angr/bin/python',
          version: '9.2.120',
          checked_candidates: ['python'],
          error: null,
        }),
      runPythonJson: async () => ({
        parsed: {
          arch: 'AMD64',
          entry: '0x401000',
          node_count: 7,
          edge_count: 9,
          function_count: 3,
          functions: [
            { address: '0x401000', name: 'main', block_count: 4 },
            { address: '0x402000', name: 'decrypt_config', block_count: 3 },
          ],
        },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      analysis: 'cfg_fast',
      max_functions: 2,
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.angr_cfgfast.v1')
    expect(data.tool_version).toBe('0.2.0')
    expect(data.node_count).toBe(7)
    expect(data.edge_count).toBe(9)
    expect(data.function_count).toBe(3)
    expect(data.functions).toHaveLength(2)
    expect(data.recommended_next_tools).toEqual(['artifact.read', 'workflow.search'])
    expect(data.recommended_next_tools).not.toContain('code.functions.smart_recover')
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.angr_cfgfast.evidence_summary.v1',
        source_tool: 'angr.analyze',
        artifact_type: 'backend_angr_cfg_fast',
        sample_id: sampleId,
        analysis: 'cfg_fast',
        arch: 'AMD64',
        node_count: 7,
        edge_count: 9,
        function_count: 3,
        preview_function_count: 2,
        artifact_id: result.artifacts?.[0]?.id,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.angr_cfgfast.workflow_handoff.v1',
        handoff_mode: 'angr_cfgfast_to_function_recovery_review',
        artifact_type: 'backend_angr_cfg_fast',
        recommended_next_tools: ['artifact.read', 'workflow.search'],
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'recover-and-corroborate-functions',
          next_tools: ['code.functions.smart_recover', 'analysis.evidence.graph'],
        }),
      ])
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.angr_cfgfast.quality_gates.v1',
        passive_static_analysis: true,
        read_only_backend: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        artifact_persisted: true,
      })
    )
    expect(result.artifacts?.[0]).toEqual(
      expect.objectContaining({ type: 'backend_angr_cfg_fast', mime: 'application/json' })
    )

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persisted = JSON.parse(
      await fs.readFile(path.join(workspace.root, result.artifacts![0].path), 'utf8')
    )
    expect(persisted.schema).toBe('rikune.angr_cfgfast.v1')
    expect(persisted.workflow_handoff.schema).toBe('rikune.angr_cfgfast.workflow_handoff.v1')
    expect(persisted.quality_gates.passive_static_analysis).toBe(true)
    expect(persisted.raw_angr_result.functions).toHaveLength(2)
  })

  test('reports setup_required without invoking Python when angr is unavailable', async () => {
    const runPythonJson = jest.fn(async () => {
      throw new Error('runPythonJson should not be called')
    })
    const handler = createAngrAnalyzeHandler(workspaceManager, database, {
      resolveBackends: () =>
        backendResolution({
          ...unavailable,
          checked_candidates: ['python'],
          error: 'angr is not installed',
        }),
      runPythonJson,
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    expect((result.data as any).status).toBe('setup_required')
    expect((result.data as any).backend.error).toBe('angr is not installed')
    expect(result.warnings).toContain('angr is not installed')
    expect(runPythonJson).not.toHaveBeenCalled()
  })

  test('returns backend errors without persisting artifacts', async () => {
    const handler = createAngrAnalyzeHandler(workspaceManager, database, {
      resolveBackends: () =>
        backendResolution({
          available: true,
          source: 'config',
          path: '/opt/angr/bin/python',
          version: '9.2.120',
          checked_candidates: ['python'],
          error: null,
        }),
      runPythonJson: async () => {
        throw new Error('angr backend failed')
      },
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('angr backend failed')
    expect(database.findArtifacts(sampleId)).toHaveLength(0)
  })
})
