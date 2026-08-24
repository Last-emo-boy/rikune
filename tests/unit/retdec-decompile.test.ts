import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createRetDecDecompileHandler,
  retdecDecompileToolDefinition,
} from '../../src/plugins/retdec/tools/retdec-decompile.js'

const unavailable = {
  available: false,
  source: 'none',
  path: null,
  version: null,
  checked_candidates: [],
  error: null,
}

function backendResolution(retdec = unavailable) {
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
    angr: unavailable,
    panda: unavailable,
    retdec,
  }
}

describe('retdec.decompile', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'2'.repeat(64)}`

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'retdec-decompile-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'sample.exe'), Buffer.from('MZretdec'))
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('declares static decompile workflow and optional RetDec backend metadata', () => {
    expect(retdecDecompileToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'read_only', 'bounded_output', 'no_network_by_default'])
    )
    expect(retdecDecompileToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'retdec.decompile-handoff',
        startsWith: ['retdec.decompile'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'workflow.search',
          'code.cross_decompiler.consensus',
          'workflow.reconstruct',
          'analysis.evidence.graph',
        ]),
        producesArtifacts: expect.arrayContaining([
          'backend_retdec_decompile_plain',
          'backend_retdec_decompile_json-human',
        ]),
        safety: expect.arrayContaining(['passive', 'read_only', 'no_network_by_default']),
      })
    )
    expect(retdecDecompileToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(retdecDecompileToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'retdec',
        backendKind: 'external',
        adapter: 'retdec.static.decompile',
        envVar: 'RETDEC_PATH',
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
          missingBackendBehavior: 'Return setup_required without running any backend command.',
        }),
      })
    )
  })

  test('returns a standard handoff envelope while preserving the raw decompile artifact', async () => {
    const handler = createRetDecDecompileHandler(workspaceManager, database, {
      resolveBackends: () =>
        backendResolution({
          available: true,
          source: 'config',
          path: '/opt/retdec/bin/retdec-decompiler',
          version: '5.0',
          checked_candidates: ['retdec-decompiler'],
          error: null,
        }),
      executeCommand: async (_binaryPath, args) => {
        const outputIndex = args.indexOf('--output')
        expect(outputIndex).toBeGreaterThanOrEqual(0)
        await fs.writeFile(args[outputIndex + 1], 'int main(void) {\n    return 0;\n}\n', 'utf8')
        return { stdout: 'retdec ok', stderr: '', exitCode: 0, timedOut: false }
      },
    })

    const result = await handler({
      sample_id: sampleId,
      output_format: 'plain',
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.retdec_decompile.v1')
    expect(data.recommended_next_tools).toEqual(['artifact.read', 'workflow.search'])
    expect(data.recommended_next_tools).not.toContain('workflow.reconstruct')
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.retdec_decompile.evidence_summary.v1',
        source_tool: 'retdec.decompile',
        artifact_type: 'backend_retdec_decompile_plain',
        sample_id: sampleId,
        output_format: 'plain',
        output_char_count: 33,
        artifact_id: result.artifacts?.[0]?.id,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.retdec_decompile.workflow_handoff.v1',
        handoff_mode: 'retdec_decompile_to_cross_backend_review',
        artifact_type: 'backend_retdec_decompile_plain',
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
        schema: 'rikune.retdec_decompile.quality_gates.v1',
        passive_static_analysis: true,
        read_only_backend: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        artifact_persisted: true,
        semantic_completeness: 'suspect',
        decompiler_confidence_score: 0.35,
        risk_flags: ['short_entrypoint_low_call_coverage'],
        cross_backend_corroboration_required: true,
        trust_policy: 'RetDec missing calls are not negative evidence; corroborate with CFG/xref data.',
      })
    )
    expect(result.warnings?.join(' ')).toContain('missing calls')
    expect(result.artifacts?.[0]).toEqual(
      expect.objectContaining({ type: 'backend_retdec_decompile_plain', mime: 'text/x-csrc' })
    )

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persisted = await fs.readFile(
      path.join(workspace.root, result.artifacts![0].path),
      'utf8'
    )
    expect(persisted).toBe('int main(void) {\n    return 0;\n}\n')
  })

  test('reports setup_required without invoking RetDec when backend is unavailable', async () => {
    const handler = createRetDecDecompileHandler(workspaceManager, database, {
      resolveBackends: () =>
        backendResolution({
          ...unavailable,
          checked_candidates: ['retdec-decompiler'],
          error: 'retdec-decompiler not found',
        }),
      executeCommand: async () => {
        throw new Error('executeCommand should not be called')
      },
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    expect((result.data as any).status).toBe('setup_required')
    expect((result.data as any).backend.error).toBe('retdec-decompiler not found')
    expect(result.warnings).toContain('retdec-decompiler not found')
  })

  test('returns timeout errors without persisting artifacts', async () => {
    const handler = createRetDecDecompileHandler(workspaceManager, database, {
      resolveBackends: () =>
        backendResolution({
          available: true,
          source: 'config',
          path: '/opt/retdec/bin/retdec-decompiler',
          version: '5.0',
          checked_candidates: ['retdec-decompiler'],
          error: null,
        }),
      executeCommand: async () => ({
        stdout: '',
        stderr: 'timeout',
        exitCode: 1,
        timedOut: true,
      }),
    })

    const result = await handler({ sample_id: sampleId, timeout_sec: 10 })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toBe('RetDec timed out after 10 seconds.')
    expect(database.findArtifacts(sampleId)).toHaveLength(0)
  })

  test('returns a clear error when RetDec succeeds without writing output', async () => {
    const handler = createRetDecDecompileHandler(workspaceManager, database, {
      resolveBackends: () =>
        backendResolution({
          available: true,
          source: 'config',
          path: '/opt/retdec/bin/retdec-decompiler',
          version: '5.0',
          checked_candidates: ['retdec-decompiler'],
          error: null,
        }),
      executeCommand: async () => ({
        stdout: 'retdec ok without file',
        stderr: '',
        exitCode: 0,
        timedOut: false,
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain(
      'RetDec completed but did not produce the expected output file:'
    )
    expect(database.findArtifacts(sampleId)).toHaveLength(0)
  })
})
