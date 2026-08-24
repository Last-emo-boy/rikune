import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createHashIdentifyHandler,
  hashIdentifyToolDefinition,
} from '../../src/plugins/api-hash/tools/hash-identify.js'
import {
  createHashResolveHandler,
  hashResolveToolDefinition,
} from '../../src/plugins/api-hash/tools/hash-resolve.js'

const unavailablePython = {
  available: false,
  source: 'none',
  path: null,
  version: null,
  checked_candidates: ['python3', 'python'],
  error: 'Python 3 not found',
}

const availablePython = {
  available: true,
  source: 'config',
  path: '/usr/bin/python3',
  version: 'Python 3.11.8',
  checked_candidates: ['python3'],
  error: null,
}

describe('api hash tools', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'4'.repeat(64)}`

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'api-hash-tools-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: '4'.repeat(64),
      md5: '4'.repeat(32),
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

  test('declares passive profile metadata for hash identification and resolution', () => {
    expect(hashIdentifyToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['pe', 'shellcode', 'memory']),
        execution: expect.arrayContaining(['static', 'triage']),
        runtimes: ['python'],
        safety: expect.arrayContaining(['passive', 'read_only', 'no_network_by_default']),
        capabilities: expect.arrayContaining([
          'api-hash-identification',
          'hash-algorithm-candidate-ranking',
          'workflow-handoff',
        ]),
      })
    )
    expect(hashIdentifyToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'api-hash.identify-handoff',
        startsWith: ['hash.identify'],
        nextTools: expect.arrayContaining(['workflow.search', 'hash.resolve', 'disasm.quick']),
        safety: expect.arrayContaining(['passive', 'read_only', 'no_network_by_default']),
      })
    )
    expect(hashIdentifyToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(hashIdentifyToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'python',
        adapter: 'api_hash.identify',
        envVar: 'PYTHON_PATH',
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
          missingBackendBehavior: 'Return setup_required without identifying hash algorithms.',
        }),
      })
    )

    expect(hashResolveToolDefinition.artifacts).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: 'backend_hash_resolve' })])
    )
    expect(hashResolveToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'imports',
          artifactTypes: ['backend_hash_resolve'],
        }),
      ])
    )
    expect(hashResolveToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'api-hash.resolve-handoff',
        startsWith: ['hash.resolve'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'workflow.search',
          'disasm.quick',
          'analysis.evidence.graph',
        ]),
        producesArtifacts: ['backend_hash_resolve'],
      })
    )
  })

  test('hash.identify returns a standard handoff envelope with narrow next tools', async () => {
    const handler = createHashIdentifyHandler(workspaceManager, database, {
      resolveExecutable: () => availablePython,
      runPythonJson: async () => ({
        parsed: {
          candidates: [
            {
              algorithm: 'ror13',
              matches: 1,
              total: 2,
              match_rate: 0.5,
              sample_matches: [{ hash: '0xec0e4e8e', api: 'LoadLibraryA' }],
            },
          ],
        },
      }),
    })

    const result = await handler({
      hashes: ['0xec0e4e8e', '0x6a4abc5b'],
      unicode: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.api_hash_identify.v1')
    expect(data.recommended_next_tools).toEqual(['workflow.search'])
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.api_hash_identify.evidence_summary.v1',
        source_tool: 'hash.identify',
        requested_hash_count: 2,
        candidate_count: 1,
        best_algorithm: 'ror13',
        best_match_rate: 0.5,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.api_hash_identify.workflow_handoff.v1',
        handoff_mode: 'api_hash_algorithm_identification_to_resolution',
        best_algorithm: 'ror13',
        recommended_next_tools: ['workflow.search'],
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'resolve-with-identified-algorithm',
          next_tools: ['hash.resolve'],
        }),
      ])
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.api_hash_identify.quality_gates.v1',
        passive_static_analysis: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        artifact_persisted: false,
      })
    )
  })

  test('hash.resolve persists a standard API hash resolution artifact envelope', async () => {
    const handler = createHashResolveHandler(workspaceManager, database, {
      resolveExecutable: () => availablePython,
      runPythonJson: async () => ({
        parsed: {
          resolved_count: 1,
          unresolved_count: 1,
          results: [
            {
              hash: '0xec0e4e8e',
              algorithm: 'ror13',
              api_name: 'LoadLibraryA',
              dll: '',
              resolved: true,
            },
            { hash: '0x11111111', resolved: false },
          ],
        },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      hashes: ['0xec0e4e8e', '0x11111111'],
      algorithm: 'auto',
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.api_hash_resolve.v1')
    expect(data.recommended_next_tools).toEqual(['artifact.read', 'workflow.search'])
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.api_hash_resolve.evidence_summary.v1',
        source_tool: 'hash.resolve',
        artifact_type: 'backend_hash_resolve',
        sample_id: sampleId,
        algorithm: 'auto',
        requested_hash_count: 2,
        resolved_count: 1,
        unresolved_count: 1,
        resolved_api_names: ['LoadLibraryA'],
        artifact_id: result.artifacts?.[0]?.id,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.api_hash_resolve.workflow_handoff.v1',
        handoff_mode: 'api_hash_resolution_to_import_behavior_review',
        artifact_type: 'backend_hash_resolve',
        recommended_next_tools: ['artifact.read', 'workflow.search'],
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'corroborate-hash-computation',
          next_tools: ['disasm.quick', 'analysis.evidence.graph'],
        }),
      ])
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.api_hash_resolve.quality_gates.v1',
        passive_static_analysis: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        artifact_persisted: true,
      })
    )
    expect(result.artifacts?.[0]).toEqual(
      expect.objectContaining({ type: 'backend_hash_resolve', mime: 'application/json' })
    )

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persisted = JSON.parse(
      await fs.readFile(path.join(workspace.root, result.artifacts![0].path), 'utf8')
    )
    expect(persisted.schema).toBe('rikune.api_hash_resolve.v1')
    expect(persisted.workflow_handoff.schema).toBe('rikune.api_hash_resolve.workflow_handoff.v1')
    expect(persisted.quality_gates.passive_static_analysis).toBe(true)
    expect(persisted.raw_hash_result.results).toHaveLength(2)
  })

  test('reports setup_required without invoking Python when the backend is unavailable', async () => {
    const runPythonJson = jest.fn(async () => {
      throw new Error('runPythonJson should not be called')
    })
    const handler = createHashResolveHandler(workspaceManager, database, {
      resolveExecutable: () => unavailablePython,
      runPythonJson,
    })

    const result = await handler({ hashes: ['0xec0e4e8e'] })

    expect(result.ok).toBe(true)
    expect((result.data as any).status).toBe('setup_required')
    expect((result.data as any).backend.error).toBe('Python 3 not found')
    expect(result.warnings).toContain('Python 3 not found')
    expect(runPythonJson).not.toHaveBeenCalled()
  })
})
