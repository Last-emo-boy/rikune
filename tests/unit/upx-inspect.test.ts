import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import type { ToolchainBackendResolution } from '../../src/static-backend-discovery.js'
import {
  createUPXInspectHandler,
  upxInspectToolDefinition,
} from '../../src/plugins/upx/tools/upx-inspect.js'

const SAMPLE_HASH = '8'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

function createBackendResolution(): ToolchainBackendResolution {
  return {
    capa_cli: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    capa_rules: { available: false, source: 'none', path: null, error: null },
    die: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    graphviz: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    rizin: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    upx: {
      available: true,
      source: 'config',
      path: '/opt/upx/upx',
      version: '5.1.1',
      checked_candidates: ['upx'],
      error: null,
    },
    wine: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    winedbg: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    frida_cli: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    yara_x: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    qiling: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    angr: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    panda: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    retdec: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
  }
}

describe('upx.inspect tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-upx-inspect-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '8'.repeat(32),
      size: 96,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), Buffer.from('MZupx-test'))
  })

  afterEach(() => {
    database.close()
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('returns structured inspection handoff and persisted JSON artifact', async () => {
    const handler = createUPXInspectHandler(workspaceManager, database, {
      resolveBackends: createBackendResolution,
      executeCommand: async () => ({
        stdout:
          'Ultimate Packer for eXecutables\nFile size Ratio Format Name\n4096 2048 50.0% win64/pe sample.exe',
        stderr: '',
        exitCode: 0,
        timedOut: false,
      }),
    })

    const result = await handler({
      sample_id: SAMPLE_ID,
      operation: 'list',
      persist_artifact: true,
      timeout_sec: 10,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.upx_inspect.v1')
    expect(data.tool_version).toBe('0.1.0')
    expect(data.operation).toBe('list')
    expect(data.artifact_type).toBe('backend_upx_list')
    expect(data.command_args[0]).toBe('-l')
    expect(data.upx_detected).toBe(true)
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.upx_inspect.evidence_summary.v1',
        artifact_type: 'backend_upx_list',
        operation: 'list',
        upx_detected: true,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.upx_inspect.workflow_handoff.v1',
        handoff_mode: 'upx_inspection_to_unpack_validation_retriage_and_reporting',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'artifact-review-and-packer-validation',
            next_tools: expect.arrayContaining(['artifact.read', 'unpack.workflow.plan']),
          }),
          expect.objectContaining({
            goal: 'evidence-graph-and-reporting',
            next_tools: expect.arrayContaining(['analysis.evidence.graph', 'report.generate']),
          }),
        ]),
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.upx_inspect.quality_gates.v1',
        passive_inspection_only: true,
        backend_started: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        file_transformation_performed: false,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['artifact.read', 'unpack.workflow.plan', 'analysis.evidence.graph'])
    )
    expect(result.artifacts).toHaveLength(1)
    expect(data.artifact).toEqual(result.artifacts?.[0])
    expect(data.artifact.type).toBe('backend_upx_list')

    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    const artifactPayload = JSON.parse(
      fs.readFileSync(path.join(workspace.root, data.artifact.path), 'utf8')
    )
    expect(artifactPayload.schema).toBe('rikune.upx_inspect.v1')
    expect(artifactPayload.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ goal: 'artifact-review-and-packer-validation' }),
        expect.objectContaining({ goal: 'evidence-graph-and-reporting' }),
      ])
    )
  })

  test('keeps decompressed binary artifact while returning structured re-triage handoff', async () => {
    const handler = createUPXInspectHandler(workspaceManager, database, {
      resolveBackends: createBackendResolution,
      executeCommand: async (_binaryPath, args) => {
        const outputIndex = args.indexOf('-o')
        fs.writeFileSync(args[outputIndex + 1], Buffer.from('MZunpacked'))
        return {
          stdout: 'Unpacked 1 file.',
          stderr: '',
          exitCode: 0,
          timedOut: false,
        }
      },
    })

    const result = await handler({
      sample_id: SAMPLE_ID,
      operation: 'decompress',
      persist_artifact: true,
      timeout_sec: 10,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.upx_inspect.v1')
    expect(data.operation).toBe('decompress')
    expect(data.artifact_type).toBe('backend_upx_decompress')
    expect(data.artifact.type).toBe('backend_upx_decompress')
    expect(data.decompressed_artifact).toEqual(data.artifact)
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        file_transformation_performed: true,
        decompressed_artifact_created: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        retriage_required_after_decompress: true,
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'decompressed-artifact-retriage',
          next_tools: expect.arrayContaining(['static.triage', 'strings.extract', 'yara.scan']),
        }),
      ])
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['static.triage', 'strings.extract', 'analysis.evidence.graph'])
    )

    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    const artifactBytes = fs.readFileSync(path.join(workspace.root, data.artifact.path))
    expect(artifactBytes.toString('utf8')).toBe('MZunpacked')
  })

  test('declares workflow recipe metadata for validation handoff', () => {
    expect(upxInspectToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'upx.inspect-validation-handoff',
          startsWith: expect.arrayContaining(['upx.inspect', 'packer.detect', 'die.scan']),
          nextTools: expect.arrayContaining([
            'artifact.read',
            'unpack.workflow.plan',
            'analysis.evidence.graph',
          ]),
          producesArtifacts: expect.arrayContaining([
            'backend_upx_list',
            'backend_upx_test',
            'backend_upx_decompress',
          ]),
          evidence: expect.arrayContaining([
            'packed',
            'structure',
            'unpacked-binary',
            'workflow',
            'provenance',
          ]),
          safety: expect.arrayContaining([
            'passive',
            'no_live_sample_by_default',
            'no_network_by_default',
          ]),
        }),
      ])
    )
  })
})
