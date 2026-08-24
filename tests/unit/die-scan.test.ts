import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import type { ToolchainBackendResolution } from '../../src/static-backend-discovery.js'
import diePlugin from '../../src/plugins/die/index.js'
import {
  createDieScanHandler,
  dieScanToolDefinition,
} from '../../src/plugins/die/tools/die-scan.js'

const SAMPLE_HASH = '9'.repeat(64)
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
      available: true,
      source: 'config',
      path: '/opt/die/diec',
      version: '3.10',
      checked_candidates: ['diec'],
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
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
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

describe('die.scan tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-die-scan-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '9'.repeat(32),
      size: 128,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), Buffer.from('MZdie-test'))
  })

  afterEach(() => {
    database.close()
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('returns structured validation handoff and persisted DIE scan artifact', async () => {
    const handler = createDieScanHandler(workspaceManager, database, {
      resolveBackends: createBackendResolution,
      executeCommand: async (_binaryPath, args) => ({
        stdout: JSON.stringify({
          filetype: 'PE32 executable',
          arch: 'x86-64',
          mode: 'console',
          entropy: 7.31,
          detects: [
            { type: 'Compiler', name: 'Microsoft Visual C++', version: '19.3' },
            { type: 'Packer', name: 'UPX', version: '4.x', options: 'compressed' },
            { type: 'Crypto', name: 'AES constants' },
          ],
          command_args_seen: args,
        }),
        stderr: '',
        exitCode: 0,
        timedOut: false,
      }),
    })

    const result = await handler({
      sample_id: SAMPLE_ID,
      deep_scan: true,
      persist_artifact: true,
      timeout_sec: 20,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.die_scan.v1')
    expect(data.tool_version).toBe('0.1.0')
    expect(data.artifact_type).toBe('backend_die_scan')
    expect(data.command_args).toEqual(expect.arrayContaining(['-j', '-d']))
    expect(data.file_type).toBe('PE32 executable')
    expect(data.compiler_findings[0]).toEqual(
      expect.objectContaining({
        name: 'Microsoft Visual C++',
        category: 'compiler',
      })
    )
    expect(data.packer_findings[0]).toEqual(
      expect.objectContaining({
        name: 'UPX',
        category: 'packer',
      })
    )
    expect(data.crypto_findings[0]).toEqual(
      expect.objectContaining({
        name: 'AES constants',
        category: 'crypto',
      })
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.die_scan.evidence_summary.v1',
        artifact_type: 'backend_die_scan',
        detect_count: 3,
        compiler_count: 1,
        packer_count: 1,
        crypto_count: 1,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.die_scan.workflow_handoff.v1',
        handoff_mode: 'die_scan_to_packer_validation_toolchain_correlation_and_reporting',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'packer-validation-and-unpack-planning',
            priority: 'high',
            next_tools: expect.arrayContaining(['packer.detect', 'unpack.workflow.plan']),
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
        schema: 'rikune.die_scan.quality_gates.v1',
        passive_static_scan: true,
        static_backend_started: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        packer_evidence_present: true,
        evidence_graph_handoff_ready: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'artifact.read',
        'compiler.packer.detect',
        'unpack.workflow.plan',
        'analysis.evidence.graph',
      ])
    )
    expect(result.artifacts).toHaveLength(1)
    expect(data.artifact).toEqual(result.artifacts?.[0])
    expect(data.artifact.type).toBe('backend_die_scan')

    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    const artifactPayload = JSON.parse(
      fs.readFileSync(path.join(workspace.root, data.artifact.path), 'utf8')
    )
    expect(artifactPayload.schema).toBe('rikune.die_scan.v1')
    expect(artifactPayload.raw_die_json.detects).toHaveLength(3)
    expect(artifactPayload.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ goal: 'packer-validation-and-unpack-planning' }),
        expect.objectContaining({ goal: 'evidence-graph-and-reporting' }),
      ])
    )
  })

  test('declares workflow recipe metadata for validation handoff', () => {
    expect(dieScanToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'die.scan-validation-handoff',
          startsWith: expect.arrayContaining(['die.scan', 'compiler.packer.detect']),
          nextTools: expect.arrayContaining([
            'artifact.read',
            'compiler.packer.detect',
            'unpack.workflow.plan',
            'analysis.evidence.graph',
          ]),
          producesArtifacts: expect.arrayContaining(['backend_die_scan']),
          evidence: expect.arrayContaining([
            'signatures',
            'toolchain',
            'packer',
            'protector',
            'file-type',
            'workflow',
          ]),
          safety: expect.arrayContaining([
            'passive',
            'external_static_backend',
            'no_live_sample_by_default',
            'no_network_by_default',
          ]),
        }),
      ])
    )
  })

  test('declares DIE_PATH as canonical backend path metadata', () => {
    expect(diePlugin.configSchema?.[0]).toEqual(
      expect.objectContaining({
        envVar: 'DIE_PATH',
      })
    )
    expect(diePlugin.systemDeps?.[0]).toEqual(
      expect.objectContaining({
        target: '$DIE_PATH',
        envVar: 'DIE_PATH',
      })
    )
  })
})
