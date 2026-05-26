import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import { createHash } from 'crypto'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import type { ToolchainBackendResolution } from '../../src/static-backend-discovery.js'
import {
  createYaraXScanHandler,
  yaraXScanToolDefinition,
} from '../../src/plugins/yara-x/tools/yara-x-scan.js'

const SAMPLE_HASH = '6'.repeat(64)
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
      available: true,
      source: 'config',
      path: '/opt/yara-x/bin/python',
      version: '0.13.0',
      checked_candidates: ['python3'],
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

describe('yara_x.scan tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-yara-x-scan-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '7'.repeat(32),
      size: 64,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), Buffer.from('MZunit-test'))
  })

  afterEach(() => {
    database.close()
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('returns structured handoff, quality gates, and persisted artifact', async () => {
    const rulesText = 'rule SuspiciousUnitRule { strings: $a = "unit" condition: $a }'
    const handler = createYaraXScanHandler(workspaceManager, database, {
      resolveBackends: createBackendResolution,
      runPythonJson: async () => ({
        stdout: '',
        stderr: '',
        parsed: {
          match_count: 1,
          matching_rules: [
            {
              identifier: 'SuspiciousUnitRule',
              namespace: 'default',
              patterns: [
                { identifier: '$a', matches: [{ offset: 16, length: 4 }] },
                { identifier: '$b', matches: [{ offset: 32, length: 8 }] },
              ],
            },
          ],
          module_outputs: { pe: { imphash: 'abc' } },
        },
      }),
    })

    const result = await handler({
      sample_id: SAMPLE_ID,
      rules_text: rulesText,
      persist_artifact: true,
      timeout_sec: 15,
      max_matches_per_pattern: 250,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.yara_x_scan.v1')
    expect(data.tool_version).toBe('0.1.0')
    expect(data.rules_digest).toBe(createHash('sha256').update(rulesText).digest('hex'))
    expect(data.rules_source).toBe('inline')
    expect(data.match_count).toBe(1)
    expect(data.pattern_match_count).toBe(2)
    expect(data.matching_rules).toHaveLength(1)
    expect(data.matches).toHaveLength(1)
    expect(data.module_outputs.pe.imphash).toBe('abc')
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.evidence_summary.v1',
        artifact_type: 'backend_yara_x_scan',
        match_count: 1,
        pattern_match_count: 2,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.workflow_handoff.v1',
        handoff_mode: 'yara_x_scan_to_rule_validation_and_reporting',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'evidence-graph-and-reporting',
            next_tools: expect.arrayContaining(['analysis.evidence.graph', 'report.generate']),
          }),
        ]),
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.quality_gates.v1',
        passive_scan_only: true,
        backend_started: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        legacy_yara_comparison_recommended: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['artifact.read', 'yara.scan', 'analysis.evidence.graph'])
    )
    expect(result.artifacts).toHaveLength(1)
    expect(data.artifact).toEqual(result.artifacts?.[0])
    expect(data.artifact.type).toBe('backend_yara_x_scan')

    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    const artifactPayload = JSON.parse(
      fs.readFileSync(path.join(workspace.root, data.artifact.path), 'utf8')
    )
    expect(artifactPayload.schema).toBe('rikune.yara_x_scan.v1')
    expect(artifactPayload.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ goal: 'legacy-yara-comparison' }),
        expect.objectContaining({ goal: 'evidence-graph-and-reporting' }),
      ])
    )
  })

  test('declares workflow recipe metadata for validation handoff', () => {
    expect(yaraXScanToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'yara-x.scan-validation-handoff',
          startsWith: expect.arrayContaining(['yara_x.scan', 'yara.generate']),
          nextTools: expect.arrayContaining([
            'artifact.read',
            'yara.scan',
            'analysis.evidence.graph',
          ]),
          producesArtifacts: expect.arrayContaining(['backend_yara_x_scan']),
          evidence: expect.arrayContaining(['signatures', 'strings', 'workflow', 'provenance']),
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
