import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createEvidenceGraphHandler,
  evidenceGraphToolDefinition,
} from '../../src/plugins/visualization/tools/evidence-graph.js'

const SAMPLE_HASH = '4'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

describe('analysis.evidence.graph tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-evidence-graph-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '4'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    await persistStaticAnalysisJsonArtifact(workspaceManager, database, SAMPLE_ID, 'static_config_carver', 'config_carver', {
      schema: 'rikune.static_config_carver.v1',
      candidates: [
        { kind: 'url', value: 'http://c2.example.net/gate', confidence: 0.9, evidence: ['http_url_string'] },
        { kind: 'registry_path', value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', confidence: 0.8, evidence: ['registry_path_string'] },
      ],
      blob_candidates: [],
    })
    await persistStaticAnalysisJsonArtifact(workspaceManager, database, SAMPLE_ID, 'static_resource_graph', 'resource_graph', {
      schema: 'rikune.static_resource_graph.v1',
      resources: [
        {
          path: ['resources', 'id_10', 'id_1033'],
          size: 4096,
          magic: 'pe_or_dos',
          entropy: 6.1,
          stringPreview: ['resource payload'],
        },
      ],
    })
    await persistStaticAnalysisJsonArtifact(workspaceManager, database, SAMPLE_ID, 'dynamic_trace_json', 'dynamic_trace', {
      schema_version: '0.1.0',
      source_format: 'generic_json',
      evidence_kind: 'trace',
      imported_at: new Date().toISOString(),
      executed: true,
      raw_event_count: 2,
      api_calls: [
        { api: 'InternetConnectW', category: 'network', count: 1, confidence: 0.9, sources: [] },
        { api: 'RegSetValueExW', category: 'registry', count: 1, confidence: 0.9, sources: [] },
      ],
      memory_regions: [],
      modules: [],
      strings: [],
      stages: ['network', 'registry_operations'],
      risk_hints: [],
      notes: [],
    })
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore cleanup races in failed tests
    }
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('exports evidence graph tool definition', () => {
    expect(evidenceGraphToolDefinition.name).toBe('analysis.evidence.graph')
    expect(evidenceGraphToolDefinition.description).toContain('evidence graph')
  })

  test('correlates static expectations with runtime observations', async () => {
    const result = await createEvidenceGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      session_tag: 'graph-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.analysis_evidence_graph.v1')
    expect(data.summary.static_artifact_count).toBe(2)
    expect(data.summary.dynamic_artifact_count).toBe(1)
    expect(data.summary.expectation_count).toBeGreaterThanOrEqual(3)
    expect(data.summary.observation_count).toBeGreaterThanOrEqual(2)
    expect(data.summary.corroboration_edge_count).toBeGreaterThan(0)
    expect(data.graph.nodes.some((node: any) => node.kind === 'expectation' && node.category === 'network')).toBe(true)
    expect(data.graph.nodes.some((node: any) => node.kind === 'observation' && node.category === 'registry')).toBe(true)
    expect(result.artifacts?.[0]?.type).toBe('analysis_evidence_graph')
  })
})
