import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createDynamicBehaviorDiffHandler,
  dynamicBehaviorDiffToolDefinition,
} from '../../src/plugins/dynamic/tools/dynamic-behavior-diff.js'

const SAMPLE_HASH = '5'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

describe('dynamic.behavior.diff tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-behavior-diff-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '5'.repeat(32),
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
      blob_candidates: [
        { kind: 'base64', value_preview: 'U2VjcmV0Q29uZmlnVmFsdWU=', confidence: 0.5, evidence: ['decoded_entropy=3.8'] },
      ],
    })
    await persistStaticAnalysisJsonArtifact(workspaceManager, database, SAMPLE_ID, 'static_resource_graph', 'resource_graph', {
      schema: 'rikune.static_resource_graph.v1',
      resources: [
        {
          path: ['resources', 'id_10'],
          size: 8192,
          magic: 'pe_or_dos',
          entropy: 6.2,
          stringPreview: [],
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

  test('exports behavior diff tool definition', () => {
    expect(dynamicBehaviorDiffToolDefinition.name).toBe('dynamic.behavior.diff')
    expect(dynamicBehaviorDiffToolDefinition.description).toContain('static behavior expectations')
  })

  test('reports confirmed runtime behavior and dormant static expectations', async () => {
    const result = await createDynamicBehaviorDiffHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      session_tag: 'diff-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.dynamic_behavior_diff.v1')
    expect(data.diff.coverage.dynamic_executed).toBe(true)
    expect(data.diff.confirmed_behaviors.some((item: any) => item.category === 'network')).toBe(true)
    expect(data.diff.confirmed_behaviors.some((item: any) => item.category === 'persistence')).toBe(true)
    expect(data.diff.missing_expectations.some((item: any) => item.category === 'embedded_payload')).toBe(true)
    expect(data.diff.recommended_next_tools).toContain('analysis.evidence.graph')
    expect(result.artifacts?.[0]?.type).toBe('dynamic_behavior_diff')
  })
})
