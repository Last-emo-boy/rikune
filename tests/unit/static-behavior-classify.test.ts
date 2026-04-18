import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createStaticBehaviorClassifyHandler,
  staticBehaviorClassifyToolDefinition,
} from '../../src/plugins/static-triage/tools/static-behavior-classify.js'

const SAMPLE_HASH = '8'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

describe('static.behavior.classify tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-static-behavior-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

    const payload = [
      'MZ',
      'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'OpenProcess',
      'VirtualAllocEx',
      'WriteProcessMemory',
      'CreateRemoteThread',
      'CREATE_SUSPENDED',
      'NtUnmapViewOfSection',
      'SetThreadContext',
      'ResumeThread',
    ].join('\0')
    const sampleBytes = Buffer.from(payload, 'ascii')
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '8'.repeat(32),
      size: sampleBytes.length,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'behavior.exe'), sampleBytes)

    await persistStaticAnalysisJsonArtifact(workspaceManager, database, SAMPLE_ID, 'static_config_carver', 'config_carver', {
      schema: 'rikune.static_config_carver.v1',
      candidates: [
        {
          kind: 'registry_path',
          value: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          confidence: 0.84,
          evidence: ['registry_path_string'],
        },
      ],
    }, 'behavior-session')

    await persistStaticAnalysisJsonArtifact(workspaceManager, database, SAMPLE_ID, 'dynamic_trace_json', 'dynamic_trace', {
      schema_version: '0.1.0',
      source_format: 'generic_json',
      evidence_kind: 'trace',
      imported_at: new Date().toISOString(),
      executed: true,
      raw_event_count: 2,
      api_calls: [
        { api: 'WriteProcessMemory', category: 'process_manipulation', count: 1, confidence: 0.92, sources: [] },
        { api: 'CreateRemoteThread', category: 'process_manipulation', count: 1, confidence: 0.92, sources: [] },
      ],
      memory_regions: [],
      modules: [],
      strings: [],
      stages: ['prepare_remote_process_access'],
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

  test('exports behavior classifier tool definition', () => {
    expect(staticBehaviorClassifyToolDefinition.name).toBe('static.behavior.classify')
    expect(staticBehaviorClassifyToolDefinition.description).toContain('persistence')
  })

  test('classifies persistence and injection indicators', async () => {
    const result = await createStaticBehaviorClassifyHandler(workspaceManager, database)({
      sample_id: SAMPLE_ID,
      static_artifact_scope: 'session',
      static_artifact_session_tag: 'behavior-session',
      session_tag: 'classifier-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.static_behavior_classifier.v1')
    expect(data.summary.finding_count).toBeGreaterThanOrEqual(2)
    expect(data.findings.some((finding: any) => finding.id === 'persistence.run_key')).toBe(true)
    expect(data.findings.some((finding: any) => finding.id === 'injection.remote_thread')).toBe(true)
    expect(data.findings.some((finding: any) => finding.id === 'injection.process_hollowing')).toBe(true)
    expect(data.dynamic_summary.executed).toBe(true)
    expect(data.recommended_next_tools).toContain('dynamic.behavior.diff')
    expect(result.artifacts?.[0]?.type).toBe('static_behavior_classifier')
  })
})
