import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createStaticConfigCarverHandler,
  staticConfigCarverToolDefinition,
} from '../../src/plugins/static-triage/tools/static-config-carver.js'

const SAMPLE_HASH = '2'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

describe('static.config.carver tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-config-carver-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    const payload = [
      'http://c2.example.net/gate',
      '192.0.2.10:443',
      'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'Global\\sample_mutex',
      'User-Agent: Mozilla/5.0',
      'U2VjcmV0Q29uZmlnVmFsdWU=',
    ].join('\0')
    const sampleBytes = Buffer.from(`MZ\0${payload}`, 'utf8')
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '2'.repeat(32),
      size: sampleBytes.length,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), sampleBytes)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore cleanup races in failed tests
    }
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('exports a generic config carver tool definition', () => {
    expect(staticConfigCarverToolDefinition.name).toBe('static.config.carver')
    expect(staticConfigCarverToolDefinition.description).toContain('configuration')
  })

  test('extracts high-signal config candidates and persists an artifact', async () => {
    const result = await createStaticConfigCarverHandler(workspaceManager, database)({
      sample_id: SAMPLE_ID,
      session_tag: 'config-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const kinds = new Set(data.candidates.map((candidate: any) => candidate.kind))
    expect(data.schema).toBe('rikune.static_config_carver.v1')
    expect(kinds.has('url')).toBe(true)
    expect(kinds.has('ip_port')).toBe(true)
    expect(kinds.has('registry_path')).toBe(true)
    expect(kinds.has('mutex_like')).toBe(true)
    expect(kinds.has('user_agent_or_http_client')).toBe(true)
    expect(data.blob_candidates.some((blob: any) => blob.kind === 'base64')).toBe(true)
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.static_config_carver.evidence_summary.v1',
        source_tool: 'static.config.carver',
        candidate_count: data.summary.candidate_count,
        blob_candidate_count: data.summary.blob_candidate_count,
        network_indicator_count: expect.any(Number),
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.static_config_carver.workflow_handoff.v1',
        handoff_mode: 'static_config_to_evidence_correlation',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'ioc-enrichment-and-export',
            next_tools: expect.arrayContaining(['malware.intel.loop', 'ioc.export']),
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
        passive_static_carving: true,
        backend_started: false,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        config_evidence_present: true,
        network_indicator_present: true,
        encoded_blob_present: true,
        runtime_followup_requires_opt_in: true,
      })
    )
    expect(data.recommended_next_tools).toContain('dynamic.deep_plan')

    const artifacts = database.findArtifactsByType(SAMPLE_ID, 'static_config_carver')
    expect(artifacts).toHaveLength(1)
    expect(result.artifacts?.[0]?.type).toBe('static_config_carver')
  })
})
