import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import {
  createIOCExportHandler,
  iocExportToolDefinition,
} from '../../src/plugins/threat-intel/tools/ioc-export.js'

jest.setTimeout(15000)

describe('ioc.export tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let handler: ReturnType<typeof createIOCExportHandler>

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ioc-export-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    cacheManager = new CacheManager(path.join(tempDir, 'cache'), database)
    handler = createIOCExportHandler({ workspaceManager, database, cacheManager } as any)
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should return error for unknown sample', async () => {
    const result = await handler({
      sample_id: `sha256:${'a'.repeat(64)}`,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should expose IOC export handoff recipe metadata', () => {
    expect(iocExportToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'threat-intel.ioc-export-handoff',
        startsWith: expect.arrayContaining(['ioc.export', 'workflow.triage']),
        nextTools: expect.arrayContaining([
          'analysis.evidence.graph',
          'malware.intel.loop',
          'sigma.rule.generate',
          'report.generate',
        ]),
        producesArtifacts: expect.arrayContaining([
          'ioc_export_json',
          'ioc_export_csv',
          'ioc_export_stix2',
        ]),
        evidence: expect.arrayContaining(['network', 'registry', 'workflow', 'provenance']),
        safety: expect.arrayContaining(['passive', 'no_live_sample_by_default']),
      })
    )
  })

  test('should export IOC bundle in JSON and persist artifact', async () => {
    const sample = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.from('\x00'.repeat(128), 'binary'),
      Buffer.from(
        'http://download.example/payload powershell.exe HKEY_CURRENT_USER\\Software\\Run',
        'utf-8'
      ),
    ])
    const sampleId = await ingestSample(workspaceManager, database, sample)

    const result = await handler({
      sample_id: sampleId,
      format: 'json',
      include_attack_map: true,
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      schema: string
      format: string
      ioc_count: number
      available_ioc_count: number
      content: string
      attack_technique_count: number
      evidence_summary: Record<string, any>
      workflow_handoff: Record<string, any>
      quality_gates: Record<string, any>
      recommended_next_tools: string[]
      next_actions: string[]
      artifact?: { id: string; type: string }
    }
    expect(data.schema).toBe('rikune.ioc_export.v1')
    expect(data.format).toBe('json')
    expect(data.ioc_count).toBeGreaterThan(0)
    expect(data.available_ioc_count).toBeGreaterThanOrEqual(data.ioc_count)
    expect(data.content).toContain('"sample_id"')
    expect(data.attack_technique_count).toBeGreaterThanOrEqual(0)
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.ioc_export.evidence_summary.v1',
        artifact_type: 'ioc_export_json',
        exported_ioc_count: data.ioc_count,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.ioc_export.workflow_handoff.v1',
        handoff_mode: 'ioc_export_to_enrichment_detection_and_reporting',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'evidence-graph-and-reporting',
            next_tools: expect.arrayContaining(['analysis.evidence.graph']),
          }),
        ]),
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        passive_export_only: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        sharing_review_required: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['analysis.evidence.graph', 'malware.intel.loop', 'report.generate'])
    )
    expect(data.next_actions.length).toBeGreaterThan(0)
    expect(data.artifact?.type).toBe('ioc_export_json')

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const artifactPath = path.join(workspace.root, (data.artifact as { path: string }).path)
    const persisted = JSON.parse(await fs.readFile(artifactPath, 'utf-8')) as {
      schema: string
      evidence_summary: Record<string, any>
      workflow_handoff: Record<string, any>
      quality_gates: Record<string, any>
    }
    expect(persisted.schema).toBe('rikune.ioc_export.v1')
    expect(persisted.evidence_summary.schema).toBe('rikune.ioc_export.evidence_summary.v1')
    expect(persisted.workflow_handoff.schema).toBe('rikune.ioc_export.workflow_handoff.v1')
    expect(persisted.quality_gates.schema).toBe('rikune.ioc_export.quality_gates.v1')
  })

  test('should export IOC bundle in CSV without persistence', async () => {
    const sampleId = await ingestSample(
      workspaceManager,
      database,
      Buffer.concat([
        Buffer.from('MZ', 'ascii'),
        Buffer.from('\x00'.repeat(128), 'binary'),
        Buffer.from('cmd.exe /c whoami http://example.org', 'utf-8'),
      ])
    )

    const result = await handler({
      sample_id: sampleId,
      format: 'csv',
      include_attack_map: false,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as { content: string; artifact?: unknown }
    expect(data.content.split('\n')[0]).toBe('type,value,confidence,source,tags')
    expect(data.artifact).toBeUndefined()
  })

  test('should embed structured handoff extensions in STIX export', async () => {
    const sampleId = await ingestSample(
      workspaceManager,
      database,
      Buffer.concat([
        Buffer.from('MZ', 'ascii'),
        Buffer.from('\x00'.repeat(128), 'binary'),
        Buffer.from('http://stix.example.net/dropper HKEY_CURRENT_USER\\Software\\Run', 'utf-8'),
      ])
    )

    const result = await handler({
      sample_id: sampleId,
      format: 'stix2',
      include_attack_map: true,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as { content: string; mime_type: string; quality_gates: any }
    const bundle = JSON.parse(data.content) as any
    expect(data.mime_type).toBe('application/stix+json')
    expect(bundle.type).toBe('bundle')
    expect(bundle.x_mcp_schema).toBe('rikune.ioc_export.v1')
    expect(bundle.x_mcp_workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.ioc_export.workflow_handoff.v1',
        artifact_type: 'ioc_export_stix2',
      })
    )
    expect(bundle.x_mcp_quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.ioc_export.quality_gates.v1',
        stix_review_required: true,
      })
    )
    expect(data.quality_gates.stix_review_required).toBe(true)
  })
})

async function ingestSample(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  data: Buffer
): Promise<string> {
  const sha256 = crypto.createHash('sha256').update(data).digest('hex')
  const md5 = crypto.createHash('md5').update(data).digest('hex')
  const sampleId = `sha256:${sha256}`

  database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
    id: sampleId,
    sha256,
    md5,
    size: data.length,
    file_type: 'PE32',
    created_at: new Date().toISOString(),
    source: 'test',
  })

  const workspace = await workspaceManager.createWorkspace(sampleId)
  await fs.writeFile(path.join(workspace.original, 'sample.exe'), data)
  return sampleId
}
