import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { JobQueue } from '../../src/job-queue.js'
import {
  attackMapToolDefinition,
  createAttackMapHandler,
  mapIndicatorsToAttack,
} from '../../src/plugins/threat-intel/tools/attack-map.js'

jest.setTimeout(15000)

describe('attack.map tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let handler: ReturnType<typeof createAttackMapHandler>

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attack-map-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    cacheManager = new CacheManager(path.join(tempDir, 'cache'), database)
    handler = createAttackMapHandler({ workspaceManager, database, cacheManager } as any)
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should expose ATT&CK handoff workflow metadata', () => {
    expect(attackMapToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'threat-intel.attack-map-handoff',
        startsWith: expect.arrayContaining(['attack.map', 'workflow.triage']),
        nextTools: expect.arrayContaining([
          'analysis.evidence.graph',
          'ioc.export',
          'sigma.rule.generate',
          'yara.generate',
          'report.generate',
          'artifact.read',
        ]),
        producesArtifacts: expect.arrayContaining(['attack_map']),
        safety: expect.arrayContaining([
          'passive',
          'no_live_sample_by_default',
          'no_network_by_default',
        ]),
      })
    )
  })

  test('should return error for unknown sample', async () => {
    const result = await handler({
      sample_id: `sha256:${'a'.repeat(64)}`,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should map ATT&CK techniques from string and IOC evidence', async () => {
    const sample = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.from('\x00'.repeat(256), 'binary'),
      Buffer.from(
        'powershell.exe -enc AAAA http://c2.example/a HKEY_CURRENT_USER\\Software\\Run',
        'utf-8'
      ),
    ])
    const sampleId = await ingestSample(workspaceManager, database, sample)

    const result = await handler({
      sample_id: sampleId,
      include_low_confidence: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      techniques: Array<{ technique_id: string }>
      capability_clusters: Array<{ capability: string }>
      tactic_summary: Record<string, number>
      evidence_summary: Record<string, any>
      workflow_handoff: Record<string, any>
      quality_gates: Record<string, any>
      recommended_next_tools: string[]
      next_actions: string[]
    }
    expect(data.techniques.length).toBeGreaterThan(0)
    const techniqueIds = data.techniques.map((item) => item.technique_id)
    expect(
      techniqueIds.includes('T1059.001') ||
        techniqueIds.includes('T1059.003') ||
        techniqueIds.includes('T1071.001')
    ).toBe(true)
    expect(data.capability_clusters.length).toBeGreaterThan(0)
    expect(Object.keys(data.tactic_summary).length).toBeGreaterThan(0)
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['analysis.evidence.graph', 'ioc.export', 'report.generate'])
    )
    expect(data.next_actions).toEqual(
      expect.arrayContaining([
        expect.stringContaining('analysis.evidence.graph'),
        expect.stringContaining('ioc.export'),
      ])
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.attack_map.evidence_summary.v1',
        source_tool: 'attack.map',
        artifact_type: 'attack_map',
        technique_count: data.techniques.length,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.attack_map.quality_gates.v1',
        passive_mapping_only: true,
        sample_executed_by_tool: false,
        backend_started: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        analyst_review_required: true,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.attack_map.workflow_handoff.v1',
        handoff_mode: 'attack_mapping_to_evidence_detection_and_reporting',
        artifact_type: 'attack_map',
        recommended_next_tools: expect.arrayContaining([
          'analysis.evidence.graph',
          'ioc.export',
          'report.generate',
        ]),
      })
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        backend_started: false,
        network_accessed_by_tool: false,
        live_lookup_started: false,
      })
    )
  })

  test('should reuse cached ATT&CK mapping for compatible repeated requests', async () => {
    const sample = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.from('\x00'.repeat(256), 'binary'),
      Buffer.from('powershell.exe http://cached.example/a', 'utf-8'),
    ])
    const sampleId = await ingestSample(workspaceManager, database, sample)

    const first = await handler({
      sample_id: sampleId,
      include_low_confidence: true,
    })
    expect(first.ok).toBe(true)

    const second = await handler({
      sample_id: sampleId,
      include_low_confidence: true,
    })

    expect(second.ok).toBe(true)
    expect((second.metrics as any)?.cached).toBe(true)
    expect(second.warnings).toEqual(expect.arrayContaining(['Result from cache']))
  })

  test('should defer medium samples to the background queue when allowed', async () => {
    const jobQueue = new JobQueue(database)
    const deferredHandler = createAttackMapHandler({
      workspaceManager,
      database,
      cacheManager,
      jobQueue,
    } as any)
    const sample = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.alloc(1024 * 1024 + 1, 0),
      Buffer.from('http://large.example/a', 'utf-8'),
    ])
    const sampleId = await ingestSample(workspaceManager, database, sample)

    const result = await deferredHandler({
      sample_id: sampleId,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('queued')
    expect(data.result_mode).toBe('queued')
    expect(data.job_id).toBeDefined()
    expect(jobQueue.getStatus(data.job_id)?.status).toBe('queued')
  })

  test('should suppress weak ransomware mapping by default for dual-use tooling', () => {
    const indicators = {
      suspiciousImports: ['kernel32.dll!WriteProcessMemory', 'kernel32.dll!CreateProcessW'],
      suspiciousStrings: ['usage: akasha --pid 123', 'dump process memory'],
      commands: ['akasha --pid 123 dump'],
      urls: [],
      ips: [],
      registryKeys: [],
      yaraMatches: [],
      yaraLowConfidence: ['Ransomware_Indicators'],
      packed: false,
      packerConfidence: 0,
      intentLabel: 'dual_use_tool' as const,
      intentConfidence: 0.78,
    }

    const withoutLowConfidence = mapIndicatorsToAttack(indicators, {
      includeLowConfidence: false,
      maxTechniques: 20,
    })
    expect(withoutLowConfidence.techniques.some((item) => item.technique_id === 'T1486')).toBe(
      false
    )

    const withLowConfidence = mapIndicatorsToAttack(indicators, {
      includeLowConfidence: true,
      maxTechniques: 20,
    })
    const ransomwareTechnique = withLowConfidence.techniques.find(
      (item) => item.technique_id === 'T1486'
    )

    expect(ransomwareTechnique).toBeDefined()
    expect(ransomwareTechnique?.confidence_level).toBe('low')
    expect(ransomwareTechnique?.confidence).toBeLessThan(0.2)
    expect(ransomwareTechnique?.counter_evidence).toEqual(
      expect.arrayContaining([
        expect.stringContaining('low-confidence/string-heavy ransomware YARA hints'),
        expect.stringContaining('dual-use operator tool'),
      ])
    )
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

  database.insertSample({
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
