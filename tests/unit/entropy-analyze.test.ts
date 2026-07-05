import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import {
  createEntropyAnalyzeHandler,
  entropyAnalyzeToolDefinition,
} from '../../src/plugins/static-triage/tools/entropy-analyze.js'
import type { ArtifactRef } from '../../src/types.js'

const sampleId = `sha256:${'5'.repeat(64)}`

function workerEntropyData() {
  return {
    file_size: 4096,
    overall_entropy: 7.45,
    block_size: 256,
    block_count: 16,
    histogram: [0, 1, 2],
    sections: [
      {
        name: '.text',
        entropy: 6.2,
        raw_size: 1024,
        virtual_size: 1024,
        vsize_ratio: 1,
        characteristics: 'rx',
        suspicious: false,
      },
      {
        name: '.packed',
        entropy: 7.8,
        raw_size: 2048,
        virtual_size: 4096,
        vsize_ratio: 2,
        characteristics: 'rw',
        suspicious: true,
      },
    ],
    high_entropy_regions: [
      {
        offset: 1024,
        end_offset: 2048,
        length: 1024,
        avg_entropy: 7.7,
      },
    ],
    classification: {
      packing_likelihood: 'high',
      crypto_data_likelihood: 'medium',
      is_pe: true,
    },
    recommended_next_tools: ['packer.detect', 'unpack.workflow.plan'],
  }
}

describe('entropy.analyze', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'entropy-analyze-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    cacheManager = new CacheManager(path.join(tempDir, 'cache'), database)
    database.insertSample({
      id: sampleId,
      sha256: '5'.repeat(64),
      md5: '5'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'sample.exe'), Buffer.from('MZentropy'))
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('declares passive entropy profile metadata and static worker contract', () => {
    expect(entropyAnalyzeToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['pe', 'elf', 'macho', 'firmware']),
        execution: expect.arrayContaining(['static', 'triage']),
        runtimes: ['static-worker'],
        safety: expect.arrayContaining(['passive', 'read_only', 'no_network_by_default']),
        capabilities: expect.arrayContaining([
          'entropy-analysis',
          'packer-triage',
          'workflow-handoff',
        ]),
      })
    )
    expect(entropyAnalyzeToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'entropy_analysis',
        }),
      ])
    )
    expect(entropyAnalyzeToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'structure',
          artifactTypes: ['entropy_analysis'],
        }),
      ])
    )
    expect(entropyAnalyzeToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'entropy.static-handoff',
        startsWith: ['entropy.analyze'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'workflow.search',
          'packer.detect',
          'obfuscation.detect',
          'unpack.workflow.plan',
        ]),
        producesArtifacts: ['entropy_analysis'],
        safety: expect.arrayContaining(['passive', 'read_only', 'no_network_by_default']),
      })
    )
    expect(entropyAnalyzeToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: false,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(entropyAnalyzeToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'static-worker',
        backendKind: 'builtin',
        adapter: 'static_worker.entropy_analyze',
        availability: 'builtin',
        outputArtifactTypes: ['entropy_analysis'],
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
          missingBackendBehavior: 'Return worker error without falling back to sample execution.',
        }),
      })
    )
  })

  test('returns a standard entropy handoff envelope and keeps top-level next tools narrow', async () => {
    const artifact: ArtifactRef = {
      id: 'artifact-entropy-1',
      type: 'entropy_analysis',
      path: 'reports/static_analysis/default/entropy.json',
      sha256: 'a'.repeat(64),
      mime: 'application/json',
    }
    const persistStaticAnalysisJsonArtifact = jest.fn(async () => artifact)
    const handler = createEntropyAnalyzeHandler(workspaceManager, database, cacheManager, {
      callStaticWorker: async () => ({
        ok: true,
        data: workerEntropyData(),
        warnings: ['worker warning'],
        metrics: { worker_ms: 7 },
      }),
      persistStaticAnalysisJsonArtifact,
    })

    const result = await handler({
      sample_id: sampleId,
      block_size: 256,
      high_entropy_threshold: 7.2,
      force_refresh: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.entropy_analysis.v1')
    expect(data.tool_version).toBe('0.2.0')
    expect(data.sample_id).toBe(sampleId)
    expect(data.artifact_type).toBe('entropy_analysis')
    expect(data.recommended_next_tools).toEqual(['artifact.read', 'workflow.search'])
    expect(data.source_recommended_next_tools).toEqual(['packer.detect', 'unpack.workflow.plan'])
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.entropy_analysis.evidence_summary.v1',
        source_tool: 'entropy.analyze',
        artifact_type: 'entropy_analysis',
        sample_id: sampleId,
        overall_entropy: 7.45,
        suspicious_section_count: 1,
        high_entropy_region_count: 1,
        packing_likelihood: 'high',
        crypto_data_likelihood: 'medium',
        artifact_id: artifact.id,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.entropy_analysis.workflow_handoff.v1',
        handoff_mode: 'entropy_static_triage_to_packer_or_crypto_review',
        artifact_type: 'entropy_analysis',
        recommended_next_tools: ['artifact.read', 'workflow.search'],
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'packer-and-obfuscation-corroboration',
          priority: 'high',
          next_tools: ['packer.detect', 'obfuscation.detect', 'analysis.evidence.graph'],
        }),
        expect.objectContaining({
          goal: 'unpack-planning',
          next_tools: ['unpack.workflow.plan'],
        }),
      ])
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        live_execution_started: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.entropy_analysis.quality_gates.v1',
        passive_static_analysis: true,
        read_only_backend: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        artifact_persisted: true,
      })
    )
    expect(result.warnings).toContain('worker warning')
    expect(result.artifacts).toEqual([artifact])
    expect(persistStaticAnalysisJsonArtifact).toHaveBeenCalledWith(
      workspaceManager,
      database,
      sampleId,
      'entropy_analysis',
      'entropy',
      expect.objectContaining({
        tool: 'entropy.analyze',
        data: expect.objectContaining({
          schema: 'rikune.entropy_analysis.v1',
          workflow_handoff: expect.objectContaining({
            schema: 'rikune.entropy_analysis.workflow_handoff.v1',
          }),
          quality_gates: expect.objectContaining({
            artifact_persisted: false,
          }),
        }),
      })
    )
  })

  test('returns a standard envelope when reusing cached entropy data', async () => {
    const handler = createEntropyAnalyzeHandler(workspaceManager, database, cacheManager, {
      callStaticWorker: async () => ({
        ok: true,
        data: workerEntropyData(),
      }),
      persistStaticAnalysisJsonArtifact: async () => ({
        id: 'artifact-entropy-cache',
        type: 'entropy_analysis',
        path: 'reports/static_analysis/default/entropy-cache.json',
        sha256: 'b'.repeat(64),
        mime: 'application/json',
      }),
    })

    const first = await handler({ sample_id: sampleId, force_refresh: true })
    expect(first.ok).toBe(true)

    const second = await handler({ sample_id: sampleId })
    expect(second.ok).toBe(true)
    expect(second.warnings).toContain('Result from cache')
    const data = second.data as any
    expect(data.schema).toBe('rikune.entropy_analysis.v1')
    expect(data.recommended_next_tools).toEqual(['artifact.read', 'workflow.search'])
    expect(data.source_recommended_next_tools).toEqual(['packer.detect', 'unpack.workflow.plan'])
    expect(data.quality_gates.artifact_persisted).toBe(false)
  })

  test('returns an error for a missing sample without invoking the worker', async () => {
    const callStaticWorker = jest.fn(async () => ({
      ok: true,
      data: workerEntropyData(),
    }))
    const handler = createEntropyAnalyzeHandler(workspaceManager, database, cacheManager, {
      callStaticWorker,
    })

    const result = await handler({
      sample_id: `sha256:${'6'.repeat(64)}`,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
    expect(callStaticWorker).not.toHaveBeenCalled()
  })
})
