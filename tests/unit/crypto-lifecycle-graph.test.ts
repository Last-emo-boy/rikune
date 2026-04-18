import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import { persistCryptoPlanningJsonArtifact } from '../../src/plugins/static-triage/crypto-planning-artifacts.js'
import {
  createCryptoLifecycleGraphHandler,
  cryptoLifecycleGraphToolDefinition,
} from '../../src/plugins/visualization/tools/crypto-lifecycle-graph.js'

const SAMPLE_HASH = '7'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

describe('crypto.lifecycle.graph tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-crypto-lifecycle-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '7'.repeat(32),
      size: 8192,
      file_type: 'PE32+ executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    await persistCryptoPlanningJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'crypto_identification',
      'crypto_identification',
      {
        schema: 'rikune.crypto_identify.v1',
        algorithms: [
          {
            algorithm_family: 'aes',
            algorithm_name: 'AES-CBC',
            mode: 'CBC',
            confidence: 0.91,
            function: 'FUN_140023a50',
            address: '0x140023a50',
            source_apis: ['CryptAcquireContextW', 'CryptEncrypt'],
            evidence: [
              {
                kind: 'import',
                value: 'CryptEncrypt',
                source_tool: 'pe.imports.extract',
                confidence: 0.9,
              },
            ],
            candidate_constants: [
              {
                kind: 'sbox',
                label: 'AES S-box',
                preview: '637c777bf26b6fc53001672bfed7ab76',
                encoding: 'hex',
                byte_length: 256,
                entropy: 7.1,
                source: 'string',
                rationale: ['AES S-box prefix detected.'],
              },
            ],
            dynamic_support: true,
            xref_available: true,
          },
        ],
        candidate_constants: [
          {
            kind: 'iv_material',
            label: 'possible IV',
            preview: '00112233445566778899aabbccddeeff',
            encoding: 'hex',
            byte_length: 16,
            source: 'string',
            rationale: ['16-byte hex material near crypto strings.'],
          },
        ],
        runtime_observed_apis: ['CryptEncrypt'],
        summary: 'AES-like crypto evidence.',
      },
      'crypto-session'
    )

    await persistStaticAnalysisJsonArtifact(workspaceManager, database, SAMPLE_ID, 'dynamic_trace_json', 'dynamic_trace', {
      schema_version: '0.1.0',
      source_format: 'generic_json',
      evidence_kind: 'trace',
      imported_at: new Date().toISOString(),
      executed: true,
      raw_event_count: 2,
      api_calls: [
        { api: 'CryptEncrypt', category: 'crypto', count: 2, confidence: 0.94, sources: [] },
        { api: 'WriteFile', category: 'filesystem', count: 1, confidence: 0.8, sources: [] },
      ],
      memory_regions: [
        {
          region_type: 'buffer',
          purpose: 'key schedule candidate',
          source: 'unit-test',
          confidence: 0.75,
          indicators: ['AES'],
        },
      ],
      modules: ['advapi32.dll'],
      strings: ['AES'],
      stages: ['crypto_operation'],
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

  test('exports crypto lifecycle graph tool definition', () => {
    expect(cryptoLifecycleGraphToolDefinition.name).toBe('crypto.lifecycle.graph')
    expect(cryptoLifecycleGraphToolDefinition.description).toContain('crypto lifecycle graph')
  })

  test('links crypto findings with runtime API observations', async () => {
    const result = await createCryptoLifecycleGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      crypto_scope: 'session',
      crypto_session_tag: 'crypto-session',
      session_tag: 'graph-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.crypto_lifecycle_graph.v1')
    expect(data.summary.crypto_artifact_count).toBe(1)
    expect(data.summary.algorithm_count).toBe(1)
    expect(data.summary.constant_count).toBeGreaterThanOrEqual(2)
    expect(data.summary.runtime_api_count).toBeGreaterThanOrEqual(2)
    expect(data.summary.dynamic_executed).toBe(true)
    expect(data.summary.corroborated_api_count).toBeGreaterThan(0)
    expect(data.graph.nodes.some((node: any) => node.kind === 'crypto_algorithm' && node.label === 'AES-CBC')).toBe(true)
    expect(data.graph.nodes.some((node: any) => node.kind === 'api' && node.label === 'CryptEncrypt')).toBe(true)
    expect(data.graph.edges.some((edge: any) => edge.label === 'corroborates_crypto_path')).toBe(true)
    expect(result.artifacts?.[0]?.type).toBe('crypto_lifecycle_graph')
  })
})
