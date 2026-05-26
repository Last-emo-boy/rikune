import { beforeEach, describe, expect, jest, test } from '@jest/globals'
import { createCryptoIdentifyHandler } from '../../src/plugins/static-triage/tools/crypto-identify.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('crypto.identify tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>

  beforeEach(() => {
    mockWorkspaceManager = {} as unknown as jest.Mocked<WorkspaceManager>
    mockDatabase = {
      findSample: jest.fn(),
      findArtifactsByType: jest.fn().mockReturnValue([]),
      findLatestCompatibleAnalysisEvidence: jest.fn().mockReturnValue(null),
      insertAnalysisEvidence: jest.fn(),
      updateAnalysisEvidence: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
    mockCacheManager = {
      getCachedResultWithMetadata: jest.fn().mockResolvedValue(null),
      setCachedResult: jest.fn().mockResolvedValue(undefined),
    } as unknown as jest.Mocked<CacheManager>
  })

  test('should correlate static and runtime evidence into compact crypto findings', async () => {
    mockDatabase.findSample.mockReturnValue({
      id: 'sha256:test',
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    } as any)

    const handler = createCryptoIdentifyHandler(mockWorkspaceManager, mockDatabase, mockCacheManager, {
      stringsExtract: async () => ({
        ok: true,
        data: {
          enriched: {
            records: [
              {
                value: 'AES-256-CBC',
                labels: ['analyst_relevant'],
                categories: ['string'],
                function_refs: [{ address: '0x140023a50', name: 'FUN_140023A50' }],
              },
              {
                value: '637c777bf26b6fc53001672bfed7ab76ca82c97d',
                labels: ['encoded_candidate'],
                categories: ['string'],
                function_refs: [{ address: '0x140023a50', name: 'FUN_140023A50' }],
              },
            ],
          },
        },
      }),
      stringsFlossDecode: async () => ({
        ok: true,
        data: {
          enriched: {
            records: [
              {
                value: 'AES_encrypt',
                labels: ['decoded_signal'],
                categories: ['suspicious_api'],
                function_refs: [{ address: '0x140023a50', name: 'FUN_140023A50' }],
              },
            ],
          },
        },
      }),
      analysisContextLink: async () => ({
        ok: true,
        data: {
          xref_status: 'available',
          function_contexts: [
            {
              function: 'FUN_140023A50',
              address: '0x140023a50',
              top_strings: ['AES-256-CBC'],
              sensitive_apis: ['AES_encrypt'],
              rationale: ['string:AES-256-CBC'],
            },
          ],
          source_artifact_refs: [],
        },
      }),
      peImportsExtract: async () => ({
        ok: true,
        data: {
          imports: {
            'custom.dll': ['AES_encrypt'],
          },
        },
      }),
      staticCapabilityTriage: async () => ({
        ok: true,
        data: {
          behavior_namespaces: ['cryptography/encryption'],
          capability_groups: { crypto: 1 },
          capabilities: [{ name: 'encrypt data', namespace: 'cryptography', group: 'crypto' }],
        },
      }),
      loadDynamicTrace: async () =>
        ({
          observed_apis: ['AES_encrypt'],
        }) as any,
    })

    const result = await handler({
      sample_id: 'sha256:test',
      persist_artifact: false,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.algorithms.length).toBeGreaterThan(0)
    expect(data.algorithms[0].algorithm_family).toBe('aes')
    expect(data.algorithms[0].function).toBe('FUN_140023A50')
    expect(data.candidate_constants.some((item: any) => item.kind === 'sbox')).toBe(true)
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.crypto_identification.evidence_summary.v1',
        source_tool: 'crypto.identify',
        algorithm_count: data.algorithms.length,
        localized_algorithm_count: expect.any(Number),
        runtime_evidence_present: true,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.crypto_identification.workflow_handoff.v1',
        handoff_mode: 'crypto_identification_to_runtime_tracing',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'crypto-breakpoint-planning',
            next_tools: expect.arrayContaining(['breakpoint.smart', 'trace.condition']),
          }),
          expect.objectContaining({
            goal: 'crypto-lifecycle-correlation',
            next_tools: expect.arrayContaining(['crypto.lifecycle.graph', 'analysis.evidence.graph']),
          }),
        ]),
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_identification: true,
        backend_started: false,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        crypto_evidence_present: true,
        function_localized_evidence_present: true,
        runtime_followup_requires_opt_in: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['breakpoint.smart', 'trace.condition'])
    )
  })
})
