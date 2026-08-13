/**
 * Unit tests for kb.function.match tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import {
  createKbFunctionMatchHandler,
  KbFunctionMatchInputSchema,
} from '../../src/plugins/kb-collaboration/tools/kb-function-match.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('kb.function.match tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      findAnalysisEvidenceBySample: jest.fn(),
      getDb: jest.fn(),
      querySql: jest.fn().mockReturnValue([]),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = KbFunctionMatchInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = KbFunctionMatchInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = KbFunctionMatchInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })

    test('should enforce confidence and result-count boundaries', () => {
      expect(
        KbFunctionMatchInputSchema.safeParse({
          sample_id: 'sha256:bounds',
          min_confidence: 0,
          max_matches: 1,
        }).success
      ).toBe(true)
      expect(
        KbFunctionMatchInputSchema.safeParse({
          sample_id: 'sha256:bounds',
          min_confidence: 1,
          max_matches: 1000,
        }).success
      ).toBe(true)

      for (const min_confidence of [-0.001, 1.001]) {
        expect(
          KbFunctionMatchInputSchema.safeParse({
            sample_id: 'sha256:bounds',
            min_confidence,
          }).success
        ).toBe(false)
      }

      for (const max_matches of [-1, 0, 1.5, 1001]) {
        expect(
          KbFunctionMatchInputSchema.safeParse({
            sample_id: 'sha256:bounds',
            max_matches,
          }).success
        ).toBe(false)
      }
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createKbFunctionMatchHandler({
        workspaceManager: mockWorkspaceManager,
        database: mockDatabase,
      } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })

    test('should load function_kb when match_against is omitted and explain multi-view evidence', async () => {
      mockDatabase.findSample.mockReturnValue({ id: 'target' } as never)
      mockDatabase.findAnalysisEvidenceBySample.mockReturnValue([
        {
          evidence_family: 'function_index',
          result_json: {
            data: {
              functions: [
                {
                  address: '0x401000',
                  name: 'sub_401000',
                  size: 160,
                  api_calls: ['CreateFileW', 'ReadFile', 'CloseHandle'],
                  strings: ['config.dat', 'Invalid configuration'],
                  cfg_shape: 'blocks:5;edges:6;loops:1',
                  crypto_constants: ['0x9e3779b9'],
                },
              ],
            },
          },
        },
      ] as never)
      mockDatabase.querySql.mockReturnValue([
        {
          id: 'kb-size-only',
          features_apis_json: '[]',
          features_strings_json: '[]',
          features_cfg_shape: 'blocks:1;edges:0;loops:0',
          features_crypto_constants_json: '[]',
          semantics_name: 'same_size_decoy',
          semantics_explanation: 'A size-only decoy',
          semantics_behavior: 'unknown',
          semantics_confidence: 0.99,
          semantics_source: 'human',
          samples_json: '["sha256:decoy"]',
        },
        {
          id: 'kb-config-parser',
          features_apis_json: '["CreateFileW","ReadFile","CloseHandle"]',
          features_strings_json: '["config.dat","Invalid configuration"]',
          features_cfg_shape: 'blocks:5;edges:6;loops:1',
          features_crypto_constants_json: '["0x9e3779b9"]',
          semantics_name: 'parse_encrypted_config',
          semantics_explanation: 'Reads and decodes a configuration file',
          semantics_behavior: 'configuration parsing',
          semantics_confidence: 0.96,
          semantics_source: 'human',
          samples_json: '["sha256:known-family"]',
        },
      ] as never)
      const persistStaticAnalysisJsonArtifact = jest.fn(async () => undefined)
      const handler = createKbFunctionMatchHandler({
        workspaceManager: mockWorkspaceManager,
        database: mockDatabase,
        persistStaticAnalysisJsonArtifact,
      } as any)

      const args = KbFunctionMatchInputSchema.parse({
        sample_id: 'sha256:target',
        min_confidence: 0.7,
      })
      const result = await handler(args)

      expect(result.ok).toBe(true)
      expect(
        mockDatabase.querySql.mock.calls.some(([sql]) => /from\s+function_kb/i.test(String(sql)))
      ).toBe(true)
      expect(result.warnings ?? []).not.toEqual(
        expect.arrayContaining([expect.stringMatching(/No match_against/i)])
      )

      const data = result.data as any
      expect(data).toEqual(
        expect.objectContaining({
          sample_id: 'sha256:target',
          target_function_count: 1,
          reference_function_count: 2,
          match_count: 1,
        })
      )
      const match = data.matches[0]
      expect(match).toEqual(
        expect.objectContaining({
          target_function: 'sub_401000',
          matched_function: 'parse_encrypted_config',
          matched_sample_id: 'kb:kb-config-parser',
          reference_sample_ids: ['sha256:known-family'],
          confidence: expect.any(Number),
          reference_source: 'function_kb',
          kb_entry_id: 'kb-config-parser',
          reference_confidence: 0.96,
          match_basis: expect.arrayContaining([
            'api_calls',
            'strings',
            'cfg_shape',
            'crypto_constants',
          ]),
          score_breakdown: expect.objectContaining({
            exact_hash: expect.any(Number),
            api_calls: expect.any(Number),
            strings: expect.any(Number),
            cfg_shape: expect.any(Number),
            crypto_constants: expect.any(Number),
            size: expect.any(Number),
          }),
          shared_features: expect.objectContaining({
            api_calls: expect.arrayContaining(['CreateFileW', 'ReadFile', 'CloseHandle']),
            strings: expect.arrayContaining(['config.dat', 'Invalid configuration']),
            crypto_constants: expect.arrayContaining(['0x9e3779b9']),
          }),
        })
      )
      expect(match.confidence).toBeGreaterThanOrEqual(0.8)
      expect(match.score_breakdown.api_calls).toBeGreaterThan(0)
      expect(match.score_breakdown.strings).toBeGreaterThan(0)
      expect(match.score_breakdown.cfg_shape).toBeGreaterThan(0)
      expect(match.score_breakdown.crypto_constants).toBeGreaterThan(0)
      expect(match.shared_features.cfg_shape).toBeTruthy()
    })

    test('should keep exact-hash matching against explicit sample evidence backward compatible', async () => {
      mockDatabase.findSample.mockReturnValue({ id: 'target' } as never)
      mockDatabase.findAnalysisEvidenceBySample.mockImplementation((sampleId) => {
        if (sampleId === 'sha256:target') {
          return [
            {
              evidence_family: 'function_index',
              result_json: {
                functions: [
                  {
                    address: '0x401100',
                    name: 'sub_401100',
                    hash: 'a'.repeat(64),
                    size: 72,
                    api_calls: ['TargetOnlyApi'],
                  },
                ],
              },
            },
          ] as never
        }

        return [
          {
            evidence_family: 'ghidra_functions',
            result_json: {
              data: {
                functions: [
                  {
                    entry: '0x501100',
                    name: 'known_exact_function',
                    byte_hash: 'a'.repeat(64),
                    length: 96,
                    imports: ['ReferenceOnlyApi'],
                  },
                ],
              },
            },
          },
        ] as never
      })
      const handler = createKbFunctionMatchHandler({
        workspaceManager: mockWorkspaceManager,
        database: mockDatabase,
        persistStaticAnalysisJsonArtifact: jest.fn(async () => undefined),
      } as any)

      const args = KbFunctionMatchInputSchema.parse({
        sample_id: 'sha256:target',
        match_against: ['sha256:reference'],
        min_confidence: 1,
        max_matches: 10,
      })
      const result = await handler(args)

      expect(result.ok).toBe(true)
      expect(
        mockDatabase.findAnalysisEvidenceBySample.mock.calls.some(
          ([sampleId]) => sampleId === 'sha256:reference'
        )
      ).toBe(true)
      expect(mockDatabase.querySql).not.toHaveBeenCalled()
      expect(result.data).toEqual(
        expect.objectContaining({
          match_count: 1,
          exact_matches: 1,
          matches: [
            expect.objectContaining({
              target_function: 'sub_401100',
              matched_function: 'known_exact_function',
              matched_sample_id: 'sha256:reference',
              confidence: 1,
              reference_source: 'sample_evidence',
              match_basis: expect.arrayContaining(['exact_hash']),
              score_breakdown: expect.objectContaining({ exact_hash: 1 }),
            }),
          ],
        })
      )
    })

    test('should preserve legacy API and size scoring for explicit sample evidence', async () => {
      mockDatabase.findSample.mockReturnValue({ id: 'target' } as never)
      mockDatabase.findAnalysisEvidenceBySample.mockImplementation(
        (sampleId) =>
          [
            {
              evidence_family: 'function_index',
              result_json: {
                functions: [
                  {
                    address: sampleId === 'sha256:target' ? '0x401150' : '0x501150',
                    name: sampleId === 'sha256:target' ? 'sub_401150' : 'known_file_reader',
                    size: 80,
                    api_calls: ['CreateFileW', 'ReadFile'],
                  },
                ],
              },
            },
          ] as never
      )
      const handler = createKbFunctionMatchHandler({
        workspaceManager: mockWorkspaceManager,
        database: mockDatabase,
        persistStaticAnalysisJsonArtifact: jest.fn(async () => undefined),
      } as any)

      const result = await handler(
        KbFunctionMatchInputSchema.parse({
          sample_id: 'sha256:target',
          match_against: ['sha256:reference'],
        })
      )

      expect(result.ok).toBe(true)
      expect(result.data).toEqual(
        expect.objectContaining({
          match_count: 1,
          matches: [
            expect.objectContaining({
              matched_function: 'known_file_reader',
              confidence: 0.79,
              similarity: 1,
              legacy_similarity: 1,
              confidence_tier: 'review',
              match_basis: expect.arrayContaining(['api_calls', 'size']),
            }),
          ],
        })
      )
    })

    test('should not promote an API-only function_kb seed to a high-confidence match', async () => {
      mockDatabase.findSample.mockReturnValue({ id: 'target' } as never)
      mockDatabase.findAnalysisEvidenceBySample.mockReturnValue([
        {
          evidence_family: 'function_index',
          result_json: {
            functions: [
              {
                address: '0x401180',
                name: 'sub_401180',
                api_calls: ['CreateFileW'],
              },
            ],
          },
        },
      ] as never)
      mockDatabase.querySql.mockReturnValue([
        {
          id: 'seed-create-file',
          features_apis_json: '["CreateFileW"]',
          features_strings_json: '[]',
          features_cfg_shape: 'unknown',
          features_crypto_constants_json: '[]',
          semantics_name: 'CreateFileW',
          semantics_confidence: 0.99,
          semantics_source: 'auto',
          samples_json: '[]',
        },
      ] as never)
      const handler = createKbFunctionMatchHandler({
        workspaceManager: mockWorkspaceManager,
        database: mockDatabase,
        persistStaticAnalysisJsonArtifact: jest.fn(async () => undefined),
      } as any)

      const result = await handler(KbFunctionMatchInputSchema.parse({ sample_id: 'sha256:target' }))

      expect(result.ok).toBe(true)
      expect(result.data).toEqual(
        expect.objectContaining({
          reference_function_count: 1,
          match_count: 0,
          exact_matches: 0,
          high_confidence_matches: 0,
        })
      )
    })

    test('should break equal-score KB ties deterministically', async () => {
      const targetEvidence = [
        {
          evidence_family: 'function_index',
          result_json: {
            functions: [
              {
                address: '0x401200',
                name: 'sub_401200',
                api_calls: ['CreateFileW', 'ReadFile'],
                strings: ['settings.bin'],
                cfg_shape: 'blocks:3;edges:3;loops:1',
                crypto_constants: ['0xdeadbeef'],
              },
            ],
          },
        },
      ]
      const alpha = {
        id: 'kb-alpha',
        features_apis_json: '["CreateFileW","ReadFile"]',
        features_strings_json: '["settings.bin"]',
        features_cfg_shape: 'blocks:3;edges:3;loops:1',
        features_crypto_constants_json: '["0xdeadbeef"]',
        semantics_name: 'alpha_candidate',
        semantics_explanation: 'Candidate A',
        semantics_behavior: 'settings parsing',
        semantics_confidence: 0.95,
        semantics_source: 'human',
        samples_json: '["sha256:reference"]',
      }
      const zeta = {
        ...alpha,
        id: 'kb-zeta',
        semantics_name: 'zeta_candidate',
        semantics_explanation: 'Candidate Z',
      }

      const runWithRows = async (rows: (typeof alpha)[]) => {
        const database = {
          findSample: jest.fn(() => ({ id: 'target' })),
          findAnalysisEvidenceBySample: jest.fn(() => targetEvidence),
          querySql: jest.fn(() => rows),
        }
        const handler = createKbFunctionMatchHandler({
          workspaceManager: mockWorkspaceManager,
          database,
          persistStaticAnalysisJsonArtifact: jest.fn(async () => undefined),
        } as any)
        const result = await handler(
          KbFunctionMatchInputSchema.parse({
            sample_id: 'sha256:target',
            min_confidence: 0.7,
            max_matches: 10,
          })
        )
        expect(result.ok).toBe(true)
        return (result.data as any).matches[0]
      }

      const forward = await runWithRows([alpha, zeta])
      const reverse = await runWithRows([zeta, alpha])

      expect(forward.matched_function).toBe('alpha_candidate')
      expect(reverse.matched_function).toBe('alpha_candidate')
      expect(reverse.confidence).toBe(forward.confidence)
      expect(forward).toEqual(
        expect.objectContaining({
          reference_source: 'function_kb',
          ambiguous: true,
          alternative_count: expect.any(Number),
        })
      )
      expect(forward.alternative_count).toBeGreaterThanOrEqual(1)
      expect(reverse.ambiguous).toBe(true)
      expect(reverse.alternative_count).toBe(forward.alternative_count)
    })
  })
})
