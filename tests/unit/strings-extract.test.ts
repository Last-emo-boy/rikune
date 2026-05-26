/**
 * Unit tests for strings.extract tool
 * Requirements: 4.1, 4.2, 4.3
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import {
  createStringsExtractHandler,
  stringsExtractToolDefinition,
  StringsExtractInputSchema,
} from '../../src/plugins/strings/tools/strings-extract.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('strings.extract tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>

  beforeEach(() => {
    // Create mock workspace manager
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    // Create mock database
    mockDatabase = {
      findSample: jest.fn(),
      findLatestCompatibleAnalysisEvidence: jest.fn().mockReturnValue(null),
      insertAnalysisEvidence: jest.fn(),
      updateAnalysisEvidence: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    // Create mock cache manager
    mockCacheManager = {
      getCachedResult: jest.fn(),
      getCachedResultWithMetadata: jest.fn().mockResolvedValue(null),
      setCachedResult: jest.fn().mockResolvedValue(undefined),
    } as unknown as jest.Mocked<CacheManager>
  })

  describe('Input validation', () => {
    test('should accept valid input with all parameters', () => {
      const input = {
        sample_id: 'sha256:abc123',
        min_len: 4,
        encoding: 'all' as const,
        max_strings: 300,
        max_string_length: 256,
        category_filter: 'ioc' as const,
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept valid input with minimal parameters', () => {
      const input = {
        sample_id: 'sha256:abc123',
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.min_len).toBe(4) // default
        expect(result.data.encoding).toBe('all') // default
        expect(result.data.max_strings).toBe(500)
        expect(result.data.max_string_length).toBe(512)
        expect(result.data.category_filter).toBe('all')
      }
    })

    test('should reject invalid min_len (< 1)', () => {
      const input = {
        sample_id: 'sha256:abc123',
        min_len: 0,
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should reject invalid encoding', () => {
      const input = {
        sample_id: 'sha256:abc123',
        encoding: 'invalid',
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should accept encoding: ascii', () => {
      const input = {
        sample_id: 'sha256:abc123',
        encoding: 'ascii' as const,
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept encoding: unicode', () => {
      const input = {
        sample_id: 'sha256:abc123',
        encoding: 'unicode' as const,
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should reject invalid max_string_length', () => {
      const input = {
        sample_id: 'sha256:abc123',
        max_string_length: 8,
      }

      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should reject invalid category_filter', () => {
      const input = {
        sample_id: 'sha256:abc123',
        category_filter: 'malware',
      }

      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })
  })

  describe('Tool handler', () => {
    test('should declare raw string evidence workflow metadata', () => {
      expect(stringsExtractToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
        'enriched_string_analysis'
      )
      expect(stringsExtractToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
        expect.arrayContaining(['strings', 'network', 'encoded-config', 'workflow', 'provenance'])
      )
      expect(stringsExtractToolDefinition.workflowRecipes?.[0]).toEqual(
        expect.objectContaining({
          id: 'strings.raw-extraction-evidence',
          producesArtifacts: ['enriched_string_analysis'],
          nextTools: expect.arrayContaining([
            'analysis.context.link',
            'strings.floss.decode',
            'static.config.carver',
            'analysis.evidence.graph',
          ]),
          safety: expect.arrayContaining([
            'passive',
            'no_live_sample_by_default',
            'no_network_by_default',
          ]),
        })
      )
    })

    test('should return error when sample not found', async () => {
      const handler = createStringsExtractHandler(
        mockWorkspaceManager,
        mockDatabase,
        mockCacheManager
      )

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({
        sample_id: 'sha256:nonexistent',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toContain('Sample not found: sha256:nonexistent')
    })

    test('should return cached result when available', async () => {
      const handler = createStringsExtractHandler(
        mockWorkspaceManager,
        mockDatabase,
        mockCacheManager
      )

      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE32',
        created_at: '2024-01-01T00:00:00Z',
        source: 'test',
      }

      const mockCachedData = {
        strings: [
          { offset: 0, string: 'http://raw.example.test/c2', encoding: 'ascii' },
          { offset: 20, string: 'Y2FtcGFpZ25faWQ9NDI=', encoding: 'ascii' },
        ],
        count: 2,
        min_len: 4,
        encoding_filter: 'all',
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      ;(mockCacheManager as any).getCachedResultWithMetadata.mockResolvedValue({
        data: mockCachedData,
        metadata: {
          key: 'test-cache-key',
          tier: 'default',
          createdAt: '2024-01-01T00:00:00Z',
          expiresAt: '2024-02-01T00:00:00Z',
          fetchedAt: '2024-01-15T00:00:00Z',
        },
      })

      const result = await handler({
        sample_id: 'sha256:abc123',
        min_len: 4,
        encoding: 'all',
      })

      expect(result.ok).toBe(true)
      expect(result.data).toMatchObject(mockCachedData)
      expect((result.data as any).enriched).toBeDefined()
      expect((result.data as any).enriched.top_iocs.length).toBeGreaterThanOrEqual(0)
      expect((result.data as any).evidence_summary).toEqual(
        expect.objectContaining({
          schema: 'rikune.strings_extract.evidence_summary.v1',
          string_count: 2,
          top_iocs: expect.arrayContaining(['http://raw.example.test/c2']),
        })
      )
      expect((result.data as any).workflow_handoff).toEqual(
        expect.objectContaining({
          schema: 'rikune.strings_extract.workflow_handoff.v1',
          handoff_mode: 'raw_strings_to_context_ioc_and_reporting',
          recommended_next_tools: expect.arrayContaining([
            'analysis.context.link',
            'strings.floss.decode',
            'static.config.carver',
            'analysis.evidence.graph',
          ]),
        })
      )
      expect((result.data as any).workflow_handoff.dynamic_boundary).toEqual(
        expect.objectContaining({
          static_backend_started: false,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          mutation_performed: false,
        })
      )
      expect((result.data as any).quality_gates).toEqual(
        expect.objectContaining({
          passive_static_extraction: true,
          preview_mode_used: true,
          static_backend_started: false,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          evidence_graph_handoff_ready: true,
        })
      )
      expect((result.data as any).recommended_next_tools).toEqual(
        expect.arrayContaining([
          'analysis.context.link',
          'strings.floss.decode',
          'static.config.carver',
          'analysis.evidence.graph',
        ])
      )
      expect(result.warnings).toContain('Result from cache')
      expect((mockCacheManager as any).getCachedResultWithMetadata).toHaveBeenCalled()
    })

    test('should validate min_len parameter', () => {
      const input = {
        sample_id: 'sha256:abc123',
        min_len: 10,
        encoding: 'all' as const,
      }

      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.min_len).toBe(10)
      }
    })

    test('should validate encoding parameter', () => {
      const input = {
        sample_id: 'sha256:abc123',
        min_len: 4,
        encoding: 'ascii' as const,
      }

      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.encoding).toBe('ascii')
      }
    })
  })
})
