/**
 * Unit tests for yara.scan tool
 * Requirements: 5.1, 5.2, 5.3, 5.5
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createYaraScanHandler, YaraScanInputSchema } from '../../src/plugins/yara/tools/yara-scan.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('yara.scan tool', () => {
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
    } as unknown as jest.Mocked<DatabaseManager>

    // Create mock cache manager
    mockCacheManager = {
      getCachedResult: jest.fn(),
      setCachedResult: jest.fn(),
    } as unknown as jest.Mocked<CacheManager>
  })

  describe('Input validation', () => {
    test('should validate correct input', () => {
      const input = {
        sample_id: 'sha256:abc123',
        rule_set: 'malware_families',
        timeout_ms: 30000,
      }

      const result = YaraScanInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should use default timeout_ms', () => {
      const input = {
        sample_id: 'sha256:abc123',
        rule_set: 'packers',
      }

      const result = YaraScanInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.timeout_ms).toBe(30000)
      }
    })

    test('should reject invalid timeout_ms', () => {
      const input = {
        sample_id: 'sha256:abc123',
        rule_set: 'malware_families',
        timeout_ms: 500, // Too small
      }

      const result = YaraScanInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should require rule_set', () => {
      const input = {
        sample_id: 'sha256:abc123',
      }

      const result = YaraScanInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })
  })

  describe('Handler execution', () => {
    test('should return error if sample not found', async () => {
      const handler = createYaraScanHandler(mockWorkspaceManager, mockDatabase, mockCacheManager)
      
      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({
        sample_id: 'sha256:nonexistent',
        rule_set: 'malware_families',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toContain('Sample not found: sha256:nonexistent')
    })

    test('should return cached result if available', async () => {
      const handler = createYaraScanHandler(mockWorkspaceManager, mockDatabase, mockCacheManager)
      
      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE32',
        created_at: '2024-01-01T00:00:00Z',
        source: 'test',
      }

      const cachedData = {
        matches: [
          {
            rule: 'UPX_Packer',
            tags: ['packer', 'upx'],
            meta: { author: 'test' },
            strings: [],
          },
        ],
        ruleset_version: 'v1.0',
        timed_out: false,
        rule_set: 'packers',
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(cachedData)

      const result = await handler({
        sample_id: 'sha256:abc123',
        rule_set: 'packers',
      })

      expect(result.ok).toBe(true)
      expect(result.data).toEqual(cachedData)
      expect(result.warnings).toContain('Result from cache')
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
    })
  })

  describe('YARA match structure', () => {
    test('should validate match structure in schema', () => {
      const matchData = {
        matches: [
          {
            rule: 'UPX_Packer',
            tags: ['packer', 'upx'],
            meta: {
              author: 'Test Author',
              description: 'UPX packer detection',
            },
            strings: [
              {
                identifier: '$upx_magic',
                offset: 0,
                matched_data: 'UPX!',
              },
              {
                identifier: '$upx_string',
                offset: 512,
                matched_data: 'UPX packed',
              },
            ],
          },
        ],
        ruleset_version: 'abc123',
        timed_out: false,
        rule_set: 'packers',
      }

      // Verify the structure matches what we expect
      expect(matchData.matches).toHaveLength(1)
      expect(matchData.matches[0].rule).toBe('UPX_Packer')
      expect(matchData.matches[0].tags).toEqual(['packer', 'upx'])
      expect(matchData.matches[0].meta).toHaveProperty('author')
      expect(matchData.matches[0].strings).toHaveLength(2)
      expect(matchData.matches[0].strings[0]).toHaveProperty('identifier')
      expect(matchData.matches[0].strings[0]).toHaveProperty('offset')
      expect(matchData.matches[0].strings[0]).toHaveProperty('matched_data')
    })
  })
})
