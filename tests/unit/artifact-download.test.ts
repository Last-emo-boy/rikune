/**
 * Unit tests for artifact.download tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createArtifactDownloadHandler, ArtifactDownloadInputSchema } from '../../src/tools/artifact-download.js'
import type { DatabaseManager } from '../../src/database.js'

describe('artifact.download tool', () => {
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockDatabase = {
      findSample: jest.fn(),
      findArtifact: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = ArtifactDownloadInputSchema.safeParse({ artifact_id: 'artifact-abc123' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = ArtifactDownloadInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = ArtifactDownloadInputSchema.safeParse({ artifact_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createArtifactDownloadHandler(mockDatabase)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ artifact_id: 'artifact-abc123' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })
  })
})
