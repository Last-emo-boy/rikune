/**
 * Unit tests for setup.remediate tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createSetupRemediateHandler, SetupRemediateInputSchema } from '../../src/tools/setup-remediate.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('setup.remediate tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    mockCacheManager = {
      getCachedResult: jest.fn(),
      setCachedResult: jest.fn(),
    } as unknown as jest.Mocked<CacheManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = SetupRemediateInputSchema.safeParse({
        blocked_tool: { tool_name: 'ghidra.analyze', error_message: 'Ghidra not found' }
      })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = SetupRemediateInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = SetupRemediateInputSchema.safeParse({ blocked_tool: 'not-an-object' })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return remediation result', async () => {
      const handler = createSetupRemediateHandler(mockWorkspaceManager, mockDatabase, mockCacheManager)

      const result = await handler({
        blocked_tool: { tool_name: 'ghidra.analyze', error_message: 'Ghidra not found' },
      })

      // Handler returns WorkerResult
      expect(result.ok).toBeDefined()
      expect(result.data).toBeDefined()
    })
  })
})
