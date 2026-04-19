/**
 * Unit tests for kb.stats tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createKbStatsHandler, KbStatsInputSchema } from '../../src/plugins/kb-collaboration/tools/kb-stats.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('kb.stats tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
      querySql: jest.fn().mockReturnValue([]),
      queryOneSql: jest.fn().mockReturnValue({ count: 0 }),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = KbStatsInputSchema.safeParse({ include_category_breakdown: true })
      expect(result.success).toBe(true)
    })

    test('should accept empty input (all optional)', () => {
      const result = KbStatsInputSchema.safeParse({})
      expect(result.success).toBe(true)
    })

    test('should reject invalid types', () => {
      const result = KbStatsInputSchema.safeParse({ include_category_breakdown: 'yes' })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return stats successfully', async () => {
      const handler = createKbStatsHandler(mockWorkspaceManager, mockDatabase)

      const result = await handler({})

      expect(result.ok).toBe(true)
    })
  })
})
