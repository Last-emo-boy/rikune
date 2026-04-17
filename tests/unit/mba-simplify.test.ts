/**
 * Unit tests for mba.simplify tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createMbaSimplifyHandler, mbaSimplifyInputSchema } from '../../src/plugins/vm-analysis/tools/mba-simplify.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('mba.simplify tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = mbaSimplifyInputSchema.safeParse({ expressions: ['x ^ (x & y)'] })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = mbaSimplifyInputSchema.safeParse({ expressions: [] })
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = mbaSimplifyInputSchema.safeParse({ expressions: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should process expressions successfully', async () => {
      const handler = createMbaSimplifyHandler(mockWorkspaceManager, mockDatabase)

      const result = await handler({ expressions: ['x ^ (x & y)'] })

      expect(result.ok).toBe(true)
      expect(result.data).toBeDefined()
    })
  })
})
