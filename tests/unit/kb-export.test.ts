/**
 * Unit tests for kb.export tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createKbExportHandler, KbExportInputSchema } from '../../src/plugins/kb-collaboration/tools/kb-export.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('kb.export tool', () => {
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
      queryOneSql: jest.fn().mockReturnValue(undefined),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = KbExportInputSchema.safeParse({ output_path: '/tmp/export.jsonl' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = KbExportInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = KbExportInputSchema.safeParse({ output_path: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error when export fails', async () => {
      const handler = createKbExportHandler(mockWorkspaceManager, mockDatabase)

      mockDatabase.querySql.mockImplementation(() => { throw new Error('database not found') })

      const result = await handler({ output_path: '/tmp/export.jsonl' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|failed/i)
    })
  })
})
