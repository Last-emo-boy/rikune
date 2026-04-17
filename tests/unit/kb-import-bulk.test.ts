/**
 * Unit tests for kb.import.bulk tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createKbImportBulkHandler, KbImportBulkInputSchema } from '../../src/plugins/kb-collaboration/tools/kb-import-bulk.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('kb.import.bulk tool', () => {
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
      runSql: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = KbImportBulkInputSchema.safeParse({ source_type: 'seed' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = KbImportBulkInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = KbImportBulkInputSchema.safeParse({ source_type: 'invalid' })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for missing source_path on capa import', async () => {
      const handler = createKbImportBulkHandler(mockWorkspaceManager, mockDatabase)

      const result = await handler({ source_type: 'capa' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/source_path|required/i)
    })
  })
})
