/**
 * Unit tests for kb.import tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createKbImportHandler, KbImportInputSchema } from '../../src/plugins/kb-collaboration/tools/kb-import.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('kb.import tool', () => {
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
      const result = KbImportInputSchema.safeParse({ file_path: '/tmp/kb-export.jsonl' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = KbImportInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = KbImportInputSchema.safeParse({ file_path: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent file', async () => {
      const handler = createKbImportHandler(mockWorkspaceManager, mockDatabase)

      const result = await handler({ file_path: '/nonexistent/path.jsonl' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/failed|not found|ENOENT/i)
    })
  })
})
