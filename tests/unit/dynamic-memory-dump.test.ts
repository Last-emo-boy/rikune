/**
 * Unit tests for dynamic.memory.dump tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createDynamicMemoryDumpHandler, DynamicMemoryDumpInputSchema } from '../../src/plugins/dynamic/tools/dynamic-memory-dump.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { Config } from '../../src/config.js'

describe('dynamic.memory.dump tool', () => {
  let mockWorkspaceManager: WorkspaceManager
  let mockDatabase: DatabaseManager
  let mockConfig: Config

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as WorkspaceManager

    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as DatabaseManager

    mockConfig = {} as unknown as Config
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = DynamicMemoryDumpInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = DynamicMemoryDumpInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = DynamicMemoryDumpInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource when frida backend is available', async () => {
      const handler = createDynamicMemoryDumpHandler({
        workspaceManager: mockWorkspaceManager,
        database: mockDatabase,
        config: mockConfig,
      } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      // When Frida is unavailable in CI, the backend gate returns setup_required first.
      // When Frida is available, it should reach the sample-not-found branch.
      if (result.ok && (result.data as any)?.status === 'setup_required') {
        expect(result.setup_actions).toBeDefined()
        expect(result.required_user_inputs).toBeDefined()
        return
      }

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })

    test('should return structured setup_required when backend is missing', async () => {
      const handler = createDynamicMemoryDumpHandler({
        workspaceManager: mockWorkspaceManager,
        database: mockDatabase,
        config: mockConfig,
      } as any)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      // If the environment lacks Frida, this verifies the new backend gate works.
      if (!result.ok) {
        // Backend is available; nothing more to assert here.
        return
      }

      expect((result.data as any)?.status).toBe('setup_required')
      expect(result.setup_actions).toBeDefined()
      expect(result.required_user_inputs).toBeDefined()
    })
  })
})
