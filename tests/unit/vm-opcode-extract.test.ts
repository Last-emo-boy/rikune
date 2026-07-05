/**
 * Unit tests for vm.opcode.extract tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import {
  createVmOpcodeExtractHandler,
  vmOpcodeExtractInputSchema,
} from '../../src/plugins/vm-analysis/tools/vm-opcode-extract.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('vm.opcode.extract tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      findAnalysisEvidenceBySample: jest.fn(),
      findFunctions: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = vmOpcodeExtractInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = vmOpcodeExtractInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = vmOpcodeExtractInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createVmOpcodeExtractHandler(mockWorkspaceManager, mockDatabase)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })

    test('should match dispatcher evidence by normalized function address', async () => {
      const handler = createVmOpcodeExtractHandler(mockWorkspaceManager, mockDatabase)

      mockDatabase.findSample.mockReturnValue({ sample_id: 'sha256:abc123def456' } as any)
      mockDatabase.findAnalysisEvidenceBySample.mockReturnValue([
        {
          evidence_family: 'function_decompile',
          result_json: {
            function: 'FUN_100401740',
            address: '100401740',
            pseudocode: `
              while (running) {
                switch (opcode) {
                  case 0: pc = pc + 1; break;
                  case 1: regs[0] = regs[0] + regs[1]; pc = pc + 3; break;
                }
              }
            `,
          },
        },
      ] as any)

      const result = await handler({
        sample_id: 'sha256:abc123def456',
        function_address: '0x100401740',
      })

      expect(result.ok).toBe(true)
      expect((result.data as any).dispatcher_function).toBe('FUN_100401740')
      expect((result.data as any).entry_count).toBe(2)
    })

    test('should extract opcode table from direct decompiled_code input', async () => {
      const handler = createVmOpcodeExtractHandler(mockWorkspaceManager, mockDatabase)

      mockDatabase.findSample.mockReturnValue({ sample_id: 'sha256:abc123def456' } as any)
      mockDatabase.findAnalysisEvidenceBySample.mockReturnValue([])

      const result = await handler({
        sample_id: 'sha256:abc123def456',
        function_name: 'manual_dispatcher',
        decompiled_code: `
          for (;;) {
            switch (op) {
              case 0x0: pc = pc + 1; break;
              case 0x1: regs[0] = regs[0] ^ regs[1]; pc = pc + 3; break;
            }
          }
        `,
      })

      expect(result.ok).toBe(true)
      expect((result.data as any).dispatcher_function).toBe('manual_dispatcher')
      expect((result.data as any).opcode_table).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ value: 0 }),
          expect.objectContaining({ value: 1 }),
        ])
      )
    })
  })
})
