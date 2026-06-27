/**
 * Unit tests for vm.detect tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import {
  createVmDetectHandler,
  vmDetectInputSchema,
} from '../../src/plugins/vm-analysis/tools/vm-detect.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('vm.detect tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      findAnalysisEvidenceBySample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = vmDetectInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = vmDetectInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = vmDetectInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createVmDetectHandler(mockWorkspaceManager, mockDatabase)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })

    test('should detect VM candidate from single function_decompile evidence', async () => {
      const handler = createVmDetectHandler(mockWorkspaceManager, mockDatabase)

      mockDatabase.findSample.mockReturnValue({ sample_id: 'sha256:abc123def456' } as any)
      mockDatabase.findAnalysisEvidenceBySample.mockReturnValue([
        {
          evidence_family: 'function_decompile',
          result_json: {
            function: 'FUN_100401740',
            address: '100401740',
            pseudocode: `
              while (running) {
                opcode = bytecode[pc];
                switch (opcode) {
                  case 0: pc = pc + 1; break;
                  case 1: regs[0] = regs[0] + bytecode[pc + 1]; pc = pc + 2; break;
                  case 2: regs[1] = regs[1] ^ bytecode[pc + 1]; pc = pc + 2; break;
                  case 3: regs[2] = regs[2] - bytecode[pc + 1]; pc = pc + 2; break;
                  case 4: if (flag == 0) pc = bytecode[pc + 1]; break;
                  case 5: running = false; break;
                }
              }
            `,
          },
        },
      ] as any)

      const result = await handler({ sample_id: 'sha256:abc123def456', min_score: 20 })

      expect(result.ok).toBe(true)
      expect((result.data as any).total_functions_scanned).toBe(1)
      expect((result.data as any).vm_function_count).toBeGreaterThanOrEqual(1)
    })
  })
})
