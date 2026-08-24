/**
 * Unit tests for elf.structure.analyze tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  createElfStructureAnalyzeHandler,
  ElfStructureAnalyzeInputSchema,
} from '../../src/plugins/elf-macho/tools/elf-structure-analyze.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('elf.structure.analyze tool', () => {
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
      const result = ElfStructureAnalyzeInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = ElfStructureAnalyzeInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = ElfStructureAnalyzeInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createElfStructureAnalyzeHandler(mockWorkspaceManager, mockDatabase)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })

    test('forwards abort to the supervised worker and never persists after cancellation', async () => {
      const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-elf-abort-'))
      const original = path.join(tempRoot, 'original')
      fs.mkdirSync(original, { recursive: true })
      fs.writeFileSync(path.join(original, 'sample.elf'), Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
      mockDatabase.findSample.mockReturnValue({ id: 'sha256:elf' } as any)
      mockWorkspaceManager.getWorkspaceRoot = jest.fn(() => tempRoot)
      mockWorkspaceManager.getWorkspace.mockResolvedValue({
        root: tempRoot,
        original,
        reports: path.join(tempRoot, 'reports'),
        ghidra: path.join(tempRoot, 'ghidra'),
      } as any)
      let resolveStarted!: (signal: AbortSignal) => void
      const started = new Promise<AbortSignal>((resolve) => {
        resolveStarted = resolve
      })
      let resolveTeardown!: () => void
      const teardown = new Promise<void>((resolve) => {
        resolveTeardown = resolve
      })
      const runProcess = jest.fn(async (options: { abortSignal?: AbortSignal }) => {
        if (!options.abortSignal) throw new Error('missing AbortSignal')
        resolveStarted(options.abortSignal)
        await new Promise<void>((resolve) => {
          options.abortSignal?.addEventListener('abort', () => resolve(), { once: true })
        })
        await teardown
        return {
          exitCode: 0,
          signal: null,
          timedOut: false,
          stdout: '{"ok":true}\n',
          stderr: '',
          error: null,
        }
      })
      const handler = createElfStructureAnalyzeHandler(mockWorkspaceManager, mockDatabase, {
        runProcess: runProcess as any,
      })
      const controller = new AbortController()
      let settled = false
      const running = handler({ sample_id: 'sha256:elf' }, controller.signal).finally(() => {
        settled = true
      })

      try {
        const receivedSignal = await started
        controller.abort(new Error('cancel ELF worker'))
        await Promise.resolve()
        expect(receivedSignal).toBe(controller.signal)
        expect(settled).toBe(false)

        resolveTeardown()
        await expect(running).rejects.toMatchObject({ name: 'AbortError' })
        expect(mockDatabase.getDb).not.toHaveBeenCalled()
      } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true })
      }
    })
  })
})
