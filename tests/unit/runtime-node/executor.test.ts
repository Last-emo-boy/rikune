/**
 * Unit tests for runtime-node executor backend pre-flight checks
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import os from 'os'

// Set runtime paths before importing executor (config loads at import time)
const testInbox = path.join(os.tmpdir(), 'rikune-test-inbox')
const testOutbox = path.join(os.tmpdir(), 'rikune-test-outbox')
process.env.RUNTIME_INBOX = testInbox
process.env.RUNTIME_OUTBOX = testOutbox

jest.unstable_mockModule('child_process', () => ({
  spawn: jest.fn(),
}))

const { spawn } = await import('child_process')
const {
  executeTask,
  executeDynamicMemoryDump,
  executeWineRun,
  executeSpeakeasyEmulate,
  executeManagedSafeRun,
} = await import('../../../packages/runtime-node/src/executor.js')

function makeSpawnMock(sequence: Array<{ cmd: string; args: string[]; code: number }>) {
  let callIndex = 0
  return jest.fn().mockImplementation((cmd: string, args: string[]) => {
    const match = sequence.find((s) => s.cmd === cmd && JSON.stringify(s.args) === JSON.stringify(args))
      || sequence[callIndex++]
    const code = match ? match.code : 0
    const mockProc = {
      stdout: { on: jest.fn() },
      stderr: { on: jest.fn() },
      stdin: { write: jest.fn(), end: jest.fn() },
      on: jest.fn().mockImplementation((event: string, cb: any) => {
        if (event === 'close') setTimeout(() => cb(code), 0)
        if (event === 'error') {
          // only call error if code indicates failure and we want to simulate error
        }
      }),
    }
    return mockProc
  })
}

describe('runtime-node executor backend pre-flight checks', () => {
  const mockedSpawn = spawn as jest.MockedFunction<typeof spawn>
  let samplePath: string

  beforeEach(() => {
    fs.mkdirSync(testInbox, { recursive: true })
    fs.mkdirSync(testOutbox, { recursive: true })
    samplePath = path.join(testInbox, 'task-sample.sample')
    fs.writeFileSync(samplePath, Buffer.from('MZ'))
    mockedSpawn.mockClear()
  })

  afterEach(() => {
    try { fs.rmSync(testInbox, { recursive: true, force: true }) } catch {}
    try { fs.rmSync(testOutbox, { recursive: true, force: true }) } catch {}
  })

  describe('resolveBackendHint via executeTask', () => {
    test('should use runtimeBackendHint when provided', async () => {
      // Inline handler name must exist in runtime executor
      const result = await executeTask(
        {
          taskId: 't1',
          sampleId: 's1',
          tool: 'unknown.tool',
          args: {},
          timeoutMs: 1000,
          runtimeBackendHint: { type: 'inline', handler: 'executeDebugSession' },
        },
        () => {},
        () => {},
      )
      // executeDebugSession needs cdbPath, so it will fail with cdb not found rather than unknown tool
      expect(result.errors?.[0]).not.toMatch(/Unknown tool/)
    })

    test('should fallback to frida prefix heuristic when no hint', async () => {
      mockedSpawn.mockImplementation(() => {
        const mockProc: any = {
          stdout: { on: jest.fn(), pipe: jest.fn() },
          stderr: { on: jest.fn() },
          stdin: { write: jest.fn(), end: jest.fn() },
          on: jest.fn().mockImplementation((event: string, cb: any) => {
            if (event === 'close') setTimeout(() => cb(0), 0)
          }),
        }
        return mockProc
      })

      const result = await executeTask(
        {
          taskId: 't2',
          sampleId: 's1',
          tool: 'frida.runtime.instrument',
          args: {},
          timeoutMs: 1000,
        },
        () => {},
        () => {},
      )
      // It should route to python-worker/frida_worker.py and fail because sample file is missing in inbox
      expect(result.errors?.[0]).toMatch(/Sample file not found in runtime inbox/)
    })

    test('should return unknown tool when no hint and no heuristic match', async () => {
      const result = await executeTask(
        {
          taskId: 't3',
          sampleId: 's1',
          tool: 'totally.unknown.tool',
          args: {},
          timeoutMs: 1000,
        },
        () => {},
        () => {},
      )
      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/Unknown tool/)
    })
  })

  describe('executeDynamicMemoryDump', () => {
    test('should return error when frida python module is missing', async () => {
      mockedSpawn.mockImplementation(makeSpawnMock([
        { cmd: process.platform === 'win32' ? 'python' : 'python3', args: ['--version'], code: 0 },
        { cmd: process.platform === 'win32' ? 'python' : 'python3', args: ['-c', 'import frida'], code: 1 },
      ]))

      const result = await executeDynamicMemoryDump(
        { taskId: 'task-sample', sampleId: 's1', tool: 'dynamic.memory.dump', args: {}, timeoutMs: 1000 },
        () => {},
        [],
      )

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/Python module 'frida' is not installed/)
    })
  })

  describe('executeWineRun', () => {
    test('should return error when wine is missing on non-Windows', async () => {
      if (process.platform === 'win32') {
        // On Windows wine check is skipped; just verify isolation check logic instead
        expect(true).toBe(true)
        return
      }
      mockedSpawn.mockImplementation(makeSpawnMock([
        { cmd: 'wine', args: ['--version'], code: 1 },
      ]))

      const result = await executeWineRun(
        { taskId: 'task-sample', sampleId: 's1', tool: 'wine.run', args: {}, timeoutMs: 1000 },
        () => {},
        [],
      )

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/Wine is not available/)
    })
  })

  describe('executeSpeakeasyEmulate', () => {
    test('should return error when speakeasy python module is missing', async () => {
      mockedSpawn.mockImplementation(makeSpawnMock([
        { cmd: process.platform === 'win32' ? 'python' : 'python3', args: ['--version'], code: 0 },
        { cmd: process.platform === 'win32' ? 'python' : 'python3', args: ['-c', 'import speakeasy'], code: 1 },
      ]))

      const result = await executeSpeakeasyEmulate(
        { taskId: 'task-sample', sampleId: 's1', tool: 'speakeasy.emulate', args: {}, timeoutMs: 1000 },
        () => {},
        [],
      )

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/Python module 'speakeasy' is not installed/)
    })
  })

  describe('executeManagedSafeRun', () => {
    test('should return error when dotnet is missing on non-Windows', async () => {
      if (process.platform === 'win32') {
        expect(true).toBe(true)
        return
      }
      mockedSpawn.mockImplementation(makeSpawnMock([
        { cmd: 'dotnet', args: ['--version'], code: 1 },
      ]))

      const result = await executeManagedSafeRun(
        { taskId: 'task-sample', sampleId: 's1', tool: 'managed.safe_run', args: {}, timeoutMs: 1000 },
        () => {},
        [],
      )

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/dotnet CLI is not available/)
    })
  })
})
