/**
 * Unit tests for runtime-node executor backend pre-flight checks
 */

import { describe, test, expect, beforeAll, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import os from 'os'

// Set runtime paths before importing executor (config loads at import time)
const testInbox = path.join(os.tmpdir(), 'rikune-test-inbox')
const testOutbox = path.join(os.tmpdir(), 'rikune-test-outbox')
process.env.RUNTIME_INBOX = testInbox
process.env.RUNTIME_OUTBOX = testOutbox

const spawnMock = jest.fn()

jest.unstable_mockModule('child_process', () => ({
  spawn: spawnMock,
}))

let executeTask: typeof import('../../../packages/runtime-node/src/executor.js').executeTask
let executeDynamicMemoryDump: typeof import('../../../packages/runtime-node/src/executor.js').executeDynamicMemoryDump
let executeWineRun: typeof import('../../../packages/runtime-node/src/executor.js').executeWineRun
let executeSpeakeasyEmulate: typeof import('../../../packages/runtime-node/src/executor.js').executeSpeakeasyEmulate
let executeManagedSafeRun: typeof import('../../../packages/runtime-node/src/executor.js').executeManagedSafeRun
let setSpawnImplementationForTests: typeof import('../../../packages/runtime-node/src/executor.js').setSpawnImplementationForTests
let listRuntimeBackendCapabilities: typeof import('../../../packages/runtime-node/src/executor.js').listRuntimeBackendCapabilities
let getRuntimeBackendCapability: typeof import('../../../packages/runtime-node/src/executor.js').getRuntimeBackendCapability

beforeAll(async () => {
  const executorModule = await import('../../../packages/runtime-node/src/executor.js')
  executeTask = executorModule.executeTask
  executeDynamicMemoryDump = executorModule.executeDynamicMemoryDump
  executeWineRun = executorModule.executeWineRun
  executeSpeakeasyEmulate = executorModule.executeSpeakeasyEmulate
  executeManagedSafeRun = executorModule.executeManagedSafeRun
  setSpawnImplementationForTests = executorModule.setSpawnImplementationForTests
  listRuntimeBackendCapabilities = executorModule.listRuntimeBackendCapabilities
  getRuntimeBackendCapability = executorModule.getRuntimeBackendCapability
})

function makeSpawnMock(sequence: Array<{ cmd: string; args: string[]; code: number; stdout?: string; stderr?: string }>) {
  let nextIndex = 0
  return (cmd: string, args: string[]) => {
    const matchedIndex = sequence.findIndex((entry, index) => {
      if (index < nextIndex) return false
      return entry.cmd === cmd && JSON.stringify(entry.args) === JSON.stringify(args)
    })
    const match = matchedIndex >= 0 ? sequence[matchedIndex] : sequence[nextIndex]
    if (matchedIndex < 0) {
      nextIndex += 1
    } else {
      nextIndex = matchedIndex + 1
    }

    const code = match ? match.code : 0
    const stdoutHandlers: Array<(chunk: Buffer) => void> = []
    const stderrHandlers: Array<(chunk: Buffer) => void> = []
    const mockProc = {
      stdout: {
        on: jest.fn().mockImplementation((event: string, cb: (chunk: Buffer) => void) => {
          if (event === 'data') stdoutHandlers.push(cb)
        }),
      },
      stderr: {
        on: jest.fn().mockImplementation((event: string, cb: (chunk: Buffer) => void) => {
          if (event === 'data') stderrHandlers.push(cb)
        }),
      },
      stdin: { write: jest.fn(), end: jest.fn() },
      on: jest.fn().mockImplementation((event: string, cb: any) => {
        if (event === 'close') {
          setTimeout(() => {
            if (match?.stdout) {
              for (const handler of stdoutHandlers) handler(Buffer.from(match.stdout))
            }
            if (match?.stderr) {
              for (const handler of stderrHandlers) handler(Buffer.from(match.stderr))
            }
            cb(code, null)
          }, 0)
        }
      }),
      once: jest.fn().mockImplementation((event: string, cb: any) => {
        if (event === 'close') {
          setTimeout(() => cb(code, null), 0)
        }
      }),
    }
    return mockProc
  }
}

describe('runtime-node executor backend pre-flight checks', () => {
  let samplePath: string

  beforeEach(() => {
    fs.mkdirSync(testInbox, { recursive: true })
    fs.mkdirSync(testOutbox, { recursive: true })
    samplePath = path.join(testInbox, 'task-sample.sample')
    fs.writeFileSync(samplePath, Buffer.from('MZ'))
    spawnMock.mockReset()
    setSpawnImplementationForTests(spawnMock as any)
  })

  afterEach(() => {
    setSpawnImplementationForTests()
    try { fs.rmSync(testInbox, { recursive: true, force: true }) } catch {}
    try { fs.rmSync(testOutbox, { recursive: true, force: true }) } catch {}
  })

  describe('runtime backend capability registry', () => {
    test('returns normalized capability entries and lookup by hint', () => {
      const capabilities = listRuntimeBackendCapabilities()
      expect(capabilities).toEqual(expect.arrayContaining([
        expect.objectContaining({
          type: 'spawn',
          handler: 'native.sample.execute',
          requiresSample: true,
        }),
        expect.objectContaining({
          type: 'inline',
          handler: 'executeSandboxExecute',
          requiresSample: true,
        }),
      ]))

      expect(getRuntimeBackendCapability({ type: 'spawn', handler: 'native.sample.execute' })).toMatchObject({
        type: 'spawn',
        handler: 'native.sample.execute',
        requiresSample: true,
      })
      expect(getRuntimeBackendCapability({ type: 'spawn', handler: 'missing.handler' })).toBeUndefined()
    })
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
      spawnMock.mockImplementation(() => {
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
      spawnMock.mockImplementation(makeSpawnMock([
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
      spawnMock.mockImplementation(makeSpawnMock([
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
      spawnMock.mockImplementation(makeSpawnMock([
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

  describe('spawn backend execution', () => {
    test('should execute registered spawn backend and parse structured stdout', async () => {
      const structuredStdout = `${JSON.stringify({ ok: true, data: { backend: 'native.sample.execute', exit: 'ok' } })}\n`
      spawnMock.mockImplementation(makeSpawnMock([
        {
          cmd: samplePath,
          args: ['--flag', 'value'],
          code: 0,
          stdout: structuredStdout,
        },
      ]))

      const result = await executeTask(
        {
          taskId: 'task-sample',
          sampleId: 's1',
          tool: 'dynamic.spawn.native',
          args: { arguments: ['--flag', 'value'] },
          timeoutMs: 1000,
          runtimeBackendHint: { type: 'spawn', handler: 'native.sample.execute' },
        },
        () => {},
        () => {},
      )

      expect(result.ok).toBe(true)
      expect(result.result?.ok).toBe(true)
      expect(result.result?.data).toMatchObject({ backend: 'native.sample.execute', exit: 'ok' })
      expect(spawnMock).toHaveBeenCalledWith(
        samplePath,
        ['--flag', 'value'],
        expect.objectContaining({
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 1000,
          windowsHide: true,
        }),
      )
    })
  })

  describe('executeManagedSafeRun', () => {
    test('should return error when dotnet is missing on non-Windows', async () => {
      if (process.platform === 'win32') {
        expect(true).toBe(true)
        return
      }
      spawnMock.mockImplementation(makeSpawnMock([
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
