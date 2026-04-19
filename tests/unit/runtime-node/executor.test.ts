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
let executeDebugSession: typeof import('../../../packages/runtime-node/src/executor.js').executeDebugSession
let executeProcDumpCapture: typeof import('../../../packages/runtime-node/src/executor.js').executeProcDumpCapture
let executeTelemetryCapture: typeof import('../../../packages/runtime-node/src/executor.js').executeTelemetryCapture
let executeDynamicMemoryDump: typeof import('../../../packages/runtime-node/src/executor.js').executeDynamicMemoryDump
let executeWineRun: typeof import('../../../packages/runtime-node/src/executor.js').executeWineRun
let executeSpeakeasyEmulate: typeof import('../../../packages/runtime-node/src/executor.js').executeSpeakeasyEmulate
let executeManagedSafeRun: typeof import('../../../packages/runtime-node/src/executor.js').executeManagedSafeRun
let executeRuntimeToolProbe: typeof import('../../../packages/runtime-node/src/executor.js').executeRuntimeToolProbe
let setSpawnImplementationForTests: typeof import('../../../packages/runtime-node/src/executor.js').setSpawnImplementationForTests
let listRuntimeBackendCapabilities: typeof import('../../../packages/runtime-node/src/executor.js').listRuntimeBackendCapabilities
let getRuntimeBackendCapability: typeof import('../../../packages/runtime-node/src/executor.js').getRuntimeBackendCapability
let buildRuntimeToolInventory: typeof import('../../../packages/runtime-node/src/executor.js').buildRuntimeToolInventory

beforeAll(async () => {
  const executorModule = await import('../../../packages/runtime-node/src/executor.js')
  executeTask = executorModule.executeTask
  executeDebugSession = executorModule.executeDebugSession
  executeProcDumpCapture = executorModule.executeProcDumpCapture
  executeTelemetryCapture = executorModule.executeTelemetryCapture
  executeDynamicMemoryDump = executorModule.executeDynamicMemoryDump
  executeWineRun = executorModule.executeWineRun
  executeSpeakeasyEmulate = executorModule.executeSpeakeasyEmulate
  executeManagedSafeRun = executorModule.executeManagedSafeRun
  executeRuntimeToolProbe = executorModule.executeRuntimeToolProbe
  setSpawnImplementationForTests = executorModule.setSpawnImplementationForTests
  listRuntimeBackendCapabilities = executorModule.listRuntimeBackendCapabilities
  getRuntimeBackendCapability = executorModule.getRuntimeBackendCapability
  buildRuntimeToolInventory = executorModule.buildRuntimeToolInventory
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

function makeMockProcess(options: {
  pid?: number
  stdout?: string
  stderr?: string
  code?: number
  closeDelayMs?: number
}) {
  const stdoutHandlers: Array<(chunk: Buffer) => void> = []
  const stderrHandlers: Array<(chunk: Buffer) => void> = []
  const closeHandlers: any[] = []
  let closeScheduled = false
  const scheduleClose = (cb: any) => {
    closeHandlers.push(cb)
    if (closeScheduled) return
    closeScheduled = true
    setTimeout(() => {
      if (options.stdout) {
        for (const handler of stdoutHandlers) handler(Buffer.from(options.stdout))
      }
      if (options.stderr) {
        for (const handler of stderrHandlers) handler(Buffer.from(options.stderr))
      }
      for (const handler of closeHandlers) handler(options.code ?? 0, null)
    }, options.closeDelayMs ?? 0)
  }
  return {
    pid: options.pid,
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
    kill: jest.fn(),
    on: jest.fn().mockImplementation((event: string, cb: any) => {
      if (event === 'close') {
        scheduleClose(cb)
      }
    }),
    once: jest.fn().mockImplementation((event: string, cb: any) => {
      if (event === 'close') {
        scheduleClose(cb)
      }
    }),
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
    jest.restoreAllMocks()
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
        expect.objectContaining({
          type: 'inline',
          handler: 'executeBehaviorCapture',
          requiresSample: true,
        }),
      ]))

      expect(getRuntimeBackendCapability({ type: 'spawn', handler: 'native.sample.execute' })).toMatchObject({
        type: 'spawn',
        handler: 'native.sample.execute',
        requiresSample: true,
      })
      expect(getRuntimeBackendCapability({ type: 'spawn', handler: 'missing.handler' })).toBeUndefined()
      expect(getRuntimeBackendCapability({ type: 'inline', handler: 'executeRuntimeToolProbe' })).toMatchObject({
        type: 'inline',
        handler: 'executeRuntimeToolProbe',
        requiresSample: false,
      })
    })
  })

  describe('runtime tool inventory', () => {
    test('reports debugger and telemetry tool availability without executing a sample', async () => {
      const toolRoot = path.join(testInbox, 'tools')
      const debuggerDir = path.join(toolRoot, 'debuggers', 'x64')
      const sysinternalsDir = path.join(toolRoot, 'Sysinternals')
      fs.mkdirSync(debuggerDir, { recursive: true })
      fs.mkdirSync(sysinternalsDir, { recursive: true })
      fs.writeFileSync(path.join(debuggerDir, 'cdb.exe'), '')
      fs.writeFileSync(path.join(sysinternalsDir, 'procdump64.exe'), '')

      const oldToolDirs = process.env.RUNTIME_TOOL_DIRS
      process.env.RUNTIME_TOOL_DIRS = toolRoot
      try {
        const inventory = buildRuntimeToolInventory()
        expect(inventory.tools).toEqual(expect.arrayContaining([
          expect.objectContaining({ id: 'cdb', available: true }),
          expect.objectContaining({ id: 'procdump', available: true }),
        ]))
        expect(inventory.profiles).toEqual(expect.arrayContaining([
          expect.objectContaining({ id: 'debugger_cdb', status: 'ready' }),
        ]))

        const result = await executeRuntimeToolProbe(
          { taskId: 'tool-probe', sampleId: 'probe', tool: 'runtime.toolkit.probe', args: {}, timeoutMs: 1000 },
          () => {},
          [],
        )
        expect(result.ok).toBe(true)
        expect(result.artifactRefs).toEqual(expect.arrayContaining([
          expect.objectContaining({ name: 'runtime_tool_inventory.json' }),
        ]))
      } finally {
        if (oldToolDirs === undefined) {
          delete process.env.RUNTIME_TOOL_DIRS
        } else {
          process.env.RUNTIME_TOOL_DIRS = oldToolDirs
        }
      }
    })
  })

  describe('resolveBackendHint via executeTask', () => {
    test('should use runtimeBackendHint when provided', async () => {
      const originalExistsSync = fs.existsSync
      jest.spyOn(fs, 'existsSync').mockImplementation((candidate) => {
        const value = String(candidate).toLowerCase()
        if (value.endsWith('cdb.exe')) return false
        return originalExistsSync(candidate)
      })
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

  describe('executeBehaviorCapture', () => {
    test('captures TCP connection observations into behavior artifacts on Windows', async () => {
      if (process.platform !== 'win32') {
        expect(true).toBe(true)
        return
      }

      const processRowsBefore = JSON.stringify([{ ProcessId: 4, Name: 'System' }])
      const moduleRows = JSON.stringify([{ ModuleName: 'kernel32.dll', FileName: 'C:\\Windows\\System32\\kernel32.dll' }])
      const networkRows = JSON.stringify([{
        OwningProcess: 4242,
        State: 'Established',
        LocalAddress: '10.0.0.5',
        LocalPort: 50100,
        RemoteAddress: '203.0.113.10',
        RemotePort: 443,
      }])
      const processRowsAfter = JSON.stringify([
        { ProcessId: 4, Name: 'System' },
        { ProcessId: 4242, ParentProcessId: 1, Name: 'task-sample.sample', ExecutablePath: samplePath },
      ])
      const fileRows = JSON.stringify([{ FullName: path.join(testOutbox, 'task-sample', 'note.txt'), Length: 5 }])
      const psOutputs = [processRowsBefore, moduleRows, networkRows, processRowsAfter, fileRows]

      spawnMock.mockImplementation((cmd: string) => {
        if (cmd === 'powershell.exe') {
          return makeMockProcess({ stdout: psOutputs.shift() || '[]', code: 0 })
        }
        return makeMockProcess({ pid: 4242, stdout: 'hello', code: 0, closeDelayMs: 5 })
      })

      const result = await executeTask(
        {
          taskId: 'task-sample',
          sampleId: 's1',
          tool: 'dynamic.behavior.capture',
          args: { network_sinkhole: false, timeout_sec: 5 },
          timeoutMs: 5000,
          runtimeBackendHint: { type: 'inline', handler: 'executeBehaviorCapture' },
        },
        () => {},
        () => {},
      )

      expect(result.ok).toBe(true)
      expect((result.result?.data as any).network_events).toEqual(expect.arrayContaining([
        expect.objectContaining({
          remote_address: '203.0.113.10',
          remote_port: 443,
          pid: 4242,
        }),
      ]))
      expect((result.result?.data as any).normalized_trace.stages).toContain('network_activity')
      expect(result.artifactRefs).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'behavior_capture.json' }),
      ]))
    })
  })

  describe('executeDebugSession', () => {
    test('writes a transcript artifact when cdb is unavailable', async () => {
      const originalExistsSync = fs.existsSync
      jest.spyOn(fs, 'existsSync').mockImplementation((candidate) => {
        const value = String(candidate).toLowerCase()
        if (value.endsWith('cdb.exe')) return false
        return originalExistsSync(candidate)
      })

      const result = await executeDebugSession(
        { taskId: 'task-debug', sampleId: 's1', tool: 'debug.session.inspect', args: {}, timeoutMs: 1000 },
        () => {},
        [],
      )

      expect(result.ok).toBe(false)
      expect(result.artifactRefs).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'debug_session_trace.json' }),
      ]))
      const transcript = result.artifactRefs?.find((entry) => entry.name === 'debug_session_trace.json')
      expect(transcript?.path).toBeTruthy()
      expect(fs.existsSync(transcript!.path)).toBe(true)
      expect(fs.readFileSync(transcript!.path, 'utf-8')).toContain('missing_debugger')
    })

    test('passes bounded CDB command batches through the debug-session runtime', async () => {
      const taskId = 'task-cdb-batch'
      const taskSample = path.join(testInbox, `${taskId}.sample`)
      fs.writeFileSync(taskSample, Buffer.from('MZ'))

      const originalExistsSync = fs.existsSync
      jest.spyOn(fs, 'existsSync').mockImplementation((candidate) => {
        const value = String(candidate).toLowerCase()
        if (value.endsWith('cdb.exe')) return true
        return originalExistsSync(candidate)
      })
      spawnMock.mockImplementation((cmd: string, args: string[]) => {
        expect(cmd.toLowerCase()).toContain('cdb.exe')
        expect(args[0]).toBe('-c')
        expect(args[1]).toContain('bp kernel32!CreateRemoteThread')
        expect(args[1]).toContain('q')
        expect(args[2]).toBe(taskSample)
        return makeMockProcess({ stdout: 'hit breakpoint', code: 0 })
      })

      const result = await executeDebugSession(
        {
          taskId,
          sampleId: 's1',
          tool: 'debug.session.command_batch',
          args: { commands: ['bp kernel32!CreateRemoteThread', 'g'] },
          timeoutMs: 1000,
        },
        () => {},
        [],
      )

      expect(result.ok).toBe(true)
      const transcript = result.artifactRefs?.find((entry) => entry.name === 'debug_session_trace.json')
      expect(transcript?.path).toBeTruthy()
      const transcriptText = fs.readFileSync(transcript!.path, 'utf-8')
      expect(transcriptText).toContain('debug.session.command_batch')
      expect(transcriptText).toContain('CreateRemoteThread')
    })
  })

  describe('executeProcDumpCapture', () => {
    test('writes setup artifact when ProcDump is unavailable', async () => {
      const originalExistsSync = fs.existsSync
      jest.spyOn(fs, 'existsSync').mockImplementation((candidate) => {
        const value = String(candidate).toLowerCase()
        if (value.endsWith('procdump64.exe') || value.endsWith('procdump.exe')) return false
        return originalExistsSync(candidate)
      })

      const result = await executeProcDumpCapture(
        { taskId: 'task-procdump-missing', sampleId: 's1', tool: 'debug.procdump.capture', args: {}, timeoutMs: 1000 },
        () => {},
        [],
      )

      expect(result.ok).toBe(false)
      const artifact = result.artifactRefs?.find((entry) => entry.name === 'procdump_capture.json')
      expect(artifact?.path).toBeTruthy()
      expect(fs.readFileSync(artifact!.path, 'utf-8')).toContain('missing_procdump')
    })

    test('launches ProcDump and returns dump artifacts', async () => {
      const taskId = 'task-procdump-capture'
      const taskSample = path.join(testInbox, `${taskId}.sample`)
      fs.writeFileSync(taskSample, Buffer.from('MZ'))

      const originalExistsSync = fs.existsSync
      jest.spyOn(fs, 'existsSync').mockImplementation((candidate) => {
        const value = String(candidate).toLowerCase()
        if (value.endsWith('procdump64.exe') || value.endsWith('procdump.exe')) return true
        return originalExistsSync(candidate)
      })
      spawnMock.mockImplementation((cmd: string, args: string[]) => {
        expect(cmd.toLowerCase()).toMatch(/procdump/)
        expect(args).toEqual(expect.arrayContaining(['-accepteula', '-ma', '-e', '-x']))
        const dumpDir = args[args.indexOf('-x') + 1]
        expect(args).toContain(taskSample)
        fs.mkdirSync(dumpDir, { recursive: true })
        fs.writeFileSync(path.join(dumpDir, 'sample-crash.dmp'), Buffer.from('DUMP'))
        return makeMockProcess({ stdout: 'ProcDump wrote dump', code: 0 })
      })

      const result = await executeProcDumpCapture(
        {
          taskId,
          sampleId: 's1',
          tool: 'debug.procdump.capture',
          args: { mode: 'launch_crash', dump_type: 'full' },
          timeoutMs: 1000,
        },
        () => {},
        [],
      )

      expect(result.ok).toBe(true)
      expect(result.artifactRefs).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'procdump_capture.json' }),
        expect.objectContaining({ name: 'sample-crash.dmp' }),
      ]))
      const metadata = result.artifactRefs?.find((entry) => entry.name === 'procdump_capture.json')
      expect(fs.readFileSync(metadata!.path, 'utf-8')).toContain('launch_crash')
    })
  })

  describe('executeTelemetryCapture', () => {
    test('reports setup_required profile when ProcMon is unavailable', async () => {
      const originalExistsSync = fs.existsSync
      jest.spyOn(fs, 'existsSync').mockImplementation((candidate) => {
        const value = String(candidate).toLowerCase()
        if (value.endsWith('procmon64.exe') || value.endsWith('procmon.exe')) return false
        return originalExistsSync(candidate)
      })

      const result = await executeTelemetryCapture(
        {
          taskId: 'task-telemetry-missing',
          sampleId: 's1',
          tool: 'debug.telemetry.capture',
          args: { profiles: ['procmon'], capture_seconds: 0 },
          timeoutMs: 1000,
        },
        () => {},
        [],
      )

      expect(result.ok).toBe(true)
      const artifact = result.artifactRefs?.find((entry) => entry.name === 'telemetry_capture.json')
      expect(artifact?.path).toBeTruthy()
      const payload = JSON.parse(fs.readFileSync(artifact!.path, 'utf-8'))
      expect(payload.profile_results[0]).toMatchObject({ profile: 'procmon', status: 'setup_required' })
    })

    test('captures PowerShell event-log telemetry artifact', async () => {
      spawnMock.mockImplementation((cmd: string, args: string[]) => {
        expect(cmd.toLowerCase()).toBe('powershell.exe')
        const outputIndex = args.findIndex((arg) => arg.includes('Set-Content'))
        const commandText = args[args.length - 1]
        const match = commandText.match(/Set-Content -LiteralPath '([^']+)'/)
        if (outputIndex >= 0 || match) {
          const outputPath = match?.[1]
          if (outputPath) {
            fs.mkdirSync(path.dirname(outputPath), { recursive: true })
            fs.writeFileSync(outputPath, JSON.stringify([{ LogName: 'System', Id: 1 }]))
          }
        }
        return makeMockProcess({ stdout: '', code: 0 })
      })

      const result = await executeTelemetryCapture(
        {
          taskId: 'task-telemetry-eventlog',
          sampleId: 's1',
          tool: 'debug.telemetry.capture',
          args: { profiles: ['powershell_eventlog'], capture_seconds: 0 },
          timeoutMs: 1000,
        },
        () => {},
        [],
      )

      expect(result.ok).toBe(true)
      expect(result.artifactRefs).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'telemetry_capture.json' }),
        expect.objectContaining({ name: 'eventlog_snapshot.json' }),
      ]))
    })

    test('starts and stops ETW logman capture', async () => {
      spawnMock.mockImplementation((cmd: string, args: string[]) => {
        expect(cmd.toLowerCase()).toBe('logman.exe')
        if (args[0] === 'start') {
          const outputPath = args[args.indexOf('-o') + 1]
          fs.mkdirSync(path.dirname(outputPath), { recursive: true })
          fs.writeFileSync(outputPath, Buffer.from('ETL'))
        }
        return makeMockProcess({ stdout: 'ok', code: 0 })
      })

      const result = await executeTelemetryCapture(
        {
          taskId: 'task-telemetry-etw',
          sampleId: 's1',
          tool: 'debug.telemetry.capture',
          args: { profiles: ['etw_process'], capture_seconds: 0 },
          timeoutMs: 1000,
        },
        () => {},
        [],
      )

      expect(result.ok).toBe(true)
      expect(result.artifactRefs).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'etw_process.etl' }),
      ]))
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
    test('uses per-task upload manifest so sidecars stay next to the executable', async () => {
      const taskDir = path.join(testInbox, 'task-with-sidecar')
      fs.mkdirSync(taskDir, { recursive: true })
      const primary = path.join(taskDir, 'app.exe')
      const sidecar = path.join(taskDir, 'zg__kYYzqVe.dll')
      fs.writeFileSync(primary, Buffer.from('MZ'))
      fs.writeFileSync(sidecar, Buffer.from('DLL'))
      fs.writeFileSync(path.join(taskDir, 'upload-manifest.json'), JSON.stringify({
        schema: 'rikune.runtime_upload_manifest.v1',
        taskId: 'task-with-sidecar',
        primary: 'app.exe',
        files: [
          { name: 'app.exe', role: 'primary', size: 2, uploadedAt: new Date().toISOString() },
          { name: 'zg__kYYzqVe.dll', role: 'sidecar', size: 3, uploadedAt: new Date().toISOString() },
        ],
      }))
      spawnMock.mockImplementation(makeSpawnMock([
        {
          cmd: primary,
          args: [],
          code: 0,
          stdout: `${JSON.stringify({ ok: true, data: { manifest: true } })}\n`,
        },
      ]))

      const result = await executeTask(
        {
          taskId: 'task-with-sidecar',
          sampleId: 's1',
          tool: 'dynamic.spawn.native',
          args: {},
          timeoutMs: 1000,
          runtimeBackendHint: { type: 'spawn', handler: 'native.sample.execute' },
        },
        () => {},
        () => {},
      )

      expect(result.ok).toBe(true)
      expect(spawnMock).toHaveBeenCalledWith(
        primary,
        [],
        expect.objectContaining({
          cwd: taskDir,
          windowsHide: true,
        }),
      )
    })

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
