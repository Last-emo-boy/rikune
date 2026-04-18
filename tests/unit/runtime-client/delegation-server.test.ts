/**
 * Unit tests for runtime-client/delegation-server.ts
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createDelegatingServer, type RuntimeClientLike } from '../../../src/runtime-client/delegation-server.js'
import type { PluginServerInterface, ToolDefinition, WorkerResult, RuntimeBackendHint } from '../../../src/plugins/sdk.js'
import type { RuntimeBackendCapability } from '../../../src/runtime-client/runtime-client.js'
import type { WorkspaceManager } from '../../../src/workspace-manager.js'
import type { DatabaseManager } from '../../../src/database.js'
import type { RuntimeExecuteResponse } from '../../../src/runtime-client/runtime-client.js'
import { RuntimeDelegationFailureResultSchema } from '../../../src/types.js'
import { SandboxExecuteOutputSchema } from '../../../src/plugins/dynamic/tools/sandbox-execute.js'
import { SafeRunOutputSchema } from '../../../src/plugins/managed-sandbox/tools/safe-run.js'
import { wineRunOutputSchema } from '../../../src/plugins/wine/tools/wine-run.js'
import { FridaRuntimeInstrumentOutputSchema } from '../../../src/plugins/frida/tools/frida-runtime-instrument.js'
import { DebugSessionStartOutputSchema } from '../../../src/plugins/debug-session/tools/debug-session-start.js'

describe('createDelegatingServer', () => {
  let inner: PluginServerInterface & { getProgressReporter?: jest.Mock }
  let runtimeClient: RuntimeClientLike
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let resolvePrimarySamplePath: jest.Mock
  const sandboxDir = '/tmp/sandbox'

  const makeRuntimeResponse = (overrides: Partial<RuntimeExecuteResponse> = {}): RuntimeExecuteResponse => ({
    ok: true,
    taskId: 'runtime-task-1',
    result: { ok: true, data: { test: true } },
    artifactRefs: [],
    ...overrides,
  })

  beforeEach(() => {
    inner = {
      registerTool: jest.fn(),
      unregisterTool: jest.fn(),
      getProgressReporter: jest.fn().mockReturnValue({ report: jest.fn().mockResolvedValue(undefined) }),
    } as any

    runtimeClient = {
      execute: jest.fn().mockResolvedValue(makeRuntimeResponse()),
      uploadSample: jest.fn().mockResolvedValue(undefined),
      downloadArtifacts: jest.fn().mockResolvedValue([]),
      recover: jest.fn().mockResolvedValue(true),
    }

    workspaceManager = {} as WorkspaceManager
    database = {} as DatabaseManager
    resolvePrimarySamplePath = jest.fn().mockResolvedValue({ samplePath: '/tmp/sample.exe' })
  })

  const createServer = (client: RuntimeClientLike | null) =>
    createDelegatingServer(inner, 'test-plugin', client, workspaceManager, database, resolvePrimarySamplePath, sandboxDir)

  const localDynamicTool: ToolDefinition = {
    name: 'dynamic.auto_hook',
    description: 'test',
    inputSchema: {},
  }

  const remoteDynamicTool: ToolDefinition = {
    name: 'frida.runtime.instrument',
    description: 'test',
    inputSchema: {},
    runtimeBackendHint: { type: 'python-worker', handler: 'frida_worker.py' },
  }

  const availableRuntimeBackends: RuntimeBackendCapability[] = [
    {
      type: 'spawn',
      handler: 'native.sample.execute',
      description: 'Execute uploaded samples directly.',
      requiresSample: true,
    },
  ]

  const outputSchemaByTool: Record<string, { parse: (value: unknown) => unknown }> = {
    'sandbox.execute': SandboxExecuteOutputSchema,
    'managed.safe_run': SafeRunOutputSchema,
    'wine.run': wineRunOutputSchema,
    'frida.runtime.instrument': FridaRuntimeInstrumentOutputSchema,
    'debug.session.start': DebugSessionStartOutputSchema,
  }

  const runtimeBackedToolCases: Array<{
    tool: string
    hint: RuntimeBackendHint
    expectedNextTool: string
  }> = [
    {
      tool: 'sandbox.execute',
      hint: { type: 'inline', handler: 'executeSandboxExecute' },
      expectedNextTool: 'workflow.analyze.start',
    },
    {
      tool: 'managed.safe_run',
      hint: { type: 'inline', handler: 'executeManagedSafeRun' },
      expectedNextTool: 'sample.profile.get',
    },
    {
      tool: 'wine.run',
      hint: { type: 'inline', handler: 'executeWineRun' },
      expectedNextTool: 'wine.env',
    },
    {
      tool: 'frida.runtime.instrument',
      hint: { type: 'python-worker', handler: 'frida_worker.py' },
      expectedNextTool: 'frida.script.generate',
    },
    {
      tool: 'debug.session.start',
      hint: { type: 'inline', handler: 'executeDebugSession' },
      expectedNextTool: 'sample.profile.get',
    },
  ]

  test.each([
    'dynamic.auto_hook',
    'runtime.debug.session.start',
    'runtime.debug.session.status',
    'runtime.debug.session.stop',
    'runtime.debug.command',
  ])('should register local control tool %s directly on inner server', (toolName) => {
    const server = createServer(runtimeClient)
    const handler = async () => ({ ok: true } as WorkerResult)
    const tool = { ...localDynamicTool, name: toolName }

    server.registerTool(tool, handler)

    expect(inner.registerTool).toHaveBeenCalledWith(tool, handler)
    expect(runtimeClient.execute).not.toHaveBeenCalled()
  })

  test('should wrap remote dynamic tools and forward runtimeBackendHint', async () => {
    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    const originalHandler = async () => ({ ok: true } as WorkerResult)
    server.registerTool(remoteDynamicTool, originalHandler)

    expect(inner.registerTool).toHaveBeenCalledWith(remoteDynamicTool, expect.any(Function))

    const result = await wrappedHandler({ sample_id: 'sha256:abc123', _meta: {} })

    expect(runtimeClient.uploadSample).toHaveBeenCalled()
    expect(runtimeClient.execute).toHaveBeenCalledWith(
      expect.objectContaining({
        tool: 'frida.runtime.instrument',
        runtimeBackendHint: { type: 'python-worker', handler: 'frida_worker.py' },
      }),
      expect.anything()
    )
    expect(result.ok).toBe(true)
  })

  test('should return setup_required when runtimeClient is null', async () => {
    const server = createServer(null)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(result.ok).toBe(true)
    expect((result.data as any)?.status).toBe('setup_required')
    expect((result.data as any)?.failure_category).toBe('runtime_unavailable')
    expect((result.data as any)?.recommended_next_tools).toEqual(
      expect.arrayContaining(['frida.script.generate', 'dynamic.dependencies', 'system.health'])
    )
    expect(result.setup_actions).toBeDefined()
    expect(result.required_user_inputs).toBeDefined()
  })

  test('should download artifacts when runtime returns artifactRefs', async () => {
    runtimeClient.execute = jest.fn().mockResolvedValue(makeRuntimeResponse({
      result: { ok: true, data: {} },
      artifactRefs: [{ name: 'report.json', path: 'C:\\rikune-outbox\\task-123\\report.json' }],
    }))

    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(runtimeClient.downloadArtifacts).toHaveBeenCalledWith(
      expect.any(String),
      expect.stringContaining('outbox'),
      ['report.json']
    )
  })

  test('should retry on network error when recover succeeds', async () => {
    runtimeClient.execute = jest
      .fn()
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockResolvedValueOnce(makeRuntimeResponse({
        result: { ok: true, data: { recovered: true } },
        artifactRefs: [],
      }))
    runtimeClient.recover = jest.fn().mockResolvedValue(true)
    runtimeClient.getEndpoint = jest.fn().mockReturnValue('http://127.0.0.1:4020')

    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(runtimeClient.recover).toHaveBeenCalledWith({ forceRefreshCapabilities: true })
    expect(runtimeClient.execute).toHaveBeenCalledTimes(2)
    expect(result.ok).toBe(true)
    expect(result.data).toEqual({ recovered: true })
  })

  test('should skip upload when sample_id is missing', async () => {
    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    await wrappedHandler({})

    expect(runtimeClient.uploadSample).not.toHaveBeenCalled()
    expect(runtimeClient.execute).toHaveBeenCalled()
  })

  test('should return a runtime failure result when recovery does not restore connectivity', async () => {
    runtimeClient.execute = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    runtimeClient.recover = jest.fn().mockResolvedValue(false)

    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(runtimeClient.recover).toHaveBeenCalledWith({ forceRefreshCapabilities: true })
    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/Runtime execution failed/)
  })

  test('should normalize runtime execution errors without result payloads', async () => {
    runtimeClient.execute = jest.fn().mockResolvedValue(makeRuntimeResponse({
      ok: false,
      result: undefined,
      errors: ['Unsupported runtime backend hint: inline/missing.handler'],
    }))

    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(['Unsupported runtime backend hint: inline/missing.handler'])
  })

  test('should short-circuit unsupported backend hints before upload and execution', async () => {
    runtimeClient.validateRuntimeBackendHint = jest.fn().mockResolvedValue({
      supported: false,
      capabilities: availableRuntimeBackends,
    })

    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(runtimeClient.validateRuntimeBackendHint).toHaveBeenCalledWith(remoteDynamicTool.runtimeBackendHint)
    expect(runtimeClient.uploadSample).not.toHaveBeenCalled()
    expect(runtimeClient.execute).not.toHaveBeenCalled()
    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/does not advertise support for backend hint python-worker\/frida_worker.py/)
    expect(result.data).toEqual({
      status: 'setup_required',
      failure_category: 'unsupported_runtime_backend_hint',
      summary: 'Runtime does not advertise support for backend hint python-worker/frida_worker.py required by tool frida.runtime.instrument.',
      recommended_next_tools: ['frida.script.generate', 'dynamic.dependencies', 'system.health'],
      next_actions: [
        'Verify Frida runtime dependencies and reconnect a compatible runtime before retrying instrumentation.',
        'Use frida.script.generate to prepare instrumentation logic while runtime support is unavailable.',
      ],
      runtime_endpoint: null,
      required_runtime_backend_hint: remoteDynamicTool.runtimeBackendHint,
      available_runtime_backends: availableRuntimeBackends,
    })
  })

  test.each(runtimeBackedToolCases)(
    'should provide capability-aware fallback guidance for %s',
    async ({ tool, hint, expectedNextTool }) => {
      runtimeClient.validateRuntimeBackendHint = jest.fn().mockResolvedValue({
        supported: false,
        capabilities: availableRuntimeBackends,
      })

      const server = createServer(runtimeClient)
      let wrappedHandler: any
      inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

      server.registerTool(
        {
          name: tool,
          description: 'test',
          inputSchema: {},
          runtimeBackendHint: hint,
        },
        async () => ({ ok: true } as WorkerResult)
      )

      const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

      expect(result.ok).toBe(false)
      expect((result.data as any)?.failure_category).toBe('unsupported_runtime_backend_hint')
      expect((result.data as any)?.required_runtime_backend_hint).toEqual(hint)
      expect((result.data as any)?.available_runtime_backends).toEqual(availableRuntimeBackends)
      expect((result.data as any)?.recommended_next_tools).toContain(expectedNextTool)
      expect(() => RuntimeDelegationFailureResultSchema.parse(result)).not.toThrow()
      expect(() => outputSchemaByTool[tool].parse(result)).not.toThrow()
      expect(runtimeClient.uploadSample).not.toHaveBeenCalled()
      expect(runtimeClient.execute).not.toHaveBeenCalled()
    }
  )

  test('should surface recovery failure with runtime_recovery_failed category', async () => {
    runtimeClient.execute = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    runtimeClient.recover = jest.fn().mockResolvedValue(false)
    runtimeClient.getEndpoint = jest.fn().mockReturnValue('http://127.0.0.1:4010')

    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(result.ok).toBe(false)
    expect((result.data as any)?.failure_category).toBe('runtime_recovery_failed')
    expect((result.data as any)?.runtime_endpoint).toBe('http://127.0.0.1:4010')
    expect((result.data as any)?.recommended_next_tools).toContain('frida.script.generate')
  })
})
