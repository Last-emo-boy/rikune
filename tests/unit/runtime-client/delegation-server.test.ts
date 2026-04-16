/**
 * Unit tests for runtime-client/delegation-server.ts
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createDelegatingServer, type RuntimeClientLike } from '../../../src/runtime-client/delegation-server.js'
import type { PluginServerInterface, ToolDefinition, WorkerResult } from '../../../src/plugins/sdk.js'
import type { WorkspaceManager } from '../../../src/workspace-manager.js'
import type { DatabaseManager } from '../../../src/database.js'

describe('createDelegatingServer', () => {
  let inner: PluginServerInterface & { getProgressReporter?: jest.Mock }
  let runtimeClient: RuntimeClientLike
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let resolvePrimarySamplePath: jest.Mock
  const sandboxDir = '/tmp/sandbox'

  beforeEach(() => {
    inner = {
      registerTool: jest.fn(),
      unregisterTool: jest.fn(),
      getProgressReporter: jest.fn().mockReturnValue({ report: jest.fn().mockResolvedValue(undefined) }),
    } as any

    runtimeClient = {
      execute: jest.fn().mockResolvedValue({
        ok: true,
        result: { ok: true, data: { test: true } },
        artifactRefs: [],
      }),
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

  test('should register local dynamic tools directly on inner server', () => {
    const server = createServer(runtimeClient)
    const handler = async () => ({ ok: true } as WorkerResult)

    server.registerTool(localDynamicTool, handler)

    expect(inner.registerTool).toHaveBeenCalledWith(localDynamicTool, handler)
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
    expect(result.setup_actions).toBeDefined()
    expect(result.required_user_inputs).toBeDefined()
  })

  test('should download artifacts when runtime returns artifactRefs', async () => {
    runtimeClient.execute = jest.fn().mockResolvedValue({
      ok: true,
      result: { ok: true, data: {} },
      artifactRefs: [{ name: 'report.json', path: 'C:\\rikune-outbox\\task-123\\report.json' }],
    })

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
      .mockResolvedValueOnce({
        ok: true,
        result: { ok: true, data: { recovered: true } },
        artifactRefs: [],
      })

    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(runtimeClient.recover).toHaveBeenCalled()
    expect(runtimeClient.execute).toHaveBeenCalledTimes(2)
    expect(result.ok).toBe(true)
  })

  test('should return error when recovery fails after network error', async () => {
    runtimeClient.execute = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    runtimeClient.recover = jest.fn().mockResolvedValue(false)

    const server = createServer(runtimeClient)
    let wrappedHandler: any
    inner.registerTool = jest.fn((_def, handler) => { wrappedHandler = handler })

    server.registerTool(remoteDynamicTool, async () => ({ ok: true } as WorkerResult))
    const result = await wrappedHandler({ sample_id: 'sha256:abc123' })

    expect(runtimeClient.recover).toHaveBeenCalled()
    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/Runtime execution failed/)
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
})
