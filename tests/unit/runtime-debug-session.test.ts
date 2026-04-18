/**
 * Unit tests for explicit Runtime Node debug-session control tools.
 */

import { describe, test, expect, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import http from 'http'
import {
  createRuntimeDebugCommandHandler,
  createRuntimeDebugSessionStartHandler,
  createRuntimeDebugSessionStatusHandler,
  runtimeDebugCommandToolDefinition,
  runtimeDebugSessionStartToolDefinition,
  runtimeDebugSessionStatusToolDefinition,
  runtimeDebugSessionStopToolDefinition,
} from '../../src/plugins/dynamic/tools/runtime-debug-session.js'

const SAMPLE_SHA256 = 'a'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_SHA256}`

function createDebugSessionDatabaseMock(sampleId = SAMPLE_ID, sha256 = SAMPLE_SHA256) {
  const debugSessions = new Map<string, any>()
  return {
    findSample: jest.fn().mockImplementation((id: string) => id === sampleId
      ? {
          id: sampleId,
          sha256,
          md5: null,
          size: 2,
          file_type: 'PE',
          created_at: new Date().toISOString(),
          source: 'unit-test',
        }
      : undefined),
    findDebugSession: jest.fn().mockImplementation((id: string) => debugSessions.get(id)),
    findDebugSessionsBySample: jest.fn().mockImplementation((id: string) =>
      Array.from(debugSessions.values()).filter((entry) => entry.sample_id === id)
    ),
    insertDebugSession: jest.fn().mockImplementation((session: any) => {
      debugSessions.set(session.id, { ...session })
    }),
    updateDebugSession: jest.fn().mockImplementation((id: string, updates: any) => {
      const existing = debugSessions.get(id)
      if (existing) {
        debugSessions.set(id, { ...existing, ...updates })
      }
    }),
    insertArtifact: jest.fn(),
  }
}

describe('runtime debug session tools', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  test('exports explicit runtime debug-session tool definitions', () => {
    expect(runtimeDebugSessionStartToolDefinition.name).toBe('runtime.debug.session.start')
    expect(runtimeDebugSessionStatusToolDefinition.name).toBe('runtime.debug.session.status')
    expect(runtimeDebugSessionStopToolDefinition.name).toBe('runtime.debug.session.stop')
    expect(runtimeDebugCommandToolDefinition.name).toBe('runtime.debug.command')
  })

  test('attaches to a manual runtime endpoint, persists session state, and imports runtime artifacts', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-runtime-debug-'))
    const samplePath = path.join(tmpDir, 'sample.exe')
    fs.writeFileSync(samplePath, 'MZ')
    const requests: Array<{ url: string; body?: any }> = []
    const server = http.createServer((req, res) => {
      const requestUrl = new URL(req.url || '/', 'http://127.0.0.1')
      const chunks: Buffer[] = []
      req.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      req.on('end', () => {
        const rawBody = Buffer.concat(chunks).toString('utf-8')
        const body = rawBody && req.headers['content-type']?.includes('json') ? JSON.parse(rawBody) : undefined
        requests.push({ url: requestUrl.pathname, body })

        if (req.method === 'GET' && requestUrl.pathname === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true, runtime: 'test-runtime' }))
          return
        }
        if (req.method === 'GET' && requestUrl.pathname === '/capabilities') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'inline',
                  handler: 'executeDebugSession',
                  description: 'Debug session handler',
                  requiresSample: true,
                },
              ],
            },
          }))
          return
        }
        if (req.method === 'POST' && requestUrl.pathname === '/upload') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true }))
          return
        }
        if (req.method === 'POST' && requestUrl.pathname === '/execute') {
          res.writeHead(202, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true, taskId: body?.taskId }))
          return
        }
        if (req.method === 'GET' && requestUrl.pathname.startsWith('/tasks/')) {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({
            status: 'completed',
            result: {
              ok: true,
              data: { inspected: true },
              artifactRefs: [
                { name: 'runtime-report.json', path: 'C:\\rikune-outbox\\task\\runtime-report.json' },
              ],
            },
          }))
          return
        }
        if (req.method === 'GET' && requestUrl.pathname.includes('/download/') && requestUrl.pathname.endsWith('/runtime-report.json')) {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ captured: true }))
          return
        }
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'unexpected url' }))
      })
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('Failed to bind local runtime test server')

    const database = createDebugSessionDatabaseMock()
    const deps: any = {
      config: { runtime: {} },
      workspaceManager: {
        createWorkspace: jest.fn().mockImplementation(async () => ({
          root: tmpDir,
          original: path.join(tmpDir, 'original'),
          cache: path.join(tmpDir, 'cache'),
          ghidra: path.join(tmpDir, 'ghidra'),
          reports: path.join(tmpDir, 'reports'),
        })),
      },
      database,
      resolvePrimarySamplePath: jest.fn().mockResolvedValue({ samplePath }),
    }
    const endpoint = `http://127.0.0.1:${address.port}`
    const start = await createRuntimeDebugSessionStartHandler(deps)({
      manual_endpoint: endpoint,
      sample_id: SAMPLE_ID,
    })

    try {
      expect(start.ok).toBe(true)
      expect((start.data as any).persistent).toBe(true)
      expect(database.insertDebugSession).toHaveBeenCalledTimes(1)
      const sessionId = (start.data as any).session.sessionId
      expect(sessionId).toEqual(expect.any(String))

      const command = await createRuntimeDebugCommandHandler(deps)({
        session_id: sessionId,
        tool: 'debug.session.inspect',
        sample_id: SAMPLE_ID,
        args: { inspect: 'registers' },
      })

      expect(command.ok).toBe(true)
      expect((command.data as any).runtime_backend_hint).toEqual({
        type: 'inline',
        handler: 'executeDebugSession',
      })

      const executeRequest = requests.find((entry) => entry.url.endsWith('/execute'))
      expect(executeRequest?.body).toEqual(expect.objectContaining({
        sampleId: SAMPLE_ID,
        tool: 'debug.session.inspect',
        args: { inspect: 'registers' },
        runtimeBackendHint: { type: 'inline', handler: 'executeDebugSession' },
      }))
      expect(database.updateDebugSession).toHaveBeenCalled()
      expect(database.insertArtifact).toHaveBeenCalledWith(expect.objectContaining({
        sample_id: SAMPLE_ID,
        type: 'runtime_debug_artifact',
        mime: 'application/json',
      }))
      expect(command.artifacts).toHaveLength(1)
      const persistedPath = path.join(tmpDir, (command.artifacts?.[0] as any).path)
      expect(fs.existsSync(persistedPath)).toBe(true)

      const status = await createRuntimeDebugSessionStatusHandler(deps)({ session_id: sessionId, sample_id: SAMPLE_ID })
      expect(status.ok).toBe(true)
      expect((status.data as any).runtime).toEqual({ ok: true, runtime: 'test-runtime' })
      expect((status.data as any).persisted_sessions.length).toBeGreaterThanOrEqual(1)
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test('requires sample_id for sample-bound runtime commands', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ok: true, runtime: 'test-runtime' }), { status: 200 })
    )

    const deps: any = { config: { runtime: {} }, workspaceManager: {}, database: {} }
    const start = await createRuntimeDebugSessionStartHandler(deps)({
      manual_endpoint: 'http://runtime.example:18081',
    })
    const sessionId = (start.data as any).session.sessionId

    const command = await createRuntimeDebugCommandHandler(deps)({
      session_id: sessionId,
      tool: 'debug.session.inspect',
      args: { inspect: 'registers' },
    })

    expect(command.ok).toBe(false)
    expect(command.errors?.[0]).toContain('sample_id is required')
  })

  test('forwards per-session Hyper-V lifecycle policy to Host Agent and persists it', async () => {
    const runtimeServer = http.createServer((req, res) => {
      const requestUrl = new URL(req.url || '/', 'http://127.0.0.1')
      if (req.method === 'GET' && requestUrl.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, runtime: 'hyperv-runtime' }))
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'not found' }))
    })
    await new Promise<void>((resolve) => runtimeServer.listen(0, '127.0.0.1', resolve))
    const runtimeAddress = runtimeServer.address()
    if (!runtimeAddress || typeof runtimeAddress === 'string') throw new Error('Failed to bind runtime server')
    const runtimeEndpoint = `http://127.0.0.1:${runtimeAddress.port}`

    const hostAgentRequests: any[] = []
    const hostAgentServer = http.createServer((req, res) => {
      const requestUrl = new URL(req.url || '/', 'http://127.0.0.1')
      const chunks: Buffer[] = []
      req.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      req.on('end', () => {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}')
        hostAgentRequests.push({ path: requestUrl.pathname, body })
        if (req.method === 'POST' && requestUrl.pathname === '/sandbox/start') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({
            ok: true,
            endpoint: runtimeEndpoint,
            sandboxId: 'hyperv-session-1',
            backend: 'hyperv-vm',
            hyperv: {
              vmName: 'rikune-runtime',
              snapshotName: body.hypervSnapshotName,
              restoreOnStart: body.hypervRestoreOnStart,
              restoreOnRelease: body.hypervRestoreOnRelease,
              stopOnRelease: body.hypervStopOnRelease,
            },
          }))
          return
        }
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'not found' }))
      })
    })
    await new Promise<void>((resolve) => hostAgentServer.listen(0, '127.0.0.1', resolve))
    const hostAgentAddress = hostAgentServer.address()
    if (!hostAgentAddress || typeof hostAgentAddress === 'string') throw new Error('Failed to bind host agent server')

    const database = createDebugSessionDatabaseMock()
    const deps: any = {
      config: { runtime: { hostAgentEndpoint: `http://127.0.0.1:${hostAgentAddress.port}` } },
      workspaceManager: {},
      database,
    }

    try {
      const result = await createRuntimeDebugSessionStartHandler(deps)({
        sample_id: SAMPLE_ID,
        hyperv_retention_policy: 'clean_rollback',
        hyperv_snapshot_name: 'clean-base',
      })

      expect(result.ok).toBe(true)
      expect(hostAgentRequests[0].body).toEqual(expect.objectContaining({
        hypervSnapshotName: 'clean-base',
        hypervRestoreOnStart: true,
        hypervRestoreOnRelease: true,
        hypervStopOnRelease: true,
      }))
      const sessionId = (result.data as any).session.sessionId
      const persisted = database.findDebugSession(sessionId)
      expect(persisted).toBeDefined()
      const metadata = JSON.parse(persisted!.metadata_json)
      expect(metadata.hyperv_policy).toEqual(expect.objectContaining({
        vmName: 'rikune-runtime',
        snapshotName: 'clean-base',
        requestedPolicy: 'clean_rollback',
        restoreOnStart: true,
        restoreOnRelease: true,
        stopOnRelease: true,
      }))
    } finally {
      await new Promise<void>((resolve) => hostAgentServer.close(() => resolve()))
      await new Promise<void>((resolve) => runtimeServer.close(() => resolve()))
    }
  })

  test('fails before upload when Runtime Node does not advertise the required backend hint', async () => {
    const requests: Array<{ url: string; method?: string }> = []
    const server = http.createServer((req, res) => {
      const requestUrl = new URL(req.url || '/', 'http://127.0.0.1')
      requests.push({ url: requestUrl.pathname, method: req.method })

      if (req.method === 'GET' && requestUrl.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, runtime: 'test-runtime' }))
        return
      }
      if (req.method === 'GET' && requestUrl.pathname === '/capabilities') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
          ok: true,
          data: {
            runtime_backends: [
              {
                type: 'inline',
                handler: 'executeSandboxExecute',
                description: 'Sandbox execution handler',
                requiresSample: true,
              },
            ],
          },
        }))
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'unexpected url' }))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('Failed to bind local runtime test server')

    const deps: any = {
      config: { runtime: {} },
      workspaceManager: {},
      database: createDebugSessionDatabaseMock(),
      resolvePrimarySamplePath: jest.fn(),
    }
    const endpoint = `http://127.0.0.1:${address.port}`
    const start = await createRuntimeDebugSessionStartHandler(deps)({
      manual_endpoint: endpoint,
      sample_id: SAMPLE_ID,
    })

    try {
      const sessionId = (start.data as any).session.sessionId
      const command = await createRuntimeDebugCommandHandler(deps)({
        session_id: sessionId,
        tool: 'debug.session.inspect',
        sample_id: SAMPLE_ID,
      })

      expect(command.ok).toBe(false)
      expect((command.data as any).failure_category).toBe('unsupported_runtime_backend_hint')
      expect(deps.resolvePrimarySamplePath).not.toHaveBeenCalled()
      expect(requests.some((entry) => entry.url === '/upload')).toBe(false)
      expect(requests.some((entry) => entry.url === '/execute')).toBe(false)
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })
})
