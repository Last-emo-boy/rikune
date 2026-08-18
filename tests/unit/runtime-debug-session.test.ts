/**
 * Unit tests for explicit Runtime Node debug-session control tools.
 */

import { describe, test, expect, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import http from 'http'
import {
  canTransitionRuntimeDebugSessionState,
  createRuntimeDebugCommandHandler,
  createRuntimeDebugSessionStartHandler,
  createRuntimeDebugSessionStatusHandler,
  createRuntimeDebugSessionStopHandler,
  normalizeRuntimeDebugSessionState,
  runtimeDebugCommandToolDefinition,
  runtimeDebugSessionStartToolDefinition,
  runtimeDebugSessionStatusToolDefinition,
  runtimeDebugSessionStopToolDefinition,
  RUNTIME_DEBUG_SESSION_STATES,
  RuntimeDebugSessionStateSchema,
} from '../../src/plugins/dynamic/tools/runtime-debug-session.js'

const SAMPLE_SHA256 = 'a'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_SHA256}`

function createDebugSessionDatabaseMock(sampleId = SAMPLE_ID, sha256 = SAMPLE_SHA256) {
  const debugSessions = new Map<string, any>()
  return {
    findSample: jest.fn().mockImplementation((id: string) =>
      id === sampleId
        ? {
            id: sampleId,
            sha256,
            md5: null,
            size: 2,
            file_type: 'PE',
            created_at: new Date().toISOString(),
            source: 'unit-test',
          }
        : undefined
    ),
    findDebugSession: jest.fn().mockImplementation((id: string) => debugSessions.get(id)),
    findDebugSessionsBySample: jest
      .fn()
      .mockImplementation((id: string) =>
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

function createPersistedHyperVSessionRow(id: string, endpoint: string) {
  return {
    id,
    sample_id: null,
    sample_sha256: null,
    status: 'captured',
    debug_state: 'captured',
    backend: 'hyperv-vm',
    artifact_refs_json: '[]',
    metadata_json: JSON.stringify({
      endpoint,
      endpoint_parent: 'http://host-agent.internal:18082',
      backend: 'hyperv-vm',
    }),
    created_at: '2026-08-17T00:00:00.000Z',
    updated_at: '2026-08-17T00:00:00.000Z',
    finished_at: null,
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

  test('exports an explicit runtime session state machine', () => {
    expect(RUNTIME_DEBUG_SESSION_STATES).toEqual(
      expect.arrayContaining([
        'not_requested',
        'planned',
        'armed',
        'capturing',
        'approval_gated',
        'captured',
        'finished',
      ])
    )
    expect(RuntimeDebugSessionStateSchema.parse('planned')).toBe('planned')
    expect(normalizeRuntimeDebugSessionState('completed')).toBe('finished')
    expect(canTransitionRuntimeDebugSessionState('planned', 'armed')).toBe(true)
    expect(canTransitionRuntimeDebugSessionState('armed', 'capturing')).toBe(true)
    expect(canTransitionRuntimeDebugSessionState('capturing', 'approval_gated')).toBe(false)
    expect(canTransitionRuntimeDebugSessionState('finished', 'capturing')).toBe(false)
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
        const body =
          rawBody && req.headers['content-type']?.includes('json') ? JSON.parse(rawBody) : undefined
        requests.push({ url: requestUrl.pathname, body })

        if (req.method === 'GET' && requestUrl.pathname === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true, runtime: 'test-runtime' }))
          return
        }
        if (req.method === 'GET' && requestUrl.pathname === '/capabilities') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(
            JSON.stringify({
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
            })
          )
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
          res.end(
            JSON.stringify({
              status: 'completed',
              result: {
                ok: true,
                data: { inspected: true },
                artifactRefs: [
                  {
                    name: 'runtime-report.json',
                    path: 'C:\\rikune-outbox\\task\\runtime-report.json',
                  },
                ],
              },
            })
          )
          return
        }
        if (
          req.method === 'GET' &&
          requestUrl.pathname.includes('/download/') &&
          requestUrl.pathname.endsWith('/runtime-report.json')
        ) {
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
    if (!address || typeof address === 'string')
      throw new Error('Failed to bind local runtime test server')

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
      expect((command.data as any).runtime_contract).toEqual({
        type: 'inline',
        handler: 'executeDebugSession',
      })

      const executeRequest = requests.find((entry) => entry.url.endsWith('/execute'))
      expect(executeRequest?.body).toEqual(
        expect.objectContaining({
          sampleId: SAMPLE_ID,
          tool: 'debug.session.inspect',
          args: { inspect: 'registers' },
          runtime: { type: 'inline', handler: 'executeDebugSession' },
        })
      )
      expect(database.updateDebugSession).toHaveBeenCalled()
      expect(database.insertArtifact).toHaveBeenCalledWith(
        expect.objectContaining({
          sample_id: SAMPLE_ID,
          type: 'runtime_debug_artifact',
          mime: 'application/json',
        })
      )
      expect(command.artifacts).toHaveLength(1)
      expect(command.artifacts?.[0]).toEqual(
        expect.objectContaining({
          metadata: expect.objectContaining({
            runtime_schema: 'rikune.runtime_artifact.v1',
            artifact_family: 'runtime_debug',
            runtime_debug_session_id: sessionId,
            runtime_task_id: expect.any(String),
            runtime_tool: 'debug.session.inspect',
          }),
        })
      )
      const persistedPath = path.join(tmpDir, (command.artifacts?.[0] as any).path)
      expect(fs.existsSync(persistedPath)).toBe(true)

      const status = await createRuntimeDebugSessionStatusHandler(deps)({
        session_id: sessionId,
        sample_id: SAMPLE_ID,
      })
      expect(status.ok).toBe(true)
      expect((status.data as any).runtime).toEqual({ ok: true, runtime: 'test-runtime' })
      expect((status.data as any).persisted_sessions.length).toBeGreaterThanOrEqual(1)
      expect((status.data as any).persisted_sessions[0].lifecycle_state).toBe('captured')
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test('requires sample_id for sample-bound runtime commands', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(
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
    if (!runtimeAddress || typeof runtimeAddress === 'string')
      throw new Error('Failed to bind runtime server')
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
          res.end(
            JSON.stringify({
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
            })
          )
          return
        }
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'not found' }))
      })
    })
    await new Promise<void>((resolve) => hostAgentServer.listen(0, '127.0.0.1', resolve))
    const hostAgentAddress = hostAgentServer.address()
    if (!hostAgentAddress || typeof hostAgentAddress === 'string')
      throw new Error('Failed to bind host agent server')

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
      expect(hostAgentRequests[0].body).toEqual(
        expect.objectContaining({
          hypervSnapshotName: 'clean-base',
          hypervRestoreOnStart: true,
          hypervRestoreOnRelease: true,
          hypervStopOnRelease: true,
        })
      )
      const sessionId = (result.data as any).session.sessionId
      const persisted = database.findDebugSession(sessionId)
      expect(persisted).toBeDefined()
      const metadata = JSON.parse(persisted!.metadata_json)
      expect(metadata.hyperv_policy).toEqual(
        expect.objectContaining({
          vmName: 'rikune-runtime',
          snapshotName: 'clean-base',
          requestedPolicy: 'clean_rollback',
          restoreOnStart: true,
          restoreOnRelease: true,
          stopOnRelease: true,
        })
      )
    } finally {
      await new Promise<void>((resolve) => hostAgentServer.close(() => resolve()))
      await new Promise<void>((resolve) => runtimeServer.close(() => resolve()))
    }
  })

  test('fails before upload when Runtime Node does not advertise the required runtime contract', async () => {
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
        res.end(
          JSON.stringify({
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
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'unexpected url' }))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string')
      throw new Error('Failed to bind local runtime test server')

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
      expect((command.data as any).failure_category).toBe('unsupported_runtime_contract')
      expect(deps.resolvePrimarySamplePath).not.toHaveBeenCalled()
      expect(requests.some((entry) => entry.url === '/upload')).toBe(false)
      expect(requests.some((entry) => entry.url === '/execute')).toBe(false)
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })

  test('rejects a manual endpoint override before sending a configured runtime key', async () => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch')
    const result = await createRuntimeDebugSessionStartHandler({
      config: {
        runtime: {
          endpoint: 'http://runtime.internal:18081',
          apiKey: 'configured-runtime-secret',
        },
      },
      database: {},
    } as any)({ manual_endpoint: 'http://attacker.example:18081' })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/configured endpoint origin/)
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  test('rejects restored Hyper-V provenance before sending a configured runtime key', async () => {
    const row = createPersistedHyperVSessionRow(
      'persisted-hyperv-forged',
      'http://hyperv-runtime.internal:18081'
    )
    const fetchSpy = jest.spyOn(globalThis, 'fetch')
    const result = await createRuntimeDebugSessionStatusHandler({
      config: {
        runtime: {
          endpoint: 'http://configured-runtime.internal:18081',
          apiKey: 'configured-runtime-secret',
        },
      },
      database: { findDebugSession: jest.fn().mockReturnValue(row) },
    } as any)({ session_id: row.id })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/configured endpoint allowlist/)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('uses a configured runtime key for a restored endpoint on the configured origin', async () => {
    const row = createPersistedHyperVSessionRow(
      'persisted-hyperv-configured-origin',
      'http://runtime.internal:18081/restored'
    )
    const fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const body = String(input).endsWith('/capabilities')
        ? { ok: true, data: { runtime_backends: [] } }
        : { ok: true, role: 'runtime-node' }
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    const result = await createRuntimeDebugSessionStatusHandler({
      config: {
        runtime: {
          endpoint: 'http://runtime.internal:18081/configured',
          apiKey: 'configured-runtime-secret',
        },
      },
      database: { findDebugSession: jest.fn().mockReturnValue(row) },
    } as any)({ session_id: row.id })

    expect(result.ok).toBe(true)
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    for (const [, init] of fetchSpy.mock.calls) {
      expect((init as RequestInit).headers).toEqual({
        Authorization: 'Bearer configured-runtime-secret',
      })
    }
  })

  test('allows an explicit Host Agent endpoint when configured keys also exist', async () => {
    const fetchSpy = jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ok: true,
            endpoint: 'http://caller-host-agent.internal:18081',
            sandboxId: 'explicit-keys-session',
            backend: 'windows-sandbox',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ok: true, role: 'runtime' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )

    const result = await createRuntimeDebugSessionStartHandler({
      config: {
        runtime: {
          hostAgentEndpoint: 'http://configured-host-agent.internal:18082',
          hostAgentApiKey: 'configured-host-agent-secret',
          apiKey: 'configured-runtime-secret',
        },
      },
      database: createDebugSessionDatabaseMock(),
    } as any)({
      host_agent_endpoint: 'http://caller-host-agent.internal:18082',
      host_agent_api_key: 'explicit-host-agent-secret',
      runtime_api_key: 'explicit-runtime-secret',
    })

    expect(result.ok).toBe(true)
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    expect((fetchSpy.mock.calls[0][1] as RequestInit).headers).toEqual({
      'Content-Type': 'application/json',
      Authorization: 'Bearer explicit-host-agent-secret',
    })
    expect(JSON.parse(String((fetchSpy.mock.calls[0][1] as RequestInit).body))).toEqual(
      expect.objectContaining({ runtimeApiKey: 'explicit-runtime-secret' })
    )
    expect((fetchSpy.mock.calls[1][1] as RequestInit).headers).toEqual({
      Authorization: 'Bearer explicit-runtime-secret',
    })
  })

  test.each([
    [
      'configured Runtime Node key',
      {
        host_agent_api_key: 'explicit-host-agent-secret',
      },
    ],
    [
      'configured Host Agent key',
      {
        runtime_api_key: 'explicit-runtime-secret',
      },
    ],
  ])(
    'rejects an explicit Host Agent origin before sending a %s',
    async (_label, credentialOverride) => {
      const fetchSpy = jest.spyOn(globalThis, 'fetch')
      try {
        const result = await createRuntimeDebugSessionStartHandler({
          config: {
            runtime: {
              hostAgentEndpoint: 'http://configured-host-agent.internal:18082',
              hostAgentApiKey: 'configured-host-agent-secret',
              apiKey: 'configured-runtime-secret',
            },
          },
          database: {},
        } as any)({
          host_agent_endpoint: 'http://attacker.example:18082',
          ...credentialOverride,
        })

        expect(result.ok).toBe(false)
        expect(result.errors?.[0]).toMatch(/configured endpoint origin/)
        expect(fetchSpy).not.toHaveBeenCalled()
      } finally {
        fetchSpy.mockRestore()
      }
    }
  )

  test('rejects a Host Agent response that points the Runtime Node at another host', async () => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
          endpoint: 'http://attacker.example:18081',
          sandboxId: 'poisoned-session',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    )

    const result = await createRuntimeDebugSessionStartHandler({
      config: { runtime: { hostAgentEndpoint: 'http://host-agent.internal:18082' } },
      database: {},
    } as any)({})

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/trusted parent endpoint/)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    fetchSpy.mockRestore()
  })

  test('keeps live Hyper-V provenance in memory but not after persisted restoration', async () => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = new URL(String(input))
      let body: unknown
      let status = 200
      if (url.pathname === '/sandbox/start') {
        body = {
          ok: true,
          endpoint: 'http://hyperv-runtime.internal:18081',
          sandboxId: 'hyperv-session',
          backend: 'hyperv-vm',
        }
      } else if (url.pathname === '/capabilities') {
        body = { ok: true, data: { runtime_backends: [] } }
      } else if (url.pathname === '/execute' && init?.method === 'POST') {
        status = 202
        body = { ok: true, taskId: 'live-hyperv-task' }
      } else if (url.pathname.startsWith('/tasks/')) {
        body = { status: 'completed', result: { ok: true } }
      } else if (url.pathname === '/sandbox/stop') {
        body = { ok: true, stopped: true }
      } else if (url.pathname === '/health' || url.pathname === '/sandbox/health') {
        body = { ok: true, role: 'runtime' }
      } else {
        status = 404
        body = { ok: false, error: 'unexpected url' }
      }
      return new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      })
    })
    const database = createDebugSessionDatabaseMock()
    const deps = {
      config: {
        runtime: {
          hostAgentEndpoint: 'http://host-agent.internal:18082',
          apiKey: 'runtime-secret',
        },
      },
      database,
    } as any

    const start = await createRuntimeDebugSessionStartHandler(deps)({ sample_id: SAMPLE_ID })

    expect(start.ok).toBe(true)
    expect((start.data as any).session).toEqual(
      expect.objectContaining({
        endpoint: 'http://hyperv-runtime.internal:18081',
        backend: 'hyperv-vm',
      })
    )
    const sessionId = (start.data as any).session.sessionId

    const command = await createRuntimeDebugCommandHandler(deps)({
      session_id: sessionId,
      tool: 'runtime.noop',
    })
    expect(command.ok).toBe(true)

    const liveStatus = await createRuntimeDebugSessionStatusHandler(deps)({
      session_id: sessionId,
    })
    expect(liveStatus.ok).toBe(true)
    expect((liveStatus.data as any).runtime).toEqual({ ok: true, role: 'runtime' })

    const stop = await createRuntimeDebugSessionStopHandler(deps)({ session_id: sessionId })
    expect(stop.ok).toBe(true)
    const fetchCountAfterStop = fetchSpy.mock.calls.length

    const restoredStatus = await createRuntimeDebugSessionStatusHandler(deps)({
      session_id: sessionId,
    })
    expect(restoredStatus.ok).toBe(false)
    expect(restoredStatus.errors?.[0]).toMatch(/configured endpoint allowlist/)
    expect(fetchSpy).toHaveBeenCalledTimes(fetchCountAfterStop)
  })
})
