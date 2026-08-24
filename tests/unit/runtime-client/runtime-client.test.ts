/**
 * Unit tests for runtime-client capability negotiation.
 */

import { afterEach, describe, expect, jest, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { createServer, type IncomingMessage, type ServerResponse } from 'http'
import type { AddressInfo } from 'net'
import { createRuntimeClient } from '../../../src/runtime-client/runtime-client.js'
import { createLazyRemoteSandboxRuntimeClient } from '../../../src/runtime-client/lazy-remote-sandbox-client.js'
import { createRuntimeRecovery } from '../../../src/runtime-client/recovery.js'

const activeServers = new Set<ReturnType<typeof createServer>>()

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

async function startRuntimeServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
  host = '127.0.0.1'
) {
  const server = createServer(handler)
  await new Promise<void>((resolve, reject) => {
    const handleError = (error: Error) => reject(error)
    server.once('error', handleError)
    server.listen(0, host, () => {
      server.off('error', handleError)
      resolve()
    })
  })
  activeServers.add(server)
  const endpointHost = host.includes(':') ? `[${host}]` : host
  return {
    server,
    endpoint: `http://${endpointHost}:${(server.address() as AddressInfo).port}`,
  }
}

afterEach(async () => {
  await Promise.all(
    Array.from(activeServers).map(
      (server) =>
        new Promise<void>((resolve) => {
          if (!server.listening) {
            resolve()
            return
          }
          server.close(() => resolve())
        })
    )
  )
  activeServers.clear()
})

describe('runtime-client capability negotiation', () => {
  test('rejects unsafe endpoints and prevents keyed clients from moving to an unrelated origin', () => {
    for (const endpoint of [
      'file:///tmp/runtime.sock',
      'http://user:password@runtime.internal:18081',
      'http://169.254.169.254/latest/meta-data',
      'http://0.0.0.0:18081',
      'http://[::]:18081',
    ]) {
      expect(() => createRuntimeClient({ endpoint })).toThrow()
    }

    expect(() => createRuntimeClient({ endpoint: 'http://127.0.0.1:18081' })).not.toThrow()
    expect(() => createRuntimeClient({ endpoint: 'http://192.168.50.20:18081' })).not.toThrow()

    const client = createRuntimeClient({
      endpoint: 'http://runtime.internal:18081',
      apiKey: 'runtime-secret',
    })
    expect(() => client.setEndpoint('http://runtime.internal:18082')).toThrow()
    expect(() =>
      client.setEndpoint('http://runtime.internal:18082', {
        trustedParentEndpoint: 'http://runtime.internal:18081',
      })
    ).not.toThrow()
    expect(() => client.setEndpoint('http://attacker.invalid:18082')).toThrow()
    expect(() => client.setEndpoint('https://runtime.internal:18082')).toThrow()
    expect(() => client.setEndpoint('http://169.254.169.254:18082')).toThrow()
    expect(client.getEndpoint()).toBe('http://runtime.internal:18082')

    expect(() =>
      client.setEndpoint('https://192.168.137.11:18081', {
        trustedLocalSandboxLaunch: true,
      })
    ).toThrow('must use http')
    expect(() =>
      client.setEndpoint('http://192.168.137.11:18081', {
        trustedLocalSandboxLaunch: true,
      })
    ).not.toThrow()
    expect(client.getEndpoint()).toBe('http://192.168.137.11:18081')
  })

  test('connects to an IPv6 loopback endpoint without passing URL brackets to Node', async () => {
    let healthRequests = 0
    let endpoint: string
    try {
      ;({ endpoint } = await startRuntimeServer((req, res) => {
        if (req.method === 'GET' && req.url === '/health') {
          healthRequests += 1
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(
            JSON.stringify({
              ok: true,
              role: 'runtime-node',
              isolation: 'test',
              mode: 'test',
              pid: process.pid,
            })
          )
          return
        }
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false }))
      }, '::1'))
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code === 'EADDRNOTAVAIL' || code === 'EAFNOSUPPORT') {
        return
      }
      throw error
    }

    const client = createRuntimeClient({ endpoint })

    await expect(client.health()).resolves.toEqual(
      expect.objectContaining({ ok: true, role: 'runtime-node' })
    )
    expect(healthRequests).toBe(1)
  })

  test('uses the injected trusted resolver while preserving the HTTP Host hostname', async () => {
    let receivedHost: string | undefined
    const server = await startRuntimeServer((req, res) => {
      receivedHost = req.headers.host
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            role: 'runtime-node',
            isolation: 'test',
            mode: 'test',
            pid: process.pid,
          })
        )
        return
      }
      res.writeHead(404)
      res.end()
    })
    const serverPort = new URL(server.endpoint).port
    const resolver = jest.fn(async () => [{ address: '127.0.0.1', family: 4 }])
    const client = createRuntimeClient({
      endpoint: `http://runtime.test:${serverPort}`,
      resolveEndpointAddresses: resolver,
    })

    await expect(client.health()).resolves.toEqual(
      expect.objectContaining({ ok: true, role: 'runtime-node' })
    )
    expect(receivedHost).toBe(`runtime.test:${serverPort}`)
    expect(resolver).toHaveBeenCalledWith('runtime.test', { all: true, verbatim: true })
  })

  test('closes keep-alive sockets when the runtime client is disposed', async () => {
    const sockets = new Set<import('net').Socket>()
    const server = await startRuntimeServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(
        JSON.stringify({
          ok: true,
          role: 'runtime-node',
          isolation: 'test',
          mode: 'test',
          pid: process.pid,
        })
      )
    })
    server.server.on('connection', (socket) => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
    })
    const client = createRuntimeClient({ endpoint: server.endpoint })

    await expect(client.health()).resolves.toEqual(expect.objectContaining({ ok: true }))
    expect(sockets.size).toBe(1)
    const socket = Array.from(sockets)[0]
    const socketClosed = new Promise<void>((resolve) => socket.once('close', () => resolve()))

    await client.close()
    await socketClosed
    expect(sockets.size).toBe(0)
    await expect(client.close()).resolves.toBeUndefined()
  })

  test('fails before the server when the injected resolver returns a metadata address', async () => {
    let receivedRequests = 0
    const server = await startRuntimeServer((_req, res) => {
      receivedRequests += 1
      res.writeHead(200)
      res.end()
    })
    const serverPort = new URL(server.endpoint).port
    const resolver = jest.fn(async () => [{ address: '169.254.169.254', family: 4 }])
    const client = createRuntimeClient({
      endpoint: `http://runtime.test:${serverPort}`,
      resolveEndpointAddresses: resolver,
    })

    await expect(client.health()).resolves.toBeNull()
    expect(receivedRequests).toBe(0)
    expect(resolver).toHaveBeenCalledTimes(1)
  })

  test('lazy remote-sandbox client does not start sandbox for passive health/status calls', async () => {
    let sandboxStarts = 0
    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'POST' && req.url === '/sandbox/start') {
        sandboxStarts += 1
      }
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'should not be called' }))
    })

    const client = createLazyRemoteSandboxRuntimeClient({
      runtime: {
        mode: 'remote-sandbox',
        hostAgentEndpoint: endpoint,
        hostAgentApiKey: 'host-key',
        healthCheckTimeoutMs: 1_000,
        apiKey: 'runtime-key',
      },
    } as any)

    await expect(client.health()).resolves.toBeNull()
    expect(client.getEndpoint()).toBe('')
    expect(sandboxStarts).toBe(0)
  })

  test('lazy client preserves Hyper-V Host Agent provenance before and after attachment', () => {
    const client = createLazyRemoteSandboxRuntimeClient({
      runtime: {
        mode: 'remote-sandbox',
        hostAgentEndpoint: 'http://host-agent.internal:18082',
        hostAgentApiKey: 'host-key',
        apiKey: 'runtime-key',
      },
    } as any)
    const provenance = {
      trustedParentEndpoint: 'http://host-agent.internal:18082',
      trustedHostAgentBackend: 'hyperv-vm',
    }

    expect(() => client.setEndpoint('http://hyperv-one.internal:18081', provenance)).not.toThrow()
    expect(() => client.setEndpoint('http://hyperv-two.internal:18081', provenance)).not.toThrow()
    expect(client.getEndpoint()).toBe('http://hyperv-two.internal:18081')
  })

  test('lazy remote-sandbox client starts sandbox on first runtime capability request', async () => {
    let sandboxStarts = 0
    let capabilityRequests = 0

    const runtime = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        capabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'inline',
                  handler: 'executeSandboxExecute',
                  description: 'Sandbox execute backend.',
                  requiresSample: true,
                },
              ],
            },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const hostAgent = await startRuntimeServer((req, res) => {
      if (req.method === 'POST' && req.url === '/sandbox/start') {
        sandboxStarts += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, endpoint: runtime.endpoint, sandboxId: 'sandbox-1' }))
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const client = createLazyRemoteSandboxRuntimeClient({
      runtime: {
        mode: 'remote-sandbox',
        hostAgentEndpoint: hostAgent.endpoint,
        hostAgentApiKey: 'host-key',
        healthCheckTimeoutMs: 1_000,
        apiKey: 'runtime-key',
      },
    } as any)

    const capabilities = await client.getCapabilities()
    expect(capabilities?.[0]?.handler).toBe('executeSandboxExecute')
    expect(client.getEndpoint()).toBe(runtime.endpoint)
    expect(sandboxStarts).toBe(1)
    expect(capabilityRequests).toBe(1)

    await client.getCapabilities()
    expect(sandboxStarts).toBe(1)
    expect(capabilityRequests).toBe(1)
  })

  test.each([
    ['malformed object', [{ type: 'unknown', handler: 42 }]],
    ['null entry', [null]],
    [
      'mixed valid and malformed entries',
      [
        {
          type: 'inline',
          handler: 'executeSandboxExecute',
          description: 'Sandbox execute backend.',
          requiresSample: true,
        },
        { type: 'spawn', handler: '' },
      ],
    ],
  ])('fails closed for %s and refetches capabilities', async (_label, malformedEntries) => {
    let capabilityRequests = 0
    const validCapability = {
      type: 'inline',
      handler: 'executeSandboxExecute',
      description: 'Sandbox execute backend.',
      requiresSample: true,
    }
    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        capabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: capabilityRequests === 1 ? malformedEntries : [validCapability],
            },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false }))
    })

    const client = createRuntimeClient({ endpoint })

    await expect(client.getCapabilities()).resolves.toBeNull()
    expect(capabilityRequests).toBe(1)
    await expect(client.getCapabilities()).resolves.toEqual([validCapability])
    expect(capabilityRequests).toBe(2)
    await expect(client.getCapabilities()).resolves.toEqual([validCapability])
    expect(capabilityRequests).toBe(2)
  })

  test('accepts and caches a genuinely empty capability array', async () => {
    let capabilityRequests = 0
    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        capabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, data: { runtime_backends: [] } }))
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false }))
    })

    const client = createRuntimeClient({ endpoint })

    await expect(client.getCapabilities()).resolves.toEqual([])
    await expect(client.getCapabilities()).resolves.toEqual([])
    expect(capabilityRequests).toBe(1)
  })

  test('does not accept capabilities from an HTTP 200 error envelope', async () => {
    let capabilityRequests = 0
    const validCapability = {
      type: 'spawn',
      handler: 'native.sample.execute',
      description: 'Native sample execution.',
      requiresSample: true,
    }
    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        capabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: capabilityRequests > 1,
            data: { runtime_backends: [validCapability] },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false }))
    })

    const client = createRuntimeClient({ endpoint })

    await expect(client.getCapabilities()).resolves.toBeNull()
    await expect(client.getCapabilities()).resolves.toEqual([validCapability])
    expect(capabilityRequests).toBe(2)
  })

  test('lazy remote-sandbox rejects a runtime endpoint outside the Host Agent origin binding', async () => {
    const originalFetch = global.fetch
    let fetchCalls = 0
    global.fetch = async (input: string | URL | Request, init?: RequestInit) => {
      fetchCalls += 1
      const url =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      expect(url).toBe('http://host-agent.internal:18082/sandbox/start')
      expect(init).toEqual(expect.objectContaining({ method: 'POST', redirect: 'error' }))
      return {
        ok: true,
        status: 200,
        json: async () => ({
          ok: true,
          endpoint: 'http://attacker.invalid:18081',
          sandboxId: 'sandbox-malicious',
        }),
      } as any
    }

    try {
      const client = createLazyRemoteSandboxRuntimeClient({
        runtime: {
          mode: 'remote-sandbox',
          hostAgentEndpoint: 'http://host-agent.internal:18082',
          hostAgentApiKey: 'host-key',
          healthCheckTimeoutMs: 1_000,
          apiKey: 'runtime-secret',
        },
      } as any)

      await expect(client.getCapabilities()).rejects.toThrow(/untrusted runtime endpoint/i)
      expect(client.getEndpoint()).toBe('')
      expect(fetchCalls).toBe(1)
    } finally {
      global.fetch = originalFetch
    }
  })

  test('lazy remote-sandbox accepts a direct Hyper-V VM endpoint from the Host Agent', async () => {
    const runtime = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'inline',
                  handler: 'executeDebugSession',
                  description: 'Hyper-V debug runtime.',
                  requiresSample: true,
                },
              ],
            },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false }))
    }, '127.0.0.2')

    const hostAgent = await startRuntimeServer((req, res) => {
      if (req.method === 'POST' && req.url === '/sandbox/start') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            endpoint: runtime.endpoint,
            sandboxId: 'hyperv-session',
            backend: 'hyperv-vm',
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false }))
    })

    const client = createLazyRemoteSandboxRuntimeClient({
      runtime: {
        mode: 'remote-sandbox',
        hostAgentEndpoint: hostAgent.endpoint,
        hostAgentApiKey: 'host-key',
        healthCheckTimeoutMs: 1_000,
        apiKey: 'runtime-key',
      },
    } as any)

    await expect(client.getCapabilities()).resolves.toEqual([
      expect.objectContaining({ handler: 'executeDebugSession' }),
    ])
    expect(client.getEndpoint()).toBe(runtime.endpoint)
  })

  test('execute short-circuits Unsupported runtime contracts using runtime capabilities', async () => {
    let capabilityRequests = 0
    let executeRequests = 0

    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        capabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'spawn',
                  handler: 'native.sample.execute',
                  description: 'Execute uploaded samples directly.',
                  requiresSample: true,
                },
              ],
            },
          })
        )
        return
      }

      if (req.method === 'POST' && req.url === '/execute') {
        executeRequests += 1
        res.writeHead(202, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, taskId: 'should-not-run', status: 'queued' }))
        return
      }

      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const client = createRuntimeClient({ endpoint })
    const result = await client.execute({
      taskId: 'task-1',
      sampleId: 'sample-1',
      tool: 'dynamic.inline.test',
      args: {},
      timeoutMs: 1_000,
      runtime: { type: 'inline', handler: 'missing.handler' },
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(['Unsupported runtime contract: inline/missing.handler'])
    expect(result.capabilities).toEqual([
      expect.objectContaining({
        type: 'spawn',
        handler: 'native.sample.execute',
      }),
    ])
    expect(capabilityRequests).toBe(1)
    expect(executeRequests).toBe(0)
  })

  test('rejects malformed capabilities from execute error responses and refetches', async () => {
    let capabilityRequests = 0
    const validCapability = {
      type: 'inline',
      handler: 'executeSandboxExecute',
      description: 'Sandbox execute backend.',
      requiresSample: true,
    }
    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        capabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, data: { runtime_backends: [validCapability] } }))
        return
      }
      if (req.method === 'POST' && req.url === '/execute') {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: false,
            error: 'Runtime rejected the task',
            capabilities: [validCapability, null],
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false }))
    })

    const client = createRuntimeClient({ endpoint })
    const result = await client.execute({
      taskId: 'task-1',
      sampleId: 'sample-1',
      tool: 'dynamic.inline.test',
      args: {},
      timeoutMs: 1_000,
      runtime: { type: 'inline', handler: 'executeSandboxExecute' },
    })

    expect(result.ok).toBe(false)
    expect(result.capabilities).toBeUndefined()
    expect(capabilityRequests).toBe(1)
    await expect(client.getCapabilities()).resolves.toEqual([validCapability])
    expect(capabilityRequests).toBe(2)
  })

  test('validates runtime contract dimensions beyond type and handler', async () => {
    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'python-worker',
                  handler: 'frida_worker.py',
                  description: 'Frida worker bridge.',
                  requiresSample: true,
                  modes: ['safe_simulation'],
                  requiredTools: ['python'],
                  isolation: { required: true, backends: ['docker'] },
                  policy: {
                    requiresIsolation: true,
                    allowedBackends: ['docker'],
                    networkPolicy: 'disabled',
                    maxRuntimeMs: 1000,
                  },
                },
              ],
            },
          })
        )
        return
      }

      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const client = createRuntimeClient({ endpoint })
    const missingDimensions = await client.validateRuntimeContract({
      type: 'python-worker',
      handler: 'frida_worker.py',
      modes: ['live_sandbox'],
      requiredTools: ['frida'],
      isolation: { required: true, backends: ['windows-sandbox'] },
      policy: {
        requiresIsolation: true,
        allowedBackends: ['windows-sandbox'],
        networkPolicy: 'record_only',
      },
    })

    expect(missingDimensions.supported).toBe(false)
    expect(missingDimensions.capability).toBeUndefined()
    expect(missingDimensions.capabilities?.[0]).toEqual(
      expect.objectContaining({
        type: 'python-worker',
        handler: 'frida_worker.py',
        modes: ['safe_simulation'],
        requiredTools: ['python'],
        isolation: { required: true, backends: ['docker'] },
        policy: expect.objectContaining({
          requiresIsolation: true,
          allowedBackends: ['docker'],
          networkPolicy: 'disabled',
        }),
      })
    )

    const supported = await client.validateRuntimeContract({
      type: 'python-worker',
      handler: 'frida_worker.py',
      modes: ['safe_simulation'],
      requiredTools: ['python'],
      isolation: { required: true, backends: ['docker'] },
      policy: {
        requiresIsolation: true,
        allowedBackends: ['docker'],
        networkPolicy: 'disabled',
        maxRuntimeMs: 500,
      },
    })

    expect(supported.supported).toBe(true)
    expect(supported.capability).toEqual(
      expect.objectContaining({
        type: 'python-worker',
        handler: 'frida_worker.py',
      })
    )
  })

  test('setEndpoint invalidates cached capabilities for subsequent validation', async () => {
    let firstCapabilityRequests = 0
    let secondCapabilityRequests = 0

    const first = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        firstCapabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'spawn',
                  handler: 'native.sample.execute',
                  description: 'Execute uploaded samples directly.',
                  requiresSample: true,
                },
              ],
            },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const second = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        secondCapabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'inline',
                  handler: 'executeSandboxExecute',
                  description: 'Run sandbox execution inline.',
                  requiresSample: true,
                },
              ],
            },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const client = createRuntimeClient({ endpoint: first.endpoint })

    const firstValidation = await client.validateRuntimeContract({
      type: 'spawn',
      handler: 'native.sample.execute',
    })
    expect(firstValidation.supported).toBe(true)
    expect(firstCapabilityRequests).toBe(1)

    client.setEndpoint(second.endpoint)

    const secondValidation = await client.validateRuntimeContract({
      type: 'spawn',
      handler: 'native.sample.execute',
    })
    expect(secondValidation.supported).toBe(false)
    expect(secondValidation.capabilities).toEqual([
      expect.objectContaining({
        type: 'inline',
        handler: 'executeSandboxExecute',
      }),
    ])
    expect(secondCapabilityRequests).toBe(1)
  })

  test('recovery force-refreshes capabilities after endpoint replacement', async () => {
    let firstCapabilityRequests = 0
    let secondCapabilityRequests = 0

    const first = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        firstCapabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'spawn',
                  handler: 'native.sample.execute',
                  description: 'Execute uploaded samples directly.',
                  requiresSample: true,
                },
              ],
            },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const second = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        secondCapabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                {
                  type: 'inline',
                  handler: 'executeDebugSession',
                  description: 'Start debug sessions inline.',
                  requiresSample: true,
                },
              ],
            },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const client = createRuntimeClient({ endpoint: first.endpoint })
    await client.getCapabilities()
    expect(firstCapabilityRequests).toBe(1)

    const originalFetch = global.fetch
    global.fetch = async (input: string | URL | Request) => {
      const url =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      expect(url).toBe('http://127.0.0.1:18082/sandbox/start')
      return {
        ok: true,
        json: async () => ({ ok: true, endpoint: second.endpoint, sandboxId: 'sandbox-2' }),
      } as any
    }

    try {
      const recovery = createRuntimeRecovery({
        config: {
          runtime: {
            mode: 'remote-sandbox',
            hostAgentEndpoint: 'http://127.0.0.1:18082',
            hostAgentApiKey: undefined,
            healthCheckTimeoutMs: 1_000,
            apiKey: undefined,
          },
        } as any,
        runtimeClient: client,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      const recovered = await recovery.recover({ forceRefreshCapabilities: true })
      expect(recovered).toBe(true)
      expect(client.getEndpoint()).toBe(second.endpoint)
      expect(secondCapabilityRequests).toBe(1)

      const validation = await client.validateRuntimeContract({
        type: 'inline',
        handler: 'executeDebugSession',
      })
      expect(validation.supported).toBe(true)
      expect(secondCapabilityRequests).toBe(1)
    } finally {
      global.fetch = originalFetch
    }
  })
})

describe('runtime-client artifact downloads', () => {
  const unsafePathSegments = [
    '',
    '.',
    '..',
    'nested/artifact.bin',
    'nested\\artifact.bin',
    '/tmp/artifact.bin',
    'C:\\Temp\\artifact.bin',
    'artifact\0.bin',
  ]

  test('rejects unsafe local artifact paths before probing the outbox', async () => {
    const client = createRuntimeClient({ endpoint: 'http://127.0.0.1:18081' })
    const existsSpy = jest.spyOn(fs, 'existsSync')

    try {
      for (const name of unsafePathSegments) {
        await expect(
          client.downloadArtifacts('task-1', '/tmp/runtime-outbox', [name])
        ).rejects.toThrow(/artifact name/i)
      }
      await expect(
        client.downloadArtifacts('task-1', '/tmp/runtime-outbox', [
          'valid-artifact.bin',
          '../escape.bin',
        ])
      ).rejects.toThrow(/artifact name/i)
      await expect(
        client.downloadArtifacts('../escape-task', '/tmp/runtime-outbox', ['valid-artifact.bin'])
      ).rejects.toThrow(/task ID/i)
      expect(existsSpy).not.toHaveBeenCalled()
    } finally {
      existsSpy.mockRestore()
    }
  })

  test('rejects a local task outbox that is a directory link', async () => {
    const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rikune-outbox-link-'))
    const outboxDir = path.join(tempRoot, 'outbox')
    const externalTaskDir = path.join(tempRoot, 'external-task')
    await fs.promises.mkdir(outboxDir)
    await fs.promises.mkdir(externalTaskDir)
    await fs.promises.writeFile(path.join(externalTaskDir, 'artifact.bin'), 'outside')
    await fs.promises.symlink(
      externalTaskDir,
      path.join(outboxDir, 'task-1'),
      process.platform === 'win32' ? 'junction' : 'dir'
    )

    try {
      const client = createRuntimeClient({ endpoint: 'http://127.0.0.1:18081' })
      await expect(client.downloadArtifacts('task-1', outboxDir, ['artifact.bin'])).rejects.toThrow(
        /real directory|symbolic link/i
      )
    } finally {
      await fs.promises.rm(tempRoot, { recursive: true, force: true })
    }
  })

  const fileSymlinkTest = process.platform === 'win32' ? test.skip : test
  fileSymlinkTest('rejects a local artifact file link', async () => {
    const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rikune-artifact-link-'))
    const outboxDir = path.join(tempRoot, 'outbox')
    const taskDir = path.join(outboxDir, 'task-1')
    const externalArtifact = path.join(tempRoot, 'outside.bin')
    await fs.promises.mkdir(taskDir, { recursive: true })
    await fs.promises.writeFile(externalArtifact, 'outside')
    await fs.promises.symlink(externalArtifact, path.join(taskDir, 'artifact.bin'))

    try {
      const client = createRuntimeClient({ endpoint: 'http://127.0.0.1:18081' })
      await expect(client.downloadArtifacts('task-1', outboxDir, ['artifact.bin'])).rejects.toThrow(
        /real file|symbolic link/i
      )
    } finally {
      await fs.promises.rm(tempRoot, { recursive: true, force: true })
    }
  })

  test('rejects unsafe remote artifact paths before temp creation, request, or file write', async () => {
    let downloadRequests = 0
    const { endpoint } = await startRuntimeServer((_req, res) => {
      downloadRequests += 1
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false }))
    }, '127.0.0.2')
    const client = createRuntimeClient({ endpoint })
    const mkdtempSpy = jest.spyOn(fs.promises, 'mkdtemp')
    const writeSpy = jest.spyOn(fs, 'createWriteStream')

    try {
      for (const name of unsafePathSegments) {
        await expect(
          client.downloadArtifacts('task-1', '/unused/runtime-outbox', [name])
        ).rejects.toThrow(/artifact name/i)
      }
      await expect(
        client.downloadArtifacts('task-1', '/unused/runtime-outbox', [
          'valid-artifact.bin',
          '../escape.bin',
        ])
      ).rejects.toThrow(/artifact name/i)
      await expect(
        client.downloadArtifacts('../escape-task', '/unused/runtime-outbox', ['valid-artifact.bin'])
      ).rejects.toThrow(/task ID/i)
      expect(mkdtempSpy).not.toHaveBeenCalled()
      expect(writeSpy).not.toHaveBeenCalled()
      expect(downloadRequests).toBe(0)
    } finally {
      mkdtempSpy.mockRestore()
      writeSpy.mockRestore()
    }
  })

  test('aborting an accepted execute request tears down HTTP and confirms remote cancellation', async () => {
    const executeAccepted = deferred<void>()
    const cancelObserved = deferred<void>()
    let cancelRequests = 0
    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'POST' && req.url === '/execute') {
        executeAccepted.resolve()
        // Model the race where the runtime accepted the task but its 202 response
        // never reached the analyzer.
        return
      }
      if (req.method === 'POST' && req.url === '/tasks/task-abort/cancel') {
        cancelRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, taskId: 'task-abort', wasRunning: true }))
        cancelObserved.resolve()
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false }))
    }, '127.0.0.2')
    const client = createRuntimeClient({ endpoint })
    const controller = new AbortController()

    const executing = client.execute(
      {
        taskId: 'task-abort',
        sampleId: 'sample-abort',
        tool: 'sandbox.execute',
        args: {},
        timeoutMs: 120_000,
      },
      { signal: controller.signal }
    )
    await executeAccepted.promise
    controller.abort(new Error('cancel requested'))

    await expect(executing).rejects.toMatchObject({ name: 'AbortError' })
    await cancelObserved.promise
    expect(cancelRequests).toBe(1)
  })

  test.each(['invalid_json', 'connection_reset'] as const)(
    'cancels the remote task before surfacing a poll %s failure',
    async (failureMode) => {
      const events: string[] = []
      const { endpoint } = await startRuntimeServer((req, res) => {
        if (req.method === 'POST' && req.url === '/execute') {
          events.push('execute')
          res.writeHead(202, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true, taskId: 'task-poll-error', status: 'queued' }))
          return
        }
        if (req.method === 'GET' && req.url === '/tasks/task-poll-error') {
          events.push('poll')
          if (failureMode === 'invalid_json') {
            res.writeHead(200, { 'Content-Type': 'application/json' })
            res.end('{')
          } else {
            res.destroy(new Error('forced connection reset'))
          }
          return
        }
        if (req.method === 'POST' && req.url === '/tasks/task-poll-error/cancel') {
          events.push('cancel')
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true, taskId: 'task-poll-error', wasRunning: true }))
          return
        }
        res.writeHead(404)
        res.end()
      }, '127.0.0.2')
      const client = createRuntimeClient({ endpoint })

      try {
        await expect(
          client.execute({
            taskId: 'task-poll-error',
            sampleId: 'sample-poll-error',
            tool: 'sandbox.execute',
            args: {},
            timeoutMs: 120_000,
          })
        ).rejects.toBeDefined()
        expect(events).toEqual(['execute', 'poll', 'cancel'])
      } finally {
        await client.close()
      }
    }
  )

  test('aborting a hanging upload destroys the upload request and file stream', async () => {
    const uploadObserved = deferred<void>()
    const runtimeServer = await startRuntimeServer((req, _res) => {
      if (req.method === 'POST' && req.url?.startsWith('/upload?')) {
        uploadObserved.resolve()
        req.resume()
      }
    }, '127.0.0.2')
    const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rikune-upload-abort-'))
    const samplePath = path.join(tempRoot, 'sample.bin')
    await fs.promises.writeFile(samplePath, Buffer.alloc(256 * 1024, 0x41))
    const client = createRuntimeClient({ endpoint: runtimeServer.endpoint })
    const controller = new AbortController()
    const readSpy = jest.spyOn(fs, 'createReadStream')

    try {
      const uploading = client.uploadSample('task-upload', samplePath, '/unused', {
        signal: controller.signal,
      })
      await uploadObserved.promise
      controller.abort(new Error('cancel upload'))

      await expect(uploading).rejects.toMatchObject({ name: 'AbortError' })
      expect(readSpy.mock.results[0]?.value?.destroyed).toBe(true)
    } finally {
      readSpy.mockRestore()
      await client.close()
      runtimeServer.server.closeAllConnections?.()
      await fs.promises.rm(tempRoot, { recursive: true, force: true })
    }
  })

  test('aborting a hanging download destroys the response and removes the partial file', async () => {
    const downloadObserved = deferred<void>()
    const requestClosed = deferred<void>()
    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/download/task-download/report.bin') {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' })
        res.write(Buffer.alloc(32 * 1024, 0x42))
        downloadObserved.resolve()
        req.once('close', () => requestClosed.resolve())
        return
      }
      res.writeHead(404)
      res.end()
    }, '127.0.0.2')
    const client = createRuntimeClient({ endpoint })
    const controller = new AbortController()
    const writeSpy = jest.spyOn(fs, 'createWriteStream')

    try {
      const downloading = client.downloadArtifacts('task-download', '/unused', ['report.bin'], {
        signal: controller.signal,
      })
      await downloadObserved.promise
      controller.abort(new Error('cancel download'))

      await expect(downloading).rejects.toMatchObject({ name: 'AbortError' })
      await requestClosed.promise
      const partialPath = writeSpy.mock.results[0]?.value?.path
      expect(typeof partialPath).toBe('string')
      expect(fs.existsSync(partialPath as string)).toBe(false)
    } finally {
      writeSpy.mockRestore()
      await client.close()
    }
  })
})
