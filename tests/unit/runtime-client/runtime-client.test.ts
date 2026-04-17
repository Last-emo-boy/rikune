/**
 * Unit tests for runtime-client capability negotiation.
 */

import { afterEach, describe, expect, test } from '@jest/globals'
import { createServer, type IncomingMessage, type ServerResponse } from 'http'
import type { AddressInfo } from 'net'
import { createRuntimeClient } from '../../../src/runtime-client/runtime-client.js'
import { createLazyRemoteSandboxRuntimeClient } from '../../../src/runtime-client/lazy-remote-sandbox-client.js'
import { createRuntimeRecovery } from '../../../src/runtime-client/recovery.js'

const activeServers = new Set<ReturnType<typeof createServer>>()

async function startRuntimeServer(handler: (req: IncomingMessage, res: ServerResponse) => void) {
  const server = createServer(handler)
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve())
  })
  activeServers.add(server)
  return {
    server,
    endpoint: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
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
        }),
    ),
  )
  activeServers.clear()
})

describe('runtime-client capability negotiation', () => {
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

  test('lazy remote-sandbox client starts sandbox on first runtime capability request', async () => {
    let sandboxStarts = 0
    let capabilityRequests = 0

    const runtime = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        capabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
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
        }))
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

  test('execute short-circuits unsupported runtime backend hints using runtime capabilities', async () => {
    let capabilityRequests = 0
    let executeRequests = 0

    const { endpoint } = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        capabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
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
        }))
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
      runtimeBackendHint: { type: 'inline', handler: 'missing.handler' },
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(['Unsupported runtime backend hint: inline/missing.handler'])
    expect(result.capabilities).toEqual([
      expect.objectContaining({
        type: 'spawn',
        handler: 'native.sample.execute',
      }),
    ])
    expect(capabilityRequests).toBe(1)
    expect(executeRequests).toBe(0)
  })

  test('setEndpoint invalidates cached capabilities for subsequent validation', async () => {
    let firstCapabilityRequests = 0
    let secondCapabilityRequests = 0

    const first = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        firstCapabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
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
        }))
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const second = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        secondCapabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
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
        }))
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const client = createRuntimeClient({ endpoint: first.endpoint })

    const firstValidation = await client.validateRuntimeBackendHint({
      type: 'spawn',
      handler: 'native.sample.execute',
    })
    expect(firstValidation.supported).toBe(true)
    expect(firstCapabilityRequests).toBe(1)

    client.setEndpoint(second.endpoint)

    const secondValidation = await client.validateRuntimeBackendHint({
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
        res.end(JSON.stringify({
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
        }))
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    })

    const second = await startRuntimeServer((req, res) => {
      if (req.method === 'GET' && req.url === '/capabilities') {
        secondCapabilityRequests += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
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
        }))
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
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      expect(url).toBe('https://host-agent.invalid/sandbox/start')
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
            hostAgentEndpoint: 'https://host-agent.invalid',
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

      const validation = await client.validateRuntimeBackendHint({
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
