/**
 * Unit tests for Runtime Node authentication defaults.
 */

import { afterEach, describe, expect, test } from '@jest/globals'
import { createServer, request } from 'http'
import type { AddressInfo } from 'net'
import { createRuntimeRouter } from '../../../packages/runtime-node/src/router.js'
import { config as runtimeConfig } from '../../../packages/runtime-node/src/config.js'

const originalHost = runtimeConfig.server.host
const originalApiKey = runtimeConfig.runtime.apiKey
const originalNodeEnv = process.env.NODE_ENV
const activeServers = new Set<ReturnType<typeof createServer>>()

const runtimeSupport = {
  listRuntimeBackendCapabilities() {
    return []
  },
  isRuntimeContractSupported() {
    return false
  },
}

async function startRuntimeServer() {
  const router = createRuntimeRouter({
    loadRuntimeBackendSupport: async () => runtimeSupport,
  })
  const server = createServer((req, res) => {
    void router.handle(req, res)
  })

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve())
  })

  activeServers.add(server)
  return {
    server,
    port: (server.address() as AddressInfo).port,
  }
}

async function getCapabilities(port: number): Promise<{ statusCode?: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port,
        path: '/capabilities',
        method: 'GET',
      },
      (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          body += chunk
        })
        res.on('end', () => resolve({ statusCode: res.statusCode, body }))
        res.on('error', reject)
      }
    )

    req.on('error', reject)
    req.end()
  })
}

afterEach(async () => {
  runtimeConfig.server.host = originalHost
  runtimeConfig.runtime.apiKey = originalApiKey
  if (originalNodeEnv === undefined) {
    delete process.env.NODE_ENV
  } else {
    process.env.NODE_ENV = originalNodeEnv
  }

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

describe('runtime-node router auth defaults', () => {
  test('allows unauthenticated local loopback development', async () => {
    runtimeConfig.server.host = '127.0.0.1'
    runtimeConfig.runtime.apiKey = undefined
    process.env.NODE_ENV = 'test'
    const { port } = await startRuntimeServer()

    const response = await getCapabilities(port)

    expect(response.statusCode).toBe(200)
    expect(response.body).toContain('"runtime_backends":[]')
  })

  test('rejects unauthenticated non-loopback runtime binding', async () => {
    runtimeConfig.server.host = '0.0.0.0'
    runtimeConfig.runtime.apiKey = undefined
    process.env.NODE_ENV = 'test'
    const { port } = await startRuntimeServer()

    const response = await getCapabilities(port)

    expect(response.statusCode).toBe(503)
    expect(response.body).toContain('runtime_api_key_required')
    expect(response.body).toContain('RUNTIME_API_KEY is required when RUNTIME_HOST/--host binds')
  })

  test('rejects unauthenticated production runtime even on loopback', async () => {
    runtimeConfig.server.host = '127.0.0.1'
    runtimeConfig.runtime.apiKey = undefined
    process.env.NODE_ENV = 'production'
    const { port } = await startRuntimeServer()

    const response = await getCapabilities(port)

    expect(response.statusCode).toBe(503)
    expect(response.body).toContain('runtime_api_key_required')
    expect(response.body).toContain('RUNTIME_API_KEY is required when NODE_ENV=production')
  })
})
