/**
 * Unit tests for runtime-node router capabilities and execute contract
 */

import { afterEach, describe, expect, test } from '@jest/globals'
import { createServer, request } from 'http'
import type { AddressInfo } from 'net'
import fs from 'fs'
import path from 'path'
import type { RuntimeBackendCapability, RuntimeBackendHint } from '../../../packages/runtime-node/src/executor.js'
import { createRuntimeRouter } from '../../../packages/runtime-node/src/router.js'

process.env.RUNTIME_API_KEY = 'runtime-test-key'
process.env.RUNTIME_INBOX = 'C:\\rikune-test-inbox-router'
process.env.RUNTIME_OUTBOX = 'C:\\rikune-test-outbox-router'

const runtimeCapabilities: RuntimeBackendCapability[] = [
  {
    type: 'spawn',
    handler: 'native.sample.execute',
    description: 'Execute uploaded samples directly.',
    requiresSample: true,
  },
  {
    type: 'spawn',
    handler: 'dotnet.sample.run',
    description: 'Execute uploaded samples through dotnet.',
    requiresSample: true,
  },
  {
    type: 'inline',
    handler: 'executeSandboxExecute',
    description: 'Run sandbox execution inline.',
    requiresSample: true,
  },
]

const runtimeSupport = {
  listRuntimeBackendCapabilities(): RuntimeBackendCapability[] {
    return runtimeCapabilities
  },
  isRuntimeBackendHintSupported(hint: RuntimeBackendHint): boolean {
    return runtimeCapabilities.some((capability) => capability.type === hint.type && capability.handler === hint.handler)
  },
  getRuntimeBackendCapability(hint: RuntimeBackendHint): RuntimeBackendCapability | undefined {
    return runtimeCapabilities.find((capability) => capability.type === hint.type && capability.handler === hint.handler)
  },
  buildRuntimeToolInventory() {
    return {
      schema: 'rikune.runtime_tool_inventory.v1' as const,
      generatedAt: new Date().toISOString(),
      runtime: {
        platform: process.platform,
        mode: 'sandbox',
        toolSearchRoots: ['C:\\rikune-tools'],
        pathEntries: [],
      },
      tools: [
        {
          id: 'cdb',
          displayName: 'CDB / Windows Debugger',
          category: 'debugger' as const,
          role: 'Automated breakpoints.',
          available: true,
          path: 'C:\\rikune-tools\\debuggers\\x64\\cdb.exe',
          source: 'C:\\rikune-tools',
          installHint: 'Install Windows Debugging Tools.',
          profiles: ['debugger_cdb'],
        },
      ],
      profiles: [
        {
          id: 'debugger_cdb',
          status: 'ready' as const,
          requiredTools: ['cdb'],
          optionalTools: [],
          availableTools: ['cdb'],
          missingTools: [],
          recommendedTools: ['runtime.debug.command'],
        },
      ],
      summary: {
        availableToolCount: 1,
        missingToolCount: 0,
        readyProfiles: ['debugger_cdb'],
        partialProfiles: [],
        missingProfiles: [],
      },
    }
  },
}

const activeServers = new Set<ReturnType<typeof createServer>>()

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
  fs.rmSync(process.env.RUNTIME_INBOX!, { recursive: true, force: true })
  fs.rmSync(process.env.RUNTIME_OUTBOX!, { recursive: true, force: true })
})

function postUpload(port: number, taskId: string, filename: string, role: 'primary' | 'sidecar', body: string) {
  return new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port,
        path: `/upload?taskId=${encodeURIComponent(taskId)}&filename=${encodeURIComponent(filename)}&role=${role}`,
        method: 'POST',
        headers: {
          Authorization: 'Bearer runtime-test-key',
          'Content-Type': 'application/octet-stream',
          'Content-Length': Buffer.byteLength(body).toString(),
        },
      },
      (res) => {
        let responseBody = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          responseBody += chunk
        })
        res.on('end', () => resolve({ statusCode: res.statusCode, body: responseBody }))
        res.on('error', reject)
      },
    )

    req.on('error', reject)
    req.write(body)
    req.end()
  })
}

describe('runtime-node router capability and execute contract', () => {
  test('exposes runtime backend capabilities', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/capabilities',
          method: 'GET',
          headers: { Authorization: 'Bearer runtime-test-key' },
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => resolve({ statusCode: res.statusCode, body }))
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.end()
    })

    expect(response.statusCode).toBe(200)
    expect(response.body).toContain('native.sample.execute')
    expect(response.body).toContain('dotnet.sample.run')
    expect(response.body).toContain('executeSandboxExecute')
  })

  test('exposes runtime toolkit inventory without submitting an execution task', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/toolkit',
          method: 'GET',
          headers: { Authorization: 'Bearer runtime-test-key' },
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => resolve({ statusCode: res.statusCode, body }))
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.end()
    })

    expect(response.statusCode).toBe(200)
    expect(response.body).toContain('rikune.runtime_tool_inventory.v1')
    expect(response.body).toContain('debugger_cdb')
    expect(response.body).toContain('cdb')
  })

  test('stages primary uploads and sidecars into a per-task manifest', async () => {
    const { port } = await startRuntimeServer()

    const primary = await postUpload(port, 'sidecar-task', 'app.exe', 'primary', 'MZ')
    const sidecar = await postUpload(port, 'sidecar-task', 'zg__kYYzqVe.dll', 'sidecar', 'DLL')

    expect(primary.statusCode).toBe(200)
    expect(sidecar.statusCode).toBe(200)
    const primaryBody = JSON.parse(primary.body)
    const taskDir = path.dirname(primaryBody.inboxPath)
    expect(fs.existsSync(path.join(taskDir, 'app.exe'))).toBe(true)
    expect(fs.existsSync(path.join(taskDir, 'zg__kYYzqVe.dll'))).toBe(true)
    expect(fs.existsSync(primaryBody.legacyPath)).toBe(true)
    const manifest = JSON.parse(fs.readFileSync(path.join(taskDir, 'upload-manifest.json'), 'utf8'))
    expect(manifest.primary).toBe('app.exe')
    expect(manifest.files).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'app.exe', role: 'primary' }),
      expect.objectContaining({ name: 'zg__kYYzqVe.dll', role: 'sidecar' }),
    ]))
  })

  test('returns normalized runtime backend details for accepted execute requests', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/execute',
          method: 'POST',
          headers: {
            Authorization: 'Bearer runtime-test-key',
            'Content-Type': 'application/json',
          },
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => resolve({ statusCode: res.statusCode, body }))
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.write(JSON.stringify({
        taskId: 'accepted-task',
        sampleId: 'sample-1',
        tool: 'dynamic.spawn.native',
        args: {},
        timeoutMs: 1000,
        runtimeBackendHint: { type: 'spawn', handler: 'native.sample.execute' },
      }))
      req.end()
    })

    expect(response.statusCode).toBe(202)
    expect(response.body).toContain('"runtimeBackend":{"type":"spawn","handler":"native.sample.execute"')
    expect(response.body).toContain('"requiresSample":true')
  })

  test('rejects invalid execute payloads with schema errors', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/execute',
          method: 'POST',
          headers: {
            Authorization: 'Bearer runtime-test-key',
            'Content-Type': 'application/json',
          },
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => resolve({ statusCode: res.statusCode, body }))
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.write(JSON.stringify({
        taskId: 'bad id',
        sampleId: '',
        tool: '',
        args: [],
        timeoutMs: 0,
        runtimeBackendHint: { type: 'spawn', handler: 'missing.handler' },
      }))
      req.end()
    })

    expect(response.statusCode).toBe(400)
    expect(response.body).toContain('schema_validation_failed')
    expect(response.body).toContain('Execute payload validation failed')
    expect(response.body).toContain('taskId must contain only letters, numbers, underscores, or dashes')
    expect(response.body).toContain('Expected object, received array')
    expect(response.body).toContain('Number must be greater than or equal to 1')
  })

  test('rejects malformed JSON bodies with invalid_json contract', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/execute',
          method: 'POST',
          headers: {
            Authorization: 'Bearer runtime-test-key',
            'Content-Type': 'application/json',
          },
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => resolve({ statusCode: res.statusCode, body }))
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.write('{"taskId":')
      req.end()
    })

    expect(response.statusCode).toBe(400)
    expect(response.body).toContain('invalid_json')
    expect(response.body).toContain('Request body must be valid JSON')
  })

  test('rejects malformed runtime backend hints during schema validation', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/execute',
          method: 'POST',
          headers: {
            Authorization: 'Bearer runtime-test-key',
            'Content-Type': 'application/json',
          },
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => resolve({ statusCode: res.statusCode, body }))
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.write(JSON.stringify({
        taskId: 'valid-task',
        sampleId: 'sample-1',
        tool: 'dynamic.spawn.native',
        args: {},
        timeoutMs: 1000,
        runtimeBackendHint: { type: 'ssh', handler: '' },
      }))
      req.end()
    })

    expect(response.statusCode).toBe(400)
    expect(response.body).toContain('schema_validation_failed')
    expect(response.body).toContain('Invalid enum value')
    expect(response.body).toContain('String must contain at least 1 character')
  })

  test('rejects unsupported runtime backend hints', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/execute',
          method: 'POST',
          headers: {
            Authorization: 'Bearer runtime-test-key',
            'Content-Type': 'application/json',
          },
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => resolve({ statusCode: res.statusCode, body }))
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.write(JSON.stringify({
        taskId: 'valid-task',
        sampleId: 'sample-1',
        tool: 'spawn.sample.exec',
        args: {},
        timeoutMs: 1000,
        runtimeBackendHint: { type: 'spawn', handler: 'missing.handler' },
      }))
      req.end()
    })

    expect(response.statusCode).toBe(400)
    expect(response.body).toContain('unsupported_runtime_backend_hint')
    expect(response.body).toContain('Unsupported runtime backend hint')
    expect(response.body).toContain('native.sample.execute')
  })

  test('falls back to null runtime backend details when no backend hint is provided', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/execute',
          method: 'POST',
          headers: {
            Authorization: 'Bearer runtime-test-key',
            'Content-Type': 'application/json',
          },
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => resolve({ statusCode: res.statusCode, body }))
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.write(JSON.stringify({
        taskId: 'accepted-task-no-hint',
        sampleId: 'sample-1',
        tool: 'frida.runtime.instrument',
        args: {},
        timeoutMs: 1000,
      }))
      req.end()
    })

    expect(response.statusCode).toBe(202)
    expect(response.body).toContain('"runtimeBackend":null')
  })
})
