/**
 * Unit tests for runtime.hyperv.control.
 */

import { describe, test, expect } from '@jest/globals'
import http from 'http'
import {
  createRuntimeHyperVControlHandler,
  runtimeHyperVControlToolDefinition,
} from '../../src/plugins/dynamic/tools/runtime-hyperv-control.js'

describe('runtime.hyperv.control tool', () => {
  test('exports Hyper-V control tool definition', () => {
    expect(runtimeHyperVControlToolDefinition.name).toBe('runtime.hyperv.control')
  })

  test('routes status, checkpoint creation, and restore through Windows Host Agent', async () => {
    const requests: Array<{ method?: string; path: string; body?: any; auth?: string }> = []
    const server = http.createServer((req, res) => {
      const requestUrl = new URL(req.url || '/', 'http://127.0.0.1')
      const chunks: Buffer[] = []
      req.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      req.on('end', () => {
        const rawBody = Buffer.concat(chunks).toString('utf-8')
        const body = rawBody ? JSON.parse(rawBody) : undefined
        requests.push({
          method: req.method,
          path: requestUrl.pathname,
          body,
          auth: req.headers.authorization,
        })

        if (req.method === 'GET' && requestUrl.pathname === '/hyperv/status') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({
            ok: true,
            backend: 'hyperv-vm',
            hyperv: { configured: true, vmName: 'rikune-runtime', state: 'Running' },
          }))
          return
        }
        if (req.method === 'POST' && requestUrl.pathname === '/hyperv/restore') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({
            ok: true,
            backend: 'hyperv-vm',
            vmName: 'rikune-runtime',
            snapshotName: body?.snapshotName,
            runtimeReady: true,
          }))
          return
        }
        if (req.method === 'POST' && requestUrl.pathname === '/hyperv/checkpoints') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({
            ok: true,
            backend: 'hyperv-vm',
            vmName: 'rikune-runtime',
            snapshotName: body?.snapshotName,
            checkpoint: { name: body?.snapshotName },
          }))
          return
        }
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: 'not found' }))
      })
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('Failed to bind test server')

    const deps: any = {
      config: {
        runtime: {
          hostAgentEndpoint: `http://127.0.0.1:${address.port}`,
          hostAgentApiKey: 'host-secret',
          apiKey: 'runtime-secret',
        },
      },
    }

    try {
      const handler = createRuntimeHyperVControlHandler(deps)
      const status = await handler({ action: 'status' })
      const create = await handler({
        action: 'create_checkpoint',
        snapshot_name: 'post-analysis',
      })
      const restore = await handler({
        action: 'restore',
        snapshot_name: 'clean-base',
        start: true,
        wait_for_runtime: true,
        timeout_ms: 45_000,
      })

      expect(status.ok).toBe(true)
      expect((status.data as any).result.backend).toBe('hyperv-vm')
      expect(create.ok).toBe(true)
      expect((create.data as any).result.snapshotName).toBe('post-analysis')
      expect(restore.ok).toBe(true)
      expect((restore.data as any).result.snapshotName).toBe('clean-base')
      expect(requests.map((entry) => `${entry.method} ${entry.path}`)).toEqual([
        'GET /hyperv/status',
        'POST /hyperv/checkpoints',
        'POST /hyperv/restore',
      ])
      expect(requests[0].auth).toBe('Bearer host-secret')
      expect(requests[1].body).toEqual({ snapshotName: 'post-analysis' })
      expect(requests[2].body).toEqual(expect.objectContaining({
        snapshotName: 'clean-base',
        start: true,
        waitForRuntime: true,
        timeoutMs: 45_000,
        runtimeApiKey: 'runtime-secret',
      }))
      expect((restore.data as any).recommended_next_tools).toContain('dynamic.runtime.status')
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })

  test('returns setup guidance when Host Agent endpoint is missing', async () => {
    const result = await createRuntimeHyperVControlHandler({ config: { runtime: {} } } as any)({
      action: 'checkpoints',
    })

    expect(result.ok).toBe(false)
    expect((result.data as any).failure_category).toBe('host_agent_not_configured')
    expect(result.errors?.[0]).toContain('runtime.hostAgentEndpoint')
  })
})
