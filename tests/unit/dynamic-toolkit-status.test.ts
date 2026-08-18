/**
 * Unit tests for dynamic.toolkit.status.
 */

import { afterEach, describe, expect, jest, test } from '@jest/globals'
import http from 'http'
import {
  createDynamicToolkitStatusHandler,
  dynamicToolkitStatusToolDefinition,
} from '../../src/plugins/dynamic/tools/dynamic-toolkit-status.js'

const SAMPLE_ID = `sha256:${'e'.repeat(64)}`

describe('dynamic.toolkit.status tool', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  test('exports a read-only toolkit status definition without delegated runtime execution', () => {
    expect(dynamicToolkitStatusToolDefinition.name).toBe('dynamic.toolkit.status')
    expect(dynamicToolkitStatusToolDefinition.runtime).toBeUndefined()
  })

  test('aggregates runtime toolkit inventory from a configured Runtime Node endpoint', async () => {
    const runtimeServer = http.createServer((req, res) => {
      const requestUrl = new URL(req.url || '/', 'http://127.0.0.1')
      if (req.method === 'GET' && requestUrl.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, role: 'runtime' }))
        return
      }
      if (req.method === 'GET' && requestUrl.pathname === '/capabilities') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                { type: 'inline', handler: 'executeRuntimeToolProbe', requiresSample: false },
              ],
            },
          })
        )
        return
      }
      if (req.method === 'GET' && requestUrl.pathname === '/toolkit') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              schema: 'rikune.runtime_tool_inventory.v1',
              tools: [
                { id: 'cdb', available: true },
                { id: 'procmon', available: false },
              ],
              profiles: [
                { id: 'debugger_cdb', status: 'ready' },
                { id: 'procmon_capture', status: 'missing' },
              ],
            },
          })
        )
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

    try {
      const result = await createDynamicToolkitStatusHandler({
        config: { runtime: { endpoint: runtimeEndpoint } },
        database: {},
      } as any)({ sample_id: SAMPLE_ID })

      expect(result.ok).toBe(true)
      expect((result.data as any).status).toBe('ready')
      expect((result.data as any).toolkit_summary.available_tools).toContain('cdb')
      expect((result.data as any).toolkit_summary.ready_profiles).toContain('debugger_cdb')
      expect((result.data as any).recommended_next_tools).toContain('dynamic.deep_plan')
    } finally {
      await new Promise<void>((resolve) => runtimeServer.close(() => resolve()))
    }
  })

  test('returns setup guidance without launching a runtime when no endpoint exists', async () => {
    const result = await createDynamicToolkitStatusHandler({
      config: { runtime: {} },
      database: {},
    } as any)({})

    expect(result.ok).toBe(false)
    expect((result.data as any).status).toBe('not_configured')
    expect((result.data as any).recommended_next_tools).toContain('runtime.debug.session.start')
    expect(result.warnings?.[0]).toMatch(/No Runtime Node endpoint/)
  })

  test('does not send a configured runtime key to a caller-selected origin', async () => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch')
    const result = await createDynamicToolkitStatusHandler({
      config: {
        runtime: {
          endpoint: 'http://runtime.internal:18081',
          apiKey: 'configured-runtime-secret',
        },
      },
      database: {},
    } as any)({ runtime_endpoint: 'http://attacker.example:18081' })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/configured endpoint origin/)
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  test('rejects persisted Hyper-V provenance before sending a configured runtime key', async () => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch')
    const row = {
      id: 'hyperv-session',
      backend: 'hyperv-vm',
      metadata_json: JSON.stringify({
        endpoint: 'http://hyperv-runtime.internal:18081',
        endpoint_parent: 'http://host-agent.internal:18082',
      }),
    }

    const result = await createDynamicToolkitStatusHandler({
      config: { runtime: { apiKey: 'runtime-secret' } },
      database: { findDebugSession: jest.fn().mockReturnValue(row) },
    } as any)({ session_id: row.id })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/configured endpoint allowlist/)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('rejects a keyless persisted endpoint before making a request', async () => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch')
    const row = {
      id: 'keyless-persisted-session',
      backend: 'hyperv-vm',
      metadata_json: JSON.stringify({
        endpoint: 'http://forged-runtime.internal:18081',
        endpoint_parent: 'http://host-agent.internal:18082',
      }),
    }

    const result = await createDynamicToolkitStatusHandler({
      config: { runtime: {} },
      database: { findDebugSession: jest.fn().mockReturnValue(row) },
    } as any)({ session_id: row.id })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/configured endpoint allowlist/)
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
