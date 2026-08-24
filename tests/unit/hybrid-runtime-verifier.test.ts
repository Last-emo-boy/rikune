import { describe, expect, jest, test } from '@jest/globals'
import {
  resolveHybridTimeoutContract,
  verifyHybridRuntimeLifecycle,
} from '../../scripts/verify-hybrid-runtime.mjs'

const HOST_KEY = 'host-key-'.repeat(4)
const RUNTIME_KEY = 'runtime-key-'.repeat(4)
const REQUEST_ID = '5b4b7f16-9b1b-4af4-92fb-541248102dc7'
const environment = {
  RUNTIME_HOST_AGENT_ENDPOINT: 'http://host.docker.internal:18082',
  RUNTIME_HOST_AGENT_API_KEY: HOST_KEY,
  RUNTIME_API_KEY: RUNTIME_KEY,
  RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP: 'false',
}

function response(payload: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  }
}

function hostHealth(
  sandboxes: Array<{ sandboxId: string; requestId: string }> = []
): Record<string, unknown> {
  return {
    ok: true,
    backend: 'windows-sandbox',
    sandboxStartRequestCorrelation: 'request-id-v2',
    sandboxStartContract: {
      timeoutScope: 'absolute-start-deadline',
      cleanupTimeoutMs: 30_000,
      statusPath: '/sandbox/start/status',
    },
    sandboxStopContract: {
      timeoutScope: 'absolute-stop-deadline',
    },
    sandboxes,
  }
}

function startStatus(state: 'pending' | 'active' | 'settled' | 'unknown', sandboxId?: string) {
  return {
    ok: true,
    requestId: REQUEST_ID,
    state,
    ...(sandboxId ? { sandboxId } : {}),
  }
}

describe('Hybrid runtime container lifecycle verifier', () => {
  test('keeps the start client deadline beyond the absolute server and cleanup budgets', () => {
    expect(
      resolveHybridTimeoutContract({
        requestTimeoutMs: 3_000,
        startServerTimeoutMs: 5_000,
        startClientBufferMs: 2_000,
      })
    ).toEqual({
      requestTimeoutMs: 3_000,
      startServerTimeoutMs: 5_000,
      startServerExecutionBudgetMs: 5_000,
      startCleanupTimeoutMs: 30_000,
      startClientBufferMs: 2_000,
      startClientDeadlineMs: 37_001,
      stopServerTimeoutMs: 120_000,
      stopClientBufferMs: 15_000,
      stopClientDeadlineMs: 135_001,
    })
  })

  test('authenticates health, starts a sandbox, verifies Runtime Node, and always stops', async () => {
    const timeoutDurations: number[] = []
    const fetchImpl = jest
      .fn()
      .mockResolvedValueOnce(response(hostHealth()))
      .mockResolvedValueOnce(
        response({
          ok: true,
          sandboxId: 'sandbox-123',
          requestId: REQUEST_ID,
          endpoint: 'http://host.docker.internal:18081',
          backend: 'windows-sandbox',
        })
      )
      .mockResolvedValueOnce(response({ ok: true }))
      .mockResolvedValueOnce(response({ ok: true }))
      .mockResolvedValueOnce(response(startStatus('settled')))

    await expect(
      verifyHybridRuntimeLifecycle({
        environment,
        fetchImpl,
        timeoutMs: 1_000,
        requestIdFactory: () => REQUEST_ID,
        createTimeoutSignal: (durationMs) => {
          timeoutDurations.push(durationMs)
          return new AbortController().signal
        },
      })
    ).resolves.toEqual({ ok: true })

    expect(fetchImpl).toHaveBeenCalledTimes(5)
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([
      'http://host.docker.internal:18082/sandbox/health',
      'http://host.docker.internal:18082/sandbox/start',
      'http://host.docker.internal:18081/health',
      'http://host.docker.internal:18082/sandbox/stop',
      `http://host.docker.internal:18082/sandbox/start/status?requestId=${REQUEST_ID}`,
    ])
    expect(fetchImpl.mock.calls[0][1].headers.Authorization).toBe(`Bearer ${HOST_KEY}`)
    expect(fetchImpl.mock.calls[2][1].headers.Authorization).toBe(`Bearer ${RUNTIME_KEY}`)
    expect(JSON.parse(fetchImpl.mock.calls[1][1].body)).toEqual({
      requestId: REQUEST_ID,
      runtimeApiKey: RUNTIME_KEY,
      timeoutMs: 1_000,
      hypervStopOnRelease: true,
    })
    expect(JSON.parse(fetchImpl.mock.calls[3][1].body)).toEqual({
      sandboxId: 'sandbox-123',
      requestId: REQUEST_ID,
      timeoutMs: 120_000,
    })
    expect(timeoutDurations).toEqual([1_000, 46_001, 1_000, 135_001, 1_000])
  })

  test('waits for an ambiguous stop and accepts only correlated absence as cleanup proof', async () => {
    let nowMs = 0
    let active = true
    const sleepImpl = jest.fn(async (durationMs: number) => {
      nowMs += durationMs
    })
    const fetchImpl = jest.fn(async (url: string) => {
      if (url.endsWith('/sandbox/health')) return response(hostHealth())
      if (url.endsWith('/sandbox/start')) {
        return response({
          ok: true,
          sandboxId: 'ambiguous-stop',
          requestId: REQUEST_ID,
          endpoint: 'http://host.docker.internal:18081',
          backend: 'windows-sandbox',
        })
      }
      if (url === 'http://host.docker.internal:18081/health') return response({ ok: true })
      if (url.endsWith('/sandbox/stop')) {
        active = false
        throw new Error('stop response was lost after cleanup')
      }
      if (url.includes('/sandbox/start/status?')) {
        return response(
          startStatus(active ? 'active' : 'settled', active ? 'ambiguous-stop' : undefined)
        )
      }
      throw new Error(`Unexpected request: ${url}`)
    })

    await expect(
      verifyHybridRuntimeLifecycle({
        environment,
        fetchImpl,
        timeoutMs: 1_000,
        stopServerTimeoutMs: 1_000,
        stopClientBufferMs: 10,
        requestIdFactory: () => REQUEST_ID,
        nowImpl: () => nowMs,
        sleepImpl,
      })
    ).resolves.toEqual({ ok: true })

    expect(sleepImpl).toHaveBeenCalledWith(1_011)
    expect(nowMs).toBe(1_011)
    expect(active).toBe(false)
  })

  test('waits out an ambiguous start and precisely removes the correlated late sandbox', async () => {
    let nowMs = 0
    let active = false
    let statusChecks = 0
    const timeoutDurations: number[] = []
    const sleepImpl = jest.fn(async (durationMs: number) => {
      nowMs += durationMs
    })
    const fetchImpl = jest.fn(async (url: string, init: { body?: string }) => {
      if (url.endsWith('/sandbox/start')) {
        const body = JSON.parse(init.body || '{}') as Record<string, unknown>
        expect(body).toEqual({
          requestId: REQUEST_ID,
          runtimeApiKey: RUNTIME_KEY,
          timeoutMs: 1_000,
          hypervStopOnRelease: true,
        })
        active = true
        throw new Error('start response was lost after activation')
      }
      if (url.endsWith('/sandbox/stop')) {
        expect(JSON.parse(init.body || '{}')).toEqual({
          sandboxId: 'late-sandbox',
          requestId: REQUEST_ID,
          timeoutMs: 1_000,
        })
        active = false
        return response({ ok: true })
      }
      if (url.includes('/sandbox/start/status?')) {
        statusChecks += 1
        if (statusChecks === 1) return response(startStatus('pending'))
        return response(
          startStatus(active ? 'active' : 'settled', active ? 'late-sandbox' : undefined)
        )
      }
      if (url.endsWith('/sandbox/health')) {
        return response(
          hostHealth(active ? [{ sandboxId: 'late-sandbox', requestId: REQUEST_ID }] : [])
        )
      }
      throw new Error(`Unexpected request: ${url}`)
    })

    await expect(
      verifyHybridRuntimeLifecycle({
        environment,
        fetchImpl,
        timeoutMs: 1_000,
        startServerTimeoutMs: 1_000,
        startClientBufferMs: 10,
        stopServerTimeoutMs: 1_000,
        stopClientBufferMs: 10,
        requestIdFactory: () => REQUEST_ID,
        nowImpl: () => nowMs,
        sleepImpl,
        createTimeoutSignal: (durationMs) => {
          timeoutDurations.push(durationMs)
          return new AbortController().signal
        },
      })
    ).rejects.toThrow('Sandbox start request failed')

    expect(sleepImpl).toHaveBeenNthCalledWith(1, 31_011)
    expect(sleepImpl).toHaveBeenNthCalledWith(2, 100)
    expect(nowMs).toBe(31_111)
    expect(active).toBe(false)
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([
      'http://host.docker.internal:18082/sandbox/health',
      'http://host.docker.internal:18082/sandbox/start',
      `http://host.docker.internal:18082/sandbox/start/status?requestId=${REQUEST_ID}`,
      `http://host.docker.internal:18082/sandbox/start/status?requestId=${REQUEST_ID}`,
      'http://host.docker.internal:18082/sandbox/stop',
      `http://host.docker.internal:18082/sandbox/start/status?requestId=${REQUEST_ID}`,
    ])
    expect(timeoutDurations).toEqual([1_000, 31_011, 1_000, 1_000, 1_011, 1_000])
  })

  test('accepts a delayed server timeout response only after Host Agent rollback is observable', async () => {
    let nowMs = 0
    const sleepImpl = jest.fn(async () => {})
    const fetchImpl = jest.fn(async (url: string, init: { body?: string }) => {
      if (url.endsWith('/sandbox/start')) {
        expect(JSON.parse(init.body || '{}').timeoutMs).toBe(1_000)
        nowMs = 31_000
        return response({ ok: false, error: 'server start timed out and rolled back' }, 500)
      }
      if (url.includes('/sandbox/start/status?')) {
        return response(startStatus('settled'))
      }
      if (url.endsWith('/sandbox/health')) {
        return response(hostHealth())
      }
      throw new Error(`Unexpected request: ${url}`)
    })

    await expect(
      verifyHybridRuntimeLifecycle({
        environment,
        fetchImpl,
        timeoutMs: 1_000,
        startServerTimeoutMs: 1_000,
        startClientBufferMs: 10,
        requestIdFactory: () => REQUEST_ID,
        nowImpl: () => nowMs,
        sleepImpl,
      })
    ).rejects.toThrow('Sandbox start returned HTTP 500')

    expect(nowMs).toBeLessThan(31_011)
    expect(sleepImpl).not.toHaveBeenCalled()
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([
      'http://host.docker.internal:18082/sandbox/health',
      'http://host.docker.internal:18082/sandbox/start',
      `http://host.docker.internal:18082/sandbox/start/status?requestId=${REQUEST_ID}`,
    ])
  })

  test('fails closed on a bad Host Agent key without starting a sandbox', async () => {
    const fetchImpl = jest.fn().mockResolvedValue(response({ ok: false }, 401))
    await expect(
      verifyHybridRuntimeLifecycle({ environment, fetchImpl, timeoutMs: 1_000 })
    ).rejects.toThrow('Host Agent health returned HTTP 401')
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  test('stops the sandbox when Runtime Node authentication or reachability fails', async () => {
    const fetchImpl = jest
      .fn()
      .mockResolvedValueOnce(response(hostHealth()))
      .mockResolvedValueOnce(
        response({
          ok: true,
          sandboxId: 'sandbox-cleanup',
          requestId: REQUEST_ID,
          endpoint: 'http://host.docker.internal:18081',
          backend: 'windows-sandbox',
        })
      )
      .mockResolvedValueOnce(response({ ok: false }, 401))
      .mockResolvedValueOnce(response({ ok: true }))
      .mockResolvedValueOnce(response(startStatus('settled')))

    await expect(
      verifyHybridRuntimeLifecycle({
        environment,
        fetchImpl,
        timeoutMs: 1_000,
        requestIdFactory: () => REQUEST_ID,
      })
    ).rejects.toThrow('Runtime Node health returned HTTP 401')
    expect(fetchImpl).toHaveBeenCalledTimes(5)
    expect(fetchImpl.mock.calls[3][0]).toContain('/sandbox/stop')
  })

  test('treats cleanup failure as a failed lifecycle gate', async () => {
    let stopAttempts = 0
    const fetchImpl = jest.fn(async (url: string) => {
      if (url.endsWith('/sandbox/health')) return response(hostHealth())
      if (url.endsWith('/sandbox/start')) {
        return response({
          ok: true,
          sandboxId: 'sandbox-cleanup-failure',
          requestId: REQUEST_ID,
          endpoint: 'http://host.docker.internal:18081',
          backend: 'windows-sandbox',
        })
      }
      if (url === 'http://host.docker.internal:18081/health') return response({ ok: true })
      if (url.endsWith('/sandbox/stop')) {
        stopAttempts += 1
        return response({ ok: false }, 500)
      }
      if (url.includes('/sandbox/start/status?')) {
        return response(startStatus('active', 'sandbox-cleanup-failure'))
      }
      throw new Error(`Unexpected request: ${url}`)
    })

    await expect(
      verifyHybridRuntimeLifecycle({
        environment,
        fetchImpl,
        timeoutMs: 1_000,
        requestIdFactory: () => REQUEST_ID,
        sleepImpl: async () => {},
      })
    ).rejects.toThrow('Correlated sandbox remained active after stop reconciliation')
    expect(stopAttempts).toBe(2)
  })

  test('rejects reused principals and unsafe returned runtime endpoints before requests', async () => {
    const unusedFetch = jest.fn()
    await expect(
      verifyHybridRuntimeLifecycle({
        environment: { ...environment, RUNTIME_API_KEY: HOST_KEY },
        fetchImpl: unusedFetch,
      })
    ).rejects.toThrow('must be distinct')
    expect(unusedFetch).not.toHaveBeenCalled()

    const fetchImpl = jest
      .fn()
      .mockResolvedValueOnce(response(hostHealth()))
      .mockResolvedValueOnce(
        response({
          ok: true,
          sandboxId: 'sandbox-unsafe-endpoint',
          requestId: REQUEST_ID,
          endpoint: 'http://attacker.invalid:18081',
          backend: 'windows-sandbox',
        })
      )
      .mockResolvedValueOnce(response({ ok: true }))
      .mockResolvedValueOnce(response(startStatus('settled')))
    await expect(
      verifyHybridRuntimeLifecycle({
        environment,
        fetchImpl,
        timeoutMs: 1_000,
        requestIdFactory: () => REQUEST_ID,
      })
    ).rejects.toThrow('plaintext HTTP requires explicit isolated-network opt-in')
    expect(fetchImpl.mock.calls[2][0]).toContain('/sandbox/stop')
  })

  test('does not include credentials in transport failures', async () => {
    const fetchImpl = jest.fn().mockRejectedValue(new Error(`transport leaked ${HOST_KEY}`))
    let message = ''
    try {
      await verifyHybridRuntimeLifecycle({ environment, fetchImpl, timeoutMs: 1_000 })
    } catch (error) {
      message = String(error)
    }
    expect(message).toContain('Host Agent health request failed')
    expect(message).not.toContain(HOST_KEY)
    expect(message).not.toContain(RUNTIME_KEY)
  })
})
