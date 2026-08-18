/**
 * Unit tests for runtime-client/sandbox-launcher.ts
 */

import { afterEach, describe, expect, jest, test } from '@jest/globals'

const mockConfig = {
  runtime: {
    apiKey: undefined as string | undefined,
    sandboxWorkspace: '/tmp/rikune-sandbox-test',
    healthCheckTimeoutMs: 1_000,
  },
}

const mockLogger = {
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
  error: jest.fn(),
}

jest.unstable_mockModule('../../../src/config.js', () => ({
  config: mockConfig,
}))

jest.unstable_mockModule('../../../src/logger.js', () => ({
  logger: mockLogger,
}))

const {
  createSandboxLauncher,
  parseAutoSandboxReadyEndpoint,
  probeAutoSandboxRuntimeHealth,
  validateAutoSandboxRuntimeEndpoint,
} = await import('../../../src/runtime-client/sandbox-launcher.js')

const originalFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = originalFetch
  jest.clearAllMocks()
})

describe('createSandboxLauncher', () => {
  test('does not launch auto-sandbox runtime without a runtime API key', async () => {
    mockConfig.runtime.apiKey = undefined
    const launcher = createSandboxLauncher()

    await expect(launcher.launch()).resolves.toBeNull()
    expect(mockLogger.warn).toHaveBeenCalledWith(
      expect.stringContaining('Auto-sandbox runtime requires runtime.apiKey')
    )
  })

  test.each([
    'file:///tmp/runtime.sock',
    'http://operator:secret@127.0.0.1:18081',
    'http://169.254.169.254:18081',
    'http://0.0.0.0:18081',
    'http://[::]:18081',
  ])('rejects an untrusted ready-file endpoint: %s', (endpoint) => {
    expect(() => validateAutoSandboxRuntimeEndpoint(endpoint)).toThrow()
  })

  test('accepts and canonicalizes a private auto-sandbox endpoint', () => {
    expect(validateAutoSandboxRuntimeEndpoint('http://192.168.137.42:18081/runtime')).toBe(
      'http://192.168.137.42:18081'
    )
  })

  test('does not treat an incomplete ready file as a localhost runtime', () => {
    expect(parseAutoSandboxReadyEndpoint({})).toBeNull()
    expect(parseAutoSandboxReadyEndpoint({ endpoint: '' })).toBeNull()
    expect(parseAutoSandboxReadyEndpoint({ endpoint: 'http://192.168.137.42:18081/runtime' })).toBe(
      'http://192.168.137.42:18081'
    )
  })

  test('authenticates the health probe and disables redirects', async () => {
    const fetchMock = jest.fn(
      async () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
    )
    globalThis.fetch = fetchMock as typeof fetch

    await probeAutoSandboxRuntimeHealth('http://192.168.137.42:18081', 'runtime-secret')

    expect(fetchMock).toHaveBeenCalledWith(
      'http://192.168.137.42:18081/health',
      expect.objectContaining({
        headers: { Authorization: 'Bearer runtime-secret' },
        redirect: 'error',
      })
    )
  })

  test('cancels an unhealthy response body before closing the trusted fetch client', async () => {
    const response = new Response('unhealthy', { status: 503 })
    const cancelSpy = jest.spyOn(response.body!, 'cancel')
    globalThis.fetch = jest.fn(async () => response) as typeof fetch

    await expect(
      probeAutoSandboxRuntimeHealth('http://192.168.137.42:18081', 'runtime-secret')
    ).rejects.toThrow('HTTP 503')

    expect(cancelSpy).toHaveBeenCalledTimes(1)
  })

  test('rejects an unsafe health endpoint before fetch', async () => {
    const fetchMock = jest.fn()
    globalThis.fetch = fetchMock as typeof fetch

    await expect(
      probeAutoSandboxRuntimeHealth('http://169.254.169.254:18081', 'runtime-secret')
    ).rejects.toThrow()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('rejects a health probe without an API key before fetch', async () => {
    const fetchMock = jest.fn()
    globalThis.fetch = fetchMock as typeof fetch

    await expect(
      probeAutoSandboxRuntimeHealth('http://192.168.137.42:18081', undefined)
    ).rejects.toThrow('require a runtime API key')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
