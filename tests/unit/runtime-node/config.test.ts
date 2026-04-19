/**
 * Unit tests for runtime-node configuration loading.
 */

import { afterEach, describe, expect, test } from '@jest/globals'

const runtimeEnvKeys = [
  'RUNTIME_PORT',
  'RUNTIME_HOST',
  'RUNTIME_MODE',
  'RUNTIME_INBOX',
  'RUNTIME_OUTBOX',
  'RUNTIME_API_KEY',
  'RUNTIME_READY_FILE',
  'RUNTIME_CORS_ORIGIN',
  'RUNTIME_PYTHON_PATH',
  'RUNTIME_MAX_RSS_BYTES',
  'RUNTIME_MIN_DISK_SPACE_BYTES',
  'LOG_LEVEL',
] as const

function resetRuntimeEnv(): void {
  for (const key of runtimeEnvKeys) {
    delete process.env[key]
  }
}

afterEach(() => {
  resetRuntimeEnv()
})

describe('runtime-node configuration loading', () => {
  test('loads configuration from CLI flags', async () => {
    const { loadConfig } = await import('../../../packages/runtime-node/src/config.js')

    const config = loadConfig({
      argv: [
        '--host', '127.0.0.1',
        '--port', '19081',
        '--mode', 'manual',
        '--inbox', 'C:\\cli-inbox',
        '--outbox', 'C:\\cli-outbox',
        '--api-key', 'cli-secret',
        '--ready-file', 'C:\\cli-outbox\\runtime.ready.json',
        '--cors-origin', 'http://analyzer.local',
        '--python-path', 'C:\\Python311\\python.exe',
        '--max-rss-bytes', '123456',
        '--min-disk-space-bytes', '654321',
        '--log-level', 'debug',
      ],
      env: {},
    })

    expect(config.server.host).toBe('127.0.0.1')
    expect(config.server.port).toBe(19081)
    expect(config.runtime.mode).toBe('manual')
    expect(config.runtime.inbox).toBe('C:\\cli-inbox')
    expect(config.runtime.outbox).toBe('C:\\cli-outbox')
    expect(config.runtime.apiKey).toBe('cli-secret')
    expect(config.runtime.readyFile).toBe('C:\\cli-outbox\\runtime.ready.json')
    expect(config.runtime.corsOrigin).toBe('http://analyzer.local')
    expect(config.runtime.pythonPath).toBe('C:\\Python311\\python.exe')
    expect(config.runtime.maxRssBytes).toBe(123456)
    expect(config.runtime.minDiskSpaceBytes).toBe(654321)
    expect(config.logging.level).toBe('debug')
  })

  test('CLI flags override environment variables', async () => {
    const { loadConfig } = await import('../../../packages/runtime-node/src/config.js')

    const config = loadConfig({
      argv: [
        '--host', '127.0.0.1',
        '--port', '19081',
        '--ready-file', 'C:\\cli\\runtime.ready.json',
      ],
      env: {
        RUNTIME_HOST: '0.0.0.0',
        RUNTIME_PORT: '18081',
        RUNTIME_READY_FILE: 'C:\\env\\runtime.ready.json',
      },
    })

    expect(config.server.host).toBe('127.0.0.1')
    expect(config.server.port).toBe(19081)
    expect(config.runtime.readyFile).toBe('C:\\cli\\runtime.ready.json')
  })

  test('env-only configuration remains supported', async () => {
    const { loadConfig } = await import('../../../packages/runtime-node/src/config.js')

    const config = loadConfig({
      argv: [],
      env: {
        RUNTIME_HOST: '10.0.0.5',
        RUNTIME_PORT: '18091',
        RUNTIME_MODE: 'manual',
        RUNTIME_API_KEY: 'env-secret',
        RUNTIME_READY_FILE: 'C:\\env\\runtime.ready.json',
      },
    })

    expect(config.server.host).toBe('10.0.0.5')
    expect(config.server.port).toBe(18091)
    expect(config.runtime.mode).toBe('manual')
    expect(config.runtime.apiKey).toBe('env-secret')
    expect(config.runtime.readyFile).toBe('C:\\env\\runtime.ready.json')
  })

  test('accepts inline CLI assignment syntax used by sandbox launchers', async () => {
    const { loadConfig } = await import('../../../packages/runtime-node/src/config.js')

    const config = loadConfig({
      argv: [
        '--host=127.0.0.1',
        '--port=19081',
        '--ready-file=C:\\sandbox\\runtime.ready.json',
      ],
      env: {},
    })

    expect(config.server.host).toBe('127.0.0.1')
    expect(config.server.port).toBe(19081)
    expect(config.runtime.readyFile).toBe('C:\\sandbox\\runtime.ready.json')
  })

  test('throws on malformed numeric CLI values', async () => {
    const { loadConfig } = await import('../../../packages/runtime-node/src/config.js')

    expect(() => {
      loadConfig({
        argv: ['--port', 'not-a-number'],
        env: {},
      })
    }).toThrow(/Invalid numeric value for --port/)
  })
})


