/**
 * Unit tests for runtime mode × node role configuration matrix
 */

import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'

const runtimeEnvKeys = [
  'NODE_ROLE',
  'RUNTIME_MODE',
  'RUNTIME_ENDPOINT',
  'RUNTIME_API_KEY',
  'RUNTIME_HOST_AGENT_ENDPOINT',
  'RUNTIME_HOST_AGENT_API_KEY',
  'CONFIG_PATH',
] as const

let tempConfigDir: string

function writeConfig(config: Record<string, unknown>): string {
  const configPath = path.join(tempConfigDir, 'config.json')
  fs.writeFileSync(configPath, JSON.stringify(config))
  return configPath
}

async function importFreshConfigModule() {
  jest.resetModules()
  return import('../../src/config/index.ts')
}

async function expectConfigImportToFail(pattern: RegExp): Promise<void> {
  await expect(importFreshConfigModule()).rejects.toThrow(pattern)
}

function resetRuntimeEnv(): void {
  for (const key of runtimeEnvKeys) {
    delete process.env[key]
  }
}

beforeEach(() => {
  resetRuntimeEnv()
  tempConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-runtime-config-'))
  process.env.CONFIG_PATH = path.join(tempConfigDir, 'missing.json')
})

afterEach(() => {
  resetRuntimeEnv()
  fs.rmSync(tempConfigDir, { recursive: true, force: true })
})

describe('runtime mode × node role config matrix', () => {
  test('requires runtime.endpoint for analyzer manual mode', async () => {
    process.env.NODE_ROLE = 'analyzer'
    process.env.RUNTIME_MODE = 'manual'

    await expectConfigImportToFail(/runtime\.endpoint is required.*manual/)
  })

  test('requires runtime.endpoint for hybrid manual mode', async () => {
    process.env.NODE_ROLE = 'hybrid'
    process.env.RUNTIME_MODE = 'manual'

    await expectConfigImportToFail(/runtime\.endpoint is required.*manual/)
  })

  test('accepts runtime manual mode for runtime role without remote endpoint', async () => {
    process.env.NODE_ROLE = 'runtime'
    process.env.RUNTIME_MODE = 'manual'

    const { loadConfig } = await importFreshConfigModule()
    const config = loadConfig('__missing_config__.json')

    expect(config.node.role).toBe('runtime')
    expect(config.runtime.mode).toBe('manual')
    expect(config.runtime.endpoint).toBeUndefined()
  })

  test('requires host agent endpoint for analyzer remote-sandbox mode', async () => {
    process.env.NODE_ROLE = 'analyzer'
    process.env.RUNTIME_MODE = 'remote-sandbox'
    process.env.RUNTIME_HOST_AGENT_API_KEY = 'host-agent-secret'

    await expectConfigImportToFail(/runtime\.hostAgentEndpoint is required.*remote-sandbox/)
  })

  test('requires host agent endpoint for hybrid remote-sandbox mode', async () => {
    process.env.NODE_ROLE = 'hybrid'
    process.env.RUNTIME_MODE = 'remote-sandbox'
    process.env.RUNTIME_HOST_AGENT_API_KEY = 'host-agent-secret'

    await expectConfigImportToFail(/runtime\.hostAgentEndpoint is required.*remote-sandbox/)
  })

  test('requires host agent API key for analyzer remote-sandbox mode', async () => {
    process.env.NODE_ROLE = 'analyzer'
    process.env.RUNTIME_MODE = 'remote-sandbox'
    process.env.RUNTIME_HOST_AGENT_ENDPOINT = 'http://127.0.0.1:4010'

    await expectConfigImportToFail(/runtime\.hostAgentApiKey is required.*remote-sandbox/)
  })

  test('loads remote-sandbox env vars for analyzer role', async () => {
    process.env.NODE_ROLE = 'analyzer'
    process.env.RUNTIME_MODE = 'remote-sandbox'
    process.env.RUNTIME_HOST_AGENT_ENDPOINT = 'http://127.0.0.1:4010'
    process.env.RUNTIME_HOST_AGENT_API_KEY = 'host-agent-secret'

    const { loadConfig } = await importFreshConfigModule()
    const config = loadConfig('__missing_config__.json')

    expect(config.node.role).toBe('analyzer')
    expect(config.runtime.mode).toBe('remote-sandbox')
    expect(config.runtime.hostAgentEndpoint).toBe('http://127.0.0.1:4010')
    expect(config.runtime.hostAgentApiKey).toBe('host-agent-secret')
  })

  test('does not reuse the runtime API key as the host-agent API key', async () => {
    process.env.NODE_ROLE = 'analyzer'
    process.env.RUNTIME_MODE = 'remote-sandbox'
    process.env.RUNTIME_HOST_AGENT_ENDPOINT = 'http://127.0.0.1:4010'
    process.env.RUNTIME_API_KEY = 'runtime-secret'

    await expectConfigImportToFail(/runtime\.hostAgentApiKey is required.*remote-sandbox/)
  })

  test('rejects a file runtime endpoint combined with an environment runtime API key', async () => {
    const { loadConfig } = await importFreshConfigModule()
    const configPath = writeConfig({
      runtime: { endpoint: 'http://127.0.0.1:18081' },
    })
    process.env.RUNTIME_API_KEY = 'env-runtime-secret'

    expect(() => loadConfig(configPath)).toThrow(
      /runtime\.endpoint and runtime\.apiKey must come from the same source/
    )
  })

  test('rejects an environment runtime endpoint combined with a file runtime API key', async () => {
    const { loadConfig } = await importFreshConfigModule()
    const configPath = writeConfig({ runtime: { apiKey: 'file-runtime-secret' } })
    process.env.RUNTIME_ENDPOINT = 'http://127.0.0.1:28081'

    expect(() => loadConfig(configPath)).toThrow(
      /runtime\.endpoint and runtime\.apiKey must come from the same source/
    )
  })

  test('allows a complete environment runtime pair to override a complete file pair', async () => {
    const { loadConfig } = await importFreshConfigModule()
    const configPath = writeConfig({
      runtime: {
        endpoint: 'http://127.0.0.1:18081',
        apiKey: 'file-runtime-secret',
      },
    })
    process.env.RUNTIME_ENDPOINT = 'http://127.0.0.1:28081'
    process.env.RUNTIME_API_KEY = 'env-runtime-secret'

    const config = loadConfig(configPath)

    expect(config.runtime.endpoint).toBe('http://127.0.0.1:28081')
    expect(config.runtime.apiKey).toBe('env-runtime-secret')
  })

  test('loads a complete runtime pair from the file', async () => {
    const { loadConfig } = await importFreshConfigModule()
    const configPath = writeConfig({
      runtime: {
        endpoint: 'http://127.0.0.1:18081',
        apiKey: 'file-runtime-secret',
      },
    })

    const config = loadConfig(configPath)

    expect(config.runtime.endpoint).toBe('http://127.0.0.1:18081')
    expect(config.runtime.apiKey).toBe('file-runtime-secret')
  })

  test('rejects a file host-agent endpoint combined with an environment host-agent API key', async () => {
    const { loadConfig } = await importFreshConfigModule()
    const configPath = writeConfig({
      runtime: { hostAgentEndpoint: 'http://127.0.0.1:4010' },
    })
    process.env.RUNTIME_HOST_AGENT_API_KEY = 'env-host-agent-secret'

    expect(() => loadConfig(configPath)).toThrow(
      /runtime\.hostAgentEndpoint and runtime\.hostAgentApiKey must come from the same source/
    )
  })

  test('rejects an environment host-agent endpoint combined with a file host-agent API key', async () => {
    const { loadConfig } = await importFreshConfigModule()
    const configPath = writeConfig({
      runtime: { hostAgentApiKey: 'file-host-agent-secret' },
    })
    process.env.RUNTIME_HOST_AGENT_ENDPOINT = 'http://127.0.0.1:4010'

    expect(() => loadConfig(configPath)).toThrow(
      /runtime\.hostAgentEndpoint and runtime\.hostAgentApiKey must come from the same source/
    )
  })

  test('allows a complete dedicated environment host-agent pair to override the file pair', async () => {
    const { loadConfig } = await importFreshConfigModule()
    const configPath = writeConfig({
      runtime: {
        hostAgentEndpoint: 'http://127.0.0.1:3010',
        hostAgentApiKey: 'file-host-agent-secret',
      },
    })
    process.env.RUNTIME_HOST_AGENT_ENDPOINT = 'http://127.0.0.1:4010'
    process.env.RUNTIME_HOST_AGENT_API_KEY = 'env-host-agent-secret'

    const config = loadConfig(configPath)

    expect(config.runtime.hostAgentEndpoint).toBe('http://127.0.0.1:4010')
    expect(config.runtime.hostAgentApiKey).toBe('env-host-agent-secret')
  })

  test('allows only an environment runtime API key in auto-sandbox mode', async () => {
    const { loadConfig } = await importFreshConfigModule()
    process.env.NODE_ROLE = 'analyzer'
    process.env.RUNTIME_MODE = 'auto-sandbox'
    process.env.RUNTIME_API_KEY = 'env-runtime-secret'

    const config = loadConfig(process.env.CONFIG_PATH)

    expect(config.runtime.endpoint).toBeUndefined()
    expect(config.runtime.apiKey).toBe('env-runtime-secret')
  })

  test('allows an inert host-agent API key when no host-agent endpoint is configured', async () => {
    const { loadConfig } = await importFreshConfigModule()
    process.env.RUNTIME_MODE = 'disabled'
    process.env.RUNTIME_HOST_AGENT_API_KEY = 'inert-host-agent-secret'

    const config = loadConfig(process.env.CONFIG_PATH)

    expect(config.runtime.hostAgentEndpoint).toBeUndefined()
    expect(config.runtime.hostAgentApiKey).toBe('inert-host-agent-secret')
  })

  test('accepts disabled runtime mode for all node roles', async () => {
    const roles = ['analyzer', 'runtime', 'hybrid'] as const

    for (const role of roles) {
      resetRuntimeEnv()
      process.env.CONFIG_PATH = path.join(tempConfigDir, 'missing.json')
      process.env.NODE_ROLE = role
      process.env.RUNTIME_MODE = 'disabled'

      const { loadConfig } = await importFreshConfigModule()
      const config = loadConfig('__missing_config__.json')

      expect(config.node.role).toBe(role)
      expect(config.runtime.mode).toBe('disabled')
    }
  })
})
