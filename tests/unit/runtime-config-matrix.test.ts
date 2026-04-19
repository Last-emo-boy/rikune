/**
 * Unit tests for runtime mode × node role configuration matrix
 */

import { afterEach, describe, expect, jest, test } from '@jest/globals'

const runtimeEnvKeys = [
  'NODE_ROLE',
  'RUNTIME_MODE',
  'RUNTIME_ENDPOINT',
  'RUNTIME_API_KEY',
  'RUNTIME_HOST_AGENT_ENDPOINT',
  'RUNTIME_HOST_AGENT_API_KEY',
  'CONFIG_PATH',
] as const

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

afterEach(() => {
  resetRuntimeEnv()
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

  test('prefers dedicated host-agent API key over shared runtime API key', async () => {
    process.env.NODE_ROLE = 'analyzer'
    process.env.RUNTIME_MODE = 'remote-sandbox'
    process.env.RUNTIME_HOST_AGENT_ENDPOINT = 'http://127.0.0.1:4010'
    process.env.RUNTIME_HOST_AGENT_API_KEY = 'host-agent-secret'
    process.env.RUNTIME_API_KEY = 'runtime-secret'

    const { loadConfig } = await importFreshConfigModule()
    const config = loadConfig('__missing_config__.json')

    expect(config.runtime.hostAgentApiKey).toBe('host-agent-secret')
    expect(config.runtime.apiKey).toBe('runtime-secret')
  })

  test('accepts disabled runtime mode for all node roles', async () => {
    const roles = ['analyzer', 'runtime', 'hybrid'] as const

    for (const role of roles) {
      resetRuntimeEnv()
      process.env.NODE_ROLE = role
      process.env.RUNTIME_MODE = 'disabled'

      const { loadConfig } = await importFreshConfigModule()
      const config = loadConfig('__missing_config__.json')

      expect(config.node.role).toBe(role)
      expect(config.runtime.mode).toBe('disabled')
    }
  })
})
