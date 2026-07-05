/**
 * Unit tests for runtime-client/sandbox-launcher.ts
 */

import { describe, expect, jest, test } from '@jest/globals'

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

const { createSandboxLauncher } = await import('../../../src/runtime-client/sandbox-launcher.js')

describe('createSandboxLauncher', () => {
  test('does not launch auto-sandbox runtime without a runtime API key', async () => {
    mockConfig.runtime.apiKey = undefined
    const launcher = createSandboxLauncher()

    await expect(launcher.launch()).resolves.toBeNull()
    expect(mockLogger.warn).toHaveBeenCalledWith(
      expect.stringContaining('Auto-sandbox runtime requires runtime.apiKey')
    )
  })
})
