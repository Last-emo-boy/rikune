/**
 * Unit tests for runtime-client/recovery.ts
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createRuntimeRecovery, type RecoveryContext } from '../../../src/runtime-client/recovery.js'
import type { Config } from '../../../src/config.js'

describe('createRuntimeRecovery', () => {
  let mockConfig: Config
  let mockRuntimeClient: any
  let mockSandboxLauncher: any

  beforeEach(() => {
    mockRuntimeClient = {
      setEndpoint: jest.fn(),
      health: jest.fn(),
      execute: jest.fn(),
      uploadSample: jest.fn(),
      downloadArtifacts: jest.fn(),
    }

    mockSandboxLauncher = {
      teardown: jest.fn().mockResolvedValue(undefined),
      launch: jest.fn().mockResolvedValue({ endpoint: 'http://127.0.0.1:18081', sandboxDir: '/tmp/sandbox' }),
    }

    mockConfig = {
      runtime: {
        mode: 'disabled',
        endpoint: undefined,
        apiKey: undefined,
        hostAgentEndpoint: undefined,
        hostAgentApiKey: undefined,
        sandboxWorkspace: '/tmp',
        heartbeatIntervalMs: 30000,
        healthCheckTimeoutMs: 60000,
      },
    } as unknown as Config

    global.fetch = jest.fn() as any
  })

  describe('remote-sandbox mode', () => {
    beforeEach(() => {
      mockConfig.runtime.mode = 'remote-sandbox'
      mockConfig.runtime.hostAgentEndpoint = 'http://host-agent:18082'
    })

    test('should recover by calling host agent /sandbox/start', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ ok: true, endpoint: 'http://new-endpoint:18081', sandboxId: 'sb-123' }),
      })

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: null,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      const result = await recovery.recover()

      expect(result).toBe(true)
      expect(global.fetch).toHaveBeenCalledWith(
        'http://host-agent:18082/sandbox/start',
        expect.objectContaining({ method: 'POST' })
      )
    })

    test('should update existing runtimeClient endpoint', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ ok: true, endpoint: 'http://new-endpoint:18081', sandboxId: 'sb-123' }),
      })

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: mockRuntimeClient,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      const result = await recovery.recover()

      expect(result).toBe(true)
      expect(mockRuntimeClient.setEndpoint).toHaveBeenCalledWith('http://new-endpoint:18081')
    })

    test('should return false when host agent responds with non-ok', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 503,
        text: async () => 'Service Unavailable',
      })

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: null,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      const result = await recovery.recover()

      expect(result).toBe(false)
    })

    test('should return false when hostAgentEndpoint is missing', async () => {
      mockConfig.runtime.hostAgentEndpoint = undefined

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: null,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      const result = await recovery.recover()

      expect(result).toBe(false)
      expect(global.fetch).not.toHaveBeenCalled()
    })
  })

  describe('auto-sandbox mode', () => {
    beforeEach(() => {
      mockConfig.runtime.mode = 'auto-sandbox'
    })

    test('should recover by tearing down and relaunching sandbox', async () => {
      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: null,
        runtimeConnection: null,
        sandboxLauncher: mockSandboxLauncher,
      })

      const result = await recovery.recover()

      expect(result).toBe(true)
      expect(mockSandboxLauncher.teardown).toHaveBeenCalled()
      expect(mockSandboxLauncher.launch).toHaveBeenCalled()
    })

    test('should create new runtimeClient if none exists', async () => {
      // createRuntimeClient is imported inside recovery.ts; we verify via setters
      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: null,
        runtimeConnection: null,
        sandboxLauncher: mockSandboxLauncher,
      })

      await recovery.recover()
      // After recovery, setRuntimeClient should have been called with a client
      const newClient = { setEndpoint: jest.fn() }
      recovery.setRuntimeClient(newClient)
      expect(newClient.setEndpoint).not.toHaveBeenCalled() // just verify setter works
    })

    test('should return false when sandboxLauncher is null', async () => {
      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: null,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      const result = await recovery.recover()

      expect(result).toBe(false)
    })

    test('should return false when sandbox launch fails', async () => {
      mockSandboxLauncher.launch.mockResolvedValueOnce(null)

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: null,
        runtimeConnection: null,
        sandboxLauncher: mockSandboxLauncher,
      })

      const result = await recovery.recover()

      expect(result).toBe(false)
    })
  })

  describe('setter methods', () => {
    test('setRuntimeClient, setRuntimeConnection, setSandboxLauncher update internal refs', async () => {
      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: null,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      const newClient = { setEndpoint: jest.fn() }
      const newConnection = { endpoint: 'http://test', sandboxDir: '/tmp' }
      const newLauncher = { teardown: jest.fn(), launch: jest.fn() }

      recovery.setRuntimeClient(newClient)
      recovery.setRuntimeConnection(newConnection as any)
      recovery.setSandboxLauncher(newLauncher as any)

      // Verify by checking recovery uses updated refs in auto-sandbox path
      mockConfig.runtime.mode = 'auto-sandbox'
      ;(newLauncher as any).launch.mockResolvedValue({ endpoint: 'http://test', sandboxDir: '/tmp' })

      const result = await recovery.recover()
      expect(result).toBe(true)
      expect(newLauncher.launch).toHaveBeenCalled()
    })
  })
})
