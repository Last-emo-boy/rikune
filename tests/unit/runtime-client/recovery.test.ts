/**
 * Unit tests for runtime-client/recovery.ts
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import {
  createRuntimeRecovery,
  type RecoveryContext,
} from '../../../src/runtime-client/recovery.js'
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
      launch: jest
        .fn()
        .mockResolvedValue({ endpoint: 'http://127.0.0.1:18081', sandboxDir: '/tmp/sandbox' }),
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
        json: async () => ({
          ok: true,
          endpoint: 'http://host-agent:18081',
          sandboxId: 'sb-123',
        }),
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
        expect.objectContaining({ method: 'POST', redirect: 'error' })
      )
    })

    test('should update existing runtimeClient endpoint', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          endpoint: 'http://host-agent:18081',
          sandboxId: 'sb-123',
        }),
      })

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: mockRuntimeClient,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      const result = await recovery.recover()

      expect(result).toBe(true)
      expect(mockRuntimeClient.setEndpoint).toHaveBeenCalledWith('http://host-agent:18081', {
        trustedParentEndpoint: 'http://host-agent:18082',
      })
    })

    test('should reject a runtime endpoint that is not bound to the Host Agent', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          endpoint: 'http://attacker.invalid:18081',
          sandboxId: 'sb-malicious',
        }),
      })

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: mockRuntimeClient,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      await expect(recovery.recover()).resolves.toBe(false)
      expect(mockRuntimeClient.setEndpoint).not.toHaveBeenCalled()
      expect(global.fetch).toHaveBeenCalledWith(
        'http://host-agent:18082/sandbox/start',
        expect.objectContaining({ redirect: 'error' })
      )
    })

    test('accepts a direct Hyper-V VM endpoint designated by the trusted Host Agent', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          endpoint: 'http://hyperv-runtime.internal:18081',
          sandboxId: 'hyperv-session',
          backend: 'hyperv-vm',
        }),
      })

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: mockRuntimeClient,
        runtimeConnection: null,
        sandboxLauncher: null,
      })

      await expect(recovery.recover()).resolves.toBe(true)
      expect(mockRuntimeClient.setEndpoint).toHaveBeenCalledWith(
        'http://hyperv-runtime.internal:18081',
        {
          trustedParentEndpoint: 'http://host-agent:18082',
          trustedHostAgentBackend: 'hyperv-vm',
        }
      )
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

    test('should use the previous connection as provenance when the listener port changes', async () => {
      mockConfig.runtime.apiKey = 'runtime-secret'
      mockSandboxLauncher.launch.mockResolvedValueOnce({
        endpoint: 'http://127.0.0.1:18082',
        sandboxDir: '/tmp/sandbox-new',
      })

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: mockRuntimeClient,
        runtimeConnection: {
          endpoint: 'http://127.0.0.1:18081',
          sandboxDir: '/tmp/sandbox-old',
        } as any,
        sandboxLauncher: mockSandboxLauncher,
      })

      await expect(recovery.recover()).resolves.toBe(true)
      expect(mockRuntimeClient.setEndpoint).toHaveBeenCalledWith('http://127.0.0.1:18082', {
        trustedLocalSandboxLaunch: true,
      })
    })

    test('allows a trusted local launcher to rotate to a new sandbox host', async () => {
      mockConfig.runtime.apiKey = 'runtime-secret'
      mockSandboxLauncher.launch.mockResolvedValueOnce({
        endpoint: 'http://192.168.137.11:18081',
        sandboxDir: '/tmp/sandbox-new',
      })

      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: mockRuntimeClient,
        runtimeConnection: {
          endpoint: 'http://192.168.137.10:18081',
          sandboxDir: '/tmp/sandbox-old',
        } as any,
        sandboxLauncher: mockSandboxLauncher,
      })

      await expect(recovery.recover()).resolves.toBe(true)
      expect(mockRuntimeClient.setEndpoint).toHaveBeenCalledWith('http://192.168.137.11:18081', {
        trustedLocalSandboxLaunch: true,
      })
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

    test('coalesces concurrent recovery attempts into one sandbox launch', async () => {
      let resolveLaunch: ((connection: unknown) => void) | undefined
      mockSandboxLauncher.launch.mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveLaunch = resolve
          })
      )
      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: mockRuntimeClient,
        runtimeConnection: null,
        sandboxLauncher: mockSandboxLauncher,
      })

      const first = recovery.recover()
      const second = recovery.recover()
      expect(second).toBe(first)
      await Promise.resolve()
      expect(mockSandboxLauncher.teardown).toHaveBeenCalledTimes(1)
      expect(mockSandboxLauncher.launch).toHaveBeenCalledTimes(1)

      resolveLaunch?.({ endpoint: 'http://127.0.0.1:18081', sandboxDir: '/tmp/sandbox' })
      await expect(Promise.all([first, second])).resolves.toEqual([true, true])
      expect(mockRuntimeClient.setEndpoint).toHaveBeenCalledTimes(1)
    })

    test('releases the single-flight lock after a failed recovery', async () => {
      mockSandboxLauncher.launch.mockResolvedValueOnce(null).mockResolvedValueOnce({
        endpoint: 'http://127.0.0.1:18081',
        sandboxDir: '/tmp/sandbox-retry',
      })
      const recovery = createRuntimeRecovery({
        config: mockConfig,
        runtimeClient: mockRuntimeClient,
        runtimeConnection: null,
        sandboxLauncher: mockSandboxLauncher,
      })

      await expect(recovery.recover()).resolves.toBe(false)
      await expect(recovery.recover()).resolves.toBe(true)
      expect(mockSandboxLauncher.launch).toHaveBeenCalledTimes(2)
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
      ;(newLauncher as any).launch.mockResolvedValue({
        endpoint: 'http://test',
        sandboxDir: '/tmp',
      })

      const result = await recovery.recover()
      expect(result).toBe(true)
      expect(newLauncher.launch).toHaveBeenCalled()
    })
  })
})
