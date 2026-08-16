/**
 * Unit tests for core/plugin-orchestrator.ts
 */

import { describe, test, expect, beforeAll, beforeEach, jest } from '@jest/globals'
import type { Plugin, PluginServerInterface, PluginStatus } from '../../../src/plugins/sdk.js'

jest.unstable_mockModule('../../../src/config.js', () => ({
  config: { node: { role: 'analyzer' } },
}))

jest.unstable_mockModule('../../../src/logger.js', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), debug: jest.fn(), error: jest.fn() },
}))

const mockToolSurfaceManager = {
  registerPlugin: jest.fn(),
  unregisterPlugin: jest.fn(),
  isEnabled: jest.fn().mockReturnValue(false),
}

jest.unstable_mockModule('../../../src/core/tool-surface-manager.js', () => ({
  getToolSurfaceManager: jest.fn().mockReturnValue(mockToolSurfaceManager),
}))

jest.unstable_mockModule('../../../src/core/plugin-runtime-bridge.js', () => ({
  PluginRuntimeBridge: jest.fn().mockImplementation(() => ({
    createServerForPlugin: jest.fn().mockImplementation((server) => server),
  })),
}))

jest.unstable_mockModule('../../../src/core/plugin-system/plugin-context.js', () => ({
  createPluginContext: jest.fn().mockReturnValue({ pluginId: 'test', getConfig: jest.fn() }),
}))

jest.unstable_mockModule('../../../src/core/plugin-system/system-deps.js', () => ({
  checkSystemDeps: jest.fn().mockResolvedValue({ results: [], allRequiredOk: true }),
}))

jest.unstable_mockModule('../../../src/core/plugin-system/discovery.js', () => ({
  discoverBuiltInPlugins: jest.fn().mockResolvedValue([]),
  discoverExternalPlugins: jest.fn().mockResolvedValue([]),
}))

let config: typeof import('../../../src/config.js').config
let PluginOrchestrator: typeof import('../../../src/core/plugin-orchestrator.js').PluginOrchestrator

beforeAll(async () => {
  ;({ config } = await import('../../../src/config.js'))
  ;({ PluginOrchestrator } = await import('../../../src/core/plugin-orchestrator.js'))
})

describe('PluginOrchestrator', () => {
  let orchestrator: PluginOrchestrator
  const mockServer = {
    registerTool: jest.fn(),
    unregisterTool: jest.fn(),
    registerPrompt: jest.fn(),
    registerResource: jest.fn(),
    getClientCapabilities: jest.fn(),
    getClientVersion: jest.fn(),
    createMessage: jest.fn(),
    getToolDefinitions: jest.fn().mockReturnValue([]),
  }
  const mockDeps = {} as any

  beforeEach(() => {
    orchestrator = new PluginOrchestrator()
    ;(config as any).node.role = 'analyzer'
    jest.clearAllMocks()
  })

  function makePlugin(id: string, overrides?: Partial<Plugin>): Plugin {
    return {
      id,
      name: id,
      version: '1.0.0',
      register(server) {
        server.registerTool(
          { name: `${id}.tool`, description: `${id} tool`, inputSchema: {} },
          async () => ({ ok: true })
        )
        return [`${id}.tool`]
      },
      ...overrides,
    } as Plugin
  }

  describe('resolveEnabledPlugins', () => {
    test('* returns all plugins', () => {
      const original = process.env.PLUGINS
      process.env.PLUGINS = '*'
      const plugins = [makePlugin('a'), makePlugin('b')]
      expect(orchestrator.resolveEnabledPlugins(plugins)).toEqual(plugins)
      process.env.PLUGINS = original ?? ''
    })

    test('comma list returns only included', () => {
      const original = process.env.PLUGINS
      process.env.PLUGINS = 'a'
      const plugins = [makePlugin('a'), makePlugin('b')]
      const result = orchestrator.resolveEnabledPlugins(plugins)
      expect(result.map((p) => p.id)).toEqual(['a'])
      process.env.PLUGINS = original ?? ''
    })

    test('exclusion prefix skips listed plugin', () => {
      const original = process.env.PLUGINS
      process.env.PLUGINS = '-b'
      const plugins = [makePlugin('a'), makePlugin('b')]
      const result = orchestrator.resolveEnabledPlugins(plugins)
      expect(result.map((p) => p.id)).toEqual(['a'])
      process.env.PLUGINS = original ?? ''
    })
  })

  describe('resolvePluginsByRole', () => {
    test('hybrid keeps all', () => {
      ;(config as any).node.role = 'hybrid'
      const plugins = [
        makePlugin('a', { executionDomain: 'static' }),
        makePlugin('b', { executionDomain: 'dynamic' }),
      ]
      expect(orchestrator.resolvePluginsByRole(plugins)).toEqual(plugins)
    })

    test('analyzer keeps all', () => {
      ;(config as any).node.role = 'analyzer'
      const plugins = [
        makePlugin('a', { executionDomain: 'static' }),
        makePlugin('b', { executionDomain: 'dynamic' }),
      ]
      expect(orchestrator.resolvePluginsByRole(plugins).map((p) => p.id)).toEqual(['a', 'b'])
    })

    test('runtime keeps only dynamic plugins', () => {
      ;(config as any).node.role = 'runtime'
      const plugins = [
        makePlugin('a', { executionDomain: 'static' }),
        makePlugin('b', { executionDomain: 'dynamic' }),
        makePlugin('c', { executionDomain: 'both' }),
      ]
      expect(orchestrator.resolvePluginsByRole(plugins).map((p) => p.id)).toEqual(['b', 'c'])
    })
  })

  describe('topoSort', () => {
    test('should sort in dependency order', () => {
      const a = makePlugin('a')
      const b = makePlugin('b', { dependencies: ['a'] })
      const c = makePlugin('c', { dependencies: ['b'] })
      expect(orchestrator.topoSort([c, a, b]).map((p) => p.id)).toEqual(['a', 'b', 'c'])
    })

    test('should throw on cycles', () => {
      const a = makePlugin('a', { dependencies: ['b'] })
      const b = makePlugin('b', { dependencies: ['a'] })
      expect(() => orchestrator.topoSort([a, b])).toThrow(/cycle/)
    })
  })

  describe('loadAll', () => {
    test('should retain the first plugin ID and report later duplicates', async () => {
      const retained = makePlugin('duplicate-id')
      const rejectedRegister = jest.fn()
      const rejected = makePlugin('duplicate-id', {
        name: 'Rejected duplicate',
        register: rejectedRegister,
      })

      const statuses = await orchestrator.loadAll(mockServer as any, mockDeps, [retained, rejected])

      expect(statuses).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ id: 'duplicate-id', status: 'loaded' }),
          expect.objectContaining({
            id: 'duplicate-id',
            status: 'error',
            reasonCode: 'duplicate-plugin-id',
          }),
        ])
      )
      expect(orchestrator.getDiscoveredPlugins()).toEqual([retained])
      expect(rejectedRegister).not.toHaveBeenCalled()
    })
  })

  describe('loadOne', () => {
    test('should skip plugin when dependency not loaded', async () => {
      const p = makePlugin('b', { dependencies: ['a'] })
      const status = await orchestrator.loadOne(p, mockServer as any, mockDeps)
      expect(status.status).toBe('skipped-deps')
      expect(status.reasonCode).toBe('missing-dependency')
      expect(status.controlPlaneStatus).toBe('failed')
    })

    test('should skip plugin when check() returns false on runtime node', async () => {
      ;(config as any).node.role = 'runtime'
      const p = makePlugin('a', { check: () => false })
      const status = await orchestrator.loadOne(p, mockServer as any, mockDeps)
      expect(status.status).toBe('skipped-check')
      expect(status.reasonCode).toBe('prerequisite-check-failed')
      expect(status.controlPlaneStatus).toBe('failed')
    })

    test('should load dynamic plugin even if check() fails on analyzer (for delegation)', async () => {
      ;(config as any).node.role = 'analyzer'
      const p = makePlugin('a', { executionDomain: 'dynamic', check: () => false })
      const status = await orchestrator.loadOne(p, mockServer as any, mockDeps)
      expect(status.status).toBe('loaded')
      expect(status.controlPlaneStatus).toBe('completed')
    })

    test('should load plugin successfully', async () => {
      const p = makePlugin('a')
      const status = await orchestrator.loadOne(p, mockServer as any, mockDeps)
      expect(status.status).toBe('loaded')
      expect(status.controlPlaneStatus).toBe('completed')
      expect(status.statusDetail).toContain('tool')
      expect(status.tools).toContain('a.tool')
      expect(mockServer.registerTool).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'a.tool' }),
        expect.any(Function)
      )
    })

    test('should auto-register declarative plugin tools', async () => {
      const p = makePlugin('a', {
        register: undefined,
        tools: [
          {
            definition: {
              name: 'a.tool',
              description: 'Declarative tool',
              inputSchema: {},
            },
            handler: async () => ({ ok: true }),
          },
        ],
      } as Partial<Plugin>)

      const status = await orchestrator.loadOne(p, mockServer as any, mockDeps)

      expect(status.status).toBe('loaded')
      expect(status.tools).toEqual(['a.tool'])
      expect(mockServer.registerTool).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'a.tool' }),
        expect.any(Function)
      )
    })

    test('reports quality warnings without blocking plugin loading', async () => {
      const p = makePlugin('dynamic-no-schema', {
        executionDomain: 'dynamic',
        register: undefined,
        tools: [
          {
            definition: {
              name: 'dynamic_no_schema.tool',
              description: 'Dynamic tool with intentionally sparse metadata',
              inputSchema: {},
            },
            handler: async () => ({ ok: true }),
          },
        ],
      } as Partial<Plugin>)

      const status = await orchestrator.loadOne(p, mockServer as any, mockDeps)

      expect(status.status).toBe('loaded')
      expect(status.qualityWarnings?.map((warning) => warning.code)).toEqual(
        expect.arrayContaining([
          'missing-output-schema',
          'missing-surface-rules',
          'missing-system-deps',
          'missing-readiness-check',
          'missing-aspects',
          'missing-evidence',
          'missing-runtime-policy',
          'dynamic-runtime-contract-missing',
        ])
      )
    })

    test('should report invalid plugin contracts before registration', async () => {
      const p = makePlugin('bad plugin', { register: undefined } as Partial<Plugin>)
      const status = await orchestrator.loadOne(p, mockServer as any, mockDeps)

      expect(status.status).toBe('error')
      expect(status.reasonCode).toBe('registration-failed')
      expect(status.statusDetail).toContain('Invalid plugin contract')
    })

    test('should roll back tools when plugin registration fails partway through', async () => {
      const registeredTools = new Map<string, unknown>()
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          if (definition.name === 'partial.second') {
            throw new Error('registration failure')
          }
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
      }
      const p = makePlugin('partial', {
        register(server) {
          server.registerTool(
            { name: 'partial.first', description: 'First tool', inputSchema: {} },
            async () => ({ ok: true })
          )
          server.registerTool(
            { name: 'partial.second', description: 'Second tool', inputSchema: {} },
            async () => ({ ok: true })
          )
          return ['partial.first', 'partial.second']
        },
      })

      const status = await orchestrator.loadOne(p, transactionalServer as any, mockDeps)

      expect(status.status).toBe('error')
      expect(status.reasonCode).toBe('registration-failed')
      expect(registeredTools.size).toBe(0)
      expect(transactionalServer.unregisterTool).toHaveBeenCalledWith('partial.first')
    })

    test('should track tools when register returns void', async () => {
      const registeredTools = new Map<string, unknown>()
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
      }
      const p = makePlugin('void-register', {
        register(server) {
          server.registerTool(
            { name: 'void_register.tool', description: 'Tracked tool', inputSchema: {} },
            async () => ({ ok: true })
          )
        },
      })

      const status = await orchestrator.loadOne(p, transactionalServer as any, mockDeps)

      expect(status.status).toBe('loaded')
      expect(status.tools).toEqual(['void_register.tool'])
      expect(orchestrator.getPluginForTool('void_register.tool')).toBe('void-register')
      ;(orchestrator as any).server = transactionalServer
      await orchestrator.unload('void-register')

      expect(transactionalServer.unregisterTool).toHaveBeenCalledWith('void_register.tool')
      expect(registeredTools.size).toBe(0)
    })

    test('should reject unregistered returned names and preserve existing tools on rollback', async () => {
      const registeredTools = new Map<string, unknown>([
        ['core.existing', { name: 'core.existing', description: 'Core tool', inputSchema: {} }],
      ])
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
      }
      const p = makePlugin('spoof', {
        register(server) {
          server.registerTool(
            { name: 'spoof.tool', description: 'Plugin tool', inputSchema: {} },
            async () => ({ ok: true })
          )
          return ['spoof.tool', 'core.existing']
        },
      })

      const status = await orchestrator.loadOne(p, transactionalServer as any, mockDeps)

      expect(status.status).toBe('error')
      expect(status.reasonCode).toBe('registration-failed')
      expect(registeredTools.has('core.existing')).toBe(true)
      expect(registeredTools.has('spoof.tool')).toBe(false)
      expect(transactionalServer.unregisterTool).toHaveBeenCalledWith('spoof.tool')
      expect(transactionalServer.unregisterTool).not.toHaveBeenCalledWith('core.existing')
      expect(orchestrator.getPluginForTool('core.existing')).toBeUndefined()
    })

    test('should prevent a plugin from unregistering a core tool during registration', async () => {
      const registeredTools = new Map<string, unknown>([
        ['core.existing', { name: 'core.existing', description: 'Core tool', inputSchema: {} }],
      ])
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
      }
      const p = makePlugin('unregister-spoof', {
        register(server) {
          server.unregisterTool('core.existing')
        },
      })

      const status = await orchestrator.loadOne(p, transactionalServer as any, mockDeps)

      expect(status.status).toBe('error')
      expect(status.reasonCode).toBe('registration-failed')
      expect(registeredTools.has('core.existing')).toBe(true)
      expect(transactionalServer.unregisterTool).not.toHaveBeenCalledWith('core.existing')
    })

    test('should not expose mutable server methods through plugin dependencies', async () => {
      const registeredTools = new Map<string, unknown>([
        ['core.existing', { name: 'core.existing', description: 'Core tool', inputSchema: {} }],
      ])
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
        callTool: jest.fn(),
      }
      let topLevelServer: Record<string, unknown> | undefined
      let platformServer: Record<string, unknown> | undefined
      const p = makePlugin('dependency-scope', {
        register(_server, deps) {
          topLevelServer = deps.server as Record<string, unknown>
          platformServer = deps.services?.platform?.server as Record<string, unknown>
          return []
        },
      })
      const pluginDeps = {
        ...mockDeps,
        server: transactionalServer,
        services: { platform: { server: transactionalServer } },
      }

      const status = await orchestrator.loadOne(p, transactionalServer as any, pluginDeps as any)

      expect(status.status).toBe('loaded')
      expect(topLevelServer).toBe(platformServer)
      expect(topLevelServer?.unregisterTool).toBeUndefined()
      expect(topLevelServer?.registerTool).toBeUndefined()
      expect(topLevelServer?.callTool).toBeUndefined()
      expect(topLevelServer?.callToolInternal).toEqual(expect.any(Function))
      expect(Object.isFrozen(topLevelServer)).toBe(true)
      expect(registeredTools.has('core.existing')).toBe(true)
      const callToolInternal = topLevelServer?.callToolInternal as (
        ...args: unknown[]
      ) => Promise<unknown>
      for (const toolName of ['plugin.disable', 'plugin_disable']) {
        await expect(callToolInternal(toolName, { plugin_id: 'victim' })).rejects.toThrow(
          /control-plane tool/
        )
      }
      expect(transactionalServer.callTool).not.toHaveBeenCalled()
    })

    test('should reject a stale registration server after another plugin takes ownership', async () => {
      const registeredTools = new Map<string, unknown>()
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
      }
      let retainedServer: PluginServerInterface | undefined
      const firstPlugin = makePlugin('owner-a', {
        register(server) {
          retainedServer = server
          server.registerTool(
            { name: 'shared.tool', description: 'Shared tool', inputSchema: {} },
            async () => ({ ok: true })
          )
          return ['shared.tool']
        },
      })

      await orchestrator.loadOne(firstPlugin, transactionalServer as any, mockDeps)
      ;(orchestrator as any).server = transactionalServer
      await orchestrator.unload('owner-a')

      const secondPlugin = makePlugin('owner-b', {
        register(server) {
          server.registerTool(
            { name: 'shared.tool', description: 'Replacement tool', inputSchema: {} },
            async () => ({ ok: true })
          )
          return ['shared.tool']
        },
      })
      const secondStatus = await orchestrator.loadOne(
        secondPlugin,
        transactionalServer as any,
        mockDeps
      )
      const staleServer = retainedServer
      const replacementRegister = jest.fn()
      const replacementUnregister = jest.fn()
      try {
        Object.defineProperty(staleServer, 'registerTool', { value: replacementRegister })
        Object.defineProperty(staleServer, 'unregisterTool', { value: replacementUnregister })
      } catch {
        // Frozen registrar methods cannot be replaced.
      }
      transactionalServer.unregisterTool.mockClear()
      transactionalServer.registerTool.mockClear()

      expect(secondStatus.status).toBe('loaded')
      expect(staleServer).toBeDefined()
      expect(Object.isFrozen(staleServer)).toBe(true)
      expect(() => staleServer?.unregisterTool('shared.tool')).toThrow(/owned by another plugin/)
      expect(() =>
        staleServer?.registerTool(
          { name: 'shared.late', description: 'Late tool', inputSchema: {} },
          async () => ({ ok: true })
        )
      ).toThrow(/no longer active/)
      expect(replacementRegister).not.toHaveBeenCalled()
      expect(replacementUnregister).not.toHaveBeenCalled()
      expect(transactionalServer.unregisterTool).not.toHaveBeenCalled()
      expect(transactionalServer.registerTool).not.toHaveBeenCalled()
      expect(registeredTools.has('shared.tool')).toBe(true)
      expect(registeredTools.has('shared.late')).toBe(false)
      expect(orchestrator.getPluginForTool('shared.tool')).toBe('owner-b')
    })

    test('should revoke registration immediately after a synchronous register returns', async () => {
      const registeredTools = new Map<string, unknown>()
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
      }
      let lateRegistrationDone: Promise<void> | undefined
      let lateRegistrationError: unknown
      const plugin = makePlugin('sync-revoke', {
        register(server) {
          server.registerTool(
            { name: 'sync_revoke.tool', description: 'Registered tool', inputSchema: {} },
            async () => ({ ok: true })
          )
          lateRegistrationDone = Promise.resolve().then(() => {
            try {
              server.registerTool(
                { name: 'orphan.tool', description: 'Orphan tool', inputSchema: {} },
                async () => ({ ok: true })
              )
            } catch (error) {
              lateRegistrationError = error
            }
          })
          return ['sync_revoke.tool']
        },
      })

      const status = await orchestrator.loadOne(plugin, transactionalServer as any, mockDeps)
      const lateDone = lateRegistrationDone
      expect(lateDone).toBeDefined()
      await lateDone

      expect(status.status).toBe('loaded')
      expect(status.tools).toEqual(['sync_revoke.tool'])
      expect(lateRegistrationError).toBeInstanceOf(Error)
      expect((lateRegistrationError as Error).message).toMatch(/no longer active/)
      expect(registeredTools.has('orphan.tool')).toBe(false)
    })

    test('should keep registration active until a Promise-based register settles', async () => {
      const registeredTools = new Map<string, unknown>()
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
      }
      let releaseRegistration: () => void = () => {}
      const registrationGate = new Promise<void>((resolve) => {
        releaseRegistration = resolve
      })
      let retainedServer: PluginServerInterface | undefined
      const promiseRegister = async (server: PluginServerInterface) => {
        retainedServer = server
        await registrationGate
        server.registerTool(
          { name: 'promise_register.tool', description: 'Promise tool', inputSchema: {} },
          async () => ({ ok: true })
        )
        return ['promise_register.tool']
      }
      const plugin = makePlugin('promise-register', {
        register: promiseRegister,
      })

      const loadPromise = orchestrator.loadOne(plugin, transactionalServer as any, mockDeps)
      expect(registeredTools.has('promise_register.tool')).toBe(false)
      releaseRegistration()
      const status = await loadPromise
      const settledServer = retainedServer

      expect(status.status).toBe('loaded')
      expect(status.tools).toEqual(['promise_register.tool'])
      expect(registeredTools.has('promise_register.tool')).toBe(true)
      expect(settledServer).toBeDefined()
      expect(() =>
        settledServer?.registerTool(
          { name: 'promise_register.late', description: 'Late tool', inputSchema: {} },
          async () => ({ ok: true })
        )
      ).toThrow(/no longer active/)
      expect(registeredTools.has('promise_register.late')).toBe(false)
    })

    test('should keep tool ownership stable if a plugin mutates its exported id', async () => {
      const registeredTools = new Map<string, unknown>()
      const transactionalServer = {
        ...mockServer,
        registerTool: jest.fn((definition: { name: string }) => {
          registeredTools.set(definition.name, definition)
        }),
        unregisterTool: jest.fn((name: string) => {
          registeredTools.delete(name)
        }),
        getToolDefinitions: jest.fn(() => [...registeredTools.values()]),
      }

      await orchestrator.loadOne(makePlugin('victim'), transactionalServer as any, mockDeps)
      const mutablePlugin = {
        ...makePlugin('mutating'),
        register(server: any) {
          ;(mutablePlugin as any).id = 'victim'
          server.unregisterTool('victim.tool')
        },
      } as Plugin

      const status = await orchestrator.loadOne(mutablePlugin, transactionalServer as any, mockDeps)

      expect(status.status).toBe('error')
      expect(registeredTools.has('victim.tool')).toBe(true)
      expect(transactionalServer.unregisterTool).not.toHaveBeenCalledWith('victim.tool')
      expect(orchestrator.getPluginForTool('victim.tool')).toBe('victim')
    })
  })

  describe('unload', () => {
    test('should unregister tools and remove from loaded map', async () => {
      ;(orchestrator as any).server = mockServer
      const p = makePlugin('a')
      await orchestrator.loadOne(p, mockServer as any, mockDeps)
      await orchestrator.unload('a')
      expect(mockServer.unregisterTool).toHaveBeenCalledWith('a.tool')
      expect(mockToolSurfaceManager.unregisterPlugin).toHaveBeenCalledWith('a')
      expect(orchestrator.getPluginForTool('a.tool')).toBeUndefined()
      expect(orchestrator.isLoaded('a')).toBe(false)
    })

    test('should remove plugin tool owners even when status tools are stale', async () => {
      ;(orchestrator as any).server = mockServer
      const p = makePlugin('a')
      await orchestrator.loadOne(p, mockServer as any, mockDeps)
      const status = orchestrator.getStatuses().find((item: PluginStatus) => item.id === 'a')
      if (status) status.tools = []

      await orchestrator.unload('a')

      expect(mockServer.unregisterTool).toHaveBeenCalledWith('a.tool')
      expect(orchestrator.getPluginForTool('a.tool')).toBeUndefined()
      expect(mockToolSurfaceManager.unregisterPlugin).toHaveBeenCalledWith('a')
    })
  })
})
