/**
 * Unit tests for core/plugin-orchestrator.ts
 */

import { describe, test, expect, beforeAll, beforeEach, jest } from '@jest/globals'
import type { Plugin, PluginStatus } from '../../../src/plugins/sdk.js'

jest.unstable_mockModule('../../../src/config.js', () => ({
  config: { node: { role: 'analyzer' } },
}))

jest.unstable_mockModule('../../../src/logger.js', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), debug: jest.fn(), error: jest.fn() },
}))

jest.unstable_mockModule('../../../src/core/tool-surface-manager.js', () => ({
  getToolSurfaceManager: jest.fn().mockReturnValue({
    registerPlugin: jest.fn(),
    isEnabled: jest.fn().mockReturnValue(false),
  }),
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
      register: () => [`${id}.tool`],
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
      expect(result.map(p => p.id)).toEqual(['a'])
      process.env.PLUGINS = original ?? ''
    })

    test('exclusion prefix skips listed plugin', () => {
      const original = process.env.PLUGINS
      process.env.PLUGINS = '-b'
      const plugins = [makePlugin('a'), makePlugin('b')]
      const result = orchestrator.resolveEnabledPlugins(plugins)
      expect(result.map(p => p.id)).toEqual(['a'])
      process.env.PLUGINS = original ?? ''
    })
  })

  describe('resolvePluginsByRole', () => {
    test('hybrid keeps all', () => {
      ;(config as any).node.role = 'hybrid'
      const plugins = [makePlugin('a', { executionDomain: 'static' }), makePlugin('b', { executionDomain: 'dynamic' })]
      expect(orchestrator.resolvePluginsByRole(plugins)).toEqual(plugins)
    })

    test('analyzer keeps all', () => {
      ;(config as any).node.role = 'analyzer'
      const plugins = [makePlugin('a', { executionDomain: 'static' }), makePlugin('b', { executionDomain: 'dynamic' })]
      expect(orchestrator.resolvePluginsByRole(plugins).map(p => p.id)).toEqual(['a', 'b'])
    })

    test('runtime keeps only dynamic plugins', () => {
      ;(config as any).node.role = 'runtime'
      const plugins = [
        makePlugin('a', { executionDomain: 'static' }),
        makePlugin('b', { executionDomain: 'dynamic' }),
        makePlugin('c', { executionDomain: 'both' }),
      ]
      expect(orchestrator.resolvePluginsByRole(plugins).map(p => p.id)).toEqual(['b', 'c'])
    })
  })

  describe('topoSort', () => {
    test('should sort in dependency order', () => {
      const a = makePlugin('a')
      const b = makePlugin('b', { dependencies: ['a'] })
      const c = makePlugin('c', { dependencies: ['b'] })
      expect(orchestrator.topoSort([c, a, b]).map(p => p.id)).toEqual(['a', 'b', 'c'])
    })

    test('should throw on cycles', () => {
      const a = makePlugin('a', { dependencies: ['b'] })
      const b = makePlugin('b', { dependencies: ['a'] })
      expect(() => orchestrator.topoSort([a, b])).toThrow(/cycle/)
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
      expect(mockServer.registerTool).not.toHaveBeenCalled() // register is called inside plugin.register, not orchestrator directly
    })
  })

  describe('unload', () => {
    test('should unregister tools and remove from loaded map', async () => {
      ;(orchestrator as any).server = mockServer
      const p = makePlugin('a')
      await orchestrator.loadOne(p, mockServer as any, mockDeps)
      await orchestrator.unload('a')
      expect(mockServer.unregisterTool).toHaveBeenCalledWith('a.tool')
      expect(orchestrator.isLoaded('a')).toBe(false)
    })
  })
})
