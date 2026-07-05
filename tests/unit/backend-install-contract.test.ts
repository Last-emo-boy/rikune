import { describe, expect, test } from '@jest/globals'
import { discoverBuiltInPlugins } from '../../src/core/plugin-system/discovery.js'
import { createPluginTestHarness, type Plugin } from '../../src/plugins/sdk.js'

const WORKER_PLUGINS = [
  'restringer',
  'jsimplifier',
  'jsir-cascade',
  'jsvmp-analysis',
  'gtirb',
  'remill',
  'radare2',
  'wabt',
  'lief',
  'miasm',
  'triton',
  'manifold',
  'qbdi',
  'culifter',
]

function routeFor(plugin: Plugin): string[] {
  return (plugin.systemDeps ?? [])
    .filter((dep) => dep.dockerFeature)
    .map((dep) => `${dep.dockerFeature}:${dep.dockerInstallRoute ?? 'missing'}`)
}

describe('backend install contract', () => {
  test('worker-backed plugins declare concrete Docker install or explicit non-default routes', async () => {
    const plugins = await discoverBuiltInPlugins()
    const byId = new Map(plugins.map((plugin) => [plugin.id, plugin]))

    for (const id of WORKER_PLUGINS) {
      const plugin = byId.get(id)
      expect(plugin).toBeDefined()
      const routes = routeFor(plugin!)
      expect(routes.length).toBeGreaterThan(0)
      expect(routes.some((route) => route.endsWith(':missing'))).toBe(false)
    }
  })

  test('workerBackend packaging metadata matches plugin systemDeps routes', async () => {
    const plugins = await discoverBuiltInPlugins()

    for (const plugin of plugins.filter((candidate) => WORKER_PLUGINS.includes(candidate.id))) {
      const harness = createPluginTestHarness()
      harness.registerPlugin(plugin)
      const toolBackends = harness.registeredTools
        .map((entry) => entry.definition.workerBackend)
        .filter(Boolean)

      for (const backend of toolBackends) {
        expect(backend!.packaging?.installRoute).toBeTruthy()
        expect(backend!.packaging?.installProfile).toBeTruthy()
        const dockerFeature = backend!.packaging?.dockerFeature
        if (dockerFeature) {
          expect(plugin.systemDeps?.some((dep) => dep.dockerFeature === dockerFeature)).toBe(true)
        }
      }
    }
  })
})
