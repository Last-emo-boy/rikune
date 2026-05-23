import { describe, expect, test } from '@jest/globals'
import { discoverBuiltInPlugins } from '../../src/core/plugin-system/discovery.js'
import { createPluginTestHarness, type Plugin } from '../../src/plugins/sdk.js'

function requirePlugin(plugins: Plugin[], id: string): Plugin {
  const plugin = plugins.find((candidate) => candidate.id === id)
  expect(plugin).toBeDefined()
  return plugin as Plugin
}

describe('frontier worker-backed plugins', () => {
  test.each([
    ['restringer', 'restringer.deobfuscation.run', 'REstringer'],
    ['jsimplifier', 'jsimplifier.pipeline.run', 'JSIMPLIFIER'],
    ['jsir-cascade', 'jsir.cascade.normalize', 'JSIR/CASCADE'],
    ['gtirb', 'gtirb.ir.generate', 'GTIRB'],
    ['remill', 'remill.lift.run', 'Remill'],
    ['manifold', 'manifold.fact.extract', 'Manifold'],
    ['qbdi', 'qbdi.trace.run', 'QBDI'],
    ['culifter', 'culifter.gpu.artifact.inventory', 'CuLifter'],
  ])('%s registers worker contract for %s', async (pluginId, toolName, backendName) => {
    const plugins = await discoverBuiltInPlugins()
    const plugin = requirePlugin(plugins, pluginId)
    const harness = createPluginTestHarness()
    harness.registerPlugin(plugin)

    const tool = harness.registeredTools.find((entry) => entry.definition.name === toolName)
    expect(tool).toBeDefined()
    expect(tool!.definition.workerBackend).toEqual(
      expect.objectContaining({
        version: 'backend-worker.v1',
        backendName,
      })
    )
    expect(tool!.definition.artifacts?.length).toBeGreaterThan(0)
    expect(tool!.definition.workflowRecipes?.length).toBeGreaterThan(0)
  })

  test.each([
    ['restringer', 'restringer.deobfuscation.run', 'recovered_string_arrays'],
    ['jsimplifier', 'jsimplifier.pipeline.run', 'pass_timeline'],
    ['jsir-cascade', 'jsir.cascade.normalize', 'handler_candidates'],
    ['gtirb', 'gtirb.ir.generate', 'cfg_blocks'],
    ['remill', 'remill.lift.run', 'lifted_instructions'],
    ['manifold', 'manifold.fact.extract', 'agreement'],
    ['culifter', 'culifter.gpu.artifact.inventory', 'gpu_driver_required'],
  ])('%s builtin worker returns structured fixture data', async (pluginId, toolName, key) => {
    const plugins = await discoverBuiltInPlugins()
    const plugin = requirePlugin(plugins, pluginId)
    const harness = createPluginTestHarness()
    harness.registerPlugin(plugin)
    const tool = harness.registeredTools.find((entry) => entry.definition.name === toolName)

    const result = await tool!.handler({
      path: 'fixtures/sample',
      mode: 'builtin',
      preview: true,
      goals: ['fixture'],
    })

    expect((result as any).ok).toBe(true)
    expect((result as any).data).toEqual(
      expect.objectContaining({
        [key]: expect.anything(),
        execution_semantics: expect.objectContaining({
          actual_mode: 'worker_builtin',
          live_execution: false,
        }),
      })
    )
    expect((result as any).evidence?.[0]).toEqual(
      expect.objectContaining({
        category: 'provenance',
        toolName,
      })
    )
  })

  test('QBDI worker requires explicit opt-in before delegated runtime handoff', async () => {
    const plugins = await discoverBuiltInPlugins()
    const plugin = requirePlugin(plugins, 'qbdi')
    const harness = createPluginTestHarness()
    harness.registerPlugin(plugin)
    const tool = harness.registeredTools.find((entry) => entry.definition.name === 'qbdi.trace.run')

    const result = await tool!.handler({
      path: 'sample.exe',
      mode: 'delegated-runtime',
      approved: false,
    })

    expect((result as any).ok).toBe(false)
    expect((result as any).errors).toEqual(expect.arrayContaining(['explicit_opt_in_required']))
    expect((result as any).data.readiness).toEqual(
      expect.objectContaining({
        status: 'policy_denied',
        does_not_start_backend: true,
      })
    )
  })

  test('plan-only tools remain registered beside worker-backed tools', async () => {
    const plugins = await discoverBuiltInPlugins()
    const plugin = requirePlugin(plugins, 'restringer')
    const harness = createPluginTestHarness()
    harness.registerPlugin(plugin)
    const names = harness.registeredTools.map((tool) => tool.definition.name)

    expect(names).toEqual(
      expect.arrayContaining(['restringer.deobfuscation.plan', 'restringer.deobfuscation.run'])
    )
  })
})
