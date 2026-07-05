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
    ['jsvmp-analysis', 'jsvmp.bytecode.recover', 'JSVMP Analysis'],
    ['gtirb', 'gtirb.ir.generate', 'GTIRB'],
    ['remill', 'remill.lift.run', 'Remill'],
    ['radare2', 'radare2.pipeline.run', 'radare2'],
    ['wabt', 'wabt.toolchain.run', 'WABT'],
    ['lief', 'lief.binary.inspect', 'LIEF'],
    ['miasm', 'miasm.ir.lift', 'Miasm'],
    ['triton', 'triton.symbolic.slice', 'Triton'],
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
    ['jsvmp-analysis', 'jsvmp.bytecode.recover', 'bytecode_candidates'],
    ['gtirb', 'gtirb.ir.generate', 'cfg_blocks'],
    ['remill', 'remill.lift.run', 'lifted_instructions'],
    ['radare2', 'radare2.pipeline.run', 'functions_indexed'],
    ['wabt', 'wabt.toolchain.run', 'wasm_sections'],
    ['lief', 'lief.binary.inspect', 'parsed_format'],
    ['miasm', 'miasm.ir.lift', 'ir_blocks'],
    ['triton', 'triton.symbolic.slice', 'symbolic_expressions'],
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

  test.each([
    [
      'restringer',
      'restringer.deobfuscation.run',
      'RESTRINGER_PATH',
      'src/plugins/restringer/workers/restringer-worker.js',
      'recovered_string_arrays',
    ],
    [
      'jsimplifier',
      'jsimplifier.pipeline.run',
      'JSIMPLIFIER_WORKER_PATH',
      'src/plugins/jsimplifier/workers/jsimplifier-worker.js',
      'pass_timeline',
    ],
    [
      'jsir-cascade',
      'jsir.cascade.normalize',
      'JSIR_WORKER_PATH',
      'src/plugins/jsir-cascade/workers/jsir-cascade-worker.js',
      'handler_candidates',
    ],
    [
      'jsvmp-analysis',
      'jsvmp.bytecode.recover',
      'JSVMP_WORKER_PATH',
      'src/plugins/jsvmp-analysis/workers/jsvmp-worker.js',
      'bytecode_candidates',
    ],
    [
      'manifold',
      'manifold.fact.extract',
      'MANIFOLD_WORKER_PATH',
      'src/plugins/manifold/workers/manifold-worker.js',
      'facts',
    ],
  ])(
    '%s external worker wrapper runs through backend-worker.v1 bridge',
    async (pluginId, toolName, envVar, workerPath, key) => {
      const previous = process.env[envVar]
      process.env[envVar] = `node ${process.cwd()}/${workerPath}`
      try {
        const plugins = await discoverBuiltInPlugins()
        const plugin = requirePlugin(plugins, pluginId)
        const harness = createPluginTestHarness()
        harness.registerPlugin(plugin)
        const tool = harness.registeredTools.find((entry) => entry.definition.name === toolName)

        const result = await tool!.handler({
          path: 'fixtures/sample',
          mode: 'external',
          preview: true,
        })

        expect((result as any).ok).toBe(true)
        expect((result as any).data).toEqual(
          expect.objectContaining({
            [key]: expect.anything(),
            execution_semantics: expect.objectContaining({
              actual_mode: 'worker_external',
              live_execution: false,
              no_network: true,
              no_mutation: true,
            }),
          })
        )
      } finally {
        if (previous === undefined) {
          delete process.env[envVar]
        } else {
          process.env[envVar] = previous
        }
      }
    }
  )

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
