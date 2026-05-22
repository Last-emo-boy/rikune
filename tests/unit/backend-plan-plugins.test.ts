import { describe, expect, test } from '@jest/globals'
import { discoverBuiltInPlugins } from '../../src/core/plugin-system/discovery.js'
import { createPluginTestHarness, type Plugin } from '../../src/plugins/sdk.js'

function requirePlugin(plugins: Plugin[], id: string): Plugin {
  const plugin = plugins.find((candidate) => candidate.id === id)
  expect(plugin).toBeDefined()
  return plugin as Plugin
}

describe('advanced backend planning plugins', () => {
  test.each([
    ['jsvmp-analysis', 'jsvmp.bytecode.plan', 'jsvmp_bytecode_plan', 'JSVMP Analysis'],
    ['revng', 'revng.pipeline.plan', 'revng_pipeline_plan', 'rev.ng'],
    ['triton', 'triton.symbolic.plan', 'triton_symbolic_plan', 'Triton'],
    ['miasm', 'miasm.ir.plan', 'miasm_ir_plan', 'Miasm'],
    ['lief', 'lief.binary.plan', 'lief_binary_plan', 'LIEF'],
    ['radare2', 'radare2.pipeline.plan', 'radare2_pipeline_plan', 'radare2'],
    ['wabt', 'wabt.toolchain.plan', 'wabt_toolchain_plan', 'WABT'],
  ])(
    '%s stays plan-only and does not start external backends',
    async (pluginId, toolName, artifactType, backendName) => {
      const plugins = await discoverBuiltInPlugins()
      const plugin = requirePlugin(plugins, pluginId)
      const harness = createPluginTestHarness()
      harness.registerPlugin(plugin)
      const tool = harness.registeredTools.find((entry) => entry.definition.name === toolName)
      expect(tool).toBeDefined()

      const result = await tool!.handler({
        sample_id: 'sha256:sample',
        goals: ['symbolic', 'decompile', 'cfg'],
        static_evidence: ['pe_structure', 'function_disassembly'],
        requested_outputs: ['comparison_report'],
      })

      expect((result as any).ok).toBe(true)
      const data = (result as any).data
      expect(data).toEqual(
        expect.objectContaining({
          backend: backendName,
          status: 'plan_only',
          execution_semantics: expect.objectContaining({
            actual_mode: 'plan_only',
            live_execution: false,
          }),
          policy: expect.objectContaining({
            passive: true,
            no_execute: true,
            no_backend_start: true,
            no_network: true,
          }),
        })
      )
      expect(data.output_artifacts).toEqual(expect.arrayContaining([artifactType]))
      expect(data.safety_notes).toEqual(expect.arrayContaining(['No backend process was started.']))
      expect(data.recommended_next_tools.length).toBeGreaterThan(0)
    }
  )
})
