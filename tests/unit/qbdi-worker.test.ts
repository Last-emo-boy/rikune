import { describe, expect, test } from '@jest/globals'
import { discoverBuiltInPlugins } from '../../src/core/plugin-system/discovery.js'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'

describe('qbdi worker', () => {
  test('requires explicit opt-in for delegated runtime worker', async () => {
    const plugins = await discoverBuiltInPlugins()
    const plugin = plugins.find((candidate) => candidate.id === 'qbdi')
    expect(plugin).toBeDefined()
    const harness = createPluginTestHarness()
    harness.registerPlugin(plugin!)
    const tool = harness.registeredTools.find((entry) => entry.definition.name === 'qbdi.trace.run')
    expect(tool?.definition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'QBDI',
        backendKind: 'delegated-runtime',
      })
    )

    const result = await tool!.handler({ path: 'sample.exe', mode: 'delegated-runtime' })
    expect((result as any).ok).toBe(false)
    expect((result as any).errors).toEqual(expect.arrayContaining(['explicit_opt_in_required']))
  })
})
