import { expect } from '@jest/globals'
import { discoverBuiltInPlugins } from '../../src/core/plugin-system/discovery.js'
import { createPluginTestHarness, type Plugin } from '../../src/plugins/sdk.js'

function requirePlugin(plugins: Plugin[], id: string): Plugin {
  const plugin = plugins.find((candidate) => candidate.id === id)
  expect(plugin).toBeDefined()
  return plugin as Plugin
}

export async function expectFrontierWorkerTool(input: {
  pluginId: string
  toolName: string
  backendName: string
  fixtureKey: string
  args?: Record<string, unknown>
}) {
  const plugins = await discoverBuiltInPlugins()
  const plugin = requirePlugin(plugins, input.pluginId)
  const harness = createPluginTestHarness()
  harness.registerPlugin(plugin)
  const tool = harness.registeredTools.find((entry) => entry.definition.name === input.toolName)
  expect(tool).toBeDefined()
  expect(tool!.definition.workerBackend).toEqual(
    expect.objectContaining({
      version: 'backend-worker.v1',
      backendName: input.backendName,
    })
  )

  const result = await tool!.handler({
    path: 'fixtures/sample',
    mode: 'builtin',
    preview: true,
    ...(input.args ?? {}),
  })

  expect((result as any).ok).toBe(true)
  expect((result as any).data).toEqual(
    expect.objectContaining({
      [input.fixtureKey]: expect.anything(),
      execution_semantics: expect.objectContaining({
        actual_mode: 'worker_builtin',
        live_execution: false,
      }),
    })
  )
}
