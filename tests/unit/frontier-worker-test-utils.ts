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
        data_provenance: 'fixture',
      }),
    })
  )
  const artifacts = (result as any).artifacts ?? []
  for (const artifact of artifacts) {
    expect(artifact.metadata?.passthrough).toBe(true)
    expect(artifact.metadata?.data_provenance).toBe('fixture')
  }
}

export async function expectFrontierWorkerRejectsExternal(input: {
  pluginId: string
  toolName: string
  args?: Record<string, unknown>
}) {
  const plugins = await discoverBuiltInPlugins()
  const plugin = requirePlugin(plugins, input.pluginId)
  const harness = createPluginTestHarness()
  harness.registerPlugin(plugin)
  const tool = harness.registeredTools.find((entry) => entry.definition.name === input.toolName)
  expect(tool).toBeDefined()

  const result = await tool!.handler({
    path: 'fixtures/sample',
    mode: 'external',
    preview: true,
    ...(input.args ?? {}),
  })

  expect((result as any).ok).toBe(false)
  // Without a configured backend path (and no explicit opt-in for delegated-runtime),
  // external execution must be denied — either because external backends are not
  // enabled or because the backend binary is not configured.
  expect((result as any).errors).toEqual(
    expect.arrayContaining([
      expect.stringMatching(/external_backend_execution_not_enabled|backend_path_missing/),
    ])
  )
  // A denied request must never stamp analysis-backed provenance.
  const data = (result as any).data ?? {}
  const semantics = data.execution_semantics
  if (semantics && typeof semantics === 'object') {
    expect(semantics.data_provenance).not.toBe('analysis')
  }
}
