import { describe, expect, test } from '@jest/globals'
import { createToolsDiscoverHandler } from '../../src/tools/tools-discover.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import type { Plugin } from '../../src/plugins/sdk.js'

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
}

describe('tools.discover', () => {
  test('lists categories with role-aware guidance metadata', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'pe-analysis-test',
        name: 'PE Analysis Test',
        description: 'PE tools',
        surfaceRules: { tier: 1, category: 'static-analysis' },
        tools: [],
      },
      {
        id: 'ghidra-test',
        name: 'Ghidra Test',
        description: 'Ghidra tools',
        surfaceRules: { tier: 3, category: 'reverse-engineering' },
        tools: [],
      },
      {
        id: 'runtime-test',
        name: 'Runtime Test',
        description: 'Runtime tools',
        surfaceRules: { tier: 3, category: 'dynamic-analysis' },
        tools: [],
      },
    ]
    surface.registerPlugin(plugins[0], ['pe.imports.extract'])
    surface.registerPlugin(plugins[1], ['ghidra.analyze'])
    surface.registerPlugin(plugins[2], ['sandbox.execute'])

    const pluginManager = {
      getStatuses: () =>
        plugins.map((plugin) => ({
          id: plugin.id,
          name: plugin.name,
          description: plugin.description,
          status: 'loaded',
          tools: [],
        })),
    }
    const handler = createToolsDiscoverHandler(pluginManager as any)

    const result = await handler({ action: 'list' })

    expect(result.ok).toBe(true)
    const categories = (result.data as any).categories
    const staticPlugin = categories
      .find((category: any) => category.category === 'static-analysis')
      .plugins.find((plugin: any) => plugin.id === 'pe-analysis-test')
    const reversePlugin = categories
      .find((category: any) => category.category === 'reverse-engineering')
      .plugins.find((plugin: any) => plugin.id === 'ghidra-test')
    const runtimePlugin = categories
      .find((category: any) => category.category === 'dynamic-analysis')
      .plugins.find((plugin: any) => plugin.id === 'runtime-test')

    expect(staticPlugin.tool_surface_role).toBe('specialist')
    expect(staticPlugin.preferred_primary_tools).toEqual(
      expect.arrayContaining(['workflow.analyze.start', 'workflow.analyze.status'])
    )
    expect(reversePlugin.tool_surface_role).toBe('expert')
    expect(runtimePlugin.tool_surface_role).toBe('runtime_gated')
  })

  test('activates plugins and returns activated tool names', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugin: Plugin = {
      id: 'yara-test',
      name: 'YARA Test',
      description: 'YARA scan tools',
      surfaceRules: { tier: 2, category: 'malware-analysis', activateOn: { findings: ['c2'] } },
      tools: [],
    }
    surface.registerPlugin(plugin, ['yara.scan'])

    const handler = createToolsDiscoverHandler({
      getStatuses: () => [
        {
          id: plugin.id,
          name: plugin.name,
          description: plugin.description,
          status: 'loaded',
          tools: [],
        },
      ],
    } as any)

    const result = await handler({ action: 'activate', finding: 'c2' })

    expect(result.ok).toBe(true)
    expect((result.data as any).activated).toEqual(['yara-test'])
    expect((result.data as any).activated_tools).toEqual(['yara.scan'])
  })
})
