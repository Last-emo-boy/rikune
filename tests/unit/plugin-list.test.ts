import { beforeEach, describe, expect, jest, test } from '@jest/globals'

let pluginManagerMock: any
let surfaceMock: any

jest.unstable_mockModule('../../src/plugins.js', () => ({
  getPluginManager: () => pluginManagerMock,
}))

jest.unstable_mockModule('../../src/core/tool-surface-manager.js', () => ({
  getToolSurfaceManager: () => surfaceMock,
}))

const { createPluginListHandler } = await import('../../src/tools/plugin-list.js')

describe('plugin.list', () => {
  beforeEach(() => {
    const plugins = [
      {
        id: 'android-package',
        name: 'Android Package',
        executionDomain: 'static',
        aspects: {
          formats: ['apk', 'aab', 'dex'],
          platforms: ['android'],
          execution: ['static'],
          evidence: ['manifest', 'signatures'],
        },
        tools: [
          {
            definition: {
              name: 'android.package.inventory',
              description: 'Inventory Android packages',
              inputSchema: {},
              aspects: {
                formats: ['apk', 'dex'],
                platforms: ['android'],
                execution: ['static'],
                evidence: ['manifest'],
              },
              artifacts: [{ type: 'android_package_inventory' }],
              evidence: [{ category: 'manifest' }],
              workflowRecipes: [
                {
                  id: 'android.static.behavior',
                  title: 'Android static behavior',
                  startsWith: ['android.package.inventory'],
                  nextTools: ['apk.manifest.parse', 'dex.classes.list'],
                  producesArtifacts: ['android_package_inventory'],
                  evidence: ['manifest', 'workflow'],
                  safety: ['passive'],
                },
              ],
            },
          },
        ],
      },
      {
        id: 'linux-binary',
        name: 'Linux Binary',
        executionDomain: 'static',
        aspects: {
          formats: ['linux-binary', 'elf', 'elf-executable'],
          platforms: ['linux'],
          execution: ['static'],
          evidence: ['structure', 'symbols'],
        },
        tools: [
          {
            definition: {
              name: 'linux.binary.inventory',
              description: 'Inventory Linux binaries',
              inputSchema: {},
              aspects: {
                formats: ['elf-executable'],
                platforms: ['linux'],
                execution: ['static'],
                evidence: ['structure'],
              },
              artifacts: [{ type: 'linux_binary_inventory' }],
              evidence: [{ category: 'structure' }],
            },
          },
        ],
      },
    ]

    pluginManagerMock = {
      getStatuses: jest.fn(() => [
        {
          id: 'android-package',
          name: 'Android Package',
          executionDomain: 'static',
          status: 'loaded',
          tools: ['android.package.inventory'],
          qualityWarnings: [{ code: 'missing-output-schema', message: 'fixture warning' }],
        },
        {
          id: 'linux-binary',
          name: 'Linux Binary',
          executionDomain: 'static',
          status: 'skipped-deps',
          tools: ['linux.binary.inventory'],
          depChecks: [{ dep: { name: 'readelf' }, available: false, error: 'missing' }],
          qualityWarnings: [],
        },
      ]),
      getDiscoveredPlugins: jest.fn(() => plugins),
    }

    surfaceMock = {
      listCategories: jest.fn(() => [
        {
          category: 'android-analysis',
          plugins: [
            {
              id: 'android-package',
              name: 'Android Package',
              tools: ['android.package.inventory'],
              tier: 1,
              activated: true,
            },
          ],
        },
        {
          category: 'linux-analysis',
          plugins: [
            {
              id: 'linux-binary',
              name: 'Linux Binary',
              tools: ['linux.binary.inventory'],
              tier: 1,
              activated: false,
            },
          ],
        },
      ]),
    }
  })

  test('returns plugin aspect matrix and quality metadata', async () => {
    const handler = createPluginListHandler({} as any)
    const result = await handler({})

    expect(result.isError).toBeUndefined()
    const summary = result.structuredContent as any
    expect(summary.plugin_matrix.by_format.apk.tools).toContain('android.package.inventory')
    expect(summary.plugin_matrix.by_format['elf-executable'].blocked_tools).toContain(
      'linux.binary.inventory'
    )
    expect(summary.plugin_matrix.missing_deps).toEqual(
      expect.arrayContaining(['linux-binary: readelf'])
    )
    expect(summary.plugin_matrix.summary.workflow_recipe_count).toBe(1)
    expect(summary.plugin_matrix.by_workflow['android.static.behavior'].tools).toContain(
      'android.package.inventory'
    )

    const android = summary.plugins.find((plugin: any) => plugin.id === 'android-package')
    expect(android.aspects).toEqual(
      expect.objectContaining({
        formats: ['apk', 'aab', 'dex'],
        platforms: ['android'],
      })
    )
    expect(android.format_matrix.apk.tools).toContain('android.package.inventory')
    expect(android.tool_metadata[0].format_matrix.apk).toEqual(
      expect.objectContaining({
        platforms: ['android'],
        execution: ['static'],
        evidence: expect.arrayContaining(['manifest']),
        artifacts: expect.arrayContaining(['android_package_inventory']),
        workflow_recipes: expect.arrayContaining(['android.static.behavior']),
      })
    )
    expect(android.workflow_recipes).toEqual([
      expect.objectContaining({
        id: 'android.static.behavior',
        nextTools: ['apk.manifest.parse', 'dex.classes.list'],
      }),
    ])
    expect(android.tool_metadata[0].workflow_recipes).toEqual([
      expect.objectContaining({ id: 'android.static.behavior' }),
    ])
    expect(android.quality_warnings).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'missing-output-schema' })])
    )
  })
})
