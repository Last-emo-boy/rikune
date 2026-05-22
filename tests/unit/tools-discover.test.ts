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
        aspects: {
          formats: ['PE'],
          platforms: ['Windows'],
          execution: ['static'],
          capabilities: ['imports'],
          evidence: ['structure'],
        },
        surfaceRules: { tier: 1, category: 'static-analysis' },
        tools: [
          {
            definition: {
              name: 'pe.imports.extract',
              description: 'Extract PE imports',
              inputSchema: {},
              artifacts: [{ type: 'pe.imports.json', description: 'PE imports' }],
              evidence: [{ category: 'imports', artifactTypes: ['pe.imports.json'] }],
              workflowRecipes: [
                {
                  id: 'pe.imports.review',
                  title: 'PE imports review',
                  startsWith: ['pe.imports.extract'],
                  nextTools: ['analysis.evidence.graph'],
                  producesArtifacts: ['pe.imports.json'],
                  evidence: ['imports', 'workflow'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
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
        aspects: {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['dynamic'],
          runtimes: ['windows-sandbox'],
          safety: ['passive', 'opt_in_dynamic'],
        },
        runtimePolicy: {
          passiveByDefault: true,
          requiresUserOptIn: true,
          requiresIsolation: true,
          allowedBackends: ['windows-sandbox'],
          networkPolicy: 'record_only',
        },
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
          qualityWarnings:
            plugin.id === 'runtime-test'
              ? [{ code: 'missing-evidence', message: 'test warning' }]
              : [],
        })),
      getDiscoveredPlugins: () => plugins,
      getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
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
    expect(staticPlugin.aspects).toEqual(
      expect.objectContaining({
        formats: ['pe'],
        platforms: ['windows'],
        capabilities: ['imports'],
      })
    )
    expect(staticPlugin.aspect_coverage).toEqual(
      expect.arrayContaining(['formats: pe', 'platforms: windows'])
    )
    expect(staticPlugin.artifact_declarations).toEqual([
      { type: 'pe.imports.json', description: 'PE imports' },
    ])
    expect(staticPlugin.evidence_declarations).toEqual([
      { category: 'imports', artifactTypes: ['pe.imports.json'] },
    ])
    expect(staticPlugin.workflow_recipes).toEqual([
      expect.objectContaining({
        id: 'pe.imports.review',
        nextTools: ['analysis.evidence.graph'],
      }),
    ])
    expect(
      categories.find((category: any) => category.category === 'static-analysis').plugin_matrix
        .by_workflow['pe.imports.review'].tools
    ).toContain('pe.imports.extract')
    expect(reversePlugin.tool_surface_role).toBe('expert')
    expect(runtimePlugin.tool_surface_role).toBe('runtime_gated')
    expect(runtimePlugin.runtime_policy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresIsolation: true,
        networkPolicy: 'record_only',
      })
    )
    expect(runtimePlugin.quality_warnings).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'missing-evidence' })])
    )
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
      getDiscoveredPlugins: () => [plugin],
      getPlugin: (id: string) => (id === plugin.id ? plugin : undefined),
    } as any)

    const result = await handler({ action: 'activate', finding: 'c2' })

    expect(result.ok).toBe(true)
    expect((result.data as any).activated).toEqual(['yara-test'])
    expect((result.data as any).activated_tools).toEqual(['yara.scan'])
  })

  test('builds a cross-platform binary format matrix with target recommendations', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'android-package-test',
        name: 'Android Package Test',
        aspects: {
          formats: ['android-package', 'apk', 'aab', 'dex'],
          platforms: ['android'],
          execution: ['static'],
          evidence: ['manifest', 'signatures'],
        },
        surfaceRules: {
          tier: 1,
          category: 'android-analysis',
          activateOn: { fileTypes: ['apk', 'aab', 'dex', 'android-package'] },
        },
        tools: [
          {
            definition: {
              name: 'android.package.inventory',
              description: 'Inventory Android packages',
              inputSchema: {},
              aspects: {
                formats: ['apk', 'aab', 'dex'],
                platforms: ['android'],
                execution: ['static'],
                evidence: ['manifest', 'signatures'],
              },
              artifacts: [{ type: 'android_package_inventory' }],
              evidence: [{ category: 'manifest' }, { category: 'signatures' }],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'apple-signing-test',
        name: 'Apple Signing Test',
        aspects: {
          formats: ['macho', 'ipa', 'apple-signing', 'mobileprovision'],
          platforms: ['macos', 'ios'],
          execution: ['static'],
          evidence: ['certificates', 'package-metadata'],
        },
        surfaceRules: {
          tier: 1,
          category: 'apple-analysis',
          activateOn: { fileTypes: ['macho', 'ipa', 'mobileprovision'] },
        },
        tools: [
          {
            definition: {
              name: 'apple.signing.inspect',
              description: 'Inspect Apple signing metadata',
              inputSchema: {},
              aspects: {
                formats: ['macho', 'ipa', 'apple-signing'],
                platforms: ['macos', 'ios'],
                execution: ['static'],
                evidence: ['certificates'],
              },
              artifacts: [{ type: 'apple_signing_inventory' }],
              evidence: [{ category: 'certificates' }],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'linux-binary-test',
        name: 'Linux Binary Test',
        aspects: {
          formats: ['linux-binary', 'elf', 'elf-executable', 'elf-core'],
          platforms: ['linux'],
          execution: ['static'],
          evidence: ['structure', 'symbols'],
        },
        surfaceRules: {
          tier: 1,
          category: 'linux-analysis',
          activateOn: { fileTypes: ['elf', 'elf-executable', 'elf-core'] },
        },
        tools: [
          {
            definition: {
              name: 'linux.binary.inventory',
              description: 'Inventory Linux binaries',
              inputSchema: {},
              aspects: {
                formats: ['elf', 'elf-executable', 'elf-core'],
                platforms: ['linux'],
                execution: ['static'],
                evidence: ['structure', 'symbols'],
              },
              artifacts: [{ type: 'linux_binary_inventory' }],
              evidence: [{ category: 'structure' }, { category: 'symbols' }],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'firmware-container-test',
        name: 'Firmware Container Test',
        aspects: {
          formats: ['container', 'archive', 'firmware', 'squashfs'],
          platforms: ['linux', 'embedded'],
          execution: ['static'],
          evidence: ['filesystem', 'package-metadata'],
        },
        surfaceRules: {
          tier: 1,
          category: 'container-analysis',
          activateOn: { fileTypes: ['container', 'archive', 'squashfs'] },
        },
        tools: [
          {
            definition: {
              name: 'container.structure.analyze',
              description: 'Analyze nested containers',
              inputSchema: {},
              aspects: {
                formats: ['container', 'archive', 'firmware'],
                platforms: ['linux', 'embedded'],
                execution: ['static'],
                evidence: ['filesystem'],
              },
              artifacts: [{ type: 'container_structure_inventory' }],
              evidence: [{ category: 'filesystem' }],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]

    for (const plugin of plugins) {
      surface.registerPlugin(plugin, plugin.tools.map((tool) => tool.definition.name))
    }

    const handler = createToolsDiscoverHandler({
      getStatuses: () =>
        plugins.map((plugin) => ({
          id: plugin.id,
          name: plugin.name,
          status: 'loaded',
          tools: plugin.tools.map((tool) => tool.definition.name),
          depChecks: [],
          qualityWarnings: [],
        })),
      getDiscoveredPlugins: () => plugins,
      getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
    } as any)

    const result = await handler({ action: 'list', file_type: 'APK' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.target_file_type_tags).toEqual(
      expect.arrayContaining(['apk', 'android', 'dex', 'android-package'])
    )
    expect(data.plugin_matrix.by_format.apk.tools).toContain('android.package.inventory')
    expect(data.plugin_matrix.by_format.macho.tools).toContain('apple.signing.inspect')
    expect(data.plugin_matrix.by_format['elf-executable'].tools).toContain(
      'linux.binary.inventory'
    )
    expect(data.plugin_matrix.by_format.container.tools).toContain(
      'container.structure.analyze'
    )
    expect(data.recommended_tools).toContain('android.package.inventory')
    expect(data.plugin_matrix.target.matched_plugins).toContain('android-package-test')
    expect(data.available_tools).toEqual(
      expect.arrayContaining([
        'android.package.inventory',
        'apple.signing.inspect',
        'linux.binary.inventory',
        'container.structure.analyze',
      ])
    )
  })
})
