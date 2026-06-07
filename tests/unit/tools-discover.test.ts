import { describe, expect, test } from '@jest/globals'
import { z } from 'zod'
import { createToolsDiscoverHandler } from '../../src/tools/tools-discover.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import type { Plugin } from '../../src/plugins/sdk.js'

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
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
              workerBackend: {
                version: 'backend-worker.v1',
                backendName: 'FixturePEWorker',
                backendKind: 'external',
                adapter: 'fixture.pe.imports',
                availability: 'optional',
                defaultMode: 'builtin',
                supportedModes: ['builtin', 'external'],
                outputArtifactTypes: ['pe.imports.json'],
                policy: {
                  passiveByDefault: true,
                  noNetwork: true,
                  noMutation: true,
                  noLiveExecution: true,
                },
                readiness: {
                  doesNotStartBackend: true,
                  setupActions: ['Set FIXTURE_PE_WORKER_PATH for external mode.'],
                },
              },
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
      expect.arrayContaining(['workflow.search', 'workflow.run'])
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
    expect(staticPlugin.worker_backend).toEqual(
      expect.objectContaining({
        version: 'backend-worker.v1',
        backendName: 'FixturePEWorker',
        adapter: 'fixture.pe.imports',
      })
    )
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
    expect((result.data as any).activation_audit).toEqual(
      expect.objectContaining({
        action: 'activate',
        activated_plugins: ['yara-test'],
        activated_tools: ['yara.scan'],
        policy: expect.objectContaining({
          progressive_surface_enabled: true,
          discovery_required_for_hidden_tools: true,
          readiness_not_bypassed: true,
          backend_execution_started: false,
        }),
      })
    )
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
      surface.registerPlugin(
        plugin,
        plugin.tools.map((tool) => tool.definition.name)
      )
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
    expect(data.plugin_matrix.by_format['elf-executable'].tools).toContain('linux.binary.inventory')
    expect(data.plugin_matrix.by_format.container.tools).toContain('container.structure.analyze')
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

  test('filters portal results by query without requiring prior activation', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'jsvmp-test',
        name: 'JSVMP Test',
        description: 'Recover JavaScript virtual machine bytecode',
        aspects: {
          formats: ['js', 'javascript'],
          capabilities: ['jsvmp-bytecode-recovery', 'handler-map-recovery'],
        },
        surfaceRules: {
          tier: 2,
          category: 'reverse-engineering',
          activateOn: { fileTypes: ['js', 'javascript'], findings: ['jsvmp'] },
        },
        tools: [
          {
            definition: {
              name: 'jsvmp.bytecode.recover',
              description: 'Recover JSVMP bytecode',
              inputSchema: {},
              aspects: { formats: ['js'], capabilities: ['jsvmp-bytecode-recovery'] },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'pcap-test',
        name: 'PCAP Test',
        surfaceRules: {
          tier: 1,
          category: 'network-analysis',
          activateOn: { fileTypes: ['pcap'] },
        },
        tools: [
          {
            definition: {
              name: 'pcap.analyze',
              description: 'Analyze packet captures',
              inputSchema: {},
              aspects: { formats: ['pcap'], capabilities: ['network-analysis'] },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    for (const plugin of plugins) {
      surface.registerPlugin(
        plugin,
        plugin.tools.map((tool) => tool.definition.name)
      )
    }

    const handler = createToolsDiscoverHandler({
      getStatuses: () =>
        plugins.map((plugin) => ({
          id: plugin.id,
          name: plugin.name,
          description: plugin.description,
          status: 'loaded',
          tools: plugin.tools.map((tool) => tool.definition.name),
        })),
      getDiscoveredPlugins: () => plugins,
      getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
    } as any)

    const result = await handler({ action: 'list', query: 'bytecode handler' })

    expect(result.ok).toBe(true)
    const categories = (result.data as any).categories
    expect(categories).toHaveLength(1)
    expect(categories[0].plugins[0].id).toBe('jsvmp-test')
    expect(categories[0].plugins[0].activated).toBe(false)
  })

  test('uses sample_id file type as portal target and activates tier 2 format plugins explicitly', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'javascript-deobf-test',
        name: 'JavaScript Deobfuscation Test',
        aspects: { formats: ['js', 'javascript'], capabilities: ['javascript-deobfuscation'] },
        surfaceRules: {
          tier: 2,
          category: 'reverse-engineering',
          activateOn: { fileTypes: ['js', 'javascript'], findings: ['obfuscated'] },
        },
        tools: [
          {
            definition: {
              name: 'javascript.obfuscation.profile',
              description: 'Profile JavaScript obfuscation',
              inputSchema: {},
              aspects: { formats: ['js'], capabilities: ['javascript-deobfuscation'] },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    for (const plugin of plugins) {
      surface.registerPlugin(
        plugin,
        plugin.tools.map((tool) => tool.definition.name)
      )
    }
    const handler = createToolsDiscoverHandler(
      {
        getStatuses: () =>
          plugins.map((plugin) => ({
            id: plugin.id,
            name: plugin.name,
            status: 'loaded',
            tools: plugin.tools.map((tool) => tool.definition.name),
          })),
        getDiscoveredPlugins: () => plugins,
        getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
      } as any,
      { database: { findSample: () => ({ file_type: 'JavaScript' }) } }
    )

    const listed = await handler({ action: 'list', sample_id: 'sha256:js' })
    expect((listed.data as any).sample_file_type).toBe('JavaScript')
    expect((listed.data as any).target_file_type_tags).toEqual(
      expect.arrayContaining(['js', 'javascript'])
    )
    expect((listed.data as any).categories[0].plugins[0].activated).toBe(false)

    const activated = await handler({ action: 'activate', sample_id: 'sha256:js' })
    expect((activated.data as any).activated).toEqual(['javascript-deobf-test'])
    expect((activated.data as any).activated_tools).toContain('javascript.obfuscation.profile')
    expect((activated.data as any).activation_audit).toEqual(
      expect.objectContaining({
        activated_plugins: ['javascript-deobf-test'],
        policy: expect.objectContaining({
          file_type_activation_includes_tier2: true,
          backend_execution_started: false,
        }),
      })
    )
  })

  test('activates hidden core tools by tool_name', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerCoreTools([
      'workflow.analyze.start',
      'workflow.analyze.status',
      'sample.request_upload',
    ])
    surface.registerGatewayCoreTools(['tools.discover'])

    const handler = createToolsDiscoverHandler({
      getStatuses: () => [],
      getDiscoveredPlugins: () => [],
      getPlugin: () => undefined,
    } as any)

    expect(surface.isToolVisible('workflow.analyze.start')).toBe(false)
    const result = await handler({ action: 'activate', tool_name: 'workflow_analyze_start' })
    expect((result.data as any).activated_tools).toContain('workflow.analyze.start')
    expect((result.data as any).activation_audit).toEqual(
      expect.objectContaining({
        activated_core_tools: ['workflow.analyze.start'],
        policy: expect.objectContaining({
          readiness_not_bypassed: true,
          backend_execution_started: false,
        }),
      })
    )
    expect(surface.isToolVisible('workflow.analyze.start')).toBe(true)

    const uploadResult = await handler({ action: 'activate', tool_name: 'sample.request_upload' })
    expect((uploadResult.data as any).activated_tools).toContain('sample.request_upload')
    expect(surface.isToolVisible('sample.request_upload')).toBe(true)
  })

  test('searches hidden core tools through the portal', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerCoreTools(['workflow.analyze.start', 'tool.readiness'])
    surface.registerGatewayCoreTools(['tools.discover'])

    const handler = createToolsDiscoverHandler(
      {
        getStatuses: () => [],
        getDiscoveredPlugins: () => [],
        getPlugin: () => undefined,
      } as any,
      {
        toolDefinitions: () => [
          {
            name: 'workflow.analyze.start',
            description: 'Start staged analysis for a registered sample',
            inputSchema: z.object({ sample_id: z.string() }),
          },
          {
            name: 'tool.readiness',
            description: 'Check backend readiness before dynamic or expert tools',
            inputSchema: z.object({ tool_name: z.string() }),
          },
        ],
      }
    )

    const result = await handler({ action: 'list', query: 'workflow_analyze_start' })

    expect(result.ok).toBe(true)
    const coreTools = (result.data as any).core_tools
    expect(coreTools).toHaveLength(1)
    expect(coreTools[0]).toEqual(
      expect.objectContaining({
        name: 'workflow.analyze.start',
        transport_name: 'workflow_analyze_start',
        visible: false,
        tool_surface_role: 'compatibility',
      })
    )
    expect(coreTools[0].preferred_primary_tools).toEqual(['workflow.run'])
    expect(coreTools[0].next_actions).toEqual(
      expect.arrayContaining([
        'Use tools.discover action=activate tool_name=workflow.analyze.start to expose this core tool.',
      ])
    )
  })

  test('ranks explainable recommendations for hidden plugin and core tools', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerCoreTools(['workflow.analyze.start', 'tool.readiness'])
    surface.registerGatewayCoreTools(['tools.discover'])

    const plugins: Plugin[] = [
      {
        id: 'pe-static-test',
        name: 'PE Static Test',
        description: 'PE import and structure analysis',
        aspects: {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['static'],
          capabilities: ['imports', 'structure'],
          evidence: ['imports', 'structure'],
        },
        surfaceRules: {
          tier: 1,
          category: 'static-analysis',
          activateOn: { fileTypes: ['pe'] },
        },
        tools: [
          {
            definition: {
              name: 'pe.structure.analyze',
              description: 'Analyze PE structure',
              inputSchema: {},
              aspects: {
                formats: ['pe'],
                platforms: ['windows'],
                execution: ['static'],
                evidence: ['structure'],
              },
              artifacts: [{ type: 'pe.structure.json' }],
              workflowRecipes: [
                {
                  id: 'pe.structure.workflow',
                  title: 'PE structure workflow',
                  startsWith: ['pe.structure.analyze'],
                  nextTools: ['workflow.analyze.status'],
                  producesArtifacts: ['pe.structure.json'],
                  evidence: ['structure'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'pe-runtime-test',
        name: 'PE Runtime Test',
        description: 'Runtime PE behavior analysis',
        aspects: {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['dynamic'],
          runtimes: ['windows-sandbox'],
          safety: ['passive', 'opt_in_dynamic', 'requires_isolation'],
        },
        runtimePolicy: {
          passiveByDefault: true,
          requiresUserOptIn: true,
          requiresIsolation: true,
          networkPolicy: 'disabled',
        },
        surfaceRules: {
          tier: 3,
          category: 'dynamic-analysis',
          activateOn: { fileTypes: ['pe'] },
        },
        tools: [
          {
            definition: {
              name: 'sandbox.execute',
              description: 'Run isolated PE behavior collection',
              inputSchema: {},
              aspects: {
                formats: ['pe'],
                platforms: ['windows'],
                execution: ['dynamic'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]

    for (const plugin of plugins) {
      surface.registerPlugin(
        plugin,
        plugin.tools.map((tool) => tool.definition.name)
      )
    }

    const handler = createToolsDiscoverHandler(
      {
        getStatuses: () =>
          plugins.map((plugin) => ({
            id: plugin.id,
            name: plugin.name,
            description: plugin.description,
            status: 'loaded',
            tools: plugin.tools.map((tool) => tool.definition.name),
            depChecks: [],
            qualityWarnings: [],
          })),
        getDiscoveredPlugins: () => plugins,
        getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
      } as any,
      {
        toolDefinitions: () => [
          {
            name: 'workflow.analyze.start',
            description: 'Start staged analysis for a registered sample',
            inputSchema: z.object({ sample_id: z.string() }),
          },
          {
            name: 'tool.readiness',
            description: 'Check backend readiness',
            inputSchema: z.object({ tool_name: z.string() }),
          },
        ],
      }
    )

    const result = await handler({ action: 'recommend', file_type: 'PE', query: 'imports' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.action).toBe('recommend')
    expect(data.recommendations[0]).toEqual(
      expect.objectContaining({
        kind: 'plugin',
        plugin_id: 'pe-static-test',
        readiness_state: 'hidden_activation_required',
        activation_command: { action: 'activate', plugin_id: 'pe-static-test' },
      })
    )
    expect(data.recommendations[0].score).toBeGreaterThan(0)
    expect(data.recommendations[0].match_reasons).toEqual(
      expect.arrayContaining([expect.stringContaining('Matches target file type tags')])
    )
    expect(data.recommendations[0].why_hidden).toEqual(
      expect.arrayContaining(['Plugin is not currently visible in the progressive surface.'])
    )
    expect(data.recommendations.some((item: any) => item.plugin_id === 'pe-runtime-test')).toBe(
      true
    )
    const runtimeRecommendation = data.recommendations.find(
      (item: any) => item.plugin_id === 'pe-runtime-test'
    )
    expect(runtimeRecommendation.readiness_state).toBe('runtime_opt_in_required')
    expect(runtimeRecommendation.activation_plan).toEqual(
      expect.arrayContaining(['Call tool.readiness for the selected tool before execution.'])
    )
  })

  test('surfaces backend install profile gates in recommendations', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'radare2-test',
        name: 'radare2 Test',
        description: 'radare2 backend planning',
        aspects: {
          formats: ['pe', 'elf'],
          platforms: ['windows', 'linux'],
          execution: ['static'],
          capabilities: ['disassembly', 'xref-analysis'],
          evidence: ['functions', 'xrefs'],
        },
        surfaceRules: {
          tier: 3,
          category: 'reverse-engineering',
          activateOn: { fileTypes: ['pe', 'elf'] },
        },
        systemDeps: [
          {
            type: 'binary',
            name: 'radare2',
            target: '$RADARE2_PATH',
            envVar: 'RADARE2_PATH',
            dockerDefault: '/usr/local/bin/radare2',
            required: false,
            description: 'radare2 reverse-engineering framework',
            dockerFeature: 'radare2',
            dockerInstall: 'Install radare2 from distro packages or provide a pinned release',
            dockerValidation: ['radare2 -v >/dev/null 2>&1'],
            dockerInstallRoute: 'profile-gated',
            dockerInstallProfile: 'optional',
          },
        ],
        tools: [
          {
            definition: {
              name: 'radare2.analysis.plan',
              description: 'Plan radare2 disassembly workflow',
              inputSchema: {},
              aspects: {
                formats: ['pe', 'elf'],
                execution: ['static'],
                capabilities: ['disassembly'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerPlugin(plugins[0], ['radare2.analysis.plan'])

    const handler = createToolsDiscoverHandler({
      getStatuses: () => [
        {
          id: 'radare2-test',
          name: 'radare2 Test',
          description: 'radare2 backend planning',
          status: 'loaded',
          tools: ['radare2.analysis.plan'],
          depChecks: [],
          qualityWarnings: [],
        },
      ],
      getDiscoveredPlugins: () => plugins,
      getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
    } as any)

    const result = await handler({ action: 'recommend', file_type: 'PE', query: 'disassembly' })

    expect(result.ok).toBe(true)
    const recommendation = (result.data as any).recommendations.find(
      (item: any) => item.plugin_id === 'radare2-test'
    )
    expect(recommendation).toEqual(
      expect.objectContaining({
        readiness_state: 'backend_profile_required',
        backend_profile_summary: expect.objectContaining({ profile_gated: 1 }),
      })
    )
    expect(recommendation.backend_install_profile).toEqual([
      expect.objectContaining({
        docker_feature: 'radare2',
        install_route: 'profile-gated',
        install_profile: 'optional',
        enabled_by_profiles: expect.arrayContaining(['optional', 'full', 'all']),
        safety_gate: 'profile_opt_in_required',
      }),
    ])
    expect(recommendation.match_reasons).toEqual(
      expect.arrayContaining([
        expect.stringContaining('Backend install routes: radare2:profile-gated/optional'),
      ])
    )
    expect(recommendation.activation_plan).toEqual(
      expect.arrayContaining([
        'Use backend profile full for radare2 when building the analyzer image.',
      ])
    )
  })
})
