import { describe, expect, test } from '@jest/globals'

import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import { createPluginTestHarness, type Plugin, type ToolDefinition } from '../../src/plugins/sdk.js'
import winePlugin from '../../src/plugins/wine/index.js'
import {
  WINE_PROFILE_NEXT_TOOLS,
  WINE_ROUTE_TERMS,
  WINE_REG_ARTIFACT_TYPE,
  WINE_RUN_ARTIFACT_TYPES,
  WINE_SEARCH_TERMS,
} from '../../src/plugins/wine/wine-metadata.js'
import { wineDllOverridesToolDefinition } from '../../src/plugins/wine/tools/wine-dll-overrides.js'
import { wineEnvToolDefinition } from '../../src/plugins/wine/tools/wine-env.js'
import { wineRegToolDefinition } from '../../src/plugins/wine/tools/wine-reg.js'
import { wineRunToolDefinition } from '../../src/plugins/wine/tools/wine-run.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'

const FORBIDDEN_DEFAULT_NEXT_TOOLS = ['sandbox.execute', 'tool.help', 'tools.discover']

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
  surface.visiblePluginTools = new Set()
}

function toolDefinitions(): ToolDefinition[] {
  return [
    wineRunToolDefinition,
    wineEnvToolDefinition,
    wineDllOverridesToolDefinition,
    wineRegToolDefinition,
  ]
}

function registeredWinePlugin(): Plugin {
  const harness = createPluginTestHarness()
  harness.registerPlugin(winePlugin)
  return {
    ...winePlugin,
    tools: harness.registeredTools.map(({ definition, handler }) => ({ definition, handler })),
  } as Plugin
}

function createPluginManager(plugins: Plugin[]) {
  return {
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
  } as any
}

function categories(definition: ToolDefinition): string[] {
  return (definition.evidence ?? []).map((item: any) => item.category)
}

describe('wine plugin metadata and search profile', () => {
  test('declares Wine as an opt-in runtime profile without network/API trace evidence', () => {
    expect(winePlugin.executionDomain).toBe('dynamic')
    expect(winePlugin.surfaceRules).toEqual({ tier: 3, category: 'dynamic-analysis' })
    expect(winePlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['pe', 'dll', 'dotnet', 'pe-clr', 'msi', 'installer'])
    )
    expect(winePlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'opt_in_dynamic',
        'requires_isolation',
        'no_live_sample_by_default',
        'no_network_by_default',
        'approval_required_for_live_execution',
      ])
    )
    expect(winePlugin.aspects?.evidence).toEqual(
      expect.arrayContaining([
        'runtime-readiness',
        'configuration',
        'filesystem',
        'registry',
        'process',
        'timeline',
        'workflow',
        'provenance',
      ])
    )
    expect(winePlugin.aspects?.evidence).not.toEqual(
      expect.arrayContaining(['network', 'api-calls'])
    )
    expect(winePlugin.aspects?.search).toEqual(
      expect.arrayContaining(['wine preflight', 'windows runtime on linux', 'dll override'])
    )
    expect(winePlugin.aspects?.route_terms).toEqual(
      expect.arrayContaining([
        'wine_compatibility_profile',
        'runtime_intent_router',
        'approval_gated_execution',
      ])
    )
    expect(winePlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'disabled',
        maxRuntimeMs: 120_000,
      })
    )
  })

  test('declares tool-level artifacts, evidence, recipes, and runtime policy boundaries', () => {
    const byName = new Map(toolDefinitions().map((definition) => [definition.name, definition]))
    const wineRun = byName.get('wine.run')!
    const wineEnv = byName.get('wine.env')!
    const wineDllOverrides = byName.get('wine.dll_overrides')!
    const wineReg = byName.get('wine.reg')!

    expect(wineRun.artifacts?.map((artifact: any) => artifact.type)).toEqual(
      WINE_RUN_ARTIFACT_TYPES
    )
    expect(categories(wineRun)).toEqual(
      expect.arrayContaining([
        'runtime-readiness',
        'process',
        'filesystem',
        'timeline',
        'workflow',
        'provenance',
      ])
    )
    expect(categories(wineRun)).not.toEqual(expect.arrayContaining(['network', 'api-calls']))
    expect(wineRun.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'wine.pe-preflight',
        startsWith: ['wine.run'],
        nextTools: WINE_PROFILE_NEXT_TOOLS,
        defaultMode: 'preflight',
        liveExecutionRequires: expect.arrayContaining(['approved=true']),
      })
    )

    expect(wineEnv.artifacts).toBeUndefined()
    expect(categories(wineEnv)).toEqual(
      expect.arrayContaining([
        'runtime-readiness',
        'configuration',
        'filesystem',
        'workflow',
        'provenance',
      ])
    )
    expect(wineEnv.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'wine.prefix-profile',
        startsWith: ['wine.env'],
        preferredActions: expect.arrayContaining(['list', 'inspect']),
      })
    )

    expect(wineDllOverrides.artifacts).toBeUndefined()
    expect(categories(wineDllOverrides)).toEqual(
      expect.arrayContaining(['configuration', 'filesystem', 'workflow', 'provenance'])
    )
    expect(wineDllOverrides.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'wine.dll-override-plan',
        startsWith: ['wine.dll_overrides'],
        preferredActions: expect.arrayContaining(['get', 'list']),
      })
    )

    expect(wineReg.artifacts?.map((artifact: any) => artifact.type)).toEqual([
      WINE_REG_ARTIFACT_TYPE,
    ])
    expect(categories(wineReg)).toEqual(
      expect.arrayContaining(['registry', 'configuration', 'workflow', 'provenance'])
    )
    expect(wineReg.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'wine.registry-profile',
        startsWith: ['wine.reg'],
        producesArtifacts: [WINE_REG_ARTIFACT_TYPE],
        preferredActions: expect.arrayContaining(['query', 'export']),
      })
    )

    for (const definition of byName.values()) {
      expect(definition.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          requiresUserOptIn: true,
          requiresIsolation: true,
          networkPolicy: 'disabled',
        })
      )
      expect(definition.aspects?.search).toEqual(expect.arrayContaining(WINE_SEARCH_TERMS))
      expect(definition.aspects?.route_terms).toEqual(expect.arrayContaining(WINE_ROUTE_TERMS))
      for (const recipe of definition.workflowRecipes ?? []) {
        expect((recipe as any).nextTools?.[0]).not.toBe('wine.run')
        for (const forbidden of FORBIDDEN_DEFAULT_NEXT_TOOLS) {
          expect((recipe as any).nextTools ?? []).not.toContain(forbidden)
        }
      }
    }
  })

  test('workflow.search finds Wine profiles without exposing runtime tools', async () => {
    resetSurfaceForTest()
    const plugin = registeredWinePlugin()
    const surface = getToolSurfaceManager()
    surface.registerPlugin(
      plugin,
      plugin.tools.map((tool) => tool.definition.name)
    )
    const handler = createWorkflowSearchHandler(createPluginManager([plugin]))

    const result = await handler({
      file_type: '.exe',
      query: 'wine preflight PE runtime registry prefix',
      goal: 'dynamic',
      top_k: 5,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const match = data.results.find((item: any) => item.plugin_id === 'wine')
    expect(match).toEqual(
      expect.objectContaining({
        plugin_id: 'wine',
        activation_required: true,
        activation_command: expect.objectContaining({
          action: 'activate',
          tool: 'workflow.search',
          via: 'workflow.search',
        }),
      })
    )
    expect(match.recommended_tools).toEqual(
      expect.arrayContaining(['wine.run', 'wine.env', 'wine.dll_overrides', 'wine.reg'])
    )
    for (const forbidden of FORBIDDEN_DEFAULT_NEXT_TOOLS) {
      expect(match.recommended_tools).not.toContain(forbidden)
    }
    expect(data.recommended_next_tools).toBeUndefined()
    for (const tool of plugin.tools.map((item) => item.definition.name)) {
      expect(surface.isToolVisible(tool)).toBe(false)
    }
  })
})
