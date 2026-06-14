import { describe, expect, test } from '@jest/globals'

import crossModulePlugin from '../../src/plugins/cross-module/index.js'
import {
  callGraphCrossModuleToolDefinition,
  CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE,
} from '../../src/plugins/cross-module/tools/call-graph-cross-module.js'
import {
  crossBinaryCompareToolDefinition,
  CROSS_BINARY_COMPARE_ARTIFACT_TYPE,
} from '../../src/plugins/cross-module/tools/cross-binary-compare.js'
import {
  dllDependencyTreeToolDefinition,
  DLL_DEPENDENCY_TREE_ARTIFACT_TYPE,
} from '../../src/plugins/cross-module/tools/dll-dependency-tree.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import type { Plugin } from '../../src/plugins/sdk.js'

function expectPassiveNoSideEffects(policy: Record<string, unknown> | undefined) {
  expect(policy).toEqual(
    expect.objectContaining({
      passiveByDefault: true,
      requiresUserOptIn: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      networkPolicy: 'disabled',
    })
  )
}

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function createCrossModuleSearchPlugin(): Plugin {
  return {
    ...crossModulePlugin,
    tools: [
      {
        definition: crossBinaryCompareToolDefinition,
        handler: async () => ({ ok: true }),
      },
      {
        definition: callGraphCrossModuleToolDefinition,
        handler: async () => ({ ok: true }),
      },
      {
        definition: dllDependencyTreeToolDefinition,
        handler: async () => ({ ok: true }),
      },
    ],
  }
}

function createPluginManager(plugins: Plugin[]) {
  return {
    getStatuses: () =>
      plugins.map((plugin) => ({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        status: 'loaded',
        tools: (plugin.tools ?? []).map((tool) => tool.definition.name),
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any
}

describe('cross-module metadata deepening', () => {
  test('plugin exposes cross-module search and passive profile tags', () => {
    expect(crossModulePlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['pe', 'dll', 'exe', 'elf', 'so', 'macho', 'dylib', 'native'])
    )
    expect(crossModulePlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'dependency-graph',
        'dependency-tree',
        'dll-dependency',
        'cross-module',
        'call-graph',
        'imports/exports/symbols/call-graph',
        'search-profile',
        'workflow-handoff',
        'metadata-only-handoff',
      ])
    )
    expect(crossModulePlugin.aspects?.evidence).toEqual(
      expect.arrayContaining([
        'imports',
        'exports',
        'symbols',
        'dependency-graph',
        'call-graph',
        'dll-dependency',
        'workflow',
        'provenance',
      ])
    )
    expectPassiveNoSideEffects(crossModulePlugin.runtimePolicy as Record<string, unknown>)
  })

  test('tools declare artifacts, evidence, workflows, and passive runtime policy', () => {
    expect(crossBinaryCompareToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: CROSS_BINARY_COMPARE_ARTIFACT_TYPE,
          mimeTypes: expect.arrayContaining(['application/json']),
        }),
      ])
    )
    expect(callGraphCrossModuleToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE,
          mimeTypes: expect.arrayContaining(['application/json']),
        }),
      ])
    )
    expect(dllDependencyTreeToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: DLL_DEPENDENCY_TREE_ARTIFACT_TYPE,
          mimeTypes: expect.arrayContaining(['application/json']),
        }),
      ])
    )

    expect(callGraphCrossModuleToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'imports' }),
        expect.objectContaining({ category: 'exports' }),
        expect.objectContaining({ category: 'symbols' }),
        expect.objectContaining({ category: 'call-graph' }),
        expect.objectContaining({ category: 'dependency-graph' }),
        expect.objectContaining({ category: 'cross-module' }),
      ])
    )
    expect(dllDependencyTreeToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'dll-dependency' }),
        expect.objectContaining({ category: 'dependency-tree' }),
        expect.objectContaining({ category: 'dependency-graph' }),
        expect.objectContaining({ category: 'sideload-risk' }),
      ])
    )

    for (const definition of [
      crossBinaryCompareToolDefinition,
      callGraphCrossModuleToolDefinition,
      dllDependencyTreeToolDefinition,
    ]) {
      expect(definition.workflowRecipes?.[0]).toEqual(
        expect.objectContaining({
          nextTools: expect.arrayContaining([
            'pe.imports.extract',
            'elf.imports.extract',
            'macho.structure.analyze',
            'native.object.inventory',
            'analysis.evidence.graph',
            'report.generate',
          ]),
          requiredArtifacts: expect.arrayContaining(['sample']),
          safety: expect.arrayContaining([
            'passive',
            'no_network_by_default',
            'no_mutation',
            'no_live_sample_by_default',
            'no_sample_execution',
          ]),
        })
      )
      expectPassiveNoSideEffects(definition.runtimePolicy as Record<string, unknown>)
      expect(definition.workerBackend).toBeUndefined()
    }
  })

  test('workflow.search recalls cross-module tools for dependency and call graph queries', async () => {
    resetSurfaceForTest()
    const plugin = createCrossModuleSearchPlugin()
    const surface = getToolSurfaceManager()
    surface.registerPlugin(
      plugin,
      (plugin.tools ?? []).map((tool) => tool.definition.name)
    )
    const handler = createWorkflowSearchHandler(createPluginManager([plugin]))

    const queries = [
      {
        query: 'dependency graph cross-module',
        expectedTool: 'call.graph.cross.module',
      },
      {
        query: 'DLL dependency',
        expectedTool: 'dll.dependency.tree',
      },
      {
        query: 'imports/exports/symbols/call graph',
        expectedTool: 'call.graph.cross.module',
      },
    ]

    for (const { query, expectedTool } of queries) {
      const result = await handler({ query, top_k: 5 })
      expect(result.ok).toBe(true)

      const data = result.data as any
      const crossModuleResult = data.results.find(
        (item: Record<string, unknown>) => item.plugin_id === 'cross-module'
      )

      expect(crossModuleResult).toEqual(
        expect.objectContaining({
          plugin_id: 'cross-module',
          recommended_tools: expect.arrayContaining([expectedTool]),
        })
      )
      expect(data.search_profile.recommended_tools).toEqual(
        expect.arrayContaining([expectedTool])
      )
    }
  })
})
