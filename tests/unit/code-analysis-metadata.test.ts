import { describe, expect, test } from '@jest/globals'
import codeAnalysisPlugin from '../../src/plugins/code-analysis/index.js'
import { codeFunctionsListToolDefinition } from '../../src/plugins/code-analysis/tools/code-functions-list.js'
import { codeFunctionsRankToolDefinition } from '../../src/plugins/code-analysis/tools/code-functions-rank.js'
import { codeFunctionsSmartRecoverToolDefinition } from '../../src/plugins/code-analysis/tools/code-functions-smart-recover.js'
import { codeFunctionsDefineToolDefinition } from '../../src/plugins/code-analysis/tools/code-functions-define.js'
import { codeFunctionsSearchToolDefinition } from '../../src/plugins/code-analysis/tools/code-functions-search.js'
import { codeXrefsAnalyzeToolDefinition } from '../../src/plugins/code-analysis/tools/code-xrefs-analyze.js'
import { codeFunctionDecompileToolDefinition } from '../../src/plugins/code-analysis/tools/code-function-decompile.js'
import { codeFunctionDisassembleToolDefinition } from '../../src/plugins/code-analysis/tools/code-function-disassemble.js'
import { codeFunctionCFGToolDefinition } from '../../src/plugins/code-analysis/tools/code-function-cfg.js'
import { codeFunctionsReconstructToolDefinition } from '../../src/plugins/code-analysis/tools/code-functions-reconstruct.js'
import { codeReconstructPlanToolDefinition } from '../../src/plugins/code-analysis/tools/code-reconstruct-plan.js'
import { codeReconstructExportToolDefinition } from '../../src/plugins/code-analysis/tools/code-reconstruct-export.js'
import { dotNetReconstructExportToolDefinition } from '../../src/plugins/code-analysis/tools/dotnet-reconstruct-export.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'
import { createToolHelpHandler } from '../../src/tools/tool-help.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import type { Plugin, ToolDefinition } from '../../src/plugins/sdk.js'

const CODE_ANALYSIS_DEFINITIONS: ToolDefinition[] = [
  codeFunctionsSmartRecoverToolDefinition,
  codeFunctionsDefineToolDefinition,
  codeFunctionsListToolDefinition,
  codeFunctionsRankToolDefinition,
  codeFunctionsSearchToolDefinition,
  codeXrefsAnalyzeToolDefinition,
  codeFunctionDecompileToolDefinition,
  codeFunctionDisassembleToolDefinition,
  codeFunctionCFGToolDefinition,
  codeFunctionsReconstructToolDefinition,
  codeReconstructPlanToolDefinition,
  codeReconstructExportToolDefinition,
  dotNetReconstructExportToolDefinition,
]

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function toolNames(plugin: Plugin): string[] {
  return (plugin.tools ?? []).map((tool) => tool.definition.name)
}

function createCodeAnalysisSearchPlugin(): Plugin {
  return {
    ...codeAnalysisPlugin,
    tools: CODE_ANALYSIS_DEFINITIONS.map((definition) => ({
      definition,
      handler: async () => ({ ok: true }),
    })),
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
        tools: toolNames(plugin),
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any
}

describe('code-analysis metadata/search/profile', () => {
  test('declares metadata for function recovery, CFG, xrefs, reconstruct, and exports', () => {
    expect(codeAnalysisPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'function-recovery',
        'function-search',
        'control-flow-graph',
        'native-export',
        'dotnet-export',
      ])
    )
    expect(codeAnalysisPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        allowedBackends: ['local'],
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(codeFunctionsSmartRecoverToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['function-boundary-recovery', 'metadata-only-handoff'])
    )
    expect(codeXrefsAnalyzeToolDefinition.evidence).toEqual(
      expect.arrayContaining([expect.objectContaining({ category: 'xrefs' })])
    )
    expect(codeFunctionCFGToolDefinition.artifacts).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: 'function_cfg_graph' })])
    )
    expect(codeFunctionsReconstructToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'code-analysis.function-reconstruct',
          nextTools: expect.arrayContaining([
            'code.reconstruct.export',
            'dotnet.reconstruct.export',
          ]),
        }),
      ])
    )
    expect(codeReconstructExportToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['native-export', 'native-reconstruct-export'])
    )
    expect(dotNetReconstructExportToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['dotnet-export', 'dotnet-reconstruct-export'])
    )
  })

  test('workflow.search matches function recovery, CFG, xref, decompile, reconstruct, consensus, and export queries', async () => {
    resetSurfaceForTest()
    const plugin = createCodeAnalysisSearchPlugin()
    const surface = getToolSurfaceManager()
    surface.registerPlugin(plugin, toolNames(plugin))
    const handler = createWorkflowSearchHandler(createPluginManager([plugin]))

    for (const query of [
      'function recovery',
      'CFG control flow graph',
      'xref cross reference',
      'decompile pseudocode',
      'reconstruct source reconstruction',
      'dotnet export',
      'native export',
    ]) {
      const result = await handler({ query, goal: 'reverse', top_k: 5 })
      expect(result.ok).toBe(true)
      const data = result.data as any
      const match = data.results.find((item: any) => item.plugin_id === 'code-analysis')
      expect(match).toEqual(
        expect.objectContaining({
          plugin_id: 'code-analysis',
        })
      )
      expect(match.score_breakdown.query_score).toBeGreaterThan(0)
      expect(match.matched_profile_fields.join(' ')).toMatch(/query terms|workflow\/tools/)
    }
  })

  test('tool.help exposes CFG and dotnet export profile metadata', async () => {
    const handler = createToolHelpHandler(() => CODE_ANALYSIS_DEFINITIONS)

    const cfgResult = await handler({
      tool_name: 'code.function.cfg',
      include_fields: false,
      include_output_schema: false,
    })
    expect(cfgResult.ok).toBe(true)
    const cfg = (cfgResult.data as any).tools[0]
    expect(cfg.name).toBe('code_function_cfg')
    expect(cfg.aspects.capabilities).toEqual(
      expect.arrayContaining(['function-cfg', 'cfg-export', 'control-flow-graph'])
    )
    expect(cfg.artifact_declarations).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: 'function_cfg_graph' })])
    )
    expect(cfg.workflow_recipes).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'code-analysis.function-cfg-export' })])
    )
    expect(cfg.runtime_policy).toEqual(
      expect.objectContaining({ noNetwork: true, noLiveExecution: true })
    )

    const dotnetResult = await handler({
      tool_name: 'dotnet.reconstruct.export',
      include_fields: false,
      include_output_schema: false,
    })
    expect(dotnetResult.ok).toBe(true)
    const dotnet = (dotnetResult.data as any).tools[0]
    expect(dotnet.aspects.capabilities).toEqual(
      expect.arrayContaining(['dotnet-export', 'managed-source-export'])
    )
    expect(dotnet.workflow_recipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'code-analysis.dotnet-reconstruct-export' }),
      ])
    )
  })
})
