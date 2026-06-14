import { describe, expect, test } from '@jest/globals'
import officeAnalysisPlugin from '../../src/plugins/office-analysis/index.js'
import {
  officeVbaExtractToolDefinition,
  OFFICE_VBA_EXTRACT_ARTIFACT_TYPE,
} from '../../src/plugins/office-analysis/tools/office-vba-extract.js'
import {
  officeMacroDetectToolDefinition,
  OFFICE_MACRO_DETECTION_ARTIFACT_TYPE,
} from '../../src/plugins/office-analysis/tools/office-macro-detect.js'
import {
  officeOleAnalyzeToolDefinition,
  OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE,
} from '../../src/plugins/office-analysis/tools/office-ole-analyze.js'
import { officeBehaviorProfileToolDefinition } from '../../src/plugins/office-analysis/tools/office-behavior-profile.js'
import { OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE } from '../../src/plugins/office-analysis/office-analysis-metadata.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import type { Plugin } from '../../src/plugins/sdk.js'

function resetSurfaceForSearchTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function toolNames(plugin: Plugin): string[] {
  return (plugin.tools ?? []).map((tool) => tool.definition.name)
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

function expectPassiveStaticPolicy(policy: Record<string, unknown> | undefined) {
  expect(policy).toEqual(
    expect.objectContaining({
      passiveByDefault: true,
      requiresUserOptIn: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      noOfficeAutomation: true,
      noMacroExecution: true,
    })
  )
}

describe('office-analysis metadata/search/profile', () => {
  test('declares office search profile tags, artifacts, evidence, workflows, and runtime policy', () => {
    expect(officeAnalysisPlugin.tools?.map((tool) => tool.definition.name)).toEqual(
      expect.arrayContaining([
        'office.vba.extract',
        'office.macro.detect',
        'office.ole.analyze',
        'office.behavior.profile',
      ])
    )
    expect(officeAnalysisPlugin.aspects?.search).toEqual(
      expect.arrayContaining([
        'office',
        'vba macro',
        'ole',
        'excel macro',
        'malicious document',
        'behavior profile',
        'static only',
      ])
    )
    expectPassiveStaticPolicy(officeAnalysisPlugin.runtimePolicy as Record<string, unknown>)

    const definitions = [
      officeVbaExtractToolDefinition,
      officeMacroDetectToolDefinition,
      officeOleAnalyzeToolDefinition,
      officeBehaviorProfileToolDefinition,
    ]
    for (const definition of definitions) {
      expect(definition.aspects?.formats).toEqual(
        expect.arrayContaining(['office', 'docm', 'xlsm', 'ole', 'ooxml'])
      )
      expect(definition.aspects?.search).toEqual(
        expect.arrayContaining(['office', 'vba macro', 'ole', 'malicious document', 'static only'])
      )
      expect(definition.workflowRecipes?.length).toBeGreaterThan(0)
      expect(definition.evidence).toEqual(
        expect.arrayContaining([expect.objectContaining({ category: 'workflow' })])
      )
      expectPassiveStaticPolicy(definition.runtimePolicy as Record<string, unknown>)
    }

    expect(officeVbaExtractToolDefinition.artifacts).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: OFFICE_VBA_EXTRACT_ARTIFACT_TYPE })])
    )
    expect(officeMacroDetectToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: OFFICE_MACRO_DETECTION_ARTIFACT_TYPE, required: false }),
      ])
    )
    expect(officeOleAnalyzeToolDefinition.artifacts).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE })])
    )
    expect(officeBehaviorProfileToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE, required: false }),
      ])
    )

    expect(OFFICE_MACRO_DETECTION_ARTIFACT_TYPE).toBe('backend_office_macro_detection')
    expect(officeVbaExtractToolDefinition.workerBackend?.outputArtifactTypes).toEqual([
      OFFICE_VBA_EXTRACT_ARTIFACT_TYPE,
    ])
    expect(officeMacroDetectToolDefinition.workerBackend?.outputArtifactTypes).toEqual([
      OFFICE_MACRO_DETECTION_ARTIFACT_TYPE,
    ])
    expect(officeOleAnalyzeToolDefinition.workerBackend?.outputArtifactTypes).toEqual([
      OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE,
    ])
    expect(officeBehaviorProfileToolDefinition.workerBackend).toBeUndefined()
  })

  test('workflow.search matches office, VBA macro, OLE, Excel macro, malicious document, behavior profile, and static-only queries', async () => {
    resetSurfaceForSearchTest()
    const surface = getToolSurfaceManager()
    surface.registerPlugin(officeAnalysisPlugin, toolNames(officeAnalysisPlugin))
    const handler = createWorkflowSearchHandler(createPluginManager([officeAnalysisPlugin]))

    for (const query of [
      'office',
      'VBA macro',
      'OLE',
      'Excel macro',
      'malicious document',
      'behavior profile',
      'static-only',
    ]) {
      const result = await handler({ query, goal: 'static', top_k: 5 })
      expect(result.ok).toBe(true)
      const data = result.data as any
      const match = data.results.find((item: any) => item.plugin_id === 'office-analysis')
      expect(match).toEqual(
        expect.objectContaining({
          plugin_id: 'office-analysis',
          workflow_id: expect.stringMatching(/^office\./),
          available_tools: expect.arrayContaining([
            'office.vba.extract',
            'office.macro.detect',
            'office.ole.analyze',
            'office.behavior.profile',
          ]),
        })
      )
      expect(match.matched_profile_fields.join(' ')).toMatch(/query terms|workflow\/tools/)
    }
  })

  test('behavior profile workflow recipe names required upstream office artifacts', () => {
    expect(officeBehaviorProfileToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'office.macro.static-profile',
        requiredArtifacts: expect.arrayContaining([
          OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE,
          OFFICE_MACRO_DETECTION_ARTIFACT_TYPE,
          OFFICE_VBA_EXTRACT_ARTIFACT_TYPE,
        ]),
        producesArtifacts: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE],
        nextTools: expect.arrayContaining(['ioc.export', 'yara.generate', 'workflow.search']),
      })
    )
  })
})
