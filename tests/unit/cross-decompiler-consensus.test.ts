import { describe, expect, test } from '@jest/globals'
import { z } from 'zod'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import codeAnalysisPlugin from '../../src/plugins/code-analysis/index.js'
import {
  createCrossDecompilerConsensusHandler,
  crossDecompilerConsensusToolDefinition,
} from '../../src/plugins/code-analysis/tools/cross-decompiler-consensus.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import { createToolsDiscoverHandler } from '../../src/tools/tools-discover.js'

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

const fixtureArtifacts = [
  {
    backend: 'Ghidra',
    tool_name: 'ghidra.analyze',
    backend_version: '11.x-fixture',
    artifact_type: 'ghidra_analysis',
    artifact_id: 'artifact:ghidra',
    confidence: 0.9,
    provenance: { source: 'unit-test', fixture: true },
    functions: [
      {
        address: '0x401000',
        name: 'main',
        signature: 'int main(void)',
        calls: ['CreateFileA', 'helper'],
        xrefs: ['entry'],
        strings: ['config.dat'],
        constants: ['0x10'],
        cfg_shape: { blocks: 4, edges: 5, loops: 1 },
        decompiled_text_hash: 'text-main-a',
        ir_fact_hash: 'ir-main',
        confidence: 0.92,
      },
      {
        address: '0x401080',
        name: 'helper',
        signature: 'int helper(int)',
        calls: ['CloseHandle'],
        strings: ['done'],
        constants: ['0x2'],
        cfg_shape: { blocks: 2, edges: 1, loops: 0 },
        decompiled_text_hash: 'text-helper',
        ir_fact_hash: 'ir-helper',
        confidence: 0.88,
      },
    ],
  },
  {
    backend: 'radare2',
    tool_name: 'radare2.pipeline.run',
    backend_version: '5.x-fixture',
    artifact_type: 'radare2_function_index',
    artifact_id: 'artifact:r2',
    confidence: 0.82,
    provenance: { source: 'unit-test', fixture: true },
    functions: [
      {
        address: '0x401000',
        name: 'entry_main',
        signature: 'int main(int argc, char **argv)',
        calls: ['CreateFileA', 'helper'],
        xrefs: ['entry'],
        strings: ['config.dat'],
        constants: ['0x10'],
        cfg_shape: { blocks: 5, edges: 6, loops: 1 },
        decompiled_text_hash: 'text-main-b',
        ir_fact_hash: 'ir-main',
        confidence: 0.8,
      },
      {
        address: '0x401080',
        name: 'helper',
        signature: 'int helper(int)',
        calls: ['CloseHandle'],
        strings: ['done'],
        constants: ['0x2'],
        cfg_shape: { blocks: 2, edges: 1, loops: 0 },
        decompiled_text_hash: 'text-helper',
        ir_fact_hash: 'ir-helper',
        confidence: 0.76,
      },
    ],
  },
]

describe('code.cross_decompiler.consensus', () => {
  test('compares fixture artifacts without starting external backends', async () => {
    const handler = createCrossDecompilerConsensusHandler()

    const result = await handler({
      sample_id: 'sha256:fixture',
      artifacts: fixtureArtifacts,
      expected_backends: ['ghidra', 'radare2', 'retdec', 'gtirb'],
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'static_fixture_consensus',
        live_execution: false,
        backend_process_started: false,
        network_access: false,
        mutation: false,
      })
    )
    expect(data.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_backend_start: true,
        no_live_sample_execution: true,
        no_network: true,
        read_only: true,
      })
    )
    expect(data.artifact_summary.backends_present).toEqual(
      expect.arrayContaining(['ghidra', 'radare2'])
    )
    expect(data.agreement.functions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          key: 'addr:0x401000',
          backends: expect.arrayContaining(['ghidra', 'radare2']),
          shared_calls: expect.arrayContaining(['createfilea', 'helper']),
          shared_strings: expect.arrayContaining(['config.dat']),
          ir_fact_hashes: ['ir-main'],
        }),
        expect.objectContaining({
          key: 'addr:0x401080',
          names: ['helper'],
          decompiled_text_hashes: ['text-helper'],
        }),
      ])
    )
    expect(data.disagreement.count).toBeGreaterThanOrEqual(1)
    expect(data.disagreement.functions[0].conflicts.map((conflict: any) => conflict.field)).toEqual(
      expect.arrayContaining(['signature', 'cfg_shape'])
    )
    expect(data.missing_backend_gaps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          backend: 'retdec',
          recommended_tools: expect.arrayContaining(['retdec.decompile']),
        }),
        expect.objectContaining({
          backend: 'gtirb',
          recommended_tools: expect.arrayContaining(['gtirb.ir.generate']),
        }),
      ])
    )
    expect(data.backend_coverage).toEqual(
      expect.objectContaining({
        schema: 'rikune.cross_decompiler.backend_coverage.v1',
        coverage_score: 0.5,
        present_backends: expect.arrayContaining(['ghidra', 'radare2']),
        missing_backends: expect.arrayContaining(['retdec', 'gtirb']),
      })
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.cross_decompiler.evidence_summary.v1',
        agreement_count: 2,
        disagreement_count: expect.any(Number),
        missing_backend_count: 2,
      })
    )
    expect(data.function_evidence_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.cross_decompiler.function_evidence_handoff.v1',
        handoff_mode: 'function_evidence_consensus',
      })
    )
    expect(data.function_evidence_handoff.stable_functions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          key: 'addr:0x401080',
          recommended_tools: expect.arrayContaining(['code.functions.reconstruct']),
        }),
      ])
    )
    expect(data.function_evidence_handoff.disputed_functions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          key: 'addr:0x401000',
          severity: 'high',
          recommended_tools: expect.arrayContaining(['code.function.cfg']),
        }),
      ])
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        passive_fixture_only: true,
        backend_process_started: false,
        sample_executed: false,
        network_accessed: false,
        minimum_backend_count_met: true,
        expected_backend_coverage_met: false,
        analyst_review_required: true,
      })
    )
    expect(data.follow_up_recommendations).toEqual(
      expect.arrayContaining(['code.function.cfg', 'analysis.evidence.graph'])
    )
    expect(data.evidence_graph.nodes.length).toBeGreaterThan(0)
    expect(result.warnings?.[0]).toContain('Missing 2 expected backend')
  })

  test('is registered by code-analysis with workflow metadata', () => {
    const harness = createPluginTestHarness()
    const registeredNames = harness.registerPlugin(codeAnalysisPlugin)
    const tool = harness.registeredTools.find(
      (entry) => entry.definition.name === 'code.cross_decompiler.consensus'
    )

    expect(registeredNames).toContain('code.cross_decompiler.consensus')
    expect(tool).toBeDefined()
    expect(tool!.definition.aspects?.formats).toEqual(
      expect.arrayContaining(['pe', 'elf', 'macho', 'firmware', 'object'])
    )
    expect(tool!.definition.artifacts?.map((artifact) => artifact.type)).toContain(
      'cross_decompiler_consensus'
    )
    expect(tool!.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'reverse.cross-decompiler.consensus',
        nextTools: expect.arrayContaining([
          'ghidra.analyze',
          'retdec.decompile',
          'radare2.pipeline.run',
          'analysis.evidence.graph',
        ]),
      })
    )
    expect(crossDecompilerConsensusToolDefinition.workerBackend).toBeUndefined()
  })

  test('is discoverable by PE reverse-engineering goals before activation', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const harness = createPluginTestHarness()
    const tools = harness.registerPlugin(codeAnalysisPlugin)
    surface.registerPlugin(codeAnalysisPlugin, tools)

    const registeredDefinitions = harness.registeredTools.map((entry) => entry.definition)
    const pluginWithDefinitions = {
      ...codeAnalysisPlugin,
      tools: harness.registeredTools.map((entry) => ({
        definition: entry.definition,
        handler: entry.handler,
      })),
    }
    const handler = createToolsDiscoverHandler(
      {
        getStatuses: () => [
          {
            id: codeAnalysisPlugin.id,
            name: codeAnalysisPlugin.name,
            description: codeAnalysisPlugin.description,
            status: 'loaded',
            tools,
            depChecks: [],
            qualityWarnings: [],
          },
        ],
        getDiscoveredPlugins: () => [pluginWithDefinitions],
        getPlugin: (id: string) =>
          id === codeAnalysisPlugin.id ? pluginWithDefinitions : undefined,
      } as any,
      {
        toolDefinitions: () => [
          {
            name: 'tool.readiness',
            description: 'Check tool readiness',
            inputSchema: z.object({ tool_name: z.string() }),
          },
          ...registeredDefinitions,
        ],
      }
    )

    const result = await handler({
      action: 'recommend',
      file_type: 'PE',
      query: 'cross decompiler consensus ir',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const codeAnalysis = data.recommendations.find(
      (item: any) => item.plugin_id === 'code-analysis'
    )
    expect(codeAnalysis).toEqual(
      expect.objectContaining({
        readiness_state: 'runtime_opt_in_required',
        activation_command: expect.objectContaining({
          action: 'activate',
          plugin_id: 'code-analysis',
        }),
      })
    )
    expect(codeAnalysis.available_tools).toContain('code.cross_decompiler.consensus')
    expect(codeAnalysis.workflow_recipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'reverse.cross-decompiler.consensus' }),
      ])
    )
    expect(data.recommended_tools).toContain('code.cross_decompiler.consensus')
  })
})
