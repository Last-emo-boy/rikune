import { describe, expect, test } from '@jest/globals'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import gtirbPlugin from '../../src/plugins/gtirb/index.js'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'
import {
  expectFrontierWorkerTool,
  expectFrontierWorkerRejectsExternal,
} from './frontier-worker-test-utils.js'

describe('gtirb worker', () => {
  function toolNames() {
    return (gtirbPlugin.tools ?? []).map((tool) => tool.definition.name)
  }

  function createPluginManager() {
    return {
      getStatuses: () => [
        {
          id: gtirbPlugin.id,
          name: gtirbPlugin.name,
          description: gtirbPlugin.description,
          status: 'loaded',
          tools: toolNames(),
          depChecks: [],
          qualityWarnings: [],
        },
      ],
      getDiscoveredPlugins: () => [gtirbPlugin],
      getPlugin: (id: string) => (id === gtirbPlugin.id ? gtirbPlugin : undefined),
    } as any
  }

  function resetSurfaceForSearchTest() {
    const surface = getToolSurfaceManager() as any
    surface.entries = new Map()
    surface.visiblePluginTools = new Set()
    surface.coreTools = new Set()
    surface.visibleCoreTools = new Set()
  }

  function registeredTool(name: string) {
    const harness = createPluginTestHarness()
    harness.registerPlugin(gtirbPlugin)
    const tool = harness.registeredTools.find((entry) => entry.definition.name === name)
    expect(tool).toBeDefined()
    return tool!
  }

  test('declares GTIRB search profile, route terms, and handoff metadata', () => {
    expect(gtirbPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(gtirbPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'search-profile',
        'workflow-handoff',
        'metadata-only-handoff',
        'binary-ir-handoff',
        'cfg-symbol-handoff',
        'rewrite-boundary-handoff',
        'cross-backend-ir-comparison',
      ])
    )
    expect(gtirbPlugin.aspects?.evidence).toEqual(
      expect.arrayContaining(['cfg', 'function-boundaries', 'relocations', 'aux-data'])
    )
    expect(gtirbPlugin.aspects?.search).toEqual(
      expect.arrayContaining([
        'gtirb',
        'binary ir',
        'cfg recovery',
        'symbol correlation',
        'rewrite boundary',
      ])
    )
    expect(gtirbPlugin.aspects?.profile).toEqual(
      expect.arrayContaining([
        'gtirb-ir-profile',
        'cfg-symbol-profile',
        'rewrite-boundary-profile',
        'cross-backend-ir-profile',
      ])
    )
    expect(gtirbPlugin.aspects?.route_terms).toEqual(
      expect.arrayContaining([
        'gtirb_ir_handoff',
        'cfg_symbol_handoff',
        'rewrite_boundary_handoff',
        'cross_backend_ir_comparison',
      ])
    )
    expect(gtirbPlugin.surfaceRules?.activateOn?.findings).toEqual(
      expect.arrayContaining([
        'gtirb',
        'ir-generation',
        'rewrite-boundary',
        'symbol-correlation',
        'cross-backend-check',
      ])
    )

    const planTool = registeredTool('gtirb.ir.plan').definition
    expect(planTool.aspects?.route_terms).toEqual(
      expect.arrayContaining(['gtirb_ir_handoff', 'rewrite_boundary_handoff'])
    )
    expect(planTool.runtimePolicy).toEqual(
      expect.objectContaining({ passiveByDefault: true, noNetwork: true, noMutation: true })
    )

    const workerTool = registeredTool('gtirb.ir.generate').definition
    expect(workerTool.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'gtirb_ir_artifact' }),
        expect.objectContaining({ type: 'gtirb_cfg_summary' }),
        expect.objectContaining({ type: 'gtirb_aux_data_summary' }),
      ])
    )
    expect(workerTool.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'cfg' }),
        expect.objectContaining({ category: 'aux-data' }),
        expect.objectContaining({ category: 'workflow' }),
        expect.objectContaining({ category: 'provenance' }),
      ])
    )
    expect(workerTool.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'gtirb.binary.ir-worker',
        nextTools: expect.arrayContaining([
          'remill.lift.run',
          'manifold.fact.extract',
          'analysis.evidence.graph',
          'artifact.read',
        ]),
        producesArtifacts: expect.arrayContaining([
          'gtirb_ir_artifact',
          'gtirb_cfg_summary',
          'gtirb_aux_data_summary',
        ]),
        routeTerms: expect.arrayContaining(['gtirb_ir_handoff', 'cfg_symbol_handoff']),
      })
    )
    expect(workerTool.workerBackend?.outputArtifactTypes).toEqual(
      expect.arrayContaining(['gtirb_ir_artifact', 'gtirb_cfg_summary', 'gtirb_aux_data_summary'])
    )
  })

  test('workflow.search matches GTIRB IR, CFG, aux data, and rewrite boundary terms', async () => {
    resetSurfaceForSearchTest()
    getToolSurfaceManager().registerPlugin(gtirbPlugin, toolNames())
    const handler = createWorkflowSearchHandler(createPluginManager())

    const result = await handler({
      query: 'gtirb binary ir cfg edges aux data rewrite boundary',
      goal: 'reverse',
      top_k: 5,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const match = data.results.find((item: any) => item.plugin_id === 'gtirb')
    expect(match).toEqual(
      expect.objectContaining({
        plugin_id: 'gtirb',
        recommended_tools: expect.arrayContaining(['gtirb.ir.plan', 'gtirb.ir.generate']),
        workflow_id: expect.stringMatching(/^gtirb\./),
      })
    )
    expect(match.score_breakdown.query_score).toBeGreaterThan(0)
    expect(match.matched_profile_fields.join(' ')).toMatch(/query terms|workflow\/tools/)
  })

  test('plan returns GTIRB evidence, workflow handoff, and quality gates', async () => {
    const tool = registeredTool('gtirb.ir.plan')
    const result = await tool.handler({
      sample_id: 'sha256:gtirb-plan',
      goals: ['cfg', 'rewrite-boundary'],
      static_evidence: ['pe_structure_analysis', 'function_index'],
    })

    expect((result as any).ok).toBe(true)
    const data = (result as any).data
    expect(data.status).toBe('plan_only')
    expect(data.policy).toEqual(
      expect.objectContaining({ no_backend_start: true, no_network: true })
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.gtirb_ir.evidence_summary.v1',
        source_tool: 'gtirb.ir.plan',
        mode: 'plan',
        read_only_ir_only: true,
        route_terms: expect.arrayContaining(['gtirb_ir_handoff', 'rewrite_boundary_handoff']),
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.gtirb_ir.workflow_handoff.v1',
        handoff_mode: 'gtirb_ir_to_lifting_rewrite_boundary_and_cross_backend_comparison',
        routing: expect.arrayContaining([
          expect.objectContaining({ goal: 'cfg-symbol-correlation' }),
          expect.objectContaining({ goal: 'cross-backend-lift-comparison' }),
          expect.objectContaining({ goal: 'rewrite-boundary-review' }),
        ]),
      })
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        passive_static_only: true,
        sample_execution_allowed: false,
        network_allowed: false,
        mutation_allowed: false,
        binary_rewrite_allowed: false,
        binary_rewrite_performed: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.gtirb_ir.quality_gates.v1',
        passive_static_only: true,
        read_only_ir_generation: true,
        local_artifact_only: true,
        rewrite_boundary_declared: true,
        sample_executed_by_tool: false,
        network_used_by_tool: false,
        mutation_performed: false,
        binary_rewrite_performed: false,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['analysis.evidence.graph', 'artifact.read', 'workflow.search'])
    )
  })

  test('runs builtin read-only IR generation contract', async () => {
    await expectFrontierWorkerTool({
      pluginId: 'gtirb',
      toolName: 'gtirb.ir.generate',
      backendName: 'GTIRB',
      fixtureKey: 'cfg_blocks',
      args: { target: { architecture: 'x64' } },
    })
  })

  test('worker returns GTIRB handoff envelope and read-only gates', async () => {
    const tool = registeredTool('gtirb.ir.generate')
    const result = await tool.handler({
      path: 'fixtures/sample.exe',
      mode: 'builtin',
      preview: true,
      goals: ['cfg-symbol-correlation'],
      passes: ['cfg', 'symbols'],
      target: { architecture: 'x64', function: 'entry' },
    })

    expect((result as any).ok).toBe(true)
    const data = (result as any).data
    expect(data).toEqual(
      expect.objectContaining({
        plugin_id: 'gtirb',
        schema_version: 'rikune.gtirb_ir.fixture_summary.v1',
        cfg_blocks: 3,
        read_only: true,
        rewrite_allowed: false,
        raw_generation_performed: false,
        backend_wrapper_required: true,
        aux_data_tables: expect.arrayContaining(['functionEntries', 'symbolForwarding']),
      })
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.gtirb_ir.evidence_summary.v1',
        source_tool: 'gtirb.ir.generate',
        mode: 'worker',
        cfg_blocks: 3,
        symbols: expect.arrayContaining(['entry', 'func_0']),
        read_only_ir_only: true,
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'cfg-symbol-correlation',
          next_tools: expect.arrayContaining(['manifold.fact.extract', 'analysis.evidence.graph']),
        }),
        expect.objectContaining({
          goal: 'rewrite-boundary-review',
          next_tools: expect.arrayContaining(['artifact.read', 'report.generate']),
        }),
      ])
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        passive_static_only: true,
        sample_execution_allowed: false,
        network_allowed: false,
        mutation_allowed: false,
        binary_rewrite_allowed: false,
        sample_executed_by_tool: false,
        network_used_by_tool: false,
        mutation_performed: false,
        binary_rewrite_performed: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.gtirb_ir.quality_gates.v1',
        passive_static_only: true,
        read_only_ir_generation: true,
        read_only_ir_only: true,
        cfg_summary_present: true,
        symbol_summary_present: true,
        rewrite_boundary_declared: true,
        sample_executed_by_tool: false,
        network_used_by_tool: false,
        mutation_performed: false,
        binary_rewrite_performed: false,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'remill.lift.run',
        'manifold.fact.extract',
        'analysis.evidence.graph',
        'artifact.read',
      ])
    )
    expect(data.selected_passes).toEqual(['cfg', 'symbols'])
    expect(data.goals).toEqual(['cfg-symbol-correlation'])
    expect(data.target).toEqual(expect.objectContaining({ architecture: 'x64', function: 'entry' }))
  })

  test('rejects external backend without explicit opt-in', async () => {
    await expectFrontierWorkerRejectsExternal({
      pluginId: 'gtirb',
      toolName: 'gtirb.ir.generate',
    })
  })
})
