import { describe, expect, test } from '@jest/globals'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import { createPluginTestHarness, type Plugin, type ToolDefinition } from '../../src/plugins/sdk.js'
import wasmPlugin from '../../src/plugins/wasm/index.js'
import wasmRuntimePlugin from '../../src/plugins/wasm-runtime/index.js'
import { createToolReadinessHandler } from '../../src/tools/tool-readiness.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function createPluginManager(plugins: Plugin[]) {
  return {
    getPluginForTool: (toolName: string) =>
      plugins.find((plugin) =>
        plugin.tools.some((tool) => tool.definition.name === toolName)
      )?.id,
    getStatuses: () =>
      plugins.map((plugin) => ({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        status: 'loaded',
        executionDomain: plugin.executionDomain,
        reasonCode: null,
        statusDetail: 'loaded',
        tools: plugin.tools.map((tool) => tool.definition.name),
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any
}

function allToolDefinitions(plugins: Plugin[]): ToolDefinition[] {
  return plugins.flatMap((plugin) => plugin.tools.map((tool) => tool.definition))
}

describe('wasm.runtime.plan readiness metadata', () => {
  test('declares WASM/WAT runtime plan metadata without opening runtime execution paths', () => {
    const harness = createPluginTestHarness()
    harness.registerPlugin(wasmRuntimePlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'wasm.runtime.plan'
    )

    expect(wasmRuntimePlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['wasm', 'wasi', 'wat'])
    )
    expect(wasmRuntimePlugin.aspects?.architectures).toEqual(
      expect.arrayContaining(['wasm', 'wasm32'])
    )
    expect(wasmRuntimePlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'wasi-capability-plan',
        'resource-grant-review',
        'preopen-policy-review',
        'network-policy-review',
        'custom-section-provenance',
      ])
    )
    expect(wasmRuntimePlugin.aspects?.evidence).toEqual(
      expect.arrayContaining([
        'imports',
        'exports',
        'wasi-capability',
        'custom-section',
        'resource-grant',
        'workflow',
        'provenance',
      ])
    )
    expect(wasmRuntimePlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'disabled',
        noInstantiation: true,
        noWasiGrants: true,
        noResourceGrants: true,
        resourceGrants: 'none',
      })
    )
    expect(wasmRuntimePlugin.systemDeps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'binary',
          name: 'wasmtime',
          envVar: 'WASMTIME_PATH',
          required: false,
          dockerInstallProfile: 'runtime',
        }),
      ])
    )
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'wasm.runtime.opt-in',
        startsWith: expect.arrayContaining(['wasm.runtime.plan', 'tool.readiness']),
        nextTools: expect.arrayContaining([
          'tool.readiness',
          'artifact.read',
          'analysis.evidence.graph',
          'dynamic.runtime.status',
        ]),
        evidence: expect.arrayContaining([
          'imports',
          'exports',
          'wasi-capability',
          'custom-section',
          'resource-grant',
          'provenance',
        ]),
        safety: expect.arrayContaining([
          'passive',
          'requires_isolation',
          'no_live_sample_by_default',
          'no_network_by_default',
        ]),
        runtimeBackends: ['wasmtime'],
      })
    )
    expect(tool?.definition.runtime).toBeUndefined()
  })

  test('maps static WASM structure evidence into a plan-only no-grant handoff', async () => {
    const harness = createPluginTestHarness()
    harness.registerPlugin(wasmRuntimePlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'wasm.runtime.plan'
    )

    const result = (await tool?.handler({
      sample_id: 'sha256:wasm',
      file_type: 'wat',
      requested_backends: ['wasmtime'],
      static_evidence: [
        'wasi_snapshot_preview1.fd_write',
        'export:run',
        'custom-section:name',
        'resource-grant:preopen:/tmp',
        'network-policy:disabled',
      ],
    })) as any

    expect(result.ok).toBe(true)
    expect(result.data.formats).toEqual(expect.arrayContaining(['wasm', 'wasi', 'wat']))
    expect(result.data.policy).toEqual(
      expect.objectContaining({
        networkPolicy: 'disabled',
        noInstantiation: true,
        noWasiGrants: true,
        noResourceGrants: true,
        resourceGrants: 'none',
      })
    )
    expect(result.data.runtime_handoff).toEqual(
      expect.objectContaining({
        from_static_tool: 'wasm.structure.analyze',
        static_artifact_type: 'wasm_structure',
        required_before_execution: expect.arrayContaining([
          'wasm.runtime.plan',
          'tool.readiness',
          'analysis.evidence.graph',
          'artifact.read',
        ]),
        execution_constraints: expect.objectContaining({
          no_instantiation: true,
          no_wasi_grants: true,
          no_network: true,
          resource_grants: 'none',
        }),
      })
    )
    expect(result.data.static_correlation.provided_evidence).toEqual(
      expect.arrayContaining([
        'custom-section:name',
        'resource-grant:preopen:/tmp',
        'network-policy:disabled',
      ])
    )
    expect(result.data.selected_backends[0].readiness_checks.join(' ')).toMatch(
      /preopens disabled/i
    )
    expect(result.data.selected_backends[0].readiness_checks.join(' ')).toMatch(
      /resource grants disabled/i
    )
    expect(result.data.selected_backends[0].readiness_checks.join(' ')).toMatch(
      /network policy remains disabled/i
    )
    expect(result.data.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'wasm.runtime.plan',
        'tool.readiness',
        'analysis.evidence.graph',
        'artifact.read',
      ])
    )
    expect(result.data.safety_notes.join(' ')).toMatch(/No WASI preopens/i)
    expect(result.data.safety_notes.join(' ')).toMatch(/network access were created/i)
    expect(result.data.execution_semantics.live_execution).toBe(false)
  })

  test('surfaces WASM runtime readiness policy through tool.readiness', async () => {
    const plugins = [wasmPlugin, wasmRuntimePlugin]
    const handler = createToolReadinessHandler(
      () => allToolDefinitions(plugins),
      () => createPluginManager(plugins)
    )

    const result = (await handler({
      tool_name: 'wasm.runtime.plan',
      force_refresh: false,
    })) as any

    expect(result.ok).toBe(true)
    expect(result.data.readiness).toBe('ready')
    expect(result.data.runtime_plane).toBe('local_planning')
    expect(result.data.aspects.formats).toEqual(expect.arrayContaining(['wasm', 'wasi', 'wat']))
    expect(result.data.workflow_recipes[0]).toEqual(
      expect.objectContaining({
        id: 'wasm.runtime.opt-in',
        nextTools: expect.arrayContaining(['analysis.evidence.graph', 'artifact.read']),
      })
    )
    expect(result.data.runtime_policy).toEqual(
      expect.objectContaining({
        networkPolicy: 'disabled',
        noInstantiation: true,
        noWasiGrants: true,
        noResourceGrants: true,
      })
    )
    expect(result.data.runtime_policy_status).toEqual(
      expect.objectContaining({
        policy_denied: false,
        allowed_backends: ['wasmtime'],
        network_policy: 'disabled',
      })
    )
    expect(result.data.execution_semantics.live_execution).toBe(false)
  })

  test('lets workflow.search find static and runtime WASM handoffs by WAT and grant terms', async () => {
    resetSurfaceForTest()
    const plugins = [wasmPlugin, wasmRuntimePlugin]
    const surface = getToolSurfaceManager()
    for (const plugin of plugins) {
      surface.registerPlugin(
        plugin,
        plugin.tools.map((tool) => tool.definition.name)
      )
    }
    const handler = createWorkflowSearchHandler(createPluginManager(plugins))

    const result = (await handler({
      file_type: '.wat',
      query: 'WASI import export resource-grant preopen network custom-section provenance runtime',
      goal: 'dynamic',
      top_k: 5,
    })) as any

    expect(result.ok).toBe(true)
    const pluginIds = result.data.results.map((item: any) => item.plugin_id)
    expect(pluginIds).toEqual(expect.arrayContaining(['wasm', 'wasm-runtime']))
    const runtimeResult = result.data.results.find(
      (item: any) => item.plugin_id === 'wasm-runtime'
    )
    const staticResult = result.data.results.find((item: any) => item.plugin_id === 'wasm')

    expect(runtimeResult).toEqual(
      expect.objectContaining({
        workflow_id: 'wasm.runtime.opt-in',
        recommended_tools: expect.arrayContaining(['wasm.runtime.plan']),
        activation_required: true,
      })
    )
    expect(runtimeResult.matched_profile_fields.join(' ')).toMatch(/query terms/i)
    expect(staticResult).toEqual(
      expect.objectContaining({
        workflow_id: 'wasm.static.inventory',
        recommended_tools: expect.arrayContaining(['wasm.structure.analyze']),
      })
    )
  })
})
