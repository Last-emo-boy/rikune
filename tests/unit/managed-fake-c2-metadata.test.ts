import { describe, expect, test } from '@jest/globals'

import managedFakeC2Plugin from '../../src/plugins/managed-fake-c2/index.js'
import {
  FAKE_C2_ARTIFACT_TYPES,
  fakeC2ToolDefinition,
} from '../../src/plugins/managed-fake-c2/tools/fake-c2.js'
import { buildManagedFakeC2Envelope } from '../../src/plugins/managed-fake-c2/managed-fake-c2-metadata.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'
import type { Plugin } from '../../src/plugins/sdk.js'

function resetSurfaceForTest() {
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

describe('managed-fake-c2 metadata/readiness/profile', () => {
  test('declares explicit opt-in isolated sinkhole plugin metadata and env/dependency guidance', () => {
    expect(managedFakeC2Plugin.version).toBe('1.1.0')
    expect(managedFakeC2Plugin.executionDomain).toBe('dynamic')
    expect(managedFakeC2Plugin.runtimePolicy).toEqual(
      expect.objectContaining({
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'restricted',
        sinkholedOnly: true,
        noArbitraryOutboundNetwork: true,
        workflowSearchAutoRun: false,
      })
    )
    expect(managedFakeC2Plugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'explicit-opt-in',
        'isolated-sinkhole',
        'sinkholed-only',
        'no-arbitrary-outbound-network',
        'workflow-search-does-not-run',
        'validation-planner-required',
      ])
    )
    expect(managedFakeC2Plugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'c2-emulation',
        'http-sinkhole',
        'request-capture',
        'runtime-handoff',
        'validation-planner',
        'workflow-handoff',
        'quality-gates',
        'search-profile',
      ])
    )
    expect(managedFakeC2Plugin.aspects?.search).toEqual(
      expect.arrayContaining(['fake c2', 'fakenet', 'http beacon', 'sinkhole'])
    )
    expect(managedFakeC2Plugin.aspects?.profile).toEqual(
      expect.arrayContaining([
        'managed-fake-c2',
        'fake-c2-sinkhole',
        'explicit-opt-in-runtime',
        'request-capture-profile',
      ])
    )
    expect(managedFakeC2Plugin.aspects?.route_terms).toEqual(
      expect.arrayContaining([
        'static_c2_to_sinkhole_validation',
        'fake_c2_request_capture_handoff',
        'workflow_search_does_not_run',
        'no_arbitrary_outbound_network',
      ])
    )
    expect(managedFakeC2Plugin.surfaceRules?.activateOn?.findings).toEqual(
      expect.arrayContaining(['c2', 'network_ioc', 'http_beacon', 'sinkhole', 'fakenet'])
    )
    expect(managedFakeC2Plugin.configSchema).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          envVar: 'FAKE_C2_DEFAULT_PORT',
          description: expect.stringContaining('callers must pass listen_port explicitly'),
        }),
        expect.objectContaining({
          envVar: 'FAKE_C2_TLS_CERT',
          description: expect.stringContaining('does not read this env var'),
        }),
        expect.objectContaining({
          envVar: 'FAKE_C2_TLS_KEY',
          description: expect.stringContaining('does not read this env var'),
        }),
      ])
    )
    expect(managedFakeC2Plugin.systemDeps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'python3', required: true }),
        expect.objectContaining({
          name: 'openssl',
          required: false,
          description: expect.stringContaining('use_tls=true'),
        }),
        expect.objectContaining({
          name: 'dotnet',
          required: false,
          dockerInstallProfile: 'runtime',
        }),
        expect.objectContaining({
          name: 'mono',
          required: false,
          dockerInstallProfile: 'runtime',
        }),
      ])
    )
    expect(toolNames(managedFakeC2Plugin)).toEqual(['managed.fake_c2'])
  })

  test('declares tool artifacts, evidence, workflow recipe, runtime policy, and worker backend', () => {
    expect(fakeC2ToolDefinition.runtime).toEqual({
      type: 'python-worker',
      handler: 'src/plugins/managed-fake-c2/workers/managed_fake_c2_worker.py',
    })
    expect(fakeC2ToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'restricted',
        sinkholedOnly: true,
        noArbitraryOutboundNetwork: true,
        validationPlannerRequired: true,
        workflowSearchAutoRun: false,
      })
    )
    expect(fakeC2ToolDefinition.aspects?.profile).toEqual(
      expect.arrayContaining(['fake-c2-sinkhole', 'network-ioc-validation'])
    )
    expect(fakeC2ToolDefinition.aspects?.route_terms).toEqual(
      expect.arrayContaining([
        'managed_fake_c2_profile',
        'dns_redirect_handoff',
        'beacon_gate_validation',
      ])
    )
    expect(fakeC2ToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: FAKE_C2_ARTIFACT_TYPES.session }),
        expect.objectContaining({ type: FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope }),
      ])
    )
    expect(fakeC2ToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'network' }),
        expect.objectContaining({ category: 'http' }),
        expect.objectContaining({ category: 'c2' }),
        expect.objectContaining({ category: 'timeline' }),
        expect.objectContaining({ category: 'provenance' }),
        expect.objectContaining({ category: 'workflow' }),
      ])
    )

    const recipe = fakeC2ToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'managed-fake-c2.c2-emulation-validation'
    ) as any
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: expect.arrayContaining([
          'static.config.carver',
          'c2.extract',
          'debug.network.plan',
          'tool.readiness',
          'managed.fake_c2',
        ]),
        nextTools: expect.arrayContaining([
          'dynamic.behavior.capture',
          'malware.intel.loop',
          'analysis.evidence.graph',
          'report.generate',
        ]),
        producesArtifacts: expect.arrayContaining([
          FAKE_C2_ARTIFACT_TYPES.session,
          FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope,
        ]),
        safety: expect.arrayContaining([
          'explicit-opt-in',
          'sinkholed-network-only',
          'no-arbitrary-outbound-network',
          'validation-planner-required',
          'workflow-search-does-not-run',
        ]),
        searchTags: expect.arrayContaining([
          'fake c2',
          'http beacon',
          'network_ioc',
          'sinkhole',
          'validation planner',
        ]),
      })
    )
    expect(recipe.quality.gates.join(' ')).toContain('Explicit analyst opt-in')
    expect(recipe.handoff.forbiddenAutomation).toEqual(
      expect.arrayContaining(['workflow.search must not run managed.fake_c2 automatically'])
    )

    expect(fakeC2ToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'Managed Fake C2 Runtime Worker',
        backendKind: 'delegated-runtime',
        adapter: 'managed-fake-c2.python-worker',
        outputArtifactTypes: expect.arrayContaining([
          FAKE_C2_ARTIFACT_TYPES.session,
          FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope,
        ]),
        policy: expect.objectContaining({
          requiresUserOptIn: true,
          requiresIsolation: true,
          sinkholedOnly: true,
          noArbitraryOutboundNetwork: true,
        }),
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
          missingBackendBehavior: expect.stringContaining('must not start from workflow.search'),
          qualityContract: expect.objectContaining({
            requiredBeforeExecution: expect.arrayContaining([
              'explicit-opt-in',
              'isolated-runtime-selected',
              'sinkholed-network-policy-confirmed',
              'validation-planner-reviewed',
            ]),
          }),
          handoffContract: expect.objectContaining({
            expectedConsumers: expect.arrayContaining([
              'dynamic.behavior.capture',
              'analysis.evidence.graph',
              'report.generate',
            ]),
          }),
        }),
      })
    )
  })

  test('workflow.search finds Fake C2 profiles without activating or executing them', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerPlugin(managedFakeC2Plugin, toolNames(managedFakeC2Plugin))
    const handler = createWorkflowSearchHandler(createPluginManager([managedFakeC2Plugin]))

    for (const query of ['fake c2', 'http beacon', 'network_ioc', 'sinkhole validation planner']) {
      const result = await handler({ query, goal: 'dynamic', top_k: 5 })
      expect(result.ok).toBe(true)
      const data = result.data as any
      const match = data.results.find((item: any) => item.plugin_id === 'managed-fake-c2')
      expect(match).toEqual(
        expect.objectContaining({
          recommended_tools: expect.arrayContaining(['managed.fake_c2']),
          workflow_id: 'managed-fake-c2.c2-emulation-validation',
          activation_required: true,
          activation_command: expect.objectContaining({
            action: 'activate',
            tool: 'workflow.search',
            via: 'workflow.search',
          }),
        })
      )
      expect(['runtime_opt_in_required', 'hidden_activation_required']).toContain(
        match.readiness_state
      )
      expect(surface.isToolVisible('managed.fake_c2')).toBe(false)
    }
  })

  test('builds result-level evidence, handoff, and quality gates for captured requests', () => {
    const envelope = buildManagedFakeC2Envelope({
      sample_id: 'sha256:abc',
      endpoint_count: 2,
      dns_redirect_count: 1,
      capture_requests: true,
      use_tls: true,
      auto_run_sample: false,
      listen_port: 8443,
      timeout_seconds: 30,
      worker_result: {
        ok: true,
        data: {
          total_requests_captured: 1,
          requests: [{ method: 'POST', path: '/gate' }],
          sample_execution: null,
        },
      },
    })

    expect(envelope.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'artifact.read',
        'dynamic.behavior.capture',
        'malware.intel.loop',
        'analysis.evidence.graph',
        'report.generate',
      ])
    )
    expect(envelope.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.managed_fake_c2.evidence_summary.v1',
        source_tool: 'managed.fake_c2',
        sample_id: 'sha256:abc',
        artifact_type: FAKE_C2_ARTIFACT_TYPES.session,
        route_terms: expect.arrayContaining([
          'static_c2_to_sinkhole_validation',
          'fake_c2_request_capture_handoff',
        ]),
        dynamic_only_after_opt_in: true,
      })
    )
    expect(envelope.evidence_summary.counts).toEqual(
      expect.objectContaining({
        endpoints_configured: 2,
        dns_redirects: 1,
        requests_captured: 1,
      })
    )
    expect(envelope.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.managed_fake_c2.workflow_handoff.v1',
        handoff_mode: 'static_c2_indicators_to_isolated_sinkhole_validation',
        artifact_contract: expect.objectContaining({
          produces: expect.arrayContaining([
            FAKE_C2_ARTIFACT_TYPES.session,
            FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope,
          ]),
          mime: 'application/json',
        }),
      })
    )
    expect(envelope.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        explicit_opt_in_required: true,
        isolated_runtime_required: true,
        validation_planner_required: true,
        workflow_search_can_start_listener: false,
        workflow_search_can_execute_sample: false,
        arbitrary_outbound_network_allowed: false,
        dns_or_hosts_mutation_outside_runtime_allowed: false,
        auto_run_sample_requested: false,
      })
    )
    expect(envelope.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'behavior-capture-correlation',
          priority: 'high',
          next_tools: expect.arrayContaining(['dynamic.behavior.capture']),
        }),
        expect.objectContaining({
          goal: 'dns-redirect-review',
          priority: 'medium',
          blocking_conditions: expect.arrayContaining([
            expect.stringContaining('isolated runtime'),
          ]),
        }),
      ])
    )
    expect(envelope.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.managed_fake_c2.quality_gates.v1',
        explicit_opt_in_required: true,
        isolated_runtime_required: true,
        validation_planner_required: true,
        sinkholed_network_only: true,
        workflow_search_auto_run: false,
        workflow_search_started_listener: false,
        arbitrary_outbound_network_allowed: false,
        dns_or_hosts_mutation_outside_runtime_allowed: false,
        endpoint_config_present: true,
        request_capture_enabled: true,
        requests_captured: true,
        auto_run_sample_requested: false,
        sample_execution_result_present: false,
      })
    )
  })
})
