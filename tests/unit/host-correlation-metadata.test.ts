import { describe, expect, test } from '@jest/globals'

import hostCorrelationPlugin from '../../src/plugins/host-correlation/index.js'
import {
  HostCorrelateInputSchema,
  buildHostCorrelateCacheArgs,
  enrichHostCorrelationResult,
  hostCorrelateToolDefinition,
} from '../../src/plugins/host-correlation/tools/host-correlate.js'

describe('host-correlation metadata deepening', () => {
  test('declares passive host correlation search profile and workflow metadata', () => {
    const definition = hostCorrelateToolDefinition
    const recipe = definition.workflowRecipes?.find(
      (candidate) => candidate.id === 'host-correlation.loader-context-handoff'
    )

    expect(hostCorrelationPlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['pe', 'dll', 'exe', 'windows-host-artifacts', 'manifest', 'registry'])
    )
    expect(hostCorrelationPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'host-correlation',
        'loader-correlation',
        'sideloading-analysis',
        'workflow-handoff',
        'search-profile',
      ])
    )
    expect(hostCorrelationPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noSampleExecution: true,
        noHostMutation: true,
      })
    )
    expect(hostCorrelationPlugin.systemDeps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'python',
          name: 'pefile',
          required: false,
        }),
      ])
    )
    expect(definition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'host_correlation',
          mime: 'application/json',
        }),
      ])
    )
    expect(definition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'process',
          artifactTypes: expect.arrayContaining(['host_correlation']),
        }),
        expect.objectContaining({
          category: 'persistence',
          artifactTypes: expect.arrayContaining(['host_correlation']),
        }),
        expect.objectContaining({
          category: 'sideloading',
          artifactTypes: expect.arrayContaining(['host_correlation']),
        }),
        expect.objectContaining({
          category: 'workflow',
          artifactTypes: expect.arrayContaining(['host_correlation']),
        }),
        expect.objectContaining({
          category: 'provenance',
          artifactTypes: expect.arrayContaining(['host_correlation']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['host.correlate'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'dll.dependency.tree',
          'analysis.evidence.graph',
          'attack.map',
          'report.generate',
        ]),
        requiredArtifacts: expect.arrayContaining(['sample']),
        producesArtifacts: expect.arrayContaining(['host_correlation']),
        evidence: expect.arrayContaining(['process', 'filesystem', 'registry', 'workflow']),
        safety: expect.arrayContaining([
          'passive',
          'no_sample_execution',
          'no_host_mutation',
          'no_network_by_default',
        ]),
        runtimeBackends: expect.arrayContaining(['local']),
      })
    )
    expect(definition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        allowedBackends: ['local'],
        networkPolicy: 'disabled',
        noSampleExecution: true,
        noHostMutation: true,
      })
    )
    expect(definition.workerBackend).toEqual(
      expect.objectContaining({
        backendKind: 'external',
        availability: 'required',
        supportedModes: ['local'],
        defaultMode: 'local',
        inputArtifactTypes: ['sample'],
        outputArtifactTypes: ['host_correlation'],
        policy: expect.objectContaining({
          passiveByDefault: true,
          noNetwork: true,
          noMutation: true,
          noLiveExecution: true,
        }),
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
        }),
      })
    )
  })

  test('covers every correlation option in cache args', () => {
    const baseline = buildHostCorrelateCacheArgs(
      HostCorrelateInputSchema.parse({
        sample_id: 'sha256:demo',
        scan_directory: 'C:/samples',
      })
    )
    const changed = buildHostCorrelateCacheArgs(
      HostCorrelateInputSchema.parse({
        sample_id: 'sha256:demo',
        scan_directory: 'C:/samples',
        check_scheduled_tasks: false,
        check_services: false,
        check_startup: false,
        check_sideload: false,
        check_com_registration: false,
        check_import_tables: false,
        recursive: true,
        max_depth: 5,
      })
    )

    expect(baseline).toEqual(
      expect.objectContaining({
        scan_directory: 'C:/samples',
        check_scheduled_tasks: true,
        check_services: true,
        check_startup: true,
        check_sideload: true,
        check_com_registration: true,
        check_import_tables: true,
        recursive: false,
        max_depth: 2,
      })
    )
    expect(changed).toEqual(
      expect.objectContaining({
        check_scheduled_tasks: false,
        check_services: false,
        check_startup: false,
        check_sideload: false,
        check_com_registration: false,
        check_import_tables: false,
        recursive: true,
        max_depth: 5,
      })
    )
    expect(changed).not.toEqual(baseline)
  })

  test('adds host correlation handoff envelope without execution or mutation', () => {
    const enriched = enrichHostCorrelationResult(
      {
        ok: true,
        data: {
          sample: 'C:/samples/payload.dll',
          sample_name: 'payload.dll',
          scan_directory: 'C:/samples',
          host_exes: [{ host_exe: 'C:/samples/host.exe', imports_sample: true }],
          sideloading: [{ type: 'manifest', file: 'C:/samples/host.exe.manifest' }],
          scheduled_tasks: [{ type: 'scheduled_task', task_name: 'DemoTask' }],
          services: [],
          startup: [],
          com_registration: [],
          total_findings: 3,
          summary: 'Found 3 correlation(s) for payload.dll',
        },
      },
      { sampleId: 'sha256:host-demo', scanDirectory: 'C:/samples' }
    )
    const data = enriched.data as Record<string, any>

    expect(data.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_sample_execution: true,
        no_host_mutation: true,
        no_network: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'pe.structure.analyze',
        'dll.dependency.tree',
        'analysis.evidence.graph',
        'attack.map',
        'windows.runtime.plan',
      ])
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.host_correlation.evidence_summary.v1',
        source_tool: 'host.correlate',
        artifact_type: 'host_correlation',
        sample_id: 'sha256:host-demo',
        scan_directory: 'C:/samples',
        total_findings: 3,
        static_only: true,
        sample_executed_by_tool: false,
        host_mutated_by_tool: false,
      })
    )
    expect(data.evidence_summary.finding_counts).toEqual(
      expect.objectContaining({
        host_exes: 1,
        sideloading: 1,
        scheduled_tasks: 1,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.host_correlation.workflow_handoff.v1',
        handoff_mode: 'host_loader_context_to_evidence_graph_and_runtime_plan',
        artifact_type: 'host_correlation',
        recommended_next_tools: expect.arrayContaining([
          'dll.dependency.tree',
          'analysis.evidence.graph',
          'attack.map',
        ]),
      })
    )
    expect(data.workflow_handoff.artifact_contract).toEqual(
      expect.objectContaining({
        consumes: ['sample', 'host filesystem metadata'],
        produces: ['host_correlation'],
        expected_consumers: expect.arrayContaining([
          'workflow.search',
          'artifact.read',
          'analysis.evidence.graph',
          'report.generate',
        ]),
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'loader-and-sideloading-static-analysis',
          priority: 'high',
          consumes: ['host_correlation'],
          produces: ['loader_context_graph'],
        }),
        expect.objectContaining({
          goal: 'persistence-and-execution-context-reporting',
          priority: 'high',
          consumes: ['host_correlation'],
          produces: ['host_persistence_context'],
        }),
      ])
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        host_process_started_by_tool: false,
        service_modified_by_tool: false,
        scheduled_task_modified_by_tool: false,
        registry_modified_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.host_correlation.quality_gates.v1',
        passive_correlation: true,
        import_table_correlation_present: true,
        sideloading_correlation_present: true,
        persistence_correlation_present: true,
        sample_executed_by_tool: false,
        host_process_started_by_tool: false,
        mutation_performed: false,
      })
    )
  })
})
