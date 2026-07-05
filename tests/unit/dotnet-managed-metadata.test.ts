import { describe, expect, test } from '@jest/globals'

import dotnetManagedPlugin from '../../src/plugins/dotnet-managed/index.js'
import {
  DOTNET_ASSEMBLY_ARTIFACT_TYPE,
  DOTNET_ASSEMBLY_EVIDENCE_SUMMARY_SCHEMA,
  DOTNET_ASSEMBLY_QUALITY_GATES_SCHEMA,
  DOTNET_ASSEMBLY_WORKFLOW_HANDOFF_SCHEMA,
  DOTNET_MANAGED_FOLLOW_UP_TOOLS,
  DOTNET_MANAGED_ROUTE_TERMS,
  DOTNET_MANAGED_RUNTIME_POLICY,
} from '../../src/plugins/dotnet-managed/dotnet-managed-metadata.js'
import {
  buildDotnetAssemblyInventoryFromBuffer,
  dotnetAssemblyInspectToolDefinition,
} from '../../src/plugins/dotnet-managed/tools/dotnet-assembly-inspect.js'

const FORBIDDEN_NEXT_TOOLS = [
  'sandbox.execute',
  'dynamic.runtime.status',
  'dynamic.trace.import',
  'safe.run',
  'dotnet.decompile',
  'tools.discover',
]

function managedPeFixture(): Buffer {
  return Buffer.from(
    [
      'MZ',
      'BSJB',
      'mscoree.dll',
      'AssemblyName Demo.Managed',
      'TargetFrameworkAttribute .NETCoreApp,Version=v8.0',
      'DllImportAttribute KERNEL32.dll',
      'System.Runtime',
    ].join('\0'),
    'latin1'
  )
}

describe('dotnet-managed metadata', () => {
  test('declares passive inventory handoff metadata without widening execution semantics', () => {
    expect(dotnetManagedPlugin.version).toBe('1.1.0')
    expect(dotnetManagedPlugin.aspects?.execution).toEqual(
      expect.arrayContaining(['static', 'triage', 'workflow-handoff'])
    )
    expect(dotnetManagedPlugin.aspects?.execution).not.toContain('decompilation')
    expect(dotnetManagedPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'assembly-metadata',
        'managed-metadata',
        'target-framework-profile',
        'pinvoke-profile',
        'managed-xref-handoff',
        'workflow-handoff',
      ])
    )
    expect(dotnetManagedPlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_execute',
        'no_runtime_start',
        'no_package_restore',
        'no_decompiler_launch',
        'no_network',
        'no_mutation',
      ])
    )
    expect(dotnetManagedPlugin.aspects?.search).toEqual(
      expect.arrayContaining(['clr-metadata', 'target-framework', 'managed-xref'])
    )
    expect(dotnetManagedPlugin.aspects?.route_terms).toEqual(
      expect.arrayContaining(DOTNET_MANAGED_ROUTE_TERMS)
    )
    expect(dotnetManagedPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        ...DOTNET_MANAGED_RUNTIME_POLICY,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noClrStart: true,
        noPackageRestore: true,
        noDecompilerLaunch: true,
      })
    )

    expect(dotnetAssemblyInspectToolDefinition.aspects?.execution).not.toContain('decompilation')
    expect(dotnetAssemblyInspectToolDefinition.aspects?.profile).toEqual(expect.any(Array))
    expect(dotnetAssemblyInspectToolDefinition.aspects?.route_terms).toEqual(
      expect.arrayContaining(DOTNET_MANAGED_ROUTE_TERMS)
    )
    expect(dotnetAssemblyInspectToolDefinition.artifacts?.[0]).toEqual(
      expect.objectContaining({
        type: DOTNET_ASSEMBLY_ARTIFACT_TYPE,
        mime: 'application/json',
      })
    )
    expect(dotnetAssemblyInspectToolDefinition.evidence?.map((item) => item.category)).toEqual(
      expect.arrayContaining(['managed-metadata', 'workflow', 'provenance'])
    )
    expect(dotnetAssemblyInspectToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'dotnet-managed.passive-inventory-handoff',
        startsWith: ['dotnet.assembly.inspect'],
        nextTools: DOTNET_MANAGED_FOLLOW_UP_TOOLS,
        producesArtifacts: [DOTNET_ASSEMBLY_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_execute',
          'no_runtime_start',
          'no_package_restore',
          'no_decompiler_launch',
        ]),
      })
    )
    for (const forbidden of FORBIDDEN_NEXT_TOOLS) {
      expect(
        dotnetAssemblyInspectToolDefinition.workflowRecipes?.[0].nextTools ?? []
      ).not.toContain(forbidden)
    }
    expect(dotnetAssemblyInspectToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noClrStart: true,
        noPackageRestore: true,
        noDecompilerLaunch: true,
      })
    )
  })

  test('builds evidence summary, workflow handoff, and quality gates from passive hints', () => {
    const inventory = buildDotnetAssemblyInventoryFromBuffer(managedPeFixture(), {
      filename: 'Demo.Managed.dll',
      sampleId: 'sha256:dotnet',
      size: 8192,
    })

    expect(inventory.format).toBe('pe-clr')
    expect(inventory.assembly_hints).toContain('Demo.Managed')
    expect(inventory.pinvoke_hints).toContain('KERNEL32.dll')
    expect(inventory.recommended_next_tools).toEqual(DOTNET_MANAGED_FOLLOW_UP_TOOLS)
    expect(inventory.recommended_next_tools).not.toContain('dotnet.decompile')
    expect(inventory.decompile_plan.recommended_tools).toEqual(
      expect.arrayContaining([
        'dotnet.metadata.extract',
        'dotnet.types.list',
        'dotnet.decompile.type',
      ])
    )
    expect(inventory.decompile_plan.recommended_tools).not.toContain('dotnet.decompile')

    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: DOTNET_ASSEMBLY_EVIDENCE_SUMMARY_SCHEMA,
        source_tool: 'dotnet.assembly.inspect',
        sample_id: 'sha256:dotnet',
        artifact_type: DOTNET_ASSEMBLY_ARTIFACT_TYPE,
        route_terms: DOTNET_MANAGED_ROUTE_TERMS,
        static_only: true,
      })
    )
    expect(inventory.evidence_summary?.counts).toEqual(
      expect.objectContaining({
        assembly_hints: 1,
      })
    )
    expect(
      (inventory.evidence_summary?.counts as Record<string, number>).pinvoke_hints
    ).toBeGreaterThan(0)
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: DOTNET_ASSEMBLY_WORKFLOW_HANDOFF_SCHEMA,
        handoff_mode: 'dotnet_passive_inventory_to_managed_analysis',
        artifact_contract: expect.objectContaining({
          consumes: ['sample'],
          produces: [DOTNET_ASSEMBLY_ARTIFACT_TYPE],
          mime: 'application/json',
          expected_consumers: DOTNET_MANAGED_FOLLOW_UP_TOOLS,
        }),
      })
    )
    expect(inventory.workflow_handoff?.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'managed-metadata-confirmation',
          next_tools: ['dotnet.metadata.extract', 'dotnet.types.list'],
        }),
        expect.objectContaining({
          goal: 'bounded-decompilation-planning',
          next_tools: ['dotnet.decompile.type'],
          blocking_conditions: expect.arrayContaining([
            expect.stringContaining('Do not run whole-assembly decompilation'),
          ]),
        }),
        expect.objectContaining({
          goal: 'evidence-and-reporting',
          next_tools: ['analysis.evidence.graph', 'artifact.read', 'report.generate'],
        }),
      ])
    )
    expect(inventory.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        activation_boundary: 'result-scoped',
        sample_execution_allowed: false,
        sample_executed_by_tool: false,
        clr_start_allowed: false,
        clr_started_by_tool: false,
        package_restore_allowed: false,
        package_restored_by_tool: false,
        decompiler_launch_allowed: false,
        decompiler_launched_by_tool: false,
        network_allowed: false,
        mutation_allowed: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: DOTNET_ASSEMBLY_QUALITY_GATES_SCHEMA,
        passive_static_inventory: true,
        bounded_preview_only: true,
        format_detected: true,
        managed_or_package_format: true,
        assembly_hints_present: true,
        pinvoke_hints_present: true,
        sample_executed_by_tool: false,
        clr_started_by_tool: false,
        mutation_performed: false,
      })
    )
  })
})
