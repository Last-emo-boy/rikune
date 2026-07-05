import { describe, expect, test } from '@jest/globals'

import unityManagedPlugin from '../../src/plugins/unity-managed/index.js'
import {
  buildUnityMetadataInventoryFromBuffer,
  unityMetadataInspectToolDefinition,
} from '../../src/plugins/unity-managed/tools/unity-metadata-inspect.js'

function localZip(entries: string[]): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry)
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name)
  }
  return Buffer.concat(chunks)
}

describe('unity-managed metadata deepening', () => {
  test('declares passive Unity search profile and workflow metadata', () => {
    const definition = unityMetadataInspectToolDefinition
    const recipe = definition.workflowRecipes?.find(
      (candidate) => candidate.id === 'unity-managed.passive-metadata-handoff'
    )

    expect(unityManagedPlugin.aspects?.formats).toEqual(
      expect.arrayContaining([
        'unity',
        'unity-metadata',
        'global-metadata.dat',
        'il2cpp',
        'gameassembly',
        'libil2cpp',
        'mono',
      ])
    )
    expect(unityManagedPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'search-profile',
        'workflow-handoff',
        'metadata-only-handoff',
        'il2cpp-bridge-plan',
      ])
    )
    expect(unityManagedPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(definition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'unity_metadata_inventory',
          mimeTypes: expect.arrayContaining(['application/json']),
        }),
      ])
    )
    expect(definition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'structure',
          artifactTypes: expect.arrayContaining(['unity_metadata_inventory']),
        }),
        expect.objectContaining({
          category: 'manifest',
          artifactTypes: expect.arrayContaining(['unity_metadata_inventory']),
        }),
        expect.objectContaining({
          category: 'symbols',
          artifactTypes: expect.arrayContaining(['unity_metadata_inventory']),
        }),
        expect.objectContaining({
          category: 'package-metadata',
          artifactTypes: expect.arrayContaining(['unity_metadata_inventory']),
        }),
        expect.objectContaining({
          category: 'workflow',
          artifactTypes: expect.arrayContaining(['unity_metadata_inventory']),
        }),
        expect.objectContaining({
          category: 'provenance',
          artifactTypes: expect.arrayContaining(['unity_metadata_inventory']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['unity.metadata.inspect'],
        nextTools: expect.arrayContaining([
          'dotnet.assembly.inspect',
          'pe.structure.analyze',
          'elf.structure.analyze',
          'analysis.evidence.graph',
          'artifact.read',
        ]),
        requiredArtifacts: expect.arrayContaining(['sample']),
        producesArtifacts: expect.arrayContaining(['unity_metadata_inventory']),
        evidence: expect.arrayContaining(['manifest', 'nested-binaries', 'workflow', 'provenance']),
        safety: expect.arrayContaining([
          'passive',
          'no_runtime_start',
          'no_native_load',
          'no_decompiler_launch',
        ]),
        runtimeBackends: expect.arrayContaining(['local']),
      })
    )
    expect(definition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noRuntimeStart: true,
        noNativeLoad: true,
        noDecompilerLaunch: true,
      })
    )
  })

  test('returns profile-friendly handoff without Unity runtime or native loading', () => {
    const inventory = buildUnityMetadataInventoryFromBuffer(
      Buffer.concat([
        localZip([
          'Data/Managed/Assembly-CSharp.dll',
          'GameAssembly.dll',
          'global-metadata.dat',
          'lib/arm64/libil2cpp.so',
        ]),
        Buffer.from('Unity 2021.3.15f1 global-metadata.dat GameAssembly.dll libil2cpp.so'),
      ]),
      { filename: 'Game.zip', sampleId: 'sha256:unity-demo' }
    )

    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_runtime_start: true,
        no_native_load: true,
        no_decompiler_launch: true,
        no_network: true,
        no_mutation: true,
      })
    )
    expect(inventory.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'unity-managed.passive-metadata-handoff' }),
      ])
    )
    expect(inventory.formats).toEqual(
      expect.arrayContaining(['unity', 'unity-metadata', 'il2cpp', 'mono'])
    )
    expect(inventory.evidence).toEqual(
      expect.arrayContaining(['manifest', 'nested-binaries', 'workflow', 'provenance'])
    )
    expect(inventory.managed_assembly_candidates).toEqual(
      expect.arrayContaining(['Data/Managed/Assembly-CSharp.dll'])
    )
    expect(inventory.il2cpp_candidates).toEqual(
      expect.arrayContaining(['GameAssembly.dll', 'lib/arm64/libil2cpp.so'])
    )
    expect(inventory.metadata_candidates).toEqual(expect.arrayContaining(['global-metadata.dat']))
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'dotnet.assembly.inspect',
        'pe.structure.analyze',
        'elf.structure.analyze',
        'analysis.evidence.graph',
        'artifact.read',
      ])
    )
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.unity_metadata_inventory.evidence_summary.v1',
        source_tool: 'unity.metadata.inspect',
        artifact_type: 'unity_metadata_inventory',
        sample_id: 'sha256:unity-demo',
        filename: 'Game.zip',
        evidence_categories: expect.arrayContaining([
          'manifest',
          'structure',
          'workflow',
          'provenance',
        ]),
        static_only: true,
        native_library_loaded: false,
        unity_runtime_started: false,
      })
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.unity_metadata_inventory.workflow_handoff.v1',
        handoff_mode: 'unity_metadata_to_managed_il2cpp_static_analysis',
        artifact_type: 'unity_metadata_inventory',
        recommended_next_tools: expect.arrayContaining([
          'dotnet.assembly.inspect',
          'analysis.evidence.graph',
          'artifact.read',
        ]),
      })
    )
    expect(inventory.workflow_handoff?.artifact_contract).toEqual(
      expect.objectContaining({
        consumes: ['sample'],
        produces: ['unity_metadata_inventory'],
        expected_consumers: expect.arrayContaining([
          'workflow.search',
          'artifact.read',
          'analysis.evidence.graph',
          'report.generate',
        ]),
      })
    )
    expect(inventory.workflow_handoff?.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'il2cpp-metadata-native-bridge-static-analysis',
          consumes: ['unity_metadata_inventory'],
          produces: ['il2cpp_bridge_static_plan'],
        }),
        expect.objectContaining({
          goal: 'managed-assembly-static-inventory',
          consumes: ['unity_metadata_inventory'],
          produces: ['managed_assembly_inventory'],
        }),
      ])
    )
    expect(inventory.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        unity_runtime_started_by_tool: false,
        native_library_loaded_by_tool: false,
        decompiler_launched_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.unity_metadata_inventory.quality_gates.v1',
        passive_static_inventory: true,
        bounded_preview_only: true,
        managed_assembly_candidates_present: true,
        il2cpp_candidates_present: true,
        metadata_candidates_present: true,
        bridge_pairing_candidate_present: true,
        sample_executed_by_tool: false,
        unity_runtime_started_by_tool: false,
        native_library_loaded_by_tool: false,
      })
    )
  })
})
