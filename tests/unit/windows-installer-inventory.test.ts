import { describe, expect, test } from '@jest/globals'
import {
  buildWindowsInstallerInventoryFromBuffer,
  windowsInstallerInventoryToolDefinition,
} from '../../src/plugins/windows-installer/tools/windows-installer-inventory.js'

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

function cabFixture(): Buffer {
  const data = Buffer.alloc(36)
  data.write('MSCF', 0, 'ascii')
  data.writeUInt32LE(data.length, 8)
  data.writeUInt32LE(36, 16)
  data[24] = 3
  data[25] = 1
  data.writeUInt16LE(1, 26)
  data.writeUInt16LE(2, 28)
  return data
}

describe('installer.inventory', () => {
  test('inventories MSIX payloads without install, custom-action execution, or payload launch', () => {
    const inventory = buildWindowsInstallerInventoryFromBuffer(
      Buffer.concat([
        localZip(['AppxManifest.xml', 'VFS/Demo.exe', 'scripts/install.ps1']),
        Buffer.from('CustomAction Binary.Demo VFS/Demo.dll install.ps1'),
      ]),
      { filename: 'demo.msix' }
    )

    expect(inventory.installer_format).toBe('msix')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_install: true,
        no_payload_launch: true,
      })
    )
    expect(inventory.script_candidates).toContain('scripts/install.ps1')
    expect(inventory.custom_action_candidates.length).toBeGreaterThan(0)
    expect(inventory.nested_payload_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: expect.stringContaining('Demo.exe'),
          routed_formats: expect.arrayContaining(['pe']),
          recommended_tools: expect.arrayContaining(['pe.structure.analyze']),
        }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'pe.structure.analyze',
        'sbom.provenance.graph',
        'windows.runtime.plan',
      ])
    )
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.windows_installer_inventory.evidence_summary.v1',
        source_tool: 'installer.inventory',
        artifact_type: 'windows_installer_inventory',
        installer_format: 'msix',
        custom_action_candidate_count: inventory.custom_action_candidates.length,
        script_candidate_count: inventory.script_candidates.length,
        nested_payload_candidate_count: inventory.nested_payload_candidates.length,
        static_only: true,
      })
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.windows_installer_inventory.workflow_handoff.v1',
        handoff_mode: 'windows_installer_inventory_to_payload_supply_chain_and_runtime_planning',
        artifact_type: 'windows_installer_inventory',
        recommended_next_tools: expect.arrayContaining([
          'pe.structure.analyze',
          'sbom.provenance.graph',
          'windows.runtime.plan',
        ]),
      })
    )
    expect(inventory.workflow_handoff?.artifact_contract).toEqual(
      expect.objectContaining({
        consumes: ['sample'],
        produces: ['windows_installer_inventory'],
      })
    )
    expect(inventory.workflow_handoff?.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'nested-payload-static-analysis',
          priority: 'high',
          next_tools: expect.arrayContaining(['pe.structure.analyze']),
        }),
        expect.objectContaining({
          goal: 'installer-supply-chain-provenance',
          next_tools: expect.arrayContaining(['sbom.provenance.graph', 'analysis.evidence.graph']),
        }),
        expect.objectContaining({
          goal: 'windows-runtime-plan-only',
          priority: 'high',
          next_tools: expect.arrayContaining(['windows.runtime.plan']),
        }),
      ])
    )
    expect(inventory.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        installer_launched_by_tool: false,
        package_installed_by_tool: false,
        custom_action_executed_by_tool: false,
        script_executed_by_tool: false,
        payload_launched_by_tool: false,
        runtime_started_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.windows_installer_inventory.quality_gates.v1',
        passive_static_inventory: true,
        bounded_preview_only: true,
        format_detected: true,
        custom_action_candidates_present: true,
        script_candidates_present: true,
        nested_payload_routing_present: true,
        sample_executed_by_tool: false,
        installer_launched_by_tool: false,
        package_installed_by_tool: false,
        custom_action_executed_by_tool: false,
        script_executed_by_tool: false,
        payload_launched_by_tool: false,
        runtime_started_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
  })

  test('recognizes CAB, NSIS, and Inno formats as passive inventory only', () => {
    const cab = buildWindowsInstallerInventoryFromBuffer(cabFixture(), { filename: 'payload.cab' })
    const nsis = buildWindowsInstallerInventoryFromBuffer(
      Buffer.concat([Buffer.from('MZ'), Buffer.from('NullsoftInst setup.exe')]),
      { filename: 'setup.exe' }
    )
    const inno = buildWindowsInstallerInventoryFromBuffer(
      Buffer.concat([Buffer.from('MZ'), Buffer.from('Inno Setup setup.exe')]),
      { filename: 'setup.exe' }
    )

    expect(cab.installer_format).toBe('cab')
    expect(cab.cab_summary?.file_count).toBe(2)
    expect(nsis.installer_format).toBe('nsis')
    expect(nsis.unsupported_detail).toMatch(/does not execute/i)
    expect(inno.installer_format).toBe('inno')
    expect(
      [cab, nsis, inno].every((item) => item.policy.no_install && item.policy.no_execute)
    ).toBe(true)
  })

  test('declares passive workflow recipe, artifact, evidence, and follow-up chain metadata', () => {
    const definition = windowsInstallerInventoryToolDefinition
    const recipe = definition.workflowRecipes?.find(
      (candidate) => candidate.id === 'windows-installer.passive-inventory-handoff'
    )

    expect(definition.artifacts).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: 'windows_installer_inventory' })])
    )
    expect(definition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'package-metadata',
          artifactTypes: expect.arrayContaining(['windows_installer_inventory']),
        }),
        expect.objectContaining({
          category: 'nested-binaries',
          artifactTypes: expect.arrayContaining(['windows_installer_inventory']),
        }),
      ])
    )
    expect(definition.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_installer_execution', 'no_live_sample_by_default'])
    )
    expect(definition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['workflow-plan', 'metadata-only-handoff'])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        nextTools: expect.arrayContaining([
          'pe.structure.analyze',
          'sbom.provenance.graph',
          'windows.runtime.plan',
        ]),
        producesArtifacts: expect.arrayContaining(['windows_installer_inventory']),
        evidence: expect.arrayContaining(['package-metadata', 'nested-binaries', 'provenance']),
        safety: expect.arrayContaining([
          'passive',
          'no_installer_execution',
          'no_live_sample_by_default',
        ]),
      })
    )
  })
})
