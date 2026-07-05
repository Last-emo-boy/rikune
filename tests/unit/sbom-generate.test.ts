import { describe, expect, jest, test } from '@jest/globals'
import type { DatabaseManager } from '../../src/database.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import {
  createSbomGenerateHandler,
  sbomGenerateToolDefinition,
} from '../../src/plugins/sbom/tools/sbom-generate.js'

function databaseWithEvidence(): DatabaseManager {
  return {
    querySql: jest.fn((sql: string) => {
      if (sql.includes('pe_imports')) {
        return [{ library: 'KERNEL32.dll' }, { library: 'USER32.dll' }]
      }
      if (sql.includes('dotnet_references')) {
        return [{ name: 'Newtonsoft.Json', version: '13.0.3' }]
      }
      if (sql.includes('strings_cache')) {
        return [
          { value: 'zlib1.dll' },
          { value: 'driver.sys' },
          { value: 'Version=1.2.3' },
        ]
      }
      if (sql.includes('samples')) {
        return [{ sha256: 'a'.repeat(64), md5: 'b'.repeat(32) }]
      }
      return []
    }),
  } as unknown as DatabaseManager
}

function emptyDatabase(): DatabaseManager {
  return {
    querySql: jest.fn(() => []),
  } as unknown as DatabaseManager
}

describe('sbom.generate', () => {
  test('declares minimal artifact, evidence, workflow, and builtin passive policy contract', () => {
    const recipe = sbomGenerateToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'supply-chain.sbom.generate-handoff'
    )

    expect(sbomGenerateToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining([
        'cyclonedx',
        'spdx-lite',
        'container',
        'docker-image',
        'oci-image',
        'msi',
        'firmware',
      ])
    )
    expect(sbomGenerateToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'workflow-plan',
        'workflow-handoff',
        'package-metadata-provenance',
        'container-provenance',
        'installer-provenance',
        'firmware-provenance',
      ])
    )
    expect(sbomGenerateToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'cyclonedx_sbom' }),
        expect.objectContaining({ type: 'spdx_lite_sbom' }),
        expect.objectContaining({ type: 'sbom_generation_evidence' }),
      ])
    )
    expect(sbomGenerateToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'sbom',
          artifactTypes: expect.arrayContaining(['cyclonedx_sbom', 'spdx_lite_sbom']),
        }),
        expect.objectContaining({
          category: 'package-metadata',
          artifactTypes: expect.arrayContaining(['sbom_generation_evidence']),
        }),
        expect.objectContaining({ category: 'provenance' }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: expect.arrayContaining([
          'sbom.generate',
          'container.structure.analyze',
          'linux.package.inventory',
          'installer.inventory',
          'firmware.workflow.plan',
        ]),
        nextTools: expect.arrayContaining([
          'sbom.provenance.graph',
          'vuln.pattern.summary',
          'analysis.evidence.graph',
          'report.generate',
        ]),
        producesArtifacts: expect.arrayContaining([
          'cyclonedx_sbom',
          'spdx_lite_sbom',
          'sbom_generation_evidence',
        ]),
        evidence: expect.arrayContaining(['sbom', 'package-metadata', 'workflow', 'provenance']),
        safety: expect.arrayContaining([
          'passive',
          'no_install',
          'no_installer_execution',
          'no_auto_mount',
          'no_network_by_default',
        ]),
      })
    )
    expect(sbomGenerateToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendKind: 'builtin',
        availability: 'builtin',
        supportedModes: ['builtin'],
        defaultMode: 'builtin',
        inputArtifactTypes: expect.arrayContaining([
          'container_structure',
          'windows_installer_inventory',
          'linux_package_inventory',
          'firmware_scan',
        ]),
        outputArtifactTypes: expect.arrayContaining([
          'cyclonedx_sbom',
          'spdx_lite_sbom',
          'sbom_generation_evidence',
        ]),
        policy: expect.objectContaining({
          passiveByDefault: true,
          noNetwork: true,
          noMutation: true,
          noLiveExecution: true,
          noInstall: true,
          noMount: true,
          noInstallerExecution: true,
        }),
        readiness: expect.objectContaining({ doesNotStartBackend: true }),
      })
    )
  })

  test('returns CycloneDX with compact workflow-search handoff metadata by default', async () => {
    const handler = createSbomGenerateHandler({} as WorkspaceManager, databaseWithEvidence())
    const result = await handler({ sample_id: 'sha256:demo' } as never)
    const textSbom = JSON.parse(result.content[0].text ?? '{}')
    const data = result.structuredContent as any

    expect(textSbom.bomFormat).toBe('CycloneDX')
    expect(textSbom.evidence_summary).toBeUndefined()
    expect(data.bomFormat).toBe('CycloneDX')
    expect(data.components).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'KERNEL32' }),
        expect.objectContaining({ name: 'USER32' }),
        expect.objectContaining({ name: 'Newtonsoft.Json', version: '13.0.3' }),
        expect.objectContaining({ name: 'zlib1.dll' }),
        expect.objectContaining({ name: 'driver.sys' }),
      ])
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.sbom_generate.evidence_summary.v1',
        sample_id: 'sha256:demo',
        sbom_format: 'cyclonedx',
        artifact_type: 'cyclonedx_sbom',
        component_count: 5,
        sample_hash_count: 2,
        network_enrichment_performed: false,
      })
    )
    expect(data.evidence_summary.evidence_source_counts).toEqual(
      expect.objectContaining({
        'pe-import-table': 2,
        'dotnet-metadata': 1,
        'embedded-string': 2,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.sbom_generate.workflow_handoff.v1',
        handoff_mode: 'sbom_to_supply_chain_provenance_and_reporting',
        recommended_next_tools: expect.arrayContaining([
          'sbom.provenance.graph',
          'vuln.pattern.summary',
          'analysis.evidence.graph',
          'report.generate',
        ]),
      })
    )
    expect(data.workflow_handoff.artifact_contract.produces).toEqual(
      expect.arrayContaining(['cyclonedx_sbom', 'sbom_generation_evidence'])
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        package_install_performed: false,
        installer_execution_performed: false,
        container_entrypoint_run: false,
        firmware_mounted: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.sbom_generate.quality_gates.v1',
        requested_format: 'cyclonedx',
        passive_static_correlation: true,
        component_inventory_present: true,
        hash_lookup_requested: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['sbom.provenance.graph', 'analysis.evidence.graph'])
    )
  })

  test('returns SPDX-lite handoff and sparse-inventory guidance without network enrichment', async () => {
    const handler = createSbomGenerateHandler({} as WorkspaceManager, emptyDatabase())
    const result = await handler({
      sample_id: 'sha256:empty',
      format: 'spdx-lite',
      include_hashes: false,
    })
    const data = result.structuredContent as any

    expect(data.spdxVersion).toBe('SPDX-2.3')
    expect(data.packages).toEqual([])
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        sbom_format: 'spdx-lite',
        artifact_type: 'spdx_lite_sbom',
        component_count: 0,
        sample_hash_count: 0,
        network_enrichment_performed: false,
      })
    )
    expect(data.workflow_handoff.coverage).toEqual(
      expect.objectContaining({
        supports_cyclonedx: true,
        supports_spdx_lite: true,
        package_metadata_provenance: true,
        container_provenance: true,
        installer_provenance: true,
        firmware_provenance: true,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        requested_format: 'spdx-lite',
        component_inventory_present: false,
        hash_lookup_requested: false,
        package_install_performed: false,
        network_accessed_by_tool: false,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'metadata.extract',
        'strings.extract',
        'container.structure.analyze',
        'linux.package.inventory',
        'installer.inventory',
        'firmware.workflow.plan',
      ])
    )
    expect(data.next_actions.join(' ')).toMatch(/does not fetch dependency data from the network/)
  })
})
