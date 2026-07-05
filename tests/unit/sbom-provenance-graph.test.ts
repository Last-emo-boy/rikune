import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import sbomPlugin from '../../src/plugins/sbom/index.js'
import { buildSbomProvenanceGraph } from '../../src/plugins/sbom/tools/sbom-provenance-graph.js'

describe('sbom.provenance.graph', () => {
  test('merges duplicate components across local inventory sources with provenance', () => {
    const graph = buildSbomProvenanceGraph({
      sample_id: 'sha256:supply',
      sources: {
        'container.structure.analyze': {
          nested_binary_candidates: [
            { path: 'usr/lib/libcrypto.so', type_hint: 'elf' },
            { path: 'payload/app.apk', type_hint: 'android-package' },
          ],
        },
        'linux.package.inventory': {
          nested_binary_candidates: [{ path: 'usr/lib/libcrypto.so', type_hint: 'elf' }],
          maintainer_script_candidates: ['postinst'],
        },
        'installer.inventory': {
          nested_payload_candidates: [{ path: 'bin/setup.dll', type_hint: 'pe' }],
          custom_action_candidates: ['CustomAction.Install'],
        },
        'firmware.workflow.plan': {
          signatures: [{ description: 'Squashfs filesystem, little endian' }],
        },
      },
    })

    expect(graph.result_mode).toBe('sbom_provenance_graph')
    expect(graph.components.map((component: any) => component.name)).toEqual(
      expect.arrayContaining(['libcrypto.so', 'app.apk', 'setup.dll', 'postinst'])
    )
    const libcrypto = graph.components.find((component: any) => component.name === 'libcrypto.so')
    expect(libcrypto.evidence_sources).toEqual(
      expect.arrayContaining([
        'container.structure.analyze:nested_binary_candidates',
        'linux.package.inventory:nested_binary_candidates',
      ])
    )
    expect(graph.risk_summary.network_enrichment_performed).toBe(false)
    expect(graph.exports.cyclonedx.components).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'libcrypto.so' })])
    )
    expect(graph.exports.spdx_lite.packages).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'setup.dll' })])
    )
    expect(graph.recommended_next_tools).toEqual(
      expect.arrayContaining(['sbom.generate', 'vuln.pattern.summary', 'report.generate'])
    )
    expect(graph.safety_notes.join(' ')).toMatch(/No package install/)
  })

  test('registers the provenance graph workflow metadata', () => {
    const harness = createPluginTestHarness({
      deps: { workspaceManager: {}, database: {} },
    })
    const names = harness.registerPlugin(sbomPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'sbom.provenance.graph'
    )

    expect(names).toContain('sbom.provenance.graph')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'supply-chain.sbom.provenance',
        nextTools: expect.arrayContaining(['sbom.generate', 'vuln.pattern.summary']),
      })
    )
  })
})
