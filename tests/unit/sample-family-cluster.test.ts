import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import similarityPlugin from '../../src/plugins/similarity/index.js'
import { buildSampleFamilyCluster } from '../../src/plugins/similarity/tools/sample-family-cluster.js'

describe('sample.family.cluster', () => {
  test('clusters samples deterministically from shared features and diff evidence', () => {
    const result = buildSampleFamilyCluster({
      samples: [
        {
          sample_id: 'sha256:a',
          imports: ['CreateFileW', 'InternetOpenA', 'VirtualAlloc'],
          strings: ['campaign-alpha', 'https://c2.example.test/a'],
          functions: ['decrypt_config', 'beacon_loop'],
          family: 'demo',
        },
        {
          sample_id: 'sha256:b',
          imports: ['CreateFileW', 'InternetOpenA', 'VirtualAlloc'],
          strings: ['campaign-alpha', 'https://c2.example.test/b'],
          functions: ['decrypt_config', 'beacon_loop'],
          family: 'demo',
        },
        {
          sample_id: 'sha256:c',
          imports: ['RegOpenKeyW'],
          strings: ['unrelated'],
          functions: ['main'],
        },
      ],
      binary_diffs: [{ sample_id_a: 'sha256:a', sample_id_b: 'sha256:b', similarity: 0.82 }],
      min_shared_features: 2,
    })

    expect(result.schema).toBe('rikune.sample_family_cluster.v1')
    expect(result.tool_version).toBe('0.2.0')
    expect(result.result_mode).toBe('sample_family_cluster')
    expect(result.clusters).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          members: ['sha256:a', 'sha256:b'],
          suggested_family_label: 'demo',
        }),
      ])
    )
    expect(result.relationships).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          source: 'sha256:a',
          target: 'sha256:b',
          shared_feature_count: expect.any(Number),
        }),
      ])
    )
    expect(result.kb_handoff.tool).toBe('kb.context.suggest')
    expect(result.reporting_handoff.tool).toBe('report.generate')
    expect(result.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.sample_family_cluster.evidence_summary.v1',
        source_tool: 'sample.family.cluster',
        artifact_type: 'sample_family_cluster',
        sample_count: 3,
        multi_sample_cluster_count: 1,
        singleton_count: 1,
        grouped_sample_count: 2,
        relationship_count: 1,
        known_findings: ['family-cluster', 'variant-group'],
      })
    )
    expect(result.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.sample_family_cluster.workflow_handoff.v1',
        source_tool: 'sample.family.cluster',
        handoff_mode: 'family_cluster_to_variant_review',
        artifact_type: 'sample_family_cluster',
        recommended_next_tools: expect.arrayContaining([
          'binary.diff.summary',
          'kb.context.suggest',
          'analysis.evidence.graph',
          'report.generate',
          'workflow.search',
        ]),
      })
    )
    expect(result.workflow_handoff.artifact_contract).toEqual(
      expect.objectContaining({
        produces: ['sample_family_cluster'],
        persisted_by_tool: false,
        expected_consumers: expect.arrayContaining([
          'binary.diff.summary',
          'kb.context.suggest',
          'analysis.evidence.graph',
          'report.generate',
        ]),
      })
    )
    expect(result.workflow_handoff.binary_diff_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sample_id_a: 'sha256:a',
          sample_id_b: 'sha256:b',
          confidence: expect.any(Number),
        }),
      ])
    )
    expect(result.route_profile).toEqual(
      expect.objectContaining({
        schema: 'rikune.sample_family_cluster.route_profile.v1',
        artifact_type: 'sample_family_cluster',
        route_terms: expect.arrayContaining(['similarity', 'family', 'variant', 'binary-diff']),
        coverage_gap_domains: expect.arrayContaining([
          'variant-diff-review',
          'family-kb-correlation',
        ]),
      })
    )
    expect(result.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.sample_family_cluster.quality_gates.v1',
        passive_static_correlation: true,
        no_fuzzy_backend_required: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        has_multi_sample_cluster: true,
      })
    )
    expect(result.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'binary.diff.summary',
        'kb.context.suggest',
        'analysis.evidence.graph',
        'report.generate',
        'workflow.search',
      ])
    )
  })

  test('registers similarity family workflow metadata', () => {
    const harness = createPluginTestHarness({
      deps: { workspaceManager: {}, database: {} },
    })
    const names = harness.registerPlugin(similarityPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'sample.family.cluster'
    )

    expect(names).toContain('sample.family.cluster')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'similarity.family-cluster',
        nextTools: expect.arrayContaining([
          'binary.diff.summary',
          'kb.context.suggest',
          'analysis.evidence.graph',
          'report.generate',
          'workflow.search',
        ]),
        producesArtifacts: ['sample_family_cluster'],
      })
    )
    expect(tool?.definition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['variant-analysis', 'workflow-handoff'])
    )
  })
})
